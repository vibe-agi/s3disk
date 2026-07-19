package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/presignedshare"
	"github.com/vibe-agi/s3disk/s3store"
)

func runPublish(ctx context.Context, options PublishOptions) error {
	if ctx == nil {
		return fmt.Errorf("s3disk share publish: context is required")
	}
	if err := validatePublishOptions(&options); err != nil {
		return err
	}
	// This read-only local preflight happens before the first S3 write. The
	// final write still uses O_EXCL to close the race with another process.
	if err := preflightPublishLocalPaths(options); err != nil {
		return fmt.Errorf("s3disk share publish: local preflight: %w", err)
	}
	// Calculate the fixed absolute deadline once. Publication time consumes the
	// same grant; it must never be silently extended after scanning finishes.
	expiresAt := time.Now().Add(options.ExpiresIn).UTC().Truncate(time.Second)
	tlsCAPEM, err := readBoundedFile(options.TLSCAFile, presignedshare.MaximumTLSRootCAPEMBytes)
	if err != nil {
		return fmt.Errorf("s3disk share publish: read TLS CA: %w", err)
	}
	httpClient, err := s3HTTPClient(tlsCAPEM)
	if err != nil {
		return fmt.Errorf("s3disk share publish: TLS CA: %w", err)
	}
	rawStore, err := s3store.New(ctx, s3store.Config{
		Bucket: options.Bucket, Region: options.Region, Endpoint: options.Endpoint,
		ExpectedBucketOwner: options.ExpectedBucketOwner, UsePathStyle: options.UsePathStyle,
		AllowInsecureEndpoint: options.AllowInsecureEndpoint, HTTPClient: httpClient,
	})
	if err != nil {
		return fmt.Errorf("s3disk share publish: configure S3: %w", err)
	}
	repositoryID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		return err
	}
	shareID, err := presignedshare.GenerateShareID()
	if err != nil {
		return err
	}
	rootNonce := make([]byte, 32)
	if _, err := rand.Read(rootNonce); err != nil {
		return fmt.Errorf("s3disk share publish: generate root namespace: %w", err)
	}
	clientKey, err := s3disk.GenerateClientEncryptionKey()
	if err != nil {
		return err
	}
	profile, err := s3disk.NewClientEncryptionProfile(repositoryID, clientKey)
	if err != nil {
		return err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("s3disk share publish: generate signing key: %w", err)
	}
	const keyID = "share-key-1"
	signer, err := s3disk.NewEd25519ReferenceSigner(repositoryID, keyID, privateKey)
	if err != nil {
		return err
	}
	verifier, err := s3disk.NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{keyID: publicKey})
	if err != nil {
		return err
	}
	basePrefix := strings.Trim(options.Prefix, "/")
	sharePrefix := basePrefix + "/shares/" + shareID.String()
	stateDir, err := preparePrivateDirectory(options.StateDir)
	if err != nil {
		return fmt.Errorf("s3disk share publish: state directory: %w", err)
	}
	shareStateDir := filepath.Join(stateDir, shareID.String())
	if err := os.Mkdir(shareStateDir, 0o700); err != nil {
		return fmt.Errorf("s3disk share publish: create isolated state: %w", err)
	}
	journal, err := s3disk.NewFilePublicationJournal(filepath.Join(shareStateDir, "publication-journal.json"))
	if err != nil {
		return err
	}
	repository, _, err := s3disk.InitializeRepository(ctx, rawStore, sharePrefix, s3disk.RepositoryConfig{
		RepositoryID: repositoryID, ClientEncryption: profile,
	}, s3disk.RepositoryInitializationOptions{ConfirmEmptyPrefix: true})
	if err != nil {
		return fmt.Errorf("s3disk share publish: initialize repository: %w", err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: signer, ReferenceVerifier: verifier, PublicationJournal: journal,
		AllowTrustOnFirstUse: true, Symlinks: s3disk.SymlinkRejectExternal,
	})
	if err != nil {
		return fmt.Errorf("s3disk share publish: create publisher: %w", err)
	}
	var snapshot s3disk.Snapshot
	if options.All {
		snapshot, err = publisher.Publish(ctx, options.Source, options.Channel)
	} else {
		snapshot, err = publisher.PublishSelected(ctx, options.Source, options.Channel, options.Paths)
	}
	if err != nil {
		return fmt.Errorf("s3disk share publish: publish snapshot: %w", err)
	}
	if !expiresAt.After(time.Now()) {
		return fmt.Errorf("s3disk share publish: authorization expired while publishing")
	}
	presigner, err := rawStore.NewPresignSession(ctx, expiresAt)
	if err != nil {
		return fmt.Errorf("s3disk share publish: create fixed-expiry presigner: %w", err)
	}
	rootKey := sharePrefix + "/share-root/" + base64.RawURLEncoding.EncodeToString(rootNonce)
	rootCapability, err := presigner.PresignGet(ctx, rootKey)
	if err != nil {
		return fmt.Errorf("s3disk share publish: mint root bearer: %w", err)
	}
	referenceKey := repository.SignedReferenceKey(options.Channel)
	rootPublisher, err := presignedshare.NewRootPublisher(presignedshare.RootPublisherConfig{
		Store: rawStore, ClientEncryption: profile, RootKey: rootKey, RootCapability: rootCapability,
		RepositoryPrefix: sharePrefix, ReferenceKey: referenceKey, ShareID: shareID,
		Presigner: presigner, Signer: signer, Verifier: verifier,
	})
	if err != nil {
		return fmt.Errorf("s3disk share publish: create share root: %w", err)
	}
	if _, err := rootPublisher.CreatePublishedSnapshot(ctx, repository, options.Channel, snapshot); err != nil {
		return fmt.Errorf("s3disk share publish: publish share root: %w", err)
	}
	bearer, err := rootCapability.ExportBearer()
	if err != nil {
		return fmt.Errorf("s3disk share publish: export root bearer: %w", err)
	}
	value := handoff{
		Format: handoffFormat, Profile: handoffProfile, ShareID: shareID.String(),
		AuthorizationExpiresAt: expiresAt, RootBearer: base64.RawURLEncoding.EncodeToString(bearer),
		RepositoryPrefix: sharePrefix, ReferenceKey: referenceKey, Channel: options.Channel,
		RepositoryID: repositoryID.String(), ReferenceKeyID: keyID,
		ReferencePublicKey:    base64.RawURLEncoding.EncodeToString(publicKey),
		TrustedCheckpoint:     handoffCheckpoint{Generation: snapshot.Generation, Commit: snapshot.Commit.String()},
		TLSRootCAPEM:          base64.RawURLEncoding.EncodeToString(tlsCAPEM),
		AllowInsecureLoopback: options.AllowInsecureEndpoint,
		ClientEncryptionKey:   clientKey.ExportSecret(),
	}
	if err := writeHandoff(options.HandoffOut, value); err != nil {
		return fmt.Errorf("s3disk share publish: write handoff: %w", err)
	}
	if options.StatusWriter != nil {
		mode := "watching"
		if options.Once {
			mode = "one-shot"
		}
		_, _ = fmt.Fprintf(options.StatusWriter, "ready: handoff=%q expires_at=%s mode=%s\n",
			options.HandoffOut, expiresAt.Format(time.RFC3339), mode)
	}
	if options.Once {
		return nil
	}
	watchContext, cancelWatch := context.WithDeadline(ctx, expiresAt)
	defer cancelWatch()
	watchOptions := s3disk.WatchOptions{
		AfterPublished: func(updateContext context.Context, updated s3disk.Snapshot) error {
			_, updateErr := rootPublisher.UpdatePublishedSnapshot(updateContext, repository, options.Channel, updated)
			return updateErr
		},
	}
	if options.All {
		err = publisher.Watch(watchContext, options.Source, options.Channel, watchOptions)
	} else {
		err = publisher.WatchSelected(watchContext, options.Source, options.Channel, options.Paths, watchOptions)
	}
	if err != nil && !(watchContext.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded))) {
		return fmt.Errorf("s3disk share publish: watch source: %w", err)
	}
	return nil
}
