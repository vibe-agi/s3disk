package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/presignedshare"
)

const publisherReferenceKeyID = "share-key-1"

func runPublish(ctx context.Context, options PublishOptions) error {
	return runPublishWithOperations(ctx, options, productionPublisherOperations())
}

func runPublishWithOperations(ctx context.Context, options PublishOptions, operations publisherOperations) (resultErr error) {
	if ctx == nil {
		return fmt.Errorf("s3disk share publish: context is required")
	}
	if err := validatePublisherOperations(operations); err != nil {
		return fmt.Errorf("s3disk share publish: %w", err)
	}
	if err := validatePublishOptions(&options); err != nil {
		return err
	}

	// Fix the absolute authorization window before any path, credential, source,
	// or S3 work. All later work consumes this same grant and cannot extend it.
	createdAt := operations.now().UTC().Truncate(time.Second)
	expiresAt := createdAt.Add(options.ExpiresIn).UTC().Truncate(time.Second)
	if createdAt.IsZero() || !expiresAt.After(createdAt) {
		return fmt.Errorf("s3disk share publish: invalid authorization clock")
	}
	runContext, cancelRun := context.WithDeadline(ctx, expiresAt)
	defer cancelRun()
	if err := requirePublisherAuthorization(runContext, expiresAt, operations.now); err != nil {
		return fmt.Errorf("s3disk share publish: %w", err)
	}

	localPaths, err := preflightPublishLocalPaths(runContext, options)
	if err != nil {
		return fmt.Errorf("s3disk share publish: local preflight: %w", err)
	}
	recoveryMaterial, err := readRecoveryKeyFileContext(runContext, localPaths.recoveryKey)
	if err != nil {
		return fmt.Errorf("s3disk share publish: read recovery key: %w", err)
	}
	tlsCAPEM, err := readBoundedFile(options.TLSCAFile, presignedshare.MaximumTLSRootCAPEMBytes)
	if err != nil {
		return fmt.Errorf("s3disk share publish: read TLS CA: %w", err)
	}
	defer clear(tlsCAPEM)
	canonicalCAPEM, err := canonicalTLSRootCAPEM(tlsCAPEM)
	if err != nil {
		return fmt.Errorf("s3disk share publish: TLS CA: %w", err)
	}
	clear(tlsCAPEM)
	tlsCAPEM = canonicalCAPEM
	if err := requirePublisherAuthorization(runContext, expiresAt, operations.now); err != nil {
		return fmt.Errorf("s3disk share publish: %w", err)
	}

	handle, err := operations.openS3(runContext, publisherS3Config{
		bucket: options.Bucket, region: options.Region, endpoint: options.Endpoint,
		expectedBucketOwner: options.ExpectedBucketOwner, usePathStyle: options.UsePathStyle,
		allowInsecureEndpoint: options.AllowInsecureEndpoint, tlsRootCAPEM: tlsCAPEM,
	})
	if err != nil {
		return fmt.Errorf("s3disk share publish: configure S3: %w", err)
	}
	if err := validatePublisherS3Handle(handle); err != nil {
		return fmt.Errorf("s3disk share publish: %w", err)
	}
	if err := requirePublisherAuthorization(runContext, expiresAt, operations.now); err != nil {
		return fmt.Errorf("s3disk share publish: %w", err)
	}

	repositoryID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		return fmt.Errorf("s3disk share publish: generate repository identity: %w", err)
	}
	shareID, err := presignedshare.GenerateShareID()
	if err != nil {
		return fmt.Errorf("s3disk share publish: generate share identity: %w", err)
	}
	rootNonce := make([]byte, 32)
	if _, err := rand.Read(rootNonce); err != nil {
		return fmt.Errorf("s3disk share publish: generate root namespace: %w", err)
	}
	defer clear(rootNonce)
	clientKey, err := s3disk.GenerateClientEncryptionKey()
	if err != nil {
		return fmt.Errorf("s3disk share publish: generate client encryption key: %w", err)
	}
	profile, err := s3disk.NewClientEncryptionProfile(repositoryID, clientKey)
	if err != nil {
		return fmt.Errorf("s3disk share publish: create client encryption profile: %w", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("s3disk share publish: generate signing key: %w", err)
	}
	signer, err := s3disk.NewEd25519ReferenceSigner(repositoryID, publisherReferenceKeyID, privateKey)
	if err != nil {
		return fmt.Errorf("s3disk share publish: create reference signer: %w", err)
	}
	verifier, err := s3disk.NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{
		publisherReferenceKeyID: publicKey,
	})
	if err != nil {
		return fmt.Errorf("s3disk share publish: create reference verifier: %w", err)
	}

	basePrefix := strings.Trim(options.Prefix, "/")
	repositoryPrefix := basePrefix + "/shares/" + shareID.String()
	lowLevelRepository, err := s3disk.NewRepositoryWithOptions(handle.store, repositoryPrefix,
		s3disk.RepositoryOptions{ClientEncryption: profile})
	if err != nil {
		return fmt.Errorf("s3disk share publish: validate repository namespace: %w", err)
	}
	referenceKey := lowLevelRepository.SignedReferenceKey(options.Channel)
	rootKey := repositoryPrefix + "/share-root/" + base64.RawURLEncoding.EncodeToString(rootNonce)

	stateDir, err := preparePrivateDirectory(localPaths.stateDir)
	if err != nil {
		return fmt.Errorf("s3disk share publish: state directory: %w", err)
	}
	shareDirectory := filepath.Join(stateDir, shareID.String())
	if err := os.Mkdir(shareDirectory, 0o700); err != nil {
		return fmt.Errorf("s3disk share publish: create isolated state: %w", err)
	}
	if err := syncPrivateDirectory(stateDir); err != nil {
		return fmt.Errorf("s3disk share publish: make isolated state durable: %w", err)
	}
	lock, err := acquirePublisherSessionLock(runContext, shareDirectory)
	if err != nil {
		return fmt.Errorf("s3disk share publish: acquire session lock: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Close()) }()
	recoveryStores, err := newPublisherRecoveryStores(shareDirectory, repositoryID, shareID, recoveryMaterial)
	if err != nil {
		return fmt.Errorf("s3disk share publish: create recovery stores: %w", err)
	}

	if err := requirePublisherAuthorization(runContext, expiresAt, operations.now); err != nil {
		return fmt.Errorf("s3disk share publish: %w", err)
	}
	presigner, err := handle.newPresignSession(runContext, expiresAt)
	if err != nil {
		return fmt.Errorf("s3disk share publish: create fixed-expiry presigner: %w", err)
	}
	if err := validatePublisherPresigner(presigner); err != nil {
		return fmt.Errorf("s3disk share publish: %w", err)
	}
	rootCapability, err := presigner.PresignGet(runContext, rootKey)
	if err != nil {
		return fmt.Errorf("s3disk share publish: mint root bearer: %w", err)
	}
	rootPublisher, err := presignedshare.NewRootPublisher(presignedshare.RootPublisherConfig{
		Store: handle.store, RecoveryJournal: recoveryStores.root, ClientEncryption: profile,
		RootKey: rootKey, RootCapability: rootCapability, RepositoryPrefix: repositoryPrefix,
		ReferenceKey: referenceKey, ShareID: shareID, Presigner: presigner,
		Signer: signer, Verifier: verifier,
	})
	if err != nil {
		return fmt.Errorf("s3disk share publish: create recoverable share root: %w", err)
	}
	if err := rootPublisher.PrepareRecovery(runContext); err != nil {
		return fmt.Errorf("s3disk share publish: prepare root recovery: %w", err)
	}
	bearer, err := rootCapability.ExportBearer()
	if err != nil {
		return fmt.Errorf("s3disk share publish: export root bearer: %w", err)
	}
	defer clear(bearer)
	importedRoot, err := presignedshare.ParseBearer(bearer,
		presignedshare.CapabilityOptions{AllowInsecureLoopback: options.AllowInsecureEndpoint})
	if err != nil {
		return fmt.Errorf("s3disk share publish: parse recovery root bearer: %w", err)
	}
	// Exercise the exact restart authority before committing the session. From
	// this point onward even the fresh process uses the restored publisher.
	rootPublisher, err = presignedshare.RestoreRootPublisher(runContext, presignedshare.RootPublisherConfig{
		Store: handle.store, RecoveryJournal: recoveryStores.root, ClientEncryption: profile,
		RootKey: rootKey, RootCapability: importedRoot, RepositoryPrefix: repositoryPrefix,
		ReferenceKey: referenceKey, ShareID: shareID, Presigner: presigner,
		Signer: signer, Verifier: verifier,
	})
	if err != nil {
		return fmt.Errorf("s3disk share publish: verify restart authority: %w", err)
	}

	selectedBytes, selectedPaths := canonicalPublisherSelection(options.Paths)
	state := publisherSession{
		Format: publisherSessionFormat, Profile: publisherSessionProfile,
		Sequence: 1, Phase: publisherSessionPrepared, CreatedAt: createdAt,
		AuthorizationExpiresAt: expiresAt, ShareID: shareID.String(), RepositoryID: repositoryID.String(),
		RecoveryKeyID: recoveryMaterial.keyID, SourcePath: []byte(localPaths.source), SelectAll: options.All,
		SelectedPaths: selectedBytes, Once: options.Once, HandoffPath: []byte(localPaths.handoff),
		Bucket: options.Bucket, Prefix: basePrefix, Region: options.Region, Endpoint: options.Endpoint,
		ExpectedBucketOwner: options.ExpectedBucketOwner, UsePathStyle: options.UsePathStyle,
		AllowInsecureEndpoint: options.AllowInsecureEndpoint, TLSRootCAPEM: append([]byte(nil), tlsCAPEM...),
		RepositoryPrefix: repositoryPrefix, Channel: options.Channel, ReferenceKey: referenceKey,
		ReferenceKeyID: publisherReferenceKeyID, ReferencePrivateSeed: privateKey.Seed(),
		RootKey: rootKey, RootBearer: append([]byte(nil), bearer...), ClientEncryptionKey: clientKey.ExportSecret(),
	}
	loaded, err := createPublisherSession(runContext, recoveryStores.session, state, operations.now())
	if err != nil {
		return fmt.Errorf("s3disk share publish: persist prepared session: %w", err)
	}
	writePublisherPreparedStatus(options.StatusWriter, loaded.state, shareDirectory)
	if err := publisherDurablePhaseBoundary(runContext, loaded.state, operations); err != nil {
		return fmt.Errorf("s3disk share publish: after prepared session: %w", err)
	}

	repository, _, err := s3disk.InitializeRepository(runContext, handle.store, repositoryPrefix,
		s3disk.RepositoryConfig{RepositoryID: repositoryID, ClientEncryption: profile},
		s3disk.RepositoryInitializationOptions{ConfirmEmptyPrefix: true})
	if err != nil {
		return fmt.Errorf("s3disk share publish: initialize repository: %w", err)
	}
	if err := publisherExternalEffectBoundary(runContext, loaded.state, operations, publisherEffectRepositoryReady); err != nil {
		return fmt.Errorf("s3disk share publish: after repository effect: %w", err)
	}
	loaded, err = advancePublisherSession(runContext, recoveryStores.session, loaded,
		publisherSessionRepositoryReady, nil, s3disk.Digest{}, operations.now())
	if err != nil {
		return fmt.Errorf("s3disk share publish: persist repository phase: %w", err)
	}
	if err := publisherDurablePhaseBoundary(runContext, loaded.state, operations); err != nil {
		return fmt.Errorf("s3disk share publish: after repository phase: %w", err)
	}

	journal, err := s3disk.NewFilePublicationJournal(filepath.Join(shareDirectory, publicationJournalFileName))
	if err != nil {
		return fmt.Errorf("s3disk share publish: create publication journal: %w", err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: signer, ReferenceVerifier: verifier, PublicationJournal: journal,
		AllowTrustOnFirstUse: true, Symlinks: s3disk.SymlinkRejectExternal,
		ProtectedSourceFiles: protectedPublisherSourceFiles(
			localPaths.recoveryKey, localPaths.handoff, shareDirectory,
		),
	})
	if err != nil {
		return fmt.Errorf("s3disk share publish: create publisher: %w", err)
	}
	recovery, err := publisher.RecoverPublication(runContext, options.Channel)
	if err != nil {
		return fmt.Errorf("s3disk share publish: initialize publication recovery: %w", err)
	}
	if err := publisherExternalEffectBoundary(runContext, loaded.state, operations, publisherEffectJournalReady); err != nil {
		return fmt.Errorf("s3disk share publish: after journal effect: %w", err)
	}
	loaded, err = advancePublisherSession(runContext, recoveryStores.session, loaded,
		publisherSessionJournalReady, nil, s3disk.Digest{}, operations.now())
	if err != nil {
		return fmt.Errorf("s3disk share publish: persist journal phase: %w", err)
	}
	if err := publisherDurablePhaseBoundary(runContext, loaded.state, operations); err != nil {
		return fmt.Errorf("s3disk share publish: after journal phase: %w", err)
	}

	snapshot := recovery.Current
	if snapshot.Generation == 0 {
		if err := requirePublisherAuthorization(runContext, expiresAt, operations.now); err != nil {
			return fmt.Errorf("s3disk share publish: %w", err)
		}
		if options.All {
			snapshot, err = publisher.Publish(runContext, localPaths.source, options.Channel)
		} else {
			snapshot, err = publisher.PublishSelected(runContext, localPaths.source, options.Channel, selectedPaths)
		}
		if err != nil {
			return fmt.Errorf("s3disk share publish: publish snapshot: %w", err)
		}
	}
	if err := publisherExternalEffectBoundary(runContext, loaded.state, operations, publisherEffectInitialPublicationReady); err != nil {
		return fmt.Errorf("s3disk share publish: after initial publication effect: %w", err)
	}
	checkpoint := handoffCheckpoint{Generation: snapshot.Generation, Commit: snapshot.Commit.String()}
	loaded, err = advancePublisherSession(runContext, recoveryStores.session, loaded,
		publisherSessionInitialPublicationReady, &checkpoint, s3disk.Digest{}, operations.now())
	if err != nil {
		return fmt.Errorf("s3disk share publish: persist initial publication phase: %w", err)
	}
	if err := publisherDurablePhaseBoundary(runContext, loaded.state, operations); err != nil {
		return fmt.Errorf("s3disk share publish: after initial publication phase: %w", err)
	}

	expectedHandoff, encodedHandoff, digest, err := buildPublisherHandoff(loaded.state)
	if err != nil {
		return fmt.Errorf("s3disk share publish: build handoff: %w", err)
	}
	clear(encodedHandoff)
	if err := requirePublisherAuthorization(runContext, expiresAt, operations.now); err != nil {
		return fmt.Errorf("s3disk share publish: %w", err)
	}
	if _, err := rootPublisher.CreatePublishedSnapshot(runContext, repository, options.Channel, snapshot); err != nil {
		return fmt.Errorf("s3disk share publish: publish share root: %w", err)
	}
	if err := publisherExternalEffectBoundary(runContext, loaded.state, operations, publisherEffectInitialRootReady); err != nil {
		return fmt.Errorf("s3disk share publish: after initial root effect: %w", err)
	}
	loaded, err = advancePublisherSession(runContext, recoveryStores.session, loaded,
		publisherSessionInitialRootReady, nil, digest, operations.now())
	if err != nil {
		return fmt.Errorf("s3disk share publish: persist initial root phase: %w", err)
	}
	if err := publisherDurablePhaseBoundary(runContext, loaded.state, operations); err != nil {
		return fmt.Errorf("s3disk share publish: after initial root phase: %w", err)
	}

	if err := requirePublisherAuthorization(runContext, expiresAt, operations.now); err != nil {
		return fmt.Errorf("s3disk share publish: %w", err)
	}
	if err := installOrVerifyHandoff(runContext, localPaths.handoff, expectedHandoff, digest); err != nil {
		return fmt.Errorf("s3disk share publish: reconcile handoff: %w", err)
	}
	if err := publisherExternalEffectBoundary(runContext, loaded.state, operations, publisherEffectHandoffReady); err != nil {
		return fmt.Errorf("s3disk share publish: after handoff effect: %w", err)
	}
	loaded, err = advancePublisherSession(runContext, recoveryStores.session, loaded,
		publisherSessionHandoffReady, nil, s3disk.Digest{}, operations.now())
	if err != nil {
		return fmt.Errorf("s3disk share publish: persist handoff phase: %w", err)
	}
	if err := publisherDurablePhaseBoundary(runContext, loaded.state, operations); err != nil {
		return fmt.Errorf("s3disk share publish: after handoff phase: %w", err)
	}

	if options.Once {
		loaded, err = advancePublisherSession(runContext, recoveryStores.session, loaded,
			publisherSessionCompleted, nil, s3disk.Digest{}, operations.now())
		if err != nil {
			return fmt.Errorf("s3disk share publish: persist completion: %w", err)
		}
		if err := publisherDurablePhaseBoundary(runContext, loaded.state, operations); err != nil {
			return fmt.Errorf("s3disk share publish: after completion: %w", err)
		}
		writePublisherReadyStatus(options.StatusWriter, loaded.state)
		return nil
	}

	writePublisherReadyStatus(options.StatusWriter, loaded.state)
	if err := requirePublisherAuthorization(runContext, expiresAt, operations.now); err != nil {
		return fmt.Errorf("s3disk share publish: %w", err)
	}
	if err := watchPublisherSource(runContext, publisher, rootPublisher, repository, loaded.state, selectedPaths, options.ErrorWriter); err != nil {
		return fmt.Errorf("s3disk share publish: %w", err)
	}
	return nil
}

func canonicalPublisherSelection(paths []string) ([][]byte, []string) {
	values := append([]string(nil), paths...)
	sort.Strings(values)
	unique := values[:0]
	for _, value := range values {
		if len(unique) == 0 || value != unique[len(unique)-1] {
			unique = append(unique, value)
		}
	}
	encoded := make([][]byte, len(unique))
	for index := range unique {
		encoded[index] = []byte(unique[index])
	}
	if encoded == nil {
		encoded = make([][]byte, 0)
	}
	return encoded, append([]string(nil), unique...)
}

func publisherDurablePhaseBoundary(
	ctx context.Context,
	state publisherSession,
	operations publisherOperations,
) error {
	if err := operations.afterDurablePhase(ctx, state.Phase); err != nil {
		return err
	}
	return requirePublisherAuthorization(ctx, state.AuthorizationExpiresAt, operations.now)
}

func publisherExternalEffectBoundary(
	ctx context.Context,
	state publisherSession,
	operations publisherOperations,
	effect publisherExternalEffect,
) error {
	if err := operations.afterExternalEffect(ctx, effect); err != nil {
		return err
	}
	return requirePublisherAuthorization(ctx, state.AuthorizationExpiresAt, operations.now)
}

func writePublisherReadyStatus(output io.Writer, state publisherSession) {
	if output == nil {
		return
	}
	mode := "watching"
	if state.Once {
		mode = "one-shot"
	}
	_, _ = fmt.Fprintf(output,
		"ready: share_id=%q handoff=%q expires_at=%s mode=%s\n",
		state.ShareID, string(state.HandoffPath), state.AuthorizationExpiresAt.Format(time.RFC3339), mode,
	)
}

func writePublisherPreparedStatus(
	output io.Writer,
	state publisherSession,
	shareDirectory string,
) {
	if output == nil {
		return
	}
	_, _ = fmt.Fprintf(output,
		"prepared: share_id=%q state=%q expires_at=%s\n",
		state.ShareID, shareDirectory, state.AuthorizationExpiresAt.Format(time.RFC3339),
	)
}

func watchPublisherSource(
	ctx context.Context,
	publisher *s3disk.Publisher,
	rootPublisher *presignedshare.RootPublisher,
	repository *s3disk.Repository,
	state publisherSession,
	selectedPaths []string,
	errorOutput io.Writer,
) error {
	watchOptions := s3disk.WatchOptions{
		AfterPublished: func(updateContext context.Context, updated s3disk.Snapshot) error {
			_, updateErr := rootPublisher.UpdatePublishedSnapshot(updateContext, repository, state.Channel, updated)
			return updateErr
		},
		OnError: func(err error) {
			if errorOutput != nil && err != nil {
				_, _ = fmt.Fprintf(errorOutput, "warning: continuous publication will retry: %v\n", err)
			}
		},
	}
	var err error
	if state.SelectAll {
		err = publisher.Watch(ctx, string(state.SourcePath), state.Channel, watchOptions)
	} else {
		err = publisher.WatchSelected(ctx, string(state.SourcePath), state.Channel, selectedPaths, watchOptions)
	}
	if err != nil && !(ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded))) {
		return fmt.Errorf("watch source: %w", err)
	}
	return nil
}
