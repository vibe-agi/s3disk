//go:build integration

package s3store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/presignedshare"
)

// TestMinIOOnlyS3PresignedShare proves the complete runtime authority split
// against real MinIO. A owns the credentialed Store and signing key. The
// recipient bootstrap below deliberately contains only one exported root
// bearer plus public bindings/trust state; after that handoff, B's Reader uses
// anonymous, exact-key presigned GETs to S3 and has no Store, credential
// provider, signing key, callback, broker, or network path to A.
func TestMinIOOnlyS3PresignedShare(t *testing.T) {
	endpoint := os.Getenv("S3DISK_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("S3DISK_TEST_S3_ENDPOINT is not set")
	}
	accessKey := envOr("S3DISK_TEST_S3_ACCESS_KEY", "s3disk")
	secretKey := envOr("S3DISK_TEST_S3_SECRET_KEY", "s3disk-secret")
	bucket := fmt.Sprintf("s3disk-only-s3-share-%d", time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	createBucketWithRetry(t, ctx, endpoint, accessKey, secretKey, bucket)

	// This exception permits plaintext HTTP only when the presigned endpoint is
	// a literal loopback address. Production recipients leave it false and use
	// HTTPS. Both ParseBearer and Reader independently enforce the restriction.
	const allowInsecureLoopbackForMinIOTest = true

	store, err := New(ctx, Config{
		Bucket: bucket, Region: "us-east-1", Endpoint: endpoint, UsePathStyle: true,
		CredentialsProvider: CredentialsProviderFunc(func(context.Context) (Credentials, error) {
			return Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	const (
		repositoryPrefix = "only-s3-integration"
		channel          = "shared"
		rootKey          = "only-s3-share/root.bundle"
		selectedPath     = "shared/selected.txt"
		hiddenPath       = "shared/private.txt"
	)
	repository, err := s3disk.NewRepository(store, repositoryPrefix)
	if err != nil {
		t.Fatal(err)
	}
	repositoryID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := s3disk.NewEd25519ReferenceSigner(repositoryID, "only-s3-minio", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := s3disk.NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{
		"only-s3-minio": publicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateIntegrationDirectory(t), "publisher.journal"))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ReferenceSigner:                          signer, ReferenceVerifier: verifier,
		PublicationJournal: journal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	source := privateIntegrationDirectory(t)
	if err := os.MkdirAll(filepath.Join(source, "shared"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeOnlyS3IntegrationFile(t, filepath.Join(source, selectedPath), "selected generation one")
	writeOnlyS3IntegrationFile(t, filepath.Join(source, hiddenPath), "must remain private")
	firstSnapshot, err := publisher.PublishSelected(ctx, source, channel, []string{selectedPath})
	if err != nil {
		t.Fatal(err)
	}
	if firstSnapshot.Generation != 1 {
		t.Fatalf("first generation = %d, want 1", firstSnapshot.Generation)
	}
	firstClosure, err := repository.ResolveSnapshotClosure(ctx, channel, s3disk.SnapshotClosureOptions{
		ReferenceVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	firstChunkKey := onlyChunkKey(t, firstClosure.ObjectKeys)
	firstChunk, err := store.Get(ctx, firstChunkKey, s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// One fixed signing instant and absolute deadline covers the root URL and
	// every immutable-object URL in every revision of this short-lived share.
	requestedExpiry := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	presignSession, err := store.NewPresignSession(ctx, requestedExpiry)
	if err != nil {
		t.Fatal(err)
	}
	effectiveExpiry, ok := presignSession.AuthorizationExpiry()
	if !ok || !effectiveExpiry.Equal(requestedExpiry) {
		t.Fatalf("presign expiry = %s, %t; want fixed %s", effectiveExpiry, ok, requestedExpiry)
	}
	rootCapability, err := presignSession.PresignGet(ctx, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if !rootCapability.ExpiresAt().Equal(effectiveExpiry) {
		t.Fatalf("root expiry = %s, want %s", rootCapability.ExpiresAt(), effectiveExpiry)
	}
	shareID, err := presignedshare.GenerateShareID()
	if err != nil {
		t.Fatal(err)
	}
	rootPublisher, err := presignedshare.NewRootPublisher(presignedshare.RootPublisherConfig{
		Store: store, RootKey: rootKey, RootCapability: rootCapability,
		RepositoryPrefix: repositoryPrefix, ReferenceKey: repository.SignedReferenceKey(channel),
		ShareID: shareID, Presigner: presignSession, Signer: signer, Verifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	firstRoot, err := rootPublisher.Create(ctx, firstClosure)
	if err != nil {
		t.Fatal(err)
	}
	if !firstRoot.Updated || firstRoot.Revision != 1 || firstRoot.Snapshot != firstSnapshot {
		t.Fatalf("first root publication = %+v, want updated revision 1", firstRoot)
	}

	rootBearer, err := rootCapability.ExportBearer()
	if err != nil {
		t.Fatal(err)
	}
	recipientWatermarkPath := filepath.Join(privateIntegrationDirectory(t), "recipient.watermark")
	bootstrap := onlyS3RecipientBootstrap{
		RootBearer: append([]byte(nil), rootBearer...), RepositoryPrefix: repositoryPrefix,
		ReferenceKey: repository.SignedReferenceKey(channel), ShareID: shareID,
		Verifier: verifier,
		Checkpoint: s3disk.Watermark{
			RepositoryID: repositoryID, Generation: firstSnapshot.Generation, Commit: firstSnapshot.Commit,
		},
		WatermarkPath:         recipientWatermarkPath,
		AllowInsecureLoopback: allowInsecureLoopbackForMinIOTest,
	}
	recipientReader, recipient := newOnlyS3Recipient(t, bootstrap, channel)
	if expiry, known := recipientReader.AuthorizationExpiry(); !known || !expiry.Equal(effectiveExpiry) {
		t.Fatalf("recipient expiry = %s, %t; want %s", expiry, known, effectiveExpiry)
	}
	assertOnlyS3DiagnosticsAreRedacted(t, secretKey, presignSession, rootCapability, recipientReader)

	// Remove the sole selected chunk before B observes any root or metadata.
	// Refresh, Stat, and Open must still succeed because chunks are lazy.
	if err := store.Delete(ctx, firstChunkKey); err != nil {
		t.Fatal(err)
	}
	refresh, err := recipient.Refresh(ctx)
	if err != nil {
		t.Fatalf("recipient metadata refresh with missing chunk: %v", err)
	}
	if refresh.Status != s3disk.RefreshUpdated || refresh.Generation != 1 {
		t.Fatalf("first recipient refresh = %+v, want updated generation 1", refresh)
	}
	if _, err := recipient.Stat(ctx, selectedPath); err != nil {
		t.Fatalf("selected metadata with missing chunk: %v", err)
	}
	if _, err := recipient.Stat(ctx, hiddenPath); !errors.Is(err, s3disk.ErrPathNotFound) {
		t.Fatalf("hidden sibling Stat error = %v, want ErrPathNotFound", err)
	}
	missingFile, err := recipient.Open(ctx, selectedPath)
	if err != nil {
		t.Fatalf("open selected metadata with missing chunk: %v", err)
	}
	missingBuffer := make([]byte, missingFile.Size())
	if _, err := missingFile.ReadAtContext(ctx, missingBuffer, 0); !errors.Is(err, s3disk.ErrObjectNotFound) {
		t.Fatalf("missing lazy chunk error = %v, want ErrObjectNotFound", err)
	} else {
		assertErrorHasNoBearer(t, err, secretKey)
	}
	if _, err := store.PutIfAbsent(ctx, firstChunkKey, firstChunk.Data); err != nil {
		t.Fatalf("restore exact selected chunk: %v", err)
	}
	if got := readOnlyS3IntegrationFile(t, ctx, recipient, selectedPath); got != "selected generation one" {
		t.Fatalf("first lazy read = %q", got)
	}

	// A advances the selected projection and conditionally replaces the same S3
	// root object. B receives no second bearer and polls the original root URL.
	writeOnlyS3IntegrationFile(t, filepath.Join(source, selectedPath), "selected generation two")
	writeOnlyS3IntegrationFile(t, filepath.Join(source, hiddenPath), "still private and irrelevant")
	secondSnapshot, err := publisher.PublishSelected(ctx, source, channel, []string{selectedPath})
	if err != nil {
		t.Fatal(err)
	}
	if secondSnapshot.Generation != 2 {
		t.Fatalf("second generation = %d, want 2", secondSnapshot.Generation)
	}
	secondClosure, err := repository.ResolveSnapshotClosure(ctx, channel, s3disk.SnapshotClosureOptions{
		ReferenceVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondRoot, err := rootPublisher.Update(ctx, secondClosure)
	if err != nil {
		t.Fatal(err)
	}
	if !secondRoot.Updated || secondRoot.Revision != 2 || secondRoot.Snapshot != secondSnapshot {
		t.Fatalf("second root publication = %+v, want updated revision 2", secondRoot)
	}
	unchangedBearer, err := rootCapability.ExportBearer()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unchangedBearer, rootBearer) {
		t.Fatal("root bearer changed across an update of the same S3 root object")
	}
	refresh, err = recipient.Refresh(ctx)
	if err != nil {
		t.Fatalf("recipient generation-two refresh: %v", err)
	}
	if refresh.Status != s3disk.RefreshUpdated || refresh.Generation != 2 {
		t.Fatalf("second recipient refresh = %+v, want updated generation 2", refresh)
	}
	if got := readOnlyS3IntegrationFile(t, ctx, recipient, selectedPath); got != "selected generation two" {
		t.Fatalf("second lazy read = %q", got)
	}
	if _, err := recipient.Stat(ctx, hiddenPath); !errors.Is(err, s3disk.ErrPathNotFound) {
		t.Fatalf("updated hidden sibling Stat error = %v, want ErrPathNotFound", err)
	}

	// Restart B with no in-memory bundle or capabilities while preserving only
	// its durable generation-two watermark and the original handoff. Consumer
	// validates that watermark's ancestry before reading the mutable reference,
	// so Reader must bootstrap the same fixed S3 root on the first exact commit
	// GET. No A callback, credential, or replacement bearer is introduced.
	restartedReader, restartedRecipient := newOnlyS3Recipient(t, bootstrap, channel)
	if restartedReader == recipientReader {
		t.Fatal("restart unexpectedly reused the in-memory Reader")
	}
	refresh, err = restartedRecipient.Refresh(ctx)
	if err != nil {
		t.Fatalf("recipient restart from generation-two watermark: %v", err)
	}
	if refresh.Status != s3disk.RefreshUpdated || refresh.Generation != 2 {
		t.Fatalf("restarted recipient refresh = %+v, want updated generation 2", refresh)
	}
	if got := readOnlyS3IntegrationFile(t, ctx, restartedRecipient, selectedPath); got != "selected generation two" {
		t.Fatalf("restarted lazy read = %q", got)
	}
}

// TestMinIOOnlyS3EncryptedPresignedShare proves the strict-share-isolation
// profile against a real S3-compatible server. Raw S3 authority can observe
// and disrupt ciphertext, but B needs the separately handed-off share key to
// authenticate and decrypt the root, metadata, and lazily fetched chunk.
func TestMinIOOnlyS3EncryptedPresignedShare(t *testing.T) {
	endpoint := os.Getenv("S3DISK_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("S3DISK_TEST_S3_ENDPOINT is not set")
	}
	accessKey := envOr("S3DISK_TEST_S3_ACCESS_KEY", "s3disk")
	secretKey := envOr("S3DISK_TEST_S3_SECRET_KEY", "s3disk-secret")
	bucket := fmt.Sprintf("s3disk-encrypted-only-s3-%d", time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	createBucketWithRetry(t, ctx, endpoint, accessKey, secretKey, bucket)

	store, err := New(ctx, Config{
		Bucket: bucket, Region: "us-east-1", Endpoint: endpoint, UsePathStyle: true,
		CredentialsProvider: CredentialsProviderFunc(func(context.Context) (Credentials, error) {
			return Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	repositoryID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	shareKey, err := s3disk.GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := s3disk.NewClientEncryptionProfile(repositoryID, shareKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := s3disk.NewEd25519ReferenceSigner(repositoryID, "encrypted-minio", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := s3disk.NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{"encrypted-minio": publicKey})
	if err != nil {
		t.Fatal(err)
	}

	const (
		repositoryPrefix = "encrypted-share-isolation"
		channel          = "shared"
		rootKey          = "encrypted-share/root.bundle"
		selectedPath     = "shared/customer.txt"
		hiddenPath       = "shared/private.txt"
		selectedData     = "customer plaintext protected from leaked S3 credentials"
	)
	repository, err := s3disk.NewRepositoryWithOptions(store, repositoryPrefix, s3disk.RepositoryOptions{ClientEncryption: profile})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateIntegrationDirectory(t), "encrypted-publisher.journal"))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ReferenceSigner:                          signer, ReferenceVerifier: verifier,
		PublicationJournal: journal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	source := privateIntegrationDirectory(t)
	if err := os.MkdirAll(filepath.Join(source, "shared"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeOnlyS3IntegrationFile(t, filepath.Join(source, selectedPath), selectedData)
	writeOnlyS3IntegrationFile(t, filepath.Join(source, hiddenPath), "never included in the selected closure")
	snapshot, err := publisher.PublishSelected(ctx, source, channel, []string{selectedPath})
	if err != nil {
		t.Fatal(err)
	}
	closure, err := repository.ResolveSnapshotClosure(ctx, channel, s3disk.SnapshotClosureOptions{ReferenceVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	chunkKey := onlyChunkKey(t, closure.ObjectKeys)
	for _, objectKey := range closure.ObjectKeys {
		if !strings.Contains(objectKey, "/hmac-sha256/") || strings.Contains(objectKey, snapshot.Commit.String()) {
			t.Fatalf("encrypted physical key exposes a plaintext digest or wrong profile: %q", objectKey)
		}
	}
	rawChunk, err := store.Get(ctx, chunkKey, s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawChunk.Data, []byte(selectedData)) {
		t.Fatal("credentialed raw S3 GET exposed chunk plaintext")
	}

	expiry := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	presignSession, err := store.NewPresignSession(ctx, expiry)
	if err != nil {
		t.Fatal(err)
	}
	rootCapability, err := presignSession.PresignGet(ctx, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	shareID, err := presignedshare.GenerateShareID()
	if err != nil {
		t.Fatal(err)
	}
	rootPublisher, err := presignedshare.NewRootPublisher(presignedshare.RootPublisherConfig{
		Store: store, ClientEncryption: profile,
		RootKey: rootKey, RootCapability: rootCapability,
		RepositoryPrefix: repositoryPrefix, ReferenceKey: repository.SignedReferenceKey(channel),
		ShareID: shareID, Presigner: presignSession, Signer: signer, Verifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rootPublisher.CreatePublishedSnapshot(ctx, repository, channel, snapshot); err != nil {
		t.Fatal(err)
	}
	rawRoot, err := store.Get(ctx, rootKey, s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawRoot.Data, closure.ReferenceData) || bytes.Contains(rawRoot.Data, []byte(`"capabilities"`)) {
		t.Fatal("credentialed raw S3 GET exposed root metadata or bearer capabilities")
	}
	wrongShareKey, err := s3disk.GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	wrongProfile, err := s3disk.NewClientEncryptionProfile(repositoryID, wrongShareKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongProfile.OpenObject(rootKey, rawRoot.Data); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("wrong private seed opened credential-readable root: %v", err)
	}

	rootBearer, err := rootCapability.ExportBearer()
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := onlyS3RecipientBootstrap{
		RootBearer: append([]byte(nil), rootBearer...), RepositoryPrefix: repositoryPrefix,
		ReferenceKey: repository.SignedReferenceKey(channel), ShareID: shareID,
		Verifier: verifier, ClientEncryption: profile,
		Checkpoint:            s3disk.Watermark{RepositoryID: repositoryID, Generation: snapshot.Generation, Commit: snapshot.Commit},
		WatermarkPath:         filepath.Join(privateIntegrationDirectory(t), "encrypted-recipient.watermark"),
		AllowInsecureLoopback: true,
	}
	reader, recipient := newOnlyS3Recipient(t, bootstrap, channel)
	assertOnlyS3DiagnosticsAreRedacted(t, shareKey.ExportSecret(), profile, reader)

	// Metadata refresh does not require the selected chunk. Removing it proves
	// the recipient still performs a genuinely lazy encrypted data read.
	if err := store.Delete(ctx, chunkKey); err != nil {
		t.Fatal(err)
	}
	if _, err := recipient.Refresh(ctx); err != nil {
		t.Fatalf("encrypted metadata refresh with missing chunk: %v", err)
	}
	if _, err := recipient.Stat(ctx, hiddenPath); !errors.Is(err, s3disk.ErrPathNotFound) {
		t.Fatalf("hidden encrypted path error = %v, want ErrPathNotFound", err)
	}
	file, err := recipient.Open(ctx, selectedPath)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, file.Size())
	if _, err := file.ReadAtContext(ctx, buffer, 0); !errors.Is(err, s3disk.ErrObjectNotFound) {
		t.Fatalf("missing encrypted lazy chunk error = %v", err)
	}
	if _, err := store.PutIfAbsent(ctx, chunkKey, rawChunk.Data); err != nil {
		t.Fatal(err)
	}
	if got := readOnlyS3IntegrationFile(t, ctx, recipient, selectedPath); got != selectedData {
		t.Fatalf("encrypted lazy read = %q", got)
	}
}

// onlyS3RecipientBootstrap is the complete A-to-B handoff. Verifier contains
// public keys only. In particular this type cannot carry s3store.Store,
// Credentials, CredentialsProvider, ReferenceSigner, or an A-side callback.
type onlyS3RecipientBootstrap struct {
	RootBearer            []byte
	RepositoryPrefix      string
	ReferenceKey          string
	ShareID               presignedshare.ShareID
	Verifier              s3disk.ReferenceVerifier
	ClientEncryption      *s3disk.ClientEncryptionProfile
	Checkpoint            s3disk.Watermark
	WatermarkPath         string
	AllowInsecureLoopback bool
}

func newOnlyS3Recipient(
	t *testing.T,
	bootstrap onlyS3RecipientBootstrap,
	channel string,
) (*presignedshare.Reader, *s3disk.Consumer) {
	t.Helper()
	rootCapability, err := presignedshare.ParseBearer(bootstrap.RootBearer, presignedshare.CapabilityOptions{
		AllowInsecureLoopback: bootstrap.AllowInsecureLoopback,
	})
	if err != nil {
		t.Fatal("parse recipient root bearer")
	}
	reader, err := presignedshare.NewReader(presignedshare.ReaderConfig{
		RootCapability: rootCapability, RepositoryPrefix: bootstrap.RepositoryPrefix,
		ReferenceKey: bootstrap.ReferenceKey, ShareID: bootstrap.ShareID, Verifier: bootstrap.Verifier,
		ClientEncryption:      bootstrap.ClientEncryption,
		AllowInsecureLoopback: bootstrap.AllowInsecureLoopback,
	})
	if err != nil {
		t.Fatalf("construct recipient reader: %v", err)
	}
	repository, err := s3disk.NewReadOnlyRepositoryWithOptions(reader, bootstrap.RepositoryPrefix, s3disk.RepositoryOptions{
		ClientEncryption: bootstrap.ClientEncryption,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bootstrap.WatermarkPath == "" {
		t.Fatal("recipient bootstrap watermark path is required")
	}
	watermarks, err := s3disk.NewFileWatermarkStore(bootstrap.WatermarkPath)
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, channel, s3disk.ConsumerOptions{
		Watermarks: watermarks, RequirePersistentWatermark: true,
		ReferenceVerifier: bootstrap.Verifier, TrustedCheckpoint: &bootstrap.Checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	return reader, consumer
}

func onlyChunkKey(t *testing.T, keys []string) string {
	t.Helper()
	var chunkKeys []string
	for _, key := range keys {
		if strings.Contains(key, "/objects/chunk/") {
			chunkKeys = append(chunkKeys, key)
		}
	}
	if len(chunkKeys) != 1 {
		t.Fatalf("selected closure has %d chunk keys, want exactly 1", len(chunkKeys))
	}
	return chunkKeys[0]
}

func writeOnlyS3IntegrationFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readOnlyS3IntegrationFile(t *testing.T, ctx context.Context, consumer *s3disk.Consumer, path string) string {
	t.Helper()
	file, err := consumer.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, file.Size())
	if _, err := file.ReadAtContext(ctx, data, 0); err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	return string(data)
}

func assertOnlyS3DiagnosticsAreRedacted(
	t *testing.T,
	secretKey string,
	values ...any,
) {
	t.Helper()
	for _, value := range values {
		diagnostic := fmt.Sprintf("%v | %+v | %#v", value, value, value)
		if strings.Contains(diagnostic, secretKey) ||
			strings.Contains(strings.ToLower(diagnostic), "x-amz-signature") ||
			strings.Contains(strings.ToLower(diagnostic), "x-amz-credential") {
			t.Fatal("ordinary diagnostics exposed presigned bearer or credential material")
		}
	}
}

func assertErrorHasNoBearer(t *testing.T, err error, secretKey string) {
	t.Helper()
	diagnostic := err.Error()
	if strings.Contains(diagnostic, secretKey) ||
		strings.Contains(strings.ToLower(diagnostic), "x-amz-signature") ||
		strings.Contains(strings.ToLower(diagnostic), "x-amz-credential") {
		t.Fatal("classified recipient error exposed bearer or credential material")
	}
}
