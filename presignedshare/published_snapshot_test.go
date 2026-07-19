package presignedshare

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestRootPublisherPublishedSnapshotBindsAuthenticatedObservation(t *testing.T) {
	fixture := newPublishedSnapshotFixture(t)
	first := fixture.publish(t, "one")

	created, err := fixture.rootPublisher.CreatePublishedSnapshot(
		context.Background(), fixture.repository, fixture.channel, first,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !created.Updated || created.Revision != 1 || !samePublishedSnapshot(created.Snapshot, first) {
		t.Fatalf("created root = %+v", created)
	}

	second := fixture.publish(t, "two")
	before := fixture.presigner.callCount()
	if _, err := fixture.rootPublisher.UpdatePublishedSnapshot(
		context.Background(), fixture.repository, fixture.channel, first,
	); !errors.Is(err, s3disk.ErrPublishConflict) {
		t.Fatalf("stale expected snapshot error = %v, want ErrPublishConflict", err)
	}
	if calls := fixture.presigner.callCount(); calls != before {
		t.Fatalf("mismatched expected snapshot minted %d capabilities", calls-before)
	}
	if bundle := fixture.loadRoot(t); bundle.Revision() != 1 || bundle.ReferenceCommit() != first.Commit {
		t.Fatalf("mismatched expected snapshot changed root: %s", bundle)
	}

	updated, err := fixture.rootPublisher.UpdatePublishedSnapshot(
		context.Background(), fixture.repository, fixture.channel, second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.Updated || updated.Revision != 2 || !samePublishedSnapshot(updated.Snapshot, second) {
		t.Fatalf("updated root = %+v", updated)
	}
	if bundle := fixture.loadRoot(t); bundle.Revision() != 2 || bundle.ReferenceCommit() != second.Commit {
		t.Fatalf("updated bundle = %s", bundle)
	}
}

func TestRootPublisherPublishedSnapshotNeverFallsBackToUnsignedReference(t *testing.T) {
	fixture := newPublishedSnapshotFixture(t)
	signedSnapshot := fixture.publish(t, "signed")
	if _, err := fixture.rootPublisher.CreatePublishedSnapshot(
		context.Background(), fixture.repository, fixture.channel, signedSnapshot,
	); err != nil {
		t.Fatal(err)
	}

	// The same Store and prefix also contain an attacker-controlled unsigned
	// channel. The safe helper always resolves signed-refs/v1 with its configured
	// verifier and therefore cannot turn this value into a signed root bundle.
	unsignedRepository, err := s3disk.NewRepository(fixture.store, fixture.prefix)
	if err != nil {
		t.Fatal(err)
	}
	unsignedPublisher, err := s3disk.NewPublisher(unsignedRepository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	attackerSource := t.TempDir()
	if err := os.WriteFile(filepath.Join(attackerSource, "shared.txt"), []byte("attacker"), 0o600); err != nil {
		t.Fatal(err)
	}
	unsignedSnapshot, err := unsignedPublisher.PublishSelected(
		context.Background(), attackerSource, fixture.channel, []string{"shared.txt"},
	)
	if err != nil {
		t.Fatal(err)
	}
	before := fixture.presigner.callCount()
	_, err = fixture.rootPublisher.UpdatePublishedSnapshot(
		context.Background(), unsignedRepository, fixture.channel, unsignedSnapshot,
	)
	if !errors.Is(err, s3disk.ErrPublishConflict) {
		t.Fatalf("unsigned snapshot error = %v, want authenticated observation conflict", err)
	}
	if calls := fixture.presigner.callCount(); calls != before {
		t.Fatalf("unsigned snapshot minted %d capabilities", calls-before)
	}
	if bundle := fixture.loadRoot(t); bundle.ReferenceCommit() != signedSnapshot.Commit {
		t.Fatalf("unsigned reference changed root: %s", bundle)
	}
}

func TestRootPublisherPublishedSnapshotRejectsIncompleteIdentityBeforeStoreIO(t *testing.T) {
	fixture := newPublishedSnapshotFixture(t)
	fixture.store.ResetStats()
	_, err := fixture.rootPublisher.CreatePublishedSnapshot(
		context.Background(), fixture.repository, fixture.channel, s3disk.Snapshot{},
	)
	if !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("incomplete snapshot error = %v, want ErrInvalidBundle", err)
	}
	stats := fixture.store.Stats()
	if stats.Gets != 0 || stats.Puts != 0 || stats.Heads != 0 || stats.BytesRead != 0 || stats.BytesWritten != 0 {
		t.Fatalf("incomplete snapshot performed Store I/O: %+v", stats)
	}
}

func TestSafePublishedSnapshotErrorPreservesMissingBucketWithoutProviderDetails(t *testing.T) {
	const secret = "https://provider.invalid/bucket?X-Amz-Signature=resolve-secret"
	err := safePublishedSnapshotError(fmt.Errorf("provider rejected %s: %w", secret, s3disk.ErrBucketNotFound))
	if !errors.Is(err, s3disk.ErrBucketNotFound) {
		t.Fatalf("safe published-snapshot error = %v, want ErrBucketNotFound", err)
	}
	if errors.Is(err, s3disk.ErrStoreUnavailable) {
		t.Fatalf("missing bucket was degraded to a transient Store error: %v", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "resolve-secret") {
		t.Fatalf("safe published-snapshot error leaked provider detail: %v", err)
	}
}

func TestRootPublisherPublishedSnapshotRejectsRepositoryEncryptionMismatch(t *testing.T) {
	fixture := newPublishedSnapshotFixture(t)
	snapshot := fixture.publish(t, "plaintext repository")
	key, err := s3disk.GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := s3disk.NewClientEncryptionProfile(fixture.verifier.RepositoryID(), key)
	if err != nil {
		t.Fatal(err)
	}
	rootPublisher, err := NewRootPublisher(RootPublisherConfig{
		Store: fixture.store, ClientEncryption: profile,
		RootKey: fixture.rootKey, RootCapability: fixture.rootCapability,
		RepositoryPrefix: fixture.prefix, ReferenceKey: fixture.repository.SignedReferenceKey(fixture.channel),
		ShareID: fixture.shareID, Presigner: fixture.presigner, Signer: fixture.signer, Verifier: fixture.verifier,
	})
	if err != nil {
		t.Fatal(err)
	}

	before := fixture.presigner.callCount()
	for _, operation := range []struct {
		name string
		run  func() (RootPublication, error)
	}{
		{name: "CreatePublishedSnapshot", run: func() (RootPublication, error) {
			return rootPublisher.CreatePublishedSnapshot(context.Background(), fixture.repository, fixture.channel, snapshot)
		}},
		{name: "UpdatePublishedSnapshot", run: func() (RootPublication, error) {
			return rootPublisher.UpdatePublishedSnapshot(context.Background(), fixture.repository, fixture.channel, snapshot)
		}},
	} {
		t.Run(operation.name, func(t *testing.T) {
			if _, err := operation.run(); !errors.Is(err, s3disk.ErrInvalidSnapshotClosure) {
				t.Fatalf("%s encryption mismatch error = %v, want ErrInvalidSnapshotClosure", operation.name, err)
			}
		})
	}
	if calls := fixture.presigner.callCount(); calls != before {
		t.Fatalf("high-level encryption mismatch minted %d capabilities", calls-before)
	}
	if _, err := fixture.store.Get(context.Background(), fixture.rootKey, s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrObjectNotFound) {
		t.Fatalf("high-level encryption mismatch wrote a share root: %v", err)
	}
}

type publishedSnapshotFixture struct {
	store          *memstore.Store
	repository     *s3disk.Repository
	publisher      *s3disk.Publisher
	rootPublisher  *RootPublisher
	presigner      *publishedSnapshotPresigner
	signer         s3disk.ReferenceSigner
	verifier       s3disk.ReferenceVerifier
	source         string
	prefix         string
	channel        string
	rootKey        string
	rootCapability Capability
	shareID        ShareID
}

func newPublishedSnapshotFixture(t *testing.T) *publishedSnapshotFixture {
	t.Helper()
	const (
		prefix  = "published-snapshot-repo"
		channel = "main"
		rootKey = "shares/published-snapshot/root"
	)
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, prefix)
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
	signer, err := s3disk.NewEd25519ReferenceSigner(repositoryID, "published-snapshot", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := s3disk.NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{
		"published-snapshot": publicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := s3disk.NewFilePublicationJournal(filepath.Join(t.TempDir(), "publisher.journal"))
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
	expiresAt := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	rootCapability, err := newTestCapability(
		rootKey,
		"https://objects.example.test/bucket/published-root?X-Amz-Signature=root-secret",
		nil,
		expiresAt,
		CapabilityOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	shareID, err := GenerateShareID()
	if err != nil {
		t.Fatal(err)
	}
	presigner := &publishedSnapshotPresigner{expiresAt: expiresAt}
	rootPublisher, err := NewRootPublisher(RootPublisherConfig{
		Store: store, RootKey: rootKey, RootCapability: rootCapability,
		RepositoryPrefix: prefix, ReferenceKey: repository.SignedReferenceKey(channel),
		ShareID: shareID, Presigner: presigner, Signer: signer, Verifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &publishedSnapshotFixture{
		store: store, repository: repository, publisher: publisher,
		rootPublisher: rootPublisher, presigner: presigner, signer: signer, verifier: verifier,
		source: t.TempDir(), prefix: prefix, channel: channel, rootKey: rootKey,
		rootCapability: rootCapability, shareID: shareID,
	}
}

func (fixture *publishedSnapshotFixture) publish(t *testing.T, contents string) s3disk.Snapshot {
	t.Helper()
	if err := os.WriteFile(filepath.Join(fixture.source, "shared.txt"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := fixture.publisher.PublishSelected(
		context.Background(), fixture.source, fixture.channel, []string{"shared.txt"},
	)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func (fixture *publishedSnapshotFixture) loadRoot(t *testing.T) *Bundle {
	t.Helper()
	object, err := fixture.store.Get(context.Background(), fixture.rootKey, s3disk.GetOptions{MaxBytes: MaximumBundleBytes})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Decode(context.Background(), object.Data, fixture.verifier, DecodeOptions{
		RootCapability: fixture.rootCapability, RepositoryPrefix: fixture.prefix,
		ReferenceKey: fixture.repository.SignedReferenceKey(fixture.channel), ShareID: fixture.shareID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

type publishedSnapshotPresigner struct {
	mu        sync.Mutex
	expiresAt time.Time
	calls     int
}

func (presigner *publishedSnapshotPresigner) AuthorizationExpiry() (time.Time, bool) {
	if presigner == nil {
		return time.Time{}, false
	}
	return presigner.expiresAt, true
}

func (presigner *publishedSnapshotPresigner) PresignGet(_ context.Context, key string) (Capability, error) {
	presigner.mu.Lock()
	defer presigner.mu.Unlock()
	presigner.calls++
	return newTestCapability(
		key,
		fmt.Sprintf("https://objects.example.test/bucket/object-%d?X-Amz-Signature=secret", presigner.calls),
		http.Header{},
		presigner.expiresAt,
		CapabilityOptions{},
	)
}

func (presigner *publishedSnapshotPresigner) callCount() int {
	presigner.mu.Lock()
	defer presigner.mu.Unlock()
	return presigner.calls
}
