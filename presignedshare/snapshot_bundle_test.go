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
	"reflect"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestBuildSnapshotBundlePresignsExactlyResolvedClosure(t *testing.T) {
	fixture := newSnapshotBundleFixture(t)
	encoded, err := BuildSnapshotBundle(context.Background(), fixture.input, fixture.signer, fixture.verifier)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fixture.presigner.keys, fixture.input.Closure.ObjectKeys) {
		t.Fatalf("presigned keys = %q, want exact closure %q", fixture.presigner.keys, fixture.input.Closure.ObjectKeys)
	}
	bundle, err := Decode(context.Background(), encoded, fixture.verifier, DecodeOptions{
		RootCapability: fixture.input.RootCapability, RepositoryPrefix: fixture.input.RepositoryPrefix,
		ReferenceKey: fixture.input.Closure.ReferenceKey, ShareID: fixture.input.ShareID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bundle.CapabilityCount() != len(fixture.input.Closure.ObjectKeys) ||
		bundle.ReferenceGeneration() != fixture.input.Closure.Snapshot.Generation ||
		bundle.ReferenceCommit() != fixture.input.Closure.Snapshot.Commit {
		t.Fatalf("bundle identity/count = %d/%d/%s", bundle.CapabilityCount(), bundle.ReferenceGeneration(), bundle.ReferenceCommit())
	}
}

func TestBuildSnapshotBundleRejectsModifiedClosureBeforePresigning(t *testing.T) {
	fixture := newSnapshotBundleFixture(t)
	fixture.input.Closure.ObjectKeys = append(append([]string(nil), fixture.input.Closure.ObjectKeys...),
		"repo/.s3disk/v1/objects/chunk/sha256/aa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	_, err := BuildSnapshotBundle(context.Background(), fixture.input, fixture.signer, fixture.verifier)
	if !errors.Is(err, s3disk.ErrInvalidSnapshotClosure) {
		t.Fatalf("modified closure error = %v, want ErrInvalidSnapshotClosure", err)
	}
	if len(fixture.presigner.keys) != 0 {
		t.Fatalf("modified closure presigned keys: %q", fixture.presigner.keys)
	}
}

func TestBuildSnapshotBundleRejectsMismatchedPresignerResult(t *testing.T) {
	fixture := newSnapshotBundleFixture(t)
	fixture.presigner.returnWrongKey = true
	if _, err := BuildSnapshotBundle(context.Background(), fixture.input, fixture.signer, fixture.verifier); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("mismatched presigner error = %v, want ErrInvalidBundle", err)
	}
}

type snapshotBundleFixture struct {
	input     SnapshotBundleInput
	presigner *recordingExactPresigner
	signer    s3disk.ReferenceSigner
	verifier  s3disk.ReferenceVerifier
}

func newSnapshotBundleFixture(t *testing.T) snapshotBundleFixture {
	t.Helper()
	ctx := context.Background()
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "repo")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "shared.txt"), []byte("shared"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishSelected(ctx, source, "main", []string{"shared.txt"}); err != nil {
		t.Fatal(err)
	}
	closure, err := repository.ResolveSnapshotClosure(ctx, "main", s3disk.SnapshotClosureOptions{})
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
	signer, err := s3disk.NewEd25519ReferenceSigner(repositoryID, "snapshot-bundle", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := s3disk.NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{"snapshot-bundle": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	rootKey := "shares/test/root"
	root, err := newTestCapability(rootKey, "https://objects.example.test/bucket/share-root?signature=root", nil, expiry, CapabilityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	shareID, err := GenerateShareID()
	if err != nil {
		t.Fatal(err)
	}
	presigner := &recordingExactPresigner{expiry: expiry}
	return snapshotBundleFixture{
		input: SnapshotBundleInput{
			RootKey: rootKey, RootCapability: root, RepositoryPrefix: "repo",
			ShareID: shareID, Revision: 1, Closure: closure, Presigner: presigner,
		},
		presigner: presigner, signer: signer, verifier: verifier,
	}
}

type recordingExactPresigner struct {
	expiry         time.Time
	keys           []string
	returnWrongKey bool
}

func (presigner *recordingExactPresigner) AuthorizationExpiry() (time.Time, bool) {
	return presigner.expiry, true
}

func (presigner *recordingExactPresigner) PresignGet(_ context.Context, key string) (Capability, error) {
	presigner.keys = append(presigner.keys, key)
	exactKey := key
	if presigner.returnWrongKey {
		exactKey += "-wrong"
	}
	return newTestCapability(
		exactKey,
		fmt.Sprintf("https://objects.example.test/bucket/object-%d?signature=secret", len(presigner.keys)),
		http.Header{},
		presigner.expiry,
		CapabilityOptions{},
	)
}
