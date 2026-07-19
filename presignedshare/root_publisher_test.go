package presignedshare

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestRootPublisherCreateIdempotentAndUpdate(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	first := fixture.publish(t, "one")
	publisher := fixture.newPublisher(t, fixture.base, 0)

	created, err := publisher.Create(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	if !created.Updated || created.Revision != 1 || created.Snapshot != first.Snapshot || created.Version.ETag == "" {
		t.Fatalf("created publication = %+v", created)
	}
	presignedAfterCreate := fixture.presigner.callCount()

	idempotent, err := publisher.Create(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	if idempotent.Updated || idempotent.Revision != 1 || idempotent.Snapshot != first.Snapshot || idempotent.Version != created.Version {
		t.Fatalf("idempotent publication = %+v, created = %+v", idempotent, created)
	}
	if calls := fixture.presigner.callCount(); calls != presignedAfterCreate {
		t.Fatalf("idempotent Create made %d additional presign calls", calls-presignedAfterCreate)
	}

	second := fixture.publish(t, "two")
	updated, err := publisher.Update(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.Updated || updated.Revision != 2 || updated.Snapshot != second.Snapshot || updated.Version.ETag == created.Version.ETag {
		t.Fatalf("updated publication = %+v", updated)
	}
	bundle := fixture.loadRoot(t)
	if bundle.Revision() != 2 || bundle.ReferenceGeneration() != second.Snapshot.Generation ||
		bundle.ReferenceCommit() != second.Snapshot.Commit || bundle.CapabilityCount() != len(second.ObjectKeys) {
		t.Fatalf("installed root = %s", bundle)
	}
}

func TestRootPublisherCreateRejectsDifferentExistingRoot(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	first := fixture.publish(t, "one")
	publisher := fixture.newPublisher(t, fixture.base, 0)
	if _, err := publisher.Create(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := fixture.publish(t, "two")
	before := fixture.presigner.callCount()

	_, err := publisher.Create(context.Background(), second)
	if !errors.Is(err, ErrRootPublishConflict) {
		t.Fatalf("second Create error = %v, want ErrRootPublishConflict", err)
	}
	if calls := fixture.presigner.callCount(); calls != before {
		t.Fatalf("conflicting Create made %d presign calls", calls-before)
	}
	if got := fixture.loadRoot(t); got.Revision() != 1 || got.ReferenceCommit() != first.Snapshot.Commit {
		t.Fatalf("conflicting Create changed root: %s", got)
	}
}

func TestRootPublisherReferenceVersionChangeAdvancesRevision(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	first := fixture.publish(t, "one")
	publisher := fixture.newPublisher(t, fixture.base, 0)
	if _, err := publisher.Create(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	// Reinstall the exact canonical reference bytes as a new S3 observation.
	// The snapshot identity is unchanged, but the sealed closure and bundle must
	// retain the new ETag/VersionID instead of treating it as exact idempotence.
	fixture.base.ForcePut(fixture.referenceKey, first.ReferenceData)
	rewritten, err := fixture.repository.ResolveSnapshotClosure(context.Background(), "main", s3disk.SnapshotClosureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rewritten.Snapshot != first.Snapshot || !bytes.Equal(rewritten.ReferenceData, first.ReferenceData) ||
		rewritten.ReferenceVersion == first.ReferenceVersion {
		t.Fatalf("rewritten reference fixture did not retain identity and change version: old=%+v new=%+v", first, rewritten)
	}

	publication, err := publisher.Update(context.Background(), rewritten)
	if err != nil {
		t.Fatal(err)
	}
	if !publication.Updated || publication.Revision != 2 {
		t.Fatalf("rewritten reference publication = %+v, want updated revision 2", publication)
	}
	if got := fixture.loadRoot(t).Reference().Version; got != rewritten.ReferenceVersion {
		t.Fatalf("root embedded reference version = %+v, want %+v", got, rewritten.ReferenceVersion)
	}
}

func TestRootPublisherUpdateMissingRootIsRollbackAndDoesNotWrite(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	first := fixture.publish(t, "one")
	publisher := fixture.newPublisher(t, fixture.base, 0)
	if _, err := publisher.Create(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := fixture.base.Delete(context.Background(), fixture.rootKey); err != nil {
		t.Fatal(err)
	}
	fixture.base.ResetStats()
	before := fixture.presigner.callCount()

	_, err := publisher.Update(context.Background(), first)
	if !errors.Is(err, s3disk.ErrRollbackDetected) {
		t.Fatalf("Update after root deletion error = %v, want ErrRollbackDetected", err)
	}
	stats := fixture.base.Stats()
	if stats.Gets != 0 || stats.Puts != 0 || stats.BytesWritten != 0 {
		// Missing memstore GETs are intentionally not counted, so zero Gets is
		// expected; Puts/BytesWritten are the important no-recreation proof.
		t.Fatalf("Update after deletion store stats = %+v", stats)
	}
	if calls := fixture.presigner.callCount(); calls != before {
		t.Fatalf("Update after deletion made %d presign calls", calls-before)
	}
	if _, err := fixture.base.Get(context.Background(), fixture.rootKey, s3disk.GetOptions{MaxBytes: MaximumBundleBytes}); !errors.Is(err, s3disk.ErrObjectNotFound) {
		t.Fatalf("deleted root was recreated: %v", err)
	}
}

func TestRootPublisherReconcilesAppliedCreateAndUpdateAfterLostResponses(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		fixture := newRootPublisherFixture(t)
		closure := fixture.publish(t, "one")
		store := &rootPublisherFaultStore{base: fixture.base, losePutResponse: true}
		publisher := fixture.newPublisher(t, store, 0)

		publication, err := publisher.Create(context.Background(), closure)
		if err != nil {
			t.Fatal(err)
		}
		if !publication.Updated || publication.Revision != 1 || publication.Version.ETag == "" {
			t.Fatalf("reconciled create = %+v", publication)
		}
		if calls := store.putCalls.Load(); calls != 1 {
			t.Fatalf("PutIfAbsent calls = %d, want 1", calls)
		}
	})

	t.Run("update", func(t *testing.T) {
		fixture := newRootPublisherFixture(t)
		first := fixture.publish(t, "one")
		creator := fixture.newPublisher(t, fixture.base, 0)
		if _, err := creator.Create(context.Background(), first); err != nil {
			t.Fatal(err)
		}
		second := fixture.publish(t, "two")
		store := &rootPublisherFaultStore{base: fixture.base, loseCASResponse: true}
		publisher := fixture.newPublisher(t, store, 0)

		publication, err := publisher.Update(context.Background(), second)
		if err != nil {
			t.Fatal(err)
		}
		if !publication.Updated || publication.Revision != 2 || publication.Version.ETag == "" {
			t.Fatalf("reconciled update = %+v", publication)
		}
		if calls := store.casCalls.Load(); calls != 1 {
			t.Fatalf("CompareAndSwap calls = %d, want 1", calls)
		}
	})
}

func TestRootPublisherRetriesAfterConcurrentPreconditionWinner(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	first := fixture.publish(t, "one")
	creator := fixture.newPublisher(t, fixture.base, 0)
	created, err := creator.Create(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	second := fixture.publish(t, "two")
	third := fixture.publish(t, "three")
	competingRoot, err := BuildSnapshotBundle(context.Background(), SnapshotBundleInput{
		RootKey: fixture.rootKey, RootCapability: fixture.rootCapability,
		RepositoryPrefix: fixture.repositoryPrefix, ShareID: fixture.shareID,
		Revision: 2, Closure: second, Presigner: fixture.presigner,
	}, fixture.signer, fixture.verifier)
	if err != nil {
		t.Fatal(err)
	}
	store := &rootPublisherFaultStore{base: fixture.base, competingRoot: competingRoot}
	publisher := fixture.newPublisher(t, store, 0)

	publication, err := publisher.Update(context.Background(), third)
	if err != nil {
		t.Fatal(err)
	}
	if !publication.Updated || publication.Revision != 3 || publication.Snapshot != third.Snapshot {
		t.Fatalf("publication after competing winner = %+v", publication)
	}
	if calls := store.casCalls.Load(); calls != 2 {
		t.Fatalf("CompareAndSwap calls = %d, want 2", calls)
	}
	if store.competingError != nil {
		t.Fatalf("install competing root: %v", store.competingError)
	}
	if created.Version.ETag == publication.Version.ETag {
		t.Fatal("root version did not advance")
	}
	if got := fixture.loadRoot(t); got.Revision() != 3 || got.ReferenceCommit() != third.Snapshot.Commit {
		t.Fatalf("final root = %s", got)
	}
}

func TestRootPublisherRejectsRollbackAndSplitBrain(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	first := fixture.publish(t, "one")
	publisher := fixture.newPublisher(t, fixture.base, 0)
	if _, err := publisher.Create(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := fixture.publish(t, "two")
	if _, err := publisher.Update(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	if _, err := publisher.Update(context.Background(), first); !errors.Is(err, s3disk.ErrRollbackDetected) {
		t.Fatalf("older closure error = %v, want ErrRollbackDetected", err)
	}
	divergent := independentClosureAtGeneration(t, fixture.repositoryPrefix, 2, "divergent")
	if divergent.Snapshot.Generation != second.Snapshot.Generation || divergent.Snapshot.Commit == second.Snapshot.Commit {
		t.Fatalf("bad divergent fixture: current=%+v divergent=%+v", second.Snapshot, divergent.Snapshot)
	}
	if _, err := publisher.Update(context.Background(), divergent); !errors.Is(err, s3disk.ErrSplitBrain) {
		t.Fatalf("same-generation divergent closure error = %v, want ErrSplitBrain", err)
	}
	if got := fixture.loadRoot(t); got.Revision() != 2 || got.ReferenceCommit() != second.Snapshot.Commit {
		t.Fatalf("rejected rollback/split-brain changed root: %s", got)
	}
}

func TestRootPublisherErrorsRedactStoreAndCapabilityURLs(t *testing.T) {
	const secretURL = "https://objects.example.test/bucket/root?X-Amz-Credential=AKIASECRET&X-Amz-Signature=super-secret"

	t.Run("initial read", func(t *testing.T) {
		fixture := newRootPublisherFixture(t)
		closure := fixture.publish(t, "one")
		store := &rootPublisherFaultStore{
			base:     fixture.base,
			getError: fmt.Errorf("provider GET %s: %w", secretURL, s3disk.ErrAccessDenied),
		}
		publisher := fixture.newPublisher(t, store, 0)
		_, err := publisher.Create(context.Background(), closure)
		if !errors.Is(err, s3disk.ErrAccessDenied) {
			t.Fatalf("read error = %v, want ErrAccessDenied", err)
		}
		assertNoRootSecret(t, err, secretURL)
	})

	t.Run("ambiguous write and failed reconciliation", func(t *testing.T) {
		fixture := newRootPublisherFixture(t)
		closure := fixture.publish(t, "one")
		store := &rootPublisherFaultStore{
			base:              fixture.base,
			putError:          fmt.Errorf("provider PUT %s failed", secretURL),
			getErrorAfterCall: 1,
			getError:          fmt.Errorf("provider GET %s failed", secretURL),
		}
		publisher := fixture.newPublisher(t, store, 0)
		_, err := publisher.Create(context.Background(), closure)
		if !errors.Is(err, ErrRootPublishIndeterminate) {
			t.Fatalf("ambiguous error = %v, want ErrRootPublishIndeterminate", err)
		}
		assertNoRootSecret(t, err, secretURL)
	})

	t.Run("presigner", func(t *testing.T) {
		fixture := newRootPublisherFixture(t)
		closure := fixture.publish(t, "one")
		config := fixture.config(fixture.base, 0)
		config.Presigner = &failingRootPresigner{
			expiry: fixture.expiry,
			err:    fmt.Errorf("presign provider returned %s", secretURL),
		}
		publisher, err := NewRootPublisher(config)
		if err != nil {
			t.Fatal(err)
		}
		_, err = publisher.Create(context.Background(), closure)
		if !errors.Is(err, s3disk.ErrStoreMisconfigured) {
			t.Fatalf("presigner error = %v, want ErrStoreMisconfigured", err)
		}
		assertNoRootSecret(t, err, secretURL)
	})
}

func TestRootPublisherSerializationWaitIsContextCancellable(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	closure := fixture.publish(t, "one")
	store := &rootPublisherFaultStore{base: fixture.base}
	publisher := fixture.newPublisher(t, store, 0)

	// Hold the private gate exactly as an in-flight publication would. No Store
	// operation should start while the second caller waits for this token.
	<-publisher.gate
	baseContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &observableCancelContext{Context: baseContext, waiting: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, err := publisher.Create(ctx, closure)
		result <- err
	}()
	select {
	case <-ctx.waiting:
	case <-time.After(time.Second):
		publisher.gate <- struct{}{}
		t.Fatal("Create did not reach the serialization gate")
	}
	cancel()
	var err error
	select {
	case err = <-result:
	case <-time.After(time.Second):
		publisher.gate <- struct{}{}
		t.Fatal("Create did not return after cancellation")
	}
	publisher.gate <- struct{}{}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting Create error = %v, want context cancellation", err)
	}
	if calls := store.getCalls.Load(); calls != 0 {
		t.Fatalf("waiting Create made %d Store.Get calls", calls)
	}
}

func TestRootPublisherCanceledReconciliationRemainsIndeterminate(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	closure := fixture.publish(t, "one")
	store := &cancelingRootWriteStore{base: fixture.base}
	publisher := fixture.newPublisher(t, store, 0)
	ctx, cancel := context.WithCancel(context.Background())
	store.cancel = cancel

	_, err := publisher.Create(ctx, closure)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrRootPublishIndeterminate) {
		t.Fatalf("canceled reconciliation error = %v, want context.Canceled and ErrRootPublishIndeterminate", err)
	}
}

func TestRootPublisherExpiredAuthorizationDoesNotPerformStoreIO(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	closure := fixture.publish(t, "one")
	store := &rootPublisherFaultStore{base: fixture.base}
	publisher := fixture.newPublisher(t, store, 0)
	// The value was safely minted and validated by NewRootPublisher. Advancing
	// its private deadline models the wall clock moving past the fixed share
	// deadline without relying on a timing-sensitive sleep.
	publisher.rootCapability.expiresAt = time.Now().Add(-time.Second)

	_, err := publisher.Create(context.Background(), closure)
	if !errors.Is(err, s3disk.ErrAccessDenied) {
		t.Fatalf("expired Create error = %v, want ErrAccessDenied", err)
	}
	if store.getCalls.Load()+store.headCalls.Load()+store.putCalls.Load()+store.casCalls.Load() != 0 {
		t.Fatalf("expired Create performed Store I/O: get=%d head=%d put=%d cas=%d",
			store.getCalls.Load(), store.headCalls.Load(), store.putCalls.Load(), store.casCalls.Load())
	}
}

func TestNewRootPublisherRejectsRootProtocolObjectCollisionWithoutStoreIO(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	closure := fixture.publish(t, "one")
	store := &rootPublisherFaultStore{base: fixture.base}
	for _, rootKey := range []string{fixture.referenceKey, closure.ObjectKeys[0]} {
		rootCapability, err := newTestCapability(
			rootKey,
			"https://objects.example.test/bucket/collision?X-Amz-Signature=root-secret",
			nil,
			fixture.expiry,
			CapabilityOptions{},
		)
		if err != nil {
			t.Fatal(err)
		}
		config := fixture.config(store, 0)
		config.RootKey = rootKey
		config.RootCapability = rootCapability
		if _, err := NewRootPublisher(config); !errors.Is(err, ErrInvalidBundle) {
			t.Fatalf("protocol-colliding root %q error = %v, want ErrInvalidBundle", rootKey, err)
		}
	}
	if store.getCalls.Load()+store.headCalls.Load()+store.putCalls.Load()+store.casCalls.Load() != 0 {
		t.Fatalf("collision validation performed Store I/O: get=%d head=%d put=%d cas=%d",
			store.getCalls.Load(), store.headCalls.Load(), store.putCalls.Load(), store.casCalls.Load())
	}
}

func TestNewRootPublisherRequiresSignedReferenceByDefaultWithoutStoreIO(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	fixture.publish(t, "one")
	store := &rootPublisherFaultStore{base: fixture.base}
	config := fixture.config(store, 0)
	config.DangerouslyAllowUnsignedReference = false

	_, err := NewRootPublisher(config)
	if !errors.Is(err, ErrUntrustedBundle) {
		t.Fatalf("unsigned reference error = %v, want ErrUntrustedBundle", err)
	}
	if store.getCalls.Load()+store.headCalls.Load()+store.putCalls.Load()+store.casCalls.Load() != 0 {
		t.Fatalf("unsigned-reference validation performed Store I/O: get=%d head=%d put=%d cas=%d",
			store.getCalls.Load(), store.headCalls.Load(), store.putCalls.Load(), store.casCalls.Load())
	}

	config.ReferenceKey = fixture.repository.SignedReferenceKey("main")
	if _, err := NewRootPublisher(config); err != nil {
		t.Fatalf("default signed-reference configuration: %v", err)
	}
	if store.getCalls.Load()+store.headCalls.Load()+store.putCalls.Load()+store.casCalls.Load() != 0 {
		t.Fatalf("signed-reference constructor performed Store I/O: get=%d head=%d put=%d cas=%d",
			store.getCalls.Load(), store.headCalls.Load(), store.putCalls.Load(), store.casCalls.Load())
	}
}

func TestNewRootPublisherRejectsTypedNilDependenciesWithoutStoreIO(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	fixture.publish(t, "one")
	counted := &rootPublisherFaultStore{base: fixture.base}
	valid := fixture.config(counted, 0)

	var nilStore *rootPublisherFaultStore
	storeConfig := valid
	storeConfig.Store = nilStore
	if _, err := NewRootPublisher(storeConfig); !errors.Is(err, s3disk.ErrStoreMisconfigured) {
		t.Fatalf("typed-nil Store error = %v, want ErrStoreMisconfigured", err)
	}

	var nilPresigner *rootTestPresigner
	presignerConfig := valid
	presignerConfig.Presigner = nilPresigner
	if _, err := NewRootPublisher(presignerConfig); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("typed-nil Presigner error = %v, want ErrInvalidBundle", err)
	}

	var nilSigner *s3disk.Ed25519ReferenceSigner
	signerConfig := valid
	signerConfig.Signer = nilSigner
	if _, err := NewRootPublisher(signerConfig); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("typed-nil Signer error = %v, want ErrInvalidBundle", err)
	}

	var nilVerifier *s3disk.Ed25519ReferenceVerifier
	verifierConfig := valid
	verifierConfig.Verifier = nilVerifier
	if _, err := NewRootPublisher(verifierConfig); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("typed-nil Verifier error = %v, want ErrInvalidBundle", err)
	}
	if counted.getCalls.Load()+counted.headCalls.Load()+counted.putCalls.Load()+counted.casCalls.Load() != 0 {
		t.Fatalf("constructor performed Store I/O: get=%d head=%d put=%d cas=%d",
			counted.getCalls.Load(), counted.headCalls.Load(), counted.putCalls.Load(), counted.casCalls.Load())
	}
}

func TestNewRootPublisherRejectsCustomVerifierBeforeCallingIt(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	builtIn, ok := fixture.verifier.(*s3disk.Ed25519ReferenceVerifier)
	if !ok {
		t.Fatalf("fixture verifier = %T", fixture.verifier)
	}
	verifier := &rootPublisherCountingVerifier{Ed25519ReferenceVerifier: builtIn}
	config := fixture.config(fixture.base, 0)
	config.Verifier = verifier
	if _, err := NewRootPublisher(config); !errors.Is(err, ErrUntrustedBundle) {
		t.Fatalf("custom verifier error = %v, want ErrUntrustedBundle", err)
	}
	if verifier.calls != 0 {
		t.Fatalf("custom verifier calls = %d, want 0", verifier.calls)
	}

	config.DangerouslyAllowCustomReferenceVerifier = true
	if _, err := NewRootPublisher(config); err != nil {
		t.Fatalf("NewRootPublisher with dangerous custom-verifier opt-out: %v", err)
	}
	if verifier.calls == 0 {
		t.Fatal("dangerous custom-verifier opt-out did not invoke the custom verifier")
	}
}

func TestRootPublisherRecordsExactInsecureLoopbackMode(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	httpsPublisher := fixture.newPublisher(t, fixture.base, 0)
	if httpsPublisher.allowInsecureLoopback {
		t.Fatal("HTTPS root enabled insecure loopback decoding")
	}

	root, err := newTestCapability(
		fixture.rootKey,
		"http://127.0.0.1:9000/bucket/root?X-Amz-Signature=root-secret",
		nil,
		fixture.expiry,
		CapabilityOptions{AllowInsecureLoopback: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	presigner := &rootTestPresigner{
		expiry:  fixture.expiry,
		origin:  "http://127.0.0.1:9000",
		options: CapabilityOptions{AllowInsecureLoopback: true},
	}
	config := fixture.config(fixture.base, 0)
	config.RootCapability = root
	config.Presigner = presigner
	httpPublisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	if !httpPublisher.allowInsecureLoopback {
		t.Fatal("literal HTTP loopback root did not enable loopback decoding")
	}
}

func TestRootPublisherOrdinaryFormattingAndJSONRedactBearerMaterial(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	publisher := fixture.newPublisher(t, fixture.base, 0)
	value := *publisher
	encodedPointer, err := json.Marshal(publisher)
	if err != nil {
		t.Fatal(err)
	}
	encodedValue, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	renderings := []string{
		fmt.Sprintf("%v", publisher),
		fmt.Sprintf("%+v", publisher),
		fmt.Sprintf("%#v", publisher),
		fmt.Sprintf("%v", value),
		fmt.Sprintf("%+v", value),
		fmt.Sprintf("%#v", value),
		string(encodedPointer),
		string(encodedValue),
	}
	for _, rendering := range renderings {
		for _, secret := range []string{
			fixture.rootCapability.rawURL,
			"objects.example.test",
			"X-Amz-Credential",
			"root-secret",
			"object-secret",
		} {
			if strings.Contains(rendering, secret) {
				t.Fatalf("ordinary formatting leaked %q: %s", secret, rendering)
			}
		}
		if !strings.Contains(rendering, "redacted") {
			t.Fatalf("ordinary formatting lacks an explicit redaction marker: %s", rendering)
		}
	}
}

type rootPublisherFixture struct {
	base              *memstore.Store
	repository        *s3disk.Repository
	snapshotPublisher *s3disk.Publisher
	source            string
	repositoryPrefix  string
	referenceKey      string
	rootKey           string
	rootCapability    Capability
	shareID           ShareID
	expiry            time.Time
	presigner         *rootTestPresigner
	signer            s3disk.ReferenceSigner
	verifier          s3disk.ReferenceVerifier
}

func newRootPublisherFixture(t *testing.T) *rootPublisherFixture {
	t.Helper()
	const repositoryPrefix = "root-publisher-repo"
	base := memstore.New()
	repository, err := s3disk.NewRepository(base, repositoryPrefix)
	if err != nil {
		t.Fatal(err)
	}
	snapshotPublisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
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
	signer, err := s3disk.NewEd25519ReferenceSigner(repositoryID, "root-publisher-test", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := s3disk.NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{"root-publisher-test": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	shareID, err := GenerateShareID()
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	rootKey := "shares/root-publisher/root"
	rootCapability, err := newTestCapability(
		rootKey,
		"https://objects.example.test/bucket/root?X-Amz-Credential=redacted&X-Amz-Signature=root-secret",
		nil,
		expiry,
		CapabilityOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return &rootPublisherFixture{
		base: base, repository: repository, snapshotPublisher: snapshotPublisher,
		source: t.TempDir(), repositoryPrefix: repositoryPrefix,
		referenceKey: repository.ReferenceKey("main"), rootKey: rootKey,
		rootCapability: rootCapability, shareID: shareID, expiry: expiry,
		presigner: &rootTestPresigner{expiry: expiry, origin: "https://objects.example.test"},
		signer:    signer, verifier: verifier,
	}
}

func (fixture *rootPublisherFixture) publish(t *testing.T, contents string) s3disk.SnapshotClosure {
	t.Helper()
	if err := os.WriteFile(filepath.Join(fixture.source, "shared.txt"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.snapshotPublisher.PublishSelected(context.Background(), fixture.source, "main", []string{"shared.txt"}); err != nil {
		t.Fatal(err)
	}
	closure, err := fixture.repository.ResolveSnapshotClosure(context.Background(), "main", s3disk.SnapshotClosureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return closure
}

func (fixture *rootPublisherFixture) config(store s3disk.Store, maxAttempts int) RootPublisherConfig {
	return RootPublisherConfig{
		Store: store, RootKey: fixture.rootKey, RootCapability: fixture.rootCapability,
		RepositoryPrefix: fixture.repositoryPrefix, ReferenceKey: fixture.referenceKey,
		ShareID: fixture.shareID, Presigner: fixture.presigner,
		Signer: fixture.signer, Verifier: fixture.verifier, MaxPublishAttempts: maxAttempts,
		DangerouslyAllowUnsignedReference: true,
	}
}

func (fixture *rootPublisherFixture) newPublisher(t *testing.T, store s3disk.Store, maxAttempts int) *RootPublisher {
	t.Helper()
	publisher, err := NewRootPublisher(fixture.config(store, maxAttempts))
	if err != nil {
		t.Fatal(err)
	}
	return publisher
}

func (fixture *rootPublisherFixture) loadRoot(t *testing.T) *Bundle {
	t.Helper()
	object, err := fixture.base.Get(context.Background(), fixture.rootKey, s3disk.GetOptions{MaxBytes: MaximumBundleBytes})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Decode(context.Background(), object.Data, fixture.verifier, DecodeOptions{
		RootCapability: fixture.rootCapability, RepositoryPrefix: fixture.repositoryPrefix,
		ReferenceKey: fixture.referenceKey, ShareID: fixture.shareID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

type rootTestPresigner struct {
	mu      sync.Mutex
	expiry  time.Time
	origin  string
	options CapabilityOptions
	keys    []string
}

type rootPublisherCountingVerifier struct {
	*s3disk.Ed25519ReferenceVerifier
	calls int
}

func (verifier *rootPublisherCountingVerifier) RepositoryID() s3disk.RepositoryID {
	verifier.calls++
	return verifier.Ed25519ReferenceVerifier.RepositoryID()
}

func (verifier *rootPublisherCountingVerifier) Verify(ctx context.Context, keyID string, message, signature []byte) error {
	verifier.calls++
	return verifier.Ed25519ReferenceVerifier.Verify(ctx, keyID, message, signature)
}

type failingRootPresigner struct {
	expiry time.Time
	err    error
}

func (presigner *failingRootPresigner) AuthorizationExpiry() (time.Time, bool) {
	return presigner.expiry, true
}

func (presigner *failingRootPresigner) PresignGet(context.Context, string) (Capability, error) {
	return Capability{}, presigner.err
}

func (presigner *rootTestPresigner) AuthorizationExpiry() (time.Time, bool) {
	if presigner == nil {
		return time.Time{}, false
	}
	return presigner.expiry, true
}

func (presigner *rootTestPresigner) PresignGet(_ context.Context, key string) (Capability, error) {
	presigner.mu.Lock()
	defer presigner.mu.Unlock()
	presigner.keys = append(presigner.keys, key)
	return newTestCapability(
		key,
		fmt.Sprintf("%s/bucket/object-%d?X-Amz-Signature=object-secret", presigner.origin, len(presigner.keys)),
		http.Header{},
		presigner.expiry,
		presigner.options,
	)
}

func (presigner *rootTestPresigner) callCount() int {
	presigner.mu.Lock()
	defer presigner.mu.Unlock()
	return len(presigner.keys)
}

type rootPublisherFaultStore struct {
	base s3disk.Store

	getError          error
	getErrorAfterCall int64
	putError          error
	losePutResponse   bool
	loseCASResponse   bool
	competingRoot     []byte
	competingError    error

	getCalls  atomic.Int64
	headCalls atomic.Int64
	putCalls  atomic.Int64
	casCalls  atomic.Int64
	mu        sync.Mutex
}

func (store *rootPublisherFaultStore) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	call := store.getCalls.Add(1)
	if store.getError != nil && call > store.getErrorAfterCall {
		return s3disk.Object{}, store.getError
	}
	return store.base.Get(ctx, key, options)
}

func (store *rootPublisherFaultStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	store.headCalls.Add(1)
	return store.base.Head(ctx, key)
}

func (store *rootPublisherFaultStore) PutIfAbsent(ctx context.Context, key string, data []byte) (s3disk.Version, error) {
	store.putCalls.Add(1)
	if store.putError != nil {
		return s3disk.Version{}, store.putError
	}
	version, err := store.base.PutIfAbsent(ctx, key, data)
	store.mu.Lock()
	lose := store.losePutResponse && err == nil
	store.losePutResponse = false
	store.mu.Unlock()
	if lose {
		return s3disk.Version{}, errors.New("injected lost PutIfAbsent response containing https://provider.invalid/secret")
	}
	return version, err
}

func (store *rootPublisherFaultStore) CompareAndSwap(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
	call := store.casCalls.Add(1)
	store.mu.Lock()
	competing := append([]byte(nil), store.competingRoot...)
	if len(competing) != 0 {
		store.competingRoot = nil
	}
	lose := store.loseCASResponse
	store.loseCASResponse = false
	store.mu.Unlock()
	if len(competing) != 0 {
		_, err := store.base.CompareAndSwap(ctx, key, expected, competing)
		store.mu.Lock()
		store.competingError = err
		store.mu.Unlock()
		if err != nil {
			return s3disk.Version{}, err
		}
		return s3disk.Version{}, fmt.Errorf("competing writer won call %d: %w", call, s3disk.ErrPrecondition)
	}
	version, err := store.base.CompareAndSwap(ctx, key, expected, data)
	if lose && err == nil {
		return s3disk.Version{}, errors.New("injected lost CompareAndSwap response containing https://provider.invalid/secret")
	}
	return version, err
}

type cancelingRootWriteStore struct {
	base   s3disk.Store
	cancel context.CancelFunc
}

type observableCancelContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (ctx *observableCancelContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.waiting) })
	return ctx.Context.Done()
}

func (store *cancelingRootWriteStore) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	return store.base.Get(ctx, key, options)
}

func (store *cancelingRootWriteStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	return store.base.Head(ctx, key)
}

func (store *cancelingRootWriteStore) PutIfAbsent(context.Context, string, []byte) (s3disk.Version, error) {
	store.cancel()
	return s3disk.Version{}, context.Canceled
}

func (store *cancelingRootWriteStore) CompareAndSwap(context.Context, string, *s3disk.Version, []byte) (s3disk.Version, error) {
	store.cancel()
	return s3disk.Version{}, context.Canceled
}

func independentClosureAtGeneration(t *testing.T, prefix string, generation int, finalContents string) s3disk.SnapshotClosure {
	t.Helper()
	base := memstore.New()
	repository, err := s3disk.NewRepository(base, prefix)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	for current := 1; current <= generation; current++ {
		contents := fmt.Sprintf("branch-%d", current)
		if current == generation {
			contents = finalContents
		}
		if err := os.WriteFile(filepath.Join(source, "shared.txt"), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := publisher.PublishSelected(context.Background(), source, "main", []string{"shared.txt"}); err != nil {
			t.Fatal(err)
		}
	}
	closure, err := repository.ResolveSnapshotClosure(context.Background(), "main", s3disk.SnapshotClosureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return closure
}

func assertNoRootSecret(t *testing.T, err error, secretURL string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	message := err.Error()
	for _, secret := range []string{secretURL, "AKIASECRET", "super-secret", "X-Amz-Signature", "X-Amz-Credential"} {
		if strings.Contains(message, secret) {
			t.Fatalf("error leaked bearer material %q: %v", secret, err)
		}
	}
}

var _ s3disk.Store = (*rootPublisherFaultStore)(nil)
var _ s3disk.Store = (*cancelingRootWriteStore)(nil)
