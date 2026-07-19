package presignedshare

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/vibe-agi/s3disk"
)

func TestRootPublisherInvalidWriteVersionReconcilesOrClassifiesIndeterminate(t *testing.T) {
	t.Run("applied target converges through GET", func(t *testing.T) {
		fixture := newRootPublisherFixture(t)
		closure := fixture.publish(t, "non-WAL invalid version applied")
		store := &rootWriteClassificationStore{base: fixture.base, applyWrite: true, invalidVersion: true}
		publisher := fixture.newPublisher(t, store, 1)

		publication, err := publisher.Create(context.Background(), closure)
		if err != nil {
			t.Fatal(err)
		}
		if !publication.Updated || publication.Revision != 1 || publication.Version.ETag == "" {
			t.Fatalf("reconciled publication = %+v", publication)
		}
		if writes, gets := store.callCounts(); writes != 1 || gets != 2 {
			t.Fatalf("Store calls = writes %d, GETs %d; want one write and initial plus reconciliation GET", writes, gets)
		}
	})

	t.Run("CAS with oversized version metadata converges through GET", func(t *testing.T) {
		fixture := newRootPublisherFixture(t)
		first := fixture.publish(t, "non-WAL valid initial root")
		creator := fixture.newPublisher(t, fixture.base, 1)
		if _, err := creator.Create(context.Background(), first); err != nil {
			t.Fatal(err)
		}
		second := fixture.publish(t, "non-WAL oversized CAS version applied")
		store := &rootWriteClassificationStore{
			base: fixture.base, applyWrite: true, invalidVersion: true,
			invalidVersionValue: s3disk.Version{
				ETag:      "invalid-write-response",
				VersionID: strings.Repeat("v", s3disk.MaxStoreVersionTokenBytes+1),
			},
		}
		publisher := fixture.newPublisher(t, store, 1)

		publication, err := publisher.Update(context.Background(), second)
		if err != nil {
			t.Fatal(err)
		}
		if !publication.Updated || publication.Revision != 2 || publication.Version.ETag == "" ||
			len(publication.Version.VersionID) > s3disk.MaxStoreVersionTokenBytes {
			t.Fatalf("reconciled CAS publication = %+v", publication)
		}
		if writes, gets := store.callCounts(); writes != 1 || gets != 2 {
			t.Fatalf("Store calls = writes %d, GETs %d; want one CAS and initial plus reconciliation GET", writes, gets)
		}
	})

	t.Run("unobserved target retains incompatible classification", func(t *testing.T) {
		fixture := newRootPublisherFixture(t)
		closure := fixture.publish(t, "non-WAL invalid version absent")
		store := &rootWriteClassificationStore{base: fixture.base, invalidVersion: true}
		publisher := fixture.newPublisher(t, store, 1)

		_, err := publisher.Create(context.Background(), closure)
		assertIndeterminateRootWriteClass(t, err, s3disk.ErrStoreIncompatible)
		if writes, gets := store.callCounts(); writes != 1 || gets != 2 {
			t.Fatalf("Store calls = writes %d, GETs %d; want one write and an immediate reconciliation GET", writes, gets)
		}
	})

	t.Run("raw non-precondition error is safely classified", func(t *testing.T) {
		const secret = "https://provider.invalid/root?X-Amz-Signature=write-secret"
		fixture := newRootPublisherFixture(t)
		closure := fixture.publish(t, "non-WAL access denied")
		store := &rootWriteClassificationStore{
			base:     fixture.base,
			writeErr: fmt.Errorf("provider rejected %s: %w", secret, s3disk.ErrAccessDenied),
		}
		publisher := fixture.newPublisher(t, store, 1)

		_, err := publisher.Create(context.Background(), closure)
		assertIndeterminateRootWriteClass(t, err, s3disk.ErrAccessDenied)
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "write-secret") {
			t.Fatalf("root write error leaked provider detail: %v", err)
		}
	})

	t.Run("missing bucket retains its permanent classification", func(t *testing.T) {
		const secret = "https://provider.invalid/root?X-Amz-Signature=missing-bucket-secret"
		fixture := newRootPublisherFixture(t)
		closure := fixture.publish(t, "non-WAL bucket missing")
		store := &rootWriteClassificationStore{
			base:     fixture.base,
			writeErr: fmt.Errorf("provider rejected %s: %w", secret, s3disk.ErrBucketNotFound),
		}
		publisher := fixture.newPublisher(t, store, 1)

		_, err := publisher.Create(context.Background(), closure)
		assertIndeterminateRootWriteClass(t, err, s3disk.ErrBucketNotFound)
		if errors.Is(err, s3disk.ErrStoreUnavailable) {
			t.Fatalf("missing bucket was degraded to a transient Store error: %v", err)
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "missing-bucket-secret") {
			t.Fatalf("missing-bucket write error leaked provider detail: %v", err)
		}
	})

	t.Run("reconciliation failure retains its sanitized current classification", func(t *testing.T) {
		const writeSecret = "https://provider.invalid/root?X-Amz-Signature=write-unavailable-secret"
		const readSecret = "https://provider.invalid/root?X-Amz-Signature=read-denied-secret"
		fixture := newRootPublisherFixture(t)
		closure := fixture.publish(t, "non-WAL reconciliation read failure")
		store := &rootWriteClassificationStore{
			base:            fixture.base,
			writeErr:        fmt.Errorf("provider write failed %s: %w", writeSecret, s3disk.ErrStoreUnavailable),
			reconcileGetErr: fmt.Errorf("provider read failed %s: %w", readSecret, s3disk.ErrAccessDenied),
		}
		publisher := fixture.newPublisher(t, store, 1)

		_, err := publisher.Create(context.Background(), closure)
		assertIndeterminateRootWriteClass(t, err, s3disk.ErrStoreUnavailable)
		if !errors.Is(err, s3disk.ErrAccessDenied) {
			t.Fatalf("root reconciliation error = %v, want ErrAccessDenied", err)
		}
		if strings.Contains(err.Error(), writeSecret) || strings.Contains(err.Error(), readSecret) ||
			strings.Contains(err.Error(), "unavailable-secret") || strings.Contains(err.Error(), "denied-secret") {
			t.Fatalf("root reconciliation error leaked provider detail: %v", err)
		}
	})
}

func TestRootPublisherRecoverableInvalidWriteVersionReconcilesOrClassifiesIndeterminate(t *testing.T) {
	t.Run("applied target converges through GET", func(t *testing.T) {
		fixture := newRootPublisherFixture(t)
		closure := fixture.publish(t, "WAL invalid version applied")
		journal := newRootTestRecoveryJournal()
		store := &rootWriteClassificationStore{base: fixture.base, applyWrite: true, invalidVersion: true}
		config := fixture.config(store, 1)
		config.RecoveryJournal = journal
		publisher, err := NewRootPublisher(config)
		if err != nil {
			t.Fatal(err)
		}

		publication, err := publisher.Create(context.Background(), closure)
		if err != nil {
			t.Fatal(err)
		}
		if !publication.Updated || publication.Revision != 1 || publication.Version.ETag == "" {
			t.Fatalf("reconciled publication = %+v", publication)
		}
		if writes, gets := store.callCounts(); writes != 1 || gets != 3 {
			t.Fatalf("Store calls = writes %d, GETs %d; want one write and the post-write reconciliation GET", writes, gets)
		}
		if record := journal.decoded(t); record.Pending != nil || record.Committed == nil {
			t.Fatalf("reconciled journal = %+v", record)
		}
	})

	t.Run("unobserved target retains incompatible classification", func(t *testing.T) {
		fixture := newRootPublisherFixture(t)
		closure := fixture.publish(t, "WAL invalid version absent")
		journal := newRootTestRecoveryJournal()
		store := &rootWriteClassificationStore{base: fixture.base, invalidVersion: true}
		config := fixture.config(store, 1)
		config.RecoveryJournal = journal
		publisher, err := NewRootPublisher(config)
		if err != nil {
			t.Fatal(err)
		}

		_, err = publisher.Create(context.Background(), closure)
		assertIndeterminateRootWriteClass(t, err, s3disk.ErrStoreIncompatible)
		if writes, gets := store.callCounts(); writes != 1 || gets != 3 {
			t.Fatalf("Store calls = writes %d, GETs %d; want one write and an immediate reconciliation GET", writes, gets)
		}
		if record := journal.decoded(t); record.Pending == nil {
			t.Fatal("indeterminate write did not retain its exact pending target")
		}
	})

	t.Run("raw non-precondition error is safely classified", func(t *testing.T) {
		const secret = "https://provider.invalid/root?X-Amz-Signature=wal-write-secret"
		fixture := newRootPublisherFixture(t)
		closure := fixture.publish(t, "WAL access denied")
		journal := newRootTestRecoveryJournal()
		store := &rootWriteClassificationStore{
			base:     fixture.base,
			writeErr: fmt.Errorf("provider rejected %s: %w", secret, s3disk.ErrAccessDenied),
		}
		config := fixture.config(store, 1)
		config.RecoveryJournal = journal
		publisher, err := NewRootPublisher(config)
		if err != nil {
			t.Fatal(err)
		}

		_, err = publisher.Create(context.Background(), closure)
		assertIndeterminateRootWriteClass(t, err, s3disk.ErrAccessDenied)
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "wal-write-secret") {
			t.Fatalf("recoverable root write error leaked provider detail: %v", err)
		}
	})
}

func TestRecoverPendingInvalidWriteVersionReconcilesOrClassifiesIndeterminate(t *testing.T) {
	newPending := func(t *testing.T) (*rootPublisherFixture, *rootTestRecoveryJournal, RootPublisherConfig) {
		t.Helper()
		fixture := newRootPublisherFixture(t)
		closure := fixture.publish(t, "RecoverPending classification")
		journal := newRootTestRecoveryJournal()
		initialStore := &rootRecoveryFaultStore{
			base: fixture.base, journal: journal, rejectWrites: true,
		}
		config := fixture.config(initialStore, 1)
		config.RecoveryJournal = journal
		publisher, err := NewRootPublisher(config)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publisher.Create(context.Background(), closure); !errors.Is(err, ErrRootPublishIndeterminate) {
			t.Fatalf("Create pending target error = %v, want ErrRootPublishIndeterminate", err)
		}
		if record := journal.decoded(t); record.Pending == nil {
			t.Fatal("failed setup write did not retain a pending target")
		}
		config.RootCapability = rootRecoveryImportBearer(t, fixture.rootCapability)
		config.Signer = nil
		config.Presigner = nil
		return fixture, journal, config
	}

	t.Run("applied target converges through GET", func(t *testing.T) {
		fixture, journal, config := newPending(t)
		store := &rootWriteClassificationStore{base: fixture.base, applyWrite: true, invalidVersion: true}
		config.Store = store
		publisher, err := RestoreRootPublisher(context.Background(), config)
		if err != nil {
			t.Fatal(err)
		}

		result, err := publisher.RecoverPending(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !result.HadPending || !result.PendingCleared || !result.RootFound || result.Version.ETag == "" {
			t.Fatalf("RecoverPending result = %+v", result)
		}
		if writes, gets := store.callCounts(); writes != 1 || gets != 2 {
			t.Fatalf("Store calls = writes %d, GETs %d; want one write and initial plus reconciliation GET", writes, gets)
		}
		if record := journal.decoded(t); record.Pending != nil || record.Committed == nil {
			t.Fatalf("reconciled journal = %+v", record)
		}
	})

	t.Run("unobserved target retains incompatible classification", func(t *testing.T) {
		fixture, journal, config := newPending(t)
		store := &rootWriteClassificationStore{base: fixture.base, invalidVersion: true}
		config.Store = store
		publisher, err := RestoreRootPublisher(context.Background(), config)
		if err != nil {
			t.Fatal(err)
		}

		_, err = publisher.RecoverPending(context.Background())
		assertIndeterminateRootWriteClass(t, err, s3disk.ErrStoreIncompatible)
		if writes, gets := store.callCounts(); writes != 1 || gets != 2 {
			t.Fatalf("Store calls = writes %d, GETs %d; want one write and an immediate reconciliation GET", writes, gets)
		}
		if record := journal.decoded(t); record.Pending == nil {
			t.Fatal("indeterminate recovery did not retain its exact pending target")
		}
	})

	t.Run("raw non-precondition error is safely classified", func(t *testing.T) {
		const secret = "https://provider.invalid/root?X-Amz-Signature=recovery-write-secret"
		fixture, _, config := newPending(t)
		store := &rootWriteClassificationStore{
			base:     fixture.base,
			writeErr: fmt.Errorf("provider rejected %s: %w", secret, s3disk.ErrAccessDenied),
		}
		config.Store = store
		publisher, err := RestoreRootPublisher(context.Background(), config)
		if err != nil {
			t.Fatal(err)
		}

		_, err = publisher.RecoverPending(context.Background())
		assertIndeterminateRootWriteClass(t, err, s3disk.ErrAccessDenied)
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "recovery-write-secret") {
			t.Fatalf("RecoverPending write error leaked provider detail: %v", err)
		}
	})
}

func assertIndeterminateRootWriteClass(t *testing.T, err, class error) {
	t.Helper()
	if !errors.Is(err, ErrRootPublishIndeterminate) || !errors.Is(err, class) {
		t.Fatalf("root write error = %v, want ErrRootPublishIndeterminate and %v", err, class)
	}
}

type rootWriteClassificationStore struct {
	base                s3disk.Store
	applyWrite          bool
	invalidVersion      bool
	invalidVersionValue s3disk.Version
	writeErr            error
	reconcileGetErr     error

	mu     sync.Mutex
	gets   int
	writes int
}

func (store *rootWriteClassificationStore) Get(
	ctx context.Context,
	key string,
	options s3disk.GetOptions,
) (s3disk.Object, error) {
	store.mu.Lock()
	store.gets++
	writes := store.writes
	reconcileGetErr := store.reconcileGetErr
	store.mu.Unlock()
	if writes > 0 && reconcileGetErr != nil {
		return s3disk.Object{}, reconcileGetErr
	}
	return store.base.Get(ctx, key, options)
}

func (store *rootWriteClassificationStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	return store.base.Head(ctx, key)
}

func (store *rootWriteClassificationStore) PutIfAbsent(
	ctx context.Context,
	key string,
	data []byte,
) (s3disk.Version, error) {
	store.recordWrite()
	if store.writeErr != nil {
		return s3disk.Version{}, store.writeErr
	}
	var version s3disk.Version
	var err error
	if store.applyWrite {
		version, err = store.base.PutIfAbsent(ctx, key, data)
		if err != nil {
			return version, err
		}
	}
	if store.invalidVersion {
		return store.invalidVersionValue, nil
	}
	return version, nil
}

func (store *rootWriteClassificationStore) CompareAndSwap(
	ctx context.Context,
	key string,
	expected *s3disk.Version,
	data []byte,
) (s3disk.Version, error) {
	store.recordWrite()
	if store.writeErr != nil {
		return s3disk.Version{}, store.writeErr
	}
	var version s3disk.Version
	var err error
	if store.applyWrite {
		version, err = store.base.CompareAndSwap(ctx, key, expected, data)
		if err != nil {
			return version, err
		}
	}
	if store.invalidVersion {
		return store.invalidVersionValue, nil
	}
	return version, nil
}

func (store *rootWriteClassificationStore) recordWrite() {
	store.mu.Lock()
	store.writes++
	store.mu.Unlock()
}

func (store *rootWriteClassificationStore) callCounts() (writes, gets int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.writes, store.gets
}

var _ s3disk.Store = (*rootWriteClassificationStore)(nil)
