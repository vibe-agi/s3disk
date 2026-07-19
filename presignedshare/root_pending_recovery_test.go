package presignedshare

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestRecoverPendingSettlesAppliedUpdateWithoutOriginalClosureOrBuildCalls(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	journal := newRootTestRecoveryJournal()
	signer := &rootRecoveryCountingSigner{delegate: fixture.signer}
	config := fixture.config(fixture.base, 1)
	config.RecoveryJournal = journal
	config.Signer = signer
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}

	first := fixture.publish(t, "pending recovery generation one")
	if publication, err := publisher.Create(context.Background(), first); err != nil || publication.Revision != 1 {
		t.Fatalf("Create = %+v, %v", publication, err)
	}
	second := fixture.publish(t, "pending recovery generation two")
	lossStore := &rootPendingCASLossStore{base: fixture.base, loseNextCASResponse: true}
	lossConfig := config
	lossConfig.Store = lossStore
	lossPublisher, err := NewRootPublisher(lossConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lossPublisher.Update(context.Background(), second); !errors.Is(err, ErrRootPublishIndeterminate) {
		t.Fatalf("ambiguous Update error = %v, want ErrRootPublishIndeterminate", err)
	}
	if record := journal.decoded(t); record.Pending == nil || record.Pending.TargetRevision != 2 {
		t.Fatalf("ambiguous update journal = %+v, want pending revision two", record)
	}

	signCalls := signer.callCount()
	presignCalls := fixture.presigner.callCount()
	restoreConfig := lossConfig
	restoreConfig.RootCapability = rootRecoveryImportBearer(t, fixture.rootCapability)
	restored, err := RestoreRootPublisher(context.Background(), restoreConfig)
	if err != nil {
		t.Fatal(err)
	}
	result, err := restored.RecoverPending(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.HadPending || !result.PendingCleared || !result.RootFound || result.WroteRoot ||
		result.Revision != 2 || result.ReferenceGeneration != second.Snapshot.Generation ||
		result.ReferenceCommit != second.Snapshot.Commit || result.Version.ETag == "" {
		t.Fatalf("RecoverPending result = %+v", result)
	}
	if signer.callCount() != signCalls || fixture.presigner.callCount() != presignCalls {
		t.Fatalf(
			"RecoverPending build calls: signer %d -> %d, presigner %d -> %d",
			signCalls,
			signer.callCount(),
			presignCalls,
			fixture.presigner.callCount(),
		)
	}
	if record := journal.decoded(t); record.Pending != nil || record.Committed == nil || record.Committed.Revision != 2 {
		t.Fatalf("settled journal = %+v", record)
	}

	// The caller only has a newer closure after restart. Settling the older WAL
	// first must leave the publisher free to advance to that different closure.
	third := fixture.publish(t, "different closure available after restart")
	publication, err := restored.Update(context.Background(), third)
	if err != nil || !publication.Updated || publication.Revision != 3 {
		t.Fatalf("Update with different closure after RecoverPending = %+v, %v", publication, err)
	}
}

func TestRecoverPendingReplaysExactTargetWithoutSignerOrPresigner(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	closure := fixture.publish(t, "pending target without build dependencies")
	journal := newRootTestRecoveryJournal()
	faultStore := &rootRecoveryFaultStore{base: fixture.base, journal: journal, rejectWrites: true}
	config := fixture.config(faultStore, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Create(context.Background(), closure); !errors.Is(err, ErrRootPublishIndeterminate) {
		t.Fatalf("Create error = %v, want ErrRootPublishIndeterminate", err)
	}
	exactTarget := journal.target(t)

	faultStore.rejectWrites = false
	restoreConfig := config
	restoreConfig.RootCapability = rootRecoveryImportBearer(t, fixture.rootCapability)
	restoreConfig.Signer = nil
	restoreConfig.Presigner = nil
	restored, err := RestoreRootPublisher(context.Background(), restoreConfig)
	if err != nil {
		t.Fatal(err)
	}
	result, err := restored.RecoverPending(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.HadPending || !result.PendingCleared || !result.RootFound || !result.WroteRoot ||
		result.Revision != 1 || result.ReferenceGeneration != closure.Snapshot.Generation ||
		result.ReferenceCommit != closure.Snapshot.Commit {
		t.Fatalf("RecoverPending result = %+v", result)
	}
	object, err := fixture.base.Get(context.Background(), fixture.rootKey, s3disk.GetOptions{MaxBytes: MaximumBundleBytes})
	if err != nil || !bytes.Equal(object.Data, exactTarget) {
		t.Fatalf("replayed target = exact %v, error %v", bytes.Equal(object.Data, exactTarget), err)
	}
}

func TestRecoverPendingNoPendingSafelyReconcilesCommittedRoot(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	closure := fixture.publish(t, "already committed root")
	journal := newRootTestRecoveryJournal()
	config := fixture.config(fixture.base, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := publisher.Create(context.Background(), closure)
	if err != nil {
		t.Fatal(err)
	}

	result, err := publisher.RecoverPending(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.HadPending || result.PendingCleared || result.WroteRoot || !result.RootFound ||
		result.Revision != publication.Revision || result.ReferenceGeneration != closure.Snapshot.Generation ||
		result.ReferenceCommit != closure.Snapshot.Commit || result.Version != publication.Version {
		t.Fatalf("no-pending RecoverPending result = %+v", result)
	}
}

func TestRecoveryOnlyPublisherClassifiesMissingRootBuildAuthorityPrecisely(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	journal := newRootTestRecoveryJournal()
	config := fixture.config(fixture.base, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	first := fixture.publish(t, "committed before recovery-only restart")
	if _, err := publisher.Create(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	recoveryConfig := config
	recoveryConfig.Signer = nil
	recoveryConfig.Presigner = nil
	recoveryOnly, err := NewRootPublisher(recoveryConfig)
	if err != nil {
		t.Fatal(err)
	}
	second := fixture.publish(t, "new closure needs build authority")
	_, err = recoveryOnly.Update(context.Background(), second)
	if !errors.Is(err, ErrRootBuildAuthorityRequired) {
		t.Fatalf("Update error = %v, want ErrRootBuildAuthorityRequired", err)
	}
	if errors.Is(err, s3disk.ErrStoreMisconfigured) {
		t.Fatalf("missing build authority was misclassified as Store configuration failure: %v", err)
	}
}

func TestRecoverPendingPreparedJournalWithoutRootIsNoOp(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	journal := newRootTestRecoveryJournal()
	config := fixture.config(fixture.base, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.PrepareRecovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	journalWrites := journal.compareAndSwapCallCount

	result, err := publisher.RecoverPending(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result != (RootRecoveryResult{}) {
		t.Fatalf("prepared no-op result = %+v", result)
	}
	if journal.compareAndSwapCallCount != journalWrites {
		t.Fatalf("prepared no-op added a journal write: %d -> %d", journalWrites, journal.compareAndSwapCallCount)
	}
}

func TestRecoverPendingRechecksContextAfterJournalLoadBeforeRootIO(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	journal := newRootTestRecoveryJournal()
	prepareConfig := fixture.config(fixture.base, 1)
	prepareConfig.RecoveryJournal = journal
	preparer, err := NewRootPublisher(prepareConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := preparer.PrepareRecovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, revision := rootRecoveryJournalState(t, journal)

	ctx, cancel := context.WithCancel(context.Background())
	loadJournal := &rootRecoveryIgnoringContextJournal{
		data: data, revision: revision, found: true, afterLoad: cancel,
	}
	store := &rootRecoveryRejectingCountingStore{}
	config := prepareConfig
	config.Store = store
	config.RecoveryJournal = loadJournal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.RecoverPending(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("RecoverPending post-load error = %v, want context.Canceled", err)
	}
	if store.callCount() != 0 || loadJournal.compareAndSwapCallCount() != 0 {
		t.Fatalf(
			"post-load cancellation reached Store/journal mutation: Store=%d CAS=%d",
			store.callCount(),
			loadJournal.compareAndSwapCallCount(),
		)
	}
}

func TestRecoverPendingHonorsConfiguredWriteAttemptBound(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	closure := fixture.publish(t, "bounded pending recovery")
	journal := newRootTestRecoveryJournal()
	faultStore := &rootRecoveryFaultStore{base: fixture.base, journal: journal, rejectWrites: true}
	config := fixture.config(faultStore, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Create(context.Background(), closure); !errors.Is(err, ErrRootPublishIndeterminate) {
		t.Fatalf("Create error = %v, want ErrRootPublishIndeterminate", err)
	}

	preconditions := &rootPendingPreconditionStore{}
	restoreConfig := config
	restoreConfig.Store = preconditions
	restoreConfig.RootCapability = rootRecoveryImportBearer(t, fixture.rootCapability)
	restoreConfig.Signer = nil
	restoreConfig.Presigner = nil
	restoreConfig.MaxPublishAttempts = 3
	restored, err := RestoreRootPublisher(context.Background(), restoreConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restored.RecoverPending(context.Background()); !errors.Is(err, ErrRootPublishConflict) {
		t.Fatalf("RecoverPending attempt-bound error = %v, want ErrRootPublishConflict", err)
	}
	if calls := preconditions.writeCallCount(); calls != 3 {
		t.Fatalf("RecoverPending writes = %d, want 3", calls)
	}
}

func TestRecoverPendingRejectsCorruptJournalBeforeRootStoreIO(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	closure := fixture.publish(t, "corrupt pending recovery")
	journal := newRootTestRecoveryJournal()
	faultStore := &rootRecoveryFaultStore{base: fixture.base, journal: journal, rejectWrites: true}
	config := fixture.config(faultStore, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Create(context.Background(), closure); !errors.Is(err, ErrRootPublishIndeterminate) {
		t.Fatalf("Create error = %v, want ErrRootPublishIndeterminate", err)
	}

	countingStore := &rootRecoveryRejectingCountingStore{}
	restoreConfig := config
	restoreConfig.Store = countingStore
	restoreConfig.RootCapability = rootRecoveryImportBearer(t, fixture.rootCapability)
	restoreConfig.Signer = nil
	restoreConfig.Presigner = nil
	restored, err := RestoreRootPublisher(context.Background(), restoreConfig)
	if err != nil {
		t.Fatal(err)
	}
	journal.mu.Lock()
	journal.data[len(journal.data)-1] ^= 0x80
	journal.mu.Unlock()

	if _, err := restored.RecoverPending(context.Background()); !errors.Is(err, ErrRootRecoveryState) {
		t.Fatalf("RecoverPending corrupt journal error = %v, want ErrRootRecoveryState", err)
	}
	if calls := countingStore.callCount(); calls != 0 {
		t.Fatalf("corrupt journal reached root Store %d times", calls)
	}
}

func TestRecoverPendingRejectsValidSameRevisionMismatch(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	wanted := fixture.publish(t, "wanted pending root")
	journal := newRootTestRecoveryJournal()
	faultStore := &rootRecoveryFaultStore{base: fixture.base, journal: journal, rejectWrites: true}
	config := fixture.config(faultStore, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Create(context.Background(), wanted); !errors.Is(err, ErrRootPublishIndeterminate) {
		t.Fatalf("Create wanted error = %v, want ErrRootPublishIndeterminate", err)
	}

	other := fixture.publish(t, "different valid root at the same revision")
	otherStore := memstore.New()
	otherConfig := fixture.config(otherStore, 1)
	otherPublisher, err := NewRootPublisher(otherConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherPublisher.Create(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	otherObject, err := otherStore.Get(context.Background(), fixture.rootKey, s3disk.GetOptions{MaxBytes: MaximumBundleBytes})
	if err != nil {
		t.Fatal(err)
	}
	fixture.base.ForcePut(fixture.rootKey, otherObject.Data)

	faultStore.rejectWrites = false
	if _, err := publisher.RecoverPending(context.Background()); !errors.Is(err, s3disk.ErrSplitBrain) {
		t.Fatalf("RecoverPending mismatched root error = %v, want ErrSplitBrain", err)
	}
	if record := journal.decoded(t); record.Pending == nil {
		t.Fatal("mismatched root unexpectedly cleared pending recovery")
	}
}

func TestRecoverPendingNeverRecreatesMissingCommittedUpdateBase(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	journal := newRootTestRecoveryJournal()
	config := fixture.config(fixture.base, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	first := fixture.publish(t, "committed root before missing base")
	if _, err := publisher.Create(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := fixture.publish(t, "pending update whose base disappears")
	faultStore := &rootRecoveryFaultStore{base: fixture.base, journal: journal, rejectWrites: true}
	faultConfig := config
	faultConfig.Store = faultStore
	faultPublisher, err := NewRootPublisher(faultConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := faultPublisher.Update(context.Background(), second); !errors.Is(err, ErrRootPublishIndeterminate) {
		t.Fatalf("Update error = %v, want ErrRootPublishIndeterminate", err)
	}

	missing := &rootPendingMissingStore{}
	restoreConfig := faultConfig
	restoreConfig.Store = missing
	restoreConfig.RootCapability = rootRecoveryImportBearer(t, fixture.rootCapability)
	restoreConfig.Signer = nil
	restoreConfig.Presigner = nil
	restored, err := RestoreRootPublisher(context.Background(), restoreConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restored.RecoverPending(context.Background()); !errors.Is(err, s3disk.ErrRollbackDetected) {
		t.Fatalf("RecoverPending missing update base error = %v, want ErrRollbackDetected", err)
	}
	if missing.writeCallCount() != 0 {
		t.Fatalf("missing committed update base caused %d root writes", missing.writeCallCount())
	}
}

type rootPendingCASLossStore struct {
	base s3disk.Store

	mu                     sync.Mutex
	loseNextCASResponse    bool
	failNextReconciliation bool
}

func (store *rootPendingCASLossStore) Get(
	ctx context.Context,
	key string,
	options s3disk.GetOptions,
) (s3disk.Object, error) {
	store.mu.Lock()
	fail := store.failNextReconciliation
	store.failNextReconciliation = false
	store.mu.Unlock()
	if fail {
		return s3disk.Object{}, s3disk.ErrStoreUnavailable
	}
	return store.base.Get(ctx, key, options)
}

func (store *rootPendingCASLossStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	return store.base.Head(ctx, key)
}

func (store *rootPendingCASLossStore) PutIfAbsent(
	ctx context.Context,
	key string,
	data []byte,
) (s3disk.Version, error) {
	return store.base.PutIfAbsent(ctx, key, data)
}

func (store *rootPendingCASLossStore) CompareAndSwap(
	ctx context.Context,
	key string,
	expected *s3disk.Version,
	data []byte,
) (s3disk.Version, error) {
	version, err := store.base.CompareAndSwap(ctx, key, expected, data)
	if err != nil {
		return version, err
	}
	store.mu.Lock()
	lose := store.loseNextCASResponse
	store.loseNextCASResponse = false
	store.failNextReconciliation = lose
	store.mu.Unlock()
	if lose {
		return s3disk.Version{}, errors.New("test: applied root CAS response lost")
	}
	return version, nil
}

type rootPendingMissingStore struct {
	mu     sync.Mutex
	writes int
}

type rootPendingPreconditionStore struct {
	mu     sync.Mutex
	writes int
}

func (*rootPendingPreconditionStore) Get(context.Context, string, s3disk.GetOptions) (s3disk.Object, error) {
	return s3disk.Object{}, s3disk.ErrObjectNotFound
}

func (*rootPendingPreconditionStore) Head(context.Context, string) (s3disk.Version, error) {
	return s3disk.Version{}, s3disk.ErrObjectNotFound
}

func (store *rootPendingPreconditionStore) PutIfAbsent(
	context.Context,
	string,
	[]byte,
) (s3disk.Version, error) {
	store.mu.Lock()
	store.writes++
	store.mu.Unlock()
	return s3disk.Version{}, s3disk.ErrPrecondition
}

func (store *rootPendingPreconditionStore) CompareAndSwap(
	context.Context,
	string,
	*s3disk.Version,
	[]byte,
) (s3disk.Version, error) {
	store.mu.Lock()
	store.writes++
	store.mu.Unlock()
	return s3disk.Version{}, s3disk.ErrPrecondition
}

func (store *rootPendingPreconditionStore) writeCallCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.writes
}

func (*rootPendingMissingStore) Get(context.Context, string, s3disk.GetOptions) (s3disk.Object, error) {
	return s3disk.Object{}, s3disk.ErrObjectNotFound
}

func (*rootPendingMissingStore) Head(context.Context, string) (s3disk.Version, error) {
	return s3disk.Version{}, s3disk.ErrObjectNotFound
}

func (store *rootPendingMissingStore) PutIfAbsent(
	context.Context,
	string,
	[]byte,
) (s3disk.Version, error) {
	store.mu.Lock()
	store.writes++
	store.mu.Unlock()
	return s3disk.Version{}, errors.New("test: unexpected root create")
}

func (store *rootPendingMissingStore) CompareAndSwap(
	context.Context,
	string,
	*s3disk.Version,
	[]byte,
) (s3disk.Version, error) {
	store.mu.Lock()
	store.writes++
	store.mu.Unlock()
	return s3disk.Version{}, errors.New("test: unexpected root update")
}

func (store *rootPendingMissingStore) writeCallCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.writes
}

var _ s3disk.Store = (*rootPendingCASLossStore)(nil)
var _ s3disk.Store = (*rootPendingMissingStore)(nil)
var _ s3disk.Store = (*rootPendingPreconditionStore)(nil)
