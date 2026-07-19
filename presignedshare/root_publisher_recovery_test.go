package presignedshare

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/publisherstate"
)

func TestRootPublisherRecoveryPersistsPendingBeforeWriteAndRestartsWithoutBuildDependencies(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	closure := fixture.publish(t, "recover-before-write")
	journal := newRootTestRecoveryJournal()
	store := &rootRecoveryFaultStore{base: fixture.base, journal: journal, rejectWrites: true}
	config := fixture.config(store, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := publisher.Create(context.Background(), closure); !errors.Is(err, ErrRootPublishIndeterminate) {
		t.Fatalf("Create before crash error = %v, want ErrRootPublishIndeterminate", err)
	}
	if !store.writeSawPending || store.writeCalls != 1 {
		t.Fatalf("write observation = pending %v, calls %d; want one write after durable pending", store.writeSawPending, store.writeCalls)
	}
	pendingTarget := store.lastTarget()
	if len(pendingTarget) == 0 {
		t.Fatal("crash-before-write did not retain exact target bytes")
	}
	presignCalls := fixture.presigner.callCount()

	store.rejectWrites = false
	restartConfig := fixture.config(store, 1)
	restartConfig.RecoveryJournal = journal
	restartConfig.Presigner = nil
	restartConfig.Signer = nil
	restarted, err := NewRootPublisher(restartConfig)
	if err != nil {
		t.Fatalf("restart without build dependencies: %v", err)
	}
	if restarted.CanBuildNewRoot() || !restarted.RecoveryEnabled() {
		t.Fatalf(
			"recovery-only status = can_build %v, recovery %v",
			restarted.CanBuildNewRoot(),
			restarted.RecoveryEnabled(),
		)
	}
	publication, err := restarted.Create(context.Background(), closure)
	if err != nil {
		t.Fatal(err)
	}
	if !publication.Updated || publication.Revision != 1 {
		t.Fatalf("recovered publication = %+v", publication)
	}
	if fixture.presigner.callCount() != presignCalls {
		t.Fatal("pending recovery invoked the unavailable/original presigner")
	}
	object, err := fixture.base.Get(context.Background(), fixture.rootKey, s3disk.GetOptions{MaxBytes: MaximumBundleBytes})
	if err != nil || !bytes.Equal(object.Data, pendingTarget) {
		t.Fatalf("installed target changed across restart: equal=%v error=%v", bytes.Equal(object.Data, pendingTarget), err)
	}
	record := journal.decoded(t)
	if record.Pending != nil || record.HighestRevision != 1 {
		t.Fatalf("committed recovery record = %+v", record)
	}
}

func TestRootPublisherRejectsTypedNilContextBeforeRecoveryIO(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	closure := fixture.publish(t, "typed nil context")
	journal := newRootTestRecoveryJournal()
	store := &rootRecoveryFaultStore{base: fixture.base, journal: journal}
	config := fixture.config(store, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	var nilContext *rootRecoveryNilContext
	if _, err := publisher.Create(nilContext, closure); err == nil {
		t.Fatal("Create accepted a typed-nil context")
	}
	if store.writeCalls != 0 || journal.compareAndSwapCallCount != 0 {
		t.Fatal("typed-nil context reached recovery I/O")
	}
}

func TestRootPublisherRecoveryBoundsStoreWriteByFixedAuthorizationExpiry(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	closure := fixture.publish(t, "fixed expiry write deadline")
	expiresAt := time.Now().Add(500 * time.Millisecond).UTC().Round(0)
	rootCapability, err := newTestCapability(
		fixture.rootKey,
		"https://objects.example.test/bucket/root?X-Amz-Signature=fixed-expiry-secret",
		nil,
		expiresAt,
		CapabilityOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	journal := newRootTestRecoveryJournal()
	store := &rootRecoveryFaultStore{
		base: fixture.base, journal: journal, blockWritesUntilContext: true,
	}
	config := fixture.config(store, 1)
	config.RecoveryJournal = journal
	config.RootCapability = rootCapability
	config.Presigner = &rootTestPresigner{expiry: expiresAt, origin: "https://objects.example.test"}
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := publisher.Create(context.Background(), closure); !errors.Is(err, context.DeadlineExceeded) ||
		!errors.Is(err, ErrRootPublishIndeterminate) {
		t.Fatalf("Create error = %v, want deadline and indeterminate", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("authorization deadline did not bound Store write: %s", elapsed)
	}
	store.mu.Lock()
	writeDeadline := store.lastWriteDeadline
	writeHadDeadline := store.lastWriteHadDeadline
	store.mu.Unlock()
	if !writeHadDeadline || !writeDeadline.Equal(expiresAt) {
		t.Fatalf("Store write deadline = %s, %v; want fixed expiry %s", writeDeadline, writeHadDeadline, expiresAt)
	}
}

func TestRootPublisherRecoveryReconcilesAppliedLostResponseAfterRestart(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	closure := fixture.publish(t, "applied-before-response-loss")
	journal := newRootTestRecoveryJournal()
	store := &rootRecoveryFaultStore{base: fixture.base, journal: journal, losePutResponse: true, failReconcileAfterLostWrite: true}
	config := fixture.config(store, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Create(context.Background(), closure); !errors.Is(err, ErrRootPublishIndeterminate) {
		t.Fatalf("lost-response Create error = %v, want ErrRootPublishIndeterminate", err)
	}
	writes := store.writeCalls
	target := store.lastTarget()

	restartConfig := fixture.config(store, 1)
	restartConfig.RecoveryJournal = journal
	restartConfig.Presigner = nil
	restartConfig.Signer = nil
	restarted, err := NewRootPublisher(restartConfig)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := restarted.Create(context.Background(), closure)
	if err != nil {
		t.Fatal(err)
	}
	if publication.Revision != 1 || !publication.Updated || store.writeCalls != writes {
		t.Fatalf("reconciled publication = %+v, writes %d -> %d", publication, writes, store.writeCalls)
	}
	object, err := fixture.base.Get(context.Background(), fixture.rootKey, s3disk.GetOptions{MaxBytes: MaximumBundleBytes})
	if err != nil || !bytes.Equal(object.Data, target) {
		t.Fatalf("reconciled remote target changed: equal=%v error=%v", bytes.Equal(object.Data, target), err)
	}
}

func TestRootPublisherRecoveryAnchorsAppliedPendingBeforePublishingNewClosure(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	first := fixture.publish(t, "applied old pending")
	journal := newRootTestRecoveryJournal()
	store := &rootRecoveryFaultStore{
		base: fixture.base, journal: journal, losePutResponse: true,
		failReconcileAfterLostWrite: true,
	}
	config := fixture.config(store, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Create(context.Background(), first); !errors.Is(err, ErrRootPublishIndeterminate) {
		t.Fatalf("initial Create error = %v, want ErrRootPublishIndeterminate", err)
	}
	if record := journal.decoded(t); record.Pending == nil {
		t.Fatal("lost response did not leave a pending journal record")
	}

	second := fixture.publish(t, "new closure after crash")
	restartConfig := fixture.config(store, 1)
	restartConfig.RecoveryJournal = journal
	restarted, err := NewRootPublisher(restartConfig)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := restarted.Update(context.Background(), second)
	if err != nil || publication.Revision != 2 || !publication.Updated {
		t.Fatalf("Update after old pending = %+v, %v", publication, err)
	}
	record := journal.decoded(t)
	if record.Pending != nil || record.Committed == nil || record.Committed.Revision != 2 {
		t.Fatalf("new closure did not advance the reconciled journal: %+v", record)
	}
}

func TestRootPublisherRecoveryReconcilesJournalCASLostResponseBeforeStoreWrite(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	closure := fixture.publish(t, "journal-response-loss")
	journal := newRootTestRecoveryJournal()
	journal.loseNextCASResponse = true
	store := &rootRecoveryFaultStore{base: fixture.base, journal: journal}
	config := fixture.config(store, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := publisher.Create(context.Background(), closure)
	if err != nil || publication.Revision != 1 || !publication.Updated {
		t.Fatalf("Create after journal response loss = %+v, %v", publication, err)
	}
	if !store.writeSawPending {
		t.Fatal("Store write ran before the lost-response journal CAS was reconciled")
	}
}

func TestRootPublisherRecoveryReconcilesCommittedJournalCASLostResponse(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	closure := fixture.publish(t, "committed journal response loss")
	journal := newRootTestRecoveryJournal()
	store := &rootRecoveryFaultStore{
		base: fixture.base, journal: journal, loseJournalCommitResponse: true,
	}
	config := fixture.config(store, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := publisher.Create(context.Background(), closure)
	if err != nil || publication.Revision != 1 || !publication.Updated {
		t.Fatalf("Create after committed journal response loss = %+v, %v", publication, err)
	}
	record := journal.decoded(t)
	if record.Pending != nil || record.Committed == nil || record.Committed.Revision != 1 {
		t.Fatalf("journal did not reconcile its committed state: %+v", record)
	}
}

func TestRootPublisherRecoveryRestartsAfterCommittedJournalReconciliationFailure(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	closure := fixture.publish(t, "committed journal reconciliation failure")
	journal := newRootTestRecoveryJournal()
	store := &rootRecoveryFaultStore{
		base: fixture.base, journal: journal, loseJournalCommitResponse: true,
		failJournalCommitReconcile: true,
	}
	config := fixture.config(store, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Create(context.Background(), closure); !errors.Is(err, ErrRootRecoveryIndeterminate) {
		t.Fatalf("Create error = %v, want ErrRootRecoveryIndeterminate", err)
	}

	restartConfig := fixture.config(store, 1)
	restartConfig.RecoveryJournal = journal
	restartConfig.Presigner = nil
	restartConfig.Signer = nil
	restarted, err := NewRootPublisher(restartConfig)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := restarted.Create(context.Background(), closure)
	if err != nil || publication.Revision != 1 || publication.Updated {
		t.Fatalf("restarted Create = %+v, %v", publication, err)
	}
}

func TestRootPublisherRecoveryReplaysExactClientEncryptedCiphertextAfterRestart(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	profile := newRootPublisherEncryptionProfile(t, fixture)
	var err error
	fixture.repository, err = s3disk.NewRepositoryWithOptions(
		fixture.base,
		fixture.repositoryPrefix,
		s3disk.RepositoryOptions{ClientEncryption: profile},
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.snapshotPublisher, err = s3disk.NewPublisher(
		fixture.repository,
		s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	closure := fixture.publish(t, "encrypted recovery target")
	journal := newRootTestRecoveryJournal()
	store := &rootRecoveryFaultStore{base: fixture.base, journal: journal, rejectWrites: true}
	config := fixture.config(store, 1)
	config.RecoveryJournal = journal
	config.ClientEncryption = profile
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Create(context.Background(), closure); !errors.Is(err, ErrRootPublishIndeterminate) {
		t.Fatalf("encrypted Create before restart = %v, want ErrRootPublishIndeterminate", err)
	}
	exactCiphertext := store.lastTarget()
	if len(exactCiphertext) <= int(s3disk.ClientEncryptionCiphertextOverhead) {
		t.Fatal("pending journal did not retain an encrypted root target")
	}
	journalTarget := journal.target(t)
	if !bytes.Equal(journalTarget, exactCiphertext) {
		t.Fatal("Store write target differed from the durable journal ciphertext")
	}
	opened, err := profile.OpenObject(fixture.rootKey, exactCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(opened)
	if bytes.Equal(opened, exactCiphertext) || !bytes.Contains(opened, []byte(`"payload"`)) {
		t.Fatal("journal target does not have the expected encrypted signed-bundle boundary")
	}
	presignCalls := fixture.presigner.callCount()

	store.rejectWrites = false
	restartConfig := fixture.config(store, 1)
	restartConfig.RecoveryJournal = journal
	restartConfig.ClientEncryption = profile
	restartConfig.Presigner = nil
	restartConfig.Signer = nil
	restarted, err := NewRootPublisher(restartConfig)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := restarted.Create(context.Background(), closure)
	if err != nil {
		t.Fatal(err)
	}
	if publication.Revision != 1 || !publication.Updated {
		t.Fatalf("encrypted recovery publication = %+v", publication)
	}
	if fixture.presigner.callCount() != presignCalls {
		t.Fatal("encrypted pending recovery regenerated presigned capabilities")
	}
	raw, err := fixture.base.Get(context.Background(), fixture.rootKey, s3disk.GetOptions{
		MaxBytes: MaximumBundleBytes + s3disk.ClientEncryptionCiphertextOverhead,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw.Data, exactCiphertext) {
		t.Fatal("encrypted recovery resealed instead of replaying exact S3 ciphertext")
	}
}

func TestRootPublisherRecoveryRejectsPrewrappedEncryptedStore(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	profile := newRootPublisherEncryptionProfile(t, fixture)
	wrapped, err := s3disk.NewClientEncryptedStore(fixture.base, profile)
	if err != nil {
		t.Fatal(err)
	}
	config := fixture.config(wrapped, 1)
	config.ClientEncryption = profile
	config.RecoveryJournal = newRootTestRecoveryJournal()
	if _, err := NewRootPublisher(config); !errors.Is(err, s3disk.ErrStoreMisconfigured) {
		t.Fatalf("prewrapped encrypted Store error = %v, want ErrStoreMisconfigured", err)
	}
	config.Store = &rootRecoveryEncryptedStoreWrapper{ClientEncryptedStore: wrapped}
	if _, err := NewRootPublisher(config); !errors.Is(err, s3disk.ErrStoreMisconfigured) {
		t.Fatalf("wrapped encrypted Store error = %v, want ErrStoreMisconfigured", err)
	}
}

func TestRootPublisherRecoveryRejectsSameRevisionAuthenticatedReplacement(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	closure := fixture.publish(t, "same revision replacement")
	journal := newRootTestRecoveryJournal()
	config := fixture.config(fixture.base, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Create(context.Background(), closure); err != nil {
		t.Fatal(err)
	}
	current, err := fixture.base.Get(context.Background(), fixture.rootKey, s3disk.GetOptions{MaxBytes: MaximumBundleBytes})
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := BuildSnapshotBundle(context.Background(), SnapshotBundleInput{
		RootKey: fixture.rootKey, RootCapability: fixture.rootCapability,
		RepositoryPrefix: fixture.repositoryPrefix, ShareID: fixture.shareID,
		Revision: 1, Closure: closure, Presigner: fixture.presigner,
	}, fixture.signer, fixture.verifier)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(replacement, current.Data) {
		t.Fatal("test replacement unexpectedly reproduced the committed logical root")
	}
	if _, err := fixture.base.CompareAndSwap(context.Background(), fixture.rootKey, &current.Version, replacement); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Create(context.Background(), closure); !errors.Is(err, s3disk.ErrSplitBrain) {
		t.Fatalf("same-revision replacement error = %v, want ErrSplitBrain", err)
	}
}

func TestRootPublisherRecoveryRejectsOldRootReplayAgainstCommittedAnchor(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	first := fixture.publish(t, "old root")
	journal := newRootTestRecoveryJournal()
	config := fixture.config(fixture.base, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Create(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	oldRoot, err := fixture.base.Get(context.Background(), fixture.rootKey, s3disk.GetOptions{MaxBytes: MaximumBundleBytes})
	if err != nil {
		t.Fatal(err)
	}
	second := fixture.publish(t, "new root")
	if publication, err := publisher.Update(context.Background(), second); err != nil || publication.Revision != 2 {
		t.Fatalf("Update = %+v, %v", publication, err)
	}
	current, err := fixture.base.Get(context.Background(), fixture.rootKey, s3disk.GetOptions{MaxBytes: MaximumBundleBytes})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.base.CompareAndSwap(context.Background(), fixture.rootKey, &current.Version, oldRoot.Data); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Update(context.Background(), second); !errors.Is(err, s3disk.ErrRollbackDetected) {
		t.Fatalf("old-root replay error = %v, want ErrRollbackDetected", err)
	}
}

func TestRootPublisherRecoveryPersistsRefreshedBaseVersionBeforeRetry(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	first := fixture.publish(t, "base version one")
	journal := newRootTestRecoveryJournal()
	store := &rootRecoveryFaultStore{base: fixture.base, journal: journal}
	config := fixture.config(store, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Create(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := fixture.publish(t, "pending on refreshed base")
	store.rejectWrites = true
	if _, err := publisher.Update(context.Background(), second); !errors.Is(err, ErrRootPublishIndeterminate) {
		t.Fatalf("first pending Update error = %v", err)
	}
	base, err := fixture.base.Get(context.Background(), fixture.rootKey, s3disk.GetOptions{MaxBytes: MaximumBundleBytes})
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := fixture.base.CompareAndSwap(context.Background(), fixture.rootKey, &base.Version, base.Data)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.VersionID == base.Version.VersionID {
		t.Fatal("test Store did not issue a refreshed diagnostic version")
	}
	if _, err := publisher.Update(context.Background(), second); !errors.Is(err, ErrRootPublishIndeterminate) {
		t.Fatalf("retried pending Update error = %v", err)
	}
	if store.lastWriteExpectedVersionID != refreshed.VersionID {
		t.Fatalf(
			"write observed journal expected version %q, want refreshed %q",
			store.lastWriteExpectedVersionID,
			refreshed.VersionID,
		)
	}
	record := journal.decoded(t)
	if record.Pending == nil || record.Committed == nil ||
		record.Pending.ExpectedVersionID != refreshed.VersionID || record.Committed.VersionID != refreshed.VersionID {
		t.Fatalf("refreshed pending/anchor versions were not durable: %+v", record)
	}
}

func TestRootPublisherRecoveryRejectsDifferentClosureAndIdentityBeforeRootWrite(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	first := fixture.publish(t, "pending-first")
	journal := newRootTestRecoveryJournal()
	store := &rootRecoveryFaultStore{base: fixture.base, journal: journal, rejectWrites: true}
	config := fixture.config(store, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Create(context.Background(), first); !errors.Is(err, ErrRootPublishIndeterminate) {
		t.Fatal(err)
	}
	writes := store.writeCalls
	second := fixture.publish(t, "different-closure")
	if _, err := publisher.Create(context.Background(), second); !errors.Is(err, ErrRootRecoveryState) {
		t.Fatalf("different closure error = %v, want ErrRootRecoveryState", err)
	}
	if store.writeCalls != writes {
		t.Fatal("different closure reached root Store write")
	}

	other := newRootPublisherFixture(t)
	otherClosure := other.publish(t, "other-identity")
	otherStore := &rootRecoveryFaultStore{base: other.base, journal: journal}
	otherConfig := other.config(otherStore, 1)
	otherConfig.RecoveryJournal = journal
	otherPublisher, err := NewRootPublisher(otherConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherPublisher.Create(context.Background(), otherClosure); !errors.Is(err, ErrRootRecoveryState) {
		t.Fatalf("different identity error = %v, want ErrRootRecoveryState", err)
	}
	if otherStore.writeCalls != 0 {
		t.Fatal("different identity reached root Store write")
	}
}

func TestRootRecoveryRecordEncodingIsCanonicalBoundedAndRejectsTrailingData(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	journal := newRootTestRecoveryJournal()
	config := fixture.config(fixture.base, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	record, err := publisher.newRootRecoveryRecord()
	if err != nil {
		t.Fatal(err)
	}
	record.HighestRevision = 1
	record.Pending = &rootRecoveryPending{
		TargetRevision: 1, ExpectedAbsent: true, AllowCreate: true,
		ClosureDigest: s3disk.Digest{1}, TargetDigest: s3disk.Digest{2},
		ReferenceGeneration: 1, ReferenceCommit: s3disk.Digest{3},
	}
	target := []byte("exact secret target")
	record.Pending.TargetDigest = rootRecoveryDigest("target", target)
	encoded, err := encodeRootRecoveryRecord(record, target)
	if err != nil {
		t.Fatal(err)
	}
	decoded, decodedTarget, err := decodeRootRecoveryRecord(encoded)
	if err != nil || !bytes.Equal(decodedTarget, target) || decoded.Pending == nil || decoded.Pending.TargetRevision != 1 {
		t.Fatalf("round trip = %+v, %q, %v", decoded, decodedTarget, err)
	}
	if _, _, err := decodeRootRecoveryRecord(append(append([]byte(nil), encoded...), 0)); !errors.Is(err, ErrRootRecoveryState) {
		t.Fatalf("trailing byte error = %v, want ErrRootRecoveryState", err)
	}
	if _, _, err := decodeRootRecoveryRecord(make([]byte, MaximumRootRecoveryJournalBytes+1)); !errors.Is(err, ErrRootRecoveryState) || !errors.Is(err, s3disk.ErrResourceLimit) {
		t.Fatalf("oversized error = %v", err)
	}
}

func TestRootRecoveryMetadataBoundCoversWorstCaseEscapedProtocolFields(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	publisher, err := NewRootPublisher(fixture.config(fixture.base, 1))
	if err != nil {
		t.Fatal(err)
	}
	record, err := publisher.newRootRecoveryRecord()
	if err != nil {
		t.Fatal(err)
	}
	storeToken := strings.Repeat("\x01", s3disk.MaxStoreVersionTokenBytes)
	objectKey := strings.Repeat("\x02", maximumObjectKeyBytes)
	target := []byte("x")
	record.RepositoryPrefix = objectKey
	record.RootKey = objectKey
	record.ReferenceKey = objectKey
	record.ClientEncryptionWitness = bytes.Repeat([]byte{0xff}, 1024)
	record.HighestRevision = 2
	record.Committed = &rootRecoveryCommitted{
		Revision: 1, LogicalDigest: s3disk.Digest{1}, ReferenceGeneration: 1,
		ReferenceCommit: s3disk.Digest{2}, ETag: storeToken, VersionID: storeToken,
	}
	record.Pending = &rootRecoveryPending{
		TargetRevision: 2, ExpectedETag: storeToken, ExpectedVersionID: storeToken,
		BaseDigest: s3disk.Digest{3}, ClosureDigest: s3disk.Digest{4},
		TargetDigest: rootRecoveryDigest("target", target), LogicalTargetDigest: s3disk.Digest{5},
		ReferenceGeneration: 2, ReferenceCommit: s3disk.Digest{6},
	}

	encoded, err := encodeRootRecoveryRecord(record, target)
	if err != nil {
		t.Fatalf("encode maximum escaped recovery metadata: %v", err)
	}
	metadataBytes := binary.BigEndian.Uint32(encoded[rootRecoveryMetadataLengthOffset:])
	if metadataBytes <= 32<<10 {
		t.Fatalf("hostile metadata used only %d bytes; test no longer covers the old limit", metadataBytes)
	}
	if metadataBytes > maximumRootRecoveryMetadataBytes {
		t.Fatalf("hostile metadata = %d bytes, bound = %d", metadataBytes, maximumRootRecoveryMetadataBytes)
	}
	decoded, decodedTarget, err := decodeRootRecoveryRecord(encoded)
	if err != nil {
		t.Fatalf("decode maximum escaped recovery metadata: %v", err)
	}
	if decoded.RootKey != objectKey || decoded.Committed == nil || decoded.Pending == nil ||
		decoded.Committed.ETag != storeToken || decoded.Pending.ExpectedVersionID != storeToken ||
		!bytes.Equal(decodedTarget, target) {
		t.Fatal("maximum escaped recovery metadata did not round-trip exactly")
	}
}

func TestMaximumRootRecoveryJournalFitsBuiltInSealingBounds(t *testing.T) {
	if int64(MaximumRootRecoveryJournalBytes) > int64(publisherstate.MaximumPlaintextBytes) {
		t.Fatalf(
			"maximum root recovery journal = %d, built-in protector plaintext maximum = %d",
			MaximumRootRecoveryJournalBytes,
			publisherstate.MaximumPlaintextBytes,
		)
	}
	if int64(publisherstate.MaximumEnvelopeBytes) > s3disk.DefaultFileSealedStateMaxEnvelopeBytes {
		t.Fatalf(
			"built-in protector envelope maximum = %d, default sealed-state maximum = %d",
			publisherstate.MaximumEnvelopeBytes,
			s3disk.DefaultFileSealedStateMaxEnvelopeBytes,
		)
	}
	key, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	protector, err := publisherstate.NewAESGCMProtector("root-boundary", key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := make([]byte, MaximumRootRecoveryJournalBytes)
	plaintext[0] = 0x51
	plaintext[len(plaintext)-1] = 0xa7
	envelope, err := protector.Seal(context.Background(), []byte("root-recovery-boundary"), plaintext)
	clear(plaintext)
	plaintext = nil
	if err != nil {
		t.Fatalf("seal maximum root recovery journal: %v", err)
	}
	opened, err := protector.Open(context.Background(), []byte("root-recovery-boundary"), envelope)
	clear(envelope)
	if err != nil {
		t.Fatalf("open maximum root recovery journal: %v", err)
	}
	defer clear(opened)
	if int64(len(opened)) != MaximumRootRecoveryJournalBytes || opened[0] != 0x51 || opened[len(opened)-1] != 0xa7 {
		t.Fatal("maximum root recovery journal did not round-trip through the built-in protector")
	}
}

func FuzzDecodeRootRecoveryRecordNeverPanics(f *testing.F) {
	target := []byte("fuzz-exact-target")
	record := rootRecoveryRecord{
		Format:          rootRecoveryFormatVersion,
		HighestRevision: 1,
		Pending: &rootRecoveryPending{
			TargetRevision: 1,
			AllowCreate:    true,
			ExpectedAbsent: true,
			TargetDigest:   rootRecoveryDigest("target", target),
		},
	}
	valid, err := encodeRootRecoveryRecord(record, target)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{})
	f.Add([]byte("not-a-root-recovery-record"))
	f.Add(valid)

	f.Fuzz(func(t *testing.T, encoded []byte) {
		_, decodedTarget, _ := decodeRootRecoveryRecord(encoded)
		clear(decodedTarget)
	})
}

func TestRootPublisherRecoveryRejectsCorruptJournalBeforeRootStoreIO(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	closure := fixture.publish(t, "corrupt recovery state")
	journal := newRootTestRecoveryJournal()
	store := &rootRecoveryFaultStore{base: fixture.base, journal: journal, rejectWrites: true}
	config := fixture.config(store, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Create(context.Background(), closure); !errors.Is(err, ErrRootPublishIndeterminate) {
		t.Fatal(err)
	}
	writes := store.writeCalls
	journal.mu.Lock()
	journal.data[len(journal.data)-1] ^= 0x80
	journal.mu.Unlock()
	if _, err := publisher.Create(context.Background(), closure); !errors.Is(err, ErrRootRecoveryState) {
		t.Fatalf("corrupt journal error = %v, want ErrRootRecoveryState", err)
	}
	if store.writeCalls != writes {
		t.Fatal("corrupt journal reached root Store write")
	}
}

func TestRootPublisherRecoveryRejectsInconsistentJournalLoadResultsBeforeRootStoreIO(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	closure := fixture.publish(t, "inconsistent journal load")
	nonzeroRevision := s3disk.SealedStateRevision{1}
	for _, test := range []struct {
		name     string
		data     []byte
		revision s3disk.SealedStateRevision
		found    bool
	}{
		{name: "absent with data", data: []byte("unexpected")},
		{name: "absent with revision", revision: nonzeroRevision},
		{name: "present with zero revision", data: []byte("unexpected"), found: true},
		{name: "present with empty data", revision: nonzeroRevision, found: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal := &rootRecoveryLoadResultJournal{
				data: test.data, revision: test.revision, found: test.found,
			}
			store := &rootRecoveryFaultStore{base: fixture.base, journal: newRootTestRecoveryJournal()}
			config := fixture.config(store, 1)
			config.RecoveryJournal = journal
			publisher, err := NewRootPublisher(config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := publisher.Create(context.Background(), closure); !errors.Is(err, ErrRootRecoveryState) {
				t.Fatalf("Create error = %v, want ErrRootRecoveryState", err)
			}
			if store.writeCalls != 0 || journal.compareAndSwapCalls != 0 {
				t.Fatal("inconsistent journal load reached a write")
			}
		})
	}
}

func TestRootPublisherRecoveryRedactsJournalErrorsBeforeRootStoreIO(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	closure := fixture.publish(t, "journal error redaction")
	journal := newRootTestRecoveryJournal()
	journal.compareAndSwapError = errors.New("test journal leaked https://provider.invalid/bearer-secret")
	store := &rootRecoveryFaultStore{base: fixture.base, journal: journal}
	config := fixture.config(store, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = publisher.Create(context.Background(), closure)
	if !errors.Is(err, ErrRootRecoveryIndeterminate) {
		t.Fatalf("journal CAS error = %v, want ErrRootRecoveryIndeterminate", err)
	}
	if strings.Contains(err.Error(), "provider.invalid") || strings.Contains(err.Error(), "bearer-secret") {
		t.Fatalf("journal error leaked through recovery boundary: %v", err)
	}
	if store.writeCalls != 0 {
		t.Fatal("failed journal CAS reached root Store write")
	}
}

func TestRootPublisherRecoveryClassifiesAndRedactsJournalLoadErrors(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	closure := fixture.publish(t, "journal load error redaction")
	journal := &rootRecoveryLoadResultJournal{
		loadErr: errors.New("test journal leaked https://provider.invalid/load-bearer-secret"),
	}
	store := &rootRecoveryFaultStore{base: fixture.base, journal: newRootTestRecoveryJournal()}
	config := fixture.config(store, 1)
	config.RecoveryJournal = journal
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = publisher.Create(context.Background(), closure)
	if !errors.Is(err, ErrRootRecoveryIndeterminate) || errors.Is(err, ErrRootRecoveryState) {
		t.Fatalf("journal Load error = %v, want only ErrRootRecoveryIndeterminate", err)
	}
	if strings.Contains(err.Error(), "provider.invalid") || strings.Contains(err.Error(), "load-bearer-secret") {
		t.Fatalf("journal Load error leaked through recovery boundary: %v", err)
	}
	if store.writeCalls != 0 || journal.compareAndSwapCalls != 0 {
		t.Fatal("failed journal Load reached a write")
	}
}

func TestRootRecoveryJournalErrorPreservesSafeClassification(t *testing.T) {
	for _, test := range []struct {
		name      string
		cause     error
		want      error
		wantState bool
	}{
		{name: "canceled", cause: context.Canceled, want: context.Canceled},
		{name: "deadline", cause: context.DeadlineExceeded, want: context.DeadlineExceeded},
		{name: "precondition", cause: s3disk.ErrPrecondition, want: s3disk.ErrPrecondition, wantState: true},
		{name: "resource limit", cause: s3disk.ErrResourceLimit, want: s3disk.ErrResourceLimit, wantState: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := rootRecoveryJournalError("load", test.cause)
			if !errors.Is(err, test.want) || errors.Is(err, ErrRootRecoveryState) != test.wantState ||
				errors.Is(err, ErrRootRecoveryIndeterminate) == test.wantState {
				t.Fatalf("classification = %v", err)
			}
		})
	}
}

type rootTestRecoveryJournal struct {
	mu                      sync.Mutex
	data                    []byte
	revision                s3disk.Digest
	found                   bool
	next                    uint64
	loseNextCASResponse     bool
	failLoadAfterLostCAS    bool
	failNextLoad            bool
	compareAndSwapError     error
	compareAndSwapCallCount int
}

type rootRecoveryLoadResultJournal struct {
	data                []byte
	revision            s3disk.SealedStateRevision
	found               bool
	loadErr             error
	compareAndSwapCalls int
}

func (journal *rootRecoveryLoadResultJournal) Load(context.Context) ([]byte, s3disk.SealedStateRevision, bool, error) {
	return bytes.Clone(journal.data), journal.revision, journal.found, journal.loadErr
}

func (journal *rootRecoveryLoadResultJournal) CompareAndSwap(
	context.Context,
	*s3disk.SealedStateRevision,
	[]byte,
) (s3disk.SealedStateRevision, error) {
	journal.compareAndSwapCalls++
	return s3disk.SealedStateRevision{}, errors.New("test: unexpected journal write")
}

func newRootTestRecoveryJournal() *rootTestRecoveryJournal {
	return &rootTestRecoveryJournal{next: 1}
}

func (journal *rootTestRecoveryJournal) Load(ctx context.Context) ([]byte, s3disk.SealedStateRevision, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, s3disk.Digest{}, false, err
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.failNextLoad {
		journal.failNextLoad = false
		return nil, s3disk.Digest{}, false, errors.New("test: journal reconciliation load failed")
	}
	return append([]byte(nil), journal.data...), journal.revision, journal.found, nil
}

func (journal *rootTestRecoveryJournal) CompareAndSwap(
	ctx context.Context,
	expected *s3disk.SealedStateRevision,
	next []byte,
) (s3disk.SealedStateRevision, error) {
	if err := ctx.Err(); err != nil {
		return s3disk.Digest{}, err
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	journal.compareAndSwapCallCount++
	if journal.compareAndSwapError != nil {
		return s3disk.Digest{}, journal.compareAndSwapError
	}
	if expected == nil {
		if journal.found {
			return s3disk.Digest{}, s3disk.ErrPrecondition
		}
	} else if !journal.found || journal.revision != *expected {
		return s3disk.Digest{}, s3disk.ErrPrecondition
	}
	var revision s3disk.Digest
	binary.BigEndian.PutUint64(revision[len(revision)-8:], journal.next)
	journal.next++
	journal.data = append([]byte(nil), next...)
	journal.revision = revision
	journal.found = true
	if journal.loseNextCASResponse {
		journal.loseNextCASResponse = false
		journal.failNextLoad = journal.failLoadAfterLostCAS
		journal.failLoadAfterLostCAS = false
		return revision, errors.New("test: journal CAS response lost")
	}
	return revision, nil
}

func (journal *rootTestRecoveryJournal) loseNextResponse(failReconcile bool) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	journal.loseNextCASResponse = true
	journal.failLoadAfterLostCAS = failReconcile
}

type rootRecoveryTestReporter interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

func (journal *rootTestRecoveryJournal) decoded(t rootRecoveryTestReporter) rootRecoveryRecord {
	t.Helper()
	data, _, found, err := journal.Load(context.Background())
	if err != nil || !found {
		t.Fatalf("journal Load = found %v, error %v", found, err)
	}
	record, _, err := decodeRootRecoveryRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func (journal *rootTestRecoveryJournal) target(t rootRecoveryTestReporter) []byte {
	t.Helper()
	data, _, found, err := journal.Load(context.Background())
	if err != nil || !found {
		t.Fatalf("journal Load = found %v, error %v", found, err)
	}
	_, target, err := decodeRootRecoveryRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

type rootRecoveryFaultStore struct {
	base                        s3disk.Store
	journal                     *rootTestRecoveryJournal
	rejectWrites                bool
	losePutResponse             bool
	failReconcileAfterLostWrite bool
	failNextGet                 bool
	loseJournalCommitResponse   bool
	failJournalCommitReconcile  bool
	blockWritesUntilContext     bool
	lastWriteDeadline           time.Time
	lastWriteHadDeadline        bool
	writeSawPending             bool
	lastWriteExpectedVersionID  string
	writeCalls                  int
	target                      []byte
	mu                          sync.Mutex
}

type rootRecoveryEncryptedStoreWrapper struct {
	*s3disk.ClientEncryptedStore
}

func (store *rootRecoveryFaultStore) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	store.mu.Lock()
	fail := store.failNextGet
	store.failNextGet = false
	store.mu.Unlock()
	if fail {
		return s3disk.Object{}, s3disk.ErrStoreUnavailable
	}
	return store.base.Get(ctx, key, options)
}

func (store *rootRecoveryFaultStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	return store.base.Head(ctx, key)
}

func (store *rootRecoveryFaultStore) PutIfAbsent(ctx context.Context, key string, data []byte) (s3disk.Version, error) {
	store.observeWrite(data)
	if store.blockWritesUntilContext {
		store.recordWriteDeadline(ctx)
		<-ctx.Done()
		return s3disk.Version{}, ctx.Err()
	}
	if store.rejectWrites {
		return s3disk.Version{}, s3disk.ErrStoreUnavailable
	}
	version, err := store.base.PutIfAbsent(ctx, key, data)
	if err == nil && store.losePutResponse {
		store.losePutResponse = false
		store.mu.Lock()
		store.failNextGet = store.failReconcileAfterLostWrite
		store.mu.Unlock()
		return s3disk.Version{}, errors.New("test: applied root write response lost")
	}
	return version, err
}

func (store *rootRecoveryFaultStore) CompareAndSwap(
	ctx context.Context,
	key string,
	expected *s3disk.Version,
	data []byte,
) (s3disk.Version, error) {
	store.observeWrite(data)
	if store.blockWritesUntilContext {
		store.recordWriteDeadline(ctx)
		<-ctx.Done()
		return s3disk.Version{}, ctx.Err()
	}
	if store.rejectWrites {
		return s3disk.Version{}, s3disk.ErrStoreUnavailable
	}
	return store.base.CompareAndSwap(ctx, key, expected, data)
}

func (store *rootRecoveryFaultStore) recordWriteDeadline(ctx context.Context) {
	deadline, ok := ctx.Deadline()
	store.mu.Lock()
	defer store.mu.Unlock()
	store.lastWriteDeadline = deadline
	store.lastWriteHadDeadline = ok
}

func (store *rootRecoveryFaultStore) observeWrite(data []byte) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.writeCalls++
	store.target = append([]byte(nil), data...)
	if store.loseJournalCommitResponse {
		store.journal.loseNextResponse(store.failJournalCommitReconcile)
		store.loseJournalCommitResponse = false
	}
	record := store.journal.decoded(testingTBridge{fatal: func(message string) { panic(message) }})
	store.writeSawPending = record.Pending != nil && record.Pending.TargetDigest == rootRecoveryDigest("target", data)
	if record.Pending != nil {
		store.lastWriteExpectedVersionID = record.Pending.ExpectedVersionID
	}
}

func (store *rootRecoveryFaultStore) lastTarget() []byte {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]byte(nil), store.target...)
}

// testingTBridge keeps the Store hook independent of *testing.T while reusing
// the strict journal decoder. A decoder failure is a production invariant
// violation and deliberately panics the test goroutine.
type testingTBridge struct{ fatal func(string) }

func (bridge testingTBridge) Helper() {}
func (bridge testingTBridge) Fatal(args ...any) {
	bridge.fatal(fmt.Sprint(args...))
}
func (bridge testingTBridge) Fatalf(format string, args ...any) {
	bridge.fatal(fmt.Sprintf(format, args...))
}

type rootRecoveryNilContext struct{}

func (*rootRecoveryNilContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*rootRecoveryNilContext) Done() <-chan struct{}       { return nil }
func (*rootRecoveryNilContext) Err() error                  { return nil }
func (*rootRecoveryNilContext) Value(any) any               { return nil }

var _ s3disk.SealedStateStore = (*rootTestRecoveryJournal)(nil)
var _ s3disk.SealedStateStore = (*rootRecoveryLoadResultJournal)(nil)
var _ s3disk.Store = (*rootRecoveryFaultStore)(nil)
