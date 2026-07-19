package s3disk_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

type faultPublicationJournal struct {
	base s3disk.PublicationJournalStore

	mu           sync.Mutex
	loseBegin    bool
	loseFinalize bool
	sawPending   bool
}

type zeroPendingRevisionJournal struct {
	base s3disk.PublicationJournalStore
	once sync.Once
}

func (journal *zeroPendingRevisionJournal) Load(ctx context.Context, channel string) (s3disk.PublicationJournalState, s3disk.PublicationJournalRevision, bool, error) {
	return journal.base.Load(ctx, channel)
}

func (journal *zeroPendingRevisionJournal) CompareAndSwap(
	ctx context.Context,
	channel string,
	expected *s3disk.PublicationJournalRevision,
	next s3disk.PublicationJournalState,
) (s3disk.PublicationJournalRevision, error) {
	revision, err := journal.base.CompareAndSwap(ctx, channel, expected, next)
	if err == nil && next.Pending != nil {
		zero := false
		journal.once.Do(func() { zero = true })
		if zero {
			return s3disk.PublicationJournalRevision{}, nil
		}
	}
	return revision, err
}

func TestEmptyPublicationJournalRequiresFreshBootstrapChoice(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, signer, _, verifier, _ := signedTestKeys(t)
	repository, err := s3disk.NewRepository(memstore.New(), "empty-journal-bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	journal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "publisher.journal"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.CompareAndSwap(ctx, "main", nil, s3disk.PublicationJournalState{
		RepositoryID: verifier.RepositoryID(), Channel: "main",
	}); err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: signer, ReferenceVerifier: verifier, PublicationJournal: journal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Stage(ctx, privateTestDirectory(t), "main"); !errors.Is(err, s3disk.ErrTrustStateRequired) {
		t.Fatalf("Stage with an unanchored empty journal error = %v, want ErrTrustStateRequired", err)
	}
}

func TestSignedPublisherRejectsZeroJournalRevisionBeforeRemoteCAS(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, signer, _, verifier, _ := signedTestKeys(t)
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "zero-journal-revision")
	if err != nil {
		t.Fatal(err)
	}
	fileJournal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "publisher.journal"))
	if err != nil {
		t.Fatal(err)
	}
	journal := &zeroPendingRevisionJournal{base: fileJournal}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: signer, ReferenceVerifier: verifier,
		PublicationJournal: journal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("not remotely visible yet"))
	if _, err := publisher.Publish(ctx, source, "main"); !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("Publish error = %v, want ErrStoreIncompatible", err)
	}
	if _, err := store.Get(ctx, repository.SignedReferenceKey("main"), s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrObjectNotFound) {
		t.Fatalf("signed reference exists after zero journal revision: %v", err)
	}
	state, revision, found, err := fileJournal.Load(ctx, "main")
	if err != nil || !found || revision.IsZero() || state.Pending == nil {
		t.Fatalf("durable pending after incompatible response = %+v, revision=%v, found=%v, err=%v", state, revision, found, err)
	}
	recovery, err := publisher.RecoverPublication(ctx, "main")
	if err != nil || recovery.Outcome != s3disk.PublicationRecoveryApplied {
		t.Fatalf("explicit recovery after zero response = %+v, %v", recovery, err)
	}
}

func TestSignedPublisherRejectsVersionIDOnlyReferenceBeforePending(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, signer, _, verifier, _ := signedTestKeys(t)
	base := memstore.New()
	store := &hookedStore{base: base}
	repository, err := s3disk.NewRepository(store, "version-id-only-reference")
	if err != nil {
		t.Fatal(err)
	}
	journal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "publisher.journal"))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: signer, ReferenceVerifier: verifier,
		PublicationJournal: journal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	filename := filepath.Join(source, "data")
	writeFile(t, filename, []byte("one"))
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	store.get = func(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
		object, err := base.Get(ctx, key, options)
		if err == nil && key == repository.SignedReferenceKey("main") {
			object.Version.ETag = ""
			if object.Version.VersionID == "" {
				object.Version.VersionID = "diagnostic-only"
			}
		}
		return object, err
	}
	writeFile(t, filename, []byte("two"))
	if _, err := publisher.Stage(ctx, source, "main"); !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("Stage error = %v, want ErrStoreIncompatible", err)
	}
	state, _, found, err := journal.Load(ctx, "main")
	if err != nil || !found || state.Committed == nil || state.Pending != nil {
		t.Fatalf("journal after rejected reference = %+v, found=%v, err=%v", state, found, err)
	}
}

func (journal *faultPublicationJournal) Load(ctx context.Context, channel string) (s3disk.PublicationJournalState, s3disk.PublicationJournalRevision, bool, error) {
	return journal.base.Load(ctx, channel)
}

func (journal *faultPublicationJournal) CompareAndSwap(
	ctx context.Context,
	channel string,
	expected *s3disk.PublicationJournalRevision,
	next s3disk.PublicationJournalState,
) (s3disk.PublicationJournalRevision, error) {
	revision, err := journal.base.CompareAndSwap(ctx, channel, expected, next)
	if err != nil {
		return revision, err
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if next.Pending != nil {
		journal.sawPending = true
		if journal.loseBegin {
			journal.loseBegin = false
			return s3disk.PublicationJournalRevision{}, errInjectedNetwork
		}
	}
	if next.Pending == nil && next.Committed != nil && journal.sawPending && journal.loseFinalize {
		journal.loseFinalize = false
		return s3disk.PublicationJournalRevision{}, errInjectedNetwork
	}
	return revision, nil
}

func TestSignedPublishReconcilesLostJournalCASResponses(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		loseBegin    bool
		loseFinalize bool
	}{
		{name: "begin", loseBegin: true},
		{name: "finalize", loseFinalize: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			_, signer, _, verifier, _ := signedTestKeys(t)
			store := memstore.New()
			repository, err := s3disk.NewRepository(store, "lost-journal-"+test.name)
			if err != nil {
				t.Fatal(err)
			}
			fileJournal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "publisher.journal"))
			if err != nil {
				t.Fatal(err)
			}
			journal := &faultPublicationJournal{
				base: fileJournal, loseBegin: test.loseBegin, loseFinalize: test.loseFinalize,
			}
			publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
				ReferenceSigner: signer, ReferenceVerifier: verifier,
				PublicationJournal: journal, AllowTrustOnFirstUse: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			source := privateTestDirectory(t)
			writeFile(t, filepath.Join(source, "data"), []byte("journal response loss"))
			snapshot, err := publisher.Publish(ctx, source, "main")
			if err != nil {
				t.Fatalf("publish after lost journal %s response: %v", test.name, err)
			}
			state, _, found, err := fileJournal.Load(ctx, "main")
			if err != nil || !found || state.Pending != nil || state.Committed == nil ||
				state.Committed.Generation != snapshot.Generation || state.Committed.Commit != snapshot.Commit {
				t.Fatalf("journal after reconciled %s response = %+v, found=%v, err=%v", test.name, state, found, err)
			}
		})
	}
}

func TestSignedPublishRecoversSuccessfulRemoteCASWithLostResponse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, signer, _, verifier, _ := signedTestKeys(t)
	base := memstore.New()
	store := &hookedStore{base: base}
	repository, err := s3disk.NewRepository(store, "signed-lost-remote-response")
	if err != nil {
		t.Fatal(err)
	}
	loseResponse := true
	store.compareAndSwap = func(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
		version, err := base.CompareAndSwap(ctx, key, expected, data)
		if err == nil && key == repository.SignedReferenceKey("main") && loseResponse {
			loseResponse = false
			return s3disk.Version{}, errInjectedNetwork
		}
		return version, err
	}
	journal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "publisher.journal"))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: signer, ReferenceVerifier: verifier,
		PublicationJournal: journal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("remote response loss"))
	if snapshot, err := publisher.Publish(ctx, source, "main"); err != nil || snapshot.Generation != 1 {
		t.Fatalf("signed publish after lost successful remote CAS = %+v, %v", snapshot, err)
	}
	state, _, found, err := journal.Load(ctx, "main")
	if err != nil || !found || state.Pending != nil || state.Committed == nil || state.Committed.Generation != 1 {
		t.Fatalf("journal after remote response loss = %+v, found=%v, err=%v", state, found, err)
	}
}

func TestSignedStagedPublishSurvivesBaseResign(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, oldSigner, newSigner, verifier, _ := signedTestKeys(t)
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "staged-across-resign")
	if err != nil {
		t.Fatal(err)
	}
	journal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "publisher.journal"))
	if err != nil {
		t.Fatal(err)
	}
	oldPublisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: oldSigner, ReferenceVerifier: verifier,
		PublicationJournal: journal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	filename := filepath.Join(source, "data")
	writeFile(t, filename, []byte("one"))
	if _, err := oldPublisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filename, []byte("two"))
	staged, err := oldPublisher.Stage(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	newPublisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: newSigner, ReferenceVerifier: verifier, PublicationJournal: journal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newPublisher.ResignReference(ctx, "main"); err != nil {
		t.Fatal(err)
	}
	resigned, err := store.Get(ctx, repository.SignedReferenceKey("main"), s3disk.GetOptions{})
	if err != nil || !bytes.Contains(resigned.Data, []byte(`"key_id":"online-2026-b"`)) {
		t.Fatalf("base reference was not re-signed: %s, %v", resigned.Data, err)
	}
	second, err := oldPublisher.Commit(ctx, staged)
	if err != nil {
		t.Fatalf("commit staged before base re-sign: %v", err)
	}
	if second.Generation != 2 || second.Commit != staged.Snapshot.Commit {
		t.Fatalf("commit after base re-sign = %+v, want staged %+v", second, staged.Snapshot)
	}
	state, _, found, err := journal.Load(ctx, "main")
	if err != nil || !found || state.Pending != nil || state.Committed == nil || state.Committed.Generation != 2 {
		t.Fatalf("journal after base re-sign publication = %+v, found=%v, err=%v", state, found, err)
	}
}

func TestResignRecoveryUsesExactJournaledEnvelopeWithoutSigner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, oldSigner, newSigner, verifier, _ := signedTestKeys(t)
	base := memstore.New()
	store := &hookedStore{base: base}
	repository, err := s3disk.NewRepository(store, "resign-recovery")
	if err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(privateTestDirectory(t), "publisher.journal")
	journal, err := s3disk.NewFilePublicationJournal(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	oldPublisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: oldSigner, ReferenceVerifier: verifier,
		PublicationJournal: journal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("one"))
	if _, err := oldPublisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	newPublisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: newSigner, ReferenceVerifier: verifier, PublicationJournal: journal,
	})
	if err != nil {
		t.Fatal(err)
	}
	dropResign := true
	store.compareAndSwap = func(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
		if dropResign && key == repository.SignedReferenceKey("main") {
			return s3disk.Version{}, errInjectedNetwork
		}
		return base.CompareAndSwap(ctx, key, expected, data)
	}
	if _, err := newPublisher.ResignReference(ctx, "main"); !errors.Is(err, s3disk.ErrPublishIndeterminate) {
		t.Fatalf("dropped re-sign error = %v, want ErrPublishIndeterminate", err)
	}
	state, _, found, err := journal.Load(ctx, "main")
	if err != nil || !found || state.Pending == nil || state.Pending.Kind != s3disk.PublicationIntentResign {
		t.Fatalf("pending re-sign state = %+v, found=%v, err=%v", state, found, err)
	}
	wantIntentID := state.Pending.IntentID
	wantReference := append([]byte(nil), state.Pending.Reference...)
	dropResign = false
	restartedJournal, err := s3disk.NewFilePublicationJournal(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	unavailable := &unavailableReferenceSigner{delegate: newSigner}
	restarted, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: unavailable, ReferenceVerifier: verifier, PublicationJournal: restartedJournal,
	})
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := restarted.RecoverPublication(ctx, "main")
	if err != nil {
		t.Fatalf("recover re-sign: %v", err)
	}
	if recovery.Outcome != s3disk.PublicationRecoveryApplied || recovery.IntentID != wantIntentID || unavailable.calls != 0 {
		t.Fatalf("re-sign recovery = %+v, signer calls=%d", recovery, unavailable.calls)
	}
	visible, err := base.Get(ctx, repository.SignedReferenceKey("main"), s3disk.GetOptions{})
	if err != nil || !bytes.Equal(visible.Data, wantReference) {
		t.Fatalf("visible recovered re-sign does not equal journaled bytes: err=%v", err)
	}
}

func TestConcurrentResignRecoveryNeverUsesCommitAncestryAsEnvelopeProof(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, oldSigner, newSigner, verifier, _ := signedTestKeys(t)
	base := memstore.New()
	store := &hookedStore{base: base}
	repository, err := s3disk.NewRepository(store, "resign-envelope-proof")
	if err != nil {
		t.Fatal(err)
	}
	journal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "shared.journal"))
	if err != nil {
		t.Fatal(err)
	}
	oldPublisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: oldSigner, ReferenceVerifier: verifier,
		PublicationJournal: journal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	filename := filepath.Join(source, "data")
	writeFile(t, filename, []byte("generation one"))
	first, err := oldPublisher.Publish(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}

	// Block the exact re-sign CAS after it has durably occupied Pending. A
	// separate authorized publisher then advances the commit chain from the old
	// envelope, proving that commit ancestry cannot prove the re-sign happened.
	blocked := make(chan struct{})
	release := make(chan struct{})
	var blockMu sync.Mutex
	blockNextReferenceCAS := true
	store.compareAndSwap = func(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
		blockMu.Lock()
		shouldBlock := key == repository.SignedReferenceKey("main") && blockNextReferenceCAS
		if shouldBlock {
			blockNextReferenceCAS = false
		}
		blockMu.Unlock()
		if shouldBlock {
			close(blocked)
			select {
			case <-release:
			case <-ctx.Done():
				return s3disk.Version{}, ctx.Err()
			}
		}
		return base.CompareAndSwap(ctx, key, expected, data)
	}
	resigner, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: newSigner, ReferenceVerifier: verifier, PublicationJournal: journal,
	})
	if err != nil {
		t.Fatal(err)
	}
	resignDone := make(chan error, 1)
	go func() {
		_, resignErr := resigner.ResignReference(ctx, "main")
		resignDone <- resignErr
	}()
	select {
	case <-blocked:
	case <-ctx.Done():
		t.Fatalf("re-sign did not reach blocked remote CAS: %v", ctx.Err())
	}
	state, _, found, err := journal.Load(ctx, "main")
	if err != nil || !found || state.Pending == nil || state.Pending.Kind != s3disk.PublicationIntentResign {
		t.Fatalf("blocked re-sign journal = %+v, found=%v, err=%v", state, found, err)
	}
	targetEnvelope := append([]byte(nil), state.Pending.Reference...)

	competitorJournal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "competitor.journal"))
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := s3disk.Watermark{
		RepositoryID: verifier.RepositoryID(), Generation: first.Generation, Commit: first.Commit,
	}
	competitor, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: oldSigner, ReferenceVerifier: verifier,
		PublicationJournal: competitorJournal, TrustedCheckpoint: &checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filename, []byte("generation two"))
	second, err := competitor.Publish(ctx, source, "main")
	if err != nil || second.Generation != 2 {
		t.Fatalf("competing descendant = %+v, error %v", second, err)
	}

	recoveryPublisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: newSigner, ReferenceVerifier: verifier, PublicationJournal: journal,
	})
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := recoveryPublisher.RecoverPublication(ctx, "main")
	if err != nil {
		t.Fatalf("recover re-sign behind descendant: %v", err)
	}
	if recovery.Outcome != s3disk.PublicationRecoverySuperseded || recovery.Current.Commit != second.Commit {
		t.Fatalf("re-sign recovery = %+v, want Superseded by %+v", recovery, second)
	}
	close(release)
	if err := <-resignDone; !errors.Is(err, s3disk.ErrPublishConflict) {
		t.Fatalf("concurrent original ResignReference error = %v, want ErrPublishConflict", err)
	}
	visible, err := base.Get(ctx, repository.SignedReferenceKey("main"), s3disk.GetOptions{})
	if err != nil || bytes.Equal(visible.Data, targetEnvelope) {
		t.Fatalf("target re-sign envelope unexpectedly visible: equal=%v, err=%v", bytes.Equal(visible.Data, targetEnvelope), err)
	}
}

func TestSignedRecoveryClassifiesConcurrentWinner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, signer, _, verifier, _ := signedTestKeys(t)
	base := memstore.New()
	store := &hookedStore{base: base}
	repository, err := s3disk.NewRepository(store, "signed-recovery-winner")
	if err != nil {
		t.Fatal(err)
	}
	journalA, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "publisher-a.journal"))
	if err != nil {
		t.Fatal(err)
	}
	publisherA, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: signer, ReferenceVerifier: verifier,
		PublicationJournal: journalA, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	baseSource := privateTestDirectory(t)
	baseFile := filepath.Join(baseSource, "data")
	writeFile(t, baseFile, []byte("base"))
	first, err := publisherA.Publish(ctx, baseSource, "main")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, baseFile, []byte("branch-a"))
	stagedA, err := publisherA.Stage(ctx, baseSource, "main")
	if err != nil {
		t.Fatal(err)
	}
	dropA := true
	store.compareAndSwap = func(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
		if dropA && key == repository.SignedReferenceKey("main") {
			return s3disk.Version{}, errInjectedNetwork
		}
		return base.CompareAndSwap(ctx, key, expected, data)
	}
	if _, err := publisherA.Commit(ctx, stagedA); !errors.Is(err, s3disk.ErrPublishIndeterminate) {
		t.Fatalf("branch A dropped CAS error = %v, want ErrPublishIndeterminate", err)
	}
	dropA = false
	journalB, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "publisher-b.journal"))
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := s3disk.Watermark{RepositoryID: verifier.RepositoryID(), Generation: first.Generation, Commit: first.Commit}
	publisherB, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: signer, ReferenceVerifier: verifier,
		PublicationJournal: journalB, TrustedCheckpoint: &checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	branchB := privateTestDirectory(t)
	writeFile(t, filepath.Join(branchB, "data"), []byte("branch-b"))
	winner, err := publisherB.Publish(ctx, branchB, "main")
	if err != nil {
		t.Fatal(err)
	}
	if winner.Generation != 2 || winner.Commit == stagedA.Snapshot.Commit {
		t.Fatalf("concurrent winner = %+v, staged A = %+v", winner, stagedA.Snapshot)
	}
	recovery, err := publisherA.RecoverPublication(ctx, "main")
	if err != nil {
		t.Fatalf("recover superseded publication: %v", err)
	}
	if recovery.Outcome != s3disk.PublicationRecoverySuperseded || recovery.Current.Commit != winner.Commit {
		t.Fatalf("recovery = %+v, want superseded by %+v", recovery, winner)
	}
}

func TestSignedRecoveryRecognizesPublishedDescendant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, signer, _, verifier, _ := signedTestKeys(t)
	base := memstore.New()
	store := &hookedStore{base: base}
	repository, err := s3disk.NewRepository(store, "signed-recovery-descendant")
	if err != nil {
		t.Fatal(err)
	}
	journalA, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "publisher-a.journal"))
	if err != nil {
		t.Fatal(err)
	}
	publisherA, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: signer, ReferenceVerifier: verifier,
		PublicationJournal: journalA, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	sourceA := privateTestDirectory(t)
	filename := filepath.Join(sourceA, "data")
	writeFile(t, filename, []byte("one"))
	first, err := publisherA.Publish(ctx, sourceA, "main")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filename, []byte("two"))
	staged, err := publisherA.Stage(ctx, sourceA, "main")
	if err != nil {
		t.Fatal(err)
	}
	loseRemoteResponse := true
	failReconcileRead := false
	store.compareAndSwap = func(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
		version, err := base.CompareAndSwap(ctx, key, expected, data)
		if err == nil && key == repository.SignedReferenceKey("main") && loseRemoteResponse {
			loseRemoteResponse = false
			failReconcileRead = true
			return s3disk.Version{}, errInjectedNetwork
		}
		return version, err
	}
	store.get = func(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
		if key == repository.SignedReferenceKey("main") && failReconcileRead {
			failReconcileRead = false
			return s3disk.Object{}, errInjectedNetwork
		}
		return base.Get(ctx, key, options)
	}
	if _, err := publisherA.Commit(ctx, staged); !errors.Is(err, s3disk.ErrPublishIndeterminate) {
		t.Fatalf("lost response with failed reconciliation = %v, want ErrPublishIndeterminate", err)
	}

	journalB, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "publisher-b.journal"))
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := s3disk.Watermark{RepositoryID: verifier.RepositoryID(), Generation: first.Generation, Commit: first.Commit}
	publisherB, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: signer, ReferenceVerifier: verifier,
		PublicationJournal: journalB, TrustedCheckpoint: &checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	sourceB := privateTestDirectory(t)
	writeFile(t, filepath.Join(sourceB, "data"), []byte("three"))
	third, err := publisherB.Publish(ctx, sourceB, "main")
	if err != nil {
		t.Fatal(err)
	}
	if third.Generation != 3 {
		t.Fatalf("descendant generation = %d, want 3", third.Generation)
	}
	recovery, err := publisherA.RecoverPublication(ctx, "main")
	if err != nil {
		t.Fatalf("recover published ancestor: %v", err)
	}
	if recovery.Outcome != s3disk.PublicationRecoveryApplied || recovery.IntentID.IsZero() || recovery.Current.Commit != third.Commit {
		t.Fatalf("descendant recovery = %+v, want applied with current %+v", recovery, third)
	}
}
