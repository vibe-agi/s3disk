package s3disk

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestFilePublicationJournalPendingToCommitted(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repositoryID := RepositoryID{1}
	journalPath := filepath.Join(privateTestDirectory(t), "private", "main.journal")
	journal, err := NewFilePublicationJournal(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	next := Watermark{RepositoryID: repositoryID, Generation: 1, Commit: Digest{1}}
	pending := testPublicationIntent(t, repositoryID, "main", PublicationIntentPublish, nil, next, nil, nil, 1)
	wantPending := PublicationJournalState{
		RepositoryID: repositoryID, Channel: "main", Pending: &pending,
	}
	revision, err := journal.CompareAndSwap(ctx, "main", nil, wantPending)
	if err != nil {
		t.Fatal(err)
	}
	if revision.IsZero() {
		t.Fatal("CompareAndSwap returned a zero revision")
	}

	got, loadedRevision, found, err := journal.Load(ctx, "main")
	if err != nil || !found || loadedRevision != revision || !equalPublicationJournalStates(got, wantPending) {
		t.Fatalf("Load = %+v, %v, %v, %v; want pending state, revision %s", got, loadedRevision, found, err, revision)
	}

	wantCommitted := PublicationJournalState{
		RepositoryID: repositoryID, Channel: "main", Committed: &next,
	}
	committedRevision, err := journal.CompareAndSwap(ctx, "main", &revision, wantCommitted)
	if err != nil {
		t.Fatal(err)
	}
	if committedRevision.IsZero() || committedRevision == revision {
		t.Fatalf("committed revision = %s, want a new non-zero revision", committedRevision)
	}
	got, loadedRevision, found, err = journal.Load(ctx, "main")
	if err != nil || !found || loadedRevision != committedRevision || !equalPublicationJournalStates(got, wantCommitted) {
		t.Fatalf("committed Load = %+v, %v, %v, %v", got, loadedRevision, found, err)
	}
	rewrittenRevision, err := journal.CompareAndSwap(ctx, "main", &committedRevision, wantCommitted)
	if err != nil {
		t.Fatal(err)
	}
	if rewrittenRevision.IsZero() || rewrittenRevision == committedRevision {
		t.Fatalf("same-state rewrite revision = %s, want a fresh random revision", rewrittenRevision)
	}
	if _, err := journal.CompareAndSwap(ctx, "main", &revision, wantCommitted); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("stale revision CAS error = %v, want ErrPrecondition", err)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(journalPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("journal permissions = %o, want private", info.Mode().Perm())
		}
	}
}

func TestFilePublicationJournalLoadRequiresDurableNamespace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	journal, err := NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "durability.journal"))
	if err != nil {
		t.Fatal(err)
	}
	want := PublicationJournalState{RepositoryID: RepositoryID{88}, Channel: "main"}
	errUnsynced := errors.New("test: directory sync interrupted")
	journal.syncDirectory = func(string) error { return errUnsynced }
	if _, err := journal.CompareAndSwap(ctx, "main", nil, want); !errors.Is(err, errUnsynced) {
		t.Fatalf("CompareAndSwap error = %v, want injected directory sync error", err)
	}

	// Rename has made the state visible. A new process must not be allowed to
	// act on it until it completes the missing parent-directory barrier.
	if _, _, found, err := journal.Load(ctx, "main"); !errors.Is(err, errUnsynced) || found {
		t.Fatalf("Load before durability barrier = found %v, error %v", found, err)
	}
	journal.syncDirectory = syncWatermarkDirectory
	got, revision, found, err := journal.Load(ctx, "main")
	if err != nil || !found || revision.IsZero() || !equalPublicationJournalStates(got, want) {
		t.Fatalf("Load after durability barrier = %+v, revision %v, found %v, error %v", got, revision, found, err)
	}
}

func TestFilePublicationJournalCASSerializesConcurrentIntents(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repositoryID := RepositoryID{2}
	path := filepath.Join(privateTestDirectory(t), "shared.journal")
	left, err := NewFilePublicationJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewFilePublicationJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	base := Watermark{RepositoryID: repositoryID, Generation: 1, Commit: Digest{1}}
	initial := PublicationJournalState{RepositoryID: repositoryID, Channel: "main", Committed: &base}
	if _, err := left.CompareAndSwap(ctx, "main", nil, initial); err != nil {
		t.Fatal(err)
	}

	_, leftRevision, found, err := left.Load(ctx, "main")
	if err != nil || !found {
		t.Fatalf("left Load = %s, %v, %v", leftRevision, found, err)
	}
	_, rightRevision, found, err := right.Load(ctx, "main")
	if err != nil || !found || rightRevision != leftRevision {
		t.Fatalf("right Load = %s, %v, %v; left revision %s", rightRevision, found, err, leftRevision)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	currentReference := testSignedPublicationReference(t, repositoryID, "main", base, 9)
	attempts := []struct {
		journal  *FilePublicationJournal
		revision PublicationJournalRevision
		state    PublicationJournalState
	}{
		{journal: left, revision: leftRevision},
		{journal: right, revision: rightRevision},
	}
	for index := range attempts {
		next := Watermark{RepositoryID: repositoryID, Generation: 2, Commit: Digest{byte(index + 2)}}
		version := Version{ETag: "base-etag"}
		intent := testPublicationIntent(t, repositoryID, "main", PublicationIntentPublish, &base, next, &version, currentReference, byte(index+2))
		attempts[index].state = PublicationJournalState{
			RepositoryID: repositoryID, Channel: "main", Committed: &base, Pending: &intent,
		}
	}
	for _, attempt := range attempts {
		attempt := attempt
		go func() {
			defer ready.Done()
			<-start
			_, err := attempt.journal.CompareAndSwap(ctx, "main", &attempt.revision, attempt.state)
			results <- err
		}()
	}
	close(start)
	firstErr, secondErr := <-results, <-results
	ready.Wait()
	if (firstErr == nil) == (secondErr == nil) {
		t.Fatalf("concurrent CAS errors = (%v, %v), want exactly one success", firstErr, secondErr)
	}
	loser := firstErr
	if loser == nil {
		loser = secondErr
	}
	if !errors.Is(loser, ErrPrecondition) {
		t.Fatalf("losing CAS error = %v, want ErrPrecondition", loser)
	}
}

func TestFilePublicationJournalRejectsRollbackAndForkButAcceptsValidatedAdvance(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repositoryID := RepositoryID{3}
	journal, err := NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "state.journal"))
	if err != nil {
		t.Fatal(err)
	}
	committed := Watermark{RepositoryID: repositoryID, Generation: 2, Commit: Digest{2}}
	state := PublicationJournalState{RepositoryID: repositoryID, Channel: "main", Committed: &committed}
	revision, err := journal.CompareAndSwap(ctx, "main", nil, state)
	if err != nil {
		t.Fatal(err)
	}

	rollback := Watermark{RepositoryID: repositoryID, Generation: 1, Commit: Digest{1}}
	if _, err := journal.CompareAndSwap(ctx, "main", &revision, PublicationJournalState{
		RepositoryID: repositoryID, Channel: "main", Committed: &rollback,
	}); !errors.Is(err, ErrRollbackDetected) {
		t.Fatalf("rollback error = %v, want ErrRollbackDetected", err)
	}
	fork := Watermark{RepositoryID: repositoryID, Generation: 2, Commit: Digest{99}}
	if _, err := journal.CompareAndSwap(ctx, "main", &revision, PublicationJournalState{
		RepositoryID: repositoryID, Channel: "main", Committed: &fork,
	}); !errors.Is(err, ErrSplitBrain) {
		t.Fatalf("same-generation fork error = %v, want ErrSplitBrain", err)
	}
	directAdvance := Watermark{RepositoryID: repositoryID, Generation: 3, Commit: Digest{3}}
	advanced := PublicationJournalState{
		RepositoryID: repositoryID, Channel: "main", Committed: &directAdvance,
	}
	advancedRevision, err := journal.CompareAndSwap(ctx, "main", &revision, advanced)
	if err != nil {
		t.Fatalf("adopt caller-validated remote advance: %v", err)
	}
	got, gotRevision, found, err := journal.Load(ctx, "main")
	if err != nil || !found || gotRevision != advancedRevision || !equalPublicationJournalStates(got, advanced) {
		t.Fatalf("advanced Load = %+v, %s, %v, %v", got, gotRevision, found, err)
	}
}

func TestPublicationJournalPendingMayResolveToValidatedRemoteWinner(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		winner Watermark
	}{
		{
			name:   "same-generation-competing-winner",
			winner: Watermark{RepositoryID: RepositoryID{10}, Generation: 3, Commit: Digest{77}},
		},
		{
			name:   "higher-descendant-winner",
			winner: Watermark{RepositoryID: RepositoryID{10}, Generation: 5, Commit: Digest{88}},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			repositoryID := RepositoryID{10}
			journal, err := NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "winner.journal"))
			if err != nil {
				t.Fatal(err)
			}
			base := Watermark{RepositoryID: repositoryID, Generation: 2, Commit: Digest{2}}
			initial := PublicationJournalState{RepositoryID: repositoryID, Channel: "main", Committed: &base}
			revision, err := journal.CompareAndSwap(ctx, "main", nil, initial)
			if err != nil {
				t.Fatal(err)
			}
			target := Watermark{RepositoryID: repositoryID, Generation: 3, Commit: Digest{3}}
			version := Version{ETag: "generation-2"}
			currentReference := testSignedPublicationReference(t, repositoryID, "main", base, 2)
			intent := testPublicationIntent(t, repositoryID, "main", PublicationIntentPublish, &base, target, &version, currentReference, 3)
			pending := PublicationJournalState{
				RepositoryID: repositoryID, Channel: "main", Committed: &base, Pending: &intent,
			}
			pendingRevision, err := journal.CompareAndSwap(ctx, "main", &revision, pending)
			if err != nil {
				t.Fatal(err)
			}
			resolved := PublicationJournalState{
				RepositoryID: repositoryID, Channel: "main", Committed: &test.winner,
			}
			resolvedRevision, err := journal.CompareAndSwap(ctx, "main", &pendingRevision, resolved)
			if err != nil {
				t.Fatalf("resolve to caller-validated remote winner: %v", err)
			}
			got, gotRevision, found, err := journal.Load(ctx, "main")
			if err != nil || !found || gotRevision != resolvedRevision || !equalPublicationJournalStates(got, resolved) {
				t.Fatalf("resolved Load = %+v, %s, %v, %v", got, gotRevision, found, err)
			}
		})
	}
}

func TestPublicationJournalMayRefreshPendingStoreObservation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repositoryID := RepositoryID{11}
	journal, err := NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "refresh-observation.journal"))
	if err != nil {
		t.Fatal(err)
	}
	base := Watermark{RepositoryID: repositoryID, Generation: 4, Commit: Digest{4}}
	initial := PublicationJournalState{RepositoryID: repositoryID, Channel: "main", Committed: &base}
	revision, err := journal.CompareAndSwap(ctx, "main", nil, initial)
	if err != nil {
		t.Fatal(err)
	}
	target := Watermark{RepositoryID: repositoryID, Generation: 5, Commit: Digest{5}}
	firstVersion := Version{ETag: "old-envelope"}
	firstObservedReference := testSignedPublicationReference(t, repositoryID, "main", base, 1)
	intent := testPublicationIntent(t, repositoryID, "main", PublicationIntentPublish, &base, target, &firstVersion, firstObservedReference, 5)
	pending := PublicationJournalState{
		RepositoryID: repositoryID, Channel: "main", Committed: &base, Pending: &intent,
	}
	pendingRevision, err := journal.CompareAndSwap(ctx, "main", &revision, pending)
	if err != nil {
		t.Fatal(err)
	}

	refreshed := clonePublicationJournalState(pending)
	refreshed.Pending.ExpectedVersion = &Version{ETag: "re-signed-envelope", VersionID: "new-version"}
	secondObservedReference := testSignedPublicationReference(t, repositoryID, "main", base, 2)
	refreshed.Pending.ExpectedReference = publicationReferenceDigest(secondObservedReference)
	if refreshed.Pending.IntentID != intent.IntentID {
		t.Fatal("refreshing a store observation changed the semantic intent ID")
	}
	refreshedRevision, err := journal.CompareAndSwap(ctx, "main", &pendingRevision, refreshed)
	if err != nil {
		t.Fatalf("refresh pending store observation: %v", err)
	}
	got, gotRevision, found, err := journal.Load(ctx, "main")
	if err != nil || !found || gotRevision != refreshedRevision || !equalPublicationJournalStates(got, refreshed) {
		t.Fatalf("refreshed Load = %+v, %s, %v, %v", got, gotRevision, found, err)
	}

	changedTarget := clonePublicationJournalState(refreshed)
	changedTarget.Pending.Reference = testSignedPublicationReference(t, repositoryID, "main", target, 6)
	changedTarget.Pending.IntentID, err = publicationIntentID(
		repositoryID, "main", changedTarget.Pending.Kind, changedTarget.Pending.Base,
		changedTarget.Pending.Next, changedTarget.Pending.Reference,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.CompareAndSwap(ctx, "main", &refreshedRevision, changedTarget); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("changing pending target error = %v, want ErrPrecondition", err)
	}
}

func TestFilePublicationJournalResignCanResolveWithoutChangingWatermark(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repositoryID := RepositoryID{4}
	journal, err := NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "resign.journal"))
	if err != nil {
		t.Fatal(err)
	}
	committed := Watermark{RepositoryID: repositoryID, Generation: 7, Commit: Digest{7}}
	initial := PublicationJournalState{RepositoryID: repositoryID, Channel: "main", Committed: &committed}
	revision, err := journal.CompareAndSwap(ctx, "main", nil, initial)
	if err != nil {
		t.Fatal(err)
	}
	version := Version{ETag: "old-envelope"}
	oldReference := testSignedPublicationReference(t, repositoryID, "main", committed, 1)
	intent := testPublicationIntent(t, repositoryID, "main", PublicationIntentResign, &committed, committed, &version, oldReference, 2)
	pending := PublicationJournalState{
		RepositoryID: repositoryID, Channel: "main", Committed: &committed, Pending: &intent,
	}
	pendingRevision, err := journal.CompareAndSwap(ctx, "main", &revision, pending)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.CompareAndSwap(ctx, "main", &pendingRevision, initial); err != nil {
		t.Fatalf("resolve resign intent: %v", err)
	}
}

func TestFilePublicationJournalRejectsCorruptAndOversizedFiles(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name         string
		data         []byte
		wantResource bool
	}{
		{name: "malformed", data: []byte("not-json")},
		{name: "non-canonical", data: append([]byte(`{"format":1}`), '\n')},
		{name: "oversized", data: make([]byte, maxPublicationJournalBytes+1), wantResource: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(privateTestDirectory(t), "corrupt.journal")
			journal, err := NewFilePublicationJournal(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, test.data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, _, err = journal.Load(context.Background(), "main")
			if !errors.Is(err, ErrCorruptObject) {
				t.Fatalf("Load error = %v, want ErrCorruptObject", err)
			}
			if test.wantResource && !errors.Is(err, ErrResourceLimit) {
				t.Fatalf("Load error = %v, want ErrResourceLimit", err)
			}
		})
	}
}

func TestFilePublicationJournalChecksumRejectsCanonicalFieldTampering(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repositoryID := RepositoryID{9}
	path := filepath.Join(privateTestDirectory(t), "checksum.journal")
	journal, err := NewFilePublicationJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	committed := Watermark{RepositoryID: repositoryID, Generation: 1, Commit: Digest{1}}
	if _, err := journal.CompareAndSwap(ctx, "main", nil, PublicationJournalState{
		RepositoryID: repositoryID, Channel: "main", Committed: &committed,
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var disk publicationJournalFile
	if err := decodeJSON(data, &disk); err != nil {
		t.Fatal(err)
	}
	disk.Revision[0] ^= 1
	tampered, err := canonicalJSON(disk)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := journal.Load(ctx, "main"); !errors.Is(err, ErrCorruptObject) || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("Load tampered canonical journal error = %v, want ErrCorruptObject", err)
	}
}

func TestFilePublicationJournalDoesNotAliasCallerMemory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repositoryID := RepositoryID{5}
	journal, err := NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "alias.journal"))
	if err != nil {
		t.Fatal(err)
	}
	base := Watermark{RepositoryID: repositoryID, Generation: 1, Commit: Digest{1}}
	initial := PublicationJournalState{RepositoryID: repositoryID, Channel: "main", Committed: &base}
	revision, err := journal.CompareAndSwap(ctx, "main", nil, initial)
	if err != nil {
		t.Fatal(err)
	}
	next := Watermark{RepositoryID: repositoryID, Generation: 2, Commit: Digest{2}}
	version := Version{ETag: "etag-one", VersionID: "version-one"}
	oldReference := testSignedPublicationReference(t, repositoryID, "main", base, 1)
	intent := testPublicationIntent(t, repositoryID, "main", PublicationIntentPublish, &base, next, &version, oldReference, 2)
	wantReference := append([]byte(nil), intent.Reference...)
	wantIntentID := intent.IntentID
	state := PublicationJournalState{
		RepositoryID: repositoryID, Channel: "main", Committed: &base, Pending: &intent,
	}
	if _, err := journal.CompareAndSwap(ctx, "main", &revision, state); err != nil {
		t.Fatal(err)
	}

	state.Committed.Generation = 99
	state.Pending.Base.Generation = 99
	state.Pending.ExpectedVersion.ETag = "mutated"
	state.Pending.Reference[0] ^= 0xff
	loaded, _, found, err := journal.Load(ctx, "main")
	if err != nil || !found {
		t.Fatalf("Load = %+v, %v, %v", loaded, found, err)
	}
	if loaded.Committed.Generation != 1 || loaded.Pending.Base.Generation != 1 ||
		loaded.Pending.ExpectedVersion.ETag != "etag-one" || loaded.Pending.IntentID != wantIntentID ||
		!bytesEqual(loaded.Pending.Reference, wantReference) {
		t.Fatalf("stored state aliased caller memory: %+v", loaded)
	}

	loaded.Committed.Generation = 88
	loaded.Pending.Base.Generation = 88
	loaded.Pending.ExpectedVersion.VersionID = "changed"
	loaded.Pending.Reference[0] ^= 0xff
	reloaded, _, _, err := journal.Load(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Committed.Generation != 1 || reloaded.Pending.Base.Generation != 1 ||
		reloaded.Pending.ExpectedVersion.VersionID != "version-one" ||
		!bytesEqual(reloaded.Pending.Reference, wantReference) {
		t.Fatalf("Load output aliased durable state: %+v", reloaded)
	}
}

func TestPublicationJournalLostResponseCanBeRecognizedByReload(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repositoryID := RepositoryID{6}
	fileJournal, err := NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "lost-response.journal"))
	if err != nil {
		t.Fatal(err)
	}
	journal := &lostPublicationJournalResponse{store: fileJournal, loseNext: true}
	next := Watermark{RepositoryID: repositoryID, Generation: 1, Commit: Digest{1}}
	intent := testPublicationIntent(t, repositoryID, "main", PublicationIntentPublish, nil, next, nil, nil, 1)
	want := PublicationJournalState{RepositoryID: repositoryID, Channel: "main", Pending: &intent}
	if _, err := journal.CompareAndSwap(ctx, "main", nil, want); !errors.Is(err, errLostPublicationJournalResponse) {
		t.Fatalf("CompareAndSwap error = %v, want lost response", err)
	}
	got, revision, found, err := journal.Load(ctx, "main")
	if err != nil || !found || revision.IsZero() {
		t.Fatalf("reload after lost response = %+v, %s, %v, %v", got, revision, found, err)
	}
	if got.Pending == nil || got.Pending.IntentID != intent.IntentID || !equalPublicationJournalStates(got, want) {
		t.Fatalf("reload cannot recognize applied intent: got %+v want %+v", got, want)
	}
}

func TestPublicationIntentIDExcludesStoreObservation(t *testing.T) {
	t.Parallel()

	repositoryID := RepositoryID{7}
	base := Watermark{RepositoryID: repositoryID, Generation: 1, Commit: Digest{1}}
	next := Watermark{RepositoryID: repositoryID, Generation: 2, Commit: Digest{2}}
	reference := testSignedPublicationReference(t, repositoryID, "main", next, 2)
	first, err := publicationIntentID(repositoryID, "main", PublicationIntentPublish, &base, next, reference)
	if err != nil {
		t.Fatal(err)
	}
	second, err := publicationIntentID(repositoryID, "main", PublicationIntentPublish, &base, next, append([]byte(nil), reference...))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("same semantic intent IDs differ: %s != %s", first, second)
	}
	changed := append([]byte(nil), reference...)
	changed[len(changed)-1] ^= 1
	third, err := publicationIntentID(repositoryID, "main", PublicationIntentPublish, &base, next, changed)
	if err != nil {
		t.Fatal(err)
	}
	if third == first {
		t.Fatal("changing target reference did not change intent ID")
	}
}

func TestPublicationReferenceDigestUsesZeroForAbsentReference(t *testing.T) {
	t.Parallel()

	if got := publicationReferenceDigest(nil); !got.IsZero() {
		t.Fatalf("nil reference digest = %s, want zero", got)
	}
	if got := publicationReferenceDigest([]byte{}); !got.IsZero() {
		t.Fatalf("empty reference digest = %s, want zero", got)
	}
	first := publicationReferenceDigest([]byte("first"))
	second := publicationReferenceDigest([]byte("second"))
	if first.IsZero() || second.IsZero() || first == second {
		t.Fatalf("domain-separated reference digests = (%s, %s)", first, second)
	}
}

func TestFilePublicationJournalRejectsInvalidIntentID(t *testing.T) {
	t.Parallel()

	repositoryID := RepositoryID{8}
	next := Watermark{RepositoryID: repositoryID, Generation: 1, Commit: Digest{1}}
	intent := testPublicationIntent(t, repositoryID, "main", PublicationIntentPublish, nil, next, nil, nil, 1)
	intent.IntentID = Digest{99}
	journal, err := NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "bad-intent.journal"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.CompareAndSwap(context.Background(), "main", nil, PublicationJournalState{
		RepositoryID: repositoryID, Channel: "main", Pending: &intent,
	}); !errors.Is(err, ErrCorruptObject) {
		t.Fatalf("invalid intent ID error = %v, want ErrCorruptObject", err)
	}
}

func TestPublicationJournalRejectsVersionIDOnlyExpectedVersion(t *testing.T) {
	t.Parallel()
	repositoryID := RepositoryID{41}
	base := Watermark{RepositoryID: repositoryID, Generation: 1, Commit: Digest{42}}
	next := Watermark{RepositoryID: repositoryID, Generation: 2, Commit: Digest{43}}
	intent := testPublicationIntent(
		t, repositoryID, "main", PublicationIntentPublish, &base, next,
		&Version{VersionID: "diagnostic-only"}, []byte("observed-reference"), 44,
	)
	err := validatePublicationJournalState(PublicationJournalState{
		RepositoryID: repositoryID, Channel: "main", Committed: &base, Pending: &intent,
	})
	if !errors.Is(err, ErrCorruptObject) {
		t.Fatalf("VersionID-only intent error = %v, want ErrCorruptObject", err)
	}
}

var errLostPublicationJournalResponse = errors.New("test: publication journal response lost")

type lostPublicationJournalResponse struct {
	store    PublicationJournalStore
	loseNext bool
}

func (journal *lostPublicationJournalResponse) Load(ctx context.Context, channel string) (PublicationJournalState, PublicationJournalRevision, bool, error) {
	return journal.store.Load(ctx, channel)
}

func (journal *lostPublicationJournalResponse) CompareAndSwap(ctx context.Context, channel string, expected *PublicationJournalRevision, next PublicationJournalState) (PublicationJournalRevision, error) {
	revision, err := journal.store.CompareAndSwap(ctx, channel, expected, next)
	if err == nil && journal.loseNext {
		journal.loseNext = false
		return PublicationJournalRevision{}, errLostPublicationJournalResponse
	}
	return revision, err
}

func testPublicationIntent(
	t *testing.T,
	repositoryID RepositoryID,
	channel string,
	kind PublicationIntentKind,
	base *Watermark,
	next Watermark,
	expectedVersion *Version,
	expectedReference []byte,
	signatureByte byte,
) PublicationIntent {
	t.Helper()
	reference := testSignedPublicationReference(t, repositoryID, channel, next, signatureByte)
	intent := PublicationIntent{
		Kind: kind, Base: clonePublicationWatermark(base), Next: next,
		ExpectedReference: publicationReferenceDigest(expectedReference), Reference: reference,
	}
	if base == nil {
		intent.ExpectedReference = Digest{}
	}
	if expectedVersion != nil {
		version := *expectedVersion
		intent.ExpectedVersion = &version
	}
	intentID, err := publicationIntentID(repositoryID, channel, kind, intent.Base, next, reference)
	if err != nil {
		t.Fatal(err)
	}
	intent.IntentID = intentID
	return intent
}

func testSignedPublicationReference(t *testing.T, repositoryID RepositoryID, channel string, watermark Watermark, signatureByte byte) []byte {
	t.Helper()
	data, err := canonicalJSON(signedReferenceEnvelope{
		Format: objectFormatVersion,
		Reference: signedReferencePayload{
			Format: objectFormatVersion, RepositoryID: repositoryID, Channel: channel,
			Generation: watermark.Generation, Commit: watermark.Commit, KeyID: fmt.Sprintf("key-%d", signatureByte),
		},
		Signature: []byte{signatureByte},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func equalPublicationJournalStates(left, right PublicationJournalState) bool {
	return left.RepositoryID == right.RepositoryID && left.Channel == right.Channel &&
		equalWatermarkPointers(left.Committed, right.Committed) && equalPublicationIntents(left.Pending, right.Pending)
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
