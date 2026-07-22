package s3disk_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

// cooperativeFinalizeJournal models a shared/remote publication journal in which
// a second publisher observes this publisher's freshly installed pending intent
// and cooperatively drives it to completion before this publisher's own
// post-begin recovery runs. onPending fires exactly once, immediately after the
// begin CAS that first installs a pending intent commits to the base journal.
type cooperativeFinalizeJournal struct {
	base      s3disk.PublicationJournalStore
	onPending func()
	triggered bool
}

func (journal *cooperativeFinalizeJournal) Load(ctx context.Context, channel string) (s3disk.PublicationJournalState, s3disk.PublicationJournalRevision, bool, error) {
	return journal.base.Load(ctx, channel)
}

func (journal *cooperativeFinalizeJournal) CompareAndSwap(
	ctx context.Context,
	channel string,
	expected *s3disk.PublicationJournalRevision,
	next s3disk.PublicationJournalState,
) (s3disk.PublicationJournalRevision, error) {
	revision, err := journal.base.CompareAndSwap(ctx, channel, expected, next)
	if err == nil && next.Pending != nil && !journal.triggered {
		journal.triggered = true
		if journal.onPending != nil {
			journal.onPending()
		}
	}
	return revision, err
}

// TestSignedPublishSucceedsWhenCooperatingPublisherFinalizesPending covers the
// interleaving where a publisher's own begin CAS succeeds, but before its
// post-begin RecoverPublication runs a cooperating publisher sharing the durable
// journal finalizes this exact pending intent (advancing committed and clearing
// pending). RecoverPublication then reports Outcome=None because pending is
// gone. This publication IS live at the committed reference, so it must be
// reported as success -- exactly as the begin-CAS-failure branch already
// classifies the same resolved state via classifyResolvedPublication -- not as a
// spurious ErrPublishConflict.
func TestSignedPublishSucceedsWhenCooperatingPublisherFinalizesPending(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, signer, _, verifier, _ := signedTestKeys(t)
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "signed-cooperative-finalize")
	if err != nil {
		t.Fatal(err)
	}
	base, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "publisher.journal"))
	if err != nil {
		t.Fatal(err)
	}

	// The cooperating publisher shares the same store and durable journal. It
	// only reconciles an already journaled pending intent, so it never re-signs.
	cooperating, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ReferenceSigner:                          signer, ReferenceVerifier: verifier,
		PublicationJournal: base, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	journal := &cooperativeFinalizeJournal{base: base}
	journal.onPending = func() {
		// The instant this publisher's begin CAS installs its pending intent, the
		// cooperating publisher observes it on the shared journal, drives this
		// exact reference to the remote store, advances the committed anchor, and
		// clears pending.
		recovery, err := cooperating.RecoverPublication(ctx, "main")
		if err != nil {
			t.Errorf("cooperating finalize: %v", err)
			return
		}
		if recovery.Outcome != s3disk.PublicationRecoveryApplied {
			t.Errorf("cooperating finalize outcome = %v, want Applied", recovery.Outcome)
		}
	}

	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ReferenceSigner:                          signer, ReferenceVerifier: verifier,
		PublicationJournal: journal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("cooperative finalize"))

	snapshot, err := publisher.Publish(ctx, source, "main")
	if err != nil {
		t.Fatalf("publish after cooperating finalize = %v, want success", err)
	}
	if snapshot.Generation != 1 {
		t.Fatalf("published snapshot generation = %d, want 1", snapshot.Generation)
	}

	state, _, found, err := base.Load(ctx, "main")
	if err != nil || !found || state.Pending != nil || state.Committed == nil || state.Committed.Generation != 1 {
		t.Fatalf("journal after cooperating finalize = %+v, found=%v, err=%v", state, found, err)
	}
}
