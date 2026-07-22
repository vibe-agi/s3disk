package s3disk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"
)

const publicationRecoveryAttempts = 4

// PublicationRecoveryOutcome describes how a durable pending publication was
// resolved. Superseded means another authenticated branch won the remote CAS.
type PublicationRecoveryOutcome uint8

const (
	PublicationRecoveryNone PublicationRecoveryOutcome = iota
	PublicationRecoveryApplied
	PublicationRecoverySuperseded
)

// PublicationRecovery reports the result of reconciling a durable publication
// intent. Current is the journal's committed snapshot after reconciliation.
type PublicationRecovery struct {
	Outcome  PublicationRecoveryOutcome
	IntentID Digest
	Current  Snapshot
}

func clonePublicationJournalStatePointer(state *PublicationJournalState) *PublicationJournalState {
	if state == nil {
		return nil
	}
	cloned := clonePublicationJournalState(*state)
	return &cloned
}

func clonePublicationJournalRevision(revision *PublicationJournalRevision) *PublicationJournalRevision {
	if revision == nil {
		return nil
	}
	cloned := *revision
	return &cloned
}

func clonePublicationIntent(intent *PublicationIntent) *PublicationIntent {
	if intent == nil {
		return nil
	}
	cloned := *intent
	cloned.Base = clonePublicationWatermark(intent.Base)
	if intent.ExpectedVersion != nil {
		version := *intent.ExpectedVersion
		cloned.ExpectedVersion = &version
	}
	cloned.Reference = append([]byte(nil), intent.Reference...)
	return &cloned
}

func (publisher *Publisher) loadPublicationJournal(
	ctx context.Context,
	channel string,
) (PublicationJournalState, PublicationJournalRevision, bool, error) {
	state, revision, found, err := publisher.publicationJournal.Load(ctx, channel)
	if err != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, fmt.Errorf("load publication journal: %w", err)
	}
	if !found {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, nil
	}
	if revision.IsZero() {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, fmt.Errorf("%w: zero publication journal revision", ErrCorruptObject)
	}
	if err := publisher.validateLoadedPublicationJournal(ctx, channel, state); err != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, err
	}
	return clonePublicationJournalState(state), revision, true, nil
}

func (publisher *Publisher) compareAndSwapPublicationJournal(
	ctx context.Context,
	channel string,
	expected *PublicationJournalRevision,
	next PublicationJournalState,
) (PublicationJournalRevision, error) {
	revision, err := publisher.publicationJournal.CompareAndSwap(ctx, channel, expected, next)
	if err == nil && revision.IsZero() {
		return PublicationJournalRevision{}, fmt.Errorf("%w: publication journal returned a zero revision", ErrStoreIncompatible)
	}
	return revision, err
}

func (publisher *Publisher) validateLoadedPublicationJournal(
	ctx context.Context,
	channel string,
	state PublicationJournalState,
) error {
	if err := validatePublicationJournalState(state); err != nil {
		return fmt.Errorf("invalid publication journal: %w", err)
	}
	repositoryID := publisher.referenceVerifier.RepositoryID()
	if state.RepositoryID != repositoryID || state.Channel != channel {
		return fmt.Errorf("%w: publication journal identity mismatch", ErrUntrustedReference)
	}
	if publisher.trustedCheckpoint == nil {
		return nil
	}
	checkpoint := *publisher.trustedCheckpoint
	if state.Committed == nil {
		return fmt.Errorf("%w: publication journal is below trusted checkpoint", ErrRollbackDetected)
	}
	switch {
	case state.Committed.Generation < checkpoint.Generation:
		return ErrRollbackDetected
	case state.Committed.Generation == checkpoint.Generation && state.Committed.Commit != checkpoint.Commit:
		return ErrSplitBrain
	}
	return publisher.validatePublicationCheckpoint(ctx, channel, *state.Committed, checkpoint)
}

func (publisher *Publisher) loadOrInitializePublicationJournal(
	ctx context.Context,
	channel string,
) (PublicationJournalState, PublicationJournalRevision, error) {
	state, revision, found, err := publisher.loadPublicationJournal(ctx, channel)
	if err != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, err
	}
	if found {
		// An empty journal records no authenticated anchor and no exact pending
		// operation. A TOFU choice from an abandoned pre-publication attempt must
		// not silently authorize bootstrap after restart.
		if state.Committed == nil && state.Pending == nil &&
			publisher.trustedCheckpoint == nil && !publisher.allowTrustOnFirstUse {
			return PublicationJournalState{}, PublicationJournalRevision{}, ErrTrustStateRequired
		}
		return state, revision, nil
	}
	if publisher.trustedCheckpoint == nil && !publisher.allowTrustOnFirstUse {
		return PublicationJournalState{}, PublicationJournalRevision{}, ErrTrustStateRequired
	}
	state = PublicationJournalState{
		RepositoryID: publisher.referenceVerifier.RepositoryID(),
		Channel:      channel,
		Committed:    clonePublicationWatermark(publisher.trustedCheckpoint),
	}
	revision, casErr := publisher.compareAndSwapPublicationJournal(ctx, channel, nil, state)
	if casErr == nil {
		if publisher.trustedCheckpoint != nil {
			publisher.checkpointValidated[channel] = *publisher.trustedCheckpoint
		}
		return clonePublicationJournalState(state), revision, nil
	}
	if errors.Is(casErr, ErrStoreIncompatible) {
		return PublicationJournalState{}, PublicationJournalRevision{}, casErr
	}

	// A crash-safe local write or remote journal service may apply its CAS and
	// lose the response. Reload before deciding initialization failed.
	loaded, loadedRevision, loadedFound, loadErr := publisher.loadPublicationJournal(ctx, channel)
	if loadErr != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, fmt.Errorf("initialize publication journal: %w; reload: %w", casErr, loadErr)
	}
	if !loadedFound {
		return PublicationJournalState{}, PublicationJournalRevision{}, fmt.Errorf("initialize publication journal: %w", casErr)
	}
	return loaded, loadedRevision, nil
}

func (publisher *Publisher) preparePublicationJournal(
	ctx context.Context,
	channel string,
) (PublicationJournalState, PublicationJournalRevision, error) {
	state, revision, err := publisher.loadOrInitializePublicationJournal(ctx, channel)
	if err != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, err
	}
	if state.Pending == nil {
		return state, revision, nil
	}
	if _, err := publisher.recoverPublication(ctx, channel, state, revision); err != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, err
	}
	state, revision, found, err := publisher.loadPublicationJournal(ctx, channel)
	if err != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, err
	}
	if !found || state.Pending != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, fmt.Errorf("%w: publication recovery did not resolve its journal", ErrPublishIndeterminate)
	}
	return state, revision, nil
}

// RecoverPublication reconciles a durable pending signed-reference CAS. It
// never re-signs: recovery always retries the exact reference bytes recorded
// before the first remote CAS. Unresolved outcomes remain pending and fail
// closed so a restarted publisher cannot reuse the generation.
func (publisher *Publisher) RecoverPublication(ctx context.Context, channel string) (PublicationRecovery, error) {
	if publisher.referenceVerifier == nil || publisher.publicationJournal == nil {
		return PublicationRecovery{}, fmt.Errorf("%w: signed publication journal is not configured", ErrUntrustedReference)
	}
	if err := publisher.repository.validateChannel(channel); err != nil {
		return PublicationRecovery{}, err
	}
	state, revision, err := publisher.loadOrInitializePublicationJournal(ctx, channel)
	if err != nil {
		return PublicationRecovery{}, err
	}
	if state.Pending == nil {
		result := PublicationRecovery{Outcome: PublicationRecoveryNone}
		if state.Committed != nil {
			result.Current, err = publisher.snapshotForPublicationWatermark(ctx, *state.Committed)
		}
		return result, err
	}
	return publisher.recoverPublication(ctx, channel, state, revision)
}

func (publisher *Publisher) recoverPublication(
	ctx context.Context,
	channel string,
	state PublicationJournalState,
	revision PublicationJournalRevision,
) (PublicationRecovery, error) {
	initial := clonePublicationIntent(state.Pending)
	if initial == nil {
		return PublicationRecovery{Outcome: PublicationRecoveryNone}, nil
	}
	target, err := publisher.validatePendingPublication(ctx, channel, *initial)
	if err != nil {
		return PublicationRecovery{}, err
	}
	var lastErr error
	for attempt := 0; attempt < publicationRecoveryAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return PublicationRecovery{}, fmt.Errorf("%w: recover publication %s: %w", ErrPublishIndeterminate, initial.IntentID, err)
		}
		if state.Pending == nil {
			return publisher.classifyResolvedPublication(ctx, channel, initial, state.Committed)
		}
		if !equalPublicationIntentSemantics(initial, state.Pending) {
			return PublicationRecovery{}, fmt.Errorf("%w: another publication replaced pending intent %s", ErrPublishConflict, initial.IntentID)
		}

		reference, object, getErr := publisher.repository.getReferenceWithVerifier(ctx, channel, "", publisher.referenceVerifier)
		if errors.Is(getErr, ErrObjectNotFound) {
			if state.Pending.Base != nil {
				return PublicationRecovery{}, fmt.Errorf("%w: signed reference disappeared while intent %s was pending", ErrRollbackDetected, initial.IntentID)
			}
			_, lastErr = publisher.repository.compareAndSwap(
				ctx, publisher.repository.SignedReferenceKey(channel), nil, state.Pending.Reference,
			)
			if lastErr == nil {
				return publisher.finalizePublication(ctx, state, revision, state.Pending.Next, target, PublicationRecoveryApplied)
			}
			state, revision, err = publisher.reloadPublicationRecovery(ctx, channel, initial)
			if err != nil {
				return PublicationRecovery{}, err
			}
			continue
		}
		if getErr != nil {
			lastErr = fmt.Errorf("read signed reference: %w", getErr)
			break
		}

		remote := Watermark{
			RepositoryID: publisher.referenceVerifier.RepositoryID(),
			Generation:   reference.Generation,
			Commit:       reference.Commit,
		}
		remoteCommit, err := publisher.readPublicationCommit(ctx, remote)
		if err != nil {
			return PublicationRecovery{}, err
		}
		remoteSnapshot := snapshotFromPublicationCommit(remote, remoteCommit)
		if state.Committed != nil {
			switch {
			case remote.Generation < state.Committed.Generation:
				return PublicationRecovery{}, ErrRollbackDetected
			case remote.Generation == state.Committed.Generation && remote.Commit != state.Committed.Commit:
				return PublicationRecovery{}, ErrSplitBrain
			}
		}

		if state.Pending.Kind == PublicationIntentResign && remote == state.Pending.Next {
			switch {
			case bytes.Equal(object.Data, state.Pending.Reference):
				return publisher.finalizePublication(ctx, state, revision, remote, remoteSnapshot, PublicationRecoveryApplied)
			case publicationReferenceDigest(object.Data) != state.Pending.ExpectedReference:
				return publisher.finalizePublication(ctx, state, revision, remote, remoteSnapshot, PublicationRecoverySuperseded)
			}
			// The original envelope is still visible; retry the exact re-sign.
			state, revision, err = publisher.refreshPublicationObservation(ctx, channel, state, revision, object)
			if err != nil {
				return PublicationRecovery{}, err
			}
			_, lastErr = publisher.repository.compareAndSwap(
				ctx, publisher.repository.SignedReferenceKey(channel), &object.Version, state.Pending.Reference,
			)
			if lastErr == nil {
				return publisher.finalizePublication(ctx, state, revision, state.Pending.Next, target, PublicationRecoveryApplied)
			}
			state, revision, err = publisher.reloadPublicationRecovery(ctx, channel, initial)
			if err != nil {
				return PublicationRecovery{}, err
			}
			continue
		}

		if remote == state.Pending.Next {
			return publisher.finalizePublication(ctx, state, revision, remote, remoteSnapshot, PublicationRecoveryApplied)
		}
		if remote.Generation > state.Pending.Next.Generation {
			if state.Pending.Kind == PublicationIntentResign {
				// Authentication envelopes do not appear in the immutable commit
				// ancestry. A descendant proves that the snapshot lineage advanced,
				// never that this exact re-sign envelope was installed.
				descends, ancestryErr := publisher.publicationDescends(ctx, remote, &remoteCommit, state.Pending.Next)
				if ancestryErr != nil {
					return PublicationRecovery{}, ancestryErr
				}
				if !descends {
					return PublicationRecovery{}, ErrSplitBrain
				}
				return publisher.finalizePublication(ctx, state, revision, remote, remoteSnapshot, PublicationRecoverySuperseded)
			}
			includesTarget, ancestryErr := publisher.publicationDescends(ctx, remote, &remoteCommit, state.Pending.Next)
			if ancestryErr != nil {
				return PublicationRecovery{}, ancestryErr
			}
			if includesTarget {
				return publisher.finalizePublication(ctx, state, revision, remote, remoteSnapshot, PublicationRecoveryApplied)
			}
			validWinner, winnerErr := publisher.validSupersedingPublication(ctx, remote, &remoteCommit, state.Pending.Base)
			if winnerErr != nil {
				return PublicationRecovery{}, winnerErr
			}
			if validWinner {
				return publisher.finalizePublication(ctx, state, revision, remote, remoteSnapshot, PublicationRecoverySuperseded)
			}
			return PublicationRecovery{}, ErrSplitBrain
		}

		if state.Pending.Base != nil && remote == *state.Pending.Base {
			state, revision, err = publisher.refreshPublicationObservation(ctx, channel, state, revision, object)
			if err != nil {
				return PublicationRecovery{}, err
			}
			_, lastErr = publisher.repository.compareAndSwap(
				ctx, publisher.repository.SignedReferenceKey(channel), &object.Version, state.Pending.Reference,
			)
			if lastErr == nil {
				return publisher.finalizePublication(ctx, state, revision, state.Pending.Next, target, PublicationRecoveryApplied)
			}
			state, revision, err = publisher.reloadPublicationRecovery(ctx, channel, initial)
			if err != nil {
				return PublicationRecovery{}, err
			}
			continue
		}

		validWinner, winnerErr := publisher.validSupersedingPublication(ctx, remote, &remoteCommit, state.Pending.Base)
		if winnerErr != nil {
			return PublicationRecovery{}, winnerErr
		}
		if validWinner {
			return publisher.finalizePublication(ctx, state, revision, remote, remoteSnapshot, PublicationRecoverySuperseded)
		}
		return PublicationRecovery{}, ErrSplitBrain
	}
	if lastErr == nil {
		lastErr = errors.New("publication recovery retry limit reached")
	}
	return PublicationRecovery{}, fmt.Errorf("%w: pending intent %s remains durable: %w", ErrPublishIndeterminate, initial.IntentID, lastErr)
}

func (publisher *Publisher) validatePendingPublication(
	ctx context.Context,
	channel string,
	intent PublicationIntent,
) (Snapshot, error) {
	if err := validatePublicationJournalIntent(publisher.referenceVerifier.RepositoryID(), channel, intent); err != nil {
		return Snapshot{}, fmt.Errorf("invalid pending publication: %w", err)
	}
	reference, err := verifySignedSnapshotReference(ctx, intent.Reference, channel, publisher.referenceVerifier)
	if err != nil {
		return Snapshot{}, fmt.Errorf("authenticate pending publication: %w", err)
	}
	if reference.Generation != intent.Next.Generation || reference.Commit != intent.Next.Commit {
		return Snapshot{}, fmt.Errorf("%w: pending reference does not match its watermark", ErrCorruptObject)
	}
	commit, err := publisher.readPublicationCommit(ctx, intent.Next)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read pending commit: %w", err)
	}
	if intent.Kind == PublicationIntentPublish {
		if intent.Base == nil {
			if commit.Parent != nil {
				return Snapshot{}, fmt.Errorf("%w: first pending commit has a parent", ErrSplitBrain)
			}
		} else if commit.Parent == nil || *commit.Parent != intent.Base.Commit {
			return Snapshot{}, fmt.Errorf("%w: pending commit does not directly descend from its base", ErrSplitBrain)
		}
	}
	return Snapshot{
		Generation:  intent.Next.Generation,
		Commit:      intent.Next.Commit,
		Root:        commit.Root,
		PublishedAt: time.Unix(0, commit.PublishedAtUnix).UTC(),
	}, nil
}

func (publisher *Publisher) readPublicationCommit(ctx context.Context, watermark Watermark) (commitManifest, error) {
	var commit commitManifest
	if err := publisher.repository.getManifest(ctx, "commit", watermark.Commit, &commit); err != nil {
		return commitManifest{}, fmt.Errorf("read signed publication commit: %w", err)
	}
	if err := validateCommitManifest(&commit, watermark.Generation); err != nil {
		return commitManifest{}, err
	}
	return commit, nil
}

func (publisher *Publisher) snapshotForPublicationWatermark(ctx context.Context, watermark Watermark) (Snapshot, error) {
	commit, err := publisher.readPublicationCommit(ctx, watermark)
	if err != nil {
		return Snapshot{}, err
	}
	return snapshotFromPublicationCommit(watermark, commit), nil
}

func snapshotFromPublicationCommit(watermark Watermark, commit commitManifest) Snapshot {
	return Snapshot{
		Generation:  watermark.Generation,
		Commit:      watermark.Commit,
		Root:        commit.Root,
		PublishedAt: time.Unix(0, commit.PublishedAtUnix).UTC(),
	}
}

func (publisher *Publisher) publicationDescends(
	ctx context.Context,
	candidate Watermark,
	commit *commitManifest,
	anchor Watermark,
) (bool, error) {
	reference := snapshotReference{Format: objectFormatVersion, Generation: candidate.Generation, Commit: candidate.Commit}
	err := publisher.validatePublicationDescendant(ctx, reference, commit, anchor)
	if errors.Is(err, ErrSplitBrain) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (publisher *Publisher) validSupersedingPublication(
	ctx context.Context,
	candidate Watermark,
	commit *commitManifest,
	base *Watermark,
) (bool, error) {
	if base != nil {
		if candidate.Generation <= base.Generation {
			return false, nil
		}
		return publisher.publicationDescends(ctx, candidate, commit, *base)
	}
	if candidate.Generation == 1 {
		return commit.Parent == nil, nil
	}
	if candidate.Generation > uint64(maxCommitWalk) {
		return false, fmt.Errorf("%w: publication ancestry exceeds %d generations", ErrResourceLimit, maxCommitWalk)
	}
	parent := commit.Parent
	for generation := candidate.Generation - 1; generation > 0; generation-- {
		if parent == nil || parent.IsZero() {
			return false, nil
		}
		var ancestor commitManifest
		if err := publisher.repository.getManifest(ctx, "commit", *parent, &ancestor); err != nil {
			return false, fmt.Errorf("validate superseding history at generation %d: %w", generation, err)
		}
		if err := validateCommitManifest(&ancestor, generation); err != nil {
			return false, err
		}
		parent = ancestor.Parent
	}
	return parent == nil, nil
}

func (publisher *Publisher) refreshPublicationObservation(
	ctx context.Context,
	channel string,
	state PublicationJournalState,
	revision PublicationJournalRevision,
	object Object,
) (PublicationJournalState, PublicationJournalRevision, error) {
	if state.Pending == nil || state.Pending.Base == nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, fmt.Errorf("%w: no based pending publication", ErrPrecondition)
	}
	if object.Version.ETag == "" {
		return PublicationJournalState{}, PublicationJournalRevision{}, fmt.Errorf("%w: store returned an empty reference version", ErrStoreIncompatible)
	}
	desired := clonePublicationJournalState(state)
	version := object.Version
	desired.Pending.ExpectedVersion = &version
	desired.Pending.ExpectedReference = publicationReferenceDigest(object.Data)
	if equalPublicationIntents(state.Pending, desired.Pending) {
		return state, revision, nil
	}
	newRevision, casErr := publisher.compareAndSwapPublicationJournal(ctx, channel, &revision, desired)
	if casErr == nil {
		return desired, newRevision, nil
	}
	if errors.Is(casErr, ErrStoreIncompatible) {
		return PublicationJournalState{}, PublicationJournalRevision{}, casErr
	}
	loaded, loadedRevision, found, loadErr := publisher.loadPublicationJournal(ctx, channel)
	if loadErr != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, fmt.Errorf("refresh publication observation: %w; reload: %w", casErr, loadErr)
	}
	if !found {
		return PublicationJournalState{}, PublicationJournalRevision{}, fmt.Errorf("%w: publication journal disappeared", ErrRollbackDetected)
	}
	if loaded.Pending == nil || !equalPublicationIntentSemantics(state.Pending, loaded.Pending) {
		return loaded, loadedRevision, fmt.Errorf("%w: pending publication changed while refreshing its remote observation", ErrPublishConflict)
	}
	if equalPublicationIntents(loaded.Pending, desired.Pending) {
		return loaded, loadedRevision, nil
	}
	return loaded, loadedRevision, fmt.Errorf("%w: publication observation changed concurrently", ErrPublishConflict)
}

func (publisher *Publisher) reloadPublicationRecovery(
	ctx context.Context,
	channel string,
	initial *PublicationIntent,
) (PublicationJournalState, PublicationJournalRevision, error) {
	state, revision, found, err := publisher.loadPublicationJournal(ctx, channel)
	if err != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, err
	}
	if !found {
		return PublicationJournalState{}, PublicationJournalRevision{}, fmt.Errorf("%w: publication journal disappeared", ErrRollbackDetected)
	}
	if state.Pending != nil && !equalPublicationIntentSemantics(initial, state.Pending) {
		return PublicationJournalState{}, PublicationJournalRevision{}, fmt.Errorf("%w: pending publication changed concurrently", ErrPublishConflict)
	}
	return state, revision, nil
}

func (publisher *Publisher) finalizePublication(
	ctx context.Context,
	state PublicationJournalState,
	revision PublicationJournalRevision,
	committed Watermark,
	snapshot Snapshot,
	outcome PublicationRecoveryOutcome,
) (PublicationRecovery, error) {
	intentID := Digest{}
	if state.Pending != nil {
		intentID = state.Pending.IntentID
	}
	if snapshot.Generation != committed.Generation || snapshot.Commit != committed.Commit || snapshot.Root.IsZero() {
		return PublicationRecovery{}, fmt.Errorf("%w: publication result does not match committed watermark", ErrCorruptObject)
	}
	desired := clonePublicationJournalState(state)
	desired.Committed = clonePublicationWatermark(&committed)
	desired.Pending = nil
	_, casErr := publisher.compareAndSwapPublicationJournal(ctx, state.Channel, &revision, desired)
	if errors.Is(casErr, ErrStoreIncompatible) {
		return PublicationRecovery{}, casErr
	}
	if casErr != nil {
		loaded, _, found, loadErr := publisher.loadPublicationJournal(ctx, state.Channel)
		if loadErr != nil {
			return PublicationRecovery{}, fmt.Errorf("finalize publication: %w; reload: %w", casErr, loadErr)
		}
		if !found || loaded.Pending != nil || !equalWatermarkPointers(loaded.Committed, desired.Committed) {
			return PublicationRecovery{}, fmt.Errorf("%w: finalize pending publication: %w", ErrPublishIndeterminate, casErr)
		}
	}
	return PublicationRecovery{Outcome: outcome, IntentID: intentID, Current: snapshot}, nil
}

func (publisher *Publisher) classifyResolvedPublication(
	ctx context.Context,
	channel string,
	intent *PublicationIntent,
	committed *Watermark,
) (PublicationRecovery, error) {
	if committed == nil {
		return PublicationRecovery{}, fmt.Errorf("%w: resolved publication has no committed watermark", ErrRollbackDetected)
	}
	if intent.Kind == PublicationIntentResign {
		return publisher.classifyResolvedResign(ctx, channel, intent, *committed)
	}
	snapshot, err := publisher.snapshotForPublicationWatermark(ctx, *committed)
	if err != nil {
		return PublicationRecovery{}, err
	}
	outcome := PublicationRecoverySuperseded
	if *committed == intent.Next {
		outcome = PublicationRecoveryApplied
	} else if committed.Generation > intent.Next.Generation {
		commit, err := publisher.readPublicationCommit(ctx, *committed)
		if err != nil {
			return PublicationRecovery{}, err
		}
		applied, err := publisher.publicationDescends(ctx, *committed, &commit, intent.Next)
		if err != nil {
			return PublicationRecovery{}, err
		}
		if applied {
			outcome = PublicationRecoveryApplied
		}
	}
	return PublicationRecovery{Outcome: outcome, IntentID: intent.IntentID, Current: snapshot}, nil
}

func (publisher *Publisher) classifyResolvedResign(
	ctx context.Context,
	channel string,
	intent *PublicationIntent,
	committed Watermark,
) (PublicationRecovery, error) {
	reference, object, err := publisher.repository.getReferenceWithVerifier(ctx, channel, "", publisher.referenceVerifier)
	if err != nil {
		return PublicationRecovery{}, fmt.Errorf("%w: classify resolved re-sign: %w", ErrPublishIndeterminate, err)
	}
	remote := Watermark{
		RepositoryID: publisher.referenceVerifier.RepositoryID(),
		Generation:   reference.Generation,
		Commit:       reference.Commit,
	}
	remoteCommit, err := publisher.readPublicationCommit(ctx, remote)
	if err != nil {
		return PublicationRecovery{}, err
	}
	switch {
	case remote.Generation < committed.Generation:
		return PublicationRecovery{}, ErrRollbackDetected
	case remote.Generation == committed.Generation && remote.Commit != committed.Commit:
		return PublicationRecovery{}, ErrSplitBrain
	case remote.Generation > committed.Generation:
		if err := publisher.validatePublicationDescendant(ctx, reference, &remoteCommit, committed); err != nil {
			return PublicationRecovery{}, err
		}
	}
	if remote.Generation < intent.Next.Generation {
		return PublicationRecovery{}, ErrRollbackDetected
	}
	if remote.Generation == intent.Next.Generation && remote.Commit != intent.Next.Commit {
		return PublicationRecovery{}, ErrSplitBrain
	}
	outcome := PublicationRecoverySuperseded
	if remote == intent.Next && bytes.Equal(object.Data, intent.Reference) {
		outcome = PublicationRecoveryApplied
	} else if remote == intent.Next && publicationReferenceDigest(object.Data) == intent.ExpectedReference {
		// Pending may only be cleared after proving either the exact target or a
		// different authenticated winner. Seeing the original envelope means the
		// journal and remote proof are inconsistent, so fail closed.
		return PublicationRecovery{}, fmt.Errorf("%w: resolved re-sign still exposes its original envelope", ErrPublishIndeterminate)
	} else if remote.Generation > intent.Next.Generation {
		if err := publisher.validatePublicationDescendant(ctx, reference, &remoteCommit, intent.Next); err != nil {
			return PublicationRecovery{}, err
		}
	}
	return PublicationRecovery{
		Outcome: outcome, IntentID: intent.IntentID,
		Current: snapshotFromPublicationCommit(remote, remoteCommit),
	}, nil
}

func (publisher *Publisher) acceptObservedPublication(
	ctx context.Context,
	channel string,
	state PublicationJournalState,
	revision PublicationJournalRevision,
	reference snapshotReference,
	commit *commitManifest,
) (PublicationJournalState, PublicationJournalRevision, error) {
	if state.Pending != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, fmt.Errorf("%w: unresolved publication intent", ErrPublishIndeterminate)
	}
	candidate := Watermark{
		RepositoryID: publisher.referenceVerifier.RepositoryID(),
		Generation:   reference.Generation,
		Commit:       reference.Commit,
	}
	if state.Committed != nil {
		switch {
		case candidate.Generation < state.Committed.Generation:
			return PublicationJournalState{}, PublicationJournalRevision{}, ErrRollbackDetected
		case candidate.Generation == state.Committed.Generation && candidate.Commit != state.Committed.Commit:
			return PublicationJournalState{}, PublicationJournalRevision{}, ErrSplitBrain
		case candidate == *state.Committed:
			return state, revision, nil
		}
		if err := publisher.validatePublicationDescendant(ctx, reference, commit, *state.Committed); err != nil {
			return PublicationJournalState{}, PublicationJournalRevision{}, err
		}
	}
	desired := clonePublicationJournalState(state)
	desired.Committed = clonePublicationWatermark(&candidate)
	newRevision, casErr := publisher.compareAndSwapPublicationJournal(ctx, channel, &revision, desired)
	if casErr == nil {
		return desired, newRevision, nil
	}
	if errors.Is(casErr, ErrStoreIncompatible) {
		return PublicationJournalState{}, PublicationJournalRevision{}, casErr
	}
	loaded, loadedRevision, found, loadErr := publisher.loadPublicationJournal(ctx, channel)
	if loadErr != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, fmt.Errorf("adopt signed publication: %w; reload: %w", casErr, loadErr)
	}
	if found && loaded.Pending == nil && equalWatermarkPointers(loaded.Committed, desired.Committed) {
		return loaded, loadedRevision, nil
	}
	if errors.Is(casErr, ErrPrecondition) {
		return PublicationJournalState{}, PublicationJournalRevision{}, fmt.Errorf("%w: publication journal changed concurrently", ErrPublishConflict)
	}
	return PublicationJournalState{}, PublicationJournalRevision{}, casErr
}

func (publisher *Publisher) commitSignedPublication(ctx context.Context, staged *StagedSnapshot) (Snapshot, error) {
	if staged.publicationState == nil || staged.publicationRevision == nil || staged.publicationIntent == nil {
		return Snapshot{}, fmt.Errorf("%w: staged signed publication lacks durable journal state", ErrCorruptObject)
	}
	state := clonePublicationJournalState(*staged.publicationState)
	revision := *staged.publicationRevision
	intent := clonePublicationIntent(staged.publicationIntent)
	if state.Pending != nil || !equalWatermarkPointers(state.Committed, intent.Base) {
		return Snapshot{}, fmt.Errorf("%w: stale staged publication journal state", ErrPublishConflict)
	}
	begun := false
	for attempt := 0; attempt < 2; attempt++ {
		desired := clonePublicationJournalState(state)
		desired.Pending = clonePublicationIntent(intent)
		_, casErr := publisher.compareAndSwapPublicationJournal(ctx, staged.channel, &revision, desired)
		if casErr == nil {
			begun = true
			break
		}
		if errors.Is(casErr, ErrStoreIncompatible) {
			return Snapshot{}, casErr
		}
		loaded, loadedRevision, found, loadErr := publisher.loadPublicationJournal(ctx, staged.channel)
		if loadErr != nil {
			return Snapshot{}, fmt.Errorf("begin durable publication: %w; reload: %w", casErr, loadErr)
		}
		if !found {
			return Snapshot{}, fmt.Errorf("%w: publication journal disappeared", ErrRollbackDetected)
		}
		if loaded.Pending != nil {
			if !equalPublicationIntents(loaded.Pending, intent) {
				return Snapshot{}, fmt.Errorf("%w: another signed publication owns the durable pending slot", ErrPublishConflict)
			}
			begun = true // The begin CAS was applied but its response was lost.
			break
		}
		if equalWatermarkPointers(loaded.Committed, intent.Base) {
			// A re-sign or another idempotent journal update changed only the
			// revision after Stage. The semantic base is unchanged, so retry the
			// durable begin; recovery will refresh the remote CAS observation.
			state, revision = loaded, loadedRevision
			continue
		}
		resolved, resolveErr := publisher.classifyResolvedPublication(ctx, staged.channel, intent, loaded.Committed)
		if resolveErr == nil && resolved.Outcome == PublicationRecoveryApplied {
			return staged.snapshot, nil
		}
		if resolveErr != nil {
			return Snapshot{}, resolveErr
		}
		return Snapshot{}, ErrPublishConflict
	}
	if !begun {
		return Snapshot{}, fmt.Errorf("%w: publication journal kept changing before durable begin", ErrPublishConflict)
	}
	recovery, err := publisher.RecoverPublication(ctx, staged.channel)
	if err != nil {
		return Snapshot{}, err
	}
	if recovery.Outcome == PublicationRecoveryApplied && recovery.IntentID == intent.IntentID {
		return staged.snapshot, nil
	}
	if recovery.Outcome == PublicationRecoveryNone {
		// A cooperating publisher sharing the durable journal drove this exact
		// pending intent to the remote and cleared pending before recovery ran,
		// so RecoverPublication reported None (it has no intent to classify
		// against). Resolve the current committed reference against our intent
		// the same way the begin-CAS-conflict branch does, so an already-applied
		// publication is not misreported as a conflict. A genuinely competing
		// winner classifies as Superseded and still returns ErrPublishConflict.
		loaded, _, found, loadErr := publisher.loadPublicationJournal(ctx, staged.channel)
		if loadErr != nil {
			return Snapshot{}, loadErr
		}
		if found {
			resolved, resolveErr := publisher.classifyResolvedPublication(ctx, staged.channel, intent, loaded.Committed)
			if resolveErr != nil {
				return Snapshot{}, resolveErr
			}
			if resolved.Outcome == PublicationRecoveryApplied {
				return staged.snapshot, nil
			}
		}
	}
	return Snapshot{}, ErrPublishConflict
}
