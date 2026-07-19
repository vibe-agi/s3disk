package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/presignedshare"
)

func runResume(ctx context.Context, options ResumeOptions) error {
	return runResumeWithOperations(ctx, options, productionPublisherOperations())
}

func runResumeWithOperations(ctx context.Context, options ResumeOptions, operations publisherOperations) (resultErr error) {
	if ctx == nil {
		return fmt.Errorf("s3disk share resume: context is required")
	}
	if err := validatePublisherOperations(operations); err != nil {
		return fmt.Errorf("s3disk share resume: %w", err)
	}
	if err := validateResumeOptions(&options); err != nil {
		return err
	}
	shareID, err := presignedshare.ParseShareID(options.ShareID)
	if err != nil || shareID.String() != options.ShareID {
		return fmt.Errorf("s3disk share resume: invalid canonical share identity")
	}
	localPaths, err := preflightResumeLocalPaths(ctx, options, shareID.String())
	if err != nil {
		return fmt.Errorf("s3disk share resume: local preflight: %w", err)
	}
	lock, err := acquirePublisherSessionLock(ctx, localPaths.shareDirectory)
	if err != nil {
		return fmt.Errorf("s3disk share resume: acquire session lock: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Close()) }()

	// No credential provider, S3 constructor, authenticated source path, or
	// handoff is touched before the recovery key opens the sealed session and
	// its original absolute authorization deadline is checked.
	recoveryMaterial, err := readRecoveryKeyFileContext(ctx, localPaths.recoveryKey)
	if err != nil {
		return fmt.Errorf("s3disk share resume: read recovery key: %w", err)
	}
	sessionStore, err := newPublisherSessionSealedStore(localPaths.shareDirectory, shareID, recoveryMaterial)
	if err != nil {
		return fmt.Errorf("s3disk share resume: open sealed session store: %w", err)
	}
	loaded, found, err := loadPublisherSession(ctx, sessionStore, operations.now())
	if err != nil {
		return fmt.Errorf("s3disk share resume: authenticate session: %w", err)
	}
	if !found {
		return fmt.Errorf("s3disk share resume: %w", ErrPublisherSessionNotFound)
	}
	if loaded.state.ShareID != shareID.String() {
		return fmt.Errorf("s3disk share resume: %w: share identity mismatch", ErrInvalidPublisherSession)
	}
	identity, err := reconstructPublisherIdentity(loaded.state, operations.now())
	if err != nil {
		return fmt.Errorf("s3disk share resume: reconstruct identity: %w", err)
	}
	runContext, cancelRun := context.WithDeadline(ctx, loaded.state.AuthorizationExpiresAt)
	defer cancelRun()
	if err := requirePublisherAuthorization(runContext, loaded.state.AuthorizationExpiresAt, operations.now); err != nil {
		return fmt.Errorf("s3disk share resume: %w", err)
	}
	requireSource := !loaded.state.Once ||
		!publisherPhaseAtLeast(loaded.state.Phase, publisherSessionInitialPublicationReady)
	rootStore, err := newRootRecoverySealedStore(
		localPaths.shareDirectory, identity.repositoryID, identity.shareID, recoveryMaterial,
	)
	if err != nil {
		return fmt.Errorf("s3disk share resume: open root recovery store: %w", err)
	}
	if err := requirePublisherAuthorization(runContext, loaded.state.AuthorizationExpiresAt, operations.now); err != nil {
		return fmt.Errorf("s3disk share resume: %w", err)
	}

	handle, err := operations.openS3(runContext, publisherSessionS3Config(loaded.state))
	if err != nil {
		return fmt.Errorf("s3disk share resume: configure S3: %w", err)
	}
	if err := validatePublisherS3Handle(handle); err != nil {
		return fmt.Errorf("s3disk share resume: %w", err)
	}
	if err := requirePublisherAuthorization(runContext, loaded.state.AuthorizationExpiresAt, operations.now); err != nil {
		return fmt.Errorf("s3disk share resume: %w", err)
	}
	restoreRootPublisher := func(presigner presignedshare.ExactGETPresigner, withSigner bool) (*presignedshare.RootPublisher, error) {
		config := presignedshare.RootPublisherConfig{
			Store: handle.store, RecoveryJournal: rootStore, ClientEncryption: identity.profile,
			RootKey: loaded.state.RootKey, RootCapability: identity.rootCapability,
			RepositoryPrefix: loaded.state.RepositoryPrefix, ReferenceKey: loaded.state.ReferenceKey,
			ShareID: identity.shareID, Presigner: presigner, Verifier: identity.verifier,
		}
		if withSigner {
			config.Signer = identity.signer
		}
		return presignedshare.RestoreRootPublisher(runContext, config)
	}

	// Recover exact WAL bytes before resolving or publishing a newer repository
	// snapshot. This path deliberately has neither a signer nor a presigner, so
	// an already durable operation remains recoverable after A's S3 credentials
	// rotate to a set which cannot mint URLs through the original deadline.
	rootPublisher, err := restoreRootPublisher(nil, false)
	if err != nil {
		return fmt.Errorf("s3disk share resume: restore exact root authority: %w", err)
	}
	if _, err := rootPublisher.RecoverPending(runContext); err != nil {
		return fmt.Errorf("s3disk share resume: recover pending share root: %w", err)
	}
	// Settling authenticated WAL bytes must not depend on a removable source
	// volume or the handoff destination being online. Validate those local paths
	// only after exact root recovery, and before any new publication or handoff
	// operation begins.
	if err := preflightRecoveredSessionPaths(runContext, loaded.state, localPaths, requireSource); err != nil {
		return fmt.Errorf("s3disk share resume: authenticated local preflight: %w", err)
	}
	ensureRootBuildAuthority := func() error {
		if rootPublisher.CanBuildNewRoot() {
			return nil
		}
		if err := requirePublisherAuthorization(runContext, loaded.state.AuthorizationExpiresAt, operations.now); err != nil {
			return err
		}
		presigner, err := handle.newPresignSession(runContext, loaded.state.AuthorizationExpiresAt)
		if err != nil {
			return fmt.Errorf("recreate fixed-expiry presigner: %w", err)
		}
		if err := validatePublisherPresigner(presigner); err != nil {
			return err
		}
		if err := requirePublisherAuthorization(runContext, loaded.state.AuthorizationExpiresAt, operations.now); err != nil {
			return err
		}
		rootPublisher, err = restoreRootPublisher(presigner, true)
		if err != nil {
			return fmt.Errorf("restore root build authority: %w", err)
		}
		return nil
	}

	originalPhase := loaded.state.Phase
	var repository *s3disk.Repository
	configuration := s3disk.RepositoryConfig{
		RepositoryID: identity.repositoryID, ClientEncryption: identity.profile,
	}
	if originalPhase == publisherSessionPrepared {
		repository, _, err = s3disk.InitializeRepository(runContext, handle.store,
			loaded.state.RepositoryPrefix, configuration,
			s3disk.RepositoryInitializationOptions{ConfirmEmptyPrefix: true})
	} else {
		repository, _, err = s3disk.OpenRepository(runContext, handle.store,
			loaded.state.RepositoryPrefix, configuration)
	}
	if err != nil {
		return fmt.Errorf("s3disk share resume: reconcile repository descriptor: %w", err)
	}
	if loaded.state.Phase == publisherSessionPrepared {
		if err := publisherExternalEffectBoundary(runContext, loaded.state, operations, publisherEffectRepositoryReady); err != nil {
			return fmt.Errorf("s3disk share resume: after repository effect: %w", err)
		}
		loaded, err = advancePublisherSession(runContext, sessionStore, loaded,
			publisherSessionRepositoryReady, nil, s3disk.Digest{}, operations.now())
		if err != nil {
			return fmt.Errorf("s3disk share resume: persist repository phase: %w", err)
		}
		if err := publisherDurablePhaseBoundary(runContext, loaded.state, operations); err != nil {
			return fmt.Errorf("s3disk share resume: after repository phase: %w", err)
		}
	}

	journal, err := s3disk.NewFilePublicationJournal(filepath.Join(localPaths.shareDirectory, publicationJournalFileName))
	if err != nil {
		return fmt.Errorf("s3disk share resume: open publication journal: %w", err)
	}
	trustedCheckpoint, err := publisherTrustedCheckpoint(loaded.state, identity.repositoryID)
	if err != nil {
		return fmt.Errorf("s3disk share resume: restore publication checkpoint: %w", err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: identity.signer, ReferenceVerifier: identity.verifier,
		PublicationJournal: journal, TrustedCheckpoint: trustedCheckpoint,
		AllowTrustOnFirstUse: trustedCheckpoint == nil, Symlinks: s3disk.SymlinkRejectExternal,
		ProtectedSourceFiles: protectedPublisherSourceFiles(
			localPaths.recoveryKey, string(loaded.state.HandoffPath), localPaths.shareDirectory,
		),
	})
	if err != nil {
		return fmt.Errorf("s3disk share resume: restore publisher: %w", err)
	}
	publicationRecovery, err := publisher.RecoverPublication(runContext, loaded.state.Channel)
	if err != nil {
		return fmt.Errorf("s3disk share resume: recover publication: %w", err)
	}
	if loaded.state.Phase == publisherSessionRepositoryReady {
		if err := publisherExternalEffectBoundary(runContext, loaded.state, operations, publisherEffectJournalReady); err != nil {
			return fmt.Errorf("s3disk share resume: after journal effect: %w", err)
		}
		loaded, err = advancePublisherSession(runContext, sessionStore, loaded,
			publisherSessionJournalReady, nil, s3disk.Digest{}, operations.now())
		if err != nil {
			return fmt.Errorf("s3disk share resume: persist journal phase: %w", err)
		}
		if err := publisherDurablePhaseBoundary(runContext, loaded.state, operations); err != nil {
			return fmt.Errorf("s3disk share resume: after journal phase: %w", err)
		}
	}

	selectedPaths := publisherSelectedPathStrings(loaded.state.SelectedPaths)
	snapshot := publicationRecovery.Current
	if snapshot.Generation == 0 {
		if publisherPhaseAtLeast(loaded.state.Phase, publisherSessionInitialPublicationReady) {
			return fmt.Errorf("s3disk share resume: %w: durable publication is below the session checkpoint", s3disk.ErrRollbackDetected)
		}
		if err := requirePublisherAuthorization(runContext, loaded.state.AuthorizationExpiresAt, operations.now); err != nil {
			return fmt.Errorf("s3disk share resume: %w", err)
		}
		if loaded.state.SelectAll {
			snapshot, err = publisher.Publish(runContext, string(loaded.state.SourcePath), loaded.state.Channel)
		} else {
			snapshot, err = publisher.PublishSelected(runContext, string(loaded.state.SourcePath), loaded.state.Channel, selectedPaths)
		}
		if err != nil {
			return fmt.Errorf("s3disk share resume: publish initial snapshot: %w", err)
		}
	}
	if loaded.state.Phase == publisherSessionJournalReady {
		if err := publisherExternalEffectBoundary(runContext, loaded.state, operations, publisherEffectInitialPublicationReady); err != nil {
			return fmt.Errorf("s3disk share resume: after initial publication effect: %w", err)
		}
		checkpoint := handoffCheckpoint{Generation: snapshot.Generation, Commit: snapshot.Commit.String()}
		loaded, err = advancePublisherSession(runContext, sessionStore, loaded,
			publisherSessionInitialPublicationReady, &checkpoint, s3disk.Digest{}, operations.now())
		if err != nil {
			return fmt.Errorf("s3disk share resume: persist initial publication phase: %w", err)
		}
		if err := publisherDurablePhaseBoundary(runContext, loaded.state, operations); err != nil {
			return fmt.Errorf("s3disk share resume: after initial publication phase: %w", err)
		}
	}
	if loaded.state.TrustedCheckpoint == nil ||
		!publisherPhaseAtLeast(loaded.state.Phase, publisherSessionInitialPublicationReady) {
		return fmt.Errorf("s3disk share resume: %w: initial checkpoint is absent", ErrInvalidPublisherSession)
	}
	if snapshot.Generation < loaded.state.TrustedCheckpoint.Generation ||
		(snapshot.Generation == loaded.state.TrustedCheckpoint.Generation &&
			!snapshotMatchesCheckpoint(snapshot, *loaded.state.TrustedCheckpoint)) {
		return fmt.Errorf("s3disk share resume: %w: publication contradicts the initial checkpoint", s3disk.ErrRollbackDetected)
	}

	expectedHandoff, encodedHandoff, expectedDigest, err := buildPublisherHandoff(loaded.state)
	if err != nil {
		return fmt.Errorf("s3disk share resume: rebuild handoff: %w", err)
	}
	clear(encodedHandoff)
	if publisherPhaseAtLeast(loaded.state.Phase, publisherSessionInitialRootReady) &&
		loaded.state.HandoffDigest != expectedDigest.String() {
		return fmt.Errorf("s3disk share resume: %w: authenticated handoff digest changed", ErrInvalidPublisherSession)
	}
	if err := requirePublisherAuthorization(runContext, loaded.state.AuthorizationExpiresAt, operations.now); err != nil {
		return fmt.Errorf("s3disk share resume: %w", err)
	}
	reconcileShareRoot := func() error {
		var reconcileErr error
		if publisherPhaseAtLeast(loaded.state.Phase, publisherSessionInitialRootReady) {
			_, reconcileErr = rootPublisher.UpdatePublishedSnapshot(runContext, repository, loaded.state.Channel, snapshot)
		} else {
			_, reconcileErr = rootPublisher.CreatePublishedSnapshot(runContext, repository, loaded.state.Channel, snapshot)
			if errors.Is(reconcileErr, presignedshare.ErrRootPublishConflict) {
				_, reconcileErr = rootPublisher.UpdatePublishedSnapshot(runContext, repository, loaded.state.Channel, snapshot)
			}
		}
		return reconcileErr
	}
	// First try with recovery-only authority. Generation and commit are not a
	// sufficient shortcut: the root also binds the exact signed-reference bytes
	// and Store version, so rewriting identical reference bytes may legitimately
	// require a new root revision. Only the publisher's explicit missing-build-
	// authority error is allowed to trigger fresh presigning.
	err = reconcileShareRoot()
	if errors.Is(err, presignedshare.ErrRootBuildAuthorityRequired) && !rootPublisher.CanBuildNewRoot() {
		if err := ensureRootBuildAuthority(); err != nil {
			return fmt.Errorf("s3disk share resume: prepare share-root update: %w", err)
		}
		err = reconcileShareRoot()
	}
	if err != nil {
		return fmt.Errorf("s3disk share resume: reconcile share root: %w", err)
	}
	if loaded.state.Phase == publisherSessionInitialPublicationReady {
		if err := publisherExternalEffectBoundary(runContext, loaded.state, operations, publisherEffectInitialRootReady); err != nil {
			return fmt.Errorf("s3disk share resume: after initial root effect: %w", err)
		}
		loaded, err = advancePublisherSession(runContext, sessionStore, loaded,
			publisherSessionInitialRootReady, nil, expectedDigest, operations.now())
		if err != nil {
			return fmt.Errorf("s3disk share resume: persist initial root phase: %w", err)
		}
		if err := publisherDurablePhaseBoundary(runContext, loaded.state, operations); err != nil {
			return fmt.Errorf("s3disk share resume: after initial root phase: %w", err)
		}
	}

	if err := requirePublisherAuthorization(runContext, loaded.state.AuthorizationExpiresAt, operations.now); err != nil {
		return fmt.Errorf("s3disk share resume: %w", err)
	}
	if err := installOrVerifyHandoff(runContext, string(loaded.state.HandoffPath), expectedHandoff, expectedDigest); err != nil {
		return fmt.Errorf("s3disk share resume: reconcile handoff: %w", err)
	}
	if loaded.state.Phase == publisherSessionInitialRootReady {
		if err := publisherExternalEffectBoundary(runContext, loaded.state, operations, publisherEffectHandoffReady); err != nil {
			return fmt.Errorf("s3disk share resume: after handoff effect: %w", err)
		}
		loaded, err = advancePublisherSession(runContext, sessionStore, loaded,
			publisherSessionHandoffReady, nil, s3disk.Digest{}, operations.now())
		if err != nil {
			return fmt.Errorf("s3disk share resume: persist handoff phase: %w", err)
		}
		if err := publisherDurablePhaseBoundary(runContext, loaded.state, operations); err != nil {
			return fmt.Errorf("s3disk share resume: after handoff phase: %w", err)
		}
	}

	if loaded.state.Once {
		if loaded.state.Phase == publisherSessionHandoffReady {
			loaded, err = advancePublisherSession(runContext, sessionStore, loaded,
				publisherSessionCompleted, nil, s3disk.Digest{}, operations.now())
			if err != nil {
				return fmt.Errorf("s3disk share resume: persist completion: %w", err)
			}
			if err := publisherDurablePhaseBoundary(runContext, loaded.state, operations); err != nil {
				return fmt.Errorf("s3disk share resume: after completion: %w", err)
			}
		}
		writePublisherReadyStatus(options.StatusWriter, loaded.state)
		return nil
	}
	if loaded.state.Phase != publisherSessionHandoffReady {
		return fmt.Errorf("s3disk share resume: %w: continuous session has an invalid terminal phase", ErrInvalidPublisherSession)
	}
	if err := ensureRootBuildAuthority(); err != nil {
		return fmt.Errorf("s3disk share resume: prepare continuous root publication: %w", err)
	}
	writePublisherReadyStatus(options.StatusWriter, loaded.state)
	if err := requirePublisherAuthorization(runContext, loaded.state.AuthorizationExpiresAt, operations.now); err != nil {
		return fmt.Errorf("s3disk share resume: %w", err)
	}
	if err := watchPublisherSource(runContext, publisher, rootPublisher, repository, loaded.state, selectedPaths, options.ErrorWriter); err != nil {
		return fmt.Errorf("s3disk share resume: %w", err)
	}
	return nil
}

func publisherSelectedPathStrings(encoded [][]byte) []string {
	paths := make([]string, len(encoded))
	for index := range encoded {
		paths[index] = string(encoded[index])
	}
	return paths
}
