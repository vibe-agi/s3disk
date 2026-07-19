package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/internal/presignedcap"
	"github.com/vibe-agi/s3disk/memstore"
	"github.com/vibe-agi/s3disk/presignedshare"
	"github.com/vibe-agi/s3disk/publisherstate"
)

func TestRunPublishPersistsPreparedRecoveryBeforeFirstStoreOperation(t *testing.T) {
	requirePrivateSecretFiles(t)
	requirePublisherSessionSealedState(t)

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	source := t.TempDir()
	stateDirectory := t.TempDir()
	if err := os.Chmod(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	handoffPath := filepath.Join(t.TempDir(), "share.handoff")
	recoveryKeyPath := filepath.Join(t.TempDir(), "publisher-recovery-key.json")
	recoveryMaterial := writeOrderingRecoveryKey(t, recoveryKeyPath)
	sentinel := errors.New("ordering store sentinel")

	presigner := &orderingExactPresigner{}
	store := &orderingSentinelStore{sentinel: sentinel}
	store.beforeFirst = func(operationContext context.Context, operation string) error {
		if operation != "Get" {
			return fmt.Errorf("first Store operation = %s, want Get", operation)
		}
		if presigner.shareID.IsZero() {
			return errors.New("root presigner did not capture a share identity")
		}
		shareDirectory := filepath.Join(stateDirectory, presigner.shareID.String())
		sessionStore, err := newPublisherSessionSealedStore(
			shareDirectory, presigner.shareID, recoveryMaterial,
		)
		if err != nil {
			return fmt.Errorf("open session store: %w", err)
		}
		loaded, found, err := loadPublisherSession(operationContext, sessionStore, now)
		if err != nil {
			return fmt.Errorf("load prepared session: %w", err)
		}
		if !found {
			return errors.New("prepared session was absent at first Store operation")
		}
		if loaded.state.Phase != publisherSessionPrepared || loaded.state.Sequence != 1 {
			return fmt.Errorf(
				"session phase at first Store operation = %q/%d, want prepared/1",
				loaded.state.Phase, loaded.state.Sequence,
			)
		}
		if loaded.state.ShareID != presigner.shareID.String() {
			return errors.New("prepared session has a different share identity")
		}

		repositoryID, err := s3disk.ParseRepositoryID(loaded.state.RepositoryID)
		if err != nil {
			return fmt.Errorf("parse prepared repository identity: %w", err)
		}
		rootStore, err := newRootRecoverySealedStore(
			shareDirectory, repositoryID, presigner.shareID, recoveryMaterial,
		)
		if err != nil {
			return fmt.Errorf("open root recovery store: %w", err)
		}
		rootState, _, rootFound, err := rootStore.Load(operationContext)
		clear(rootState)
		if err != nil {
			return fmt.Errorf("load root recovery state: %w", err)
		}
		if !rootFound {
			return errors.New("root recovery state was absent at first Store operation")
		}

		identity, err := reconstructPublisherIdentity(loaded.state, now)
		if err != nil {
			return fmt.Errorf("reconstruct prepared identity: %w", err)
		}
		restored, err := presignedshare.RestoreRootPublisher(operationContext, presignedshare.RootPublisherConfig{
			Store: store, RecoveryJournal: rootStore, ClientEncryption: identity.profile,
			RootKey: loaded.state.RootKey, RootCapability: identity.rootCapability,
			RepositoryPrefix: loaded.state.RepositoryPrefix, ReferenceKey: loaded.state.ReferenceKey,
			ShareID: identity.shareID, Presigner: presigner, Signer: identity.signer,
			Verifier: identity.verifier,
		})
		if err != nil {
			return fmt.Errorf("restore prepared root authority: %w", err)
		}
		if !restored.RecoveryEnabled() || !restored.CanBuildNewRoot() {
			return errors.New("restored root publisher lacks recovery or publication authority")
		}
		return nil
	}

	operations := publisherOperations{
		now: func() time.Time { return now },
		openS3: func(context.Context, publisherS3Config) (publisherS3Handle, error) {
			return publisherS3Handle{
				store: store,
				newPresignSession: func(_ context.Context, expiresAt time.Time) (presignedshare.ExactGETPresigner, error) {
					presigner.expiresAt = expiresAt
					return presigner, nil
				},
			}, nil
		},
		afterExternalEffect: func(context.Context, publisherExternalEffect) error { return nil },
		afterDurablePhase:   func(context.Context, publisherSessionPhase) error { return nil },
	}
	options := PublishOptions{
		Source: source, All: true, Bucket: "ordering-bucket", Prefix: "ordering/prefix",
		Region: "us-east-1", Endpoint: "http://127.0.0.1:9000", UsePathStyle: true,
		AllowInsecureEndpoint: true, Channel: "main", ExpiresIn: time.Hour,
		HandoffOut: handoffPath, StateDir: stateDirectory, RecoveryKey: recoveryKeyPath, Once: true,
	}

	err := runPublishWithOperations(ctx, options, operations)
	if !errors.Is(err, sentinel) {
		t.Fatalf("runPublishWithOperations error = %v, want ordering sentinel", err)
	}
	if store.validationErr != nil {
		t.Fatalf("durable state at first Store operation: %v", store.validationErr)
	}
	if store.calls != 1 {
		t.Fatalf("Store calls = %d, want exactly the failing first operation", store.calls)
	}
}

func TestRunResumeRejectsAuthenticatedExpiredSessionBeforeOpeningS3(t *testing.T) {
	requirePrivateSecretFiles(t)
	requirePublisherSessionSealedState(t)

	ctx := context.Background()
	realNow := time.Now().UTC().Truncate(time.Second)
	state := newTestPublisherSession(t, realNow)
	shareID, err := presignedshare.ParseShareID(state.ShareID)
	if err != nil {
		t.Fatal(err)
	}
	stateDirectory := t.TempDir()
	if err := os.Chmod(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	shareDirectory := filepath.Join(stateDirectory, shareID.String())
	if err := os.Mkdir(shareDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	recoveryKeyPath := filepath.Join(t.TempDir(), "publisher-recovery-key.json")
	recoveryMaterial := writeOrderingRecoveryKey(t, recoveryKeyPath)
	state.RecoveryKeyID = recoveryMaterial.keyID
	sessionStore, err := newPublisherSessionSealedStore(shareDirectory, shareID, recoveryMaterial)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := createPublisherSession(ctx, sessionStore, state, realNow); err != nil {
		t.Fatal(err)
	}

	openS3Calls := 0
	expiredNow := state.AuthorizationExpiresAt.Add(time.Second)
	operations := publisherOperations{
		now: func() time.Time { return expiredNow },
		openS3: func(context.Context, publisherS3Config) (publisherS3Handle, error) {
			openS3Calls++
			return publisherS3Handle{}, errors.New("openS3 must not run for an expired session")
		},
		afterExternalEffect: func(context.Context, publisherExternalEffect) error { return nil },
		afterDurablePhase:   func(context.Context, publisherSessionPhase) error { return nil },
	}

	err = runResumeWithOperations(ctx, ResumeOptions{
		StateDir: stateDirectory, ShareID: shareID.String(), RecoveryKey: recoveryKeyPath,
	}, operations)
	if !errors.Is(err, ErrPublisherSessionExpired) {
		t.Fatalf("runResumeWithOperations error = %v, want ErrPublisherSessionExpired", err)
	}
	if openS3Calls != 0 {
		t.Fatalf("openS3 calls = %d, want zero for an expired authenticated session", openS3Calls)
	}
	loaded, found, loadErr := loadPublisherSession(ctx, sessionStore, realNow)
	if loadErr != nil || !found || loaded.state.Phase != publisherSessionPrepared {
		t.Fatalf(
			"expired resume changed prepared session: phase=%q found=%t err=%v",
			loaded.state.Phase, found, loadErr,
		)
	}
}

func TestRunPublishThenResumeCompletedOneShotWithoutSource(t *testing.T) {
	requirePrivateSecretFiles(t)
	requirePublisherSessionSealedState(t)

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "shared.txt"), []byte("one-shot round trip"), 0o600); err != nil {
		t.Fatal(err)
	}
	stateDirectory := t.TempDir()
	if err := os.Chmod(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	handoffPath := filepath.Join(t.TempDir(), "share.handoff")
	recoveryKeyPath := filepath.Join(t.TempDir(), "publisher-recovery-key.json")
	recoveryMaterial := writeOrderingRecoveryKey(t, recoveryKeyPath)
	store := memstore.New()
	presigner := &orderingExactPresigner{}
	openS3Calls := 0
	presignSessionCalls := 0
	operations := publisherOperations{
		now: func() time.Time { return now },
		openS3: func(context.Context, publisherS3Config) (publisherS3Handle, error) {
			openS3Calls++
			return publisherS3Handle{
				store: store,
				newPresignSession: func(_ context.Context, expiresAt time.Time) (presignedshare.ExactGETPresigner, error) {
					presignSessionCalls++
					presigner.expiresAt = expiresAt
					return presigner, nil
				},
			}, nil
		},
		afterExternalEffect: func(context.Context, publisherExternalEffect) error { return nil },
		afterDurablePhase:   func(context.Context, publisherSessionPhase) error { return nil },
	}
	publishOptions := PublishOptions{
		Source: source, All: true, Bucket: "roundtrip-bucket", Prefix: "roundtrip/prefix",
		Region: "us-east-1", Endpoint: "http://127.0.0.1:9000", UsePathStyle: true,
		AllowInsecureEndpoint: true, Channel: "main", ExpiresIn: time.Hour,
		HandoffOut: handoffPath, StateDir: stateDirectory, RecoveryKey: recoveryKeyPath, Once: true,
	}
	if err := runPublishWithOperations(ctx, publishOptions, operations); err != nil {
		t.Fatalf("runPublishWithOperations: %v", err)
	}
	if presigner.shareID.IsZero() {
		t.Fatal("successful publish did not expose its share identity through the root presign")
	}
	if openS3Calls != 1 {
		t.Fatalf("publish openS3 calls = %d, want 1", openS3Calls)
	}
	if presignSessionCalls != 1 {
		t.Fatalf("publish presign-session calls = %d, want 1", presignSessionCalls)
	}

	shareDirectory := filepath.Join(stateDirectory, presigner.shareID.String())
	sessionStore, err := newPublisherSessionSealedStore(
		shareDirectory, presigner.shareID, recoveryMaterial,
	)
	if err != nil {
		t.Fatal(err)
	}
	loaded, found, err := loadPublisherSession(ctx, sessionStore, now)
	if err != nil || !found {
		t.Fatalf("load completed publisher session: found=%t err=%v", found, err)
	}
	if loaded.state.Phase != publisherSessionCompleted || !loaded.state.Once {
		t.Fatalf("published session = phase %q once=%t, want completed one-shot", loaded.state.Phase, loaded.state.Once)
	}
	handoffBefore, err := os.ReadFile(handoffPath)
	if err != nil {
		t.Fatal(err)
	}
	rootBefore, err := store.Get(ctx, loaded.state.RootKey, s3disk.GetOptions{MaxBytes: 65 << 20})
	if err != nil {
		t.Fatalf("read root before resume: %v", err)
	}

	if err := os.RemoveAll(source); err != nil {
		t.Fatal(err)
	}
	beforeResume := store.Stats()
	if err := runResumeWithOperations(ctx, ResumeOptions{
		StateDir: stateDirectory, ShareID: presigner.shareID.String(), RecoveryKey: recoveryKeyPath,
	}, operations); err != nil {
		t.Fatalf("runResumeWithOperations completed one-shot without source: %v", err)
	}
	if openS3Calls != 2 {
		t.Fatalf("publish plus resume openS3 calls = %d, want 2", openS3Calls)
	}
	if presignSessionCalls != 1 {
		t.Fatalf("completed one-shot resume presign-session calls = %d, want no call beyond publish", presignSessionCalls)
	}
	afterResume := store.Stats()
	if afterResume.Gets <= beforeResume.Gets {
		t.Fatalf("resume Store gets = before %d after %d, want root/repository reconciliation", beforeResume.Gets, afterResume.Gets)
	}

	handoffAfter, err := os.ReadFile(handoffPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(handoffAfter, handoffBefore) {
		t.Fatal("completed one-shot resume changed the exact handoff bytes")
	}
	loaded, found, err = loadPublisherSession(ctx, sessionStore, now)
	if err != nil || !found || loaded.state.Phase != publisherSessionCompleted || !loaded.state.Once {
		t.Fatalf(
			"session after completed resume = phase %q once=%t found=%t err=%v",
			loaded.state.Phase, loaded.state.Once, found, err,
		)
	}
	rootAfter, err := store.Get(ctx, loaded.state.RootKey, s3disk.GetOptions{MaxBytes: 65 << 20})
	if err != nil {
		t.Fatalf("read root after resume: %v", err)
	}
	if rootAfter.Version != rootBefore.Version || !bytes.Equal(rootAfter.Data, rootBefore.Data) {
		t.Fatal("completed one-shot resume changed the already reconciled root")
	}
}

func TestRunResumeSettlesExactPendingRootWithoutPresigning(t *testing.T) {
	requirePrivateSecretFiles(t)
	requirePublisherSessionSealedState(t)

	tests := []struct {
		name             string
		applyLostWrite   bool
		wantResumeWrites int
	}{
		{name: "write applied before response loss", applyLostWrite: true, wantResumeWrites: 0},
		{name: "write replayed from exact WAL", applyLostWrite: false, wantResumeWrites: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Second)
			source := t.TempDir()
			if err := os.WriteFile(filepath.Join(source, "shared.txt"), []byte("exact pending root"), 0o600); err != nil {
				t.Fatal(err)
			}
			stateDirectory := t.TempDir()
			if err := os.Chmod(stateDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			handoffPath := filepath.Join(t.TempDir(), "share.handoff")
			recoveryKeyPath := filepath.Join(t.TempDir(), "publisher-recovery-key.json")
			recoveryMaterial := writeOrderingRecoveryKey(t, recoveryKeyPath)
			baseStore := memstore.New()
			store := &orderingPendingRootStore{base: baseStore, applyLostWrite: test.applyLostWrite}
			presigner := &orderingExactPresigner{}
			publishPresignCalls := 0
			publishOperations := publisherOperations{
				now: func() time.Time { return now },
				openS3: func(context.Context, publisherS3Config) (publisherS3Handle, error) {
					return publisherS3Handle{
						store: store,
						newPresignSession: func(_ context.Context, expiresAt time.Time) (presignedshare.ExactGETPresigner, error) {
							publishPresignCalls++
							presigner.expiresAt = expiresAt
							return presigner, nil
						},
					}, nil
				},
				afterExternalEffect: func(context.Context, publisherExternalEffect) error { return nil },
				afterDurablePhase:   func(context.Context, publisherSessionPhase) error { return nil },
			}
			publishOptions := PublishOptions{
				Source: source, All: true, Bucket: "pending-root-bucket",
				Prefix: "pending-root/" + strings.ReplaceAll(test.name, " ", "-"), Region: "us-east-1",
				Endpoint: "http://127.0.0.1:9000", UsePathStyle: true,
				AllowInsecureEndpoint: true, Channel: "main", ExpiresIn: time.Hour,
				HandoffOut: handoffPath, StateDir: stateDirectory,
				RecoveryKey: recoveryKeyPath, Once: true,
			}
			publishErr := runPublishWithOperations(ctx, publishOptions, publishOperations)
			if !errors.Is(publishErr, presignedshare.ErrRootPublishIndeterminate) {
				t.Fatalf("publish error = %v, want ErrRootPublishIndeterminate", publishErr)
			}
			if publishPresignCalls != 1 || presigner.shareID.IsZero() {
				t.Fatalf("publish presign calls = %d share=%s, want one call and a share identity", publishPresignCalls, presigner.shareID)
			}
			if lostWrites, failedReads, _ := store.stats(); lostWrites != 1 || failedReads != 1 {
				t.Fatalf("root fault calls = lost writes %d failed reads %d, want 1/1", lostWrites, failedReads)
			}

			shareDirectory := filepath.Join(stateDirectory, presigner.shareID.String())
			sessionStore, err := newPublisherSessionSealedStore(
				shareDirectory, presigner.shareID, recoveryMaterial,
			)
			if err != nil {
				t.Fatal(err)
			}
			crashed, found, err := loadPublisherSession(ctx, sessionStore, now)
			if err != nil || !found {
				t.Fatalf("load crashed session: found=%t err=%v", found, err)
			}
			if crashed.state.Phase != publisherSessionInitialPublicationReady || !crashed.state.Once {
				t.Fatalf("crashed session = phase %q once=%t, want initial publication one-shot", crashed.state.Phase, crashed.state.Once)
			}
			rootBefore, rootBeforeErr := baseStore.Get(
				ctx, crashed.state.RootKey, s3disk.GetOptions{MaxBytes: 65 << 20},
			)
			if test.applyLostWrite {
				if rootBeforeErr != nil {
					t.Fatalf("read applied root before resume: %v", rootBeforeErr)
				}
			} else if !errors.Is(rootBeforeErr, s3disk.ErrObjectNotFound) {
				t.Fatalf("unapplied root before resume = version %#v err %v", rootBefore.Version, rootBeforeErr)
			}
			if _, err := os.Lstat(handoffPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("handoff existed before root recovery: %v", err)
			}
			if err := os.RemoveAll(source); err != nil {
				t.Fatal(err)
			}

			store.beginResume()
			resumePresignCalls := 0
			presignMustNotRun := errors.New("pending root recovery must not presign")
			resumeOperations := publisherOperations{
				now: func() time.Time { return now },
				openS3: func(context.Context, publisherS3Config) (publisherS3Handle, error) {
					return publisherS3Handle{
						store: store,
						newPresignSession: func(context.Context, time.Time) (presignedshare.ExactGETPresigner, error) {
							resumePresignCalls++
							return nil, presignMustNotRun
						},
					}, nil
				},
				afterExternalEffect: func(context.Context, publisherExternalEffect) error { return nil },
				afterDurablePhase:   func(context.Context, publisherSessionPhase) error { return nil },
			}
			if err := runResumeWithOperations(ctx, ResumeOptions{
				StateDir: stateDirectory, ShareID: presigner.shareID.String(), RecoveryKey: recoveryKeyPath,
			}, resumeOperations); err != nil {
				t.Fatalf("resume exact pending root: %v", err)
			}
			if resumePresignCalls != 0 {
				t.Fatalf("resume presign calls = %d, want zero", resumePresignCalls)
			}
			if _, _, resumeWrites := store.stats(); resumeWrites != test.wantResumeWrites {
				t.Fatalf("root writes during resume = %d, want %d", resumeWrites, test.wantResumeWrites)
			}

			completed, found, err := loadPublisherSession(ctx, sessionStore, now)
			if err != nil || !found || completed.state.Phase != publisherSessionCompleted || !completed.state.Once {
				t.Fatalf(
					"recovered session = phase %q once=%t found=%t err=%v",
					completed.state.Phase, completed.state.Once, found, err,
				)
			}
			rootAfter, err := baseStore.Get(
				ctx, completed.state.RootKey, s3disk.GetOptions{MaxBytes: 65 << 20},
			)
			if err != nil {
				t.Fatalf("read recovered root: %v", err)
			}
			if test.applyLostWrite &&
				(rootAfter.Version != rootBefore.Version || !bytes.Equal(rootAfter.Data, rootBefore.Data)) {
				t.Fatal("resume replaced a root which was applied before response loss")
			}
			share, err := readHandoff(handoffPath)
			if err != nil {
				t.Fatalf("read recovered handoff: %v", err)
			}
			bundle := decodeOrderingRoot(t, ctx, share, completed.state.RootKey, rootAfter.Data)
			if bundle.Revision() != 1 || bundle.ReferenceGeneration() != 1 ||
				bundle.ReferenceCommit().String() != completed.state.TrustedCheckpoint.Commit {
				t.Fatalf(
					"recovered root = revision %d generation %d commit %s",
					bundle.Revision(), bundle.ReferenceGeneration(), bundle.ReferenceCommit(),
				)
			}
		})
	}
}

func TestRunResumeLazilyPresignsWhenExactReferenceVersionChanges(t *testing.T) {
	requirePrivateSecretFiles(t)
	requirePublisherSessionSealedState(t)

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "shared.txt"), []byte("reference rewrite"), 0o600); err != nil {
		t.Fatal(err)
	}
	stateDirectory := t.TempDir()
	if err := os.Chmod(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	handoffPath := filepath.Join(t.TempDir(), "share.handoff")
	recoveryKeyPath := filepath.Join(t.TempDir(), "publisher-recovery-key.json")
	recoveryMaterial := writeOrderingRecoveryKey(t, recoveryKeyPath)
	store := memstore.New()
	presigner := &orderingExactPresigner{}
	presignSessionCalls := 0
	operations := publisherOperations{
		now: func() time.Time { return now },
		openS3: func(context.Context, publisherS3Config) (publisherS3Handle, error) {
			return publisherS3Handle{
				store: store,
				newPresignSession: func(_ context.Context, expiresAt time.Time) (presignedshare.ExactGETPresigner, error) {
					presignSessionCalls++
					presigner.expiresAt = expiresAt
					return presigner, nil
				},
			}, nil
		},
		afterExternalEffect: func(context.Context, publisherExternalEffect) error { return nil },
		afterDurablePhase:   func(context.Context, publisherSessionPhase) error { return nil },
	}
	publishOptions := PublishOptions{
		Source: source, All: true, Bucket: "reference-rewrite-bucket", Prefix: "reference-rewrite",
		Region: "us-east-1", Endpoint: "http://127.0.0.1:9000", UsePathStyle: true,
		AllowInsecureEndpoint: true, Channel: "main", ExpiresIn: time.Hour,
		HandoffOut: handoffPath, StateDir: stateDirectory, RecoveryKey: recoveryKeyPath, Once: true,
	}
	if err := runPublishWithOperations(ctx, publishOptions, operations); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if presignSessionCalls != 1 || presigner.shareID.IsZero() {
		t.Fatalf("publish presign calls = %d share=%s, want one call and a share identity", presignSessionCalls, presigner.shareID)
	}

	shareDirectory := filepath.Join(stateDirectory, presigner.shareID.String())
	sessionStore, err := newPublisherSessionSealedStore(
		shareDirectory, presigner.shareID, recoveryMaterial,
	)
	if err != nil {
		t.Fatal(err)
	}
	beforeSession, found, err := loadPublisherSession(ctx, sessionStore, now)
	if err != nil || !found || beforeSession.state.Phase != publisherSessionCompleted {
		t.Fatalf("load completed session: phase=%q found=%t err=%v", beforeSession.state.Phase, found, err)
	}
	handoffBefore, err := os.ReadFile(handoffPath)
	if err != nil {
		t.Fatal(err)
	}
	rootBefore, err := store.Get(ctx, beforeSession.state.RootKey, s3disk.GetOptions{MaxBytes: 65 << 20})
	if err != nil {
		t.Fatal(err)
	}
	referenceBefore, err := store.Get(ctx, beforeSession.state.ReferenceKey, s3disk.GetOptions{MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	store.ForcePut(beforeSession.state.ReferenceKey, referenceBefore.Data)
	referenceAfter, err := store.Get(ctx, beforeSession.state.ReferenceKey, s3disk.GetOptions{MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if referenceAfter.Version == referenceBefore.Version || !bytes.Equal(referenceAfter.Data, referenceBefore.Data) {
		t.Fatalf("reference rewrite = before %#v after %#v equal-bytes=%t", referenceBefore.Version, referenceAfter.Version, bytes.Equal(referenceAfter.Data, referenceBefore.Data))
	}
	if err := os.RemoveAll(source); err != nil {
		t.Fatal(err)
	}

	if err := runResumeWithOperations(ctx, ResumeOptions{
		StateDir: stateDirectory, ShareID: presigner.shareID.String(), RecoveryKey: recoveryKeyPath,
	}, operations); err != nil {
		t.Fatalf("resume after exact reference rewrite: %v", err)
	}
	if presignSessionCalls != 2 {
		t.Fatalf("publish plus lazy resume presign calls = %d, want 2", presignSessionCalls)
	}
	rootAfter, err := store.Get(ctx, beforeSession.state.RootKey, s3disk.GetOptions{MaxBytes: 65 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if rootAfter.Version == rootBefore.Version || bytes.Equal(rootAfter.Data, rootBefore.Data) {
		t.Fatal("reference version rewrite did not advance the encrypted share root")
	}
	handoffAfter, err := os.ReadFile(handoffPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(handoffAfter, handoffBefore) {
		t.Fatal("reference version rewrite changed the initial handoff")
	}
	share, err := readHandoff(handoffPath)
	if err != nil {
		t.Fatal(err)
	}
	bundle := decodeOrderingRoot(t, ctx, share, beforeSession.state.RootKey, rootAfter.Data)
	if bundle.Revision() != 2 || bundle.ReferenceGeneration() != 1 ||
		bundle.ReferenceCommit().String() != beforeSession.state.TrustedCheckpoint.Commit ||
		bundle.Reference().Version != referenceAfter.Version {
		t.Fatalf(
			"rewritten root = revision %d generation %d commit %s reference-version %#v, want revision 2 and %#v",
			bundle.Revision(), bundle.ReferenceGeneration(), bundle.ReferenceCommit(), bundle.Reference().Version, referenceAfter.Version,
		)
	}
	afterSession, found, err := loadPublisherSession(ctx, sessionStore, now)
	if err != nil || !found || afterSession.state.Phase != publisherSessionCompleted ||
		afterSession.revision != beforeSession.revision ||
		afterSession.authenticatedDigest != beforeSession.authenticatedDigest {
		t.Fatalf(
			"completed session changed during lazy root update: phase=%q found=%t revision=%x err=%v",
			afterSession.state.Phase, found, afterSession.revision, err,
		)
	}
}

func TestRunResumeDoesNotPresignForStoreMisconfiguration(t *testing.T) {
	requirePrivateSecretFiles(t)
	requirePublisherSessionSealedState(t)

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "shared.txt"), []byte("store classification"), 0o600); err != nil {
		t.Fatal(err)
	}
	stateDirectory := t.TempDir()
	if err := os.Chmod(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	handoffPath := filepath.Join(t.TempDir(), "share.handoff")
	recoveryKeyPath := filepath.Join(t.TempDir(), "publisher-recovery-key.json")
	recoveryMaterial := writeOrderingRecoveryKey(t, recoveryKeyPath)
	store := memstore.New()
	presigner := &orderingExactPresigner{}
	presignSessionCalls := 0
	operations := publisherOperations{
		now: func() time.Time { return now },
		openS3: func(context.Context, publisherS3Config) (publisherS3Handle, error) {
			return publisherS3Handle{
				store: store,
				newPresignSession: func(_ context.Context, expiresAt time.Time) (presignedshare.ExactGETPresigner, error) {
					presignSessionCalls++
					presigner.expiresAt = expiresAt
					return presigner, nil
				},
			}, nil
		},
		afterExternalEffect: func(context.Context, publisherExternalEffect) error { return nil },
		afterDurablePhase:   func(context.Context, publisherSessionPhase) error { return nil },
	}
	publishOptions := PublishOptions{
		Source: source, All: true, Bucket: "classification-bucket", Prefix: "classification",
		Region: "us-east-1", Endpoint: "http://127.0.0.1:9000", UsePathStyle: true,
		AllowInsecureEndpoint: true, Channel: "main", ExpiresIn: time.Hour,
		HandoffOut: handoffPath, StateDir: stateDirectory, RecoveryKey: recoveryKeyPath, Once: true,
	}
	if err := runPublishWithOperations(ctx, publishOptions, operations); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if presignSessionCalls != 1 || presigner.shareID.IsZero() {
		t.Fatalf("publish presign calls = %d share=%s, want one", presignSessionCalls, presigner.shareID)
	}

	shareDirectory := filepath.Join(stateDirectory, presigner.shareID.String())
	sessionStore, err := newPublisherSessionSealedStore(shareDirectory, presigner.shareID, recoveryMaterial)
	if err != nil {
		t.Fatal(err)
	}
	loaded, found, err := loadPublisherSession(ctx, sessionStore, now)
	if err != nil || !found || loaded.state.Phase != publisherSessionCompleted {
		t.Fatalf("load completed session: phase=%q found=%t err=%v", loaded.state.Phase, found, err)
	}
	if err := os.RemoveAll(source); err != nil {
		t.Fatal(err)
	}

	failing := &orderingFailKeyGetStore{
		base: store, key: loaded.state.ReferenceKey, err: s3disk.ErrStoreMisconfigured,
	}
	resumeOperations := operations
	resumeOperations.openS3 = func(context.Context, publisherS3Config) (publisherS3Handle, error) {
		return publisherS3Handle{
			store: failing,
			newPresignSession: func(_ context.Context, expiresAt time.Time) (presignedshare.ExactGETPresigner, error) {
				presignSessionCalls++
				presigner.expiresAt = expiresAt
				return presigner, nil
			},
		}, nil
	}
	err = runResumeWithOperations(ctx, ResumeOptions{
		StateDir: stateDirectory, ShareID: presigner.shareID.String(), RecoveryKey: recoveryKeyPath,
	}, resumeOperations)
	if !errors.Is(err, s3disk.ErrStoreMisconfigured) {
		t.Fatalf("resume error = %v, want ErrStoreMisconfigured", err)
	}
	if errors.Is(err, presignedshare.ErrRootBuildAuthorityRequired) {
		t.Fatalf("Store error was misclassified as missing root build authority: %v", err)
	}
	if presignSessionCalls != 1 {
		t.Fatalf("Store configuration failure acquired a new presign session: calls=%d", presignSessionCalls)
	}
	if failing.failures != 1 {
		t.Fatalf("reference Store failures = %d, want one", failing.failures)
	}
}

func TestRunPublishExternalEffectCrashWindowsResumeOneShotWithoutForkOrOverwrite(t *testing.T) {
	requirePrivateSecretFiles(t)
	requirePublisherSessionSealedState(t)

	tests := []struct {
		effect        publisherExternalEffect
		crashedPhase  publisherSessionPhase
		rootExists    bool
		handoffExists bool
	}{
		{publisherEffectRepositoryReady, publisherSessionPrepared, false, false},
		{publisherEffectJournalReady, publisherSessionRepositoryReady, false, false},
		{publisherEffectInitialPublicationReady, publisherSessionJournalReady, false, false},
		{publisherEffectInitialRootReady, publisherSessionInitialPublicationReady, true, false},
		{publisherEffectHandoffReady, publisherSessionInitialRootReady, true, true},
	}
	for _, test := range tests {
		t.Run(string(test.effect), func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Second)
			source := t.TempDir()
			if err := os.WriteFile(filepath.Join(source, "shared.txt"), []byte("crash-window payload"), 0o600); err != nil {
				t.Fatal(err)
			}
			stateDirectory := t.TempDir()
			if err := os.Chmod(stateDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			handoffPath := filepath.Join(t.TempDir(), "share.handoff")
			recoveryKeyPath := filepath.Join(t.TempDir(), "publisher-recovery-key.json")
			recoveryMaterial := writeOrderingRecoveryKey(t, recoveryKeyPath)
			store := memstore.New()
			presigner := &orderingExactPresigner{}
			crash := fmt.Errorf("crash after %s external effect", test.effect)
			failpointCalls := 0
			crashOperations := orderingMemstorePublisherOperations(
				now, store, presigner,
				func(_ context.Context, effect publisherExternalEffect) error {
					if effect != test.effect {
						return nil
					}
					failpointCalls++
					return crash
				},
			)
			publishOptions := PublishOptions{
				Source: source, All: true, Bucket: "crash-window-bucket",
				Prefix: "crash-window/" + string(test.effect), Region: "us-east-1",
				Endpoint: "http://127.0.0.1:9000", UsePathStyle: true,
				AllowInsecureEndpoint: true, Channel: "main", ExpiresIn: time.Hour,
				HandoffOut: handoffPath, StateDir: stateDirectory,
				RecoveryKey: recoveryKeyPath, Once: true,
			}
			publishErr := runPublishWithOperations(ctx, publishOptions, crashOperations)
			if !errors.Is(publishErr, crash) {
				t.Fatalf("publish error = %v, want crash sentinel", publishErr)
			}
			if failpointCalls != 1 {
				t.Fatalf("target effect failpoint calls = %d, want 1", failpointCalls)
			}
			if presigner.shareID.IsZero() {
				t.Fatal("crashed publish did not retain its share identity")
			}

			shareDirectory := filepath.Join(stateDirectory, presigner.shareID.String())
			sessionStore, err := newPublisherSessionSealedStore(
				shareDirectory, presigner.shareID, recoveryMaterial,
			)
			if err != nil {
				t.Fatal(err)
			}
			crashed, found, err := loadPublisherSession(ctx, sessionStore, now)
			if err != nil || !found {
				t.Fatalf("load crashed session: found=%t err=%v", found, err)
			}
			if crashed.state.Phase != test.crashedPhase {
				t.Fatalf("crashed phase = %q, want %q", crashed.state.Phase, test.crashedPhase)
			}

			handoffBefore, handoffBeforeErr := os.ReadFile(handoffPath)
			if test.handoffExists {
				if handoffBeforeErr != nil {
					t.Fatalf("read handoff after applied handoff effect: %v", handoffBeforeErr)
				}
			} else if !errors.Is(handoffBeforeErr, os.ErrNotExist) {
				t.Fatalf("handoff before its effect = data %d bytes, err %v", len(handoffBefore), handoffBeforeErr)
			}

			rootBefore, rootBeforeErr := store.Get(
				ctx, crashed.state.RootKey, s3disk.GetOptions{MaxBytes: 65 << 20},
			)
			if test.rootExists {
				if rootBeforeErr != nil {
					t.Fatalf("read root after applied root effect: %v", rootBeforeErr)
				}
			} else if !errors.Is(rootBeforeErr, s3disk.ErrObjectNotFound) {
				t.Fatalf("root before its effect = version %#v, err %v", rootBefore.Version, rootBeforeErr)
			}

			resumeOperations := orderingMemstorePublisherOperations(now, store, presigner, nil)
			if err := runResumeWithOperations(ctx, ResumeOptions{
				StateDir: stateDirectory, ShareID: presigner.shareID.String(), RecoveryKey: recoveryKeyPath,
			}, resumeOperations); err != nil {
				t.Fatalf("resume after %s effect: %v", test.effect, err)
			}

			completed, found, err := loadPublisherSession(ctx, sessionStore, now)
			if err != nil || !found {
				t.Fatalf("load completed session: found=%t err=%v", found, err)
			}
			if completed.state.Phase != publisherSessionCompleted || !completed.state.Once {
				t.Fatalf(
					"recovered session = phase %q once=%t, want completed one-shot",
					completed.state.Phase, completed.state.Once,
				)
			}
			if completed.state.TrustedCheckpoint == nil || completed.state.TrustedCheckpoint.Generation != 1 {
				t.Fatalf("recovered checkpoint = %#v, want generation 1", completed.state.TrustedCheckpoint)
			}

			handoffAfter, err := os.ReadFile(handoffPath)
			if err != nil {
				t.Fatalf("read recovered handoff: %v", err)
			}
			if test.handoffExists && !bytes.Equal(handoffAfter, handoffBefore) {
				t.Fatal("resume overwrote an already installed exact handoff")
			}
			decodedHandoff, err := readHandoff(handoffPath)
			if err != nil {
				t.Fatalf("authenticate recovered handoff: %v", err)
			}

			journal, err := s3disk.NewFilePublicationJournal(
				filepath.Join(shareDirectory, "publication-journal.json"),
			)
			if err != nil {
				t.Fatal(err)
			}
			journalState, _, journalFound, err := journal.Load(ctx, completed.state.Channel)
			if err != nil || !journalFound {
				t.Fatalf("load recovered publication journal: found=%t err=%v", journalFound, err)
			}
			if journalState.Pending != nil || journalState.Committed == nil ||
				journalState.Committed.Generation != 1 ||
				journalState.Committed.Commit.String() != completed.state.TrustedCheckpoint.Commit {
				t.Fatalf(
					"recovered journal forked or remained pending: committed=%#v pending=%#v",
					journalState.Committed, journalState.Pending,
				)
			}

			rootAfter, err := store.Get(
				ctx, completed.state.RootKey, s3disk.GetOptions{MaxBytes: 65 << 20},
			)
			if err != nil {
				t.Fatalf("read recovered root: %v", err)
			}
			if test.rootExists &&
				(rootAfter.Version != rootBefore.Version || !bytes.Equal(rootAfter.Data, rootBefore.Data)) {
				t.Fatal("resume overwrote an already committed root")
			}
			logicalRoot, err := decodedHandoff.profile.OpenObject(completed.state.RootKey, rootAfter.Data)
			if err != nil {
				t.Fatalf("decrypt recovered root: %v", err)
			}
			verifier, err := s3disk.NewEd25519ReferenceVerifier(
				decodedHandoff.repository,
				map[string]ed25519.PublicKey{decodedHandoff.wire.ReferenceKeyID: decodedHandoff.publicKey},
			)
			if err != nil {
				clear(logicalRoot)
				t.Fatal(err)
			}
			bundle, err := presignedshare.Decode(ctx, logicalRoot, verifier, presignedshare.DecodeOptions{
				RootCapability: decodedHandoff.root, RepositoryPrefix: decodedHandoff.wire.RepositoryPrefix,
				ReferenceKey: decodedHandoff.wire.ReferenceKey, ShareID: decodedHandoff.shareID,
				AllowInsecureLoopback: decodedHandoff.wire.AllowInsecureLoopback,
			})
			clear(logicalRoot)
			if err != nil {
				t.Fatalf("authenticate recovered root bundle: %v", err)
			}
			if bundle.Revision() != 1 || bundle.ReferenceGeneration() != 1 ||
				bundle.ReferenceCommit().String() != completed.state.TrustedCheckpoint.Commit ||
				bundle.CapabilityCount() == 0 {
				t.Fatalf(
					"recovered root forked or advanced unexpectedly: revision=%d generation=%d commit=%s capabilities=%d",
					bundle.Revision(), bundle.ReferenceGeneration(), bundle.ReferenceCommit(), bundle.CapabilityCount(),
				)
			}
		})
	}
}

func writeOrderingRecoveryKey(t *testing.T, path string) recoveryKeyMaterial {
	t.Helper()
	key, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	material, _, err := writeRecoveryKeyFile(context.Background(), path, key)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func orderingMemstorePublisherOperations(
	now time.Time,
	store *memstore.Store,
	presigner *orderingExactPresigner,
	afterExternalEffect func(context.Context, publisherExternalEffect) error,
) publisherOperations {
	if afterExternalEffect == nil {
		afterExternalEffect = func(context.Context, publisherExternalEffect) error { return nil }
	}
	return publisherOperations{
		now: func() time.Time { return now },
		openS3: func(context.Context, publisherS3Config) (publisherS3Handle, error) {
			return publisherS3Handle{
				store: store,
				newPresignSession: func(_ context.Context, expiresAt time.Time) (presignedshare.ExactGETPresigner, error) {
					presigner.expiresAt = expiresAt
					return presigner, nil
				},
			}, nil
		},
		afterExternalEffect: afterExternalEffect,
		afterDurablePhase:   func(context.Context, publisherSessionPhase) error { return nil },
	}
}

type orderingPendingRootStore struct {
	base           *memstore.Store
	applyLostWrite bool

	mu                     sync.Mutex
	injected               bool
	failNextRootGet        bool
	resume                 bool
	lostRootWrites         int
	failedRootReads        int
	rootWritesDuringResume int
}

type orderingFailKeyGetStore struct {
	base *memstore.Store
	key  string
	err  error

	failures int
}

func (store *orderingFailKeyGetStore) Get(
	ctx context.Context,
	key string,
	options s3disk.GetOptions,
) (s3disk.Object, error) {
	if key == store.key {
		store.failures++
		return s3disk.Object{}, store.err
	}
	return store.base.Get(ctx, key, options)
}

func (store *orderingFailKeyGetStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	return store.base.Head(ctx, key)
}

func (store *orderingFailKeyGetStore) PutIfAbsent(
	ctx context.Context,
	key string,
	data []byte,
) (s3disk.Version, error) {
	return store.base.PutIfAbsent(ctx, key, data)
}

func (store *orderingFailKeyGetStore) CompareAndSwap(
	ctx context.Context,
	key string,
	expected *s3disk.Version,
	data []byte,
) (s3disk.Version, error) {
	return store.base.CompareAndSwap(ctx, key, expected, data)
}

func (store *orderingPendingRootStore) Get(
	ctx context.Context,
	key string,
	options s3disk.GetOptions,
) (s3disk.Object, error) {
	store.mu.Lock()
	if strings.Contains(key, "/share-root/") && store.failNextRootGet {
		store.failNextRootGet = false
		store.failedRootReads++
		store.mu.Unlock()
		return s3disk.Object{}, s3disk.ErrStoreUnavailable
	}
	store.mu.Unlock()
	return store.base.Get(ctx, key, options)
}

func (store *orderingPendingRootStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	return store.base.Head(ctx, key)
}

func (store *orderingPendingRootStore) PutIfAbsent(
	ctx context.Context,
	key string,
	data []byte,
) (s3disk.Version, error) {
	if !strings.Contains(key, "/share-root/") {
		return store.base.PutIfAbsent(ctx, key, data)
	}
	store.mu.Lock()
	if !store.injected {
		store.injected = true
		store.failNextRootGet = true
		store.lostRootWrites++
		apply := store.applyLostWrite
		store.mu.Unlock()
		if apply {
			if _, err := store.base.PutIfAbsent(ctx, key, data); err != nil {
				return s3disk.Version{}, err
			}
		}
		return s3disk.Version{}, s3disk.ErrStoreUnavailable
	}
	if store.resume {
		store.rootWritesDuringResume++
	}
	store.mu.Unlock()
	return store.base.PutIfAbsent(ctx, key, data)
}

func (store *orderingPendingRootStore) CompareAndSwap(
	ctx context.Context,
	key string,
	expected *s3disk.Version,
	data []byte,
) (s3disk.Version, error) {
	store.mu.Lock()
	if store.resume && strings.Contains(key, "/share-root/") {
		store.rootWritesDuringResume++
	}
	store.mu.Unlock()
	return store.base.CompareAndSwap(ctx, key, expected, data)
}

func (store *orderingPendingRootStore) beginResume() {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.resume = true
}

func (store *orderingPendingRootStore) stats() (lostWrites, failedReads, resumeWrites int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.lostRootWrites, store.failedRootReads, store.rootWritesDuringResume
}

func decodeOrderingRoot(
	t *testing.T,
	ctx context.Context,
	share decodedHandoff,
	rootKey string,
	stored []byte,
) *presignedshare.Bundle {
	t.Helper()
	logical, err := share.profile.OpenObject(rootKey, stored)
	if err != nil {
		t.Fatalf("decrypt root: %v", err)
	}
	defer clear(logical)
	verifier, err := s3disk.NewEd25519ReferenceVerifier(
		share.repository,
		map[string]ed25519.PublicKey{share.wire.ReferenceKeyID: share.publicKey},
	)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := presignedshare.Decode(ctx, logical, verifier, presignedshare.DecodeOptions{
		RootCapability: share.root, RepositoryPrefix: share.wire.RepositoryPrefix,
		ReferenceKey: share.wire.ReferenceKey, ShareID: share.shareID,
		AllowInsecureLoopback: share.wire.AllowInsecureLoopback,
	})
	if err != nil {
		t.Fatalf("authenticate root: %v", err)
	}
	return bundle
}

type orderingSentinelStore struct {
	sentinel      error
	beforeFirst   func(context.Context, string) error
	once          sync.Once
	calls         int
	validationErr error
}

func (store *orderingSentinelStore) fail(ctx context.Context, operation string) error {
	store.calls++
	store.once.Do(func() {
		if store.beforeFirst != nil {
			store.validationErr = store.beforeFirst(ctx, operation)
		}
	})
	return store.sentinel
}

func (store *orderingSentinelStore) Get(ctx context.Context, _ string, _ s3disk.GetOptions) (s3disk.Object, error) {
	return s3disk.Object{}, store.fail(ctx, "Get")
}

func (store *orderingSentinelStore) Head(ctx context.Context, _ string) (s3disk.Version, error) {
	return s3disk.Version{}, store.fail(ctx, "Head")
}

func (store *orderingSentinelStore) PutIfAbsent(ctx context.Context, _ string, _ []byte) (s3disk.Version, error) {
	return s3disk.Version{}, store.fail(ctx, "PutIfAbsent")
}

func (store *orderingSentinelStore) CompareAndSwap(
	ctx context.Context,
	_ string,
	_ *s3disk.Version,
	_ []byte,
) (s3disk.Version, error) {
	return s3disk.Version{}, store.fail(ctx, "CompareAndSwap")
}

type orderingExactPresigner struct {
	expiresAt time.Time
	shareID   presignedshare.ShareID
}

func (presigner *orderingExactPresigner) AuthorizationExpiry() (time.Time, bool) {
	return presigner.expiresAt, !presigner.expiresAt.IsZero()
}

func (presigner *orderingExactPresigner) PresignGet(
	ctx context.Context,
	key string,
) (presignedshare.Capability, error) {
	if err := ctx.Err(); err != nil {
		return presignedshare.Capability{}, err
	}
	if presigner.shareID.IsZero() {
		shareID, err := orderingShareIDFromRootKey(key)
		if err != nil {
			return presignedshare.Capability{}, err
		}
		presigner.shareID = shareID
	}
	rawURL := "http://127.0.0.1:9000/ordering/" + url.PathEscape(key) + "?X-Amz-Signature=ordering-secret"
	return presignedshare.NewCapabilityFromExactGET(
		presignedcap.NewExactGET(key, rawURL, http.Header{}, presigner.expiresAt),
		presignedshare.CapabilityOptions{AllowInsecureLoopback: true},
	)
}

func orderingShareIDFromRootKey(key string) (presignedshare.ShareID, error) {
	const marker = "/shares/"
	start := strings.Index(key, marker)
	if start < 0 {
		return presignedshare.ShareID{}, errors.New("root key has no share namespace")
	}
	remainder := key[start+len(marker):]
	end := strings.IndexByte(remainder, '/')
	if end < 1 {
		return presignedshare.ShareID{}, errors.New("root key has no canonical share identity")
	}
	shareID, err := presignedshare.ParseShareID(remainder[:end])
	if err != nil {
		return presignedshare.ShareID{}, err
	}
	return shareID, nil
}

var _ s3disk.Store = (*orderingSentinelStore)(nil)
var _ s3disk.Store = (*orderingPendingRootStore)(nil)
var _ presignedshare.ExactGETPresigner = (*orderingExactPresigner)(nil)
