package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/presignedshare"
	"github.com/vibe-agi/s3disk/publisherstate"
)

func TestPublisherSessionCanonicalRoundTripAndRedactedDiagnostics(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	want := newTestPublisherSession(t, now)
	encoded, err := encodePublisherSession(want)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) == 0 || encoded[len(encoded)-1] != '\n' {
		t.Fatal("publisher session is not newline-terminated canonical JSON")
	}
	got, err := decodePublisherSession(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("publisher session round trip changed state\n got: %#v\nwant: %#v", got, want)
	}
	roundTrip, err := encodePublisherSession(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(roundTrip, encoded) {
		t.Fatal("publisher session encoding is not stable")
	}
	redactedJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, diagnostic := range []string{fmt.Sprint(got), fmt.Sprintf("%+v", got), fmt.Sprintf("%#v", got), string(redactedJSON)} {
		for _, secret := range []string{
			string(got.RootBearer), got.ClientEncryptionKey,
			base64.RawURLEncoding.EncodeToString(got.ReferencePrivateSeed),
			string(got.SourcePath), string(got.HandoffPath),
		} {
			if secret != "" && strings.Contains(diagnostic, secret) {
				t.Fatalf("publisher session diagnostic leaked secret or private path: %q", diagnostic)
			}
		}
		if !strings.Contains(diagnostic, "redacted") {
			t.Fatalf("publisher session diagnostic is not visibly redacted: %q", diagnostic)
		}
	}
}

func TestPublisherSessionCanonicalWireGolden(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("publisher recovery is currently fail-closed on Windows")
	}
	createdAt := time.Date(2099, time.January, 2, 3, 4, 5, 0, time.UTC)
	shareID := "AgICAgICAgICAgICAgICAg"
	prefix := "golden/prefix"
	repositoryPrefix := prefix + "/shares/" + shareID
	rootNonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	clientSecret := "s3disk-client-encryption-v1." +
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
	value := publisherSession{
		Format: publisherSessionFormat, Profile: publisherSessionProfile,
		Sequence: 1, Phase: publisherSessionPrepared,
		CreatedAt: createdAt, AuthorizationExpiresAt: createdAt.Add(time.Hour),
		ShareID: shareID, RepositoryID: strings.Repeat("01", 32), RecoveryKeyID: "rk1.golden",
		SourcePath: []byte("/golden/source"), SelectAll: true, SelectedPaths: [][]byte{}, Once: true,
		HandoffPath: []byte("/golden/share.handoff"),
		Bucket:      "golden-bucket", Prefix: prefix, Region: "us-east-1",
		Endpoint: "http://127.0.0.1:9000", UsePathStyle: true, AllowInsecureEndpoint: true,
		RepositoryPrefix: repositoryPrefix, Channel: "main",
		ReferenceKey:   repositoryPrefix + "/.s3disk/v1/signed-refs/v1/bWFpbg",
		ReferenceKeyID: "share-key-1", ReferencePrivateSeed: bytes.Repeat([]byte{3}, ed25519.SeedSize),
		RootKey:    repositoryPrefix + "/share-root/" + rootNonce,
		RootBearer: []byte("golden-root-bearer-v1"), ClientEncryptionKey: clientSecret,
	}
	encoded, err := encodePublisherSession(value)
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprintf("%x", sha256.Sum256(encoded))
	const want = "cb0c7aa8fe45a8a5cad9dbc13a668564193f218594520fc439114a75827d2a63"
	if got != want {
		t.Fatalf("canonical publisher-session wire SHA-256 = %s, want %s", got, want)
	}
}

func TestPublisherSessionStrictDecoderRejectsNonCanonicalAndUnknownData(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	valid, err := encodePublisherSession(newTestPublisherSession(t, now))
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(valid, &object); err != nil {
		t.Fatal(err)
	}
	object["secret_access_key"] = json.RawMessage(`"must-never-be-a-wire-field"`)
	unknown, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	unknown = append(unknown, '\n')

	cases := map[string][]byte{
		"missing newline":      bytes.TrimSuffix(valid, []byte{'\n'}),
		"leading whitespace":   append([]byte{' '}, valid...),
		"trailing value":       append(bytes.Clone(valid), []byte("{}\n")...),
		"unknown credential":   unknown,
		"duplicate format key": bytes.Replace(valid, []byte(`{"format":`), []byte(`{"format":1,"format":`), 1),
	}
	nullSelection := bytes.Replace(valid, []byte(`"selected_paths":[]`), []byte(`"selected_paths":null`), 1)
	cases["null selected paths"] = nullSelection
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodePublisherSession(encoded); !errors.Is(err, ErrInvalidPublisherSession) {
				t.Fatalf("decode error = %v, want ErrInvalidPublisherSession", err)
			}
		})
	}
}

func TestPublisherSessionPhaseAndImmutableStateValidation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	prepared := newTestPublisherSession(t, now)
	checkpoint := testPublisherSessionCheckpoint()
	var handoffDigest s3disk.Digest
	handoffDigest[0] = 0x7f

	current := prepared
	for _, step := range []struct {
		phase      publisherSessionPhase
		checkpoint *handoffCheckpoint
		digest     s3disk.Digest
	}{
		{phase: publisherSessionRepositoryReady},
		{phase: publisherSessionJournalReady},
		{phase: publisherSessionInitialPublicationReady, checkpoint: &checkpoint},
		{phase: publisherSessionInitialRootReady, digest: handoffDigest},
		{phase: publisherSessionHandoffReady},
		{phase: publisherSessionCompleted},
	} {
		next, err := nextPublisherSession(current, step.phase, step.checkpoint, step.digest)
		if err != nil {
			t.Fatalf("advance to %s: %v", step.phase, err)
		}
		if err := validatePublisherSessionTransition(current, next); err != nil {
			t.Fatalf("validate transition to %s: %v", step.phase, err)
		}
		current = next
	}

	for name, mutate := range map[string]func(*publisherSession){
		"checkpoint too early": func(value *publisherSession) {
			checkpoint := testPublisherSessionCheckpoint()
			value.TrustedCheckpoint = &checkpoint
		},
		"digest too early": func(value *publisherSession) {
			value.HandoffDigest = handoffDigest.String()
		},
		"completed continuous": func(value *publisherSession) {
			value.Once = false
			value.Phase = publisherSessionCompleted
			value.Sequence = 7
			checkpoint := testPublisherSessionCheckpoint()
			value.TrustedCheckpoint = &checkpoint
			value.HandoffDigest = handoffDigest.String()
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := clonePublisherSession(prepared)
			mutate(&candidate)
			if err := validatePublisherSession(candidate); !errors.Is(err, ErrInvalidPublisherSession) {
				t.Fatalf("validation error = %v, want ErrInvalidPublisherSession", err)
			}
		})
	}
	for name, mutate := range map[string]func(*publisherSession){
		"skip phase": func(value *publisherSession) {
			value.Phase = publisherSessionJournalReady
			value.Sequence = 3
		},
		"change bucket": func(value *publisherSession) {
			value.Phase = publisherSessionRepositoryReady
			value.Sequence = 2
			value.Bucket = "other"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := clonePublisherSession(prepared)
			mutate(&candidate)
			if err := validatePublisherSessionTransition(prepared, candidate); !errors.Is(err, ErrInvalidPublisherSession) {
				t.Fatalf("transition error = %v, want ErrInvalidPublisherSession", err)
			}
		})
	}
}

func TestPublisherSessionSealedStoresEncryptAndSeparateRolesAndShares(t *testing.T) {
	requirePublisherSessionSealedState(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	session := newTestPublisherSession(t, now)
	shareID, err := presignedshare.ParseShareID(session.ShareID)
	if err != nil {
		t.Fatal(err)
	}
	repositoryID, err := s3disk.ParseRepositoryID(session.RepositoryID)
	if err != nil {
		t.Fatal(err)
	}
	material := newTestRecoveryKeyMaterial(t)
	session.RecoveryKeyID = material.keyID
	directory := t.TempDir()
	stores, err := newPublisherRecoveryStores(directory, repositoryID, shareID, material)
	if err != nil {
		t.Fatal(err)
	}
	created, err := createPublisherSession(ctx, stores.session, session, now)
	if err != nil {
		t.Fatal(err)
	}
	if created.state.Phase != publisherSessionPrepared || created.revision.IsZero() {
		t.Fatalf("unexpected created session: %#v", created)
	}

	raw, err := os.ReadFile(filepath.Join(directory, publisherSessionFileName))
	if err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range [][]byte{
		session.RootBearer, []byte(session.ClientEncryptionKey), session.ReferencePrivateSeed,
		[]byte(base64.StdEncoding.EncodeToString(session.RootBearer)),
		[]byte(base64.StdEncoding.EncodeToString(session.ReferencePrivateSeed)),
		session.SourcePath, []byte(base64.StdEncoding.EncodeToString(session.SourcePath)),
		session.HandoffPath, []byte(base64.StdEncoding.EncodeToString(session.HandoffPath)),
		[]byte("secret_access_key"), []byte("credential_provider"),
	} {
		if len(plaintext) > 0 && bytes.Contains(raw, plaintext) {
			t.Fatalf("sealed session contains plaintext %q", plaintext)
		}
	}
	if json.Valid(raw) {
		t.Fatal("sealed session unexpectedly exposes a plaintext JSON object")
	}
	sameDirectory := t.TempDir()
	sameStores, err := newPublisherRecoveryStores(sameDirectory, repositoryID, shareID, material)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := createPublisherSession(ctx, sameStores.session, session, now); err != nil {
		t.Fatal(err)
	}
	sameRaw, err := os.ReadFile(filepath.Join(sameDirectory, publisherSessionFileName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(raw, sameRaw) {
		t.Fatal("sealing identical session plaintext twice produced identical ciphertext")
	}

	if _, err := stores.root.CompareAndSwap(ctx, nil, []byte("root recovery witness")); err != nil {
		t.Fatal(err)
	}
	rootRaw, err := os.ReadFile(filepath.Join(directory, rootRecoveryFileName))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, rootRecoveryFileName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := stores.root.Load(ctx); !errors.Is(err, publisherstate.ErrAuthenticationFailed) {
		t.Fatalf("cross-role substitution error = %v, want authentication failure", err)
	}

	otherShareID, err := presignedshare.GenerateShareID()
	if err != nil {
		t.Fatal(err)
	}
	otherDirectory := t.TempDir()
	otherStores, err := newPublisherRecoveryStores(otherDirectory, repositoryID, otherShareID, material)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(otherDirectory, publisherSessionFileName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := otherStores.session.Load(ctx); !errors.Is(err, publisherstate.ErrAuthenticationFailed) {
		t.Fatalf("cross-share substitution error = %v, want authentication failure", err)
	}
	otherRepositoryID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	otherRootDirectory := t.TempDir()
	otherRoot, err := newRootRecoverySealedStore(otherRootDirectory, otherRepositoryID, shareID, material)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(otherRootDirectory, rootRecoveryFileName), rootRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := otherRoot.Load(ctx); !errors.Is(err, publisherstate.ErrAuthenticationFailed) {
		t.Fatalf("cross-repository root substitution error = %v, want authentication failure", err)
	}

	wrong := newTestRecoveryKeyMaterial(t)
	wrong.keyID = material.keyID
	wrongStores, err := newPublisherRecoveryStores(directory, repositoryID, shareID, wrong)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := wrongStores.session.Load(ctx); !errors.Is(err, publisherstate.ErrAuthenticationFailed) {
		t.Fatalf("wrong-key error = %v, want authentication failure", err)
	}
}

func TestPublisherSessionCASLostResponseReconcilesExactState(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	state := newTestPublisherSession(t, now)
	rawStore := &publisherSessionMemoryStore{loseNextResponse: true}
	store := newTestPublisherSessionStore(t, rawStore, state)
	created, err := createPublisherSession(context.Background(), store, state, now)
	if err != nil {
		t.Fatal(err)
	}
	if rawStore.compareAndSwaps != 1 || rawStore.loads != 1 || created.revision.IsZero() {
		t.Fatalf("create did not reconcile one lost response: %+v", rawStore)
	}

	rawStore.loseNextResponse = true
	advanced, err := advancePublisherSession(
		context.Background(), store, created, publisherSessionRepositoryReady,
		nil, s3disk.Digest{}, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if advanced.state.Phase != publisherSessionRepositoryReady || advanced.state.Sequence != 2 ||
		rawStore.compareAndSwaps != 2 || rawStore.loads != 2 {
		t.Fatalf("advance did not reconcile exact state: state=%#v store=%+v", advanced.state, rawStore)
	}
}

func TestPublisherSessionCASRejectsDivergentWinner(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	state := newTestPublisherSession(t, now)
	rawStore := &publisherSessionMemoryStore{}
	store := newTestPublisherSessionStore(t, rawStore, state)
	created, err := createPublisherSession(context.Background(), store, state, now)
	if err != nil {
		t.Fatal(err)
	}
	rawStore.beforeCAS = func(store *publisherSessionMemoryStore) {
		winner := clonePublisherSession(state)
		winner.Phase = publisherSessionRepositoryReady
		winner.Sequence = 2
		winner.Bucket = "divergent-winner"
		encoded, encodeErr := encodePublisherSessionUnchecked(winner)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		store.install(encoded)
	}
	if _, err := advancePublisherSession(
		context.Background(), store, created, publisherSessionRepositoryReady,
		nil, s3disk.Digest{}, now,
	); !errors.Is(err, ErrPublisherSessionConflict) || !errors.Is(err, s3disk.ErrPrecondition) {
		t.Fatalf("advance error = %v, want session conflict and precondition", err)
	}
}

func TestPublisherSessionRejectsMutatedLoadedStateBeforeCAS(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	state := newTestPublisherSession(t, now)
	rawStore := &publisherSessionMemoryStore{}
	store := newTestPublisherSessionStore(t, rawStore, state)
	created, err := createPublisherSession(context.Background(), store, state, now)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*publisherSession){
		"bucket": func(value *publisherSession) { value.Bucket = "other-valid-bucket" },
		"root key": func(value *publisherSession) {
			value.RootKey = strings.TrimSuffix(value.RootKey, "A") + "B"
		},
		"expiry": func(value *publisherSession) {
			value.AuthorizationExpiresAt = value.AuthorizationExpiresAt.Add(time.Minute)
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := created
			mutated.state = clonePublisherSession(created.state)
			mutate(&mutated.state)
			before := rawStore.compareAndSwaps
			if _, err := advancePublisherSession(
				context.Background(), store, mutated, publisherSessionRepositoryReady,
				nil, s3disk.Digest{}, now,
			); !errors.Is(err, ErrInvalidPublisherSession) {
				t.Fatalf("advance error = %v, want ErrInvalidPublisherSession", err)
			}
			if rawStore.compareAndSwaps != before {
				t.Fatalf("mutated state reached CAS: before=%d after=%d", before, rawStore.compareAndSwaps)
			}
		})
	}
	newer, err := advancePublisherSession(
		context.Background(), store, created, publisherSessionRepositoryReady,
		nil, s3disk.Digest{}, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	staleStateNewRevision := created
	staleStateNewRevision.revision = newer.revision
	before := rawStore.compareAndSwaps
	if _, err := advancePublisherSession(
		context.Background(), store, staleStateNewRevision, publisherSessionRepositoryReady,
		nil, s3disk.Digest{}, now,
	); !errors.Is(err, ErrInvalidPublisherSession) {
		t.Fatalf("mixed state/revision error = %v, want ErrInvalidPublisherSession", err)
	}
	if rawStore.compareAndSwaps != before {
		t.Fatalf("mixed state/revision reached CAS: before=%d after=%d", before, rawStore.compareAndSwaps)
	}
}

func TestPublisherSessionPostCASCancellationStopsContinuation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	state := newTestPublisherSession(t, now)
	rawStore := &publisherSessionMemoryStore{}
	store := newTestPublisherSessionStore(t, rawStore, state)
	ctx, cancel := context.WithCancel(context.Background())
	rawStore.beforeCAS = func(*publisherSessionMemoryStore) { cancel() }
	if _, err := createPublisherSession(ctx, store, state, now); !errors.Is(err, context.Canceled) {
		t.Fatalf("create error = %v, want context.Canceled", err)
	}
	if rawStore.compareAndSwaps != 1 || rawStore.revision.IsZero() {
		t.Fatalf("ignored-context CAS was not durably applied for later resume: %+v", rawStore)
	}
}

func TestPublisherSessionCancellationAndIdentityFailBeforeCAS(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	state := newTestPublisherSession(t, now)
	rawStore := &publisherSessionMemoryStore{}
	store := newTestPublisherSessionStore(t, rawStore, state)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := createPublisherSession(canceled, store, state, now); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled create error = %v", err)
	}
	if rawStore.loads != 0 || rawStore.compareAndSwaps != 0 {
		t.Fatalf("pre-canceled create performed I/O: %+v", rawStore)
	}
	state.RecoveryKeyID = "rk1.different"
	if _, err := createPublisherSession(context.Background(), store, state, now); !errors.Is(err, ErrInvalidPublisherSession) {
		t.Fatalf("identity mismatch error = %v", err)
	}
	if rawStore.loads != 0 || rawStore.compareAndSwaps != 0 {
		t.Fatalf("identity mismatch performed I/O: %+v", rawStore)
	}
}

func TestLoadPublisherSessionReportsExpiryAfterAuthenticatedLocalRead(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	state := newTestPublisherSession(t, now)
	rawStore := &publisherSessionMemoryStore{}
	store := newTestPublisherSessionStore(t, rawStore, state)
	encoded, err := encodePublisherSession(state)
	if err != nil {
		t.Fatal(err)
	}
	rawStore.install(encoded)
	if _, found, err := loadPublisherSession(context.Background(), store, state.AuthorizationExpiresAt); found ||
		!errors.Is(err, ErrPublisherSessionExpired) {
		t.Fatalf("expired load = (found=%t, err=%v)", found, err)
	}
	if rawStore.loads != 1 || rawStore.compareAndSwaps != 0 {
		t.Fatalf("expired load performed unexpected local I/O: %+v", rawStore)
	}
}

func TestPublisherSessionRequireActiveIsOfflineAndFixedExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	state := newTestPublisherSession(t, now)
	capability, err := state.RequireActive(now.Add(time.Minute))
	if err != nil || !capability.ExpiresAt().Equal(state.AuthorizationExpiresAt) {
		t.Fatalf("RequireActive = (%v, %v)", capability, err)
	}
	if _, err := state.RequireActive(state.AuthorizationExpiresAt); !errors.Is(err, ErrPublisherSessionExpired) {
		t.Fatalf("expiry error = %v, want ErrPublisherSessionExpired", err)
	}
	if _, err := state.RequireActive(state.CreatedAt.Add(-time.Second)); !errors.Is(err, ErrInvalidPublisherSession) {
		t.Fatalf("clock rollback error = %v, want ErrInvalidPublisherSession", err)
	}
}

func TestPublisherSessionPreservesNonUTF8PathBytes(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("Windows paths are Unicode strings")
	}
	now := time.Now().UTC().Truncate(time.Second)
	state := newTestPublisherSession(t, now)
	state.SourcePath = []byte{'/', 't', 'm', 'p', '/', 0xff, 's'}
	state.HandoffPath = []byte{'/', 't', 'm', 'p', '/', 0xfe, 'h'}
	state.SelectedPaths = [][]byte{{0xfd, 'a'}}
	state.SelectAll = false
	encoded, err := encodePublisherSession(state)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodePublisherSession(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.SourcePath, state.SourcePath) || !bytes.Equal(decoded.HandoffPath, state.HandoffPath) ||
		len(decoded.SelectedPaths) != 1 || !bytes.Equal(decoded.SelectedPaths[0], state.SelectedPaths[0]) {
		t.Fatal("publisher session changed non-UTF-8 path bytes")
	}
}

func TestPublisherSessionTwoStageResumeBootstrap(t *testing.T) {
	requirePublisherSessionSealedState(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	state := newTestPublisherSession(t, now)
	shareID, err := presignedshare.ParseShareID(state.ShareID)
	if err != nil {
		t.Fatal(err)
	}
	repositoryID, err := s3disk.ParseRepositoryID(state.RepositoryID)
	if err != nil {
		t.Fatal(err)
	}
	material := newTestRecoveryKeyMaterial(t)
	state.RecoveryKeyID = material.keyID
	directory := t.TempDir()
	fresh, err := newPublisherRecoveryStores(directory, repositoryID, shareID, material)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := createPublisherSession(ctx, fresh.session, state, now); err != nil {
		t.Fatal(err)
	}
	rootWitness := []byte("prepared-root-recovery-witness")
	if _, err := fresh.root.CompareAndSwap(ctx, nil, rootWitness); err != nil {
		t.Fatal(err)
	}

	// Resume knows only its recovery key and canonical share ID until the
	// session has authenticated. Repository identity is learned from that
	// manifest and only then enters the stronger root-WAL binding.
	resumedSessionStore, err := newPublisherSessionSealedStore(directory, shareID, material)
	if err != nil {
		t.Fatal(err)
	}
	loaded, found, err := loadPublisherSession(ctx, resumedSessionStore, now)
	if err != nil || !found {
		t.Fatalf("load session = (found=%t, err=%v)", found, err)
	}
	resumedRepositoryID, err := s3disk.ParseRepositoryID(loaded.state.RepositoryID)
	if err != nil {
		t.Fatal(err)
	}
	resumedRootStore, err := newRootRecoverySealedStore(directory, resumedRepositoryID, shareID, material)
	if err != nil {
		t.Fatal(err)
	}
	got, _, found, err := resumedRootStore.Load(ctx)
	if err != nil || !found || !bytes.Equal(got, rootWitness) {
		t.Fatalf("load root witness = (%q, found=%t, err=%v)", got, found, err)
	}
}

func TestPublisherSessionCompleteFileReplayAuthenticatesOnlyAsPhaseHint(t *testing.T) {
	requirePublisherSessionSealedState(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	state := newTestPublisherSession(t, now)
	shareID, err := presignedshare.ParseShareID(state.ShareID)
	if err != nil {
		t.Fatal(err)
	}
	material := newTestRecoveryKeyMaterial(t)
	state.RecoveryKeyID = material.keyID
	directory := t.TempDir()
	store, err := newPublisherSessionSealedStore(directory, shareID, material)
	if err != nil {
		t.Fatal(err)
	}
	created, err := createPublisherSession(ctx, store, state, now)
	if err != nil {
		t.Fatal(err)
	}
	oldFile, err := os.ReadFile(filepath.Join(directory, publisherSessionFileName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := advancePublisherSession(
		ctx, store, created, publisherSessionRepositoryReady, nil, s3disk.Digest{}, now,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, publisherSessionFileName), oldFile, 0o600); err != nil {
		t.Fatal(err)
	}
	replayed, found, err := loadPublisherSession(ctx, store, now)
	if err != nil || !found {
		t.Fatalf("load replayed session = (found=%t, err=%v)", found, err)
	}
	if replayed.state.Phase != publisherSessionPrepared {
		t.Fatalf("replayed phase = %q, want prepared", replayed.state.Phase)
	}
	// This deliberately records the FileSealedStateStore boundary: a complete
	// old file authenticates. Resume must treat the phase as a hint and prove
	// current repository, publication-journal, and root-WAL state independently.
}

func newTestPublisherSession(t *testing.T, now time.Time) publisherSession {
	t.Helper()
	repositoryID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	shareID, err := presignedshare.GenerateShareID()
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := s3disk.GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	prefix := "tenant/project"
	repositoryPrefix := prefix + "/shares/" + shareID.String()
	rootNonce := make([]byte, 32)
	if _, err := rand.Read(rootNonce); err != nil {
		t.Fatal(err)
	}
	rootKey := repositoryPrefix + "/share-root/" + base64.RawURLEncoding.EncodeToString(rootNonce)
	expiresAt := now.Add(time.Hour)
	root, err := presignedshare.DangerouslyNewUncheckedCapability(
		rootKey, "http://127.0.0.1:9000/bucket/"+rootKey+"?X-Amz-Signature=publisher-session-secret",
		nil, expiresAt, presignedshare.CapabilityOptions{AllowInsecureLoopback: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	bearer, err := root.DangerouslyExportUncheckedBearer()
	if err != nil {
		t.Fatal(err)
	}
	return publisherSession{
		Format: publisherSessionFormat, Profile: publisherSessionProfile,
		Sequence: 1, Phase: publisherSessionPrepared,
		CreatedAt: now, AuthorizationExpiresAt: expiresAt,
		ShareID: shareID.String(), RepositoryID: repositoryID.String(), RecoveryKeyID: "rk1.test",
		SourcePath: []byte(filepath.Join(t.TempDir(), "source")), SelectAll: true, SelectedPaths: [][]byte{}, Once: true,
		Bucket: "bucket", Prefix: prefix, Region: "us-east-1",
		Endpoint: "http://127.0.0.1:9000", UsePathStyle: true, AllowInsecureEndpoint: true,
		RepositoryPrefix: repositoryPrefix, Channel: "main",
		ReferenceKey:   repositoryPrefix + "/.s3disk/v1/signed-refs/v1/bWFpbg",
		ReferenceKeyID: "share-key-1", ReferencePrivateSeed: bytes.Clone(privateKey.Seed()),
		RootKey: rootKey, RootBearer: bearer, ClientEncryptionKey: clientKey.ExportSecret(),
		HandoffPath: []byte(filepath.Join(t.TempDir(), "share.handoff")),
	}
}

func testPublisherSessionCheckpoint() handoffCheckpoint {
	var commit s3disk.Digest
	commit[0] = 1
	return handoffCheckpoint{Generation: 1, Commit: commit.String()}
}

func newTestRecoveryKeyMaterial(t *testing.T) recoveryKeyMaterial {
	t.Helper()
	key, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	return recoveryKeyMaterial{keyID: deriveRecoveryKeyID(key.ExportSecret()), key: key}
}

func newTestPublisherSessionStore(
	t *testing.T,
	raw s3disk.SealedStateStore,
	state publisherSession,
) *publisherSessionStore {
	t.Helper()
	shareID, err := presignedshare.ParseShareID(state.ShareID)
	if err != nil {
		t.Fatal(err)
	}
	return &publisherSessionStore{raw: raw, shareID: shareID, recoveryKeyID: state.RecoveryKeyID}
}

func requirePublisherSessionSealedState(t *testing.T) {
	t.Helper()
	if err := s3disk.ValidatePrivateSecretDirectory(t.TempDir()); err != nil {
		if errors.Is(err, s3disk.ErrTrustStateUnsupported) {
			t.Skipf("sealed publisher state is unsupported: %v", err)
		}
		t.Fatalf("validate private publisher-state directory: %v", err)
	}
}

type publisherSessionMemoryStore struct {
	state            []byte
	revision         s3disk.SealedStateRevision
	revisionCounter  byte
	loads            int
	compareAndSwaps  int
	loseNextResponse bool
	beforeCAS        func(*publisherSessionMemoryStore)
}

func (store *publisherSessionMemoryStore) Load(context.Context) ([]byte, s3disk.SealedStateRevision, bool, error) {
	store.loads++
	if store.revision.IsZero() {
		return nil, s3disk.SealedStateRevision{}, false, nil
	}
	return bytes.Clone(store.state), store.revision, true, nil
}

func (store *publisherSessionMemoryStore) CompareAndSwap(
	_ context.Context,
	expected *s3disk.SealedStateRevision,
	next []byte,
) (s3disk.SealedStateRevision, error) {
	store.compareAndSwaps++
	if store.beforeCAS != nil {
		before := store.beforeCAS
		store.beforeCAS = nil
		before(store)
	}
	if expected == nil {
		if !store.revision.IsZero() {
			return s3disk.SealedStateRevision{}, s3disk.ErrPrecondition
		}
	} else if store.revision.IsZero() || store.revision != *expected {
		return s3disk.SealedStateRevision{}, s3disk.ErrPrecondition
	}
	store.install(next)
	if store.loseNextResponse {
		store.loseNextResponse = false
		return store.revision, errors.New("injected response loss")
	}
	return store.revision, nil
}

func (store *publisherSessionMemoryStore) install(next []byte) {
	store.revisionCounter++
	if store.revisionCounter == 0 {
		store.revisionCounter++
	}
	store.revision = s3disk.SealedStateRevision{}
	store.revision[0] = store.revisionCounter
	store.state = bytes.Clone(next)
}

func FuzzDecodePublisherSessionNeverPanics(f *testing.F) {
	f.Add([]byte("{}\n"))
	f.Add([]byte("not-json"))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		_, _ = decodePublisherSession(encoded)
	})
}
