package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/presignedshare"
	"github.com/vibe-agi/s3disk/publisherstate"
)

const (
	publisherSessionFormat  = 1
	publisherSessionProfile = "strict-s3-only-publisher-session-v1"

	// The session contains a bounded TLS CA, bearer, and byte-preserving source
	// selection. It is intentionally much smaller than the root recovery WAL.
	maximumPublisherSessionBytes             int64 = 8 << 20
	maximumPublisherSessionEnvelopeBytes     int64 = maximumPublisherSessionBytes + (1 << 20)
	maximumPublisherSessionPathBytes               = 64 << 10
	maximumPublisherSessionSelectedPathBytes       = 1 << 20
	maximumPublisherSessionSelectedPaths           = presignedshare.MaximumBundleCapabilities
	maximumPublisherSessionEndpointBytes           = 16 << 10

	publisherSessionFileName = "session.sealed"
	rootRecoveryFileName     = "root-recovery.sealed"

	publisherSessionRole = "session-manifest"
	rootRecoveryRole     = "root-recovery-journal"
)

var (
	ErrInvalidPublisherSession       = errors.New("s3disk: invalid publisher session")
	ErrPublisherSessionNotFound      = errors.New("s3disk: publisher session not found")
	ErrPublisherSessionConflict      = errors.New("s3disk: publisher session conflict")
	ErrPublisherSessionIndeterminate = errors.New("s3disk: publisher session update is indeterminate")
	ErrPublisherSessionExpired       = errors.New("s3disk: publisher session expired")

	publisherStateBindingDomain  = []byte("s3disk\x00cli\x00publisher-state-binding\x00v1\x00")
	publisherSessionDigestDomain = []byte("s3disk\x00cli\x00publisher-session-authenticated-revision\x00v1\x00")
)

type publisherSessionPhase string

const (
	publisherSessionPrepared                publisherSessionPhase = "prepared"
	publisherSessionRepositoryReady         publisherSessionPhase = "repository_ready"
	publisherSessionJournalReady            publisherSessionPhase = "journal_ready"
	publisherSessionInitialPublicationReady publisherSessionPhase = "initial_publication_ready"
	publisherSessionInitialRootReady        publisherSessionPhase = "initial_root_ready"
	publisherSessionHandoffReady            publisherSessionPhase = "handoff_ready"
	publisherSessionCompleted               publisherSessionPhase = "completed"
)

// publisherSession is the authenticated A-side restart manifest. Paths are
// byte slices so Linux filenames which are not UTF-8 survive JSON's canonical
// base64 representation without replacement. It deliberately contains no S3
// SecretAccessKey, session credential, credential provider, SDK config, HTTP
// client, or cache object. Recovery resolves A's current credentials anew.
// Phases route idempotent recovery work; they are not proof that S3 or either
// journal is current. Resume must reconcile the authoritative repository,
// publication journal, and root WAL even when a later phase is present.
type publisherSession struct {
	Format                 int                   `json:"format"`
	Profile                string                `json:"profile"`
	Sequence               uint64                `json:"sequence"`
	Phase                  publisherSessionPhase `json:"phase"`
	CreatedAt              time.Time             `json:"created_at"`
	AuthorizationExpiresAt time.Time             `json:"authorization_expires_at"`
	ShareID                string                `json:"share_id"`
	RepositoryID           string                `json:"repository_id"`
	RecoveryKeyID          string                `json:"recovery_key_id"`

	SourcePath    []byte   `json:"source_path"`
	SelectAll     bool     `json:"select_all"`
	SelectedPaths [][]byte `json:"selected_paths"`
	Once          bool     `json:"once"`
	HandoffPath   []byte   `json:"handoff_path"`

	Bucket                string `json:"bucket"`
	Prefix                string `json:"prefix"`
	Region                string `json:"region"`
	Endpoint              string `json:"endpoint,omitempty"`
	ExpectedBucketOwner   string `json:"expected_bucket_owner,omitempty"`
	UsePathStyle          bool   `json:"use_path_style"`
	AllowInsecureEndpoint bool   `json:"allow_insecure_endpoint"`
	TLSRootCAPEM          []byte `json:"tls_root_ca_pem"`

	RepositoryPrefix     string `json:"repository_prefix"`
	Channel              string `json:"channel"`
	ReferenceKey         string `json:"reference_key"`
	ReferenceKeyID       string `json:"reference_key_id"`
	ReferencePrivateSeed []byte `json:"reference_private_seed"`
	RootKey              string `json:"root_key"`
	RootBearer           []byte `json:"root_bearer"`
	ClientEncryptionKey  string `json:"client_encryption_key"`

	TrustedCheckpoint *handoffCheckpoint `json:"trusted_checkpoint,omitempty"`
	HandoffDigest     string             `json:"handoff_digest,omitempty"`
}

func (value publisherSession) String() string {
	return fmt.Sprintf(
		"s3disk.publisherSession{format:%d,profile:%q,phase:%q,sequence:%d,share_id:%q,expires_at:%s,secrets_and_paths:redacted}",
		value.Format, value.Profile, value.Phase, value.Sequence, value.ShareID,
		value.AuthorizationExpiresAt.Format(time.RFC3339Nano),
	)
}

func (value publisherSession) GoString() string { return value.String() }

// MarshalJSON is diagnostic-only and intentionally redacted. The narrowly
// scoped codec below converts through publisherSessionWire when it must persist
// the encrypted plaintext. This makes accidental generic JSON logging safe.
func (value publisherSession) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Format   int                   `json:"format"`
		Profile  string                `json:"profile"`
		Sequence uint64                `json:"sequence"`
		Phase    publisherSessionPhase `json:"phase"`
		ShareID  string                `json:"share_id"`
		Expires  time.Time             `json:"authorization_expires_at"`
		Secrets  string                `json:"secrets_and_paths"`
	}{
		Format: value.Format, Profile: value.Profile, Sequence: value.Sequence,
		Phase: value.Phase, ShareID: value.ShareID, Expires: value.AuthorizationExpiresAt,
		Secrets: "redacted",
	})
}

type publisherSessionWire publisherSession

type loadedPublisherSession struct {
	state               publisherSession
	revision            s3disk.SealedStateRevision
	authenticatedDigest s3disk.Digest
}

func (value loadedPublisherSession) String() string {
	return fmt.Sprintf("s3disk.loadedPublisherSession{state:%s,revision_present:%t}", value.state, !value.revision.IsZero())
}

func (value loadedPublisherSession) GoString() string { return value.String() }

type publisherSessionStore struct {
	raw           s3disk.SealedStateStore
	shareID       presignedshare.ShareID
	recoveryKeyID string
}

func (store *publisherSessionStore) Load(ctx context.Context) ([]byte, s3disk.SealedStateRevision, bool, error) {
	if store == nil || !publisherSessionDependencyConfigured(store.raw) {
		return nil, s3disk.SealedStateRevision{}, false, fmt.Errorf("%w: session store is not configured", ErrInvalidPublisherSession)
	}
	return store.raw.Load(ctx)
}

func (store *publisherSessionStore) CompareAndSwap(
	ctx context.Context,
	expected *s3disk.SealedStateRevision,
	next []byte,
) (s3disk.SealedStateRevision, error) {
	if store == nil || !publisherSessionDependencyConfigured(store.raw) {
		return s3disk.SealedStateRevision{}, fmt.Errorf("%w: session store is not configured", ErrInvalidPublisherSession)
	}
	return store.raw.CompareAndSwap(ctx, expected, next)
}

type publisherRecoveryStores struct {
	session *publisherSessionStore
	root    s3disk.SealedStateStore
}

func newPublisherRecoveryStores(
	shareDirectory string,
	repositoryID s3disk.RepositoryID,
	shareID presignedshare.ShareID,
	material recoveryKeyMaterial,
) (publisherRecoveryStores, error) {
	if shareDirectory == "" || repositoryID.IsZero() || shareID.IsZero() || material.keyID == "" {
		return publisherRecoveryStores{}, fmt.Errorf("%w: recovery store identity is incomplete", ErrInvalidPublisherSession)
	}
	session, err := newPublisherSessionSealedStore(shareDirectory, shareID, material)
	if err != nil {
		return publisherRecoveryStores{}, err
	}
	root, err := newRootRecoverySealedStore(shareDirectory, repositoryID, shareID, material)
	if err != nil {
		return publisherRecoveryStores{}, err
	}
	return publisherRecoveryStores{session: session, root: root}, nil
}

func newPublisherSessionSealedStore(
	shareDirectory string,
	shareID presignedshare.ShareID,
	material recoveryKeyMaterial,
) (*publisherSessionStore, error) {
	if shareDirectory == "" || shareID.IsZero() || material.keyID == "" {
		return nil, fmt.Errorf("%w: session store identity is incomplete", ErrInvalidPublisherSession)
	}
	protector, err := publisherstate.NewAESGCMProtector(material.keyID, material.key)
	if err != nil {
		return nil, fmt.Errorf("s3disk: create publisher recovery protector: %w", err)
	}
	sessionBinding, err := publisherStateBinding(publisherSessionRole, s3disk.RepositoryID{}, shareID)
	if err != nil {
		return nil, err
	}
	sessionRaw, err := s3disk.NewFileSealedStateStore(
		filepath.Join(shareDirectory, publisherSessionFileName),
		s3disk.FileSealedStateStoreOptions{
			Protector: protector, Binding: sessionBinding,
			MaxEnvelopeBytes: maximumPublisherSessionEnvelopeBytes,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("s3disk: create sealed publisher session store: %w", err)
	}
	return &publisherSessionStore{raw: sessionRaw, shareID: shareID, recoveryKeyID: material.keyID}, nil
}

func newRootRecoverySealedStore(
	shareDirectory string,
	repositoryID s3disk.RepositoryID,
	shareID presignedshare.ShareID,
	material recoveryKeyMaterial,
) (s3disk.SealedStateStore, error) {
	if shareDirectory == "" || repositoryID.IsZero() || shareID.IsZero() || material.keyID == "" {
		return nil, fmt.Errorf("%w: root recovery store identity is incomplete", ErrInvalidPublisherSession)
	}
	protector, err := publisherstate.NewAESGCMProtector(material.keyID, material.key)
	if err != nil {
		return nil, fmt.Errorf("s3disk: create root recovery protector: %w", err)
	}
	rootBinding, err := publisherStateBinding(rootRecoveryRole, repositoryID, shareID)
	if err != nil {
		return nil, err
	}
	root, err := s3disk.NewFileSealedStateStore(
		filepath.Join(shareDirectory, rootRecoveryFileName),
		s3disk.FileSealedStateStoreOptions{Protector: protector, Binding: rootBinding},
	)
	if err != nil {
		return nil, fmt.Errorf("s3disk: create sealed root recovery store: %w", err)
	}
	return root, nil
}

func publisherStateBinding(
	role string,
	repositoryID s3disk.RepositoryID,
	shareID presignedshare.ShareID,
) ([]byte, error) {
	if shareID.IsZero() ||
		(role == publisherSessionRole && !repositoryID.IsZero()) ||
		(role == rootRecoveryRole && repositoryID.IsZero()) ||
		(role != publisherSessionRole && role != rootRecoveryRole) {
		return nil, fmt.Errorf("%w: invalid publisher state binding", ErrInvalidPublisherSession)
	}
	repository := []byte(nil)
	if !repositoryID.IsZero() {
		repository = []byte(repositoryID.String())
	}
	share := []byte(shareID.String())
	binding := make([]byte, 0, len(publisherStateBindingDomain)+12+len(role)+len(repository)+len(share))
	binding = append(binding, publisherStateBindingDomain...)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(role)))
	binding = append(binding, length[:]...)
	binding = append(binding, role...)
	binary.BigEndian.PutUint32(length[:], uint32(len(repository)))
	binding = append(binding, length[:]...)
	binding = append(binding, repository...)
	binary.BigEndian.PutUint32(length[:], uint32(len(share)))
	binding = append(binding, length[:]...)
	binding = append(binding, share...)
	return binding, nil
}

func encodePublisherSession(value publisherSession) ([]byte, error) {
	if err := validatePublisherSession(value); err != nil {
		return nil, err
	}
	return encodePublisherSessionUnchecked(value)
}

func encodePublisherSessionUnchecked(value publisherSession) ([]byte, error) {
	encoded, err := json.Marshal(publisherSessionWire(value))
	if err != nil {
		return nil, fmt.Errorf("%w: encode canonical state", ErrInvalidPublisherSession)
	}
	if int64(len(encoded)+1) > maximumPublisherSessionBytes {
		clear(encoded)
		return nil, fmt.Errorf("%w: %w: state exceeds %d bytes", ErrInvalidPublisherSession, s3disk.ErrResourceLimit, maximumPublisherSessionBytes)
	}
	encoded = append(encoded, '\n')
	return encoded, nil
}

func decodePublisherSession(encoded []byte) (publisherSession, error) {
	if len(encoded) < 2 || int64(len(encoded)) > maximumPublisherSessionBytes {
		return publisherSession{}, fmt.Errorf("%w: %w: state size is invalid", ErrInvalidPublisherSession, s3disk.ErrResourceLimit)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire publisherSessionWire
	if err := decoder.Decode(&wire); err != nil {
		return publisherSession{}, fmt.Errorf("%w: malformed state", ErrInvalidPublisherSession)
	}
	value := publisherSession(wire)
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return publisherSession{}, fmt.Errorf("%w: trailing state value", ErrInvalidPublisherSession)
	}
	canonical, err := encodePublisherSession(value)
	if err != nil {
		return publisherSession{}, err
	}
	defer clear(canonical)
	if !bytes.Equal(encoded, canonical) {
		return publisherSession{}, fmt.Errorf("%w: state is not canonical", ErrInvalidPublisherSession)
	}
	return clonePublisherSession(value), nil
}

func validatePublisherSession(value publisherSession) error {
	fail := func(reason string) error {
		return fmt.Errorf("%w: %s", ErrInvalidPublisherSession, reason)
	}
	if value.Format != publisherSessionFormat || value.Profile != publisherSessionProfile {
		return fail("unsupported format or profile")
	}
	rank, ok := publisherSessionPhaseRank(value.Phase)
	if !ok || value.Sequence != uint64(rank) {
		return fail("invalid phase or sequence")
	}
	if !canonicalPublisherSessionTime(value.CreatedAt) || !canonicalPublisherSessionTime(value.AuthorizationExpiresAt) ||
		!value.AuthorizationExpiresAt.After(value.CreatedAt) ||
		value.AuthorizationExpiresAt.Sub(value.CreatedAt) > presignedshare.MaximumCapabilityLifetime {
		return fail("invalid fixed authorization window")
	}
	shareID, err := presignedshare.ParseShareID(value.ShareID)
	if err != nil {
		return fail("invalid share identity")
	}
	repositoryID, err := s3disk.ParseRepositoryID(value.RepositoryID)
	if err != nil || repositoryID.IsZero() {
		return fail("invalid repository identity")
	}
	if !validPublisherSessionKeyID(value.RecoveryKeyID) {
		return fail("invalid recovery key identity")
	}
	if err := validatePublisherSessionAbsolutePath(value.SourcePath); err != nil {
		return fail("invalid source path")
	}
	if err := validatePublisherSessionAbsolutePath(value.HandoffPath); err != nil {
		return fail("invalid handoff path")
	}
	if bytes.Equal(value.SourcePath, value.HandoffPath) {
		return fail("source and handoff paths collide")
	}
	if pathWithin(string(value.HandoffPath), string(value.SourcePath)) {
		return fail("handoff path is inside the source")
	}
	if value.SelectedPaths == nil || value.SelectAll == (len(value.SelectedPaths) > 0) {
		return fail("invalid source selection")
	}
	if len(value.SelectedPaths) > maximumPublisherSessionSelectedPaths {
		return fail("too many selected paths")
	}
	var selectedBytes int64
	var previous []byte
	for _, selected := range value.SelectedPaths {
		if len(selected) == 0 || len(selected) > maximumPublisherSessionPathBytes ||
			validateSelectedPath(string(selected)) != nil || bytes.IndexByte(selected, 0) >= 0 ||
			(previous != nil && bytes.Compare(previous, selected) >= 0) {
			return fail("invalid selected path")
		}
		selectedBytes += int64(len(selected))
		if selectedBytes > int64(maximumPublisherSessionSelectedPathBytes) {
			return fail("selected paths exceed their aggregate limit")
		}
		previous = selected
	}
	if validatePublisherSessionText(value.Bucket, 1024, false) != nil ||
		validatePublisherSessionText(value.Prefix, maximumHandoffPrefixBytes, false) != nil ||
		strings.Trim(value.Prefix, "/") != value.Prefix ||
		validatePublisherSessionText(value.Region, 256, false) != nil ||
		validatePublisherSessionText(value.Endpoint, maximumPublisherSessionEndpointBytes, true) != nil ||
		validatePublisherSessionText(value.ExpectedBucketOwner, 256, true) != nil {
		return fail("invalid S3 configuration")
	}
	if len(value.TLSRootCAPEM) > int(presignedshare.MaximumTLSRootCAPEMBytes) {
		return fail("TLS CA exceeds its limit")
	}
	if _, err := s3HTTPClient(value.TLSRootCAPEM); err != nil {
		return fail("invalid TLS CA")
	}
	if err := validateStrictShareEndpointTrust(value.Endpoint, value.AllowInsecureEndpoint, len(value.TLSRootCAPEM) > 0); err != nil {
		return fail("invalid endpoint trust")
	}
	expectedRepositoryPrefix := value.Prefix + "/shares/" + shareID.String()
	if value.RepositoryPrefix != expectedRepositoryPrefix ||
		validateHandoffText(value.RepositoryPrefix, maximumHandoffPrefixBytes, false) != nil {
		return fail("invalid repository namespace")
	}
	if validateHandoffText(value.Channel, maximumHandoffChannelBytes, false) != nil ||
		!validPublisherSessionKeyID(value.ReferenceKeyID) {
		return fail("invalid reference identity")
	}
	expectedReferenceKey := value.RepositoryPrefix + "/.s3disk/v1/signed-refs/v1/" +
		base64.RawURLEncoding.EncodeToString([]byte(value.Channel))
	if value.ReferenceKey != expectedReferenceKey || validateHandoffText(value.ReferenceKey, 1024, false) != nil {
		return fail("invalid reference key")
	}
	if len(value.ReferencePrivateSeed) != ed25519.SeedSize {
		return fail("invalid reference signing seed")
	}
	rootPrefix := value.RepositoryPrefix + "/share-root/"
	if !strings.HasPrefix(value.RootKey, rootPrefix) || len(value.RootKey) > 1024 {
		return fail("invalid root key")
	}
	rootNonce := strings.TrimPrefix(value.RootKey, rootPrefix)
	decodedNonce, err := base64.RawURLEncoding.DecodeString(rootNonce)
	if err != nil || len(decodedNonce) != 32 || base64.RawURLEncoding.EncodeToString(decodedNonce) != rootNonce {
		clear(decodedNonce)
		return fail("invalid root namespace")
	}
	clear(decodedNonce)
	if len(value.RootBearer) < 1 || len(value.RootBearer) > presignedshare.MaximumBearerExportBytes {
		return fail("invalid root bearer size")
	}
	clientKey, err := s3disk.ParseClientEncryptionKey(value.ClientEncryptionKey)
	if err != nil {
		return fail("invalid client encryption key")
	}
	if _, err := s3disk.NewClientEncryptionProfile(repositoryID, clientKey); err != nil {
		return fail("invalid client encryption profile")
	}
	checkpointRequired := rank >= mustPublisherSessionPhaseRank(publisherSessionInitialPublicationReady)
	if checkpointRequired != (value.TrustedCheckpoint != nil) {
		return fail("checkpoint does not match phase")
	}
	if value.TrustedCheckpoint != nil {
		commit, err := s3disk.ParseDigest(value.TrustedCheckpoint.Commit)
		if err != nil || commit.IsZero() || value.TrustedCheckpoint.Generation == 0 ||
			commit.String() != value.TrustedCheckpoint.Commit {
			return fail("invalid trusted checkpoint")
		}
	}
	digestRequired := rank >= mustPublisherSessionPhaseRank(publisherSessionInitialRootReady)
	if digestRequired != (value.HandoffDigest != "") {
		return fail("handoff digest does not match phase")
	}
	if value.HandoffDigest != "" {
		digest, err := s3disk.ParseDigest(value.HandoffDigest)
		if err != nil || digest.IsZero() || digest.String() != value.HandoffDigest {
			return fail("invalid handoff digest")
		}
	}
	if value.Phase == publisherSessionCompleted && !value.Once {
		return fail("continuous session cannot be completed")
	}
	return nil
}

// RequireActive validates the clock-sensitive bearer entirely offline. It is
// deliberately separate from decoding so expired sessions remain available to
// diagnostics and GC. Call it before AWS credential resolution or S3 setup.
func (value publisherSession) RequireActive(now time.Time) (presignedshare.Capability, error) {
	if err := validatePublisherSession(value); err != nil {
		return presignedshare.Capability{}, err
	}
	if now.IsZero() || now.Before(value.CreatedAt) {
		return presignedshare.Capability{}, fmt.Errorf("%w: local clock precedes session creation", ErrInvalidPublisherSession)
	}
	if !value.AuthorizationExpiresAt.After(now) {
		return presignedshare.Capability{}, ErrPublisherSessionExpired
	}
	capability, err := presignedshare.ParseBearer(
		value.RootBearer,
		presignedshare.CapabilityOptions{AllowInsecureLoopback: value.AllowInsecureEndpoint},
	)
	if err != nil || !capability.ExpiresAt().Equal(value.AuthorizationExpiresAt) {
		return presignedshare.Capability{}, fmt.Errorf("%w: root bearer does not match the fixed authorization", ErrInvalidPublisherSession)
	}
	exported, err := capability.ExportBearer()
	if err != nil || !bytes.Equal(exported, value.RootBearer) {
		clear(exported)
		return presignedshare.Capability{}, fmt.Errorf("%w: root bearer is not canonical", ErrInvalidPublisherSession)
	}
	clear(exported)
	return capability, nil
}

func createPublisherSession(
	ctx context.Context,
	store *publisherSessionStore,
	state publisherSession,
	now time.Time,
) (loadedPublisherSession, error) {
	if ctx == nil {
		return loadedPublisherSession{}, fmt.Errorf("s3disk: create publisher session context is required")
	}
	if err := ctx.Err(); err != nil {
		return loadedPublisherSession{}, err
	}
	if err := validatePublisherSessionStoreIdentity(store, state); err != nil {
		return loadedPublisherSession{}, err
	}
	if _, err := state.RequireActive(now); err != nil {
		return loadedPublisherSession{}, err
	}
	encoded, err := encodePublisherSession(state)
	if err != nil {
		return loadedPublisherSession{}, err
	}
	defer clear(encoded)
	revision, casErr := store.CompareAndSwap(ctx, nil, encoded)
	if casErr == nil {
		if revision.IsZero() {
			return loadedPublisherSession{}, fmt.Errorf("%w: session store returned a zero revision", ErrPublisherSessionIndeterminate)
		}
		if err := publisherSessionPostWriteCheck(ctx, state); err != nil {
			return loadedPublisherSession{}, err
		}
		return loadedPublisherSession{
			state: clonePublisherSession(state), revision: revision,
			authenticatedDigest: publisherSessionAuthenticatedDigest(revision, encoded),
		}, nil
	}
	return reconcilePublisherSessionWrite(ctx, store, state, encoded, revision, casErr)
}

func loadPublisherSession(
	ctx context.Context,
	store *publisherSessionStore,
	now time.Time,
) (loadedPublisherSession, bool, error) {
	if ctx == nil {
		return loadedPublisherSession{}, false, fmt.Errorf("s3disk: load publisher session context is required")
	}
	if err := ctx.Err(); err != nil {
		return loadedPublisherSession{}, false, err
	}
	if store == nil || !publisherSessionDependencyConfigured(store.raw) {
		return loadedPublisherSession{}, false, fmt.Errorf("%w: session store is not configured", ErrInvalidPublisherSession)
	}
	encoded, revision, found, err := store.Load(ctx)
	if err != nil {
		clear(encoded)
		return loadedPublisherSession{}, false, fmt.Errorf("%w: load sealed state: %w", ErrInvalidPublisherSession, err)
	}
	defer clear(encoded)
	if err := ctx.Err(); err != nil {
		return loadedPublisherSession{}, false, err
	}
	if !found {
		return loadedPublisherSession{}, false, nil
	}
	if revision.IsZero() {
		return loadedPublisherSession{}, false, fmt.Errorf("%w: present state has a zero revision", ErrInvalidPublisherSession)
	}
	state, err := decodePublisherSession(encoded)
	if err != nil {
		return loadedPublisherSession{}, false, err
	}
	if err := validatePublisherSessionStoreIdentity(store, state); err != nil {
		return loadedPublisherSession{}, false, err
	}
	if !state.AuthorizationExpiresAt.After(time.Now()) {
		return loadedPublisherSession{}, false, ErrPublisherSessionExpired
	}
	if _, err := state.RequireActive(now); err != nil {
		return loadedPublisherSession{}, false, err
	}
	return loadedPublisherSession{
		state: state, revision: revision, authenticatedDigest: publisherSessionAuthenticatedDigest(revision, encoded),
	}, true, nil
}

func advancePublisherSession(
	ctx context.Context,
	store *publisherSessionStore,
	current loadedPublisherSession,
	phase publisherSessionPhase,
	checkpoint *handoffCheckpoint,
	handoffDigest s3disk.Digest,
	now time.Time,
) (loadedPublisherSession, error) {
	if ctx == nil {
		return loadedPublisherSession{}, fmt.Errorf("s3disk: advance publisher session context is required")
	}
	if err := ctx.Err(); err != nil {
		return loadedPublisherSession{}, err
	}
	if current.revision.IsZero() || current.authenticatedDigest.IsZero() {
		return loadedPublisherSession{}, fmt.Errorf("%w: current authenticated revision is absent", ErrInvalidPublisherSession)
	}
	if err := validatePublisherSessionStoreIdentity(store, current.state); err != nil {
		return loadedPublisherSession{}, err
	}
	currentBytes, err := encodePublisherSession(current.state)
	if err != nil {
		return loadedPublisherSession{}, err
	}
	if publisherSessionAuthenticatedDigest(current.revision, currentBytes) != current.authenticatedDigest {
		clear(currentBytes)
		return loadedPublisherSession{}, fmt.Errorf("%w: current state does not match its authenticated revision", ErrInvalidPublisherSession)
	}
	clear(currentBytes)
	next, err := nextPublisherSession(current.state, phase, checkpoint, handoffDigest)
	if err != nil {
		return loadedPublisherSession{}, err
	}
	if _, err := next.RequireActive(now); err != nil {
		return loadedPublisherSession{}, err
	}
	encoded, err := encodePublisherSession(next)
	if err != nil {
		return loadedPublisherSession{}, err
	}
	defer clear(encoded)
	expected := current.revision
	revision, casErr := store.CompareAndSwap(ctx, &expected, encoded)
	if casErr == nil {
		if revision.IsZero() {
			return loadedPublisherSession{}, fmt.Errorf("%w: session store returned a zero revision", ErrPublisherSessionIndeterminate)
		}
		if err := publisherSessionPostWriteCheck(ctx, next); err != nil {
			return loadedPublisherSession{}, err
		}
		return loadedPublisherSession{
			state: next, revision: revision, authenticatedDigest: publisherSessionAuthenticatedDigest(revision, encoded),
		}, nil
	}
	return reconcilePublisherSessionWrite(ctx, store, next, encoded, revision, casErr)
}

func reconcilePublisherSessionWrite(
	ctx context.Context,
	store *publisherSessionStore,
	desired publisherSession,
	desiredBytes []byte,
	candidate s3disk.SealedStateRevision,
	writeErr error,
) (loadedPublisherSession, error) {
	if ctx.Err() == nil {
		observed, revision, found, loadErr := store.Load(ctx)
		if loadErr == nil && found && !candidate.IsZero() && revision == candidate && bytes.Equal(observed, desiredBytes) {
			clear(observed)
			if err := publisherSessionPostWriteCheck(ctx, desired); err != nil {
				return loadedPublisherSession{}, err
			}
			return loadedPublisherSession{
				state: clonePublisherSession(desired), revision: revision,
				authenticatedDigest: publisherSessionAuthenticatedDigest(revision, desiredBytes),
			}, nil
		}
		clear(observed)
		if errors.Is(writeErr, s3disk.ErrPrecondition) {
			return loadedPublisherSession{}, errors.Join(ErrPublisherSessionConflict, s3disk.ErrPrecondition)
		}
		if loadErr != nil {
			return loadedPublisherSession{}, errors.Join(ErrPublisherSessionIndeterminate, writeErr, loadErr)
		}
	} else if errors.Is(writeErr, s3disk.ErrPrecondition) {
		return loadedPublisherSession{}, errors.Join(ErrPublisherSessionConflict, s3disk.ErrPrecondition)
	}
	return loadedPublisherSession{}, errors.Join(ErrPublisherSessionIndeterminate, writeErr, ctx.Err())
}

func publisherSessionPostWriteCheck(ctx context.Context, state publisherSession) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !state.AuthorizationExpiresAt.After(time.Now()) {
		return ErrPublisherSessionExpired
	}
	return nil
}

func publisherSessionAuthenticatedDigest(revision s3disk.SealedStateRevision, encoded []byte) s3disk.Digest {
	hash := sha256.New()
	_, _ = hash.Write(publisherSessionDigestDomain)
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(revision)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(revision[:])
	binary.BigEndian.PutUint64(length[:], uint64(len(encoded)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(encoded)
	sum := hash.Sum(nil)
	var digest s3disk.Digest
	copy(digest[:], sum)
	clear(sum)
	return digest
}

func nextPublisherSession(
	current publisherSession,
	phase publisherSessionPhase,
	checkpoint *handoffCheckpoint,
	handoffDigest s3disk.Digest,
) (publisherSession, error) {
	if err := validatePublisherSession(current); err != nil {
		return publisherSession{}, err
	}
	currentRank, _ := publisherSessionPhaseRank(current.Phase)
	nextRank, ok := publisherSessionPhaseRank(phase)
	if !ok || nextRank != currentRank+1 {
		return publisherSession{}, fmt.Errorf("%w: phase must advance by exactly one step", ErrInvalidPublisherSession)
	}
	next := clonePublisherSession(current)
	next.Phase = phase
	next.Sequence = uint64(nextRank)
	switch phase {
	case publisherSessionInitialPublicationReady:
		if checkpoint == nil || handoffDigest != (s3disk.Digest{}) {
			return publisherSession{}, fmt.Errorf("%w: initial publication requires only a checkpoint", ErrInvalidPublisherSession)
		}
		cloned := *checkpoint
		next.TrustedCheckpoint = &cloned
	case publisherSessionInitialRootReady:
		if checkpoint != nil || handoffDigest.IsZero() {
			return publisherSession{}, fmt.Errorf("%w: initial root requires only a handoff digest", ErrInvalidPublisherSession)
		}
		next.HandoffDigest = handoffDigest.String()
	default:
		if checkpoint != nil || !handoffDigest.IsZero() {
			return publisherSession{}, fmt.Errorf("%w: unexpected phase evidence", ErrInvalidPublisherSession)
		}
	}
	if err := validatePublisherSession(next); err != nil {
		return publisherSession{}, err
	}
	return next, nil
}

func validatePublisherSessionTransition(previous, next publisherSession) error {
	if err := validatePublisherSession(previous); err != nil {
		return err
	}
	if err := validatePublisherSession(next); err != nil {
		return err
	}
	var checkpoint *handoffCheckpoint
	var digest s3disk.Digest
	switch next.Phase {
	case publisherSessionInitialPublicationReady:
		checkpoint = next.TrustedCheckpoint
	case publisherSessionInitialRootReady:
		parsed, err := s3disk.ParseDigest(next.HandoffDigest)
		if err != nil {
			return fmt.Errorf("%w: invalid transition evidence", ErrInvalidPublisherSession)
		}
		digest = parsed
	}
	expected, err := nextPublisherSession(previous, next.Phase, checkpoint, digest)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(expected, next) {
		return fmt.Errorf("%w: immutable session state changed", ErrInvalidPublisherSession)
	}
	return nil
}

func validatePublisherSessionStoreIdentity(store *publisherSessionStore, state publisherSession) error {
	if store == nil || !publisherSessionDependencyConfigured(store.raw) || store.shareID.IsZero() || store.recoveryKeyID == "" {
		return fmt.Errorf("%w: session store identity is incomplete", ErrInvalidPublisherSession)
	}
	if state.ShareID != store.shareID.String() || !constantTimePublisherSessionString(state.RecoveryKeyID, store.recoveryKeyID) {
		return fmt.Errorf("%w: sealed state identity mismatch", ErrInvalidPublisherSession)
	}
	return nil
}

func clonePublisherSession(value publisherSession) publisherSession {
	cloned := value
	cloned.SourcePath = bytes.Clone(value.SourcePath)
	cloned.HandoffPath = bytes.Clone(value.HandoffPath)
	cloned.TLSRootCAPEM = bytes.Clone(value.TLSRootCAPEM)
	cloned.ReferencePrivateSeed = bytes.Clone(value.ReferencePrivateSeed)
	cloned.RootBearer = bytes.Clone(value.RootBearer)
	cloned.SelectedPaths = make([][]byte, len(value.SelectedPaths))
	for index := range value.SelectedPaths {
		cloned.SelectedPaths[index] = bytes.Clone(value.SelectedPaths[index])
	}
	if value.TrustedCheckpoint != nil {
		checkpoint := *value.TrustedCheckpoint
		cloned.TrustedCheckpoint = &checkpoint
	}
	return cloned
}

func publisherSessionPhaseRank(phase publisherSessionPhase) (int, bool) {
	switch phase {
	case publisherSessionPrepared:
		return 1, true
	case publisherSessionRepositoryReady:
		return 2, true
	case publisherSessionJournalReady:
		return 3, true
	case publisherSessionInitialPublicationReady:
		return 4, true
	case publisherSessionInitialRootReady:
		return 5, true
	case publisherSessionHandoffReady:
		return 6, true
	case publisherSessionCompleted:
		return 7, true
	default:
		return 0, false
	}
}

func mustPublisherSessionPhaseRank(phase publisherSessionPhase) int {
	rank, ok := publisherSessionPhaseRank(phase)
	if !ok {
		panic("invalid built-in publisher session phase")
	}
	return rank
}

func canonicalPublisherSessionTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0 && value == value.UTC().Round(0)
}

func validatePublisherSessionAbsolutePath(value []byte) error {
	if len(value) < 1 || len(value) > maximumPublisherSessionPathBytes || bytes.IndexByte(value, 0) >= 0 {
		return ErrInvalidPublisherSession
	}
	path := string(value)
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalidPublisherSession
	}
	return nil
}

func validatePublisherSessionText(value string, maximum int, allowEmpty bool) error {
	if (!allowEmpty && value == "") || len(value) > maximum || !utf8.ValidString(value) ||
		strings.ContainsRune(value, '\x00') || strings.TrimSpace(value) != value {
		return ErrInvalidPublisherSession
	}
	return nil
}

func validPublisherSessionKeyID(value string) bool {
	if len(value) < 1 || len(value) > publisherstate.MaximumKeyIDBytes {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' ||
			character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}

func constantTimePublisherSessionString(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func publisherSessionDependencyConfigured(value any) bool {
	if value == nil {
		return false
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !reflected.IsNil()
	default:
		return true
	}
}

var _ s3disk.SealedStateStore = (*publisherSessionStore)(nil)
