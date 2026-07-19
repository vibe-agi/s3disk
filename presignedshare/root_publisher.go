package presignedshare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/vibe-agi/s3disk"
)

const (
	DefaultRootPublishAttempts = 8
	MaximumRootPublishAttempts = 100
)

var (
	ErrRootPublishConflict = errors.New("presignedshare: concurrent root publication conflict")
	// ErrRootPublishIndeterminate means a conditional write may have reached
	// S3, but an exact authenticated GET could not prove whether that target is
	// current. Retrying Create or Update with the same sealed closure is safe.
	ErrRootPublishIndeterminate = errors.New("presignedshare: root publication outcome is indeterminate")
)

// RootPublisherConfig fixes all authority and namespace state for one short-
// lived share. Store is used only by A to GET and conditionally write RootKey;
// it is never exposed to Reader or B/C/D.
type RootPublisherConfig struct {
	Store s3disk.Store
	// RecoveryJournal durably records exact pending root bytes before any S3
	// write. It is optional for API compatibility, but production publishers
	// must configure a confidential, authenticated SealedStateStore. Without it,
	// a crash can regenerate different presigned URLs under the same root
	// revision. Replaying both an old journal and its matching old S3 root is
	// outside this journal's freshness guarantee and requires an independently
	// protected monotonic backup or audit anchor.
	RecoveryJournal s3disk.SealedStateStore
	// ClientEncryption encrypts the signed root bundle before it is stored.
	// Repository objects must be configured independently with the same
	// profile through s3disk.RepositoryOptions. With RecoveryJournal, Store must
	// be the raw, unwrapped S3 Store: RootPublisher seals once, journals the exact
	// ciphertext, and hands those same bytes to Store on every recovery attempt.
	// Stores which advertise ClientEncryptionApplied are rejected. Go cannot
	// discover an opaque custom wrapper which transforms bytes without exposing
	// that marker; commercial adapters must preserve it when wrapping encryption.
	ClientEncryption   *s3disk.ClientEncryptionProfile
	RootKey            string
	RootCapability     Capability
	RepositoryPrefix   string
	ReferenceKey       string
	ShareID            ShareID
	Presigner          ExactGETPresigner
	Signer             s3disk.ReferenceSigner
	Verifier           s3disk.ReferenceVerifier
	MaxPublishAttempts int
	// DangerouslyAllowUnsignedReference permits an unsigned refs/ closure to be
	// turned into an authenticated share root. This can make an automated A-side
	// publisher a signing oracle for an attacker who can replace S3 references.
	// Commercial sharing flows must leave it false and use signed-refs/v1.
	DangerouslyAllowUnsignedReference bool
	// DangerouslyAllowCustomReferenceVerifier permits A-side root reconciliation
	// to invoke a custom verifier. It is unnecessary with the built-in Ed25519
	// verifier and must never be enabled on the S3-only B-side path.
	DangerouslyAllowCustomReferenceVerifier bool
}

// RootPublication describes one observed or newly installed root revision.
type RootPublication struct {
	Revision uint64
	Snapshot s3disk.Snapshot
	Version  s3disk.Version
	Updated  bool
}

// RootPublisher serializes one process's root updates. Cross-process writers
// are serialized by the root object's S3 conditional write.
type RootPublisher struct {
	store                                   s3disk.Store
	rootKey                                 string
	rootCapability                          Capability
	repositoryPrefix                        string
	referenceKey                            string
	shareID                                 ShareID
	presigner                               ExactGETPresigner
	signer                                  s3disk.ReferenceSigner
	verifier                                s3disk.ReferenceVerifier
	clientEncryption                        *s3disk.ClientEncryptionProfile
	maxAttempts                             int
	allowInsecureLoopback                   bool
	dangerouslyAllowCustomReferenceVerifier bool
	dangerouslyAllowUnsignedReference       bool
	recoveryJournal                         s3disk.SealedStateStore

	// gate, rather than sync.Mutex, makes waiting for the process-local
	// serialization point cancellable. The S3 conditional write remains the
	// cross-process serialization boundary.
	gate chan struct{}
}

// String deliberately exposes only bounded, non-secret status. Use a value
// receiver so formatting either the constructor-returned pointer or a copied
// value cannot recursively print the private root bearer, Store, or presigner.
func (publisher RootPublisher) String() string {
	return fmt.Sprintf(
		"presignedshare.RootPublisher{configured:%t,can_build_new_root:%t,recovery_enabled:%t,max_publish_attempts:%d,authorization_expires_at:%s,secrets:redacted}",
		publisher.configured(),
		publisher.CanBuildNewRoot(),
		publisher.RecoveryEnabled(),
		publisher.maxAttempts,
		publisher.rootCapability.expiresAt.Format(time.RFC3339Nano),
	)
}

func (publisher RootPublisher) GoString() string { return publisher.String() }

func (publisher RootPublisher) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Configured             bool      `json:"configured"`
		CanBuildNewRoot        bool      `json:"can_build_new_root"`
		RecoveryEnabled        bool      `json:"recovery_enabled"`
		MaxPublishAttempts     int       `json:"max_publish_attempts"`
		AuthorizationExpiresAt time.Time `json:"authorization_expires_at,omitempty"`
		Secrets                string    `json:"secrets"`
	}{
		Configured:             publisher.configured(),
		CanBuildNewRoot:        publisher.CanBuildNewRoot(),
		RecoveryEnabled:        publisher.RecoveryEnabled(),
		MaxPublishAttempts:     publisher.maxAttempts,
		AuthorizationExpiresAt: publisher.rootCapability.expiresAt,
		Secrets:                "redacted",
	})
}

func (publisher RootPublisher) configured() bool {
	return publisher.rootCapability.Configured() && configuredInterface(publisher.store) &&
		configuredInterface(publisher.verifier) && publisher.gate != nil &&
		(publisher.CanBuildNewRoot() || publisher.RecoveryEnabled())
}

// CanBuildNewRoot reports whether this instance retains both dependencies
// needed to mint a new root target. A recovery-only instance can still settle
// an existing durable pending target while this method returns false.
func (publisher RootPublisher) CanBuildNewRoot() bool {
	return configuredInterface(publisher.presigner) && configuredInterface(publisher.signer)
}

// RecoveryEnabled reports whether exact pending root bytes are durably
// journaled before Store writes.
func (publisher RootPublisher) RecoveryEnabled() bool {
	return configuredInterface(publisher.recoveryJournal)
}

// NewRootPublisher validates configuration without Store I/O. Signer identity
// and presigner expiry accessors are metadata contracts and must be local and
// side-effect free in custom implementations.
func NewRootPublisher(config RootPublisherConfig) (*RootPublisher, error) {
	if !configuredInterface(config.Store) {
		return nil, fmt.Errorf("%w: root Store is required", s3disk.ErrStoreMisconfigured)
	}
	if config.RecoveryJournal != nil && !configuredInterface(config.RecoveryJournal) {
		return nil, fmt.Errorf("%w: recovery journal must not be a typed nil", ErrRootRecoveryState)
	}
	hasRecovery := configuredInterface(config.RecoveryJournal)
	hasPresigner := configuredInterface(config.Presigner)
	hasSigner := configuredInterface(config.Signer)
	if !configuredInterface(config.Verifier) {
		return nil, fmt.Errorf("%w: verifier is required", ErrInvalidBundle)
	}
	if !hasRecovery && (!hasPresigner || !hasSigner) {
		return nil, fmt.Errorf("%w: presigner and signer are required without a recovery journal", ErrInvalidBundle)
	}
	if !s3disk.IsOfflineReferenceVerifier(config.Verifier) && !config.DangerouslyAllowCustomReferenceVerifier {
		return nil, fmt.Errorf("%w: custom verifier requires DangerouslyAllowCustomReferenceVerifier", ErrUntrustedBundle)
	}
	repositoryID := config.Verifier.RepositoryID()
	if repositoryID.IsZero() || (hasSigner && config.Signer.RepositoryID() != repositoryID) {
		return nil, fmt.Errorf("%w: root publisher trust roots do not match", ErrUntrustedBundle)
	}
	store := config.Store
	if config.ClientEncryption != nil {
		if config.ClientEncryption.RepositoryID() != repositoryID {
			return nil, fmt.Errorf("%w: client encryption and root publisher repository identities do not match", ErrUntrustedBundle)
		}
		if hasRecovery {
			if _, advertisesEncryption := config.Store.(interface {
				ClientEncryptionApplied(*s3disk.ClientEncryptionProfile) bool
			}); advertisesEncryption {
				return nil, fmt.Errorf(
					"%w: recovery with client encryption requires a raw Store without an encryption wrapper",
					s3disk.ErrStoreMisconfigured,
				)
			}
		} else {
			encryptedStore, err := s3disk.NewClientEncryptedStore(config.Store, config.ClientEncryption)
			if err != nil {
				return nil, fmt.Errorf("%w: client encryption configuration is invalid", s3disk.ErrStoreMisconfigured)
			}
			store = encryptedStore
		}
	}
	if hasSigner {
		if err := validateKeyID(config.Signer.KeyID()); err != nil {
			return nil, err
		}
	}
	prefix, err := validateBundleBindings(config.RepositoryPrefix, config.ReferenceKey, config.ShareID, 1, 1)
	if err != nil {
		return nil, err
	}
	referenceRemainder := strings.TrimPrefix(config.ReferenceKey, repositoryObjectNamespace(prefix))
	_, signedReference, err := channelFromReferenceRemainder(referenceRemainder)
	if err != nil {
		return nil, fmt.Errorf("%w: reference key is invalid", ErrInvalidBundle)
	}
	if !signedReference && !config.DangerouslyAllowUnsignedReference {
		return nil, fmt.Errorf("%w: root publication requires a signed repository reference", ErrUntrustedBundle)
	}
	if !validObjectKey(config.RootKey) || !config.RootCapability.Configured() ||
		config.RootCapability.provenance != capabilityProvenanceExactGET ||
		config.RootCapability.exactKey != config.RootKey {
		return nil, fmt.Errorf("%w: root is not a safely minted exact-GET capability", ErrInvalidBundle)
	}
	relativeRootKey := strings.TrimPrefix(config.RootKey, repositoryObjectNamespace(prefix))
	if relativeRootKey != config.RootKey &&
		(validReferenceRemainder(relativeRootKey) || validImmutableRemainder(relativeRootKey)) {
		return nil, fmt.Errorf("%w: root key collides with a repository protocol object", ErrInvalidBundle)
	}
	if hasPresigner {
		expiresAt, known := config.Presigner.AuthorizationExpiry()
		if !known || !expiresAt.UTC().Round(0).Equal(config.RootCapability.expiresAt) {
			return nil, fmt.Errorf("%w: presigner and root capability expiry do not match", ErrInvalidBundle)
		}
	}
	if !config.RootCapability.expiresAt.After(time.Now()) {
		return nil, fmt.Errorf("presignedshare: share authorization expired: %w", s3disk.ErrAccessDenied)
	}
	if config.MaxPublishAttempts == 0 {
		config.MaxPublishAttempts = DefaultRootPublishAttempts
	}
	if config.MaxPublishAttempts < 1 || config.MaxPublishAttempts > MaximumRootPublishAttempts {
		return nil, fmt.Errorf("%w: root publish attempts must be between 1 and %d", s3disk.ErrResourceLimit, MaximumRootPublishAttempts)
	}
	publisher := &RootPublisher{
		store: store, rootKey: config.RootKey, rootCapability: config.RootCapability,
		repositoryPrefix: prefix, referenceKey: config.ReferenceKey,
		shareID: config.ShareID, presigner: config.Presigner, signer: config.Signer,
		verifier: config.Verifier, clientEncryption: config.ClientEncryption,
		recoveryJournal:                         config.RecoveryJournal,
		maxAttempts:                             config.MaxPublishAttempts,
		allowInsecureLoopback:                   strings.HasPrefix(config.RootCapability.origin, "http://"),
		dangerouslyAllowCustomReferenceVerifier: config.DangerouslyAllowCustomReferenceVerifier,
		dangerouslyAllowUnsignedReference:       config.DangerouslyAllowUnsignedReference,
		gate:                                    make(chan struct{}, 1),
	}
	publisher.gate <- struct{}{}
	return publisher, nil
}

// Create installs revision one if RootKey is absent. It is idempotent only
// when an existing authenticated root already represents exactly closure.
// Use this method before distributing ExportBearer output.
func (publisher *RootPublisher) Create(ctx context.Context, closure s3disk.SnapshotClosure) (RootPublication, error) {
	return publisher.publish(ctx, closure, true)
}

// Update advances an existing root. A missing root is treated as rollback and
// is never silently recreated, including after process restart.
func (publisher *RootPublisher) Update(ctx context.Context, closure s3disk.SnapshotClosure) (RootPublication, error) {
	return publisher.publish(ctx, closure, false)
}

func (publisher *RootPublisher) publish(ctx context.Context, closure s3disk.SnapshotClosure, allowCreate bool) (RootPublication, error) {
	if publisher == nil {
		return RootPublication{}, fmt.Errorf("%w: nil root publisher", s3disk.ErrStoreMisconfigured)
	}
	if !configuredInterface(ctx) {
		return RootPublication{}, fmt.Errorf("presignedshare: root publish context is required")
	}
	if err := ctx.Err(); err != nil {
		return RootPublication{}, err
	}
	if publisher.gate == nil || !publisher.rootCapability.Configured() ||
		!configuredInterface(publisher.store) ||
		!configuredInterface(publisher.verifier) ||
		((!configuredInterface(publisher.presigner) || !configuredInterface(publisher.signer)) &&
			!configuredInterface(publisher.recoveryJournal)) {
		return RootPublication{}, fmt.Errorf("%w: root publisher is not initialized", s3disk.ErrStoreMisconfigured)
	}
	if !publisher.rootCapability.expiresAt.After(time.Now()) {
		return RootPublication{}, fmt.Errorf("presignedshare: share authorization expired: %w", s3disk.ErrAccessDenied)
	}
	authorizationCtx, cancelAuthorization := context.WithDeadline(ctx, publisher.rootCapability.expiresAt)
	defer cancelAuthorization()
	ctx = authorizationCtx
	if err := closure.ValidateResolvedForClientEncryption(publisher.clientEncryption); err != nil {
		return RootPublication{}, err
	}
	if closure.ReferenceKey != publisher.referenceKey {
		return RootPublication{}, fmt.Errorf("%w: closure reference key does not match root publisher", ErrInvalidBundle)
	}
	select {
	case <-ctx.Done():
		return RootPublication{}, ctx.Err()
	case <-publisher.gate:
	}
	defer func() { publisher.gate <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return RootPublication{}, err
	}
	if !publisher.rootCapability.expiresAt.After(time.Now()) {
		return RootPublication{}, fmt.Errorf("presignedshare: share authorization expired: %w", s3disk.ErrAccessDenied)
	}
	if configuredInterface(publisher.recoveryJournal) {
		return publisher.publishRecoverable(ctx, closure, allowCreate)
	}

	var hadAmbiguousWrite bool
	for attempt := 0; attempt < publisher.maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return RootPublication{}, err
		}
		currentObject, currentBundle, found, err := publisher.load(ctx)
		if err != nil {
			return RootPublication{}, err
		}
		if !found && !allowCreate {
			return RootPublication{}, fmt.Errorf("%w: existing share root disappeared", s3disk.ErrRollbackDetected)
		}
		if found {
			matches, err := rootBundleExactlyMatchesClosure(currentBundle, closure)
			if err != nil {
				return RootPublication{}, err
			}
			if matches {
				return RootPublication{
					Revision: currentBundle.revision, Snapshot: closure.Snapshot,
					Version: currentObject.Version, Updated: false,
				}, nil
			}
			if allowCreate {
				return RootPublication{}, ErrRootPublishConflict
			}
			if closure.Snapshot.Generation < currentBundle.referenceGeneration {
				return RootPublication{}, s3disk.ErrRollbackDetected
			}
			if closure.Snapshot.Generation == currentBundle.referenceGeneration && closure.Snapshot.Commit != currentBundle.referenceCommit {
				return RootPublication{}, s3disk.ErrSplitBrain
			}
			if currentBundle.revision == math.MaxUint64 {
				return RootPublication{}, s3disk.ErrGenerationExhausted
			}
		}

		revision := uint64(1)
		if found {
			revision = currentBundle.revision + 1
		}
		target, err := BuildSnapshotBundle(ctx, SnapshotBundleInput{
			RootKey: publisher.rootKey, RootCapability: publisher.rootCapability,
			RepositoryPrefix: publisher.repositoryPrefix, ShareID: publisher.shareID,
			Revision: revision, Closure: closure, Presigner: publisher.presigner,
		}, publisher.signer, publisher.verifier)
		if err != nil {
			return RootPublication{}, err
		}
		// Do not invoke a Store write with an already-canceled context or install
		// a bundle after its fixed bearer deadline elapsed while presigning.
		if err := ctx.Err(); err != nil {
			return RootPublication{}, err
		}
		if !publisher.rootCapability.expiresAt.After(time.Now()) {
			return RootPublication{}, fmt.Errorf("presignedshare: share authorization expired: %w", s3disk.ErrAccessDenied)
		}
		var version s3disk.Version
		if found {
			version, err = publisher.store.CompareAndSwap(ctx, publisher.rootKey, &currentObject.Version, target)
		} else {
			version, err = publisher.store.PutIfAbsent(ctx, publisher.rootKey, target)
		}
		if err == nil {
			if err := validateRootVersion(version); err != nil {
				return RootPublication{}, err
			}
			return RootPublication{Revision: revision, Snapshot: closure.Snapshot, Version: version, Updated: true}, nil
		}
		if errors.Is(err, s3disk.ErrPrecondition) {
			continue
		}
		hadAmbiguousWrite = true
		observed, _, observedFound, observeErr := publisher.load(ctx)
		if observeErr == nil && observedFound {
			if bytes.Equal(observed.Data, target) {
				return RootPublication{
					Revision: revision, Snapshot: closure.Snapshot,
					Version: observed.Version, Updated: true,
				}, nil
			}
			// A different authenticated value is either a concurrent winner or an
			// older value proving this attempt did not become current. Re-enter the
			// CAS loop from that exact observation.
			continue
		}
		if observeErr != nil && (errors.Is(observeErr, context.Canceled) || errors.Is(observeErr, context.DeadlineExceeded)) {
			return RootPublication{}, fmt.Errorf("%w: reconciliation canceled: %w", ErrRootPublishIndeterminate, observeErr)
		}
		return RootPublication{}, ErrRootPublishIndeterminate
	}
	if hadAmbiguousWrite {
		return RootPublication{}, ErrRootPublishIndeterminate
	}
	return RootPublication{}, ErrRootPublishConflict
}

func (publisher *RootPublisher) load(ctx context.Context) (s3disk.Object, *Bundle, bool, error) {
	object, err := publisher.store.Get(ctx, publisher.rootKey, s3disk.GetOptions{MaxBytes: MaximumBundleBytes})
	if errors.Is(err, s3disk.ErrObjectNotFound) {
		clear(object.Data)
		return s3disk.Object{}, nil, false, nil
	}
	if err != nil {
		clear(object.Data)
		return s3disk.Object{}, nil, false, safeRootStoreError(err)
	}
	if err := validateRootVersion(object.Version); err != nil {
		return s3disk.Object{}, nil, false, err
	}
	bundle, err := Decode(ctx, object.Data, publisher.verifier, DecodeOptions{
		RootCapability: publisher.rootCapability, RepositoryPrefix: publisher.repositoryPrefix,
		ReferenceKey: publisher.referenceKey, ShareID: publisher.shareID,
		AllowInsecureLoopback:                   publisher.allowInsecureLoopback,
		DangerouslyAllowCustomReferenceVerifier: publisher.dangerouslyAllowCustomReferenceVerifier,
	})
	if err != nil {
		return s3disk.Object{}, nil, false, err
	}
	return object, bundle, true, nil
}

func rootBundleExactlyMatchesClosure(bundle *Bundle, closure s3disk.SnapshotClosure) (bool, error) {
	if bundle == nil {
		return false, fmt.Errorf("%w: nil current root bundle", ErrInvalidBundle)
	}
	if closure.Snapshot.Generation != bundle.referenceGeneration || closure.Snapshot.Commit != bundle.referenceCommit ||
		bundle.referenceKey != closure.ReferenceKey || !bytes.Equal(bundle.reference.Data, closure.ReferenceData) ||
		bundle.reference.Version != closure.ReferenceVersion ||
		len(bundle.capabilities) != len(closure.ObjectKeys) {
		return false, nil
	}
	for _, key := range closure.ObjectKeys {
		if _, exists := bundle.capabilities[key]; !exists {
			return false, nil
		}
	}
	return true, nil
}

func validateRootVersion(version s3disk.Version) error {
	if version.ETag == "" || len(version.ETag) > s3disk.MaxStoreVersionTokenBytes ||
		len(version.VersionID) > s3disk.MaxStoreVersionTokenBytes {
		return fmt.Errorf("%w: root operation returned an invalid version", s3disk.ErrStoreIncompatible)
	}
	return nil
}

func safeRootStoreError(err error) error {
	for _, sentinel := range []error{
		context.Canceled, context.DeadlineExceeded, s3disk.ErrObjectNotFound,
		s3disk.ErrNotModified, s3disk.ErrPrecondition, s3disk.ErrAccessDenied,
		s3disk.ErrRateLimited, s3disk.ErrStoreUnavailable, s3disk.ErrStoreMisconfigured,
		s3disk.ErrStoreIncompatible, s3disk.ErrStoreOperationUnsupported,
		s3disk.ErrResourceLimit, s3disk.ErrCorruptObject,
	} {
		if errors.Is(err, sentinel) {
			return sentinel
		}
	}
	return s3disk.ErrStoreUnavailable
}
