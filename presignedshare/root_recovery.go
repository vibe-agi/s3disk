package presignedshare

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/vibe-agi/s3disk"
)

const (
	rootRecoveryFormatVersion        = 1
	rootRecoveryMagicBytes           = 8
	rootRecoveryVersionOffset        = rootRecoveryMagicBytes
	rootRecoveryReservedOffset       = rootRecoveryVersionOffset + 2
	rootRecoveryMetadataLengthOffset = rootRecoveryReservedOffset + 2
	rootRecoveryTargetLengthOffset   = rootRecoveryMetadataLengthOffset + 4
	rootRecoveryHeaderBytes          = rootRecoveryTargetLengthOffset + 8

	// maximumRootRecoveryMetadataBytes covers worst-case JSON escaping for all
	// bounded object keys and the four maximum-size Store version tokens which
	// can coexist in committed plus pending state. It remains well within the
	// headroom reserved by publisherstate.MaximumPlaintextBytes.
	maximumRootRecoveryMetadataBytes = 128 << 10
	maximumRootStoredTargetBytes     = MaximumBundleBytes + s3disk.ClientEncryptionCiphertextOverhead
	// MaximumRootRecoveryJournalBytes bounds the plaintext supplied to a
	// SealedStateStore. Raw target bytes are framed outside JSON so a maximum
	// encrypted 64 MiB bundle still fits the default FileSealedStateStore limit.
	MaximumRootRecoveryJournalBytes = rootRecoveryHeaderBytes + maximumRootRecoveryMetadataBytes + maximumRootStoredTargetBytes
)

var (
	rootRecoveryMagic  = [rootRecoveryMagicBytes]byte{'s', '3', 'd', 'r', 'j', 0, 1, 0}
	rootRecoveryDomain = []byte("s3disk\x00presigned-share\x00root-recovery\x00v1\x00")

	// ErrRootRecoveryState reports recovery bytes which are malformed, replayed
	// into a different share identity, or inconsistent with the requested
	// closure. Invalid loaded state fails closed before a new S3 root write.
	ErrRootRecoveryState = errors.New("presignedshare: invalid root recovery state")
	// ErrRootRecoveryIndeterminate reports that a recovery-journal operation or
	// CAS outcome could not be safely determined. Callers must retry rather than
	// assuming either durable state.
	ErrRootRecoveryIndeterminate = errors.New("presignedshare: root recovery journal outcome is indeterminate")
)

// RootRecoveryResult describes the authenticated S3 root observed after
// RecoverPending reconciles the sealed recovery journal. RootFound is false
// only for a prepared journal which has never published a root.
//
// HadPending reports whether the journal contained an operation when recovery
// began. A successful call always sets PendingCleared when HadPending is true.
// WroteRoot distinguishes replaying the exact WAL target during this call from
// merely observing that an earlier ambiguous write was already applied.
type RootRecoveryResult struct {
	HadPending          bool
	PendingCleared      bool
	RootFound           bool
	WroteRoot           bool
	Revision            uint64
	ReferenceGeneration uint64
	ReferenceCommit     s3disk.Digest
	Version             s3disk.Version
}

// rootRecoveryRecord is a write-ahead log, not an independent freshness
// oracle. Pending always owns the exact bytes handed to the raw Store, while
// Committed anchors the exact authenticated logical bundle last accepted from
// S3. A current journal detects an old or same-revision-replaced S3 root. A
// coordinated replay of both the complete journal and its matching S3 root is
// indistinguishable without a separately protected monotonic anchor.
type rootRecoveryRecord struct {
	Format                       int                    `json:"format"`
	RepositoryID                 s3disk.RepositoryID    `json:"repository_id"`
	RepositoryPrefix             string                 `json:"repository_prefix"`
	ShareID                      ShareID                `json:"share_id"`
	RootKey                      string                 `json:"root_key"`
	ReferenceKey                 string                 `json:"reference_key"`
	AuthorizationExpiresAt       time.Time              `json:"authorization_expires_at"`
	RootCapabilityDigest         s3disk.Digest          `json:"root_capability_digest"`
	ClientEncryptionConfigured   bool                   `json:"client_encryption_configured"`
	ClientEncryptionWitness      []byte                 `json:"client_encryption_witness,omitempty"`
	AllowUnsignedReference       bool                   `json:"allow_unsigned_reference"`
	AllowCustomReferenceVerifier bool                   `json:"allow_custom_reference_verifier"`
	HighestRevision              uint64                 `json:"highest_revision"`
	Committed                    *rootRecoveryCommitted `json:"committed,omitempty"`
	Pending                      *rootRecoveryPending   `json:"pending,omitempty"`
}

// rootRecoveryCommitted is the durable authenticated root anchor. Revision
// alone is insufficient: a different validly signed bundle at the same
// revision is split brain, even when it names the same snapshot closure.
type rootRecoveryCommitted struct {
	Revision            uint64        `json:"revision"`
	LogicalDigest       s3disk.Digest `json:"logical_digest"`
	ReferenceGeneration uint64        `json:"reference_generation"`
	ReferenceCommit     s3disk.Digest `json:"reference_commit"`
	ETag                string        `json:"etag"`
	VersionID           string        `json:"version_id,omitempty"`
}

type rootRecoveryPending struct {
	TargetRevision      uint64        `json:"target_revision"`
	AllowCreate         bool          `json:"allow_create"`
	ExpectedAbsent      bool          `json:"expected_absent"`
	ExpectedETag        string        `json:"expected_etag,omitempty"`
	ExpectedVersionID   string        `json:"expected_version_id,omitempty"`
	BaseDigest          s3disk.Digest `json:"base_digest"`
	ClosureDigest       s3disk.Digest `json:"closure_digest"`
	TargetDigest        s3disk.Digest `json:"target_digest"`
	LogicalTargetDigest s3disk.Digest `json:"logical_target_digest"`
	ReferenceGeneration uint64        `json:"reference_generation"`
	ReferenceCommit     s3disk.Digest `json:"reference_commit"`
}

func (pending rootRecoveryPending) expectedVersion() *s3disk.Version {
	if pending.ExpectedAbsent {
		return nil
	}
	return &s3disk.Version{ETag: pending.ExpectedETag, VersionID: pending.ExpectedVersionID}
}

func (pending *rootRecoveryPending) setExpected(version s3disk.Version, base []byte) {
	pending.ExpectedAbsent = false
	pending.ExpectedETag = version.ETag
	pending.ExpectedVersionID = version.VersionID
	pending.BaseDigest = rootRecoveryDigest("base", base)
}

func cloneRootRecoveryRecord(record rootRecoveryRecord) rootRecoveryRecord {
	cloned := record
	cloned.ClientEncryptionWitness = bytes.Clone(record.ClientEncryptionWitness)
	if record.Committed != nil {
		committed := *record.Committed
		cloned.Committed = &committed
	}
	if record.Pending != nil {
		pending := *record.Pending
		cloned.Pending = &pending
	}
	return cloned
}

func encodeRootRecoveryRecord(record rootRecoveryRecord, target []byte) ([]byte, error) {
	if record.Format != rootRecoveryFormatVersion {
		return nil, fmt.Errorf("%w: unsupported format", ErrRootRecoveryState)
	}
	if record.Pending == nil {
		if len(target) != 0 {
			return nil, fmt.Errorf("%w: idle record contains target bytes", ErrRootRecoveryState)
		}
	} else {
		if len(target) < 1 || int64(len(target)) > maximumRootStoredTargetBytes ||
			record.Pending.TargetDigest != rootRecoveryDigest("target", target) {
			return nil, fmt.Errorf("%w: pending target is invalid", ErrRootRecoveryState)
		}
	}
	metadata, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("%w: encode metadata", ErrRootRecoveryState)
	}
	if len(metadata) < 1 || len(metadata) > maximumRootRecoveryMetadataBytes {
		return nil, fmt.Errorf("%w: %w: recovery metadata exceeds its bound", ErrRootRecoveryState, s3disk.ErrResourceLimit)
	}
	encoded := make([]byte, rootRecoveryHeaderBytes+len(metadata)+len(target))
	copy(encoded, rootRecoveryMagic[:])
	binary.BigEndian.PutUint16(encoded[rootRecoveryVersionOffset:], rootRecoveryFormatVersion)
	binary.BigEndian.PutUint16(encoded[rootRecoveryReservedOffset:], 0)
	binary.BigEndian.PutUint32(encoded[rootRecoveryMetadataLengthOffset:], uint32(len(metadata)))
	binary.BigEndian.PutUint64(encoded[rootRecoveryTargetLengthOffset:], uint64(len(target)))
	copy(encoded[rootRecoveryHeaderBytes:], metadata)
	copy(encoded[rootRecoveryHeaderBytes+len(metadata):], target)
	clear(metadata)
	return encoded, nil
}

func decodeRootRecoveryRecord(encoded []byte) (rootRecoveryRecord, []byte, error) {
	if len(encoded) < rootRecoveryHeaderBytes+2 {
		return rootRecoveryRecord{}, nil, fmt.Errorf("%w: truncated framing", ErrRootRecoveryState)
	}
	if int64(len(encoded)) > MaximumRootRecoveryJournalBytes {
		return rootRecoveryRecord{}, nil, fmt.Errorf("%w: %w: recovery state exceeds its bound", ErrRootRecoveryState, s3disk.ErrResourceLimit)
	}
	if !bytes.Equal(encoded[:rootRecoveryMagicBytes], rootRecoveryMagic[:]) ||
		binary.BigEndian.Uint16(encoded[rootRecoveryVersionOffset:]) != rootRecoveryFormatVersion ||
		binary.BigEndian.Uint16(encoded[rootRecoveryReservedOffset:]) != 0 {
		return rootRecoveryRecord{}, nil, fmt.Errorf("%w: invalid framing header", ErrRootRecoveryState)
	}
	metadataLength := uint64(binary.BigEndian.Uint32(encoded[rootRecoveryMetadataLengthOffset:]))
	targetLength := binary.BigEndian.Uint64(encoded[rootRecoveryTargetLengthOffset:])
	if metadataLength < 2 || metadataLength > maximumRootRecoveryMetadataBytes || targetLength > uint64(maximumRootStoredTargetBytes) ||
		metadataLength+targetLength != uint64(len(encoded)-rootRecoveryHeaderBytes) {
		return rootRecoveryRecord{}, nil, fmt.Errorf("%w: non-canonical framing lengths", ErrRootRecoveryState)
	}
	metadataEnd := rootRecoveryHeaderBytes + int(metadataLength)
	metadata := encoded[rootRecoveryHeaderBytes:metadataEnd]
	decoder := json.NewDecoder(bytes.NewReader(metadata))
	decoder.DisallowUnknownFields()
	var record rootRecoveryRecord
	if err := decoder.Decode(&record); err != nil {
		return rootRecoveryRecord{}, nil, fmt.Errorf("%w: malformed metadata", ErrRootRecoveryState)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return rootRecoveryRecord{}, nil, fmt.Errorf("%w: trailing metadata value", ErrRootRecoveryState)
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, metadata) {
		clear(canonical)
		return rootRecoveryRecord{}, nil, fmt.Errorf("%w: metadata is not canonical", ErrRootRecoveryState)
	}
	clear(canonical)
	target := bytes.Clone(encoded[metadataEnd:])
	if record.Format != rootRecoveryFormatVersion {
		clear(target)
		return rootRecoveryRecord{}, nil, fmt.Errorf("%w: unsupported metadata format", ErrRootRecoveryState)
	}
	if record.Pending == nil {
		if len(target) != 0 {
			clear(target)
			return rootRecoveryRecord{}, nil, fmt.Errorf("%w: idle state contains a target", ErrRootRecoveryState)
		}
	} else if len(target) < 1 || record.Pending.TargetDigest != rootRecoveryDigest("target", target) {
		clear(target)
		return rootRecoveryRecord{}, nil, fmt.Errorf("%w: target digest mismatch", ErrRootRecoveryState)
	}
	return record, target, nil
}

func (publisher *RootPublisher) newRootRecoveryRecord() (rootRecoveryRecord, error) {
	capabilityDigest, err := rootCapabilityRecoveryDigest(publisher.rootCapability)
	if err != nil {
		return rootRecoveryRecord{}, err
	}
	record := rootRecoveryRecord{
		Format:       rootRecoveryFormatVersion,
		RepositoryID: publisher.verifier.RepositoryID(), RepositoryPrefix: publisher.repositoryPrefix,
		ShareID: publisher.shareID, RootKey: publisher.rootKey, ReferenceKey: publisher.referenceKey,
		AuthorizationExpiresAt:       publisher.rootCapability.expiresAt,
		RootCapabilityDigest:         capabilityDigest,
		ClientEncryptionConfigured:   publisher.clientEncryption != nil,
		AllowUnsignedReference:       publisher.dangerouslyAllowUnsignedReference,
		AllowCustomReferenceVerifier: publisher.dangerouslyAllowCustomReferenceVerifier,
	}
	if publisher.clientEncryption != nil {
		witnessPlaintext := rootRecoveryIdentityDigest(record)
		witness, err := publisher.clientEncryption.SealObject(publisher.rootKey, witnessPlaintext[:])
		if err != nil {
			return rootRecoveryRecord{}, fmt.Errorf("%w: create client-encryption witness", ErrRootRecoveryState)
		}
		record.ClientEncryptionWitness = witness
	}
	return record, nil
}

func (publisher *RootPublisher) sealRootStorageTarget(logical []byte) ([]byte, error) {
	if len(logical) < 1 || len(logical) > MaximumBundleBytes {
		return nil, fmt.Errorf("%w: logical root target exceeds its bound", ErrRootRecoveryState)
	}
	if publisher.clientEncryption == nil {
		return bytes.Clone(logical), nil
	}
	target, err := publisher.clientEncryption.SealObject(publisher.rootKey, logical)
	if err != nil {
		return nil, fmt.Errorf("%w: seal root target", ErrRootRecoveryState)
	}
	return target, nil
}

func (publisher *RootPublisher) openRootStorageTarget(target []byte) ([]byte, error) {
	maximum := int64(MaximumBundleBytes)
	if publisher.clientEncryption != nil {
		maximum += s3disk.ClientEncryptionCiphertextOverhead
	}
	if len(target) < 1 || int64(len(target)) > maximum {
		return nil, fmt.Errorf("%w: stored root target exceeds its bound", s3disk.ErrResourceLimit)
	}
	if publisher.clientEncryption == nil {
		return bytes.Clone(target), nil
	}
	logical, err := publisher.clientEncryption.OpenObject(publisher.rootKey, target)
	if err != nil {
		return nil, err
	}
	if len(logical) < 1 || len(logical) > MaximumBundleBytes {
		clear(logical)
		return nil, fmt.Errorf("%w: opened root target exceeds its bound", s3disk.ErrResourceLimit)
	}
	return logical, nil
}

func (publisher *RootPublisher) decodeRootStorageTarget(ctx context.Context, target []byte) (*Bundle, s3disk.Digest, error) {
	logical, err := publisher.openRootStorageTarget(target)
	if err != nil {
		return nil, s3disk.Digest{}, err
	}
	defer clear(logical)
	bundle, err := Decode(ctx, logical, publisher.verifier, DecodeOptions{
		RootCapability: publisher.rootCapability, RepositoryPrefix: publisher.repositoryPrefix,
		ReferenceKey: publisher.referenceKey, ShareID: publisher.shareID,
		AllowInsecureLoopback:                   publisher.allowInsecureLoopback,
		DangerouslyAllowCustomReferenceVerifier: publisher.dangerouslyAllowCustomReferenceVerifier,
	})
	if err != nil {
		return nil, s3disk.Digest{}, err
	}
	return bundle, rootRecoveryDigest("logical-root", logical), nil
}

func (publisher *RootPublisher) validateRootRecoveryRecord(ctx context.Context, record rootRecoveryRecord, target []byte) error {
	wantCapabilityDigest, err := rootCapabilityRecoveryDigest(publisher.rootCapability)
	if err != nil {
		return err
	}
	if record.Format != rootRecoveryFormatVersion || record.RepositoryID != publisher.verifier.RepositoryID() ||
		record.RepositoryPrefix != publisher.repositoryPrefix || record.ShareID != publisher.shareID ||
		record.RootKey != publisher.rootKey || record.ReferenceKey != publisher.referenceKey ||
		!record.AuthorizationExpiresAt.Equal(publisher.rootCapability.expiresAt) ||
		record.RootCapabilityDigest != wantCapabilityDigest ||
		record.ClientEncryptionConfigured != (publisher.clientEncryption != nil) ||
		record.AllowUnsignedReference != publisher.dangerouslyAllowUnsignedReference ||
		record.AllowCustomReferenceVerifier != publisher.dangerouslyAllowCustomReferenceVerifier {
		return fmt.Errorf("%w: share identity binding mismatch", ErrRootRecoveryState)
	}
	identityDigest := rootRecoveryIdentityDigest(record)
	if publisher.clientEncryption == nil {
		if len(record.ClientEncryptionWitness) != 0 {
			return fmt.Errorf("%w: unexpected client-encryption witness", ErrRootRecoveryState)
		}
	} else {
		if len(record.ClientEncryptionWitness) < 1 || len(record.ClientEncryptionWitness) > 1024 {
			return fmt.Errorf("%w: invalid client-encryption witness", ErrRootRecoveryState)
		}
		opened, err := publisher.clientEncryption.OpenObject(publisher.rootKey, bytes.Clone(record.ClientEncryptionWitness))
		if err != nil || !bytes.Equal(opened, identityDigest[:]) {
			clear(opened)
			return fmt.Errorf("%w: client-encryption profile mismatch", ErrRootRecoveryState)
		}
		clear(opened)
	}
	if record.Committed == nil && record.Pending == nil {
		if record.HighestRevision != 0 || len(target) != 0 {
			return fmt.Errorf("%w: invalid prepared state", ErrRootRecoveryState)
		}
		return nil
	}
	if record.Committed != nil {
		committed := record.Committed
		if committed.Revision == 0 || committed.LogicalDigest.IsZero() || committed.ReferenceGeneration == 0 ||
			committed.ReferenceCommit.IsZero() || validateRootVersion(s3disk.Version{
			ETag: committed.ETag, VersionID: committed.VersionID,
		}) != nil {
			return fmt.Errorf("%w: invalid committed anchor", ErrRootRecoveryState)
		}
	}
	if record.Pending == nil {
		if len(target) != 0 || record.Committed == nil || record.HighestRevision != record.Committed.Revision {
			return fmt.Errorf("%w: invalid idle state", ErrRootRecoveryState)
		}
		return nil
	}
	pending := record.Pending
	if record.HighestRevision == 0 || pending.TargetRevision == 0 || pending.TargetRevision != record.HighestRevision ||
		pending.ClosureDigest.IsZero() || pending.TargetDigest.IsZero() || pending.LogicalTargetDigest.IsZero() ||
		pending.ReferenceGeneration == 0 || pending.ReferenceCommit.IsZero() || len(target) < 1 ||
		int64(len(target)) > maximumRootStoredTargetBytes || pending.AllowCreate != pending.ExpectedAbsent {
		return fmt.Errorf("%w: invalid pending state", ErrRootRecoveryState)
	}
	if pending.ExpectedAbsent {
		if pending.TargetRevision != 1 || record.Committed != nil || pending.ExpectedETag != "" ||
			pending.ExpectedVersionID != "" || !pending.BaseDigest.IsZero() {
			return fmt.Errorf("%w: invalid absent precondition", ErrRootRecoveryState)
		}
	} else {
		version := pending.expectedVersion()
		if record.Committed == nil || record.Committed.Revision == math.MaxUint64 ||
			pending.TargetRevision != record.Committed.Revision+1 || version == nil ||
			validateRootVersion(*version) != nil || pending.BaseDigest.IsZero() {
			return fmt.Errorf("%w: invalid version precondition", ErrRootRecoveryState)
		}
		if pending.ReferenceGeneration < record.Committed.ReferenceGeneration ||
			(pending.ReferenceGeneration == record.Committed.ReferenceGeneration &&
				pending.ReferenceCommit != record.Committed.ReferenceCommit) {
			return fmt.Errorf("%w: pending snapshot does not advance its anchor", ErrRootRecoveryState)
		}
	}
	bundle, logicalDigest, err := publisher.decodeRootStorageTarget(ctx, target)
	if err != nil || bundle.revision != pending.TargetRevision ||
		bundle.referenceGeneration != pending.ReferenceGeneration || bundle.referenceCommit != pending.ReferenceCommit ||
		!bundle.authorizationExpiresAt.Equal(record.AuthorizationExpiresAt) || logicalDigest != pending.LogicalTargetDigest {
		return fmt.Errorf("%w: pending target binding mismatch", ErrRootRecoveryState)
	}
	return nil
}

// PrepareRecovery durably binds this publisher's exact root bearer, share
// identity, fixed authorization expiry, trust root, and client-encryption
// profile before any root object needs to be written to S3. It is idempotent:
// an existing valid prepared, pending, or committed record is left unchanged.
//
// Call this before persisting a resumable publishing-session manifest. The
// resulting sealed record is what lets RestoreRootPublisher distinguish an
// originally exact-GET capability from an arbitrary imported bearer after a
// process restart. RecoveryJournal must be configured.
func (publisher *RootPublisher) PrepareRecovery(ctx context.Context) error {
	if publisher == nil {
		return fmt.Errorf("%w: nil root publisher", s3disk.ErrStoreMisconfigured)
	}
	if !configuredInterface(ctx) {
		return fmt.Errorf("presignedshare: recovery preparation context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if publisher.gate == nil || !publisher.rootCapability.Configured() ||
		publisher.rootCapability.provenance != capabilityProvenanceExactGET ||
		!configuredInterface(publisher.store) || !configuredInterface(publisher.verifier) {
		return fmt.Errorf("%w: root publisher is not initialized", s3disk.ErrStoreMisconfigured)
	}
	if !configuredInterface(publisher.recoveryJournal) {
		return fmt.Errorf("%w: recovery journal is required", ErrRootRecoveryState)
	}
	if !publisher.rootCapability.expiresAt.After(time.Now()) {
		return fmt.Errorf("presignedshare: share authorization expired: %w", s3disk.ErrAccessDenied)
	}
	authorizationCtx, cancelAuthorization := context.WithDeadline(ctx, publisher.rootCapability.expiresAt)
	defer cancelAuthorization()
	ctx = authorizationCtx
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-publisher.gate:
	}
	defer func() { publisher.gate <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !publisher.rootCapability.expiresAt.After(time.Now()) {
		return fmt.Errorf("presignedshare: share authorization expired: %w", s3disk.ErrAccessDenied)
	}

	loaded, err := publisher.loadRootRecovery(ctx)
	if err != nil {
		return err
	}
	defer loaded.clear()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !publisher.rootCapability.expiresAt.After(time.Now()) {
		return fmt.Errorf("presignedshare: share authorization expired: %w", s3disk.ErrAccessDenied)
	}
	if loaded.found {
		return nil
	}
	prepared, err := publisher.saveRootRecovery(ctx, loaded, loaded.record, nil)
	prepared.clear()
	if errors.Is(err, ErrRootPublishConflict) {
		// A second publisher may have won the first CAS with a logically
		// equivalent but byte-distinct encrypted witness. Re-read and accept any
		// state which passes the complete identity and recovery validation; do
		// not weaken saveRootRecovery's exact response-loss reconciliation.
		observed, loadErr := publisher.loadRootRecovery(ctx)
		if loadErr != nil {
			return loadErr
		}
		defer observed.clear()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if !publisher.rootCapability.expiresAt.After(time.Now()) {
			return fmt.Errorf("presignedshare: share authorization expired: %w", s3disk.ErrAccessDenied)
		}
		if observed.found {
			return nil
		}
	}
	if err == nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if !publisher.rootCapability.expiresAt.After(time.Now()) {
			return fmt.Errorf("presignedshare: share authorization expired: %w", s3disk.ErrAccessDenied)
		}
	}
	return err
}

// RestoreRootPublisher authenticates an existing sealed recovery journal
// before promoting an imported root bearer back to exact-GET provenance. It
// performs no root Store I/O and never mints, signs, or writes S3 data during
// construction. RecoveryJournal is mandatory and must already contain a valid
// prepared, pending, or committed record created by an exact publisher.
//
// RootCapability must come from ParseBearer. Ordinary in-process capabilities
// continue to use NewRootPublisher. Any missing, corrupt, expired, or
// identity-mismatched recovery state fails closed.
func RestoreRootPublisher(ctx context.Context, config RootPublisherConfig) (*RootPublisher, error) {
	if !configuredInterface(ctx) {
		return nil, fmt.Errorf("presignedshare: root restore context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !configuredInterface(config.RecoveryJournal) {
		return nil, fmt.Errorf("%w: recovery journal is required", ErrRootRecoveryState)
	}
	if config.RootCapability.provenance != capabilityProvenanceImportedBearer {
		return nil, fmt.Errorf("%w: restore requires an imported root bearer", ErrRootRecoveryState)
	}
	if !s3disk.IsOfflineReferenceVerifier(config.Verifier) {
		return nil, fmt.Errorf("%w: restore requires an offline reference verifier", ErrUntrustedBundle)
	}

	publisher, err := newRootPublisher(config, true)
	if err != nil {
		return nil, err
	}
	authorizationCtx, cancelAuthorization := context.WithDeadline(ctx, publisher.rootCapability.expiresAt)
	defer cancelAuthorization()
	loaded, err := publisher.loadRootRecovery(authorizationCtx)
	if err != nil {
		return nil, err
	}
	defer loaded.clear()
	if !loaded.found {
		return nil, fmt.Errorf("%w: prepared recovery state is absent", ErrRootRecoveryState)
	}
	if err := authorizationCtx.Err(); err != nil {
		return nil, err
	}
	if !publisher.rootCapability.expiresAt.After(time.Now()) {
		return nil, fmt.Errorf("presignedshare: share authorization expired: %w", s3disk.ErrAccessDenied)
	}

	// This is the sole provenance upgrade. loadRootRecovery has already checked
	// the sealed identity, exact bearer digest, fixed expiry, trust root,
	// namespace, security flags, encryption witness, and any pending target.
	publisher.rootCapability.provenance = capabilityProvenanceExactGET
	return publisher, nil
}

// RecoverPending settles one exact root operation already authenticated by the
// sealed recovery journal. It needs no SnapshotClosure and never invokes the
// publisher's signer or presigner: both the target bytes and their exact S3
// create/CAS precondition come exclusively from the WAL.
//
// When no operation is pending, RecoverPending safely reconciles the current
// authenticated S3 root against the committed journal anchor. It never creates
// a missing root in that case, and it never recreates a missing base for an
// update. A prepared journal with no root is a successful no-op.
func (publisher *RootPublisher) RecoverPending(ctx context.Context) (RootRecoveryResult, error) {
	if publisher == nil {
		return RootRecoveryResult{}, fmt.Errorf("%w: nil root publisher", s3disk.ErrStoreMisconfigured)
	}
	if !configuredInterface(ctx) {
		return RootRecoveryResult{}, fmt.Errorf("presignedshare: root recovery context is required")
	}
	if err := ctx.Err(); err != nil {
		return RootRecoveryResult{}, err
	}
	if publisher.gate == nil || !publisher.rootCapability.Configured() ||
		publisher.rootCapability.provenance != capabilityProvenanceExactGET ||
		!configuredInterface(publisher.store) || !configuredInterface(publisher.verifier) {
		return RootRecoveryResult{}, fmt.Errorf("%w: root publisher is not initialized", s3disk.ErrStoreMisconfigured)
	}
	if !configuredInterface(publisher.recoveryJournal) {
		return RootRecoveryResult{}, fmt.Errorf("%w: recovery journal is required", ErrRootRecoveryState)
	}
	if !publisher.rootCapability.expiresAt.After(time.Now()) {
		return RootRecoveryResult{}, fmt.Errorf("presignedshare: share authorization expired: %w", s3disk.ErrAccessDenied)
	}
	authorizationCtx, cancelAuthorization := context.WithDeadline(ctx, publisher.rootCapability.expiresAt)
	defer cancelAuthorization()
	ctx = authorizationCtx
	select {
	case <-ctx.Done():
		return RootRecoveryResult{}, ctx.Err()
	case <-publisher.gate:
	}
	defer func() { publisher.gate <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return RootRecoveryResult{}, err
	}
	if !publisher.rootCapability.expiresAt.After(time.Now()) {
		return RootRecoveryResult{}, fmt.Errorf("presignedshare: share authorization expired: %w", s3disk.ErrAccessDenied)
	}
	return publisher.recoverPending(ctx)
}

func rootCapabilityRecoveryDigest(capability Capability) (s3disk.Digest, error) {
	bearer, err := capability.ExportBearer()
	if err != nil {
		return s3disk.Digest{}, fmt.Errorf("%w: root capability cannot be bound", ErrRootRecoveryState)
	}
	defer clear(bearer)
	return rootRecoveryDigest("root-capability", bearer), nil
}

func rootRecoveryIdentityDigest(record rootRecoveryRecord) s3disk.Digest {
	encoded, _ := json.Marshal(struct {
		Format                       int                 `json:"format"`
		RepositoryID                 s3disk.RepositoryID `json:"repository_id"`
		RepositoryPrefix             string              `json:"repository_prefix"`
		ShareID                      ShareID             `json:"share_id"`
		RootKey                      string              `json:"root_key"`
		ReferenceKey                 string              `json:"reference_key"`
		AuthorizationExpiresAt       time.Time           `json:"authorization_expires_at"`
		RootCapabilityDigest         s3disk.Digest       `json:"root_capability_digest"`
		ClientEncryptionConfigured   bool                `json:"client_encryption_configured"`
		AllowUnsignedReference       bool                `json:"allow_unsigned_reference"`
		AllowCustomReferenceVerifier bool                `json:"allow_custom_reference_verifier"`
	}{
		record.Format, record.RepositoryID, record.RepositoryPrefix, record.ShareID,
		record.RootKey, record.ReferenceKey, record.AuthorizationExpiresAt,
		record.RootCapabilityDigest, record.ClientEncryptionConfigured,
		record.AllowUnsignedReference, record.AllowCustomReferenceVerifier,
	})
	defer clear(encoded)
	return rootRecoveryDigest("identity", encoded)
}

func rootRecoveryClosureDigest(closure s3disk.SnapshotClosure) s3disk.Digest {
	hash := sha256.New()
	rootRecoveryWritePart(hash, []byte("closure"))
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], closure.Snapshot.Generation)
	rootRecoveryWritePart(hash, number[:])
	rootRecoveryWritePart(hash, closure.Snapshot.Commit[:])
	rootRecoveryWritePart(hash, closure.Snapshot.Root[:])
	binary.BigEndian.PutUint64(number[:], uint64(closure.Snapshot.PublishedAt.Unix()))
	rootRecoveryWritePart(hash, number[:])
	binary.BigEndian.PutUint64(number[:], uint64(closure.Snapshot.PublishedAt.Nanosecond()))
	rootRecoveryWritePart(hash, number[:])
	rootRecoveryWritePart(hash, []byte(closure.ReferenceKey))
	rootRecoveryWritePart(hash, closure.ReferenceData)
	rootRecoveryWritePart(hash, []byte(closure.ReferenceVersion.ETag))
	rootRecoveryWritePart(hash, []byte(closure.ReferenceVersion.VersionID))
	for _, key := range closure.ObjectKeys {
		rootRecoveryWritePart(hash, []byte(key))
	}
	var digest s3disk.Digest
	copy(digest[:], hash.Sum(nil))
	return digest
}

func rootRecoveryDigest(kind string, value []byte) s3disk.Digest {
	hash := sha256.New()
	_, _ = hash.Write(rootRecoveryDomain)
	rootRecoveryWritePart(hash, []byte(kind))
	rootRecoveryWritePart(hash, value)
	var digest s3disk.Digest
	copy(digest[:], hash.Sum(nil))
	return digest
}

func rootRecoveryWritePart(writer io.Writer, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

type loadedRootRecovery struct {
	record   rootRecoveryRecord
	target   []byte
	revision s3disk.SealedStateRevision
	found    bool
}

func (loaded *loadedRootRecovery) clear() {
	clear(loaded.target)
	loaded.target = nil
}

func (publisher *RootPublisher) loadRootRecovery(ctx context.Context) (loadedRootRecovery, error) {
	encoded, revision, found, err := publisher.recoveryJournal.Load(ctx)
	defer clear(encoded)
	if err != nil {
		return loadedRootRecovery{}, rootRecoveryJournalError("load", err)
	}
	if !found {
		if len(encoded) != 0 || !revision.IsZero() {
			return loadedRootRecovery{}, fmt.Errorf("%w: inconsistent absent journal load result", ErrRootRecoveryState)
		}
		record, err := publisher.newRootRecoveryRecord()
		if err != nil {
			return loadedRootRecovery{}, err
		}
		return loadedRootRecovery{record: record}, nil
	}
	if revision.IsZero() || len(encoded) < 1 || int64(len(encoded)) > MaximumRootRecoveryJournalBytes {
		return loadedRootRecovery{}, fmt.Errorf("%w: invalid journal load result", ErrRootRecoveryState)
	}
	record, target, err := decodeRootRecoveryRecord(encoded)
	if err != nil {
		return loadedRootRecovery{}, err
	}
	if err := publisher.validateRootRecoveryRecord(ctx, record, target); err != nil {
		clear(target)
		return loadedRootRecovery{}, err
	}
	return loadedRootRecovery{record: record, target: target, revision: revision, found: true}, nil
}

func (publisher *RootPublisher) saveRootRecovery(
	ctx context.Context,
	current loadedRootRecovery,
	next rootRecoveryRecord,
	target []byte,
) (loadedRootRecovery, error) {
	if err := publisher.validateRootRecoveryRecord(ctx, next, target); err != nil {
		return loadedRootRecovery{}, err
	}
	encoded, err := encodeRootRecoveryRecord(next, target)
	if err != nil {
		return loadedRootRecovery{}, err
	}
	defer clear(encoded)
	var expected *s3disk.SealedStateRevision
	if current.found {
		expected = &current.revision
	}
	candidate, casErr := publisher.recoveryJournal.CompareAndSwap(ctx, expected, encoded)
	if casErr == nil {
		if candidate.IsZero() {
			return loadedRootRecovery{}, fmt.Errorf("%w: journal CAS returned a zero revision", ErrRootRecoveryState)
		}
		return loadedRootRecovery{
			record: next, target: bytes.Clone(target), revision: candidate, found: true,
		}, nil
	}

	observed, loadErr := publisher.loadRootRecovery(ctx)
	if loadErr == nil {
		observedEncoded, encodeErr := encodeRootRecoveryRecord(observed.record, observed.target)
		if encodeErr == nil && bytes.Equal(observedEncoded, encoded) &&
			(candidate.IsZero() || observed.revision == candidate) {
			clear(observedEncoded)
			return observed, nil
		}
		clear(observedEncoded)
		observed.clear()
	}
	if errors.Is(casErr, s3disk.ErrPrecondition) {
		return loadedRootRecovery{}, ErrRootPublishConflict
	}
	if errors.Is(casErr, context.Canceled) {
		return loadedRootRecovery{}, errors.Join(ErrRootRecoveryIndeterminate, context.Canceled)
	}
	if errors.Is(casErr, context.DeadlineExceeded) {
		return loadedRootRecovery{}, errors.Join(ErrRootRecoveryIndeterminate, context.DeadlineExceeded)
	}
	return loadedRootRecovery{}, ErrRootRecoveryIndeterminate
}

type rootRecoveryObserved struct {
	raw           []byte
	version       s3disk.Version
	bundle        *Bundle
	logicalDigest s3disk.Digest
}

func (observed *rootRecoveryObserved) clear() {
	clear(observed.raw)
	observed.raw = nil
}

func (publisher *RootPublisher) loadRootForRecovery(ctx context.Context) (rootRecoveryObserved, bool, error) {
	maximum := int64(MaximumBundleBytes)
	if publisher.clientEncryption != nil {
		maximum += s3disk.ClientEncryptionCiphertextOverhead
	}
	object, err := publisher.store.Get(ctx, publisher.rootKey, s3disk.GetOptions{MaxBytes: maximum})
	if errors.Is(err, s3disk.ErrObjectNotFound) {
		clear(object.Data)
		return rootRecoveryObserved{}, false, nil
	}
	if err != nil {
		clear(object.Data)
		return rootRecoveryObserved{}, false, safeRootStoreError(err)
	}
	if err := validateRootVersion(object.Version); err != nil {
		clear(object.Data)
		return rootRecoveryObserved{}, false, err
	}
	bundle, logicalDigest, err := publisher.decodeRootStorageTarget(ctx, object.Data)
	if err != nil {
		clear(object.Data)
		return rootRecoveryObserved{}, false, err
	}
	return rootRecoveryObserved{
		raw: object.Data, version: object.Version, bundle: bundle, logicalDigest: logicalDigest,
	}, true, nil
}

func committedRootFromObservation(observed rootRecoveryObserved) *rootRecoveryCommitted {
	return &rootRecoveryCommitted{
		Revision: observed.bundle.revision, LogicalDigest: observed.logicalDigest,
		ReferenceGeneration: observed.bundle.referenceGeneration,
		ReferenceCommit:     observed.bundle.referenceCommit,
		ETag:                observed.version.ETag,
		VersionID:           observed.version.VersionID,
	}
}

func equalCommittedRoot(left, right *rootRecoveryCommitted) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func validateObservationAgainstAnchor(record rootRecoveryRecord, observed rootRecoveryObserved) error {
	if observed.bundle == nil {
		return fmt.Errorf("%w: nil authenticated root observation", ErrRootRecoveryState)
	}
	committed := record.Committed
	if committed == nil {
		return nil
	}
	if observed.bundle.revision < committed.Revision {
		return s3disk.ErrRollbackDetected
	}
	if observed.bundle.revision == committed.Revision {
		if observed.logicalDigest != committed.LogicalDigest {
			return s3disk.ErrSplitBrain
		}
		if observed.bundle.referenceGeneration != committed.ReferenceGeneration ||
			observed.bundle.referenceCommit != committed.ReferenceCommit {
			return fmt.Errorf("%w: committed anchor fields disagree", ErrRootRecoveryState)
		}
		return nil
	}
	if observed.bundle.referenceGeneration < committed.ReferenceGeneration {
		return s3disk.ErrRollbackDetected
	}
	if observed.bundle.referenceGeneration == committed.ReferenceGeneration &&
		observed.bundle.referenceCommit != committed.ReferenceCommit {
		return s3disk.ErrSplitBrain
	}
	return nil
}

func (publisher *RootPublisher) anchorRootObservation(
	ctx context.Context,
	current loadedRootRecovery,
	observed rootRecoveryObserved,
) (loadedRootRecovery, error) {
	if err := validateObservationAgainstAnchor(current.record, observed); err != nil {
		return loadedRootRecovery{}, err
	}
	committed := committedRootFromObservation(observed)
	if current.record.Pending == nil && current.record.HighestRevision == committed.Revision &&
		equalCommittedRoot(current.record.Committed, committed) {
		return current, nil
	}
	next := cloneRootRecoveryRecord(current.record)
	next.Pending = nil
	next.HighestRevision = committed.Revision
	next.Committed = committed
	return publisher.saveRootRecovery(ctx, current, next, nil)
}

func replaceLoadedRootRecovery(current *loadedRootRecovery, next loadedRootRecovery) {
	current.clear()
	*current = next
}

func rootRecoveryResultFromObservation(
	observed rootRecoveryObserved,
	hadPending bool,
	wroteRoot bool,
) RootRecoveryResult {
	return RootRecoveryResult{
		HadPending:          hadPending,
		PendingCleared:      hadPending,
		RootFound:           true,
		WroteRoot:           wroteRoot,
		Revision:            observed.bundle.revision,
		ReferenceGeneration: observed.bundle.referenceGeneration,
		ReferenceCommit:     observed.bundle.referenceCommit,
		Version:             observed.version,
	}
}

func (publisher *RootPublisher) recoverPending(ctx context.Context) (RootRecoveryResult, error) {
	recovery, err := publisher.loadRootRecovery(ctx)
	if err != nil {
		return RootRecoveryResult{}, err
	}
	defer func() { recovery.clear() }()
	if !recovery.found {
		return RootRecoveryResult{}, fmt.Errorf("%w: prepared recovery state is absent", ErrRootRecoveryState)
	}

	hadPending := recovery.record.Pending != nil
	var writeAttempts int
	var ambiguousWriteClass error
	for {
		if err := ctx.Err(); err != nil {
			if ambiguousWriteClass != nil {
				return RootRecoveryResult{}, rootPublishIndeterminateError(ambiguousWriteClass, err)
			}
			return RootRecoveryResult{}, err
		}
		if !publisher.rootCapability.expiresAt.After(time.Now()) {
			if ambiguousWriteClass != nil {
				return RootRecoveryResult{}, rootPublishIndeterminateError(ambiguousWriteClass, s3disk.ErrAccessDenied)
			}
			return RootRecoveryResult{}, fmt.Errorf("presignedshare: share authorization expired: %w", s3disk.ErrAccessDenied)
		}

		if recovery.record.Pending == nil {
			observed, found, err := publisher.loadRootForRecovery(ctx)
			if err != nil {
				return RootRecoveryResult{}, err
			}
			if err := ctx.Err(); err != nil {
				observed.clear()
				return RootRecoveryResult{}, err
			}
			if !publisher.rootCapability.expiresAt.After(time.Now()) {
				observed.clear()
				return RootRecoveryResult{}, fmt.Errorf("presignedshare: share authorization expired: %w", s3disk.ErrAccessDenied)
			}
			if !found {
				if recovery.record.Committed != nil || recovery.record.HighestRevision != 0 {
					return RootRecoveryResult{}, fmt.Errorf("%w: existing share root disappeared", s3disk.ErrRollbackDetected)
				}
				return RootRecoveryResult{}, nil
			}
			anchored, err := publisher.anchorRootObservation(ctx, recovery, observed)
			if err != nil {
				observed.clear()
				return RootRecoveryResult{}, err
			}
			result := rootRecoveryResultFromObservation(observed, hadPending, false)
			observed.clear()
			replaceLoadedRootRecovery(&recovery, anchored)
			return result, nil
		}

		pending := *recovery.record.Pending
		observed, found, err := publisher.loadRootForRecovery(ctx)
		if err != nil {
			return RootRecoveryResult{}, rootPublishIndeterminateError(ambiguousWriteClass, err)
		}
		if err := ctx.Err(); err != nil {
			observed.clear()
			return RootRecoveryResult{}, rootPublishIndeterminateError(ambiguousWriteClass, err)
		}
		if !publisher.rootCapability.expiresAt.After(time.Now()) {
			observed.clear()
			return RootRecoveryResult{}, rootPublishIndeterminateError(ambiguousWriteClass, s3disk.ErrAccessDenied)
		}
		if found && bytes.Equal(observed.raw, recovery.target) {
			anchored, err := publisher.anchorRootObservation(ctx, recovery, observed)
			if err != nil {
				observed.clear()
				return RootRecoveryResult{}, err
			}
			result := rootRecoveryResultFromObservation(observed, true, false)
			observed.clear()
			replaceLoadedRootRecovery(&recovery, anchored)
			return result, nil
		}

		if found {
			if err := validateObservationAgainstAnchor(recovery.record, observed); err != nil {
				observed.clear()
				return RootRecoveryResult{}, err
			}
			if observed.bundle.revision == pending.TargetRevision {
				if observed.logicalDigest != pending.LogicalTargetDigest {
					observed.clear()
					return RootRecoveryResult{}, s3disk.ErrSplitBrain
				}
				anchored, err := publisher.anchorRootObservation(ctx, recovery, observed)
				if err != nil {
					observed.clear()
					return RootRecoveryResult{}, err
				}
				result := rootRecoveryResultFromObservation(observed, true, false)
				observed.clear()
				replaceLoadedRootRecovery(&recovery, anchored)
				return result, nil
			}
			if observed.bundle.revision > pending.TargetRevision {
				anchored, err := publisher.anchorRootObservation(ctx, recovery, observed)
				if err != nil {
					observed.clear()
					return RootRecoveryResult{}, err
				}
				result := rootRecoveryResultFromObservation(observed, true, false)
				observed.clear()
				replaceLoadedRootRecovery(&recovery, anchored)
				return result, nil
			}
			if pending.ExpectedAbsent || recovery.record.Committed == nil ||
				observed.bundle.revision != recovery.record.Committed.Revision ||
				observed.logicalDigest != recovery.record.Committed.LogicalDigest {
				observed.clear()
				return RootRecoveryResult{}, s3disk.ErrRollbackDetected
			}
			baseDigest := rootRecoveryDigest("base", observed.raw)
			if pending.BaseDigest != baseDigest || pending.ExpectedETag != observed.version.ETag ||
				pending.ExpectedVersionID != observed.version.VersionID {
				nextRecord := cloneRootRecoveryRecord(recovery.record)
				nextRecord.Committed = committedRootFromObservation(observed)
				nextRecord.Pending.setExpected(observed.version, observed.raw)
				saved, err := publisher.saveRootRecovery(ctx, recovery, nextRecord, recovery.target)
				if err != nil {
					observed.clear()
					return RootRecoveryResult{}, err
				}
				replaceLoadedRootRecovery(&recovery, saved)
				pending = *recovery.record.Pending
			}
		} else if !pending.ExpectedAbsent {
			return RootRecoveryResult{}, fmt.Errorf("%w: root base disappeared during recovery", s3disk.ErrRollbackDetected)
		}
		observed.clear()

		targetBundle, logicalDigest, err := publisher.decodeRootStorageTarget(ctx, recovery.target)
		if err != nil || targetBundle == nil || logicalDigest != pending.LogicalTargetDigest ||
			targetBundle.revision != pending.TargetRevision ||
			targetBundle.referenceGeneration != pending.ReferenceGeneration ||
			targetBundle.referenceCommit != pending.ReferenceCommit {
			return RootRecoveryResult{}, fmt.Errorf("%w: pending target cannot be authenticated", ErrRootRecoveryState)
		}

		if writeAttempts >= publisher.maxAttempts {
			if ambiguousWriteClass != nil {
				return RootRecoveryResult{}, rootPublishIndeterminateError(ambiguousWriteClass)
			}
			return RootRecoveryResult{}, ErrRootPublishConflict
		}
		if err := ctx.Err(); err != nil {
			if ambiguousWriteClass != nil {
				return RootRecoveryResult{}, rootPublishIndeterminateError(ambiguousWriteClass, err)
			}
			return RootRecoveryResult{}, err
		}
		if !publisher.rootCapability.expiresAt.After(time.Now()) {
			if ambiguousWriteClass != nil {
				return RootRecoveryResult{}, rootPublishIndeterminateError(ambiguousWriteClass, s3disk.ErrAccessDenied)
			}
			return RootRecoveryResult{}, fmt.Errorf("presignedshare: share authorization expired: %w", s3disk.ErrAccessDenied)
		}
		writeAttempts++
		var version s3disk.Version
		if pending.ExpectedAbsent {
			version, err = publisher.store.PutIfAbsent(ctx, publisher.rootKey, recovery.target)
		} else {
			version, err = publisher.store.CompareAndSwap(ctx, publisher.rootKey, pending.expectedVersion(), recovery.target)
		}
		writeErr := err
		if writeErr == nil {
			writeErr = validateRootVersion(version)
		}
		if writeErr == nil {
			applied := rootRecoveryObserved{
				version: version, bundle: targetBundle, logicalDigest: pending.LogicalTargetDigest,
			}
			anchored, err := publisher.anchorRootObservation(ctx, recovery, applied)
			if err != nil {
				return RootRecoveryResult{}, err
			}
			result := rootRecoveryResultFromObservation(applied, true, true)
			replaceLoadedRootRecovery(&recovery, anchored)
			return result, nil
		}
		if errors.Is(writeErr, s3disk.ErrPrecondition) {
			continue
		}
		ambiguousWriteClass = errors.Join(ambiguousWriteClass, safeRootStoreError(writeErr))
		if errors.Is(writeErr, context.Canceled) {
			return RootRecoveryResult{}, rootPublishIndeterminateError(ambiguousWriteClass, context.Canceled)
		}
		if errors.Is(writeErr, context.DeadlineExceeded) {
			return RootRecoveryResult{}, rootPublishIndeterminateError(ambiguousWriteClass, context.DeadlineExceeded)
		}
	}
}

func (publisher *RootPublisher) validatePendingRootRequest(
	ctx context.Context,
	recovery loadedRootRecovery,
	closure s3disk.SnapshotClosure,
	allowCreate bool,
) (*Bundle, error) {
	pending := recovery.record.Pending
	if pending == nil || pending.AllowCreate != allowCreate ||
		pending.ClosureDigest != rootRecoveryClosureDigest(closure) {
		return nil, fmt.Errorf("%w: pending operation or closure mismatch", ErrRootRecoveryState)
	}
	bundle, logicalDigest, err := publisher.decodeRootStorageTarget(ctx, recovery.target)
	if err != nil || logicalDigest != pending.LogicalTargetDigest {
		return nil, fmt.Errorf("%w: pending target cannot be authenticated", ErrRootRecoveryState)
	}
	matches, err := rootBundleExactlyMatchesClosure(bundle, closure)
	if err != nil || !matches {
		return nil, fmt.Errorf("%w: pending target does not encode the requested closure", ErrRootRecoveryState)
	}
	return bundle, nil
}

func (publisher *RootPublisher) publishRecoverable(
	ctx context.Context,
	closure s3disk.SnapshotClosure,
	allowCreate bool,
) (RootPublication, error) {
	recovery, err := publisher.loadRootRecovery(ctx)
	if err != nil {
		return RootPublication{}, err
	}
	defer func() { recovery.clear() }()

	var writeAttempts int
	var ambiguousWriteClass error
	for {
		if err := ctx.Err(); err != nil {
			if ambiguousWriteClass != nil {
				return RootPublication{}, rootPublishIndeterminateError(ambiguousWriteClass, err)
			}
			return RootPublication{}, err
		}
		if !publisher.rootCapability.expiresAt.After(time.Now()) {
			if ambiguousWriteClass != nil {
				return RootPublication{}, rootPublishIndeterminateError(ambiguousWriteClass, s3disk.ErrAccessDenied)
			}
			return RootPublication{}, fmt.Errorf("presignedshare: share authorization expired: %w", s3disk.ErrAccessDenied)
		}

		if recovery.record.Pending == nil {
			observed, found, err := publisher.loadRootForRecovery(ctx)
			if err != nil {
				return RootPublication{}, err
			}
			if !found {
				if recovery.record.Committed != nil || recovery.record.HighestRevision != 0 || !allowCreate {
					return RootPublication{}, fmt.Errorf("%w: existing share root disappeared", s3disk.ErrRollbackDetected)
				}
			} else {
				anchored, err := publisher.anchorRootObservation(ctx, recovery, observed)
				if err != nil {
					observed.clear()
					return RootPublication{}, err
				}
				replaceLoadedRootRecovery(&recovery, anchored)

				matches, err := rootBundleExactlyMatchesClosure(observed.bundle, closure)
				if err != nil {
					observed.clear()
					return RootPublication{}, err
				}
				if matches {
					publication := RootPublication{
						Revision: observed.bundle.revision, Snapshot: closure.Snapshot,
						Version: observed.version, Updated: false,
					}
					observed.clear()
					return publication, nil
				}
				if allowCreate {
					observed.clear()
					return RootPublication{}, ErrRootPublishConflict
				}
				if closure.Snapshot.Generation < observed.bundle.referenceGeneration {
					observed.clear()
					return RootPublication{}, s3disk.ErrRollbackDetected
				}
				if closure.Snapshot.Generation == observed.bundle.referenceGeneration &&
					closure.Snapshot.Commit != observed.bundle.referenceCommit {
					observed.clear()
					return RootPublication{}, s3disk.ErrSplitBrain
				}
				if observed.bundle.revision == math.MaxUint64 {
					observed.clear()
					return RootPublication{}, s3disk.ErrGenerationExhausted
				}
			}

			if !configuredInterface(publisher.presigner) || !configuredInterface(publisher.signer) {
				observed.clear()
				return RootPublication{}, fmt.Errorf(
					"%w: signer and presigner are required to build a new recoverable root",
					ErrRootBuildAuthorityRequired,
				)
			}
			targetRevision := uint64(1)
			if found {
				targetRevision = observed.bundle.revision + 1
			}
			logicalTarget, err := BuildSnapshotBundle(ctx, SnapshotBundleInput{
				RootKey: publisher.rootKey, RootCapability: publisher.rootCapability,
				RepositoryPrefix: publisher.repositoryPrefix, ShareID: publisher.shareID,
				Revision: targetRevision, Closure: closure, Presigner: publisher.presigner,
			}, publisher.signer, publisher.verifier)
			if err != nil {
				observed.clear()
				return RootPublication{}, err
			}
			target, err := publisher.sealRootStorageTarget(logicalTarget)
			if err != nil {
				clear(logicalTarget)
				observed.clear()
				return RootPublication{}, err
			}
			nextRecord := cloneRootRecoveryRecord(recovery.record)
			nextRecord.HighestRevision = targetRevision
			nextRecord.Pending = &rootRecoveryPending{
				TargetRevision: targetRevision, AllowCreate: allowCreate, ExpectedAbsent: !found,
				ClosureDigest:       rootRecoveryClosureDigest(closure),
				TargetDigest:        rootRecoveryDigest("target", target),
				LogicalTargetDigest: rootRecoveryDigest("logical-root", logicalTarget),
				ReferenceGeneration: closure.Snapshot.Generation,
				ReferenceCommit:     closure.Snapshot.Commit,
			}
			if found {
				nextRecord.Pending.setExpected(observed.version, observed.raw)
			}
			saved, saveErr := publisher.saveRootRecovery(ctx, recovery, nextRecord, target)
			clear(logicalTarget)
			clear(target)
			observed.clear()
			if saveErr != nil {
				return RootPublication{}, saveErr
			}
			replaceLoadedRootRecovery(&recovery, saved)
			continue
		}

		pending := recovery.record.Pending
		observed, found, err := publisher.loadRootForRecovery(ctx)
		if err != nil {
			return RootPublication{}, rootPublishIndeterminateError(ambiguousWriteClass, err)
		}
		if found && bytes.Equal(observed.raw, recovery.target) {
			anchored, err := publisher.anchorRootObservation(ctx, recovery, observed)
			if err != nil {
				observed.clear()
				return RootPublication{}, err
			}
			matches, matchErr := rootBundleExactlyMatchesClosure(observed.bundle, closure)
			if matchErr != nil {
				observed.clear()
				return RootPublication{}, matchErr
			}
			version := observed.version
			observed.clear()
			replaceLoadedRootRecovery(&recovery, anchored)
			if matches {
				return RootPublication{
					Revision: pending.TargetRevision, Snapshot: closure.Snapshot,
					Version: version, Updated: true,
				}, nil
			}
			continue
		}

		if found {
			if err := validateObservationAgainstAnchor(recovery.record, observed); err != nil {
				observed.clear()
				return RootPublication{}, err
			}
			if observed.bundle.revision == pending.TargetRevision {
				if observed.logicalDigest != pending.LogicalTargetDigest {
					observed.clear()
					return RootPublication{}, s3disk.ErrSplitBrain
				}
				anchored, err := publisher.anchorRootObservation(ctx, recovery, observed)
				if err != nil {
					observed.clear()
					return RootPublication{}, err
				}
				matches, matchErr := rootBundleExactlyMatchesClosure(observed.bundle, closure)
				if matchErr != nil {
					observed.clear()
					return RootPublication{}, matchErr
				}
				version := observed.version
				observed.clear()
				replaceLoadedRootRecovery(&recovery, anchored)
				if matches {
					return RootPublication{
						Revision: pending.TargetRevision, Snapshot: closure.Snapshot,
						Version: version, Updated: false,
					}, nil
				}
				continue
			}
			if observed.bundle.revision > pending.TargetRevision {
				anchored, err := publisher.anchorRootObservation(ctx, recovery, observed)
				if err != nil {
					observed.clear()
					return RootPublication{}, err
				}
				matches, matchErr := rootBundleExactlyMatchesClosure(observed.bundle, closure)
				if matchErr != nil {
					observed.clear()
					return RootPublication{}, matchErr
				}
				publication := RootPublication{
					Revision: observed.bundle.revision, Snapshot: closure.Snapshot,
					Version: observed.version, Updated: false,
				}
				generation := observed.bundle.referenceGeneration
				commit := observed.bundle.referenceCommit
				observed.clear()
				replaceLoadedRootRecovery(&recovery, anchored)
				if matches {
					return publication, nil
				}
				if allowCreate {
					return RootPublication{}, ErrRootPublishConflict
				}
				if closure.Snapshot.Generation < generation {
					return RootPublication{}, s3disk.ErrRollbackDetected
				}
				if closure.Snapshot.Generation == generation && closure.Snapshot.Commit != commit {
					return RootPublication{}, s3disk.ErrSplitBrain
				}
				continue
			}
			if pending.ExpectedAbsent || recovery.record.Committed == nil ||
				observed.bundle.revision != recovery.record.Committed.Revision ||
				observed.logicalDigest != recovery.record.Committed.LogicalDigest {
				observed.clear()
				return RootPublication{}, s3disk.ErrRollbackDetected
			}
			baseDigest := rootRecoveryDigest("base", observed.raw)
			if pending.BaseDigest != baseDigest || pending.ExpectedETag != observed.version.ETag ||
				pending.ExpectedVersionID != observed.version.VersionID {
				nextRecord := cloneRootRecoveryRecord(recovery.record)
				nextRecord.Committed = committedRootFromObservation(observed)
				nextRecord.Pending.setExpected(observed.version, observed.raw)
				saved, err := publisher.saveRootRecovery(ctx, recovery, nextRecord, recovery.target)
				if err != nil {
					observed.clear()
					return RootPublication{}, err
				}
				replaceLoadedRootRecovery(&recovery, saved)
				pending = recovery.record.Pending
			}
		} else if !pending.ExpectedAbsent {
			return RootPublication{}, fmt.Errorf("%w: root base disappeared during recovery", s3disk.ErrRollbackDetected)
		}
		observed.clear()

		targetBundle, err := publisher.validatePendingRootRequest(ctx, recovery, closure, allowCreate)
		if err != nil {
			return RootPublication{}, err
		}

		if writeAttempts >= publisher.maxAttempts {
			if ambiguousWriteClass != nil {
				return RootPublication{}, rootPublishIndeterminateError(ambiguousWriteClass)
			}
			return RootPublication{}, ErrRootPublishConflict
		}
		if err := ctx.Err(); err != nil {
			if ambiguousWriteClass != nil {
				return RootPublication{}, rootPublishIndeterminateError(ambiguousWriteClass, err)
			}
			return RootPublication{}, err
		}
		if !publisher.rootCapability.expiresAt.After(time.Now()) {
			if ambiguousWriteClass != nil {
				return RootPublication{}, rootPublishIndeterminateError(ambiguousWriteClass, s3disk.ErrAccessDenied)
			}
			return RootPublication{}, fmt.Errorf("presignedshare: share authorization expired: %w", s3disk.ErrAccessDenied)
		}
		writeAttempts++
		var version s3disk.Version
		if pending.ExpectedAbsent {
			version, err = publisher.store.PutIfAbsent(ctx, publisher.rootKey, recovery.target)
		} else {
			version, err = publisher.store.CompareAndSwap(ctx, publisher.rootKey, pending.expectedVersion(), recovery.target)
		}
		writeErr := err
		if writeErr == nil {
			writeErr = validateRootVersion(version)
		}
		if writeErr == nil {
			applied := rootRecoveryObserved{
				version: version, bundle: targetBundle, logicalDigest: pending.LogicalTargetDigest,
			}
			anchored, err := publisher.anchorRootObservation(ctx, recovery, applied)
			if err != nil {
				return RootPublication{}, err
			}
			replaceLoadedRootRecovery(&recovery, anchored)
			return RootPublication{
				Revision: pending.TargetRevision, Snapshot: closure.Snapshot,
				Version: version, Updated: true,
			}, nil
		}
		if errors.Is(writeErr, s3disk.ErrPrecondition) {
			continue
		}
		ambiguousWriteClass = errors.Join(ambiguousWriteClass, safeRootStoreError(writeErr))
		if errors.Is(writeErr, context.Canceled) {
			return RootPublication{}, rootPublishIndeterminateError(ambiguousWriteClass, context.Canceled)
		}
		if errors.Is(writeErr, context.DeadlineExceeded) {
			return RootPublication{}, rootPublishIndeterminateError(ambiguousWriteClass, context.DeadlineExceeded)
		}
	}
}

func rootRecoveryJournalError(operation string, err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return errors.Join(ErrRootRecoveryIndeterminate, context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return errors.Join(ErrRootRecoveryIndeterminate, context.DeadlineExceeded)
	case errors.Is(err, s3disk.ErrPrecondition):
		return errors.Join(ErrRootRecoveryState, s3disk.ErrPrecondition)
	case errors.Is(err, s3disk.ErrResourceLimit):
		return errors.Join(ErrRootRecoveryState, s3disk.ErrResourceLimit)
	default:
		return fmt.Errorf("%w: journal %s failed", ErrRootRecoveryIndeterminate, operation)
	}
}
