package s3disk

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

const (
	// DefaultFileSealedStateMaxEnvelopeBytes is the finite envelope limit used
	// when FileSealedStateStoreOptions.MaxEnvelopeBytes is zero. It includes
	// headroom above a 64 MiB root-bundle plaintext and its AEAD envelope.
	DefaultFileSealedStateMaxEnvelopeBytes int64 = 65 << 20
	// FileSealedStateMaxEnvelopeBytesLimit is the hard allocation and file-size
	// ceiling accepted from configuration.
	FileSealedStateMaxEnvelopeBytesLimit int64 = 256 << 20
	// FileSealedStateMaxBindingBytes bounds the durable caller identity hashed
	// into every per-revision protector binding.
	FileSealedStateMaxBindingBytes = 64 << 10

	sealedStateFormatVersion          = uint16(1)
	sealedStateMagicBytes             = 8
	sealedStateVersionOffset          = sealedStateMagicBytes
	sealedStateReservedOffset         = sealedStateVersionOffset + 2
	sealedStateRevisionOffset         = sealedStateReservedOffset + 2
	sealedStateEnvelopeLengthOffset   = sealedStateRevisionOffset + sha256.Size
	sealedStateHeaderBytes            = sealedStateEnvelopeLengthOffset + 8
	sealedStateSealStabilizationLimit = 8
)

var (
	sealedStateMagic         = [sealedStateMagicBytes]byte{'s', '3', 'd', 's', 's', 0, 1, 0}
	sealedStateBindingDomain = []byte("s3disk\x00file-sealed-state\x00protector-binding\x00v1\x00")
)

// SealedStateRevision is an opaque random compare-and-swap revision. A
// present state always has a non-zero revision, and every successful write
// receives a fresh one even when its plaintext is unchanged.
type SealedStateRevision = Digest

// SealedStateProtector is the cryptographic boundary used by
// FileSealedStateStore. publisherstate.Protector directly satisfies this
// interface; the smaller method set also permits a keyring to change its
// active sealing key without changing the store dependency.
//
// CompareAndSwap may call Seal more than once to stabilize the envelope length
// authenticated by the outer header, then calls Open with the same binding to
// verify exact plaintext recovery before writing. Implementations must honor
// context, return a finite stable envelope length for the same input, and not
// retain, modify, or alias caller slices after returning. Returned errors must
// be safe for diagnostics and must not contain binding, plaintext, envelope,
// or key material.
type SealedStateProtector interface {
	Seal(ctx context.Context, binding, plaintext []byte) ([]byte, error)
	Open(ctx context.Context, binding, envelope []byte) ([]byte, error)
}

// SealedStateStore durably stores one opaque state value. A nil expected
// revision means "create only if absent". Any non-precondition write error may
// follow a visible rename, so callers reconcile uncertain outcomes with Load.
// A non-zero revision returned with an error is only a reconciliation candidate
// and must not be treated as proof that the write succeeded.
type SealedStateStore interface {
	Load(ctx context.Context) (state []byte, revision SealedStateRevision, found bool, err error)
	CompareAndSwap(ctx context.Context, expected *SealedStateRevision, next []byte) (SealedStateRevision, error)
}

// FileSealedStateStoreOptions configures a FileSealedStateStore. Binding must
// be a stable, non-secret encoding of the state role and durable repository or
// share identity. It is defensively copied and deliberately does not include
// the local path, so an explicitly restored state file may be relocated.
type FileSealedStateStoreOptions struct {
	Protector        SealedStateProtector
	Binding          []byte
	MaxEnvelopeBytes int64
}

func (options FileSealedStateStoreOptions) normalized() (FileSealedStateStoreOptions, error) {
	if !interfaceDependencyConfigured(options.Protector) {
		return FileSealedStateStoreOptions{}, fmt.Errorf("s3disk: sealed state protector is required and must not be a typed nil")
	}
	if len(options.Binding) < 1 || len(options.Binding) > FileSealedStateMaxBindingBytes {
		return FileSealedStateStoreOptions{}, fmt.Errorf("%w: sealed state binding must contain between 1 and %d bytes", ErrResourceLimit, FileSealedStateMaxBindingBytes)
	}
	if options.MaxEnvelopeBytes == 0 {
		options.MaxEnvelopeBytes = DefaultFileSealedStateMaxEnvelopeBytes
	}
	if options.MaxEnvelopeBytes < 1 || options.MaxEnvelopeBytes > FileSealedStateMaxEnvelopeBytesLimit {
		return FileSealedStateStoreOptions{}, fmt.Errorf(
			"%w: sealed state envelope limit must be between 1 and %d bytes",
			ErrResourceLimit, FileSealedStateMaxEnvelopeBytesLimit,
		)
	}
	options.Binding = bytes.Clone(options.Binding)
	return options, nil
}

// FileSealedStateStore stores one encrypted, crash-safe state value. It uses a
// same-directory process lock, a same-directory temporary file, file fsync,
// atomic replacement, and a parent-directory durability barrier.
//
// The outer revision and complete canonical outer header are authenticated by
// the injected protector. This prevents undetected header substitution, but it
// does not provide freshness: replaying an older complete state file can still
// authenticate. Applications needing rollback detection must anchor a
// monotonic value outside this file or validate it against external state.
type FileSealedStateStore struct {
	path             string
	lockPath         string
	protector        SealedStateProtector
	binding          []byte
	maxEnvelopeBytes int64
	gate             chan struct{}

	// Per-instance so tests can inject the post-rename crash window without a
	// process-global hook or race.
	syncDirectory func(string) error
}

// NewFileSealedStateStore prepares the protected parent directory and returns
// a store bound to one exact logical state identity. No state file is created
// until the first successful CompareAndSwap.
func NewFileSealedStateStore(path string, options FileSealedStateStoreOptions) (*FileSealedStateStore, error) {
	if path == "" {
		return nil, fmt.Errorf("s3disk: empty sealed state path")
	}
	normalized, err := options.normalized()
	if err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("s3disk: absolute sealed state path: %w", err)
	}
	directory, err := prepareWatermarkDirectory(filepath.Dir(absolute))
	if err != nil {
		return nil, fmt.Errorf("s3disk: create sealed state directory: %w", err)
	}
	// Sealed state has a stricter confidentiality contract than a watermark:
	// fail during construction on platforms which cannot prove current-owner
	// private-file semantics instead of falling back at first write.
	if err := validatePrivateSecretDirectory(directory); err != nil {
		return nil, fmt.Errorf("s3disk: validate sealed state directory: %w", err)
	}
	absolute = filepath.Join(directory, filepath.Base(absolute))
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &FileSealedStateStore{
		path: absolute, lockPath: absolute + ".lock", protector: normalized.Protector,
		binding: normalized.Binding, maxEnvelopeBytes: normalized.MaxEnvelopeBytes,
		gate: gate, syncDirectory: syncWatermarkDirectory,
	}, nil
}

// Load returns an independently owned plaintext only after the visible state
// and its parent-directory namespace have both crossed a durability barrier.
func (store *FileSealedStateStore) Load(ctx context.Context) (state []byte, revision SealedStateRevision, found bool, resultErr error) {
	if ctx == nil {
		return nil, SealedStateRevision{}, false, fmt.Errorf("s3disk: sealed state Load context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, SealedStateRevision{}, false, err
	}
	if !store.configured() {
		return nil, SealedStateRevision{}, false, fmt.Errorf("s3disk: sealed state store is not configured")
	}
	if err := store.acquire(ctx); err != nil {
		return nil, SealedStateRevision{}, false, err
	}
	defer store.release()
	unlock, err := lockSealedStateFile(ctx, store.lockPath)
	if err != nil {
		return nil, SealedStateRevision{}, false, err
	}
	state, revision, found, loadErr := store.loadLocked(ctx)
	if loadErr == nil && found {
		loadErr = store.syncParentDirectory()
	}
	unlockErr := unlock()
	if loadErr != nil || unlockErr != nil {
		clear(state)
		return nil, SealedStateRevision{}, false, errors.Join(loadErr, unlockErr)
	}
	return state, revision, found, nil
}

func (store *FileSealedStateStore) loadLocked(ctx context.Context) ([]byte, SealedStateRevision, bool, error) {
	linked, err := os.Lstat(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, SealedStateRevision{}, false, nil
	}
	if err != nil {
		return nil, SealedStateRevision{}, false, fmt.Errorf("s3disk: inspect sealed state: %w", err)
	}
	file, err := os.Open(store.path)
	if err != nil {
		return nil, SealedStateRevision{}, false, fmt.Errorf("s3disk: open sealed state: %w", err)
	}
	defer file.Close()
	if !linked.Mode().IsRegular() {
		return nil, SealedStateRevision{}, false, fmt.Errorf("%w: sealed state path is not a regular file", ErrCorruptObject)
	}
	if err := validatePrivateSecretFile(store.path, file); err != nil {
		return nil, SealedStateRevision{}, false, fmt.Errorf("s3disk: validate sealed state file: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		return nil, SealedStateRevision{}, false, fmt.Errorf("s3disk: stat sealed state: %w", err)
	}
	maximumFileBytes := int64(sealedStateHeaderBytes) + store.maxEnvelopeBytes
	if info.Size() < sealedStateHeaderBytes+1 {
		return nil, SealedStateRevision{}, false, fmt.Errorf("%w: truncated sealed state", ErrCorruptObject)
	}
	if info.Size() > maximumFileBytes {
		return nil, SealedStateRevision{}, false, fmt.Errorf(
			"%w: %w: sealed state exceeds %d bytes", ErrCorruptObject, ErrResourceLimit, maximumFileBytes,
		)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumFileBytes+1))
	if err != nil {
		return nil, SealedStateRevision{}, false, fmt.Errorf("s3disk: read sealed state: %w", err)
	}
	defer clear(data)
	if err := ctx.Err(); err != nil {
		return nil, SealedStateRevision{}, false, err
	}
	if int64(len(data)) > maximumFileBytes {
		return nil, SealedStateRevision{}, false, fmt.Errorf(
			"%w: %w: sealed state exceeds %d bytes", ErrCorruptObject, ErrResourceLimit, maximumFileBytes,
		)
	}
	prefix, revision, envelope, err := parseSealedStateFile(data, store.maxEnvelopeBytes)
	if err != nil {
		return nil, SealedStateRevision{}, false, err
	}
	protectorBinding := deriveSealedStateProtectorBinding(store.binding, prefix)
	protectorEnvelope := bytes.Clone(envelope)
	protectorOpened, err := store.protector.Open(ctx, protectorBinding, protectorEnvelope)
	if err != nil {
		clear(protectorOpened)
		clear(protectorEnvelope)
		clear(protectorBinding)
		return nil, SealedStateRevision{}, false, fmt.Errorf("s3disk: open sealed state envelope: %w", err)
	}
	if int64(len(protectorOpened)) > store.maxEnvelopeBytes {
		clear(protectorOpened)
		clear(protectorEnvelope)
		clear(protectorBinding)
		return nil, SealedStateRevision{}, false, fmt.Errorf("%w: opened sealed state exceeds configured limit", ErrResourceLimit)
	}
	opened := bytes.Clone(protectorOpened)
	clear(protectorOpened)
	clear(protectorEnvelope)
	clear(protectorBinding)
	if err := ctx.Err(); err != nil {
		clear(opened)
		return nil, SealedStateRevision{}, false, err
	}
	return opened, revision, true, nil
}

// CompareAndSwap installs next only if expected matches the durable current
// revision. A nil expected revision requires the file to be absent. A non-zero
// revision returned together with an error identifies a candidate which may
// have reached rename; only a subsequent successful Load can reconcile it.
func (store *FileSealedStateStore) CompareAndSwap(
	ctx context.Context,
	expected *SealedStateRevision,
	next []byte,
) (revision SealedStateRevision, resultErr error) {
	if ctx == nil {
		return SealedStateRevision{}, fmt.Errorf("s3disk: sealed state CompareAndSwap context is required")
	}
	if err := ctx.Err(); err != nil {
		return SealedStateRevision{}, err
	}
	if !store.configured() {
		return SealedStateRevision{}, fmt.Errorf("s3disk: sealed state store is not configured")
	}
	if int64(len(next)) > store.maxEnvelopeBytes {
		return SealedStateRevision{}, fmt.Errorf("%w: sealed state plaintext exceeds configured envelope limit", ErrResourceLimit)
	}
	next = bytes.Clone(next)
	defer clear(next)
	var expectedValue SealedStateRevision
	if expected != nil {
		expectedValue = *expected
	}

	if err := store.acquire(ctx); err != nil {
		return SealedStateRevision{}, err
	}
	defer store.release()
	unlock, err := lockSealedStateFile(ctx, store.lockPath)
	if err != nil {
		return SealedStateRevision{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()

	currentState, currentRevision, found, err := store.loadLocked(ctx)
	clear(currentState)
	if err != nil {
		return SealedStateRevision{}, err
	}
	if found {
		// A visible current file may come from a process which died between
		// rename and parent fsync. It is not a valid CAS base, and even a stale
		// precondition result is not durable evidence, until this barrier passes.
		if err := store.syncParentDirectory(); err != nil {
			return SealedStateRevision{}, err
		}
	}
	if expected == nil {
		if found {
			return SealedStateRevision{}, ErrPrecondition
		}
	} else if !found || currentRevision != expectedValue {
		return SealedStateRevision{}, ErrPrecondition
	}
	if err := ctx.Err(); err != nil {
		return SealedStateRevision{}, err
	}
	var forbidden *SealedStateRevision
	if found {
		forbidden = &currentRevision
	}
	candidate, err := newFileSealedStateRevision(forbidden)
	if err != nil {
		return SealedStateRevision{}, err
	}
	prefix, envelope, err := store.sealForRevision(ctx, candidate, next)
	if err != nil {
		return SealedStateRevision{}, err
	}
	defer clear(envelope)
	if err := ctx.Err(); err != nil {
		return SealedStateRevision{}, err
	}

	directory := filepath.Dir(store.path)
	temporary, err := os.CreateTemp(directory, ".s3disk-sealed-state-*")
	if err != nil {
		return SealedStateRevision{}, fmt.Errorf("s3disk: create sealed state temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := protectWatermarkFile(temporaryName, temporary); err != nil {
		_ = temporary.Close()
		return SealedStateRevision{}, fmt.Errorf("s3disk: protect sealed state temporary file: %w", err)
	}
	if err := validatePrivateSecretFile(temporaryName, temporary); err != nil {
		_ = temporary.Close()
		return SealedStateRevision{}, fmt.Errorf("s3disk: validate sealed state temporary file: %w", err)
	}
	if err := writeSealedStateFile(temporary, prefix, envelope); err != nil {
		_ = temporary.Close()
		return SealedStateRevision{}, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return SealedStateRevision{}, fmt.Errorf("s3disk: sync sealed state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return SealedStateRevision{}, fmt.Errorf("s3disk: close sealed state: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return SealedStateRevision{}, err
	}
	// From this point forward an error may be an applied-but-unacknowledged
	// rename. Preserve the authenticated candidate so the caller can compare it
	// with a subsequent Load; it is not a success indication by itself.
	revision = candidate
	if err := installWatermarkFile(temporaryName, store.path); err != nil {
		return revision, fmt.Errorf("s3disk: install sealed state: %w", err)
	}
	removeTemporary = false
	if err := validateInstalledSealedStateFile(store.path); err != nil {
		return revision, err
	}
	if err := store.syncParentDirectory(); err != nil {
		return revision, err
	}
	return revision, nil
}

func (store *FileSealedStateStore) sealForRevision(
	ctx context.Context,
	revision SealedStateRevision,
	plaintext []byte,
) ([]byte, []byte, error) {
	want := bytes.Clone(plaintext)
	defer clear(want)
	sealedLength := 1
	for attempt := 0; attempt < sealedStateSealStabilizationLimit; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		prefix := encodeSealedStatePrefix(revision, sealedLength)
		sealBinding := deriveSealedStateProtectorBinding(store.binding, prefix)
		sealPlaintext := bytes.Clone(want)
		protectorEnvelope, err := store.protector.Seal(ctx, sealBinding, sealPlaintext)
		if err != nil {
			clear(protectorEnvelope)
			clear(sealPlaintext)
			clear(sealBinding)
			return nil, nil, fmt.Errorf("s3disk: seal state envelope: %w", err)
		}
		if len(protectorEnvelope) < 1 || int64(len(protectorEnvelope)) > store.maxEnvelopeBytes {
			clear(protectorEnvelope)
			clear(sealPlaintext)
			clear(sealBinding)
			return nil, nil, fmt.Errorf("%w: sealed state envelope exceeds configured limit", ErrResourceLimit)
		}
		envelope := bytes.Clone(protectorEnvelope)
		clear(protectorEnvelope)
		clear(sealPlaintext)
		clear(sealBinding)
		if len(envelope) != sealedLength {
			sealedLength = len(envelope)
			clear(envelope)
			continue
		}

		openBinding := deriveSealedStateProtectorBinding(store.binding, prefix)
		openEnvelope := bytes.Clone(envelope)
		protectorOpened, openErr := store.protector.Open(ctx, openBinding, openEnvelope)
		if openErr != nil {
			clear(protectorOpened)
			clear(openEnvelope)
			clear(openBinding)
			clear(envelope)
			return nil, nil, fmt.Errorf("s3disk: self-check sealed state envelope: %w", openErr)
		}
		if int64(len(protectorOpened)) > store.maxEnvelopeBytes {
			clear(protectorOpened)
			clear(openEnvelope)
			clear(openBinding)
			clear(envelope)
			return nil, nil, fmt.Errorf("%w: protector self-check plaintext exceeds configured limit", ErrResourceLimit)
		}
		opened := bytes.Clone(protectorOpened)
		clear(protectorOpened)
		clear(openEnvelope)
		clear(openBinding)
		matches := bytes.Equal(opened, want)
		clear(opened)
		if !matches {
			clear(envelope)
			return nil, nil, fmt.Errorf("s3disk: sealed state protector self-check mismatch")
		}
		if err := ctx.Err(); err != nil {
			clear(envelope)
			return nil, nil, err
		}
		return prefix, envelope, nil
	}
	return nil, nil, fmt.Errorf("s3disk: sealed state envelope length did not stabilize")
}

func parseSealedStateFile(data []byte, maximumEnvelopeBytes int64) ([]byte, SealedStateRevision, []byte, error) {
	if len(data) < sealedStateHeaderBytes+1 {
		return nil, SealedStateRevision{}, nil, fmt.Errorf("%w: truncated sealed state", ErrCorruptObject)
	}
	if !bytes.Equal(data[:sealedStateMagicBytes], sealedStateMagic[:]) ||
		binary.BigEndian.Uint16(data[sealedStateVersionOffset:]) != sealedStateFormatVersion ||
		binary.BigEndian.Uint16(data[sealedStateReservedOffset:]) != 0 {
		return nil, SealedStateRevision{}, nil, fmt.Errorf("%w: invalid sealed state header", ErrCorruptObject)
	}
	var revision SealedStateRevision
	copy(revision[:], data[sealedStateRevisionOffset:sealedStateEnvelopeLengthOffset])
	sealedLength := binary.BigEndian.Uint64(data[sealedStateEnvelopeLengthOffset:sealedStateHeaderBytes])
	if revision.IsZero() || sealedLength < 1 || sealedLength > uint64(maximumEnvelopeBytes) {
		return nil, SealedStateRevision{}, nil, fmt.Errorf("%w: invalid sealed state revision or length", ErrCorruptObject)
	}
	if uint64(len(data)-sealedStateHeaderBytes) != sealedLength {
		return nil, SealedStateRevision{}, nil, fmt.Errorf("%w: non-canonical sealed state length", ErrCorruptObject)
	}
	prefix := encodeSealedStatePrefix(revision, int(sealedLength))
	if !bytes.Equal(prefix, data[:sealedStateHeaderBytes]) {
		return nil, SealedStateRevision{}, nil, fmt.Errorf("%w: non-canonical sealed state header", ErrCorruptObject)
	}
	return data[:sealedStateHeaderBytes], revision, data[sealedStateHeaderBytes:], nil
}

func encodeSealedStatePrefix(revision SealedStateRevision, sealedLength int) []byte {
	prefix := make([]byte, sealedStateHeaderBytes)
	copy(prefix, sealedStateMagic[:])
	binary.BigEndian.PutUint16(prefix[sealedStateVersionOffset:], sealedStateFormatVersion)
	binary.BigEndian.PutUint16(prefix[sealedStateReservedOffset:], 0)
	copy(prefix[sealedStateRevisionOffset:], revision[:])
	binary.BigEndian.PutUint64(prefix[sealedStateEnvelopeLengthOffset:], uint64(sealedLength))
	return prefix
}

func deriveSealedStateProtectorBinding(callerBinding, canonicalPrefix []byte) []byte {
	hash := sha256.New()
	_, _ = hash.Write(sealedStateBindingDomain)
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(callerBinding)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(callerBinding)
	binary.BigEndian.PutUint64(length[:], uint64(len(canonicalPrefix)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(canonicalPrefix)
	return hash.Sum(nil)
}

func newFileSealedStateRevision(forbidden *SealedStateRevision) (SealedStateRevision, error) {
	for {
		var revision SealedStateRevision
		if _, err := io.ReadFull(cryptorand.Reader, revision[:]); err != nil {
			return SealedStateRevision{}, fmt.Errorf("s3disk: generate sealed state revision: %w", err)
		}
		if !revision.IsZero() && (forbidden == nil || revision != *forbidden) {
			return revision, nil
		}
	}
}

func writeSealedStateFile(file *os.File, prefix, envelope []byte) error {
	for _, part := range [][]byte{prefix, envelope} {
		written, err := file.Write(part)
		if err != nil {
			return fmt.Errorf("s3disk: write sealed state: %w", err)
		}
		if written != len(part) {
			return fmt.Errorf("s3disk: write sealed state: %w", io.ErrShortWrite)
		}
	}
	return nil
}

func validateInstalledSealedStateFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("s3disk: open installed sealed state: %w", err)
	}
	defer file.Close()
	if err := validatePrivateSecretFile(path, file); err != nil {
		return fmt.Errorf("s3disk: validate installed sealed state: %w", err)
	}
	return nil
}

func lockSealedStateFile(ctx context.Context, path string) (func() error, error) {
	switch runtime.GOOS {
	case "darwin", "dragonfly", "freebsd", "linux", "netbsd", "openbsd", "windows":
		return lockWatermarkFile(ctx, path)
	default:
		return nil, fmt.Errorf("%w: sealed state requires an inter-process file lock on %s", ErrTrustStateUnsupported, runtime.GOOS)
	}
}

func (store *FileSealedStateStore) syncParentDirectory() error {
	syncDirectory := store.syncDirectory
	if syncDirectory == nil {
		syncDirectory = syncWatermarkDirectory
	}
	return syncDirectory(filepath.Dir(store.path))
}

func (store *FileSealedStateStore) acquire(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-store.gate:
		if err := ctx.Err(); err != nil {
			store.release()
			return err
		}
		return nil
	}
}

func (store *FileSealedStateStore) release() {
	store.gate <- struct{}{}
}

func (store *FileSealedStateStore) configured() bool {
	return store != nil && store.path != "" && store.lockPath != "" &&
		interfaceDependencyConfigured(store.protector) && len(store.binding) > 0 &&
		int64(len(store.binding)) <= FileSealedStateMaxBindingBytes &&
		store.maxEnvelopeBytes > 0 && store.maxEnvelopeBytes <= FileSealedStateMaxEnvelopeBytesLimit &&
		store.gate != nil
}

func (store *FileSealedStateStore) String() string {
	return fmt.Sprintf("s3disk.FileSealedStateStore{configured:%t,secrets:redacted}", store.configured())
}

func (store *FileSealedStateStore) GoString() string { return store.String() }

func (store *FileSealedStateStore) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Configured bool   `json:"configured"`
		Secrets    string `json:"secrets"`
	}{Configured: store.configured(), Secrets: "redacted"})
}

var _ SealedStateStore = (*FileSealedStateStore)(nil)
