package s3disk

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const publicationJournalFormatVersion = 1
const maxPublicationJournalBytes = 32 << 10

// PublicationJournalRevision is an opaque revision used for journal
// compare-and-swap operations. Revisions are random rather than derived from
// the state so that replacing a state with the same value still invalidates
// stale writers.
type PublicationJournalRevision = Digest

// PublicationIntentKind describes the mutable-reference operation protected
// by a publication journal entry.
type PublicationIntentKind string

const (
	PublicationIntentPublish PublicationIntentKind = "publish"
	PublicationIntentResign  PublicationIntentKind = "resign"
)

// PublicationIntent records one exact mutable-reference compare-and-swap.
// Reference owns the bytes which should become visible. ExpectedReference is
// a digest of the reference bytes observed together with ExpectedVersion.
type PublicationIntent struct {
	IntentID          Digest
	Kind              PublicationIntentKind
	Base              *Watermark
	Next              Watermark
	ExpectedVersion   *Version
	ExpectedReference Digest
	Reference         []byte
}

// PublicationJournalState contains the highest locally committed publication
// and, at most, one remote compare-and-swap which may be in flight. Use a
// distinct journal path for every repository/channel pair.
type PublicationJournalState struct {
	RepositoryID RepositoryID
	Channel      string
	Committed    *Watermark
	Pending      *PublicationIntent
}

// PublicationJournalStore durably and linearly serializes publication intents.
// CompareAndSwap must be atomic across every publisher for one repository and
// channel, remain durable after success, and reject a mismatched revision with
// ErrPrecondition without changing state. A nil expected revision requires the
// state to be absent. Revisions returned for present state must be non-zero and
// change after every successful CAS. Implementations must not retain or return
// aliased mutable slices. Load must return only state whose namespace update is
// durable against a later machine crash, including when another process died
// after making a rename visible but before syncing its parent directory.
// Callers reconcile an error because a CAS may have become durable before its
// response was lost.
type PublicationJournalStore interface {
	Load(ctx context.Context, channel string) (PublicationJournalState, PublicationJournalRevision, bool, error)
	CompareAndSwap(ctx context.Context, channel string, expected *PublicationJournalRevision, next PublicationJournalState) (PublicationJournalRevision, error)
}

// FilePublicationJournal stores a single channel's publication state in one
// crash-safe local file.
type FilePublicationJournal struct {
	path     string
	lockPath string
	mu       sync.Mutex

	// Per-instance so tests can inject the post-rename crash window without a
	// process-global hook or race.
	syncDirectory func(string) error
}

type publicationJournalFile struct {
	Format       int                           `json:"format"`
	Revision     Digest                        `json:"revision"`
	RepositoryID RepositoryID                  `json:"repository_id"`
	Channel      string                        `json:"channel"`
	Committed    *publicationJournalWatermark  `json:"committed,omitempty"`
	Pending      *publicationJournalIntentFile `json:"pending,omitempty"`
	Checksum     Digest                        `json:"checksum"`
}

type publicationJournalPayload struct {
	Format       int                           `json:"format"`
	Revision     Digest                        `json:"revision"`
	RepositoryID RepositoryID                  `json:"repository_id"`
	Channel      string                        `json:"channel"`
	Committed    *publicationJournalWatermark  `json:"committed,omitempty"`
	Pending      *publicationJournalIntentFile `json:"pending,omitempty"`
}

type publicationJournalWatermark struct {
	RepositoryID RepositoryID `json:"repository_id"`
	Generation   uint64       `json:"generation"`
	Commit       Digest       `json:"commit"`
}

type publicationJournalIntentFile struct {
	IntentID          Digest                       `json:"intent_id"`
	Kind              PublicationIntentKind        `json:"kind"`
	Base              *publicationJournalWatermark `json:"base,omitempty"`
	Next              publicationJournalWatermark  `json:"next"`
	ExpectedVersion   *publicationJournalVersion   `json:"expected_version,omitempty"`
	ExpectedReference Digest                       `json:"expected_reference"`
	Reference         []byte                       `json:"reference"`
}

type publicationJournalVersion struct {
	ETag      string `json:"etag"`
	VersionID string `json:"version_id,omitempty"`
}

type publicationIntentIdentity struct {
	Format       int                          `json:"format"`
	RepositoryID RepositoryID                 `json:"repository_id"`
	Channel      string                       `json:"channel"`
	Kind         PublicationIntentKind        `json:"kind"`
	Base         *publicationJournalWatermark `json:"base,omitempty"`
	Next         publicationJournalWatermark  `json:"next"`
	Reference    []byte                       `json:"reference"`
}

// NewFilePublicationJournal constructs a crash-safe single-file publication
// journal. The parent directory is created with the same platform-specific
// protections as FileWatermarkStore.
func NewFilePublicationJournal(path string) (*FilePublicationJournal, error) {
	if path == "" {
		return nil, fmt.Errorf("s3disk: empty publication journal path")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("s3disk: absolute publication journal path: %w", err)
	}
	directory, err := prepareWatermarkDirectory(filepath.Dir(absolute))
	if err != nil {
		return nil, fmt.Errorf("s3disk: create publication journal directory: %w", err)
	}
	absolute = filepath.Join(directory, filepath.Base(absolute))
	return &FilePublicationJournal{
		path: absolute, lockPath: absolute + ".lock", syncDirectory: syncWatermarkDirectory,
	}, nil
}

// Load returns an independently owned copy of the durable journal state.
func (journal *FilePublicationJournal) Load(ctx context.Context, channel string) (PublicationJournalState, PublicationJournalRevision, bool, error) {
	if err := ctx.Err(); err != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, err
	}
	if err := validateChannel(channel); err != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, err
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	unlock, err := lockWatermarkFile(ctx, journal.lockPath)
	if err != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, err
	}
	state, revision, found, loadErr := journal.loadLocked(channel)
	if loadErr == nil && found {
		// A writer may have died after rename made this state visible but before
		// syncing the directory. Never let a recovery update S3 from that state
		// until this process has completed the durability barrier.
		loadErr = journal.syncParentDirectory()
	}
	unlockErr := unlock()
	if loadErr != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, loadErr
	}
	if unlockErr != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, unlockErr
	}
	return state, revision, found, nil
}

func (journal *FilePublicationJournal) loadLocked(channel string) (PublicationJournalState, PublicationJournalRevision, bool, error) {
	linkInfo, err := os.Lstat(journal.path)
	if errors.Is(err, os.ErrNotExist) {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, nil
	}
	if err != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, fmt.Errorf("s3disk: inspect publication journal: %w", err)
	}
	file, err := os.Open(journal.path)
	if err != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, fmt.Errorf("s3disk: open publication journal: %w", err)
	}
	defer file.Close()
	info, err := validateWatermarkOpenedPath(journal.path, linkInfo, file, false)
	if err != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, err
	}
	if info.Size() < 1 {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, fmt.Errorf("%w: empty publication journal", ErrCorruptObject)
	}
	if info.Size() > maxPublicationJournalBytes {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, fmt.Errorf("%w: %w: publication journal exceeds %d bytes", ErrCorruptObject, ErrResourceLimit, maxPublicationJournalBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPublicationJournalBytes+1))
	if err != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, fmt.Errorf("s3disk: read publication journal: %w", err)
	}
	if len(data) > maxPublicationJournalBytes {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, fmt.Errorf("%w: %w: publication journal exceeds %d bytes", ErrCorruptObject, ErrResourceLimit, maxPublicationJournalBytes)
	}
	var disk publicationJournalFile
	if err := decodeJSON(data, &disk); err != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, fmt.Errorf("s3disk: decode publication journal: %w", err)
	}
	if disk.Format != publicationJournalFormatVersion || disk.Revision.IsZero() || disk.Checksum.IsZero() {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, fmt.Errorf("%w: invalid publication journal header", ErrCorruptObject)
	}
	wantChecksum, err := publicationJournalChecksum(disk)
	if err != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, err
	}
	if disk.Checksum != wantChecksum {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, fmt.Errorf("%w: publication journal checksum mismatch", ErrCorruptObject)
	}
	state := publicationJournalStateFromFile(disk)
	if state.Channel != channel {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, fmt.Errorf("%w: publication journal channel mismatch", ErrCorruptObject)
	}
	if err := validatePublicationJournalState(state); err != nil {
		return PublicationJournalState{}, PublicationJournalRevision{}, false, fmt.Errorf("s3disk: invalid publication journal state: %w", err)
	}
	return state, disk.Revision, true, nil
}

// CompareAndSwap atomically installs next if the durable revision exactly
// matches expected. It returns the newly generated revision on success.
func (journal *FilePublicationJournal) CompareAndSwap(
	ctx context.Context,
	channel string,
	expected *PublicationJournalRevision,
	next PublicationJournalState,
) (revision PublicationJournalRevision, resultErr error) {
	if err := ctx.Err(); err != nil {
		return PublicationJournalRevision{}, err
	}
	if err := validateChannel(channel); err != nil {
		return PublicationJournalRevision{}, err
	}
	next = clonePublicationJournalState(next)
	if next.Channel != channel {
		return PublicationJournalRevision{}, fmt.Errorf("%w: publication journal channel mismatch", ErrCorruptObject)
	}
	if err := validatePublicationJournalState(next); err != nil {
		return PublicationJournalRevision{}, err
	}

	journal.mu.Lock()
	defer journal.mu.Unlock()
	unlock, err := lockWatermarkFile(ctx, journal.lockPath)
	if err != nil {
		return PublicationJournalRevision{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()

	current, currentRevision, found, err := journal.loadLocked(channel)
	if err != nil {
		return PublicationJournalRevision{}, err
	}
	if expected == nil {
		if found {
			return PublicationJournalRevision{}, ErrPrecondition
		}
	} else if !found || currentRevision != *expected {
		return PublicationJournalRevision{}, ErrPrecondition
	}
	if found {
		if err := validatePublicationJournalTransition(current, next); err != nil {
			return PublicationJournalRevision{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return PublicationJournalRevision{}, err
	}
	var forbiddenRevision *PublicationJournalRevision
	if found {
		forbiddenRevision = &currentRevision
	}
	revision, err = newPublicationJournalRevision(forbiddenRevision)
	if err != nil {
		return PublicationJournalRevision{}, err
	}
	disk := publicationJournalFileFromState(next, revision)
	disk.Checksum, err = publicationJournalChecksum(disk)
	if err != nil {
		return PublicationJournalRevision{}, err
	}
	data, err := canonicalJSON(disk)
	if err != nil {
		return PublicationJournalRevision{}, fmt.Errorf("s3disk: encode publication journal: %w", err)
	}
	if len(data) > maxPublicationJournalBytes {
		return PublicationJournalRevision{}, fmt.Errorf("%w: publication journal exceeds %d bytes", ErrResourceLimit, maxPublicationJournalBytes)
	}

	directory := filepath.Dir(journal.path)
	temporary, err := os.CreateTemp(directory, ".s3disk-publication-journal-*")
	if err != nil {
		return PublicationJournalRevision{}, fmt.Errorf("s3disk: create publication journal temporary file: %w", err)
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
		return PublicationJournalRevision{}, fmt.Errorf("s3disk: protect publication journal: %w", err)
	}
	written, err := temporary.Write(data)
	if err != nil {
		_ = temporary.Close()
		return PublicationJournalRevision{}, fmt.Errorf("s3disk: write publication journal: %w", err)
	}
	if written != len(data) {
		_ = temporary.Close()
		return PublicationJournalRevision{}, fmt.Errorf("s3disk: write publication journal: %w", io.ErrShortWrite)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return PublicationJournalRevision{}, fmt.Errorf("s3disk: sync publication journal: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return PublicationJournalRevision{}, fmt.Errorf("s3disk: close publication journal: %w", err)
	}
	if err := installWatermarkFile(temporaryName, journal.path); err != nil {
		return PublicationJournalRevision{}, fmt.Errorf("s3disk: install publication journal: %w", err)
	}
	removeTemporary = false
	if err := journal.syncParentDirectory(); err != nil {
		return PublicationJournalRevision{}, err
	}
	return revision, nil
}

func (journal *FilePublicationJournal) syncParentDirectory() error {
	syncDirectory := journal.syncDirectory
	if syncDirectory == nil {
		syncDirectory = syncWatermarkDirectory
	}
	return syncDirectory(filepath.Dir(journal.path))
}

func newPublicationJournalRevision(forbidden *PublicationJournalRevision) (PublicationJournalRevision, error) {
	for {
		var revision PublicationJournalRevision
		if _, err := io.ReadFull(cryptorand.Reader, revision[:]); err != nil {
			return PublicationJournalRevision{}, fmt.Errorf("s3disk: generate publication journal revision: %w", err)
		}
		if !revision.IsZero() && (forbidden == nil || revision != *forbidden) {
			return revision, nil
		}
	}
}

// publicationIntentID deterministically identifies the semantic operation.
// ExpectedVersion and ExpectedReference are deliberately omitted: they are
// observations used to perform/reconcile the CAS, not the publication itself.
func publicationIntentID(
	repositoryID RepositoryID,
	channel string,
	kind PublicationIntentKind,
	base *Watermark,
	next Watermark,
	reference []byte,
) (Digest, error) {
	identity := publicationIntentIdentity{
		Format: publicationJournalFormatVersion, RepositoryID: repositoryID,
		Channel: channel, Kind: kind, Base: publicationJournalWatermarkPointerToFile(base),
		Next: publicationJournalWatermarkToFile(next), Reference: append([]byte(nil), reference...),
	}
	data, err := canonicalJSON(identity)
	if err != nil {
		return Digest{}, fmt.Errorf("s3disk: encode publication intent identity: %w", err)
	}
	return digestObject("publication-intent", data), nil
}

func validatePublicationIntentID(repositoryID RepositoryID, channel string, intent PublicationIntent) error {
	want, err := publicationIntentID(repositoryID, channel, intent.Kind, intent.Base, intent.Next, intent.Reference)
	if err != nil {
		return err
	}
	if intent.IntentID.IsZero() || intent.IntentID != want {
		return fmt.Errorf("%w: invalid publication intent ID", ErrCorruptObject)
	}
	return nil
}

func publicationReferenceDigest(reference []byte) Digest {
	if len(reference) == 0 {
		return Digest{}
	}
	return digestObject("publication-reference", reference)
}

func publicationJournalChecksum(disk publicationJournalFile) (Digest, error) {
	payload := publicationJournalPayload{
		Format: disk.Format, Revision: disk.Revision,
		RepositoryID: disk.RepositoryID, Channel: disk.Channel,
		Committed: disk.Committed, Pending: disk.Pending,
	}
	data, err := canonicalJSON(payload)
	if err != nil {
		return Digest{}, fmt.Errorf("s3disk: encode publication journal checksum payload: %w", err)
	}
	return digestObject("publication-journal", data), nil
}

func validatePublicationJournalState(state PublicationJournalState) error {
	if state.RepositoryID.IsZero() {
		return fmt.Errorf("%w: zero publication journal repository ID", ErrCorruptObject)
	}
	if err := validateChannel(state.Channel); err != nil {
		return fmt.Errorf("%w: invalid publication journal channel: %v", ErrCorruptObject, err)
	}
	if state.Committed != nil {
		if err := validatePublicationJournalWatermark(state.RepositoryID, *state.Committed); err != nil {
			return err
		}
	}
	if state.Pending == nil {
		return nil
	}
	if err := validatePublicationJournalIntent(state.RepositoryID, state.Channel, *state.Pending); err != nil {
		return err
	}
	if state.Committed == nil {
		if state.Pending.Base != nil {
			return fmt.Errorf("%w: pending publication has a base without a committed watermark", ErrCorruptObject)
		}
	} else if state.Pending.Base == nil || *state.Pending.Base != *state.Committed {
		return fmt.Errorf("%w: pending publication base does not equal committed watermark", ErrCorruptObject)
	}
	return nil
}

func validatePublicationJournalWatermark(repositoryID RepositoryID, watermark Watermark) error {
	if watermark.RepositoryID != repositoryID || watermark.Generation == 0 || watermark.Commit.IsZero() {
		return fmt.Errorf("%w: invalid publication journal watermark", ErrCorruptObject)
	}
	return nil
}

func validatePublicationJournalIntent(repositoryID RepositoryID, channel string, intent PublicationIntent) error {
	if intent.Kind != PublicationIntentPublish && intent.Kind != PublicationIntentResign {
		return fmt.Errorf("%w: invalid publication intent kind", ErrCorruptObject)
	}
	if err := validatePublicationJournalWatermark(repositoryID, intent.Next); err != nil {
		return err
	}
	if intent.Base != nil {
		if err := validatePublicationJournalWatermark(repositoryID, *intent.Base); err != nil {
			return err
		}
		if intent.ExpectedVersion == nil || intent.ExpectedReference.IsZero() {
			return fmt.Errorf("%w: publication intent with a base lacks its expected reference", ErrCorruptObject)
		}
	} else if intent.ExpectedVersion != nil || !intent.ExpectedReference.IsZero() {
		return fmt.Errorf("%w: first publication has an unexpected prior reference", ErrCorruptObject)
	}
	if intent.ExpectedVersion != nil {
		if intent.ExpectedVersion.ETag == "" ||
			len(intent.ExpectedVersion.ETag) > MaxStoreVersionTokenBytes || len(intent.ExpectedVersion.VersionID) > MaxStoreVersionTokenBytes {
			return fmt.Errorf("%w: invalid publication intent expected version", ErrCorruptObject)
		}
	}
	switch intent.Kind {
	case PublicationIntentPublish:
		if intent.Base == nil {
			if intent.Next.Generation != 1 {
				return fmt.Errorf("%w: first publication is not generation one", ErrCorruptObject)
			}
		} else if intent.Base.Generation == ^uint64(0) || intent.Next.Generation != intent.Base.Generation+1 {
			return fmt.Errorf("%w: publication intent does not advance exactly one generation", ErrCorruptObject)
		}
	case PublicationIntentResign:
		if intent.Base == nil || intent.Next != *intent.Base {
			return fmt.Errorf("%w: resign intent changes the committed watermark", ErrCorruptObject)
		}
	}
	if len(intent.Reference) == 0 || len(intent.Reference) > maxReferenceBytes {
		return fmt.Errorf("%w: invalid publication intent reference size", ErrResourceLimit)
	}
	if err := validatePublicationIntentReference(repositoryID, channel, intent.Next, intent.Reference); err != nil {
		return err
	}
	return validatePublicationIntentID(repositoryID, channel, intent)
}

func validatePublicationIntentReference(repositoryID RepositoryID, channel string, next Watermark, reference []byte) error {
	var envelope signedReferenceEnvelope
	if err := decodeJSON(reference, &envelope); err != nil {
		return fmt.Errorf("%w: invalid journal target reference: %v", ErrCorruptObject, err)
	}
	payload := envelope.Reference
	if envelope.Format != objectFormatVersion || payload.Format != objectFormatVersion ||
		payload.RepositoryID != repositoryID || payload.Channel != channel ||
		payload.Generation != next.Generation || payload.Commit != next.Commit ||
		len(envelope.Signature) == 0 || len(envelope.Signature) > maxReferenceSignatureSize {
		return fmt.Errorf("%w: journal target reference does not match its intent", ErrCorruptObject)
	}
	if err := validateReferenceKeyID(payload.KeyID); err != nil {
		return fmt.Errorf("%w: invalid journal target key ID", ErrCorruptObject)
	}
	return nil
}

func validatePublicationJournalTransition(current, next PublicationJournalState) error {
	if current.RepositoryID != next.RepositoryID {
		return fmt.Errorf("%w: publication journal repository changed", ErrUntrustedReference)
	}
	if current.Channel != next.Channel {
		return fmt.Errorf("%w: publication journal channel changed", ErrCorruptObject)
	}
	if current.Committed != nil {
		if next.Committed == nil || next.Committed.Generation < current.Committed.Generation {
			return ErrRollbackDetected
		}
		if next.Committed.Generation == current.Committed.Generation && next.Committed.Commit != current.Committed.Commit {
			return ErrSplitBrain
		}
	}

	if current.Pending == nil {
		// A publisher may adopt an authenticated remote reference after verifying
		// its immutable commit ancestry. The journal can enforce monotonicity and
		// same-generation uniqueness here; ancestry requires repository access and
		// is therefore the publisher's responsibility.
		return nil
	}

	if next.Pending != nil {
		if !equalWatermarkPointers(current.Committed, next.Committed) ||
			!equalPublicationIntentSemantics(current.Pending, next.Pending) {
			return fmt.Errorf("%w: pending publication semantics changed before resolution", ErrPrecondition)
		}
		// ExpectedVersion and ExpectedReference are observations rather than
		// semantic intent. A concurrent re-sign can change both while the exact
		// target operation remains safe to retry.
		return nil
	}
	// Clearing Pending records one of three caller-proven outcomes: our target
	// won, the remote CAS was conclusively rejected (Committed is unchanged),
	// or another authenticated branch won and was validated before advancing
	// Committed. This store enforces monotonicity; commit ancestry is necessarily
	// verified by the publisher because it requires immutable repository reads.
	return nil
}

func clonePublicationJournalState(state PublicationJournalState) PublicationJournalState {
	cloned := PublicationJournalState{RepositoryID: state.RepositoryID, Channel: state.Channel}
	cloned.Committed = clonePublicationWatermark(state.Committed)
	if state.Pending != nil {
		intent := *state.Pending
		intent.Base = clonePublicationWatermark(intent.Base)
		if intent.ExpectedVersion != nil {
			version := *intent.ExpectedVersion
			intent.ExpectedVersion = &version
		}
		intent.Reference = append([]byte(nil), intent.Reference...)
		cloned.Pending = &intent
	}
	return cloned
}

func clonePublicationWatermark(watermark *Watermark) *Watermark {
	if watermark == nil {
		return nil
	}
	cloned := *watermark
	return &cloned
}

func equalWatermarkPointers(left, right *Watermark) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func equalPublicationIntents(left, right *PublicationIntent) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.IntentID == right.IntentID && left.Kind == right.Kind &&
		equalWatermarkPointers(left.Base, right.Base) && left.Next == right.Next &&
		equalVersionPointers(left.ExpectedVersion, right.ExpectedVersion) &&
		left.ExpectedReference == right.ExpectedReference && bytes.Equal(left.Reference, right.Reference)
}

func equalPublicationIntentSemantics(left, right *PublicationIntent) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.IntentID == right.IntentID && left.Kind == right.Kind &&
		equalWatermarkPointers(left.Base, right.Base) && left.Next == right.Next &&
		bytes.Equal(left.Reference, right.Reference)
}

func equalVersionPointers(left, right *Version) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func publicationJournalFileFromState(state PublicationJournalState, revision PublicationJournalRevision) publicationJournalFile {
	state = clonePublicationJournalState(state)
	disk := publicationJournalFile{
		Format: publicationJournalFormatVersion, Revision: revision,
		RepositoryID: state.RepositoryID, Channel: state.Channel,
		Committed: publicationJournalWatermarkPointerToFile(state.Committed),
	}
	if state.Pending != nil {
		disk.Pending = &publicationJournalIntentFile{
			IntentID: state.Pending.IntentID, Kind: state.Pending.Kind,
			Base:              publicationJournalWatermarkPointerToFile(state.Pending.Base),
			Next:              publicationJournalWatermarkToFile(state.Pending.Next),
			ExpectedReference: state.Pending.ExpectedReference,
			Reference:         append([]byte(nil), state.Pending.Reference...),
		}
		if state.Pending.ExpectedVersion != nil {
			disk.Pending.ExpectedVersion = &publicationJournalVersion{
				ETag: state.Pending.ExpectedVersion.ETag, VersionID: state.Pending.ExpectedVersion.VersionID,
			}
		}
	}
	return disk
}

func publicationJournalStateFromFile(disk publicationJournalFile) PublicationJournalState {
	state := PublicationJournalState{
		RepositoryID: disk.RepositoryID, Channel: disk.Channel,
		Committed: publicationJournalWatermarkPointerFromFile(disk.Committed),
	}
	if disk.Pending != nil {
		state.Pending = &PublicationIntent{
			IntentID: disk.Pending.IntentID, Kind: disk.Pending.Kind,
			Base:              publicationJournalWatermarkPointerFromFile(disk.Pending.Base),
			Next:              publicationJournalWatermarkFromFile(disk.Pending.Next),
			ExpectedReference: disk.Pending.ExpectedReference,
			Reference:         append([]byte(nil), disk.Pending.Reference...),
		}
		if disk.Pending.ExpectedVersion != nil {
			state.Pending.ExpectedVersion = &Version{
				ETag: disk.Pending.ExpectedVersion.ETag, VersionID: disk.Pending.ExpectedVersion.VersionID,
			}
		}
	}
	return state
}

func publicationJournalWatermarkToFile(watermark Watermark) publicationJournalWatermark {
	return publicationJournalWatermark{
		RepositoryID: watermark.RepositoryID, Generation: watermark.Generation, Commit: watermark.Commit,
	}
}

func publicationJournalWatermarkFromFile(watermark publicationJournalWatermark) Watermark {
	return Watermark{
		RepositoryID: watermark.RepositoryID, Generation: watermark.Generation, Commit: watermark.Commit,
	}
}

func publicationJournalWatermarkPointerToFile(watermark *Watermark) *publicationJournalWatermark {
	if watermark == nil {
		return nil
	}
	converted := publicationJournalWatermarkToFile(*watermark)
	return &converted
}

func publicationJournalWatermarkPointerFromFile(watermark *publicationJournalWatermark) *Watermark {
	if watermark == nil {
		return nil
	}
	converted := publicationJournalWatermarkFromFile(*watermark)
	return &converted
}

var _ PublicationJournalStore = (*FilePublicationJournal)(nil)
