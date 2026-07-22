package s3disk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	maxProtectedSourceFiles      = 64
	maxProtectedSourcePathBytes  = 64 << 10
	maxProtectedSourceTotalBytes = 1 << 20
)

// ProtectedSourceFile identifies a local regular file whose filesystem
// identity must never appear in a published source tree. Stage pins every
// existing configured file by an open handle immediately before scanning and
// returns ErrProtectedSourceFile before reading or uploading a matching source
// file. This detects hard links and direct file bind mounts when the platform's
// os.SameFile implementation reports the same identity.
//
// AllowMissingInitially supports outputs which are created after the Publisher
// is constructed. Once a Stage observes the file, its later disappearance is a
// protection failure. Callers must serialize protected-file replacement with
// Stage; this is not a security boundary against a hostile process running as
// the same OS identity.
type ProtectedSourceFile struct {
	Path                  string
	AllowMissingInitially bool
}

// PublisherOptions controls snapshot construction.
type PublisherOptions struct {
	Chunking        ChunkingOptions
	StableReadTries int
	Symlinks        SymlinkPolicy
	// ProtectedSourceFiles prevents current filesystem aliases of sensitive
	// local files from being included in a snapshot. Paths are defensively
	// copied and made absolute by NewPublisher. Existing paths must name regular
	// non-symlink files; errors never disclose the configured path.
	ProtectedSourceFiles []ProtectedSourceFile
	// DangerouslyAllowUncommissionedRepository permits publication through a
	// low-level Repository which has no durable commissioning descriptor. This
	// disables prefix/profile/chunking identity protection and is intended only
	// for controlled legacy migration and protocol tests.
	DangerouslyAllowUncommissionedRepository bool
	ReferenceSigner                          ReferenceSigner
	// ReferenceVerifier is required with ReferenceSigner and must trust the
	// signing key. It also authenticates the existing signed history.
	ReferenceVerifier ReferenceVerifier
	// PublicationJournal durably records the exact signed reference bytes and
	// compare-and-swap precondition before a publication can become visible.
	// Signed publication fails closed without it. All publishers for one
	// repository/channel must share a linearizable journal.
	PublicationJournal PublicationJournalStore
	// TrustedCheckpoint bootstraps an existing signed channel from state
	// delivered independently of the object store.
	TrustedCheckpoint    *Watermark
	AllowTrustOnFirstUse bool
	Now                  func() time.Time
}

// Publisher scans a local tree and publishes immutable snapshots. A Publisher
// is safe for sequential use; callers must serialize Stage or StageSelected
// and their matching Commit calls.
type Publisher struct {
	repository           *Repository
	options              PublisherOptions
	referenceSigner      ReferenceSigner
	referenceVerifier    ReferenceVerifier
	publicationJournal   PublicationJournalStore
	trustedCheckpoint    *Watermark
	allowTrustOnFirstUse bool
	checkpointValidated  map[string]Watermark
	protectedSourceSeen  map[string]bool
}

func NewPublisher(repository *Repository, options PublisherOptions) (*Publisher, error) {
	if repository == nil {
		return nil, fmt.Errorf("s3disk: nil repository")
	}
	if repository.reader == nil {
		return nil, fmt.Errorf("%w: repository has no object reader", ErrStoreMisconfigured)
	}
	if repository.store == nil {
		return nil, fmt.Errorf("%w: Publisher requires Head and conditional write authority", ErrRepositoryReadOnly)
	}
	if repository.descriptor == nil && !options.DangerouslyAllowUncommissionedRepository {
		return nil, fmt.Errorf(
			"%w: Publisher requires InitializeRepository or an explicit dangerous legacy override",
			ErrRepositoryNotInitialized,
		)
	}
	if options.ReferenceSigner != nil && !interfaceDependencyConfigured(options.ReferenceSigner) {
		return nil, fmt.Errorf("s3disk: reference signer must not be a typed nil")
	}
	if options.ReferenceVerifier != nil && !interfaceDependencyConfigured(options.ReferenceVerifier) {
		return nil, fmt.Errorf("s3disk: reference verifier must not be a typed nil")
	}
	if options.PublicationJournal != nil && !interfaceDependencyConfigured(options.PublicationJournal) {
		return nil, fmt.Errorf("s3disk: publication journal must not be a typed nil")
	}
	if repository.descriptor != nil && options.Chunking == (ChunkingOptions{}) {
		options.Chunking = repository.descriptor.ChunkingOptions()
	} else {
		normalized, err := options.Chunking.normalized()
		if err != nil {
			return nil, err
		}
		if repository.descriptor != nil && normalized != repository.descriptor.ChunkingOptions() {
			return nil, fmt.Errorf("%w: publisher chunking differs from repository descriptor", ErrRepositoryConfigurationMismatch)
		}
		options.Chunking = normalized
	}
	if options.StableReadTries == 0 {
		options.StableReadTries = 3
	}
	if options.StableReadTries < 1 || options.StableReadTries > 100 {
		return nil, fmt.Errorf("s3disk: stable read tries must be between 1 and 100")
	}
	if options.Symlinks != SymlinkRejectExternal && options.Symlinks != SymlinkPreserve {
		return nil, fmt.Errorf("s3disk: invalid symlink policy")
	}
	if (options.ReferenceSigner == nil) != (options.ReferenceVerifier == nil) {
		return nil, fmt.Errorf("s3disk: reference signer and verifier must be configured together")
	}
	if options.ReferenceSigner != nil && (options.ReferenceSigner.RepositoryID().IsZero() || options.ReferenceSigner.RepositoryID() != options.ReferenceVerifier.RepositoryID()) {
		return nil, fmt.Errorf("%w: publisher signer/verifier repository mismatch", ErrUntrustedReference)
	}
	if repository.descriptor != nil && options.ReferenceSigner != nil &&
		options.ReferenceSigner.RepositoryID() != repository.descriptor.RepositoryID {
		return nil, fmt.Errorf("%w: publisher signer does not match repository descriptor", ErrUntrustedReference)
	}
	if options.ReferenceSigner != nil {
		if options.PublicationJournal == nil {
			return nil, ErrTrustStateRequired
		}
		if options.TrustedCheckpoint != nil {
			checkpoint := *options.TrustedCheckpoint
			if checkpoint.RepositoryID != options.ReferenceVerifier.RepositoryID() || checkpoint.Generation == 0 || checkpoint.Commit.IsZero() {
				return nil, fmt.Errorf("%w: invalid publisher trusted checkpoint", ErrUntrustedReference)
			}
			options.TrustedCheckpoint = &checkpoint
		}
	} else if options.PublicationJournal != nil || options.TrustedCheckpoint != nil || options.AllowTrustOnFirstUse {
		return nil, fmt.Errorf("s3disk: publication trust-state options require signed references")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	protectedSourceFiles, err := normalizeProtectedSourceFiles(options.ProtectedSourceFiles)
	if err != nil {
		return nil, err
	}
	options.ProtectedSourceFiles = protectedSourceFiles
	protectedSourceSeen, err := initiallyObservedProtectedSourceFiles(protectedSourceFiles)
	if err != nil {
		return nil, err
	}
	return &Publisher{
		repository: repository, options: options,
		referenceSigner: options.ReferenceSigner, referenceVerifier: options.ReferenceVerifier,
		publicationJournal: options.PublicationJournal, trustedCheckpoint: options.TrustedCheckpoint,
		allowTrustOnFirstUse: options.AllowTrustOnFirstUse,
		checkpointValidated:  make(map[string]Watermark),
		protectedSourceSeen:  protectedSourceSeen,
	}, nil
}

func initiallyObservedProtectedSourceFiles(values []ProtectedSourceFile) (map[string]bool, error) {
	seen := make(map[string]bool, len(values))
	for index, value := range values {
		if !value.AllowMissingInitially {
			continue
		}
		_, err := os.Lstat(value.Path)
		switch {
		case err == nil:
			seen[value.Path] = true
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return nil, fmt.Errorf(
				"%w: configured file %d cannot be initially inspected",
				ErrProtectedSourceFile, index+1,
			)
		}
	}
	return seen, nil
}

func normalizeProtectedSourceFiles(values []ProtectedSourceFile) ([]ProtectedSourceFile, error) {
	if len(values) > maxProtectedSourceFiles {
		return nil, fmt.Errorf(
			"%w: protected source file count exceeds %d",
			ErrResourceLimit, maxProtectedSourceFiles,
		)
	}
	result := make([]ProtectedSourceFile, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	totalBytes := 0
	for index, value := range values {
		if value.Path == "" || strings.IndexByte(value.Path, 0) >= 0 || len(value.Path) > maxProtectedSourcePathBytes {
			return nil, fmt.Errorf("%w: protected source file %d has an invalid path", ErrInvalidPath, index+1)
		}
		absolute, err := filepath.Abs(value.Path)
		if err != nil {
			return nil, fmt.Errorf("%w: protected source file %d path cannot be resolved", ErrInvalidPath, index+1)
		}
		absolute = filepath.Clean(absolute)
		if len(absolute) > maxProtectedSourcePathBytes {
			return nil, fmt.Errorf("%w: protected source file %d path exceeds the limit", ErrResourceLimit, index+1)
		}
		totalBytes += len(absolute)
		if totalBytes > maxProtectedSourceTotalBytes {
			return nil, fmt.Errorf("%w: protected source file paths exceed the total byte limit", ErrResourceLimit)
		}
		if _, duplicate := seen[absolute]; duplicate {
			return nil, fmt.Errorf("%w: protected source file %d duplicates an earlier path", ErrInvalidPath, index+1)
		}
		seen[absolute] = struct{}{}
		result = append(result, ProtectedSourceFile{
			Path: absolute, AllowMissingInitially: value.AllowMissingInitially,
		})
	}
	return result, nil
}

type protectedSourceIdentity struct {
	handle *os.File
	info   os.FileInfo
}

// captureProtectedSourceFiles runs after publication-journal recovery and
// immediately before source traversal. That ordering pins the journal version
// which can actually coexist with this scan rather than a version replaced by
// the Stage preparation itself.
func (publisher *Publisher) captureProtectedSourceFiles(ctx context.Context) ([]protectedSourceIdentity, error) {
	identities := make([]protectedSourceIdentity, 0, len(publisher.options.ProtectedSourceFiles))
	fail := func(err error) ([]protectedSourceIdentity, error) {
		closeProtectedSourceFiles(identities)
		return nil, err
	}
	for index, protected := range publisher.options.ProtectedSourceFiles {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		linked, err := os.Lstat(protected.Path)
		if errors.Is(err, os.ErrNotExist) {
			if protected.AllowMissingInitially && !publisher.protectedSourceSeen[protected.Path] {
				continue
			}
			return fail(fmt.Errorf("%w: configured file %d is missing", ErrProtectedSourceFile, index+1))
		}
		if err != nil {
			return fail(fmt.Errorf("%w: configured file %d cannot be inspected", ErrProtectedSourceFile, index+1))
		}
		// Any observed pathname is no longer eligible for the initial-missing
		// exception, even if its type or identity fails validation below.
		publisher.protectedSourceSeen[protected.Path] = true
		if linked.Mode()&os.ModeSymlink != 0 || !linked.Mode().IsRegular() {
			return fail(fmt.Errorf("%w: configured file %d is not a regular non-symlink file", ErrProtectedSourceFile, index+1))
		}
		handle, err := os.Open(protected.Path)
		if err != nil {
			return fail(fmt.Errorf("%w: configured file %d cannot be opened", ErrProtectedSourceFile, index+1))
		}
		opened, statErr := handle.Stat()
		current, currentErr := os.Lstat(protected.Path)
		if statErr != nil || currentErr != nil || !opened.Mode().IsRegular() ||
			current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
			!os.SameFile(linked, opened) || !os.SameFile(opened, current) {
			_ = handle.Close()
			return fail(fmt.Errorf(
				"%w: configured file %d changed during inspection: %w",
				ErrProtectedSourceFile, index+1, ErrUnstableFile,
			))
		}
		duplicate := false
		for _, identity := range identities {
			if os.SameFile(opened, identity.info) {
				duplicate = true
				break
			}
		}
		if duplicate {
			_ = handle.Close()
			continue
		}
		identities = append(identities, protectedSourceIdentity{handle: handle, info: opened})
	}
	return identities, nil
}

func closeProtectedSourceFiles(identities []protectedSourceIdentity) {
	for _, identity := range identities {
		_ = identity.handle.Close()
	}
}

// StagedSnapshot contains a complete immutable snapshot that is not visible to
// consumers until Commit succeeds.
type StagedSnapshot struct {
	Snapshot Snapshot

	repository          *Repository
	publisher           *Publisher
	channel             string
	expected            *Version
	referenceData       []byte
	publicationState    *PublicationJournalState
	publicationRevision *PublicationJournalRevision
	publicationIntent   *PublicationIntent
	unchanged           bool
	snapshot            Snapshot
}

// Stage uploads all data, manifests, and the commit object. It deliberately
// does not update the mutable channel reference.
func (publisher *Publisher) Stage(ctx context.Context, source, channel string) (*StagedSnapshot, error) {
	return publisher.stage(ctx, source, channel, nil)
}

// StageSelected uploads a projection of source containing exactly the
// requested paths. Paths use slash-separated, canonical relative syntax. A
// selected file or symlink is included together with only its ancestors; a
// selected directory includes its complete subtree. Redundant selections are
// rejected so a caller cannot accidentally broaden a share by selecting both
// an ancestor and one of its descendants. An empty selection is rejected; "."
// explicitly selects the source root and therefore its complete subtree.
//
// Like Stage, StageSelected does not update the mutable channel reference.
func (publisher *Publisher) StageSelected(ctx context.Context, source, channel string, paths []string) (*StagedSnapshot, error) {
	selection, err := newPathSelectionContext(ctx, paths)
	if err != nil {
		return nil, err
	}
	return publisher.stage(ctx, source, channel, selection)
}

func (publisher *Publisher) stage(
	ctx context.Context,
	source, channel string,
	selection *pathSelection,
) (*StagedSnapshot, error) {
	if ctx == nil {
		return nil, fmt.Errorf("s3disk: stage context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := publisher.repository.validateChannel(channel); err != nil {
		return nil, err
	}
	source, err := filepath.Abs(source)
	if err != nil {
		return nil, fmt.Errorf("resolve source path: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(source)
	if err != nil {
		return nil, fmt.Errorf("stat source: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: source is not a directory", ErrNotDirectory)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sourceRoot, err := os.OpenRoot(source)
	if err != nil {
		return nil, fmt.Errorf("open traversal-safe source root: %w", err)
	}
	defer sourceRoot.Close()
	rootHandle, err := sourceRoot.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open source root handle: %w", err)
	}
	rootInfo, statErr := rootHandle.Stat()
	closeErr := rootHandle.Close()
	if statErr != nil || closeErr != nil || !rootInfo.IsDir() || !os.SameFile(info, rootInfo) {
		return nil, fmt.Errorf("%w: source root identity changed before scan", ErrUnstableFile)
	}

	var generation uint64 = 1
	var parent *Digest
	var expected *Version
	var previous *commitManifest
	var publicationState *PublicationJournalState
	var publicationRevision *PublicationJournalRevision
	if publisher.referenceVerifier != nil {
		state, revision, err := publisher.preparePublicationJournal(ctx, channel)
		if err != nil {
			return nil, err
		}
		publicationState = &state
		publicationRevision = &revision
	}
	current, object, err := publisher.repository.getReferenceWithVerifier(ctx, channel, "", publisher.referenceVerifier)
	if err == nil {
		var commit commitManifest
		if err := publisher.repository.getManifest(ctx, "commit", current.Commit, &commit); err != nil {
			return nil, fmt.Errorf("read current commit: %w", err)
		}
		if err := validateCommitManifest(&commit, current.Generation); err != nil {
			return nil, fmt.Errorf("current commit/reference mismatch: %w", err)
		}
		if publisher.referenceVerifier != nil {
			state, revision, acceptErr := publisher.acceptObservedPublication(
				ctx, channel, *publicationState, *publicationRevision, current, &commit,
			)
			if acceptErr != nil {
				return nil, fmt.Errorf("validate current signed publication: %w", acceptErr)
			}
			publicationState = &state
			publicationRevision = &revision
		}
		if current.Generation == math.MaxUint64 {
			return nil, ErrGenerationExhausted
		}
		previous = &commit
		generation = current.Generation + 1
		parentDigest := current.Commit
		parent = &parentDigest
		version := object.Version
		expected = &version
	} else if !errors.Is(err, ErrObjectNotFound) {
		return nil, fmt.Errorf("read current reference: %w", err)
	} else if publicationState != nil && publicationState.Committed != nil {
		return nil, fmt.Errorf("%w: signed publication disappeared below durable watermark", ErrRollbackDetected)
	}

	protected, err := publisher.captureProtectedSourceFiles(ctx)
	if err != nil {
		return nil, err
	}
	defer closeProtectedSourceFiles(protected)
	root, err := publisher.buildDirectorySelection(ctx, sourceRoot, ".", info, 0, selection, protected)
	if err != nil {
		return nil, err
	}
	currentRoot, err := os.Lstat(source)
	if err != nil || !currentRoot.IsDir() || !os.SameFile(info, currentRoot) || !stableFileInfo(info, currentRoot) {
		return nil, fmt.Errorf("%w: source root identity changed during scan", ErrUnstableFile)
	}
	if previous != nil && previous.Root == root {
		snapshot := Snapshot{
			Generation:  current.Generation,
			Commit:      current.Commit,
			Root:        previous.Root,
			PublishedAt: time.Unix(0, previous.PublishedAtUnix).UTC(),
		}
		return &StagedSnapshot{
			Snapshot:            snapshot,
			repository:          publisher.repository,
			publisher:           publisher,
			channel:             channel,
			expected:            expected,
			publicationState:    clonePublicationJournalStatePointer(publicationState),
			publicationRevision: clonePublicationJournalRevision(publicationRevision),
			unchanged:           true,
			snapshot:            snapshot,
		}, nil
	}
	publishedAt := publisher.options.Now().UTC()
	commit := commitManifest{
		Format:          objectFormatVersion,
		Generation:      generation,
		Parent:          parent,
		Root:            root,
		PublishedAtUnix: publishedAt.UnixNano(),
		ResetChanges:    true,
	}
	commitDigest, err := publisher.repository.putManifest(ctx, "commit", commit)
	if err != nil {
		return nil, err
	}
	reference := snapshotReference{
		Format:     objectFormatVersion,
		Generation: generation,
		Commit:     commitDigest,
	}
	var referenceData []byte
	if publisher.referenceSigner == nil {
		referenceData, err = canonicalJSON(reference)
	} else {
		referenceData, err = signSnapshotReference(ctx, channel, reference, publisher.referenceSigner, publisher.referenceVerifier)
	}
	if err != nil {
		return nil, err
	}
	if len(referenceData) > maxReferenceBytes {
		return nil, fmt.Errorf("%w: snapshot reference is %d bytes (maximum %d)", ErrResourceLimit, len(referenceData), maxReferenceBytes)
	}
	snapshot := Snapshot{
		Generation:  generation,
		Commit:      commitDigest,
		Root:        root,
		PublishedAt: publishedAt,
	}
	var publicationIntent *PublicationIntent
	if publisher.referenceVerifier != nil {
		next := Watermark{
			RepositoryID: publisher.referenceVerifier.RepositoryID(),
			Generation:   generation,
			Commit:       commitDigest,
		}
		intent := PublicationIntent{
			Kind:      PublicationIntentPublish,
			Base:      clonePublicationWatermark(publicationState.Committed),
			Next:      next,
			Reference: append([]byte(nil), referenceData...),
		}
		if expected != nil {
			version := *expected
			intent.ExpectedVersion = &version
			intent.ExpectedReference = publicationReferenceDigest(object.Data)
		}
		intent.IntentID, err = publicationIntentID(
			publisher.referenceVerifier.RepositoryID(), channel, intent.Kind,
			intent.Base, intent.Next, intent.Reference,
		)
		if err != nil {
			return nil, err
		}
		if err := validatePublicationJournalIntent(publisher.referenceVerifier.RepositoryID(), channel, intent); err != nil {
			return nil, fmt.Errorf("construct publication intent: %w", err)
		}
		publicationIntent = &intent
	}
	return &StagedSnapshot{
		Snapshot:            snapshot,
		repository:          publisher.repository,
		publisher:           publisher,
		channel:             channel,
		expected:            expected,
		referenceData:       append([]byte(nil), referenceData...),
		publicationState:    clonePublicationJournalStatePointer(publicationState),
		publicationRevision: clonePublicationJournalRevision(publicationRevision),
		publicationIntent:   clonePublicationIntent(publicationIntent),
		snapshot:            snapshot,
	}, nil
}

// Commit atomically exposes a staged snapshot by compare-and-swapping the
// channel reference. A conflict is never retried blindly.
func (publisher *Publisher) Commit(ctx context.Context, staged *StagedSnapshot) (Snapshot, error) {
	if staged == nil || staged.publisher != publisher || staged.repository != publisher.repository || staged.channel == "" {
		return Snapshot{}, fmt.Errorf("s3disk: staged snapshot belongs to another publisher")
	}
	if staged.unchanged {
		reference, _, err := publisher.repository.getReferenceWithVerifier(ctx, staged.channel, staged.expected.ETag, publisher.referenceVerifier)
		if errors.Is(err, ErrNotModified) {
			return staged.snapshot, nil
		}
		if err == nil && reference.Generation == staged.snapshot.Generation && reference.Commit == staged.snapshot.Commit {
			return staged.snapshot, nil
		}
		if err == nil || errors.Is(err, ErrObjectNotFound) {
			return Snapshot{}, ErrPublishConflict
		}
		return Snapshot{}, fmt.Errorf("verify unchanged reference: %w", err)
	}
	if staged.publicationIntent != nil {
		return publisher.commitSignedPublication(ctx, staged)
	}
	_, err := publisher.repository.compareAndSwap(
		ctx,
		publisher.referenceKey(staged.channel),
		staged.expected,
		staged.referenceData,
	)
	if err == nil {
		return publisher.finishCommitted(staged)
	}

	// A CAS response can be lost after the object store has durably applied the
	// write. Resolve both transport errors and retry-time precondition failures
	// against the immutable commit chain before reporting a conflict. This makes
	// Commit idempotent for one StagedSnapshot without ever retrying a different
	// update blindly.
	outcome, reconcileErr := publisher.reconcileCommit(ctx, staged)
	switch outcome {
	case commitApplied:
		return publisher.finishCommitted(staged)
	case commitRejected:
		return Snapshot{}, ErrPublishConflict
	default:
		return Snapshot{}, indeterminatePublishError(err, reconcileErr)
	}
}

func (publisher *Publisher) finishCommitted(staged *StagedSnapshot) (Snapshot, error) {
	return staged.snapshot, nil
}

type commitOutcome uint8

const (
	commitUnknown commitOutcome = iota
	commitApplied
	commitRejected
)

// reconcileCommit determines whether staged appears in the currently
// published commit chain. A reference older than staged is inconclusive: weak
// S3-compatible implementations may return a stale GET after a successful CAS.
func (publisher *Publisher) reconcileCommit(ctx context.Context, staged *StagedSnapshot) (commitOutcome, error) {
	reference, _, err := publisher.repository.getReferenceWithVerifier(ctx, staged.channel, "", publisher.referenceVerifier)
	if err != nil {
		return commitUnknown, fmt.Errorf("read reference after CAS: %w", err)
	}
	if reference.Generation < staged.snapshot.Generation {
		return commitUnknown, nil
	}

	digest := reference.Commit
	generation := reference.Generation
	if generation-staged.snapshot.Generation > uint64(maxCommitWalk) {
		return commitUnknown, fmt.Errorf("%w: commit ancestry exceeds %d generations", ErrResourceLimit, maxCommitWalk)
	}
	for generation > staged.snapshot.Generation {
		if err := ctx.Err(); err != nil {
			return commitUnknown, err
		}
		var commit commitManifest
		if err := publisher.repository.getManifest(ctx, "commit", digest, &commit); err != nil {
			return commitUnknown, fmt.Errorf("walk commit chain at generation %d: %w", generation, err)
		}
		if err := validateCommitManifest(&commit, generation); err != nil {
			return commitUnknown, fmt.Errorf("invalid commit chain at generation %d: %w", generation, err)
		}
		digest = *commit.Parent
		generation--
	}
	if digest == staged.snapshot.Commit {
		return commitApplied, nil
	}
	return commitRejected, nil
}

func (publisher *Publisher) referenceKey(channel string) string {
	if publisher.referenceVerifier != nil {
		return publisher.repository.SignedReferenceKey(channel)
	}
	return publisher.repository.ReferenceKey(channel)
}

func validateCommitManifest(commit *commitManifest, generation uint64) error {
	if commit.Format != objectFormatVersion || commit.Generation != generation || commit.Root.IsZero() {
		return fmt.Errorf("%w: invalid commit header", ErrCorruptObject)
	}
	if generation == 1 {
		if commit.Parent != nil {
			return fmt.Errorf("%w: first commit has a parent", ErrCorruptObject)
		}
		return nil
	}
	if commit.Parent == nil || commit.Parent.IsZero() {
		return fmt.Errorf("%w: commit generation %d has no parent", ErrCorruptObject, generation)
	}
	return nil
}

func (publisher *Publisher) validatePublicationCheckpoint(ctx context.Context, channel string, watermark, checkpoint Watermark) error {
	anchor := checkpoint
	if validated, ok := publisher.checkpointValidated[channel]; ok {
		switch {
		case watermark.Generation < validated.Generation:
			return ErrRollbackDetected
		case watermark.Generation == validated.Generation && watermark.Commit != validated.Commit:
			return ErrSplitBrain
		case watermark == validated:
			return nil
		}
		anchor = validated
	}
	switch {
	case watermark.RepositoryID != checkpoint.RepositoryID:
		return fmt.Errorf("%w: publication watermark/checkpoint repository mismatch", ErrUntrustedReference)
	case watermark.Generation < checkpoint.Generation:
		return ErrRollbackDetected
	case watermark.Generation == checkpoint.Generation:
		if watermark.Commit != checkpoint.Commit {
			return ErrSplitBrain
		}
		publisher.checkpointValidated[channel] = watermark
		return nil
	}
	var commit commitManifest
	if err := publisher.repository.getManifest(ctx, "commit", watermark.Commit, &commit); err != nil {
		return fmt.Errorf("validate publisher watermark against checkpoint: %w", err)
	}
	if err := validateCommitManifest(&commit, watermark.Generation); err != nil {
		return err
	}
	reference := snapshotReference{Format: objectFormatVersion, Generation: watermark.Generation, Commit: watermark.Commit}
	if err := publisher.validatePublicationDescendant(ctx, reference, &commit, anchor); err != nil {
		return fmt.Errorf("publisher watermark does not descend from trusted checkpoint: %w", err)
	}
	publisher.checkpointValidated[channel] = watermark
	return nil
}

func (publisher *Publisher) validatePublicationDescendant(
	ctx context.Context,
	reference snapshotReference,
	commit *commitManifest,
	anchor Watermark,
) error {
	if reference.Generation <= anchor.Generation {
		return ErrSplitBrain
	}
	if reference.Generation-anchor.Generation > uint64(maxCommitWalk) {
		return fmt.Errorf("%w: publication ancestry exceeds %d generations", ErrResourceLimit, maxCommitWalk)
	}
	parent := commit.Parent
	for generation := reference.Generation - 1; generation > anchor.Generation; generation-- {
		if err := ctx.Err(); err != nil {
			return err
		}
		if parent == nil || parent.IsZero() {
			return ErrSplitBrain
		}
		var ancestor commitManifest
		if err := publisher.repository.getManifest(ctx, "commit", *parent, &ancestor); err != nil {
			return fmt.Errorf("validate publication ancestry at generation %d: %w", generation, err)
		}
		if err := validateCommitManifest(&ancestor, generation); err != nil {
			return fmt.Errorf("validate publication ancestry at generation %d: %w", generation, err)
		}
		parent = ancestor.Parent
	}
	if parent == nil || *parent != anchor.Commit {
		return ErrSplitBrain
	}
	return nil
}

func indeterminatePublishError(casErr, reconcileErr error) error {
	if reconcileErr != nil {
		return fmt.Errorf("%w: CAS failed (%w) and reconciliation failed: %w", ErrPublishIndeterminate, casErr, reconcileErr)
	}
	return fmt.Errorf("%w: CAS failed and the observed reference may be stale: %w", ErrPublishIndeterminate, casErr)
}

// Publish is the common Stage-then-Commit operation.
func (publisher *Publisher) Publish(ctx context.Context, source, channel string) (Snapshot, error) {
	staged, err := publisher.Stage(ctx, source, channel)
	if err != nil {
		return Snapshot{}, err
	}
	return publisher.Commit(ctx, staged)
}

// PublishSelected is the common StageSelected-then-Commit operation.
func (publisher *Publisher) PublishSelected(
	ctx context.Context,
	source, channel string,
	paths []string,
) (Snapshot, error) {
	staged, err := publisher.StageSelected(ctx, source, channel, paths)
	if err != nil {
		return Snapshot{}, err
	}
	return publisher.Commit(ctx, staged)
}

// ResignReference atomically replaces the authentication envelope for the
// current snapshot without changing its generation or commit. The exact target
// envelope is journaled before the remote CAS, so RecoverPublication can finish
// a rotation after a crash without access to the old signing operation.
func (publisher *Publisher) ResignReference(ctx context.Context, channel string) (Snapshot, error) {
	if publisher.referenceSigner == nil || publisher.referenceVerifier == nil {
		return Snapshot{}, fmt.Errorf("%w: signed references are not configured", ErrUntrustedReference)
	}
	if err := publisher.repository.validateChannel(channel); err != nil {
		return Snapshot{}, err
	}
	state, revision, err := publisher.preparePublicationJournal(ctx, channel)
	if err != nil {
		return Snapshot{}, err
	}
	reference, object, err := publisher.repository.getReferenceWithVerifier(ctx, channel, "", publisher.referenceVerifier)
	if err != nil {
		if state.Committed != nil && errors.Is(err, ErrObjectNotFound) {
			return Snapshot{}, ErrRollbackDetected
		}
		return Snapshot{}, err
	}
	var commit commitManifest
	if err := publisher.repository.getManifest(ctx, "commit", reference.Commit, &commit); err != nil {
		return Snapshot{}, fmt.Errorf("read current commit for resign: %w", err)
	}
	if err := validateCommitManifest(&commit, reference.Generation); err != nil {
		return Snapshot{}, err
	}
	state, revision, err = publisher.acceptObservedPublication(ctx, channel, state, revision, reference, &commit)
	if err != nil {
		return Snapshot{}, fmt.Errorf("validate current signed publication for resign: %w", err)
	}
	referenceData, err := signSnapshotReference(ctx, channel, reference, publisher.referenceSigner, publisher.referenceVerifier)
	if err != nil {
		return Snapshot{}, err
	}
	if len(referenceData) > maxReferenceBytes {
		return Snapshot{}, fmt.Errorf("%w: snapshot reference is %d bytes (maximum %d)", ErrResourceLimit, len(referenceData), maxReferenceBytes)
	}
	snapshot := Snapshot{
		Generation: reference.Generation, Commit: reference.Commit, Root: commit.Root,
		PublishedAt: time.Unix(0, commit.PublishedAtUnix).UTC(),
	}
	if bytes.Equal(object.Data, referenceData) {
		return snapshot, nil
	}
	if object.Version.ETag == "" {
		return Snapshot{}, fmt.Errorf("%w: store returned an empty reference version", ErrStoreIncompatible)
	}
	watermark := Watermark{
		RepositoryID: publisher.referenceVerifier.RepositoryID(),
		Generation:   reference.Generation,
		Commit:       reference.Commit,
	}
	version := object.Version
	intent := PublicationIntent{
		Kind:              PublicationIntentResign,
		Base:              clonePublicationWatermark(&watermark),
		Next:              watermark,
		ExpectedVersion:   &version,
		ExpectedReference: publicationReferenceDigest(object.Data),
		Reference:         append([]byte(nil), referenceData...),
	}
	intent.IntentID, err = publicationIntentID(
		publisher.referenceVerifier.RepositoryID(), channel, intent.Kind,
		intent.Base, intent.Next, intent.Reference,
	)
	if err != nil {
		return Snapshot{}, err
	}
	staged := &StagedSnapshot{
		Snapshot:            snapshot,
		repository:          publisher.repository,
		publisher:           publisher,
		channel:             channel,
		expected:            &version,
		referenceData:       append([]byte(nil), referenceData...),
		publicationState:    clonePublicationJournalStatePointer(&state),
		publicationRevision: clonePublicationJournalRevision(&revision),
		publicationIntent:   clonePublicationIntent(&intent),
		snapshot:            snapshot,
	}
	return publisher.commitSignedPublication(ctx, staged)
}

// pathSelection is a trie of selected source paths. A nil selection means the
// complete subtree. includeAll is only set on an exact selected path and is
// never combined with children.
type pathSelection struct {
	includeAll bool
	children   map[string]*pathSelection
}

// newPathSelectionContext validates the complete selection before source or
// object store I/O. Besides the per-path protocol limits, aggregate limits keep
// an adversarial caller from constructing an unbounded in-memory trie.
func newPathSelectionContext(ctx context.Context, values []string) (*pathSelection, error) {
	if ctx == nil {
		return nil, fmt.Errorf("s3disk: path-selection context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: selected paths must not be empty", ErrInvalidPath)
	}
	if len(values) > maxDirectoryEntries {
		return nil, fmt.Errorf("%w: %w: selection exceeds %d paths", ErrInvalidPath, ErrResourceLimit, maxDirectoryEntries)
	}

	root := &pathSelection{children: make(map[string]*pathSelection)}
	var totalBytes int64
	nodeCount := 0
	for _, value := range values {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if value == "" || strings.ContainsRune(value, '\x00') || path.IsAbs(value) {
			return nil, fmt.Errorf("%w: selected path %q is not a canonical relative path", ErrInvalidPath, value)
		}
		if len(value) > maxLookupPathBytes {
			return nil, fmt.Errorf("%w: %w: selected path exceeds %d bytes", ErrInvalidPath, ErrResourceLimit, maxLookupPathBytes)
		}
		totalBytes += int64(len(value))
		if totalBytes > maxMetadataObjectBytes {
			return nil, fmt.Errorf("%w: %w: selected paths exceed %d aggregate bytes", ErrInvalidPath, ErrResourceLimit, maxMetadataObjectBytes)
		}
		cleaned := path.Clean(value)
		if cleaned != value || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
			return nil, fmt.Errorf("%w: selected path %q is not a canonical relative path", ErrInvalidPath, value)
		}

		var components []string
		if cleaned != "." {
			components = strings.Split(cleaned, "/")
		}
		if len(components) > maxLookupDepth {
			return nil, fmt.Errorf("%w: %w: selected path exceeds %d components", ErrInvalidPath, ErrResourceLimit, maxLookupDepth)
		}

		node := root
		for _, component := range components {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if len(component) == 0 || len(component) > maxEntryNameBytes {
				return nil, fmt.Errorf("%w: %w: selected path component exceeds %d bytes", ErrInvalidPath, ErrResourceLimit, maxEntryNameBytes)
			}
			if node.includeAll {
				return nil, fmt.Errorf("%w: selected path %q is covered by an already selected ancestor", ErrInvalidPath, value)
			}
			child := node.children[component]
			if child == nil {
				nodeCount++
				if nodeCount > maxDirectoryEntries {
					return nil, fmt.Errorf("%w: %w: selection exceeds %d path components", ErrInvalidPath, ErrResourceLimit, maxDirectoryEntries)
				}
				child = &pathSelection{children: make(map[string]*pathSelection)}
				node.children[component] = child
			}
			node = child
		}
		if node.includeAll {
			return nil, fmt.Errorf("%w: selected path %q is duplicated", ErrInvalidPath, value)
		}
		if len(node.children) != 0 {
			return nil, fmt.Errorf("%w: selected path %q covers an already selected descendant", ErrInvalidPath, value)
		}
		node.includeAll = true
	}
	if root.includeAll {
		return nil, nil
	}
	return root, nil
}

func (publisher *Publisher) buildDirectorySelection(
	ctx context.Context,
	sourceRoot *os.Root,
	directory string,
	expected os.FileInfo,
	depth int,
	selection *pathSelection,
	protected []protectedSourceIdentity,
) (Digest, error) {
	if err := ctx.Err(); err != nil {
		return Digest{}, err
	}
	if depth > maxLookupDepth || len(directory) > maxLookupPathBytes {
		return Digest{}, fmt.Errorf("%w: source path exceeds protocol depth or length", ErrResourceLimit)
	}
	handle, err := sourceRoot.Open(directory)
	if err != nil {
		return Digest{}, fmt.Errorf("open directory %q: %w", directory, err)
	}
	handleOpen := true
	defer func() {
		if handleOpen {
			_ = handle.Close()
		}
	}()
	before, err := handle.Stat()
	if err != nil {
		return Digest{}, fmt.Errorf("stat opened directory %q: %w", directory, err)
	}
	if !before.IsDir() || !os.SameFile(expected, before) || !stableFileInfo(expected, before) {
		return Digest{}, fmt.Errorf("%w: directory identity changed before scan: %q", ErrUnstableFile, directory)
	}
	entries := make([]os.DirEntry, 0, 1024)
	for {
		if err := ctx.Err(); err != nil {
			return Digest{}, err
		}
		batch, readErr := handle.ReadDir(1024)
		entries = append(entries, batch...)
		if len(entries) > maxDirectoryEntries {
			return Digest{}, fmt.Errorf("%w: directory %q exceeds %d entries", ErrResourceLimit, directory, maxDirectoryEntries)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return Digest{}, fmt.Errorf("read directory %q: %w", directory, readErr)
		}
	}
	if err := ctx.Err(); err != nil {
		return Digest{}, err
	}
	// Directory entries are materialized above, so the opened directory is no
	// longer needed while child manifests are built. Closing it before recursion
	// keeps descriptor use constant with respect to protocol path depth. The
	// directory is reopened and compared with this pinned identity below.
	if err := handle.Close(); err != nil {
		return Digest{}, fmt.Errorf("close directory %q after scan: %w", directory, err)
	}
	handleOpen = false
	manifestCapacity := len(entries)
	if selection != nil && manifestCapacity > len(selection.children) {
		manifestCapacity = len(selection.children)
	}
	manifest := dirManifest{Format: objectFormatVersion, Entries: make([]dirEntry, 0, manifestCapacity)}
	var matched map[string]struct{}
	if selection != nil {
		matched = make(map[string]struct{}, len(selection.children))
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return Digest{}, err
		}
		name := entry.Name()
		var childSelection *pathSelection
		if selection != nil {
			childSelection = selection.children[name]
			if childSelection == nil {
				continue
			}
			matched[name] = struct{}{}
		}
		if len(name) == 0 || len(name) > maxEntryNameBytes {
			return Digest{}, fmt.Errorf("%w: invalid source entry name length in %q", ErrResourceLimit, directory)
		}
		if depth >= maxLookupDepth {
			return Digest{}, fmt.Errorf("%w: source path exceeds %d components", ErrResourceLimit, maxLookupDepth)
		}
		childPath := path.Join(directory, name)
		if len(childPath) > maxLookupPathBytes {
			return Digest{}, fmt.Errorf("%w: source path exceeds %d bytes", ErrResourceLimit, maxLookupPathBytes)
		}
		info, err := sourceRoot.Lstat(childPath)
		if err != nil {
			return Digest{}, fmt.Errorf("lstat source entry %q: %w", childPath, err)
		}
		if childSelection != nil && !childSelection.includeAll && !info.IsDir() {
			return Digest{}, fmt.Errorf("%w: selected path %q has descendants but is not a directory", ErrNotDirectory, childPath)
		}
		item := dirEntry{
			Name:            append([]byte(nil), []byte(name)...),
			Mode:            uint32(info.Mode().Perm()),
			Size:            info.Size(),
			ModTimeUnixNano: info.ModTime().UnixNano(),
		}
		switch {
		case info.Mode().IsRegular():
			item.Type = EntryFile
			var stableInfo os.FileInfo
			item.Node, item.Size, stableInfo, err = publisher.buildFile(ctx, sourceRoot, childPath, info, protected)
			if err == nil {
				item.Mode = uint32(stableInfo.Mode().Perm())
				item.ModTimeUnixNano = stableInfo.ModTime().UnixNano()
			}
		case info.IsDir():
			item.Type = EntryDir
			var nestedSelection *pathSelection
			if childSelection != nil && !childSelection.includeAll {
				nestedSelection = childSelection
			}
			item.Node, err = publisher.buildDirectorySelection(ctx, sourceRoot, childPath, info, depth+1, nestedSelection, protected)
			item.Size = 0
			if nestedSelection != nil {
				// This directory exists in the projection only as an ancestor.
				// Its source mtime also reflects additions and removals of hidden
				// siblings, so publishing that timestamp would leak unrelated
				// activity and advance an otherwise unchanged projection.
				item.ModTimeUnixNano = 0
			}
		case info.Mode()&os.ModeSymlink != 0:
			item.Type = EntrySymlink
			item.Node, item.Size, err = publisher.buildSymlink(ctx, sourceRoot, childPath, info)
		default:
			err = fmt.Errorf("%w: %q (%s)", ErrUnsupportedType, childPath, info.Mode())
		}
		if err != nil {
			return Digest{}, err
		}
		manifest.Entries = append(manifest.Entries, item)
	}
	sort.Slice(manifest.Entries, func(i, j int) bool {
		return bytes.Compare(manifest.Entries[i].Name, manifest.Entries[j].Name) < 0
	})
	if err := ctx.Err(); err != nil {
		return Digest{}, err
	}
	afterHandle, openErr := sourceRoot.Open(directory)
	if openErr != nil {
		return Digest{}, fmt.Errorf("%w: reopen directory after scan %q: %v", ErrUnstableFile, directory, openErr)
	}
	after, statErr := afterHandle.Stat()
	closeErr := afterHandle.Close()
	current, currentErr := sourceRoot.Lstat(directory)
	if statErr != nil || closeErr != nil || currentErr != nil ||
		!os.SameFile(before, after) || !os.SameFile(after, current) ||
		!stableFileInfo(before, after) || !stableFileInfo(after, current) {
		return Digest{}, fmt.Errorf("%w: directory changed during scan: %q", ErrUnstableFile, directory)
	}
	if selection != nil && len(matched) != len(selection.children) {
		missing := make([]string, 0, len(selection.children)-len(matched))
		for name := range selection.children {
			if _, ok := matched[name]; !ok {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		return Digest{}, fmt.Errorf("%w: %q", ErrPathNotFound, path.Join(directory, missing[0]))
	}
	return publisher.repository.putManifest(ctx, "dir", manifest)
}

func (publisher *Publisher) buildFile(
	ctx context.Context,
	sourceRoot *os.Root,
	path string,
	expected os.FileInfo,
	protected []protectedSourceIdentity,
) (Digest, int64, os.FileInfo, error) {
	for attempt := 0; attempt < publisher.options.StableReadTries; attempt++ {
		file, err := sourceRoot.Open(path)
		if err != nil {
			return Digest{}, 0, nil, fmt.Errorf("open %q: %w", path, err)
		}
		before, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return Digest{}, 0, nil, fmt.Errorf("stat open file %q: %w", path, err)
		}
		if !before.Mode().IsRegular() || !os.SameFile(expected, before) {
			_ = file.Close()
			return Digest{}, 0, nil, fmt.Errorf("%w: file identity changed before read: %q", ErrUnstableFile, path)
		}
		for _, identity := range protected {
			if os.SameFile(before, identity.info) {
				_ = file.Close()
				return Digest{}, 0, nil, fmt.Errorf("%w: source entry %q", ErrProtectedSourceFile, path)
			}
		}
		maximumRepresentableSize := int64(maxFileChunks) * int64(publisher.options.Chunking.MaxSize)
		if before.Size() > maximumRepresentableSize {
			_ = file.Close()
			return Digest{}, 0, nil, fmt.Errorf("%w: file %q exceeds the maximum representable chunk count", ErrResourceLimit, path)
		}
		manifest := fileManifest{
			Format:     objectFormatVersion,
			Algorithm:  "rabin-v1",
			MinSize:    publisher.options.Chunking.MinSize,
			AvgSize:    publisher.options.Chunking.AverageSize,
			MaxSize:    publisher.options.Chunking.MaxSize,
			Polynomial: publisher.options.Chunking.Polynomial,
			Chunks:     make([]chunkRef, 0),
		}
		var offset int64
		err = walkChunks(ctx, file, publisher.options.Chunking, func(chunk chunkData) error {
			if len(manifest.Chunks) >= maxFileChunks {
				return fmt.Errorf("%w: file %q exceeds %d chunks", ErrResourceLimit, path, maxFileChunks)
			}
			digest, err := publisher.repository.putImmutable(ctx, "chunk", chunk.Data)
			if err != nil {
				return err
			}
			if digest != chunk.Digest {
				return fmt.Errorf("%w: chunk digest changed during upload", ErrCorruptObject)
			}
			manifest.Chunks = append(manifest.Chunks, chunkRef{Offset: offset, Size: chunk.Size, Digest: digest})
			offset += chunk.Size
			return nil
		})
		after, statErr := file.Stat()
		closeErr := file.Close()
		if err != nil {
			return Digest{}, 0, nil, fmt.Errorf("chunk %q: %w", path, err)
		}
		if statErr != nil {
			return Digest{}, 0, nil, fmt.Errorf("stat after read %q: %w", path, statErr)
		}
		if closeErr != nil {
			return Digest{}, 0, nil, fmt.Errorf("close %q: %w", path, closeErr)
		}
		current, currentErr := sourceRoot.Stat(path)
		stable := currentErr == nil && os.SameFile(after, current) && stableFileInfo(before, after) && after.Size() == offset
		if stable {
			manifest.Size = offset
			digest, err := publisher.repository.putManifest(ctx, "file", manifest)
			return digest, offset, after, err
		}
		if currentErr != nil && !errors.Is(currentErr, os.ErrNotExist) {
			return Digest{}, 0, nil, currentErr
		}
	}
	return Digest{}, 0, nil, fmt.Errorf("%w: %q", ErrUnstableFile, path)
}

func stableFileInfo(before, after os.FileInfo) bool {
	return os.SameFile(before, after) &&
		before.Size() == after.Size() &&
		before.ModTime().Equal(after.ModTime()) &&
		before.Mode() == after.Mode()
}

func (publisher *Publisher) buildSymlink(ctx context.Context, sourceRoot *os.Root, linkPath string, expected os.FileInfo) (Digest, int64, error) {
	before, err := sourceRoot.Lstat(linkPath)
	if err != nil || !os.SameFile(expected, before) || !stableFileInfo(expected, before) || before.Mode()&os.ModeSymlink == 0 {
		return Digest{}, 0, fmt.Errorf("%w: symlink identity changed before read: %q", ErrUnstableFile, linkPath)
	}
	target, err := sourceRoot.Readlink(linkPath)
	if err != nil {
		return Digest{}, 0, fmt.Errorf("readlink %q: %w", linkPath, err)
	}
	after, err := sourceRoot.Lstat(linkPath)
	if err != nil || !os.SameFile(before, after) || !stableFileInfo(before, after) {
		return Digest{}, 0, fmt.Errorf("%w: symlink changed during read: %q", ErrUnstableFile, linkPath)
	}
	if len(target) == 0 || len(target) > maxSymlinkTargetBytes {
		return Digest{}, 0, fmt.Errorf("%w: symlink target exceeds protocol limit: %q", ErrResourceLimit, linkPath)
	}
	if publisher.options.Symlinks == SymlinkRejectExternal {
		if err := validateSafeSymlink(linkPath, target); err != nil {
			return Digest{}, 0, fmt.Errorf("%w: %q -> %q", err, linkPath, target)
		}
	}
	manifest := symlinkManifest{Format: objectFormatVersion, Target: []byte(target)}
	digest, err := publisher.repository.putManifest(ctx, "symlink", manifest)
	return digest, int64(len(target)), err
}

var _ io.Reader = (*os.File)(nil)
