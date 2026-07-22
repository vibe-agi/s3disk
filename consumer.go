package s3disk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vibe-agi/s3disk/internal/syncutil"
)

// RefreshStatus describes the result of checking a channel reference.
type RefreshStatus uint8

const (
	RefreshUnchanged RefreshStatus = iota
	RefreshUpdated
	RefreshNoSnapshot
	RefreshStaleIgnored
)

// RefreshResult reports the currently adopted generation after a refresh.
type RefreshResult struct {
	Status     RefreshStatus
	Generation uint64
}

// ConsumerOptions controls lazy reads. A nil Cache disables persistent chunk
// caching but still preserves snapshot consistency.
type ConsumerOptions struct {
	Cache                      ChunkCache
	Watermarks                 WatermarkStore
	RequirePersistentWatermark bool
	ReferenceVerifier          ReferenceVerifier
	// DangerouslyAllowCustomReferenceVerifier permits a verifier that is not an
	// the built-in offline Ed25519 verifier. Such an implementation can perform arbitrary
	// network I/O from RepositoryID or Verify and therefore breaks the S3-only
	// consumer boundary. Leave this false for B/C/D share consumers.
	DangerouslyAllowCustomReferenceVerifier bool
	// TrustedCheckpoint bootstraps a signed consumer from state delivered over
	// a channel independent of the object store. Without it, an existing durable
	// watermark is required unless AllowTrustOnFirstUse is explicitly selected.
	TrustedCheckpoint    *Watermark
	AllowTrustOnFirstUse bool
	Symlinks             SymlinkPolicy
	// MetadataCacheEntries is a secondary bound on the combined directory,
	// file, and symlink metadata LRU. Zero selects a finite default.
	MetadataCacheEntries int
	// MetadataCacheBytes is a conservative retained-memory budget shared by all
	// decoded directory, file, and symlink manifests. Zero selects 64 MiB.
	MetadataCacheBytes     int64
	MaxConcurrentDownloads int
	// MaxConcurrentDownloadBytes is the total byte charge allowed for cache
	// reads, object-store reads, verification, and decoding in progress. Zero
	// selects DefaultMaxConcurrentDownloadBytes. A chunk is charged at its exact
	// manifest size until every joined read finishes copying it; metadata is
	// charged conservatively at its protocol limit through decoding.
	MaxConcurrentDownloadBytes int64
	StrictCacheErrors          bool
	// OnCacheError observes best-effort cache failures. It runs synchronously
	// for the caller releasing the final joined chunk lease, after the affected
	// download and digest+size coalescing resources have been released, so it may
	// safely reenter this Consumer. Callback panics are contained.
	OnCacheError func(error)
}

const (
	// DefaultMaxConcurrentDownloadBytes admits one protocol-maximum chunk or
	// several ordinary chunks and metadata objects at once.
	DefaultMaxConcurrentDownloadBytes int64 = maxChunkObjectBytes
	// MaxConcurrentDownloadBytesLimit matches the maximum download count times
	// the protocol-maximum chunk size.
	MaxConcurrentDownloadBytesLimit int64 = 1024 * maxChunkObjectBytes
)

type adoptedSnapshot struct {
	reference snapshotReference
	commit    commitManifest
	version   Version
}

// Consumer exposes a monotonically advancing, read-only view of one channel.
// It is safe for concurrent use.
type Consumer struct {
	repository           *Repository
	channel              string
	cache                ChunkCache
	watermarks           WatermarkStore
	referenceVerifier    ReferenceVerifier
	trustedCheckpoint    *Watermark
	allowTrustOnFirstUse bool
	symlinkPolicy        SymlinkPolicy
	strictCacheErrors    bool
	onCacheError         func(error)
	downloadSlots        chan struct{}
	downloadBytes        *syncutil.WeightedSemaphore

	// refreshGate serializes Refresh while allowing a caller's context to cancel
	// before it reaches the object store. A plain mutex would make a timed poller
	// wait indefinitely behind another stuck refresh on the same Consumer.
	refreshGate     chan struct{}
	stateMu         sync.RWMutex
	state           *adoptedSnapshot
	watermark       Watermark
	watermarkLoaded bool
	// checkpointValidated is the highest durable watermark whose ancestry has
	// already been proven back to trustedCheckpoint in this process.
	checkpointValidated Watermark

	metadata       metadataCache
	metadataFlight metadataFlightGroup
	chunkFlight    syncutil.FlightGroup[chunkFlightKey]
}

func NewConsumer(repository *Repository, channel string, options ConsumerOptions) (*Consumer, error) {
	if repository == nil {
		return nil, fmt.Errorf("s3disk: nil repository")
	}
	if repository.reader == nil {
		return nil, fmt.Errorf("%w: repository has no object reader", ErrStoreMisconfigured)
	}
	if err := repository.validateChannel(channel); err != nil {
		return nil, err
	}
	if options.Cache != nil && !interfaceDependencyConfigured(options.Cache) {
		return nil, fmt.Errorf("s3disk: chunk cache must not be a typed nil")
	}
	if options.Watermarks != nil && !interfaceDependencyConfigured(options.Watermarks) {
		return nil, fmt.Errorf("s3disk: watermark store must not be a typed nil")
	}
	if options.ReferenceVerifier != nil && !interfaceDependencyConfigured(options.ReferenceVerifier) {
		return nil, fmt.Errorf("s3disk: reference verifier must not be a typed nil")
	}
	if options.ReferenceVerifier != nil && !options.DangerouslyAllowCustomReferenceVerifier {
		if !IsOfflineReferenceVerifier(options.ReferenceVerifier) {
			return nil, fmt.Errorf("s3disk: custom reference verifier requires DangerouslyAllowCustomReferenceVerifier and may break the S3-only boundary")
		}
	}
	if options.RequirePersistentWatermark && options.Watermarks == nil {
		return nil, fmt.Errorf("s3disk: persistent watermark store is required")
	}
	if options.ReferenceVerifier != nil {
		if options.ReferenceVerifier.RepositoryID().IsZero() {
			return nil, fmt.Errorf("%w: zero verifier repository ID", ErrUntrustedReference)
		}
		if repository.descriptor != nil && options.ReferenceVerifier.RepositoryID() != repository.descriptor.RepositoryID {
			return nil, fmt.Errorf("%w: verifier does not match repository descriptor", ErrUntrustedReference)
		}
		if options.Watermarks == nil {
			return nil, ErrTrustStateRequired
		}
		if options.TrustedCheckpoint != nil {
			checkpoint := *options.TrustedCheckpoint
			if checkpoint.RepositoryID != options.ReferenceVerifier.RepositoryID() || checkpoint.Generation == 0 || checkpoint.Commit.IsZero() {
				return nil, fmt.Errorf("%w: invalid trusted checkpoint", ErrUntrustedReference)
			}
			options.TrustedCheckpoint = &checkpoint
		}
	} else if options.TrustedCheckpoint != nil || options.AllowTrustOnFirstUse {
		return nil, fmt.Errorf("s3disk: trusted checkpoint options require a reference verifier")
	}
	if options.Symlinks != SymlinkRejectExternal && options.Symlinks != SymlinkPreserve {
		return nil, fmt.Errorf("s3disk: invalid symlink policy")
	}
	if options.MetadataCacheEntries == 0 {
		options.MetadataCacheEntries = defaultMetadataCacheEntries
	}
	if options.MetadataCacheEntries < 1 || options.MetadataCacheEntries > 1_000_000 {
		return nil, fmt.Errorf("s3disk: metadata cache entries must be between 1 and 1000000")
	}
	if options.MetadataCacheBytes == 0 {
		options.MetadataCacheBytes = defaultMetadataCacheBytes
	}
	if options.MetadataCacheBytes < 1 || options.MetadataCacheBytes > maxMetadataCacheBytes {
		return nil, fmt.Errorf("s3disk: metadata cache bytes must be between 1 and %d", maxMetadataCacheBytes)
	}
	if options.MaxConcurrentDownloads == 0 {
		options.MaxConcurrentDownloads = 8
	}
	if options.MaxConcurrentDownloads < 1 || options.MaxConcurrentDownloads > 1024 {
		return nil, fmt.Errorf("s3disk: concurrent downloads must be between 1 and 1024")
	}
	if options.MaxConcurrentDownloadBytes == 0 {
		options.MaxConcurrentDownloadBytes = DefaultMaxConcurrentDownloadBytes
	}
	if options.MaxConcurrentDownloadBytes < maxChunkObjectBytes || options.MaxConcurrentDownloadBytes > MaxConcurrentDownloadBytesLimit {
		return nil, fmt.Errorf("%w: concurrent download bytes must be between %d and %d", ErrResourceLimit, maxChunkObjectBytes, MaxConcurrentDownloadBytesLimit)
	}
	return &Consumer{
		repository: repository, channel: channel, cache: options.Cache,
		watermarks:           options.Watermarks,
		referenceVerifier:    options.ReferenceVerifier,
		trustedCheckpoint:    options.TrustedCheckpoint,
		allowTrustOnFirstUse: options.AllowTrustOnFirstUse,
		symlinkPolicy:        options.Symlinks,
		strictCacheErrors:    options.StrictCacheErrors,
		onCacheError:         options.OnCacheError,
		refreshGate:          make(chan struct{}, 1),
		downloadSlots:        make(chan struct{}, options.MaxConcurrentDownloads),
		downloadBytes:        syncutil.NewWeightedSemaphore(options.MaxConcurrentDownloadBytes, ErrResourceLimit),
		metadata:             newMetadataCache(options.MetadataCacheEntries, options.MetadataCacheBytes),
	}, nil
}

// Refresh conditionally reads the channel reference, validates the referenced
// commit and root directory, then atomically adopts a newer generation. Older
// generations are ignored even if a weak S3-compatible backend returns one.
func (consumer *Consumer) Refresh(ctx context.Context) (RefreshResult, error) {
	if consumer == nil || consumer.refreshGate == nil {
		return RefreshResult{}, fmt.Errorf("s3disk: consumer is not initialized")
	}
	if ctx == nil {
		return RefreshResult{}, fmt.Errorf("s3disk: refresh context is required")
	}
	select {
	case consumer.refreshGate <- struct{}{}:
		defer func() { <-consumer.refreshGate }()
	case <-ctx.Done():
		return RefreshResult{}, ctx.Err()
	}
	// A different process may have advanced a shared durable watermark since the
	// previous refresh. Reload before issuing a conditional reference GET so an
	// old ETag cannot hide that stronger local freshness requirement.
	if consumer.watermarks != nil {
		consumer.watermarkLoaded = false
	}
	if err := consumer.loadWatermark(ctx); err != nil {
		return RefreshResult{}, err
	}

	consumer.stateMu.RLock()
	current := consumer.state
	ifNoneMatch := ""
	if current != nil && (consumer.watermark.Generation == 0 ||
		(consumer.watermark.Generation == current.reference.Generation && consumer.watermark.Commit == current.reference.Commit)) {
		ifNoneMatch = current.version.ETag
	}
	consumer.stateMu.RUnlock()

	reference, object, err := consumer.downloadReference(ctx, ifNoneMatch)
	if errors.Is(err, ErrNotModified) {
		return refreshResult(current, RefreshUnchanged), nil
	}
	if errors.Is(err, ErrObjectNotFound) {
		if current == nil {
			if consumer.watermark.Generation > 0 {
				return RefreshResult{}, fmt.Errorf("%w: published reference disappeared below durable watermark", ErrRollbackDetected)
			}
			return RefreshResult{Status: RefreshNoSnapshot}, nil
		}
		if consumer.watermark.Generation > current.reference.Generation {
			return refreshResult(current, RefreshStaleIgnored), fmt.Errorf("%w: published reference disappeared below shared durable watermark", ErrRollbackDetected)
		}
		return refreshResult(current, RefreshUnchanged), nil
	}
	if err != nil {
		return refreshResult(current, RefreshUnchanged), err
	}

	// A durable watermark advanced by another process can be ahead of this
	// Consumer's in-memory snapshot. Enforce it before local comparisons. When
	// the local snapshot is equally new, an older store response is merely stale
	// and the already-exposed view remains usable.
	if consumer.watermark.Generation > 0 && (current == nil || consumer.watermark.Generation > current.reference.Generation) {
		switch {
		case reference.Generation < consumer.watermark.Generation:
			return refreshResult(current, RefreshStaleIgnored), ErrRollbackDetected
		case reference.Generation == consumer.watermark.Generation && reference.Commit != consumer.watermark.Commit:
			return refreshResult(current, RefreshUnchanged), ErrSplitBrain
		}
	}
	if current != nil {
		switch {
		case reference.Generation < current.reference.Generation:
			return refreshResult(current, RefreshStaleIgnored), nil
		case reference.Generation == current.reference.Generation && reference.Commit != current.reference.Commit:
			return refreshResult(current, RefreshUnchanged), ErrSplitBrain
		case reference.Generation == current.reference.Generation:
			consumer.stateMu.Lock()
			consumer.state.version = object.Version
			consumer.stateMu.Unlock()
			return refreshResult(current, RefreshUnchanged), nil
		}
	}

	var commit commitManifest
	if err := consumer.getManifest(ctx, "commit", reference.Commit, &commit); err != nil {
		return refreshResult(current, RefreshUnchanged), err
	}
	if err := validateCommitManifest(&commit, reference.Generation); err != nil {
		return refreshResult(current, RefreshUnchanged), fmt.Errorf("commit/reference mismatch: %w", err)
	}
	anchor := consumer.watermark
	if current != nil {
		currentWatermark := Watermark{Generation: current.reference.Generation, Commit: current.reference.Commit}
		if consumer.referenceVerifier != nil {
			currentWatermark.RepositoryID = consumer.referenceVerifier.RepositoryID()
		}
		if currentWatermark.Generation > anchor.Generation {
			anchor = currentWatermark
		} else if currentWatermark.Generation == anchor.Generation && currentWatermark.Commit != anchor.Commit {
			return refreshResult(current, RefreshUnchanged), ErrSplitBrain
		}
	}
	if anchor.Generation > 0 && reference.Generation > anchor.Generation {
		if err := consumer.validateDescendant(ctx, reference, &commit, anchor); err != nil {
			return refreshResult(current, RefreshUnchanged), err
		}
	}
	if _, err := consumer.loadDirectory(ctx, commit.Root); err != nil {
		return refreshResult(current, RefreshUnchanged), err
	}
	watermark := Watermark{Generation: reference.Generation, Commit: reference.Commit}
	if consumer.referenceVerifier != nil {
		watermark.RepositoryID = consumer.referenceVerifier.RepositoryID()
	}
	if consumer.watermarks != nil && watermark.Generation > consumer.watermark.Generation {
		var expected *Watermark
		if consumer.watermark.Generation > 0 {
			value := consumer.watermark
			expected = &value
		}
		if err := consumer.persistConsumerWatermark(ctx, expected, watermark); err != nil {
			return refreshResult(current, RefreshUnchanged), err
		}
	}
	if watermark.Generation >= consumer.watermark.Generation {
		consumer.watermark = watermark
	}
	adopted := &adoptedSnapshot{reference: reference, commit: commit, version: object.Version}
	consumer.stateMu.Lock()
	consumer.state = adopted
	consumer.stateMu.Unlock()
	return refreshResult(adopted, RefreshUpdated), nil
}

func (consumer *Consumer) loadWatermark(ctx context.Context) error {
	if consumer.watermarkLoaded {
		return nil
	}
	if consumer.watermarks == nil {
		consumer.watermarkLoaded = true
		return nil
	}
	watermark, found, err := consumer.watermarks.Load(ctx, consumer.channel)
	if err != nil {
		return fmt.Errorf("load consumer watermark: %w", err)
	}
	if !found {
		consumer.watermark = Watermark{}
	}
	if found {
		if watermark.Generation == 0 || watermark.Commit.IsZero() {
			return fmt.Errorf("%w: invalid consumer watermark", ErrCorruptObject)
		}
		if consumer.referenceVerifier != nil {
			if watermark.RepositoryID != consumer.referenceVerifier.RepositoryID() {
				return fmt.Errorf("%w: watermark repository mismatch", ErrUntrustedReference)
			}
		} else if !watermark.RepositoryID.IsZero() {
			return fmt.Errorf("%w: signed watermark used by unsigned consumer", ErrUntrustedReference)
		}
		if consumer.trustedCheckpoint != nil {
			if err := consumer.validateWatermarkCheckpoint(ctx, watermark, *consumer.trustedCheckpoint); err != nil {
				return err
			}
		}
		consumer.watermark = watermark
	}
	if consumer.referenceVerifier != nil && consumer.trustedCheckpoint != nil {
		checkpoint := *consumer.trustedCheckpoint
		if found {
			switch {
			case watermark.Generation < checkpoint.Generation:
				return ErrRollbackDetected
			case watermark.Generation == checkpoint.Generation && watermark.Commit != checkpoint.Commit:
				return ErrSplitBrain
			}
		} else {
			if persistErr := consumer.watermarks.CompareAndSwap(ctx, consumer.channel, nil, checkpoint); persistErr != nil {
				watermark, found, err = consumer.watermarks.Load(ctx, consumer.channel)
				if err != nil {
					return fmt.Errorf("persist trusted checkpoint failed (%v), then reload failed: %w", persistErr, err)
				}
				if !found || watermark.RepositoryID != checkpoint.RepositoryID || watermark.Generation < checkpoint.Generation || (watermark.Generation == checkpoint.Generation && watermark.Commit != checkpoint.Commit) {
					return fmt.Errorf("%w: durable checkpoint initialization is indeterminate or changed concurrently: %v", ErrUntrustedReference, persistErr)
				}
				if err := consumer.validateWatermarkCheckpoint(ctx, watermark, checkpoint); err != nil {
					return err
				}
				consumer.watermark = watermark
			} else {
				consumer.watermark = checkpoint
				found = true
			}
		}
	} else if consumer.referenceVerifier != nil && !found && !consumer.allowTrustOnFirstUse {
		return ErrTrustStateRequired
	}
	consumer.stateMu.RLock()
	current := consumer.state
	consumer.stateMu.RUnlock()
	if consumer.watermarks != nil && current != nil && !found && consumer.watermark.Generation == 0 {
		return ErrTrustStateRequired
	}
	if current != nil && consumer.watermark.Generation > 0 {
		if consumer.watermark.Generation < current.reference.Generation {
			return ErrRollbackDetected
		}
		if consumer.watermark.Generation == current.reference.Generation && consumer.watermark.Commit != current.reference.Commit {
			return ErrSplitBrain
		}
	}
	consumer.watermarkLoaded = true
	return nil
}

func (consumer *Consumer) validateWatermarkCheckpoint(ctx context.Context, watermark, checkpoint Watermark) error {
	anchor := checkpoint
	if !consumer.checkpointValidated.Commit.IsZero() {
		validated := consumer.checkpointValidated
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
		return fmt.Errorf("%w: watermark/checkpoint repository mismatch", ErrUntrustedReference)
	case watermark.Generation < checkpoint.Generation:
		return ErrRollbackDetected
	case watermark.Generation == checkpoint.Generation:
		if watermark.Commit != checkpoint.Commit {
			return ErrSplitBrain
		}
		consumer.checkpointValidated = watermark
		return nil
	}
	var commit commitManifest
	if err := consumer.getManifest(ctx, "commit", watermark.Commit, &commit); err != nil {
		return fmt.Errorf("validate durable watermark against checkpoint: %w", err)
	}
	if err := validateCommitManifest(&commit, watermark.Generation); err != nil {
		return err
	}
	reference := snapshotReference{Format: objectFormatVersion, Generation: watermark.Generation, Commit: watermark.Commit}
	if err := consumer.validateDescendant(ctx, reference, &commit, anchor); err != nil {
		return fmt.Errorf("durable watermark does not descend from trusted checkpoint: %w", err)
	}
	consumer.checkpointValidated = watermark
	return nil
}

func (consumer *Consumer) persistConsumerWatermark(ctx context.Context, expected *Watermark, next Watermark) error {
	err := consumer.watermarks.CompareAndSwap(ctx, consumer.channel, expected, next)
	if err == nil {
		return nil
	}
	observed, found, loadErr := consumer.watermarks.Load(ctx, consumer.channel)
	if loadErr != nil {
		consumer.watermarkLoaded = false
		return fmt.Errorf("persist consumer watermark failed (%v), then reload failed: %w", err, loadErr)
	}
	if found {
		if observed.RepositoryID != next.RepositoryID || observed.Generation == 0 || observed.Commit.IsZero() {
			return fmt.Errorf("%w: invalid consumer watermark after failed CAS", ErrUntrustedReference)
		}
		if observed == next {
			consumer.watermark = observed
			return nil
		}
		if observed.Generation == next.Generation {
			return ErrSplitBrain
		}
		if observed.Generation > next.Generation {
			consumer.watermark = observed
			return fmt.Errorf("persist consumer watermark: %w: durable watermark advanced concurrently", ErrPrecondition)
		}
	}
	consumer.watermarkLoaded = false
	return fmt.Errorf("persist consumer watermark: %w", err)
}

// validateDescendant prevents a weak or split-brain backend from moving a
// consumer between disjoint histories merely by returning a larger generation
// number. Skipped generations are allowed, but their immutable parent chain
// must lead back to the snapshot already exposed by this consumer.
func (consumer *Consumer) validateDescendant(ctx context.Context, reference snapshotReference, commit *commitManifest, anchor Watermark) error {
	if reference.Generation-anchor.Generation > uint64(maxCommitWalk) {
		return fmt.Errorf("%w: commit ancestry exceeds %d generations", ErrResourceLimit, maxCommitWalk)
	}
	parent := commit.Parent
	for generation := reference.Generation - 1; generation > anchor.Generation; generation-- {
		if err := ctx.Err(); err != nil {
			return err
		}
		if parent == nil || parent.IsZero() {
			return fmt.Errorf("%w: candidate history ends before generation %d", ErrSplitBrain, anchor.Generation)
		}
		var ancestor commitManifest
		if err := consumer.getManifest(ctx, "commit", *parent, &ancestor); err != nil {
			return fmt.Errorf("validate commit ancestry at generation %d: %w", generation, err)
		}
		if err := validateCommitManifest(&ancestor, generation); err != nil {
			return fmt.Errorf("validate commit ancestry at generation %d: %w", generation, err)
		}
		parent = ancestor.Parent
	}
	if parent == nil || *parent != anchor.Commit {
		return ErrSplitBrain
	}
	return nil
}

func refreshResult(snapshot *adoptedSnapshot, status RefreshStatus) RefreshResult {
	result := RefreshResult{Status: status}
	if snapshot != nil {
		result.Generation = snapshot.reference.Generation
	}
	return result
}

// CurrentSnapshot returns the adopted snapshot without performing network I/O.
func (consumer *Consumer) CurrentSnapshot() (Snapshot, bool) {
	consumer.stateMu.RLock()
	defer consumer.stateMu.RUnlock()
	if consumer.state == nil {
		return Snapshot{}, false
	}
	state := consumer.state
	return Snapshot{
		Generation:  state.reference.Generation,
		Commit:      state.reference.Commit,
		Root:        state.commit.Root,
		PublishedAt: time.Unix(0, state.commit.PublishedAtUnix).UTC(),
	}, true
}

func (consumer *Consumer) snapshotRoot() (Digest, uint64, error) {
	consumer.stateMu.RLock()
	defer consumer.stateMu.RUnlock()
	if consumer.state == nil {
		return Digest{}, 0, ErrNoSnapshot
	}
	return consumer.state.commit.Root, consumer.state.reference.Generation, nil
}

type resolvedEntry struct {
	entry      dirEntry
	generation uint64
	isRoot     bool
}

func cleanLookupPath(value string) ([]string, error) {
	if len(value) > maxLookupPathBytes {
		return nil, fmt.Errorf("%w: %w: path exceeds %d bytes", ErrInvalidPath, ErrResourceLimit, maxLookupPathBytes)
	}
	if strings.ContainsRune(value, '\x00') {
		return nil, ErrInvalidPath
	}
	value = strings.TrimPrefix(value, "/")
	if value == "" || value == "." {
		return nil, nil
	}
	cleaned := path.Clean(value)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") || cleaned != value {
		return nil, fmt.Errorf("%w: %q", ErrInvalidPath, value)
	}
	components := strings.Split(cleaned, "/")
	if len(components) > maxLookupDepth {
		return nil, fmt.Errorf("%w: %w: path exceeds %d components", ErrInvalidPath, ErrResourceLimit, maxLookupDepth)
	}
	for _, component := range components {
		if len(component) > maxEntryNameBytes {
			return nil, fmt.Errorf("%w: %w: path component exceeds %d bytes", ErrInvalidPath, ErrResourceLimit, maxEntryNameBytes)
		}
	}
	return components, nil
}

func (consumer *Consumer) resolve(ctx context.Context, value string) (resolvedEntry, error) {
	components, err := cleanLookupPath(value)
	if err != nil {
		return resolvedEntry{}, err
	}
	root, generation, err := consumer.snapshotRoot()
	if err != nil {
		return resolvedEntry{}, err
	}
	if len(components) == 0 {
		return resolvedEntry{
			entry:      dirEntry{Type: EntryDir, Node: root, Mode: 0o555},
			generation: generation,
			isRoot:     true,
		}, nil
	}
	directoryDigest := root
	for index, component := range components {
		directory, err := consumer.loadDirectory(ctx, directoryDigest)
		if err != nil {
			return resolvedEntry{}, err
		}
		position := sort.Search(len(directory.Entries), func(i int) bool {
			return bytes.Compare(directory.Entries[i].Name, []byte(component)) >= 0
		})
		if position == len(directory.Entries) || !bytes.Equal(directory.Entries[position].Name, []byte(component)) {
			return resolvedEntry{}, fmt.Errorf("%w: %q", ErrPathNotFound, value)
		}
		entry := directory.Entries[position]
		if index == len(components)-1 {
			return resolvedEntry{entry: entry, generation: generation}, nil
		}
		if entry.Type != EntryDir {
			return resolvedEntry{}, fmt.Errorf("%w: %q", ErrNotDirectory, component)
		}
		directoryDigest = entry.Node
	}
	panic("unreachable")
}

// Stat returns manifest metadata and never downloads file chunks.
func (consumer *Consumer) Stat(ctx context.Context, value string) (Entry, error) {
	resolved, err := consumer.resolve(ctx, value)
	if err != nil {
		return Entry{}, err
	}
	name := ""
	if !resolved.isRoot {
		name = string(resolved.entry.Name)
	}
	return publicEntry(name, resolved.entry), nil
}

// ListDir returns entries from one directory manifest and never downloads file
// chunks or lists S3 keys.
func (consumer *Consumer) ListDir(ctx context.Context, value string) ([]Entry, error) {
	resolved, err := consumer.resolve(ctx, value)
	if err != nil {
		return nil, err
	}
	if resolved.entry.Type != EntryDir {
		return nil, fmt.Errorf("%w: %q", ErrNotDirectory, value)
	}
	directory, err := consumer.loadDirectory(ctx, resolved.entry.Node)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, len(directory.Entries))
	for index, entry := range directory.Entries {
		entries[index] = publicEntry(string(entry.Name), entry)
	}
	return entries, nil
}

func publicEntry(name string, entry dirEntry) Entry {
	return Entry{
		Name:    name,
		Type:    entry.Type,
		Size:    entry.Size,
		Mode:    readonlyMode(entry.Mode),
		ModTime: time.Unix(0, entry.ModTimeUnixNano).UTC(),
	}
}

// Open pins the current file manifest. Reads through the returned handle remain
// on that version even after the Consumer adopts a newer snapshot.
func (consumer *Consumer) Open(ctx context.Context, value string) (*File, error) {
	resolved, err := consumer.resolve(ctx, value)
	if err != nil {
		return nil, err
	}
	if resolved.entry.Type == EntryDir {
		return nil, fmt.Errorf("%w: %q", ErrIsDirectory, value)
	}
	if resolved.entry.Type != EntryFile {
		return nil, fmt.Errorf("%w: %q is %s", ErrUnsupportedType, value, resolved.entry.Type)
	}
	manifest, err := consumer.loadFile(ctx, resolved.entry.Node)
	if err != nil {
		return nil, err
	}
	if manifest.Size != resolved.entry.Size {
		return nil, fmt.Errorf("%w: directory/file size mismatch", ErrCorruptObject)
	}
	return &File{consumer: consumer, manifest: manifest, generation: resolved.generation}, nil
}

// Readlink returns a symlink target without following it.
func (consumer *Consumer) Readlink(ctx context.Context, value string) (string, error) {
	resolved, err := consumer.resolve(ctx, value)
	if err != nil {
		return "", err
	}
	if resolved.entry.Type != EntrySymlink {
		return "", fmt.Errorf("%w: %q is not a symlink", ErrUnsupportedType, value)
	}
	manifest, err := consumer.loadSymlink(ctx, resolved.entry.Node)
	if err != nil {
		return "", err
	}
	if int64(len(manifest.Target)) != resolved.entry.Size {
		return "", fmt.Errorf("%w: directory/symlink size mismatch", ErrCorruptObject)
	}
	if consumer.symlinkPolicy == SymlinkRejectExternal {
		components, err := cleanLookupPath(value)
		if err != nil {
			return "", err
		}
		if err := validateSafeSymlink(strings.Join(components, "/"), string(manifest.Target)); err != nil {
			return "", err
		}
	}
	return string(manifest.Target), nil
}

func (consumer *Consumer) loadDirectory(ctx context.Context, digest Digest) (*dirManifest, error) {
	key := metadataCacheKey{kind: "dir", digest: digest}
	if value, ok := getTypedMetadata[dirManifest](&consumer.metadata, key); ok {
		return value, nil
	}
	loaded, err := consumer.metadataFlight.Do(ctx, key, func(loadCtx context.Context) (any, error) {
		if value, ok := getTypedMetadata[dirManifest](&consumer.metadata, key); ok {
			return value, nil
		}
		var manifest dirManifest
		if err := consumer.downloadManifest(loadCtx, key.kind, digest, &manifest); err != nil {
			return nil, err
		}
		if err := validateDirectoryManifest(&manifest); err != nil {
			return nil, err
		}
		return putTypedMetadata(&consumer.metadata, key, &manifest, estimateDirectoryRetainedBytes(&manifest)), nil
	})
	if err != nil {
		return nil, err
	}
	manifest, ok := loaded.(*dirManifest)
	if !ok {
		return nil, fmt.Errorf("%w: metadata flight returned wrong directory type", ErrCorruptObject)
	}
	return manifest, nil
}

func validateDirectoryManifest(manifest *dirManifest) error {
	if manifest.Format != objectFormatVersion {
		return fmt.Errorf("%w: directory format %d", ErrCorruptObject, manifest.Format)
	}
	if len(manifest.Entries) > maxDirectoryEntries {
		return fmt.Errorf("%w: %w: directory has %d entries (maximum %d)", ErrCorruptObject, ErrResourceLimit, len(manifest.Entries), maxDirectoryEntries)
	}
	for index := range manifest.Entries {
		entry := manifest.Entries[index]
		if len(entry.Name) == 0 || len(entry.Name) > maxEntryNameBytes || bytes.Equal(entry.Name, []byte(".")) || bytes.Equal(entry.Name, []byte("..")) || bytes.ContainsRune(entry.Name, '/') || bytes.IndexByte(entry.Name, 0) >= 0 || entry.Node.IsZero() {
			return fmt.Errorf("%w: invalid directory entry", ErrCorruptObject)
		}
		if entry.Mode&^0o777 != 0 || entry.Size < 0 {
			return fmt.Errorf("%w: invalid mode or size for directory entry %q", ErrCorruptObject, entry.Name)
		}
		if entry.Type != EntryFile && entry.Type != EntryDir && entry.Type != EntrySymlink {
			return fmt.Errorf("%w: invalid entry type %q", ErrCorruptObject, entry.Type)
		}
		switch entry.Type {
		case EntryDir:
			if entry.Size != 0 {
				return fmt.Errorf("%w: directory entry %q has non-zero size", ErrCorruptObject, entry.Name)
			}
		case EntryFile:
			if entry.Size > maxRepresentableFileBytes {
				return fmt.Errorf("%w: %w: file entry %q exceeds maximum size", ErrCorruptObject, ErrResourceLimit, entry.Name)
			}
		case EntrySymlink:
			if entry.Size == 0 || entry.Size > maxSymlinkTargetBytes {
				return fmt.Errorf("%w: %w: symlink entry %q has invalid size", ErrCorruptObject, ErrResourceLimit, entry.Name)
			}
		}
		if index > 0 && bytes.Compare(manifest.Entries[index-1].Name, entry.Name) >= 0 {
			return fmt.Errorf("%w: unsorted or duplicate directory entry", ErrCorruptObject)
		}
	}
	return nil
}

const maxRepresentableFileBytes = int64(maxFileChunks) * int64(maxChunkObjectBytes)

func (consumer *Consumer) loadFile(ctx context.Context, digest Digest) (*fileManifest, error) {
	key := metadataCacheKey{kind: "file", digest: digest}
	if value, ok := getTypedMetadata[fileManifest](&consumer.metadata, key); ok {
		return value, nil
	}
	loaded, err := consumer.metadataFlight.Do(ctx, key, func(loadCtx context.Context) (any, error) {
		if value, ok := getTypedMetadata[fileManifest](&consumer.metadata, key); ok {
			return value, nil
		}
		var manifest fileManifest
		if err := consumer.downloadManifest(loadCtx, key.kind, digest, &manifest); err != nil {
			return nil, err
		}
		if err := validateFileManifest(&manifest); err != nil {
			return nil, err
		}
		return putTypedMetadata(&consumer.metadata, key, &manifest, estimateFileRetainedBytes(&manifest)), nil
	})
	if err != nil {
		return nil, err
	}
	manifest, ok := loaded.(*fileManifest)
	if !ok {
		return nil, fmt.Errorf("%w: metadata flight returned wrong file type", ErrCorruptObject)
	}
	return manifest, nil
}

func validateFileManifest(manifest *fileManifest) error {
	if manifest.Format != objectFormatVersion || manifest.Algorithm != "rabin-v1" || manifest.Size < 0 {
		return fmt.Errorf("%w: invalid file manifest header", ErrCorruptObject)
	}
	if len(manifest.Chunks) > maxFileChunks {
		return fmt.Errorf("%w: %w: file has %d chunks (maximum %d)", ErrCorruptObject, ErrResourceLimit, len(manifest.Chunks), maxFileChunks)
	}
	profile := ChunkingOptions{
		MinSize:     manifest.MinSize,
		AverageSize: manifest.AvgSize,
		MaxSize:     manifest.MaxSize,
		Polynomial:  manifest.Polynomial,
	}
	normalized, err := profile.normalized()
	if err != nil || normalized != profile {
		return fmt.Errorf("%w: invalid chunking profile", ErrCorruptObject)
	}
	var offset int64
	for _, chunk := range manifest.Chunks {
		if chunk.Offset != offset || chunk.Size <= 0 || chunk.Size > int64(manifest.MaxSize) || chunk.Digest.IsZero() {
			return fmt.Errorf("%w: invalid chunk layout", ErrCorruptObject)
		}
		offset += chunk.Size
		if offset < 0 || offset > manifest.Size {
			return fmt.Errorf("%w: chunk layout exceeds file size", ErrCorruptObject)
		}
	}
	if offset != manifest.Size {
		return fmt.Errorf("%w: chunk layout size mismatch", ErrCorruptObject)
	}
	return nil
}

func (consumer *Consumer) loadSymlink(ctx context.Context, digest Digest) (*symlinkManifest, error) {
	key := metadataCacheKey{kind: "symlink", digest: digest}
	if value, ok := getTypedMetadata[symlinkManifest](&consumer.metadata, key); ok {
		return value, nil
	}
	loaded, err := consumer.metadataFlight.Do(ctx, key, func(loadCtx context.Context) (any, error) {
		if value, ok := getTypedMetadata[symlinkManifest](&consumer.metadata, key); ok {
			return value, nil
		}
		var manifest symlinkManifest
		if err := consumer.downloadManifest(loadCtx, key.kind, digest, &manifest); err != nil {
			return nil, err
		}
		if err := validateSymlinkManifest(&manifest); err != nil {
			return nil, err
		}
		return putTypedMetadata(&consumer.metadata, key, &manifest, estimateSymlinkRetainedBytes(&manifest)), nil
	})
	if err != nil {
		return nil, err
	}
	manifest, ok := loaded.(*symlinkManifest)
	if !ok {
		return nil, fmt.Errorf("%w: metadata flight returned wrong symlink type", ErrCorruptObject)
	}
	return manifest, nil
}

func validateSymlinkManifest(manifest *symlinkManifest) error {
	if manifest.Format != objectFormatVersion || len(manifest.Target) == 0 || len(manifest.Target) > maxSymlinkTargetBytes || bytes.IndexByte(manifest.Target, 0) >= 0 {
		return fmt.Errorf("%w: invalid symlink manifest", ErrCorruptObject)
	}
	return nil
}

// File is an immutable snapshot-pinned file handle.
type File struct {
	consumer   *Consumer
	manifest   *fileManifest
	generation uint64
}

func (file *File) Size() int64 { return file.manifest.Size }

func (file *File) Generation() uint64 { return file.generation }

// ReadAt implements io.ReaderAt using context.Background.
func (file *File) ReadAt(destination []byte, offset int64) (int, error) {
	return file.ReadAtContext(context.Background(), destination, offset)
}

// ReadAtContext downloads only chunks intersecting the requested byte range.
func (file *File) ReadAtContext(ctx context.Context, destination []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, fmt.Errorf("s3disk: negative read offset")
	}
	if len(destination) == 0 {
		return 0, nil
	}
	if offset >= file.manifest.Size {
		return 0, io.EOF
	}
	limit := offset + int64(len(destination))
	if limit < offset || limit > file.manifest.Size {
		limit = file.manifest.Size
	}
	written := 0
	index := sort.Search(len(file.manifest.Chunks), func(i int) bool {
		chunk := file.manifest.Chunks[i]
		return chunk.Offset+chunk.Size > offset
	})
	for index < len(file.manifest.Chunks) && offset < limit {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		chunkReference := file.manifest.Chunks[index]
		lease, err := file.consumer.getChunk(ctx, chunkReference.Digest, chunkReference.Size)
		if err != nil {
			return written, err
		}
		copied, err := copyChunkLease(ctx, lease, destination[written:], chunkReference, offset, limit)
		if err != nil {
			return written, err
		}
		written += copied
		offset += int64(copied)
		index++
	}
	if written < len(destination) {
		return written, io.EOF
	}
	return written, nil
}

// copyChunkLease scopes the acknowledgment to one chunk use. The defer is
// intentionally inside this helper so the reservation is released before the
// caller can request its next chunk, including every future error return added
// to validation or copying here.
func copyChunkLease(ctx context.Context, lease *syncutil.BytesLease, destination []byte, chunk chunkRef, offset, limit int64) (int, error) {
	defer lease.Release()
	data := lease.Data()
	if int64(len(data)) != chunk.Size {
		return 0, fmt.Errorf("%w: chunk size mismatch", ErrCorruptObject)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	start := max64(offset, chunk.Offset) - chunk.Offset
	end := min64(limit, chunk.Offset+chunk.Size) - chunk.Offset
	return copy(destination, data[start:end]), nil
}

func min64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}

func max64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}

func (consumer *Consumer) getChunk(ctx context.Context, digest Digest, expectedSize int64) (*syncutil.BytesLease, error) {
	if expectedSize < 1 || expectedSize > maxChunkObjectBytes {
		return nil, fmt.Errorf("%w: invalid expected chunk size %d", ErrCorruptObject, expectedSize)
	}
	var cacheErrors []error
	key := chunkFlightKey{digest: digest, expectedSize: expectedSize}
	return consumer.chunkFlight.Do(ctx, key, func(loadCtx context.Context) (_ []byte, ownership func(), returnErr error) {
		release, err := consumer.acquireDownload(loadCtx, expectedSize)
		if err != nil {
			return nil, nil, err
		}
		transferred := false
		defer func() {
			if !transferred {
				release()
			}
		}()
		// Cache reads can allocate and hash a complete chunk. Keep them inside
		// both the digest+size flight and the shared count/byte semaphores so many
		// concurrent cached reads cannot bypass either resource limit.
		if data, found, err := consumer.getCachedChunk(loadCtx, digest, expectedSize, func(err error) {
			cacheErrors = append(cacheErrors, err)
		}); err != nil {
			return nil, nil, err
		} else if found {
			transferred = true
			return data, release, nil
		}
		data, err := consumer.repository.getImmutableExact(loadCtx, "chunk", digest, expectedSize)
		if err != nil {
			return nil, nil, err
		}
		if consumer.cache != nil {
			if err := consumer.cache.Put(loadCtx, digest, data); err != nil {
				if consumer.strictCacheErrors {
					return nil, nil, err
				}
				cacheErrors = append(cacheErrors, err)
			}
		}
		transferred = true
		return data, release, nil
	}, func() {
		for _, err := range cacheErrors {
			consumer.reportCacheError(err)
		}
	})
}

func (consumer *Consumer) getManifest(ctx context.Context, kind string, digest Digest, value any) error {
	if kind != "commit" {
		return fmt.Errorf("s3disk: unsupported uncached metadata kind %q", kind)
	}
	destination, ok := value.(*commitManifest)
	if !ok {
		return fmt.Errorf("s3disk: invalid commit manifest destination %T", value)
	}
	key := metadataCacheKey{kind: kind, digest: digest}
	loaded, err := consumer.metadataFlight.Do(ctx, key, func(loadCtx context.Context) (any, error) {
		var manifest commitManifest
		if err := consumer.downloadManifest(loadCtx, kind, digest, &manifest); err != nil {
			return nil, err
		}
		return &manifest, nil
	})
	if err != nil {
		return err
	}
	manifest, ok := loaded.(*commitManifest)
	if !ok {
		return fmt.Errorf("%w: metadata flight returned wrong commit type", ErrCorruptObject)
	}
	*destination = *manifest
	return nil
}

func (consumer *Consumer) downloadManifest(ctx context.Context, kind string, digest Digest, value any) error {
	release, err := consumer.acquireDownload(ctx, maxMetadataObjectBytes)
	if err != nil {
		return err
	}
	defer release()
	return consumer.repository.getManifest(ctx, kind, digest, value)
}

func (consumer *Consumer) downloadReference(ctx context.Context, ifNoneMatch string) (snapshotReference, Object, error) {
	release, err := consumer.acquireDownload(ctx, maxReferenceBytes)
	if err != nil {
		return snapshotReference{}, Object{}, err
	}
	defer release()
	reference, object, err := consumer.repository.getReferenceWithVerifier(ctx, consumer.channel, ifNoneMatch, consumer.referenceVerifier)
	// Consumer callers retain only the validated version token. Do not let the
	// raw reference JSON outlive its download reservation.
	object.Data = nil
	return reference, object, err
}

func (consumer *Consumer) acquireDownload(ctx context.Context, byteCharge int64) (func(), error) {
	select {
	case consumer.downloadSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := consumer.downloadBytes.Acquire(ctx, byteCharge); err != nil {
		<-consumer.downloadSlots
		return nil, err
	}
	return func() {
		consumer.downloadBytes.Release(byteCharge)
		<-consumer.downloadSlots
	}, nil
}

func (consumer *Consumer) getCachedChunk(ctx context.Context, digest Digest, expectedSize int64, collectCacheError func(error)) ([]byte, bool, error) {
	if consumer.cache == nil {
		return nil, false, nil
	}
	var data []byte
	var found bool
	var err error
	if sized, ok := consumer.cache.(SizedChunkCache); ok {
		data, found, err = sized.GetSized(ctx, digest, expectedSize)
	} else {
		data, found, err = consumer.cache.Get(ctx, digest)
	}
	if err != nil {
		if errors.Is(err, ErrCorruptObject) || consumer.strictCacheErrors {
			return nil, false, err
		}
		collectCacheError(err)
		return nil, false, nil
	}
	if !found {
		return nil, false, nil
	}
	if int64(len(data)) != expectedSize {
		return nil, false, fmt.Errorf("%w: cache returned chunk size %d, expected %d", ErrCorruptObject, len(data), expectedSize)
	}
	if digestObject("chunk", data) != digest {
		return nil, false, fmt.Errorf("%w: cache returned wrong chunk", ErrCorruptObject)
	}
	return data, true, nil
}

func (consumer *Consumer) reportCacheError(err error) {
	if err == nil || consumer.onCacheError == nil {
		return
	}
	func() {
		defer func() { _ = recover() }()
		consumer.onCacheError(err)
	}()
}

type chunkFlightKey struct {
	digest       Digest
	expectedSize int64
}

var _ io.ReaderAt = (*File)(nil)
