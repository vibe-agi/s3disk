package s3disk

import (
	"container/heap"
	"container/list"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ChunkCache stores verified raw chunks outside the mounted tree. Get transfers
// an immutable, caller-owned byte slice: the implementation must not mutate or
// reuse it after returning. Put must finish consuming or copy data before it
// returns and must never mutate the caller's slice. Implementations must honor
// ctx and impose their own finite pre-allocation/object-size bound; Consumer
// cannot retroactively limit memory allocated inside a third-party Get.
// DiskCache implements these requirements.
type ChunkCache interface {
	Get(ctx context.Context, digest Digest) (data []byte, found bool, err error)
	Put(ctx context.Context, digest Digest, data []byte) error
}

// SizedChunkCache is an optional, source-compatible extension which lets a
// Consumer communicate the exact manifest size before a cache allocates a
// return buffer. Custom caches should implement it when they allocate on Get.
type SizedChunkCache interface {
	ChunkCache
	GetSized(ctx context.Context, digest Digest, expectedSize int64) (data []byte, found bool, err error)
}

const (
	// DefaultDiskCacheMaxBytes is the finite capacity used by NewDiskCache.
	DefaultDiskCacheMaxBytes int64 = 10 << 30
	// DefaultDiskCacheMaxChunkBytes bounds allocation for any one cache entry.
	DefaultDiskCacheMaxChunkBytes int64 = 64 << 20
	// DefaultDiskCacheMaxEntries bounds the in-memory cache index independently
	// of the byte capacity (important for repositories with very small chunks).
	DefaultDiskCacheMaxEntries = 100_000

	// DiskCacheMaxChunkBytesLimit is the protocol's maximum chunk size. A cache
	// cannot receive a larger valid chunk, so accepting a larger allocation limit
	// would only increase the impact of configuration mistakes.
	DiskCacheMaxChunkBytesLimit int64 = maxChunkObjectBytes
	// DiskCacheMaxEntriesLimit bounds the memory used by the cache index even
	// when a caller supplies an unexpectedly large option.
	DiskCacheMaxEntriesLimit = 1_000_000
	// DiskCacheMaxBytesLimit is the largest payload capacity representable by the
	// maximum number of maximum-size protocol chunks.
	DiskCacheMaxBytesLimit int64 = int64(DiskCacheMaxEntriesLimit) * DiskCacheMaxChunkBytesLimit
	// DiskCacheMaxStartupScanEntriesLimit bounds directory work while opening a
	// cache. It permits up to twice the maximum retained entry count plus all 256
	// valid digest shards, so startup can evict an overfull cache without an
	// unbounded filesystem scan.
	DiskCacheMaxStartupScanEntriesLimit = 2*DiskCacheMaxEntriesLimit + 256
)

// DiskCacheOptions controls local cache resource limits. Zero values select
// finite defaults. Chunks larger than MaxBytes or MaxChunkBytes are valid but
// are deliberately not cached. MaxStartupScanEntries bounds all directory
// entries inspected by the constructor; zero selects twice MaxEntries plus the
// 256 possible digest shards.
type DiskCacheOptions struct {
	MaxBytes              int64
	MaxChunkBytes         int64
	MaxEntries            int
	MaxStartupScanEntries int
}

func (options DiskCacheOptions) normalized() (DiskCacheOptions, error) {
	if options.MaxBytes == 0 {
		options.MaxBytes = DefaultDiskCacheMaxBytes
	}
	if options.MaxChunkBytes == 0 {
		options.MaxChunkBytes = DefaultDiskCacheMaxChunkBytes
	}
	if options.MaxEntries == 0 {
		options.MaxEntries = DefaultDiskCacheMaxEntries
	}
	if options.MaxBytes < 1 {
		return DiskCacheOptions{}, fmt.Errorf("%w: disk cache max bytes must be positive", ErrResourceLimit)
	}
	if options.MaxChunkBytes < 1 {
		return DiskCacheOptions{}, fmt.Errorf("%w: disk cache max chunk bytes must be positive", ErrResourceLimit)
	}
	if options.MaxEntries < 1 {
		return DiskCacheOptions{}, fmt.Errorf("%w: disk cache max entries must be positive", ErrResourceLimit)
	}
	if options.MaxBytes > DiskCacheMaxBytesLimit {
		return DiskCacheOptions{}, fmt.Errorf("%w: disk cache max bytes exceeds %d", ErrResourceLimit, DiskCacheMaxBytesLimit)
	}
	if options.MaxChunkBytes > DiskCacheMaxChunkBytesLimit {
		return DiskCacheOptions{}, fmt.Errorf("%w: disk cache max chunk bytes exceeds %d", ErrResourceLimit, DiskCacheMaxChunkBytesLimit)
	}
	if options.MaxEntries > DiskCacheMaxEntriesLimit {
		return DiskCacheOptions{}, fmt.Errorf("%w: disk cache max entries exceeds %d", ErrResourceLimit, DiskCacheMaxEntriesLimit)
	}
	if options.MaxStartupScanEntries == 0 {
		options.MaxStartupScanEntries = 2*options.MaxEntries + 256
	}
	if options.MaxStartupScanEntries < 1 {
		return DiskCacheOptions{}, fmt.Errorf("%w: disk cache max startup scan entries must be positive", ErrResourceLimit)
	}
	if options.MaxStartupScanEntries > DiskCacheMaxStartupScanEntriesLimit {
		return DiskCacheOptions{}, fmt.Errorf("%w: disk cache max startup scan entries exceeds %d", ErrResourceLimit, DiskCacheMaxStartupScanEntriesLimit)
	}
	if options.MaxChunkBytes > options.MaxBytes {
		options.MaxChunkBytes = options.MaxBytes
	}
	return options, nil
}

// DiskCache is a verified, content-addressed chunk cache with bounded disk and
// index usage. It is safe for concurrent use by goroutines. One cache directory
// must not be used concurrently by multiple DiskCache instances or processes.
//
// Writes use a same-directory temporary file and fsync the file before rename.
// Platforms which support durable directory synchronization also fsync the
// containing directory after installation. Cache loss after a machine failure
// is harmless: immutable chunks are always revalidated and can be fetched again
// from the object store.
type DiskCache struct {
	root       string
	chunksRoot string
	rootHandle *os.Root
	rootInfo   os.FileInfo
	chunksInfo os.FileInfo
	digestInfo os.FileInfo
	options    DiskCacheOptions

	lifecycleMu sync.RWMutex
	closed      bool

	mu         sync.Mutex
	entries    map[Digest]*diskCacheEntry
	lru        list.List // front is most recently used
	totalBytes int64

	// Serialize temporary writes so in-flight partial files consume at most one
	// additional MaxChunkBytes beyond the configured cache capacity.
	writeToken chan struct{}
}

type diskCacheEntry struct {
	digest  Digest
	size    int64
	pins    int
	invalid bool
	element *list.Element
}

// NewDiskCache opens a cache using finite production-safe defaults. Call Close
// when the cache is no longer needed.
func NewDiskCache(root string) (*DiskCache, error) {
	return NewDiskCacheWithOptions(root, DiskCacheOptions{})
}

// NewDiskCacheWithOptions opens a bounded cache and indexes existing entries.
// Structurally invalid files, oversized entries, stale partial files, and empty
// invalid directories are removed. A non-empty invalid directory is rejected
// with ErrResourceLimit rather than recursively walking an unbounded tree.
// Chunk contents are verified lazily on first read so opening a large cache
// does not require reading its entire contents. Call Close when the cache is no
// longer needed.
func NewDiskCacheWithOptions(root string, options DiskCacheOptions) (*DiskCache, error) {
	if root == "" {
		return nil, fmt.Errorf("s3disk: empty cache directory")
	}
	normalized, err := options.normalized()
	if err != nil {
		return nil, err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	root, err = prepareWatermarkDirectory(root)
	if err != nil {
		return nil, fmt.Errorf("create cache: %w", err)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("inspect cache root: %w", err)
	}
	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("s3disk: cache root is not a directory")
	}
	if err := validateWatermarkDirectory(root); err != nil {
		return nil, fmt.Errorf("s3disk: unsafe cache root: %w", err)
	}
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("open cache root: %w", err)
	}
	keepRootHandle := false
	defer func() {
		if !keepRootHandle {
			_ = rootHandle.Close()
		}
	}()
	rootInfo, err = validateManagedDirectory(rootHandle, ".", root, rootInfo)
	if err != nil {
		return nil, fmt.Errorf("validate cache root handle: %w", err)
	}
	chunksDirectory := filepath.Join(root, "chunks")
	chunksInfo, err := ensureManagedDirectory(rootHandle, "chunks", chunksDirectory)
	if err != nil {
		return nil, fmt.Errorf("create cache object directory: %w", err)
	}
	chunksRoot := filepath.Join(chunksDirectory, "sha256")
	digestInfo, err := ensureManagedDirectory(rootHandle, filepath.Join("chunks", "sha256"), chunksRoot)
	if err != nil {
		return nil, fmt.Errorf("create cache digest directory: %w", err)
	}
	cache := &DiskCache{
		root:       root,
		chunksRoot: chunksRoot,
		rootHandle: rootHandle,
		rootInfo:   rootInfo,
		chunksInfo: chunksInfo,
		digestInfo: digestInfo,
		options:    normalized,
		entries:    make(map[Digest]*diskCacheEntry),
		writeToken: make(chan struct{}, 1),
	}
	if err := cache.indexExisting(); err != nil {
		return nil, err
	}
	keepRootHandle = true
	return cache, nil
}

func (cache *DiskCache) chunkPath(digest Digest) string {
	value := digest.String()
	return filepath.Join(cache.chunksRoot, value[:2], value)
}

// Close releases the directory handle which confines cache filesystem access.
// It waits for active Get and Put calls to finish, prevents new calls from
// starting, and is safe to call more than once. Calls after Close return an
// error matching os.ErrClosed.
func (cache *DiskCache) Close() error {
	if cache == nil {
		return nil
	}
	cache.lifecycleMu.Lock()
	defer cache.lifecycleMu.Unlock()
	if cache.closed {
		return nil
	}
	cache.closed = true
	if cache.rootHandle == nil {
		return nil
	}
	err := cache.rootHandle.Close()
	cache.rootHandle = nil
	return err
}

func (cache *DiskCache) beginOperation() error {
	if cache == nil {
		return fmt.Errorf("s3disk: disk cache: %w", os.ErrClosed)
	}
	cache.lifecycleMu.RLock()
	if cache.closed || cache.rootHandle == nil {
		cache.lifecycleMu.RUnlock()
		return fmt.Errorf("s3disk: disk cache: %w", os.ErrClosed)
	}
	return nil
}

func (cache *DiskCache) endOperation() {
	cache.lifecycleMu.RUnlock()
}

func (cache *DiskCache) Get(ctx context.Context, digest Digest) ([]byte, bool, error) {
	return cache.get(ctx, digest, 0)
}

// GetSized avoids allocating or reading an entry whose indexed and on-disk
// size differs from the caller's validated file manifest.
func (cache *DiskCache) GetSized(ctx context.Context, digest Digest, expectedSize int64) ([]byte, bool, error) {
	if expectedSize < 1 || expectedSize > maxChunkObjectBytes {
		return nil, false, fmt.Errorf("%w: invalid expected cache chunk size %d", ErrResourceLimit, expectedSize)
	}
	return cache.get(ctx, digest, expectedSize)
}

func (cache *DiskCache) get(ctx context.Context, digest Digest, expectedSize int64) ([]byte, bool, error) {
	if err := cache.beginOperation(); err != nil {
		return nil, false, err
	}
	defer cache.endOperation()
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if err := cache.validateLayout(); err != nil {
		return nil, false, err
	}
	cache.mu.Lock()
	entry := cache.entries[digest]
	if entry == nil || entry.invalid || (expectedSize > 0 && entry.size != expectedSize) {
		cache.mu.Unlock()
		return nil, false, nil
	}
	entry.pins++
	cache.lru.MoveToFront(entry.element)
	cache.mu.Unlock()

	data, valid, err := cache.readEntry(ctx, entry, expectedSize)
	if err != nil {
		cache.unpin(entry)
		return nil, false, err
	}
	if !valid {
		if err := cache.discardPinned(entry); err != nil {
			return nil, false, err
		}
		return nil, false, nil
	}
	cache.unpin(entry)
	return data, true, nil
}

func (cache *DiskCache) readEntry(ctx context.Context, entry *diskCacheEntry, expectedSize int64) ([]byte, bool, error) {
	value := entry.digest.String()
	shardName := value[:2]
	shard, shardInfo, err := cache.openShard(shardName, false)
	if err != nil {
		return nil, false, err
	}
	defer shard.Close()
	linked, err := shard.Lstat(value)
	if errors.Is(err, os.ErrNotExist) {
		if validateErr := cache.validateShard(shardName, shardInfo); validateErr != nil {
			return nil, false, validateErr
		}
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("inspect chunk cache: %w", err)
	}
	if !linked.Mode().IsRegular() || linked.Mode()&os.ModeSymlink != 0 {
		return nil, false, nil
	}
	file, err := shard.Open(value)
	if err != nil {
		return nil, false, fmt.Errorf("open chunk cache: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, false, fmt.Errorf("stat chunk cache: %w", err)
	}
	if !info.Mode().IsRegular() || !os.SameFile(linked, info) || info.Size() != entry.size || info.Size() < 1 || info.Size() > cache.options.MaxChunkBytes || (expectedSize > 0 && info.Size() != expectedSize) {
		return nil, false, nil
	}
	data := make([]byte, int(info.Size()))
	read := 0
	for read < len(data) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		count, readErr := file.Read(data[read:])
		read += count
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil, false, nil
			}
			return nil, false, fmt.Errorf("read chunk cache: %w", readErr)
		}
		if count == 0 {
			return nil, false, nil
		}
	}
	var extra [1]byte
	count, readErr := file.Read(extra[:])
	if count != 0 || (readErr != nil && !errors.Is(readErr, io.EOF)) {
		return nil, false, nil
	}
	if digestObject("chunk", data) != entry.digest {
		return nil, false, nil
	}
	// Persist approximate recency through the already-open file handle. A
	// pathname-based timestamp update could follow a concurrently substituted
	// symlink outside the cache root on Unix.
	_ = touchCacheFile(file, time.Now())
	if err := cache.validateShard(shardName, shardInfo); err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func (cache *DiskCache) unpin(entry *diskCacheEntry) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if current := cache.entries[entry.digest]; current == entry && entry.pins > 0 {
		entry.pins--
		if entry.invalid && entry.pins == 0 {
			// A concurrent reader already rejected this disposable entry. Best-effort
			// cleanup here must not turn this reader's verified hit into an error.
			_ = cache.removeEntryLocked(entry)
		}
	}
}

func (cache *DiskCache) discardPinned(entry *diskCacheEntry) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	current := cache.entries[entry.digest]
	if current != entry {
		return nil
	}
	entry.invalid = true
	if entry.pins > 0 {
		entry.pins--
	}
	if entry.pins != 0 {
		// Other readers already hold the file open. Mark it unavailable to new
		// callers; the final reader removes it when releasing its pin.
		return nil
	}
	return cache.removeEntryLocked(entry)
}

func (cache *DiskCache) Put(ctx context.Context, digest Digest, data []byte) error {
	if err := cache.beginOperation(); err != nil {
		return err
	}
	defer cache.endOperation()
	if err := ctx.Err(); err != nil {
		return err
	}
	size := int64(len(data))
	if size < 1 || size > cache.options.MaxChunkBytes || size > cache.options.MaxBytes {
		return nil
	}
	if digestObject("chunk", data) != digest {
		return fmt.Errorf("%w: refusing cache write for %s", ErrCorruptObject, digest)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case cache.writeToken <- struct{}{}:
		defer func() { <-cache.writeToken }()
	case <-ctx.Done():
		return ctx.Err()
	}

	value := digest.String()
	shardName := value[:2]
	shard, shardInfo, err := cache.openShard(shardName, true)
	if err != nil {
		return fmt.Errorf("create cache shard: %w", err)
	}
	defer shard.Close()
	temporary, temporaryName, err := createCacheTemporary(shard)
	if err != nil {
		return fmt.Errorf("create cache temporary file: %w", err)
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = shard.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect cache temporary file: %w", err)
	}
	for written := 0; written < len(data); {
		if err := ctx.Err(); err != nil {
			_ = temporary.Close()
			return err
		}
		end := written + 1<<20
		if end > len(data) {
			end = len(data)
		}
		count, writeErr := temporary.Write(data[written:end])
		written += count
		if writeErr != nil {
			_ = temporary.Close()
			return fmt.Errorf("write cache temporary file: %w", writeErr)
		}
		if count == 0 {
			_ = temporary.Close()
			return fmt.Errorf("write cache temporary file: %w", io.ErrShortWrite)
		}
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync cache temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close cache temporary file: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	cache.mu.Lock()
	if existing := cache.entries[digest]; existing != nil {
		if existing.pins != 0 {
			cache.mu.Unlock()
			return nil
		}
		if err := cache.removeEntryLocked(existing); err != nil {
			cache.mu.Unlock()
			return err
		}
	}
	room, roomErr := cache.makeRoomLocked(size)
	if roomErr != nil {
		cache.mu.Unlock()
		return roomErr
	}
	if !room {
		cache.mu.Unlock()
		return nil
	}
	if err := cache.validateShard(shardName, shardInfo); err != nil {
		cache.mu.Unlock()
		return err
	}
	if err := shard.Remove(value); err != nil && !errors.Is(err, os.ErrNotExist) {
		cache.mu.Unlock()
		return fmt.Errorf("replace cache entry: %w", err)
	}
	if err := shard.Rename(temporaryName, value); err != nil {
		cache.mu.Unlock()
		return fmt.Errorf("install cache entry: %w", err)
	}
	removeTemporary = false
	if err := syncCacheRootDirectory(shard); err != nil {
		_ = shard.Remove(value)
		cache.mu.Unlock()
		return fmt.Errorf("sync cache shard: %w", err)
	}
	if err := cache.validateShard(shardName, shardInfo); err != nil {
		_ = shard.Remove(value)
		_ = syncCacheRootDirectory(shard)
		cache.mu.Unlock()
		return err
	}
	entry := &diskCacheEntry{digest: digest, size: size}
	entry.element = cache.lru.PushFront(entry)
	cache.entries[digest] = entry
	cache.totalBytes += size
	cache.mu.Unlock()
	return nil
}

func (cache *DiskCache) makeRoomLocked(size int64) (bool, error) {
	for cache.totalBytes > cache.options.MaxBytes-size || len(cache.entries) >= cache.options.MaxEntries {
		var victim *diskCacheEntry
		for element := cache.lru.Back(); element != nil; element = element.Prev() {
			candidate := element.Value.(*diskCacheEntry)
			if candidate.pins == 0 {
				victim = candidate
				break
			}
		}
		if victim == nil {
			return false, nil
		}
		if err := cache.removeEntryLocked(victim); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (cache *DiskCache) removeEntryLocked(entry *diskCacheEntry) error {
	if entry.pins != 0 {
		return fmt.Errorf("s3disk: cannot remove pinned cache entry")
	}
	value := entry.digest.String()
	shardName := value[:2]
	shard, shardInfo, openErr := cache.openShard(shardName, false)
	if openErr != nil {
		return openErr
	}
	defer shard.Close()
	err := shard.Remove(value)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove cache entry: %w", err)
	}
	delete(cache.entries, entry.digest)
	cache.lru.Remove(entry.element)
	cache.totalBytes -= entry.size
	if cache.totalBytes < 0 {
		cache.totalBytes = 0
	}
	if err == nil {
		if syncErr := syncCacheRootDirectory(shard); syncErr != nil {
			return fmt.Errorf("sync cache eviction: %w", syncErr)
		}
	}
	if validateErr := cache.validateShard(shardName, shardInfo); validateErr != nil {
		return validateErr
	}
	return nil
}

type startupCandidate struct {
	digest  Digest
	shard   string
	size    int64
	modTime time.Time
}

func (candidate startupCandidate) sortKey() string {
	return filepath.Join(candidate.shard, candidate.digest.String())
}

type startupCandidateHeap []startupCandidate

func (values startupCandidateHeap) Len() int { return len(values) }
func (values startupCandidateHeap) Less(i, j int) bool {
	if values[i].modTime.Equal(values[j].modTime) {
		return values[i].sortKey() < values[j].sortKey()
	}
	return values[i].modTime.Before(values[j].modTime)
}
func (values startupCandidateHeap) Swap(i, j int) { values[i], values[j] = values[j], values[i] }
func (values *startupCandidateHeap) Push(value any) {
	*values = append(*values, value.(startupCandidate))
}
func (values *startupCandidateHeap) Pop() any {
	old := *values
	last := old[len(old)-1]
	*values = old[:len(old)-1]
	return last
}

func (cache *DiskCache) indexExisting() error {
	if err := cache.validateLayout(); err != nil {
		return fmt.Errorf("index disk cache: %w", err)
	}
	var candidates startupCandidateHeap
	var total uint64
	remainingScanEntries := cache.options.MaxStartupScanEntries
	consumeScanEntry := func() error {
		if remainingScanEntries == 0 {
			return fmt.Errorf("%w: disk cache startup scan exceeds %d directory entries", ErrResourceLimit, cache.options.MaxStartupScanEntries)
		}
		remainingScanEntries--
		return nil
	}
	// Read directories in bounded batches rather than filepath.WalkDir, which
	// materializes every name in a directory and can itself become an allocation
	// attack when opening an untrusted or damaged cache directory.
	digestRelative := filepath.Join("chunks", "sha256")
	err := readCacheDirectoryBatches(cache.rootHandle, digestRelative, cache.digestInfo, func(entry os.DirEntry) error {
		if err := consumeScanEntry(); err != nil {
			return err
		}
		shardRelative := filepath.Join(digestRelative, entry.Name())
		if !entry.IsDir() || !validCacheShard(entry.Name()) {
			if err := cache.rootHandle.Remove(shardRelative); err != nil {
				return fmt.Errorf("%w: remove invalid cache path %q without recursive scan: %v", ErrResourceLimit, shardRelative, err)
			}
			return nil
		}
		shard, shardInfo, err := cache.openShard(entry.Name(), false)
		if err != nil {
			return err
		}
		defer shard.Close()
		modified := false
		err = readCacheDirectoryBatches(shard, ".", shardInfo, func(chunkEntry os.DirEntry) error {
			if err := consumeScanEntry(); err != nil {
				return err
			}
			if chunkEntry.IsDir() {
				if err := shard.Remove(chunkEntry.Name()); err != nil {
					return fmt.Errorf("%w: remove invalid cache directory %q without recursive scan: %v", ErrResourceLimit, chunkEntry.Name(), err)
				}
				modified = true
				return nil
			}
			candidate, valid, err := cache.startupCandidate(shard, entry.Name(), chunkEntry)
			if err != nil {
				return err
			}
			if !valid {
				if err := shard.Remove(chunkEntry.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("remove invalid cache entry %q: %w", chunkEntry.Name(), err)
				}
				modified = true
				return nil
			}
			heap.Push(&candidates, candidate)
			total += uint64(candidate.size)
			for candidates.Len() > cache.options.MaxEntries || total > uint64(cache.options.MaxBytes) {
				oldest := heap.Pop(&candidates).(startupCandidate)
				total -= uint64(oldest.size)
				if err := cache.removeStartupCandidate(oldest); err != nil {
					return fmt.Errorf("evict cache entry %q during startup: %w", oldest.sortKey(), err)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		if modified {
			if err := syncCacheRootDirectory(shard); err != nil {
				return fmt.Errorf("sync cleaned cache shard %q: %w", entry.Name(), err)
			}
		}
		return cache.validateShard(entry.Name(), shardInfo)
	})
	if err != nil {
		return fmt.Errorf("index disk cache: %w", err)
	}
	// Heap order is not iteration order. Rebuild newest-to-oldest so the in-memory
	// list has a meaningful approximate LRU immediately after restart.
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].modTime.Equal(candidates[j].modTime) {
			return candidates[i].sortKey() > candidates[j].sortKey()
		}
		return candidates[i].modTime.After(candidates[j].modTime)
	})
	for _, candidate := range candidates {
		entry := &diskCacheEntry{digest: candidate.digest, size: candidate.size}
		entry.element = cache.lru.PushBack(entry)
		cache.entries[entry.digest] = entry
		cache.totalBytes += entry.size
	}
	if err := cache.validateLayout(); err != nil {
		return fmt.Errorf("index disk cache: %w", err)
	}
	return nil
}

func (cache *DiskCache) startupCandidate(shardRoot *os.Root, shard string, entry os.DirEntry) (startupCandidate, bool, error) {
	if strings.HasPrefix(entry.Name(), ".partial-") {
		return startupCandidate{}, false, nil
	}
	digest, err := ParseDigest(entry.Name())
	if err != nil || entry.Name() != digest.String() || shard != digest.String()[:2] {
		return startupCandidate{}, false, nil
	}
	info, err := shardRoot.Lstat(entry.Name())
	if err != nil {
		return startupCandidate{}, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > cache.options.MaxChunkBytes || info.Size() > cache.options.MaxBytes {
		return startupCandidate{}, false, nil
	}
	return startupCandidate{digest: digest, shard: shard, size: info.Size(), modTime: info.ModTime()}, true, nil
}

func validCacheShard(value string) bool {
	return len(value) == 2 && strings.ContainsRune("0123456789abcdef", rune(value[0])) && strings.ContainsRune("0123456789abcdef", rune(value[1]))
}

func readCacheDirectoryBatches(root *os.Root, name string, expected os.FileInfo, visit func(os.DirEntry) error) error {
	linked, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !linked.IsDir() || linked.Mode()&os.ModeSymlink != 0 || !os.SameFile(linked, expected) {
		return fmt.Errorf("%w: cache directory identity changed", ErrCorruptObject)
	}
	directory, err := root.Open(name)
	if err != nil {
		return err
	}
	defer directory.Close()
	opened, err := directory.Stat()
	if err != nil {
		return err
	}
	if !opened.IsDir() || !os.SameFile(linked, opened) {
		return fmt.Errorf("%w: cache directory changed while opening", ErrCorruptObject)
	}
	for {
		entries, readErr := directory.ReadDir(256)
		for _, entry := range entries {
			if err := visit(entry); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	after, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !after.IsDir() || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(after, expected) || !os.SameFile(opened, after) {
		return fmt.Errorf("%w: cache directory identity changed during scan", ErrCorruptObject)
	}
	return nil
}

func ensureManagedDirectory(root *os.Root, relative, absolute string) (os.FileInfo, error) {
	err := root.Mkdir(relative, 0o700)
	created := err == nil
	if err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := validateManagedDirectory(root, relative, absolute, nil)
	if err != nil {
		return nil, err
	}
	if created {
		parent := filepath.Dir(relative)
		if err := syncCacheDirectoryAt(root, parent); err != nil {
			return nil, fmt.Errorf("sync parent directory: %w", err)
		}
	}
	return info, nil
}

func validateManagedDirectory(root *os.Root, relative, absolute string, expected os.FileInfo) (os.FileInfo, error) {
	linked, err := root.Lstat(relative)
	if err != nil {
		return nil, err
	}
	if !linked.IsDir() || linked.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: managed cache path is not a real directory", ErrCorruptObject)
	}
	directory, err := root.Open(relative)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	opened, err := validateWatermarkOpenedPath(absolute, linked, directory, true)
	if err != nil {
		return nil, fmt.Errorf("unsafe managed directory: %w", err)
	}
	if expected != nil && !os.SameFile(expected, opened) {
		return nil, fmt.Errorf("%w: managed cache directory identity changed", ErrCorruptObject)
	}
	return opened, nil
}

func (cache *DiskCache) validateLayout() error {
	if cache == nil || cache.rootHandle == nil || cache.rootInfo == nil || cache.chunksInfo == nil || cache.digestInfo == nil {
		return fmt.Errorf("%w: cache layout is not initialized", ErrCorruptObject)
	}
	absoluteRoot, err := os.Lstat(cache.root)
	if err != nil {
		return fmt.Errorf("%w: inspect cache root: %v", ErrCorruptObject, err)
	}
	if !absoluteRoot.IsDir() || absoluteRoot.Mode()&os.ModeSymlink != 0 || !os.SameFile(absoluteRoot, cache.rootInfo) {
		return fmt.Errorf("%w: cache root identity changed", ErrCorruptObject)
	}
	if _, err := validateManagedDirectory(cache.rootHandle, ".", cache.root, cache.rootInfo); err != nil {
		return fmt.Errorf("%w: validate cache root: %v", ErrCorruptObject, err)
	}
	chunksDirectory := filepath.Join(cache.root, "chunks")
	if _, err := validateManagedDirectory(cache.rootHandle, "chunks", chunksDirectory, cache.chunksInfo); err != nil {
		return fmt.Errorf("%w: validate cache object directory: %v", ErrCorruptObject, err)
	}
	digestRelative := filepath.Join("chunks", "sha256")
	if _, err := validateManagedDirectory(cache.rootHandle, digestRelative, cache.chunksRoot, cache.digestInfo); err != nil {
		return fmt.Errorf("%w: validate cache digest directory: %v", ErrCorruptObject, err)
	}
	after, err := os.Lstat(cache.root)
	if err != nil {
		return fmt.Errorf("%w: re-inspect cache root: %v", ErrCorruptObject, err)
	}
	if !after.IsDir() || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(after, cache.rootInfo) {
		return fmt.Errorf("%w: cache root identity changed during validation", ErrCorruptObject)
	}
	return nil
}

func (cache *DiskCache) validateShard(name string, expected os.FileInfo) error {
	if !validCacheShard(name) || expected == nil {
		return fmt.Errorf("%w: invalid cache shard identity", ErrCorruptObject)
	}
	if err := cache.validateLayout(); err != nil {
		return err
	}
	relative := filepath.Join("chunks", "sha256", name)
	absolute := filepath.Join(cache.chunksRoot, name)
	if _, err := validateManagedDirectory(cache.rootHandle, relative, absolute, expected); err != nil {
		return fmt.Errorf("%w: validate cache shard %q: %v", ErrCorruptObject, name, err)
	}
	return nil
}

func (cache *DiskCache) openShard(name string, create bool) (*os.Root, os.FileInfo, error) {
	if !validCacheShard(name) {
		return nil, nil, fmt.Errorf("%w: invalid cache shard %q", ErrCorruptObject, name)
	}
	if err := cache.validateLayout(); err != nil {
		return nil, nil, err
	}
	relative := filepath.Join("chunks", "sha256", name)
	absolute := filepath.Join(cache.chunksRoot, name)
	var (
		info os.FileInfo
		err  error
	)
	if create {
		info, err = ensureManagedDirectory(cache.rootHandle, relative, absolute)
	} else {
		info, err = validateManagedDirectory(cache.rootHandle, relative, absolute, nil)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("%w: open cache shard %q: %v", ErrCorruptObject, name, err)
	}
	shard, err := cache.rootHandle.OpenRoot(relative)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: open cache shard handle %q: %v", ErrCorruptObject, name, err)
	}
	keepShard := false
	defer func() {
		if !keepShard {
			_ = shard.Close()
		}
	}()
	opened, err := shard.Stat(".")
	if err != nil {
		return nil, nil, fmt.Errorf("%w: stat cache shard handle %q: %v", ErrCorruptObject, name, err)
	}
	if !opened.IsDir() || !os.SameFile(info, opened) {
		return nil, nil, fmt.Errorf("%w: cache shard %q changed while opening", ErrCorruptObject, name)
	}
	if err := cache.validateShard(name, info); err != nil {
		return nil, nil, err
	}
	keepShard = true
	return shard, info, nil
}

func createCacheTemporary(root *os.Root) (*os.File, string, error) {
	var random [16]byte
	for attempt := 0; attempt < 100; attempt++ {
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := ".partial-" + hex.EncodeToString(random[:])
		file, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return file, name, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", fmt.Errorf("s3disk: exhausted cache temporary file names")
}

func syncCacheDirectoryAt(root *os.Root, name string) error {
	directory, err := root.Open(name)
	if err != nil {
		return err
	}
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: cache sync target is not a directory", ErrCorruptObject)
	}
	return syncCacheDirectory(directory)
}

func syncCacheRootDirectory(root *os.Root) error {
	return syncCacheDirectoryAt(root, ".")
}

func (cache *DiskCache) removeStartupCandidate(candidate startupCandidate) error {
	shard, shardInfo, err := cache.openShard(candidate.shard, false)
	if err != nil {
		return err
	}
	defer shard.Close()
	err = shard.Remove(candidate.digest.String())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		if syncErr := syncCacheRootDirectory(shard); syncErr != nil {
			return syncErr
		}
	}
	return cache.validateShard(candidate.shard, shardInfo)
}

var _ ChunkCache = (*DiskCache)(nil)
var _ SizedChunkCache = (*DiskCache)(nil)
var _ io.Closer = (*DiskCache)(nil)
