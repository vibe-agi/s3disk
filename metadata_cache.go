package s3disk

import (
	"container/list"
	"context"
	"fmt"
	"sync"
	"unsafe"
)

const (
	defaultMetadataCacheEntries = 4096
	defaultMetadataCacheBytes   = int64(64 << 20)
	maxMetadataCacheBytes       = int64(1 << 30)

	// This covers the map bucket share, list element, cache entry, pointers,
	// allocator size-class rounding, and a conservative margin for each item.
	metadataCacheEntryOverheadBytes = int64(512)
	maxEstimatedRetainedBytes       = int64(1<<63 - 1)
)

type metadataCacheKey struct {
	kind   string
	digest Digest
}

type metadataCacheEntry struct {
	key           metadataCacheKey
	value         any
	retainedBytes int64
}

// metadataCache is one LRU shared by directory, file, and symlink manifests.
// maxEntries and maxBytes are independent hard limits. A value larger than the
// entire byte budget is returned to its caller but is never retained.
type metadataCache struct {
	mu            sync.Mutex
	maxEntries    int
	maxBytes      int64
	retainedBytes int64
	items         map[metadataCacheKey]*list.Element
	order         list.List
}

func newMetadataCache(maxEntries int, maxBytes int64) metadataCache {
	return metadataCache{
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
	}
}

func (cache *metadataCache) Get(key metadataCacheKey) (any, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	element := cache.items[key]
	if element == nil {
		return nil, false
	}
	cache.order.MoveToFront(element)
	return element.Value.(*metadataCacheEntry).value, true
}

func (cache *metadataCache) Put(key metadataCacheKey, value any, retainedBytes int64) any {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if existing := cache.items[key]; existing != nil {
		cache.order.MoveToFront(existing)
		return existing.Value.(*metadataCacheEntry).value
	}
	if retainedBytes < metadataCacheEntryOverheadBytes {
		retainedBytes = metadataCacheEntryOverheadBytes
	}
	if cache.maxEntries <= 0 || cache.maxBytes <= 0 || retainedBytes > cache.maxBytes {
		return value
	}
	if cache.items == nil {
		// Allocate lazily without a capacity hint. The per-entry allowance then
		// conservatively covers incremental map growth even for a tiny budget.
		cache.items = make(map[metadataCacheKey]*list.Element)
	}
	entry := &metadataCacheEntry{key: key, value: value, retainedBytes: retainedBytes}
	element := cache.order.PushFront(entry)
	cache.items[key] = element
	cache.retainedBytes += retainedBytes
	for cache.order.Len() > cache.maxEntries || cache.retainedBytes > cache.maxBytes {
		cache.removeOldest()
	}
	return value
}

func (cache *metadataCache) removeOldest() {
	oldest := cache.order.Back()
	if oldest == nil {
		return
	}
	entry := oldest.Value.(*metadataCacheEntry)
	delete(cache.items, entry.key)
	cache.order.Remove(oldest)
	cache.retainedBytes -= entry.retainedBytes
}

func (cache *metadataCache) Clear() {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.items = nil
	cache.order.Init()
	cache.retainedBytes = 0
}

func (cache *metadataCache) Len() int {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return cache.order.Len()
}

func (cache *metadataCache) RetainedBytes() int64 {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return cache.retainedBytes
}

func getTypedMetadata[T any](cache *metadataCache, key metadataCacheKey) (*T, bool) {
	value, ok := cache.Get(key)
	if !ok {
		return nil, false
	}
	typed, ok := value.(*T)
	if !ok {
		return nil, false
	}
	return typed, true
}

func putTypedMetadata[T any](cache *metadataCache, key metadataCacheKey, value *T, retainedBytes int64) *T {
	stored := cache.Put(key, value, retainedBytes)
	typed, ok := stored.(*T)
	if !ok {
		panic("s3disk: metadata cache kind/type mismatch")
	}
	return typed
}

// The estimate counts the decoded object and all variable-size allocations it
// retains. Slice capacity, rather than length, is used for backing arrays. The
// logical total is doubled for allocator rounding and decoder implementation
// details, then a fixed per-cache-entry allowance is added.
func estimateDirectoryRetainedBytes(manifest *dirManifest) int64 {
	logical := int64(unsafe.Sizeof(*manifest))
	logical = addEstimatedBytes(logical, multiplyEstimatedBytes(
		int64(cap(manifest.Entries)), int64(unsafe.Sizeof(dirEntry{}))))
	for index := range manifest.Entries {
		entry := &manifest.Entries[index]
		logical = addEstimatedBytes(logical, int64(cap(entry.Name)))
		logical = addEstimatedBytes(logical, int64(len(entry.Type)))
	}
	return conservativeMetadataEstimate(logical)
}

func estimateFileRetainedBytes(manifest *fileManifest) int64 {
	logical := int64(unsafe.Sizeof(*manifest))
	logical = addEstimatedBytes(logical, int64(len(manifest.Algorithm)))
	logical = addEstimatedBytes(logical, multiplyEstimatedBytes(
		int64(cap(manifest.Chunks)), int64(unsafe.Sizeof(chunkRef{}))))
	return conservativeMetadataEstimate(logical)
}

func estimateSymlinkRetainedBytes(manifest *symlinkManifest) int64 {
	logical := int64(unsafe.Sizeof(*manifest))
	logical = addEstimatedBytes(logical, int64(cap(manifest.Target)))
	return conservativeMetadataEstimate(logical)
}

func conservativeMetadataEstimate(logical int64) int64 {
	return addEstimatedBytes(multiplyEstimatedBytes(logical, 2), metadataCacheEntryOverheadBytes)
}

func addEstimatedBytes(left, right int64) int64 {
	if left < 0 || right < 0 || left > maxEstimatedRetainedBytes-right {
		return maxEstimatedRetainedBytes
	}
	return left + right
}

func multiplyEstimatedBytes(left, right int64) int64 {
	if left < 0 || right < 0 || (left != 0 && right > maxEstimatedRetainedBytes/left) {
		return maxEstimatedRetainedBytes
	}
	return left * right
}

type metadataFlightCall struct {
	done    chan struct{}
	value   any
	err     error
	cancel  context.CancelFunc
	waiters int
}

type metadataFlightGroup struct {
	mu    sync.Mutex
	calls map[metadataCacheKey]*metadataFlightCall
}

// Do coalesces one kind+digest metadata load. The loader continues when one
// caller cancels as long as another waiter still needs it; it is canceled when
// all waiters leave. Completed failures are not retained, so a later caller can
// retry the object store.
func (group *metadataFlightGroup) Do(ctx context.Context, key metadataCacheKey, load func(context.Context) (any, error)) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	group.mu.Lock()
	if group.calls == nil {
		group.calls = make(map[metadataCacheKey]*metadataFlightCall)
	}
	if existing := group.calls[key]; existing != nil {
		if existing.waiters > 0 {
			existing.waiters++
			group.mu.Unlock()
			return group.wait(ctx, key, existing)
		}
		delete(group.calls, key)
	}
	loadCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	call := &metadataFlightCall{done: make(chan struct{}), cancel: cancel, waiters: 1}
	group.calls[key] = call
	group.mu.Unlock()
	go group.run(key, call, loadCtx, load)
	return group.wait(ctx, key, call)
}

func (group *metadataFlightGroup) run(key metadataCacheKey, call *metadataFlightCall, ctx context.Context, load func(context.Context) (any, error)) {
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				call.err = fmt.Errorf("s3disk: metadata loader panic: %v", recovered)
			}
		}()
		call.value, call.err = load(ctx)
	}()
	group.mu.Lock()
	if group.calls[key] == call {
		delete(group.calls, key)
	}
	close(call.done)
	call.cancel()
	group.mu.Unlock()
}

func (group *metadataFlightGroup) wait(ctx context.Context, key metadataCacheKey, call *metadataFlightCall) (any, error) {
	select {
	case <-call.done:
		return call.value, call.err
	case <-ctx.Done():
		group.mu.Lock()
		if group.calls[key] == call && call.waiters > 0 {
			call.waiters--
			if call.waiters == 0 {
				call.cancel()
			}
		}
		group.mu.Unlock()
		return nil, ctx.Err()
	}
}
