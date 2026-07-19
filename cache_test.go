package s3disk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestNewDiskCacheUsesFiniteDefaults(t *testing.T) {
	cache, err := NewDiskCache(privateTestDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	closeTestDiskCache(t, cache)
	if cache.options.MaxBytes != DefaultDiskCacheMaxBytes {
		t.Fatalf("MaxBytes = %d, want %d", cache.options.MaxBytes, DefaultDiskCacheMaxBytes)
	}
	if cache.options.MaxChunkBytes != DefaultDiskCacheMaxChunkBytes {
		t.Fatalf("MaxChunkBytes = %d, want %d", cache.options.MaxChunkBytes, DefaultDiskCacheMaxChunkBytes)
	}
	if cache.options.MaxEntries != DefaultDiskCacheMaxEntries {
		t.Fatalf("MaxEntries = %d, want %d", cache.options.MaxEntries, DefaultDiskCacheMaxEntries)
	}
	wantScanEntries := 2*DefaultDiskCacheMaxEntries + 256
	if cache.options.MaxStartupScanEntries != wantScanEntries {
		t.Fatalf("MaxStartupScanEntries = %d, want %d", cache.options.MaxStartupScanEntries, wantScanEntries)
	}
}

func TestNewDiskCacheRejectsInvalidLimits(t *testing.T) {
	tests := []DiskCacheOptions{
		{MaxBytes: -1},
		{MaxChunkBytes: -1},
		{MaxEntries: -1},
		{MaxStartupScanEntries: -1},
		{MaxBytes: DiskCacheMaxBytesLimit + 1},
		{MaxChunkBytes: DiskCacheMaxChunkBytesLimit + 1},
		{MaxEntries: DiskCacheMaxEntriesLimit + 1},
		{MaxStartupScanEntries: DiskCacheMaxStartupScanEntriesLimit + 1},
	}
	for _, options := range tests {
		if _, err := NewDiskCacheWithOptions(privateTestDirectory(t), options); !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("NewDiskCacheWithOptions(%+v) error = %v, want ErrResourceLimit", options, err)
		}
	}
}

func TestDiskCacheSizedGetRejectsMismatchBeforeRead(t *testing.T) {
	cache, err := NewDiskCacheWithOptions(privateTestDirectory(t), DiskCacheOptions{
		MaxBytes: 16, MaxChunkBytes: 16, MaxEntries: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	closeTestDiskCache(t, cache)
	data := []byte("sized-cache")
	digest := digestObject("chunk", data)
	if err := cache.Put(t.Context(), digest, data); err != nil {
		t.Fatal(err)
	}
	if _, found, err := cache.GetSized(t.Context(), digest, int64(len(data)+1)); err != nil || found {
		t.Fatalf("mismatched sized Get found=%v error=%v, want clean miss", found, err)
	}
	got, found, err := cache.GetSized(t.Context(), digest, int64(len(data)))
	if err != nil || !found || !bytes.Equal(got, data) {
		t.Fatalf("exact sized Get data=%q found=%v error=%v", got, found, err)
	}
}

func TestDiskCacheStartupScanBudgetRejectsExcessDiskEntries(t *testing.T) {
	root := privateTestDirectory(t)
	shard := filepath.Join(root, "chunks", "sha256", "aa")
	if err := os.MkdirAll(shard, 0o700); err != nil {
		t.Fatal(err)
	}
	// The shard itself and its four entries require five visits. Invalid names
	// are intentional: cleanup work must consume the same budget as valid cache
	// candidates so a damaged directory cannot force an unbounded startup scan.
	for index := 0; index < 4; index++ {
		path := filepath.Join(shard, fmt.Sprintf("invalid-%d", index))
		if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := NewDiskCacheWithOptions(root, DiskCacheOptions{
		MaxBytes:              16,
		MaxChunkBytes:         8,
		MaxEntries:            2,
		MaxStartupScanEntries: 4,
	})
	if !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("NewDiskCacheWithOptions error = %v, want ErrResourceLimit", err)
	}
}

func TestDiskCacheStartupDoesNotRecursivelyCleanInvalidDirectory(t *testing.T) {
	root := privateTestDirectory(t)
	invalid := filepath.Join(root, "chunks", "sha256", "not-a-shard", "nested")
	if err := os.MkdirAll(invalid, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(invalid, "keep")
	if err := os.WriteFile(victim, []byte("operator-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewDiskCacheWithOptions(root, DiskCacheOptions{
		MaxBytes:              16,
		MaxChunkBytes:         8,
		MaxEntries:            2,
		MaxStartupScanEntries: 16,
	})
	if !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("NewDiskCacheWithOptions error = %v, want ErrResourceLimit", err)
	}
	data, readErr := os.ReadFile(victim)
	if readErr != nil {
		t.Fatalf("invalid directory contents were recursively removed: %v", readErr)
	}
	if string(data) != "operator-data" {
		t.Fatalf("invalid directory content = %q, want preserved data", data)
	}
}

func TestDiskCacheEvictsLeastRecentlyUsed(t *testing.T) {
	ctx := context.Background()
	cache, err := NewDiskCacheWithOptions(privateTestDirectory(t), DiskCacheOptions{
		MaxBytes:      8,
		MaxChunkBytes: 4,
		MaxEntries:    2,
	})
	if err != nil {
		t.Fatal(err)
	}
	closeTestDiskCache(t, cache)
	a := []byte("aaaa")
	b := []byte("bbbb")
	c := []byte("cccc")
	da := digestObject("chunk", a)
	db := digestObject("chunk", b)
	dc := digestObject("chunk", c)
	for digest, data := range map[Digest][]byte{da: a, db: b} {
		if err := cache.Put(ctx, digest, data); err != nil {
			t.Fatal(err)
		}
	}
	if _, found, err := cache.Get(ctx, da); err != nil || !found {
		t.Fatalf("touch first entry: found=%v err=%v", found, err)
	}
	if err := cache.Put(ctx, dc, c); err != nil {
		t.Fatal(err)
	}
	assertCacheHit(t, cache, da, a)
	assertCacheMiss(t, cache, db)
	assertCacheHit(t, cache, dc, c)
	entries, bytes := diskCacheUsage(cache)
	if entries != 2 || bytes != 8 {
		t.Fatalf("usage = (%d entries, %d bytes), want (2, 8)", entries, bytes)
	}
}

func TestDiskCacheSkipsChunkLargerThanLimit(t *testing.T) {
	cache, err := NewDiskCacheWithOptions(privateTestDirectory(t), DiskCacheOptions{
		MaxBytes:      8,
		MaxChunkBytes: 4,
		MaxEntries:    2,
	})
	if err != nil {
		t.Fatal(err)
	}
	closeTestDiskCache(t, cache)
	data := []byte("too large")
	digest := digestObject("chunk", data)
	if err := cache.Put(context.Background(), digest, data); err != nil {
		t.Fatalf("an oversized cache entry should be skipped, not fail: %v", err)
	}
	assertCacheMiss(t, cache, digest)
	if _, err := os.Stat(cache.chunkPath(digest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversized entry exists on disk: %v", err)
	}
}

func TestDiskCacheOwnsPutAndGetBuffers(t *testing.T) {
	t.Parallel()
	cache, err := NewDiskCacheWithOptions(privateTestDirectory(t), DiskCacheOptions{
		MaxBytes: 64, MaxChunkBytes: 64, MaxEntries: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	closeTestDiskCache(t, cache)
	ctx := context.Background()
	original := []byte("immutable cache payload")
	want := append([]byte(nil), original...)
	digest := digestObject("chunk", want)
	if err := cache.Put(ctx, digest, original); err != nil {
		t.Fatalf("Put: %v", err)
	}
	original[0] ^= 0xff

	first, found, err := cache.Get(ctx, digest)
	if err != nil || !found || !bytes.Equal(first, want) {
		t.Fatalf("first Get = %q, found=%v, err=%v; want independent original", first, found, err)
	}
	first[0] ^= 0xff
	second, found, err := cache.Get(ctx, digest)
	if err != nil || !found || !bytes.Equal(second, want) {
		t.Fatalf("second Get = %q, found=%v, err=%v; want independent buffer", second, found, err)
	}
}

func TestDiskCacheStartupIndexesAndEvictsByPersistentRecency(t *testing.T) {
	ctx := context.Background()
	root := privateTestDirectory(t)
	initial, err := NewDiskCacheWithOptions(root, DiskCacheOptions{
		MaxBytes:      8,
		MaxChunkBytes: 4,
		MaxEntries:    2,
	})
	if err != nil {
		t.Fatal(err)
	}
	closeTestDiskCache(t, initial)
	oldData := []byte("old!")
	newData := []byte("new!")
	oldDigest := digestObject("chunk", oldData)
	newDigest := digestObject("chunk", newData)
	if err := initial.Put(ctx, oldDigest, oldData); err != nil {
		t.Fatal(err)
	}
	if err := initial.Put(ctx, newDigest, newData); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Unix(1_700_000_000, 0)
	newTime := oldTime.Add(time.Hour)
	if err := os.Chtimes(initial.chunkPath(oldDigest), oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(initial.chunkPath(newDigest), newTime, newTime); err != nil {
		t.Fatal(err)
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewDiskCacheWithOptions(root, DiskCacheOptions{
		MaxBytes:      4,
		MaxChunkBytes: 4,
		MaxEntries:    1,
	})
	if err != nil {
		t.Fatal(err)
	}
	closeTestDiskCache(t, reopened)
	assertCacheMiss(t, reopened, oldDigest)
	assertCacheHit(t, reopened, newDigest, newData)
	entries, bytes := diskCacheUsage(reopened)
	if entries != 1 || bytes != 4 {
		t.Fatalf("usage = (%d entries, %d bytes), want (1, 4)", entries, bytes)
	}
}

func TestDiskCacheCorruptionIsRemovedWithoutReturningBytes(t *testing.T) {
	ctx := context.Background()
	root := privateTestDirectory(t)
	cache, err := NewDiskCacheWithOptions(root, DiskCacheOptions{
		MaxBytes:      16,
		MaxChunkBytes: 8,
		MaxEntries:    2,
	})
	if err != nil {
		t.Fatal(err)
	}
	closeTestDiskCache(t, cache)
	data := []byte("valid")
	digest := digestObject("chunk", data)
	if err := cache.Put(ctx, digest, data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache.chunkPath(digest), []byte("wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewDiskCacheWithOptions(root, cache.options)
	if err != nil {
		t.Fatal(err)
	}
	closeTestDiskCache(t, reopened)
	assertCacheMiss(t, reopened, digest)
	if _, err := os.Stat(reopened.chunkPath(digest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt entry was not removed: %v", err)
	}
	entries, bytes := diskCacheUsage(reopened)
	if entries != 0 || bytes != 0 {
		t.Fatalf("usage after corruption = (%d entries, %d bytes)", entries, bytes)
	}
}

func TestDiskCacheConcurrentCorruptReadsAreCleanMisses(t *testing.T) {
	ctx := context.Background()
	cache, err := NewDiskCacheWithOptions(privateTestDirectory(t), DiskCacheOptions{
		MaxBytes:      2 << 20,
		MaxChunkBytes: 2 << 20,
		MaxEntries:    2,
	})
	if err != nil {
		t.Fatal(err)
	}
	closeTestDiskCache(t, cache)
	data := bytes.Repeat([]byte{'v'}, 1<<20)
	digest := digestObject("chunk", data)
	if err := cache.Put(ctx, digest, data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache.chunkPath(digest), bytes.Repeat([]byte{'x'}, len(data)), 0o600); err != nil {
		t.Fatal(err)
	}

	const readers = 16
	start := make(chan struct{})
	results := make(chan error, readers)
	var wait sync.WaitGroup
	for reader := 0; reader < readers; reader++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			got, found, err := cache.Get(ctx, digest)
			if err != nil {
				results <- err
			} else if found || got != nil {
				results <- fmt.Errorf("corrupt cache entry was returned")
			}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	for err := range results {
		t.Error(err)
	}
	if _, err := os.Stat(cache.chunkPath(digest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt entry was not removed: %v", err)
	}
}

func TestDiskCacheGetBoundsFileGrowthBeforeAllocation(t *testing.T) {
	cache, err := NewDiskCacheWithOptions(privateTestDirectory(t), DiskCacheOptions{
		MaxBytes:      16,
		MaxChunkBytes: 8,
		MaxEntries:    2,
	})
	if err != nil {
		t.Fatal(err)
	}
	closeTestDiskCache(t, cache)
	data := []byte("valid")
	digest := digestObject("chunk", data)
	if err := cache.Put(context.Background(), digest, data); err != nil {
		t.Fatal(err)
	}
	// A sparse growth simulates a damaged or locally hostile cache entry. Get
	// must reject it from stat metadata without allocating its apparent size.
	if err := os.Truncate(cache.chunkPath(digest), 1<<30); err != nil {
		t.Fatal(err)
	}
	assertCacheMiss(t, cache, digest)
	if _, err := os.Stat(cache.chunkPath(digest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversized entry was not removed: %v", err)
	}
}

func TestDiskCacheStartupRemovesOversizedAndPartialFiles(t *testing.T) {
	root := privateTestDirectory(t)
	data := []byte("name")
	digest := digestObject("chunk", data)
	shard := filepath.Join(root, "chunks", "sha256", digest.String()[:2])
	if err := os.MkdirAll(shard, 0o700); err != nil {
		t.Fatal(err)
	}
	oversized := filepath.Join(shard, digest.String())
	if err := os.WriteFile(oversized, bytes.Repeat([]byte{'x'}, 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	partial := filepath.Join(shard, ".partial-abandoned")
	if err := os.WriteFile(partial, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	cache, err := NewDiskCacheWithOptions(root, DiskCacheOptions{
		MaxBytes:      16,
		MaxChunkBytes: 8,
		MaxEntries:    2,
	})
	if err != nil {
		t.Fatal(err)
	}
	closeTestDiskCache(t, cache)
	for _, path := range []string{oversized, partial} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("startup did not remove %q: %v", path, err)
		}
	}
}

func TestDiskCacheConcurrentUseStaysWithinLimits(t *testing.T) {
	cache, err := NewDiskCacheWithOptions(privateTestDirectory(t), DiskCacheOptions{
		MaxBytes:      512,
		MaxChunkBytes: 64,
		MaxEntries:    8,
	})
	if err != nil {
		t.Fatal(err)
	}
	closeTestDiskCache(t, cache)
	ctx := context.Background()
	const workers = 32
	var wait sync.WaitGroup
	errorsFound := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			data := []byte(fmt.Sprintf("%064d", worker))
			digest := digestObject("chunk", data)
			for attempt := 0; attempt < 8; attempt++ {
				if err := cache.Put(ctx, digest, data); err != nil {
					errorsFound <- err
					return
				}
				got, found, err := cache.Get(ctx, digest)
				if err != nil {
					errorsFound <- err
					return
				}
				// Another goroutine may evict the entry before this lookup. A hit,
				// however, must always contain the exact verified bytes.
				if found && !bytes.Equal(got, data) {
					errorsFound <- fmt.Errorf("worker %d read corrupt data", worker)
					return
				}
			}
		}(worker)
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if len(cache.entries) > cache.options.MaxEntries {
		t.Fatalf("entries = %d, max = %d", len(cache.entries), cache.options.MaxEntries)
	}
	if cache.totalBytes > cache.options.MaxBytes {
		t.Fatalf("bytes = %d, max = %d", cache.totalBytes, cache.options.MaxBytes)
	}
	var indexedBytes int64
	for _, entry := range cache.entries {
		indexedBytes += entry.size
		if entry.pins != 0 {
			t.Fatalf("entry %s remained pinned", entry.digest)
		}
	}
	if indexedBytes != cache.totalBytes {
		t.Fatalf("indexed bytes = %d, accounting = %d", indexedBytes, cache.totalBytes)
	}
}

func TestDiskCacheCloseIsIdempotentAndConcurrentSafe(t *testing.T) {
	cache, err := NewDiskCacheWithOptions(privateTestDirectory(t), DiskCacheOptions{
		MaxBytes:      256,
		MaxChunkBytes: 64,
		MaxEntries:    4,
	})
	if err != nil {
		t.Fatal(err)
	}
	closeTestDiskCache(t, cache)
	ctx := context.Background()
	data := []byte("concurrent-close")
	digest := digestObject("chunk", data)
	if err := cache.Put(ctx, digest, data); err != nil {
		t.Fatal(err)
	}

	const workers = 16
	start := make(chan struct{})
	errorsFound := make(chan error, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			<-start
			for {
				var operationErr error
				if worker%2 == 0 {
					operationErr = cache.Put(ctx, digest, data)
				} else {
					_, _, operationErr = cache.Get(ctx, digest)
				}
				if errors.Is(operationErr, os.ErrClosed) {
					return
				}
				if operationErr != nil {
					errorsFound <- operationErr
					return
				}
			}
		}(worker)
	}
	close(start)
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
	if err := cache.Close(); err != nil {
		t.Fatalf("second Close error = %v, want nil", err)
	}
	if got, found, err := cache.Get(ctx, digest); !errors.Is(err, os.ErrClosed) || found || got != nil {
		t.Fatalf("Get after Close = (%q, %v, %v), want os.ErrClosed", got, found, err)
	}
	if err := cache.Put(ctx, digest, data); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Put after Close error = %v, want os.ErrClosed", err)
	}
}

func assertCacheHit(t *testing.T, cache *DiskCache, digest Digest, want []byte) {
	t.Helper()
	got, found, err := cache.Get(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("cache miss for %s", digest)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("cache data = %q, want %q", got, want)
	}
}

func assertCacheMiss(t *testing.T, cache *DiskCache, digest Digest) {
	t.Helper()
	data, found, err := cache.Get(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	if found || data != nil {
		t.Fatalf("cache hit for %s: %q", digest, data)
	}
}

func diskCacheUsage(cache *DiskCache) (int, int64) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return len(cache.entries), cache.totalBytes
}

func closeTestDiskCache(t *testing.T, cache *DiskCache) {
	t.Helper()
	t.Cleanup(func() {
		if err := cache.Close(); err != nil {
			t.Errorf("close disk cache: %v", err)
		}
	})
}
