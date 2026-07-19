package s3disk

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestMetadataCacheIsBoundedAndLRU(t *testing.T) {
	t.Parallel()
	cache := newMetadataCache(2, 1<<20)
	one := digestObject("test", []byte("one"))
	two := digestObject("test", []byte("two"))
	three := digestObject("test", []byte("three"))
	oneKey := metadataCacheKey{kind: "dir", digest: one}
	twoKey := metadataCacheKey{kind: "file", digest: two}
	threeKey := metadataCacheKey{kind: "symlink", digest: three}
	value := 1
	cache.Put(oneKey, &value, 1024)
	value = 2
	cache.Put(twoKey, &value, 1024)
	if _, ok := cache.Get(oneKey); !ok {
		t.Fatal("first entry missing before eviction")
	}
	value = 3
	cache.Put(threeKey, &value, 1024)
	if _, ok := cache.Get(twoKey); ok {
		t.Fatal("least recently used entry was not evicted")
	}
	if _, ok := cache.Get(oneKey); !ok {
		t.Fatal("recently used entry was evicted")
	}
	if _, ok := cache.Get(threeKey); !ok {
		t.Fatal("new entry missing")
	}
}

func TestMetadataCacheByteBudgetEvictsAcrossKinds(t *testing.T) {
	t.Parallel()
	cache := newMetadataCache(10, 1800)
	oneKey := metadataCacheKey{kind: "dir", digest: digestObject("dir", []byte("one"))}
	twoKey := metadataCacheKey{kind: "file", digest: digestObject("file", []byte("two"))}
	threeKey := metadataCacheKey{kind: "symlink", digest: digestObject("symlink", []byte("three"))}

	cache.Put(oneKey, new(int), 900)
	cache.Put(twoKey, new(int), 900)
	if _, ok := cache.Get(oneKey); !ok {
		t.Fatal("first entry missing before byte-budget eviction")
	}
	cache.Put(threeKey, new(int), 900)

	if _, ok := cache.Get(twoKey); ok {
		t.Fatal("global byte budget did not evict the least-recently-used kind")
	}
	if _, ok := cache.Get(oneKey); !ok {
		t.Fatal("byte-budget eviction removed the most-recently-used entry")
	}
	if _, ok := cache.Get(threeKey); !ok {
		t.Fatal("new entry missing after byte-budget eviction")
	}
	if got := cache.RetainedBytes(); got != 1800 {
		t.Fatalf("retained bytes = %d, want 1800", got)
	}
}

func TestDefaultMetadataBudgetPreventsPerEntryMaximumMultiplication(t *testing.T) {
	t.Parallel()
	cache := newMetadataCache(defaultMetadataCacheEntries, defaultMetadataCacheBytes)
	for index := range defaultMetadataCacheEntries {
		var digest Digest
		digest[0] = byte(index)
		digest[1] = byte(index >> 8)
		cache.Put(metadataCacheKey{kind: "dir", digest: digest}, new(int), maxMetadataObjectBytes)
	}
	if got := cache.RetainedBytes(); got > defaultMetadataCacheBytes {
		t.Fatalf("retained bytes = %d, budget = %d", got, defaultMetadataCacheBytes)
	}
	maximumEntries := int(defaultMetadataCacheBytes / maxMetadataObjectBytes)
	if got := cache.Len(); got > maximumEntries {
		t.Fatalf("maximum-sized cached entries = %d, want at most %d", got, maximumEntries)
	}
}

func TestMetadataCacheDoesNotRetainObjectLargerThanBudget(t *testing.T) {
	t.Parallel()
	tiny := newMetadataCache(1, 1)
	tiny.Put(metadataCacheKey{kind: "dir", digest: digestObject("dir", []byte("tiny"))}, new(int), 0)
	if tiny.items != nil || tiny.Len() != 0 {
		t.Fatal("sub-overhead budget allocated cache storage")
	}

	manifest := &dirManifest{Format: objectFormatVersion, Entries: make([]dirEntry, 64)}
	for index := range manifest.Entries {
		manifest.Entries[index] = dirEntry{
			Name: []byte{byte(index + 1)}, Type: EntryFile,
			Node: digestObject("file", []byte{byte(index + 1)}),
		}
	}
	estimate := estimateDirectoryRetainedBytes(manifest)
	if estimate <= metadataCacheEntryOverheadBytes {
		t.Fatalf("directory retained-byte estimate = %d, want decoded allocations", estimate)
	}

	cache := newMetadataCache(10, estimate-1)
	hotKey := metadataCacheKey{kind: "file", digest: digestObject("file", []byte("hot"))}
	largeKey := metadataCacheKey{kind: "dir", digest: digestObject("dir", []byte("large"))}
	hot := new(int)
	cache.Put(hotKey, hot, metadataCacheEntryOverheadBytes)
	if returned := cache.Put(largeKey, manifest, estimate); returned != manifest {
		t.Fatal("oversized cache bypass did not return the decoded object")
	}
	if _, ok := cache.Get(largeKey); ok {
		t.Fatal("object larger than the total budget was retained")
	}
	if value, ok := cache.Get(hotKey); !ok || value != hot {
		t.Fatal("oversized cache bypass evicted existing hot metadata")
	}
	if got := cache.RetainedBytes(); got > estimate-1 {
		t.Fatalf("retained bytes = %d, budget = %d", got, estimate-1)
	}
}

func TestConsumerCoalescesConcurrentVerifiedMetadataLoads(t *testing.T) {
	t.Parallel()
	data, digest := validTestDirectory(t)
	store := &metadataTestStore{
		data: data, entered: make(chan struct{}), release: make(chan struct{}),
	}
	repository, err := NewRepository(store, "metadata-flight")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewConsumer(repository, "main", ConsumerOptions{MaxConcurrentDownloads: 1})
	if err != nil {
		t.Fatal(err)
	}

	const readers = 32
	start := make(chan struct{})
	results := make(chan struct {
		manifest *dirManifest
		err      error
	}, readers)
	var ready sync.WaitGroup
	ready.Add(readers)
	for range readers {
		go func() {
			ready.Done()
			<-start
			manifest, loadErr := consumer.loadDirectory(context.Background(), digest)
			results <- struct {
				manifest *dirManifest
				err      error
			}{manifest: manifest, err: loadErr}
		}()
	}
	ready.Wait()
	close(start)
	<-store.entered
	key := metadataCacheKey{kind: "dir", digest: digest}
	deadline := time.Now().Add(time.Second)
	for {
		consumer.metadataFlight.mu.Lock()
		call := consumer.metadataFlight.calls[key]
		joined := call != nil && call.waiters == readers
		consumer.metadataFlight.mu.Unlock()
		if joined {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("concurrent metadata readers did not join one kind+digest flight")
		}
		runtime.Gosched()
	}
	close(store.release)

	var first *dirManifest
	for range readers {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if len(result.manifest.Entries) != 1 {
			t.Fatalf("directory entries = %d, want 1", len(result.manifest.Entries))
		}
		if first == nil {
			first = result.manifest
		} else if result.manifest != first {
			t.Fatal("metadata waiter did not reuse the first verified decoded object")
		}
	}
	if gets := store.GetCount(); gets != 1 {
		t.Fatalf("metadata object-store GETs = %d, want 1", gets)
	}
}

func TestMetadataLoadFailureIsNotCachedAndCanRetry(t *testing.T) {
	t.Parallel()
	data, digest := validTestDirectory(t)
	store := &metadataTestStore{data: data, failures: 1}
	repository, err := NewRepository(store, "metadata-retry")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewConsumer(repository, "main", ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := consumer.loadDirectory(context.Background(), digest); err == nil || !errors.Is(err, errMetadataTestTransient) {
		t.Fatalf("first metadata load error = %v, want transient failure", err)
	}
	if got := consumer.metadata.Len(); got != 0 {
		t.Fatalf("failed metadata load cached %d entries", got)
	}
	manifest, err := consumer.loadDirectory(context.Background(), digest)
	if err != nil {
		t.Fatalf("retry metadata load: %v", err)
	}
	if len(manifest.Entries) != 1 {
		t.Fatalf("retry directory entries = %d, want 1", len(manifest.Entries))
	}
	if _, err := consumer.loadDirectory(context.Background(), digest); err != nil {
		t.Fatalf("cached metadata load: %v", err)
	}
	if gets := store.GetCount(); gets != 2 {
		t.Fatalf("metadata object-store GETs = %d, want failed GET plus one retry", gets)
	}
}

func TestMetadataFlightLeaderCancellationDoesNotPoisonFollower(t *testing.T) {
	t.Parallel()
	data, digest := validTestDirectory(t)
	store := &metadataTestStore{
		data: data, entered: make(chan struct{}), release: make(chan struct{}),
	}
	repository, err := NewRepository(store, "metadata-cancel")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewConsumer(repository, "main", ConsumerOptions{MaxConcurrentDownloads: 1})
	if err != nil {
		t.Fatal(err)
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderResult := make(chan error, 1)
	go func() {
		_, loadErr := consumer.loadDirectory(leaderCtx, digest)
		leaderResult <- loadErr
	}()
	<-store.entered
	followerResult := make(chan error, 1)
	go func() {
		_, loadErr := consumer.loadDirectory(context.Background(), digest)
		followerResult <- loadErr
	}()
	key := metadataCacheKey{kind: "dir", digest: digest}
	deadline := time.Now().Add(time.Second)
	for {
		consumer.metadataFlight.mu.Lock()
		call := consumer.metadataFlight.calls[key]
		joined := call != nil && call.waiters == 2
		consumer.metadataFlight.mu.Unlock()
		if joined {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("metadata follower did not join leader flight")
		}
		runtime.Gosched()
	}
	cancelLeader()
	if err := <-leaderResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("metadata leader error = %v, want context.Canceled", err)
	}
	close(store.release)
	if err := <-followerResult; err != nil {
		t.Fatalf("metadata follower error = %v", err)
	}
	if gets := store.GetCount(); gets != 1 {
		t.Fatalf("metadata object-store GETs = %d, want 1", gets)
	}
}

func TestConsumerMetadataCacheByteLimits(t *testing.T) {
	t.Parallel()
	repository, err := NewRepository(&manifestStore{}, "metadata-options")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewConsumer(repository, "main", ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if consumer.metadata.maxBytes != defaultMetadataCacheBytes || consumer.metadata.maxEntries != defaultMetadataCacheEntries {
		t.Fatalf("metadata defaults = %d bytes/%d entries", consumer.metadata.maxBytes, consumer.metadata.maxEntries)
	}
	for _, bytes := range []int64{-1, maxMetadataCacheBytes + 1} {
		if _, err := NewConsumer(repository, "main", ConsumerOptions{MetadataCacheBytes: bytes}); err == nil {
			t.Fatalf("metadata cache bytes %d accepted", bytes)
		}
	}
}

func validTestDirectory(t *testing.T) ([]byte, Digest) {
	t.Helper()
	manifest := dirManifest{Format: objectFormatVersion, Entries: []dirEntry{{
		Name: []byte("file"), Type: EntryFile,
		Node: digestObject("file", []byte("node")), Mode: 0o444, Size: 1,
	}}}
	data, err := canonicalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return data, digestObject("dir", data)
}

var errMetadataTestTransient = errors.New("transient metadata failure")

type metadataTestStore struct {
	mu       sync.Mutex
	data     []byte
	gets     int
	failures int
	entered  chan struct{}
	release  chan struct{}
}

func (store *metadataTestStore) Get(ctx context.Context, _ string, _ GetOptions) (Object, error) {
	store.mu.Lock()
	store.gets++
	getNumber := store.gets
	fail := store.failures > 0
	if fail {
		store.failures--
	}
	entered := store.entered
	release := store.release
	store.mu.Unlock()
	if entered != nil && getNumber == 1 {
		close(entered)
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return Object{}, ctx.Err()
		}
	}
	if fail {
		return Object{}, errMetadataTestTransient
	}
	return Object{Data: append([]byte(nil), store.data...), Version: Version{ETag: "metadata-test"}}, nil
}

func (store *metadataTestStore) GetCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.gets
}

func (*metadataTestStore) Head(context.Context, string) (Version, error) {
	return Version{}, ErrObjectNotFound
}

func (*metadataTestStore) PutIfAbsent(context.Context, string, []byte) (Version, error) {
	return Version{}, ErrPrecondition
}

func (*metadataTestStore) CompareAndSwap(context.Context, string, *Version, []byte) (Version, error) {
	return Version{}, ErrPrecondition
}
