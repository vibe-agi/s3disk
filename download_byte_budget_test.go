package s3disk

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestConsumerDownloadByteBudgetOptionBounds(t *testing.T) {
	repository, err := NewRepository(new(resourceProbeStore), "download-byte-options")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewConsumer(repository, "main", ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := consumer.downloadBytes.capacity; got != DefaultMaxConcurrentDownloadBytes {
		t.Fatalf("default download byte budget = %d, want %d", got, DefaultMaxConcurrentDownloadBytes)
	}

	for _, value := range []int64{-1, maxChunkObjectBytes - 1, MaxConcurrentDownloadBytesLimit + 1} {
		if _, err := NewConsumer(repository, "main", ConsumerOptions{MaxConcurrentDownloadBytes: value}); !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("download byte budget %d error = %v, want ErrResourceLimit", value, err)
		}
	}
	for _, value := range []int64{maxChunkObjectBytes, MaxConcurrentDownloadBytesLimit} {
		consumer, err := NewConsumer(repository, "main", ConsumerOptions{MaxConcurrentDownloadBytes: value})
		if err != nil {
			t.Fatalf("download byte budget %d: %v", value, err)
		}
		if consumer.downloadBytes.capacity != value {
			t.Fatalf("download byte budget = %d, want %d", consumer.downloadBytes.capacity, value)
		}
	}
}

func TestWeightedSemaphoreCancellationRemovesWaiter(t *testing.T) {
	semaphore := newWeightedSemaphore(10)
	if err := semaphore.Acquire(t.Context(), 10); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- semaphore.Acquire(ctx, 6) }()
	waitForSemaphoreWaiters(t, semaphore, 1)
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled acquire error = %v, want context.Canceled", err)
	}
	semaphore.mu.Lock()
	if semaphore.waiters.Len() != 0 || semaphore.used != 10 {
		t.Fatalf("after cancellation waiters=%d used=%d, want 0 and 10", semaphore.waiters.Len(), semaphore.used)
	}
	semaphore.mu.Unlock()
	semaphore.Release(10)
	if err := semaphore.Acquire(t.Context(), 10); err != nil {
		t.Fatalf("acquire after canceled waiter: %v", err)
	}
	semaphore.Release(10)
}

func TestConsumerByteBudgetBoundsConcurrentChunkGetsAndCancellation(t *testing.T) {
	firstData := []byte("first1")
	secondData := []byte("second")
	firstDigest := digestObject("chunk", firstData)
	secondDigest := digestObject("chunk", secondData)
	releases := make(chan chan struct{}, 2)
	var active atomic.Int64
	var maximum atomic.Int64
	store := &downloadBudgetStore{}
	store.get = func(ctx context.Context, key string, options GetOptions) (Object, error) {
		current := active.Add(options.MaxBytes)
		updateAtomicMaximum(&maximum, current)
		release := make(chan struct{})
		releases <- release
		select {
		case <-release:
		case <-ctx.Done():
			active.Add(-options.MaxBytes)
			return Object{}, ctx.Err()
		}
		active.Add(-options.MaxBytes)
		switch key {
		case store.firstKey:
			return Object{Data: append([]byte(nil), firstData...), Version: Version{ETag: "first"}}, nil
		case store.secondKey:
			return Object{Data: append([]byte(nil), secondData...), Version: Version{ETag: "second"}}, nil
		default:
			return Object{}, ErrObjectNotFound
		}
	}
	repository, err := NewRepository(store, "download-byte-peak")
	if err != nil {
		t.Fatal(err)
	}
	store.firstKey = repository.objectKey("chunk", firstDigest)
	store.secondKey = repository.objectKey("chunk", secondDigest)
	consumer, err := NewConsumer(repository, "main", ConsumerOptions{MaxConcurrentDownloads: 2})
	if err != nil {
		t.Fatal(err)
	}
	// Use small values to exercise the weighted algorithm without allocating
	// protocol-maximum chunks. Public construction enforces the production floor.
	consumer.downloadBytes = newWeightedSemaphore(10)

	firstResult := make(chan error, 1)
	go func() {
		lease, getErr := consumer.getChunk(t.Context(), firstDigest, int64(len(firstData)))
		if lease != nil {
			lease.Release()
		}
		firstResult <- getErr
	}()
	firstRelease := <-releases

	waitCtx, cancel := context.WithCancel(t.Context())
	secondResult := make(chan error, 1)
	go func() {
		lease, getErr := consumer.getChunk(waitCtx, secondDigest, int64(len(secondData)))
		if lease != nil {
			lease.Release()
		}
		secondResult <- getErr
	}()
	waitForSemaphoreWaiters(t, consumer.downloadBytes, 1)
	cancel()
	if err := <-secondResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled chunk error = %v, want context.Canceled", err)
	}
	select {
	case unexpected := <-releases:
		close(unexpected)
		t.Fatal("byte-budget waiter reached Store.Get before its reservation")
	default:
	}
	close(firstRelease)
	if err := <-firstResult; err != nil {
		t.Fatal(err)
	}
	if got := maximum.Load(); got > 10 {
		t.Fatalf("peak charged Store.Get bytes = %d, budget 10", got)
	}

	// Cancellation must release both the queued byte waiter and its count slot.
	thirdResult := make(chan error, 1)
	go func() {
		lease, getErr := consumer.getChunk(t.Context(), secondDigest, int64(len(secondData)))
		if lease != nil {
			lease.Release()
		}
		thirdResult <- getErr
	}()
	secondRelease := <-releases
	close(secondRelease)
	if err := <-thirdResult; err != nil {
		t.Fatal(err)
	}
}

func TestChunkReservationLivesUntilLastFlightWaiterConsumesData(t *testing.T) {
	sharedData := []byte("shared")
	otherData := []byte("second")
	sharedDigest := digestObject("chunk", sharedData)
	otherDigest := digestObject("chunk", otherData)
	sharedEntered := make(chan struct{}, 1)
	sharedRelease := make(chan struct{})
	otherEntered := make(chan struct{}, 1)
	store := &downloadBudgetStore{}
	store.get = func(ctx context.Context, key string, _ GetOptions) (Object, error) {
		switch key {
		case store.firstKey:
			select {
			case sharedEntered <- struct{}{}:
			default:
			}
			select {
			case <-sharedRelease:
				return Object{Data: append([]byte(nil), sharedData...), Version: Version{ETag: "shared"}}, nil
			case <-ctx.Done():
				return Object{}, ctx.Err()
			}
		case store.secondKey:
			otherEntered <- struct{}{}
			return Object{Data: append([]byte(nil), otherData...), Version: Version{ETag: "other"}}, nil
		default:
			return Object{}, ErrObjectNotFound
		}
	}
	repository, err := NewRepository(store, "leased-chunk-budget")
	if err != nil {
		t.Fatal(err)
	}
	store.firstKey = repository.objectKey("chunk", sharedDigest)
	store.secondKey = repository.objectKey("chunk", otherDigest)
	consumer, err := NewConsumer(repository, "main", ConsumerOptions{MaxConcurrentDownloads: 4})
	if err != nil {
		t.Fatal(err)
	}
	consumer.downloadBytes = newWeightedSemaphore(10)

	type leaseResult struct {
		lease *chunkLease
		err   error
	}
	sharedResults := make(chan leaseResult, 2)
	for range 2 {
		go func() {
			lease, getErr := consumer.getChunk(t.Context(), sharedDigest, int64(len(sharedData)))
			sharedResults <- leaseResult{lease: lease, err: getErr}
		}()
	}
	<-sharedEntered
	waitForChunkFlightUsers(t, &consumer.chunkFlight, chunkFlightKey{digest: sharedDigest, expectedSize: int64(len(sharedData))}, 2)
	close(sharedRelease)
	first := <-sharedResults
	second := <-sharedResults
	if first.err != nil || second.err != nil {
		t.Fatalf("shared flight errors = (%v, %v)", first.err, second.err)
	}
	assertSemaphoreUsed(t, consumer.downloadBytes, int64(len(sharedData)))

	first.lease.Release()
	assertSemaphoreUsed(t, consumer.downloadBytes, int64(len(sharedData)))
	otherResult := make(chan leaseResult, 1)
	go func() {
		lease, getErr := consumer.getChunk(t.Context(), otherDigest, int64(len(otherData)))
		otherResult <- leaseResult{lease: lease, err: getErr}
	}()
	waitForSemaphoreWaiters(t, consumer.downloadBytes, 1)
	select {
	case <-otherEntered:
		t.Fatal("new digest reached Store.Get while a shared chunk lease retained the byte budget")
	default:
	}

	second.lease.Release()
	select {
	case <-otherEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("new digest was not released after the final shared-flight acknowledgment")
	}
	other := <-otherResult
	if other.err != nil {
		t.Fatal(other.err)
	}
	assertSemaphoreUsed(t, consumer.downloadBytes, int64(len(otherData)))
	other.lease.Release()
	assertSemaphoreUsed(t, consumer.downloadBytes, 0)
}

func TestCanceledChunkFlightWaiterDoesNotRetainLease(t *testing.T) {
	data := []byte("shared")
	digest := digestObject("chunk", data)
	entered := make(chan struct{})
	release := make(chan struct{})
	store := &downloadBudgetStore{}
	store.get = func(ctx context.Context, _ string, _ GetOptions) (Object, error) {
		close(entered)
		select {
		case <-release:
			return Object{Data: append([]byte(nil), data...), Version: Version{ETag: "shared"}}, nil
		case <-ctx.Done():
			return Object{}, ctx.Err()
		}
	}
	repository, err := NewRepository(store, "canceled-flight-waiter")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewConsumer(repository, "main", ConsumerOptions{MaxConcurrentDownloads: 2})
	if err != nil {
		t.Fatal(err)
	}
	consumer.downloadBytes = newWeightedSemaphore(10)

	cancelCtx, cancel := context.WithCancel(t.Context())
	canceled := make(chan error, 1)
	go func() {
		lease, getErr := consumer.getChunk(cancelCtx, digest, int64(len(data)))
		if lease != nil {
			lease.Release()
		}
		canceled <- getErr
	}()
	<-entered
	type survivorResult struct {
		lease *chunkLease
		err   error
	}
	survivor := make(chan survivorResult, 1)
	go func() {
		lease, getErr := consumer.getChunk(t.Context(), digest, int64(len(data)))
		survivor <- survivorResult{lease: lease, err: getErr}
	}()
	waitForChunkFlightUsers(t, &consumer.chunkFlight, chunkFlightKey{digest: digest, expectedSize: int64(len(data))}, 2)
	cancel()
	if err := <-canceled; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled flight waiter error = %v, want context.Canceled", err)
	}
	waitForChunkFlightUsers(t, &consumer.chunkFlight, chunkFlightKey{digest: digest, expectedSize: int64(len(data))}, 1)
	close(release)
	result := <-survivor
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.lease == nil {
		t.Fatal("surviving flight waiter did not receive a lease")
	}
	assertSemaphoreUsed(t, consumer.downloadBytes, int64(len(data)))
	result.lease.Release()
	assertSemaphoreUsed(t, consumer.downloadBytes, 0)
}

func TestConsumerUsesExactChunkLimitAndSeparatesConflictingSizeFlights(t *testing.T) {
	data := []byte("same-chunk")
	digest := digestObject("chunk", data)
	entered := make(chan int64, 2)
	release := make(chan struct{})
	var gets atomic.Int32
	store := &downloadBudgetStore{}
	store.get = func(ctx context.Context, _ string, options GetOptions) (Object, error) {
		gets.Add(1)
		entered <- options.MaxBytes
		select {
		case <-release:
			return Object{Data: append([]byte(nil), data...), Version: Version{ETag: "chunk"}}, nil
		case <-ctx.Done():
			return Object{}, ctx.Err()
		}
	}
	repository, err := NewRepository(store, "exact-chunk-limit")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewConsumer(repository, "main", ConsumerOptions{MaxConcurrentDownloads: 2})
	if err != nil {
		t.Fatal(err)
	}

	correct := make(chan error, 1)
	go func() {
		lease, getErr := consumer.getChunk(t.Context(), digest, int64(len(data)))
		if lease != nil {
			lease.Release()
		}
		correct <- getErr
	}()
	if got := <-entered; got != int64(len(data)) {
		t.Fatalf("correct flight MaxBytes = %d, want %d", got, len(data))
	}
	conflicting := make(chan error, 1)
	go func() {
		lease, getErr := consumer.getChunk(t.Context(), digest, int64(len(data)+1))
		if lease != nil {
			lease.Release()
		}
		conflicting <- getErr
	}()
	if got := <-entered; got != int64(len(data)+1) {
		t.Fatalf("conflicting flight MaxBytes = %d, want %d", got, len(data)+1)
	}
	close(release)
	if err := <-correct; err != nil {
		t.Fatalf("correct-size flight: %v", err)
	}
	if err := <-conflicting; !errors.Is(err, ErrCorruptObject) {
		t.Fatalf("conflicting-size flight error = %v, want ErrCorruptObject", err)
	}
	if got := gets.Load(); got != 2 {
		t.Fatalf("Store.Get calls = %d, want two size-keyed flights", got)
	}
}

func TestConsumerRejectsStoreBodyBeyondExpectedChunkSize(t *testing.T) {
	expected := []byte("small")
	digest := digestObject("chunk", expected)
	store := &downloadBudgetStore{}
	store.get = func(_ context.Context, _ string, options GetOptions) (Object, error) {
		if options.MaxBytes != int64(len(expected)) {
			t.Fatalf("chunk MaxBytes = %d, want %d", options.MaxBytes, len(expected))
		}
		return Object{Data: []byte("small!"), Version: Version{ETag: "oversized"}}, nil
	}
	repository, err := NewRepository(store, "oversized-chunk")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewConsumer(repository, "main", ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	lease, getErr := consumer.getChunk(t.Context(), digest, int64(len(expected)))
	if lease != nil {
		lease.Release()
	}
	if !errors.Is(getErr, ErrResourceLimit) {
		t.Fatalf("oversized ignored-limit body error = %v, want ErrResourceLimit", getErr)
	}
	assertSemaphoreUsed(t, consumer.downloadBytes, 0)
}

func TestChunkLoaderPanicReleasesDownloadReservation(t *testing.T) {
	data := []byte("panic")
	digest := digestObject("chunk", data)
	repository, err := NewRepository(new(resourceProbeStore), "panic-cache-budget")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewConsumer(repository, "main", ConsumerOptions{
		Cache: &panicChunkCache{}, MaxConcurrentDownloads: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	lease, getErr := consumer.getChunk(t.Context(), digest, int64(len(data)))
	if lease != nil {
		lease.Release()
	}
	if getErr == nil {
		t.Fatal("panicking cache returned no chunk-flight error")
	}
	assertSemaphoreUsed(t, consumer.downloadBytes, 0)
	if got := len(consumer.downloadSlots); got != 0 {
		t.Fatalf("download count slots after panic = %d, want 0", got)
	}
}

func TestConsumerPassesExpectedSizeToSizedChunkCache(t *testing.T) {
	data := []byte("bounded-cache")
	digest := digestObject("chunk", data)
	cache := &recordingSizedCache{data: data}
	repository, err := NewRepository(new(resourceProbeStore), "sized-cache-consumer")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewConsumer(repository, "main", ConsumerOptions{Cache: cache})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := consumer.getChunk(t.Context(), digest, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if string(lease.data) != string(data) {
		t.Fatalf("cached data = %q, want %q", lease.data, data)
	}
	lease.Release()
	if cache.expected.Load() != int64(len(data)) {
		t.Fatalf("cache expected size = %d, want %d", cache.expected.Load(), len(data))
	}
	if cache.legacyGets.Load() != 0 {
		t.Fatalf("legacy cache Get calls = %d, want 0", cache.legacyGets.Load())
	}
}

func TestConsumerConservativelyChargesSmallMetadataAndReference(t *testing.T) {
	directoryData, err := canonicalJSON(dirManifest{Format: objectFormatVersion})
	if err != nil {
		t.Fatal(err)
	}
	directoryDigest := digestObject("dir", directoryData)
	commitDigest := digestObject("commit", []byte("commit"))
	referenceData, err := canonicalJSON(snapshotReference{Format: objectFormatVersion, Generation: 1, Commit: commitDigest})
	if err != nil {
		t.Fatal(err)
	}

	type request struct {
		maximum int64
		release chan struct{}
	}
	requests := make(chan request, 2)
	store := &downloadBudgetStore{}
	store.get = func(ctx context.Context, key string, options GetOptions) (Object, error) {
		item := request{maximum: options.MaxBytes, release: make(chan struct{})}
		requests <- item
		select {
		case <-item.release:
		case <-ctx.Done():
			return Object{}, ctx.Err()
		}
		if key == store.firstKey {
			return Object{Data: append([]byte(nil), directoryData...), Version: Version{ETag: "directory"}}, nil
		}
		return Object{Data: append([]byte(nil), referenceData...), Version: Version{ETag: "reference"}}, nil
	}
	repository, err := NewRepository(store, "metadata-byte-charge")
	if err != nil {
		t.Fatal(err)
	}
	store.firstKey = repository.objectKey("dir", directoryDigest)
	consumer, err := NewConsumer(repository, "main", ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}

	directoryResult := make(chan error, 1)
	go func() {
		_, loadErr := consumer.loadDirectory(t.Context(), directoryDigest)
		directoryResult <- loadErr
	}()
	directoryRequest := <-requests
	if directoryRequest.maximum != maxMetadataObjectBytes {
		t.Fatalf("small metadata MaxBytes = %d, want %d", directoryRequest.maximum, maxMetadataObjectBytes)
	}
	assertSemaphoreUsed(t, consumer.downloadBytes, maxMetadataObjectBytes)
	close(directoryRequest.release)
	if err := <-directoryResult; err != nil {
		t.Fatal(err)
	}

	type referenceResultValue struct {
		object Object
		err    error
	}
	referenceResult := make(chan referenceResultValue, 1)
	go func() {
		_, object, loadErr := consumer.downloadReference(t.Context(), "")
		referenceResult <- referenceResultValue{object: object, err: loadErr}
	}()
	referenceRequest := <-requests
	if referenceRequest.maximum != maxReferenceBytes {
		t.Fatalf("reference MaxBytes = %d, want %d", referenceRequest.maximum, maxReferenceBytes)
	}
	assertSemaphoreUsed(t, consumer.downloadBytes, maxReferenceBytes)
	close(referenceRequest.release)
	result := <-referenceResult
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.object.Data != nil {
		t.Fatalf("consumer retained %d raw reference bytes after releasing its reservation", len(result.object.Data))
	}
}

func waitForSemaphoreWaiters(t *testing.T, semaphore *weightedSemaphore, count int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		semaphore.mu.Lock()
		got := semaphore.waiters.Len()
		semaphore.mu.Unlock()
		if got == count {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("semaphore waiters = %d, want %d", got, count)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertSemaphoreUsed(t *testing.T, semaphore *weightedSemaphore, expected int64) {
	t.Helper()
	semaphore.mu.Lock()
	got := semaphore.used
	semaphore.mu.Unlock()
	if got != expected {
		t.Fatalf("charged download bytes = %d, want %d", got, expected)
	}
}

func waitForChunkFlightUsers(t *testing.T, group *chunkFlightGroup, key chunkFlightKey, count int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		group.mu.Lock()
		call := group.calls[key]
		got := 0
		if call != nil {
			got = call.users
		}
		group.mu.Unlock()
		if got == count {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("chunk flight users = %d, want %d", got, count)
		}
		time.Sleep(time.Millisecond)
	}
}

func updateAtomicMaximum(maximum *atomic.Int64, candidate int64) {
	for {
		observed := maximum.Load()
		if candidate <= observed || maximum.CompareAndSwap(observed, candidate) {
			return
		}
	}
}

type downloadBudgetStore struct {
	firstKey  string
	secondKey string
	get       func(context.Context, string, GetOptions) (Object, error)
}

func (store *downloadBudgetStore) Get(ctx context.Context, key string, options GetOptions) (Object, error) {
	return store.get(ctx, key, options)
}

func (*downloadBudgetStore) Head(context.Context, string) (Version, error) {
	return Version{}, ErrObjectNotFound
}

func (*downloadBudgetStore) PutIfAbsent(context.Context, string, []byte) (Version, error) {
	return Version{}, ErrPrecondition
}

func (*downloadBudgetStore) CompareAndSwap(context.Context, string, *Version, []byte) (Version, error) {
	return Version{}, ErrPrecondition
}

var _ Store = (*downloadBudgetStore)(nil)

type recordingSizedCache struct {
	data       []byte
	expected   atomic.Int64
	legacyGets atomic.Int32
}

func (cache *recordingSizedCache) Get(context.Context, Digest) ([]byte, bool, error) {
	cache.legacyGets.Add(1)
	return nil, false, nil
}

func (cache *recordingSizedCache) GetSized(_ context.Context, _ Digest, expectedSize int64) ([]byte, bool, error) {
	cache.expected.Store(expectedSize)
	return append([]byte(nil), cache.data...), true, nil
}

func (*recordingSizedCache) Put(context.Context, Digest, []byte) error { return nil }

var _ SizedChunkCache = (*recordingSizedCache)(nil)

type panicChunkCache struct{}

func (*panicChunkCache) Get(context.Context, Digest) ([]byte, bool, error) {
	panic("cache panic")
}

func (*panicChunkCache) Put(context.Context, Digest, []byte) error { return nil }

var _ ChunkCache = (*panicChunkCache)(nil)
