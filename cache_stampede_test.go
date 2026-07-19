package s3disk

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestConsumerCoalescesConcurrentCachedChunkReads(t *testing.T) {
	t.Parallel()
	data := []byte("verified cached chunk")
	digest := digestObject("chunk", data)
	cache := &blockingHitCache{
		data: data, entered: make(chan struct{}), release: make(chan struct{}),
	}
	repository, err := NewRepository(&manifestStore{}, "cached-flight")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewConsumer(repository, "main", ConsumerOptions{
		Cache: cache, MaxConcurrentDownloads: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	const readers = 32
	start := make(chan struct{})
	results := make(chan error, readers)
	var ready sync.WaitGroup
	ready.Add(readers)
	for range readers {
		go func() {
			ready.Done()
			<-start
			lease, err := consumer.getChunk(context.Background(), digest, int64(len(data)))
			if err == nil {
				if string(lease.data) != string(data) {
					err = ErrCorruptObject
				}
				lease.Release()
			}
			results <- err
		}()
	}
	ready.Wait()
	close(start)
	<-cache.entered
	deadline := time.Now().Add(time.Second)
	for {
		consumer.chunkFlight.mu.Lock()
		call := consumer.chunkFlight.calls[chunkFlightKey{digest: digest, expectedSize: int64(len(data))}]
		joined := call != nil && call.users == readers
		consumer.chunkFlight.mu.Unlock()
		if joined {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("concurrent readers did not join one cached-chunk flight")
		}
		runtime.Gosched()
	}
	close(cache.release)
	for range readers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	cache.mu.Lock()
	gets := cache.gets
	cache.mu.Unlock()
	if gets != 1 {
		t.Fatalf("cache Get calls = %d, want 1", gets)
	}
}

type blockingHitCache struct {
	mu      sync.Mutex
	data    []byte
	gets    int
	entered chan struct{}
	release chan struct{}
}

func (cache *blockingHitCache) Get(ctx context.Context, _ Digest) ([]byte, bool, error) {
	cache.mu.Lock()
	cache.gets++
	if cache.gets == 1 {
		close(cache.entered)
	}
	cache.mu.Unlock()
	select {
	case <-cache.release:
		return append([]byte(nil), cache.data...), true, nil
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
}

func (*blockingHitCache) Put(context.Context, Digest, []byte) error { return nil }

var _ ChunkCache = (*blockingHitCache)(nil)
