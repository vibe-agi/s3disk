package s3disk_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

var errCacheIO = errors.New("cache I/O failure")

type failingCache struct {
	getErr error
	putErr error
}

func (cache *failingCache) Get(context.Context, s3disk.Digest) ([]byte, bool, error) {
	return nil, false, cache.getErr
}

func (cache *failingCache) Put(context.Context, s3disk.Digest, []byte) error {
	return cache.putErr
}

type failFirstGetCache struct {
	mu      sync.Mutex
	failed  bool
	content []byte
}

func (cache *failFirstGetCache) Get(_ context.Context, _ s3disk.Digest) ([]byte, bool, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if !cache.failed {
		cache.failed = true
		return nil, false, errCacheIO
	}
	if cache.content == nil {
		return nil, false, nil
	}
	return append([]byte(nil), cache.content...), true, nil
}

func (cache *failFirstGetCache) Put(_ context.Context, _ s3disk.Digest, data []byte) error {
	cache.mu.Lock()
	cache.content = append(cache.content[:0], data...)
	cache.mu.Unlock()
	return nil
}

func TestCacheIOErrorsAreBestEffortUnlessStrict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repository, err := s3disk.NewRepository(memstore.New(), "cache-policy")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("remote bytes"))
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}

	reported := make(chan error, 8)
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
		Cache: &failingCache{getErr: errCacheIO, putErr: errCacheIO},
		OnCacheError: func(err error) {
			reported <- err
			panic("must be contained")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if got := string(readFile(t, consumer, "data")); got != "remote bytes" {
		t.Fatalf("best-effort cache read = %q", got)
	}
	if len(reported) < 2 {
		t.Fatalf("cache callback count = %d, want Get and Put errors", len(reported))
	}

	strict, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
		Cache: &failingCache{getErr: errCacheIO}, StrictCacheErrors: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strict.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	file, err := strict.Open(ctx, "data")
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, file.Size())
	if _, err := file.ReadAtContext(ctx, buffer, 0); !errors.Is(err, errCacheIO) {
		t.Fatalf("strict cache read error = %v, want cache error", err)
	}

	strictPut, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
		Cache: &failingCache{putErr: errCacheIO}, StrictCacheErrors: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strictPut.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	putFile, err := strictPut.Open(ctx, "data")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := putFile.ReadAtContext(ctx, buffer, 0); !errors.Is(err, errCacheIO) {
		t.Fatalf("strict cache write error = %v, want cache error", err)
	}
}

func TestCacheErrorCallbackCanReenterSameConsumer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repository, err := s3disk.NewRepository(memstore.New(), "cache-callback-reentry")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	want := []byte("reentrant cache callback")
	writeFile(t, filepath.Join(source, "data"), want)
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}

	type readResult struct {
		data []byte
		err  error
	}
	callbackResult := make(chan readResult, 1)
	var callbackCalls atomic.Int32
	var file *s3disk.File
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
		Cache:                  &failFirstGetCache{},
		MaxConcurrentDownloads: 1,
		OnCacheError: func(error) {
			callbackCalls.Add(1)
			nestedCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			buffer := make([]byte, file.Size())
			_, nestedErr := file.ReadAtContext(nestedCtx, buffer, 0)
			callbackResult <- readResult{data: buffer, err: nestedErr}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	file, err = consumer.Open(ctx, "data")
	if err != nil {
		t.Fatal(err)
	}

	outerResult := make(chan readResult, 1)
	go func() {
		buffer := make([]byte, file.Size())
		_, readErr := file.ReadAtContext(ctx, buffer, 0)
		outerResult <- readResult{data: buffer, err: readErr}
	}()

	select {
	case result := <-callbackResult:
		if result.err != nil {
			t.Fatalf("reentrant read from cache callback: %v", result.err)
		}
		if string(result.data) != string(want) {
			t.Fatalf("reentrant read = %q, want %q", result.data, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cache callback reentrant read did not complete")
	}
	select {
	case result := <-outerResult:
		if result.err != nil {
			t.Fatalf("outer read: %v", result.err)
		}
		if string(result.data) != string(want) {
			t.Fatalf("outer read = %q, want %q", result.data, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("outer read did not complete")
	}
	if got := callbackCalls.Load(); got != 1 {
		t.Fatalf("cache callback calls = %d, want 1", got)
	}
}

var _ s3disk.ChunkCache = (*failingCache)(nil)
var _ s3disk.ChunkCache = (*failFirstGetCache)(nil)
