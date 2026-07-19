package s3disk_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestConsumerBoundsMetadataAndChunkDownloadsTogether(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := memstore.New()
	store := &hookedStore{base: base}
	repository, err := s3disk.NewRepository(store, "download-limit")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		Chunking: s3disk.ChunkingOptions{MinSize: 64, AverageSize: 128, MaxSize: 256},
	})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	const files = 16
	for index := range files {
		data := []byte(strings.Repeat(fmt.Sprintf("%02d", index), 64))
		writeFile(t, filepath.Join(source, fmt.Sprintf("file-%02d", index)), data)
	}
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{MaxConcurrentDownloads: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}

	var active atomic.Int32
	var maximum atomic.Int32
	recordDownload := func(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
		current := active.Add(1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		timer := time.NewTimer(15 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			active.Add(-1)
			return s3disk.Object{}, ctx.Err()
		case <-timer.C:
		}
		active.Add(-1)
		return base.Get(ctx, key, options)
	}
	store.get = func(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
		if strings.Contains(key, "/objects/file/") {
			return recordDownload(ctx, key, options)
		}
		return base.Get(ctx, key, options)
	}
	handles := make([]*s3disk.File, files)
	runConcurrent(t, files, func(index int) error {
		file, err := consumer.Open(ctx, fmt.Sprintf("file-%02d", index))
		handles[index] = file
		return err
	})
	if got := maximum.Load(); got != 2 {
		t.Fatalf("maximum concurrent metadata downloads = %d, want 2", got)
	}

	active.Store(0)
	maximum.Store(0)
	store.get = func(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
		if strings.Contains(key, "/objects/chunk/") {
			return recordDownload(ctx, key, options)
		}
		return base.Get(ctx, key, options)
	}
	runConcurrent(t, files, func(index int) error {
		buffer := make([]byte, handles[index].Size())
		_, err := handles[index].ReadAtContext(ctx, buffer, 0)
		return err
	})
	if got := maximum.Load(); got != 2 {
		t.Fatalf("maximum concurrent chunk downloads = %d, want 2", got)
	}
}

func runConcurrent(t *testing.T, count int, operation func(int) error) {
	t.Helper()
	start := make(chan struct{})
	errorsFound := make(chan error, count)
	var wait sync.WaitGroup
	for index := range count {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			if err := operation(index); err != nil {
				errorsFound <- err
			}
		}(index)
	}
	close(start)
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
}
