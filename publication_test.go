package s3disk_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestStagedSnapshotIsInvisibleUntilCommit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memstore.New()
	repo, err := s3disk.NewRepository(store, "tenant/project")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repo, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "hello.txt"), []byte("version one"))

	staged, err := publisher.Stage(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	consumer := newConsumer(t, repo, "main")
	result, err := consumer.Refresh(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != s3disk.RefreshNoSnapshot {
		t.Fatalf("refresh before commit = %v, want no snapshot", result.Status)
	}

	snapshot, err := publisher.Commit(ctx, staged)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Generation != 1 {
		t.Fatalf("generation = %d, want 1", snapshot.Generation)
	}
	result, err = consumer.Refresh(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != s3disk.RefreshUpdated || result.Generation != 1 {
		t.Fatalf("refresh after commit = %+v, want generation 1", result)
	}
	if got := readFile(t, consumer, "hello.txt"); !bytes.Equal(got, []byte("version one")) {
		t.Fatalf("read = %q", got)
	}
}

func TestConsumerNeverRegressesAndOpenFilePinsItsSnapshot(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memstore.New()
	repo, err := s3disk.NewRepository(store, "project")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repo, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	filename := filepath.Join(source, "open.txt")
	writeFile(t, filename, []byte("old bytes"))
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}

	oldRef, err := store.Get(ctx, repo.ReferenceKey("main"), s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	consumer := newConsumer(t, repo, "main")
	if _, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	oldHandle, err := consumer.Open(ctx, "open.txt")
	if err != nil {
		t.Fatal(err)
	}

	writeFile(t, filename, []byte("new bytes"))
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	if result, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	} else if result.Generation != 2 {
		t.Fatalf("generation = %d, want 2", result.Generation)
	}

	oldData := make([]byte, oldHandle.Size())
	if _, err := oldHandle.ReadAtContext(ctx, oldData, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(oldData) != "old bytes" {
		t.Fatalf("old open handle read %q", oldData)
	}
	if got := string(readFile(t, consumer, "open.txt")); got != "new bytes" {
		t.Fatalf("new open read %q", got)
	}

	store.ForcePut(repo.ReferenceKey("main"), oldRef.Data)
	result, err := consumer.Refresh(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != s3disk.RefreshStaleIgnored || result.Generation != 2 {
		t.Fatalf("stale refresh = %+v", result)
	}
	if got := string(readFile(t, consumer, "open.txt")); got != "new bytes" {
		t.Fatalf("consumer regressed to %q", got)
	}
}

func TestPublishingUnchangedTreeDoesNotAdvanceGeneration(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memstore.New()
	repo, err := s3disk.NewRepository(store, "no-op")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repo, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "same.txt"), []byte("same"))
	first, err := publisher.Publish(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	store.ResetStats()
	second, err := publisher.Publish(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	if first != second || second.Generation != 1 {
		t.Fatalf("unchanged publish advanced from %+v to %+v", first, second)
	}
}

func TestPublisherRejectsSymlinkAsSourceRoot(t *testing.T) {
	t.Parallel()

	target := privateTestDirectory(t)
	link := filepath.Join(privateTestDirectory(t), "source-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "source-boundary")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(context.Background(), link, "main"); !errors.Is(err, s3disk.ErrNotDirectory) {
		t.Fatalf("publish symlink source error = %v, want ErrNotDirectory", err)
	}
}

func TestUnsafeSymlinkRequiresExplicitPreservePolicy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	source := privateTestDirectory(t)
	link := filepath.Join(source, "escape")
	if err := os.Symlink("../../outside", link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "symlink-policy")
	if err != nil {
		t.Fatal(err)
	}
	safePublisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := safePublisher.Publish(ctx, source, "main"); !errors.Is(err, s3disk.ErrUnsafeSymlink) {
		t.Fatalf("safe publish error = %v, want ErrUnsafeSymlink", err)
	}

	preservePublisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{Symlinks: s3disk.SymlinkPreserve})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := preservePublisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	safeConsumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := safeConsumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := safeConsumer.Readlink(ctx, "escape"); !errors.Is(err, s3disk.ErrUnsafeSymlink) {
		t.Fatalf("safe Readlink error = %v, want ErrUnsafeSymlink", err)
	}

	preserveConsumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{Symlinks: s3disk.SymlinkPreserve})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := preserveConsumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if target, err := preserveConsumer.Readlink(ctx, "escape"); err != nil || target != "../../outside" {
		t.Fatalf("preserved Readlink = %q, %v", target, err)
	}
}

func TestPublisherNeverFollowsPreservedSymlinkForContent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	outside := filepath.Join(privateTestDirectory(t), "secret")
	writeFile(t, outside, []byte("must not be uploaded as file content"))
	source := privateTestDirectory(t)
	link := filepath.Join(source, "external")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "preserved-link")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{Symlinks: s3disk.SymlinkPreserve})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	if stats := store.Stats(); stats.ChunkPuts != 0 {
		t.Fatalf("publisher followed preserved symlink and uploaded %d chunks", stats.ChunkPuts)
	}
}

func TestPublisherRetryUsesMetadataFromStableFileVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows permission bits do not represent Unix chmod transitions")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	base := memstore.New()
	store := &blockingChunkPutStore{
		Store: base, entered: make(chan struct{}), release: make(chan struct{}),
	}
	repository, err := s3disk.NewRepository(store, "stable-file-metadata")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	filename := filepath.Join(source, "data")
	writeFile(t, filename, []byte(strings.Repeat("content", 1024)))

	result := make(chan error, 1)
	go func() {
		_, err := publisher.Publish(ctx, source, "main")
		result <- err
	}()
	select {
	case <-store.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := os.Chmod(filename, 0o600); err != nil {
		t.Fatal(err)
	}
	close(store.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}

	consumer := newConsumer(t, repository, "main")
	if _, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	entry, err := consumer.Stat(ctx, "data")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Mode != 0o400 {
		t.Fatalf("published mode = %o, want stable post-retry mode 0400", entry.Mode)
	}
}

type blockingChunkPutStore struct {
	s3disk.Store
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (store *blockingChunkPutStore) PutIfAbsent(ctx context.Context, key string, data []byte) (s3disk.Version, error) {
	blocked := false
	if strings.Contains(key, "/objects/chunk/") {
		store.once.Do(func() {
			blocked = true
			close(store.entered)
		})
	}
	if blocked {
		select {
		case <-store.release:
		case <-ctx.Done():
			return s3disk.Version{}, ctx.Err()
		}
	}
	return store.Store.PutIfAbsent(ctx, key, data)
}

func newConsumer(t *testing.T, repo *s3disk.Repository, channel string) *s3disk.Consumer {
	t.Helper()
	cache, err := s3disk.NewDiskCache(privateTestDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cache.Close() })
	consumer, err := s3disk.NewConsumer(repo, channel, s3disk.ConsumerOptions{Cache: cache})
	if err != nil {
		t.Fatal(err)
	}
	return consumer
}

func readFile(t *testing.T, consumer *s3disk.Consumer, name string) []byte {
	t.Helper()
	f, err := consumer.Open(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, f.Size())
	_, err = f.ReadAtContext(context.Background(), data, 0)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	return data
}

func writeFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(name, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
