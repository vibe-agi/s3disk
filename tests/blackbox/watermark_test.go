package s3disk_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestPersistentWatermarkPreventsRollbackAfterRestart(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "restart-watermark")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	filename := filepath.Join(source, "data.txt")
	writeFile(t, filename, []byte("one"))
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	firstReference, err := store.Get(ctx, repository.ReferenceKey("main"), s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	watermarkPath := filepath.Join(privateTestDirectory(t), "consumer.watermark")
	watermarks, err := s3disk.NewFileWatermarkStore(watermarkPath)
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
		Watermarks: watermarks, RequirePersistentWatermark: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filename, []byte("two"))
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	if result, err := consumer.Refresh(ctx); err != nil || result.Generation != 2 {
		t.Fatalf("adopt generation 2: result=%+v err=%v", result, err)
	}
	secondReference, err := store.Get(ctx, repository.ReferenceKey("main"), s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a process restart followed by an old, but internally valid,
	// object-store response.
	store.ForcePut(repository.ReferenceKey("main"), firstReference.Data)
	restartedStore, err := s3disk.NewFileWatermarkStore(watermarkPath)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
		Watermarks: restartedStore, RequirePersistentWatermark: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Refresh(ctx); !errors.Is(err, s3disk.ErrRollbackDetected) {
		t.Fatalf("restart refresh error = %v, want ErrRollbackDetected", err)
	}
	if _, ok := restarted.CurrentSnapshot(); ok {
		t.Fatal("restarted consumer exposed a rolled-back snapshot")
	}

	store.ForcePut(repository.ReferenceKey("main"), secondReference.Data)
	if result, err := restarted.Refresh(ctx); err != nil || result.Generation != 2 {
		t.Fatalf("recover current generation: result=%+v err=%v", result, err)
	}
	if got := string(readFile(t, restarted, "data.txt")); got != "two" {
		t.Fatalf("recovered data = %q, want two", got)
	}
	if info, err := os.Stat(watermarkPath); err != nil {
		t.Fatal(err)
	} else if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("watermark permissions = %o, want private", info.Mode().Perm())
	}
}

func TestSharedWatermarkAdvanceForcesUnconditionalRefresh(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "shared-watermark-refresh")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	file := filepath.Join(source, "data")
	writeFile(t, file, []byte("one"))
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	oldReference, err := store.Get(ctx, repository.ReferenceKey("main"), s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	watermarkPath := filepath.Join(privateTestDirectory(t), "shared.watermark")
	newConsumer := func() *s3disk.Consumer {
		watermarks, err := s3disk.NewFileWatermarkStore(watermarkPath)
		if err != nil {
			t.Fatal(err)
		}
		consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
			Watermarks: watermarks, RequirePersistentWatermark: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return consumer
	}
	first, second := newConsumer(), newConsumer()
	if _, err := first.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Refresh(ctx); err != nil {
		t.Fatal(err)
	}

	writeFile(t, file, []byte("two"))
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	if result, err := first.Refresh(ctx); err != nil || result.Generation != 2 {
		t.Fatalf("first consumer advance = %+v, %v", result, err)
	}

	// The replay has exactly the ETag cached by second. Reloading the shared
	// watermark must suppress If-None-Match and expose the rollback instead of a
	// misleading 304/unchanged result.
	store.ForcePut(repository.ReferenceKey("main"), oldReference.Data)
	if _, err := second.Refresh(ctx); !errors.Is(err, s3disk.ErrRollbackDetected) {
		t.Fatalf("second consumer after shared advance/replay error = %v, want ErrRollbackDetected", err)
	}
}

func TestConsumerReconcilesAmbiguousWatermarkCAS(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	objectStore := memstore.New()
	repository, err := s3disk.NewRepository(objectStore, "ambiguous-consumer-watermark")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("value"))
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	base, err := s3disk.NewFileWatermarkStore(filepath.Join(privateTestDirectory(t), "consumer.watermark"))
	if err != nil {
		t.Fatal(err)
	}
	watermarks := &applyThenErrorWatermarkStore{base: base, failNext: true}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
		Watermarks: watermarks, RequirePersistentWatermark: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := consumer.Refresh(ctx)
	if err != nil || result.Generation != 1 {
		t.Fatalf("Refresh after applied/lost watermark CAS = %+v, %v", result, err)
	}
	if watermark, found, err := base.Load(ctx, "main"); err != nil || !found || watermark.Generation != 1 {
		t.Fatalf("durable watermark = %+v, found=%v, err=%v", watermark, found, err)
	}
}

func TestFileWatermarkStoreCreatesNestedPrivateDirectory(t *testing.T) {
	t.Parallel()

	root := privateTestDirectory(t)
	first := filepath.Join(root, "state")
	directory := filepath.Join(first, "watermarks")
	path := filepath.Join(directory, "main.watermark")
	store, err := s3disk.NewFileWatermarkStore(path)
	if err != nil {
		t.Fatal(err)
	}
	want := s3disk.Watermark{Generation: 1, Commit: s3disk.Digest{1}}
	if err := store.CompareAndSwap(context.Background(), "main", nil, want); err != nil {
		t.Fatal(err)
	}
	got, found, err := store.Load(context.Background(), "main")
	if err != nil || !found || got != want {
		t.Fatalf("Load = %+v, %v, %v; want %+v, true, nil", got, found, err, want)
	}
	if runtime.GOOS == "windows" {
		return
	}
	for _, created := range []string{first, directory} {
		info, err := os.Stat(created)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("created directory %q permissions = %o, want private", created, info.Mode().Perm())
		}
	}
}

func TestPersistentWatermarkIsRequiredWhenConfigured(t *testing.T) {
	t.Parallel()
	repository, err := s3disk.NewRepository(memstore.New(), "required-watermark")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
		RequirePersistentWatermark: true,
	}); err == nil {
		t.Fatal("NewConsumer accepted a missing required watermark store")
	}
}

func TestFileWatermarkStoreRejectsSymlinkFile(t *testing.T) {
	t.Parallel()

	directory := privateTestDirectory(t)
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "watermark")
	if err := os.WriteFile(target, []byte("not a watermark"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	store, err := s3disk.NewFileWatermarkStore(link)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(context.Background(), "main"); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("Load error = %v, want ErrCorruptObject", err)
	}
}

func TestFileWatermarkStoreCASSerializesConcurrentBranches(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(privateTestDirectory(t), "shared.watermark")
	left, err := s3disk.NewFileWatermarkStore(path)
	if err != nil {
		t.Fatal(err)
	}
	right, err := s3disk.NewFileWatermarkStore(path)
	if err != nil {
		t.Fatal(err)
	}
	initial := s3disk.Watermark{Generation: 1, Commit: s3disk.Digest{1}}
	if err := left.CompareAndSwap(ctx, "main", nil, initial); err != nil {
		t.Fatal(err)
	}
	expectedLeft, found, err := left.Load(ctx, "main")
	if err != nil || !found {
		t.Fatalf("left Load = %+v, %v, %v", expectedLeft, found, err)
	}
	expectedRight, found, err := right.Load(ctx, "main")
	if err != nil || !found {
		t.Fatalf("right Load = %+v, %v, %v", expectedRight, found, err)
	}

	errorsFound := make(chan error, 2)
	start := make(chan struct{})
	for _, attempt := range []struct {
		store    *s3disk.FileWatermarkStore
		expected s3disk.Watermark
		next     s3disk.Watermark
	}{
		{store: left, expected: expectedLeft, next: s3disk.Watermark{Generation: 2, Commit: s3disk.Digest{2}}},
		{store: right, expected: expectedRight, next: s3disk.Watermark{Generation: 2, Commit: s3disk.Digest{3}}},
	} {
		attempt := attempt
		go func() {
			<-start
			errorsFound <- attempt.store.CompareAndSwap(ctx, "main", &attempt.expected, attempt.next)
		}()
	}
	close(start)
	firstErr := <-errorsFound
	secondErr := <-errorsFound
	close(errorsFound)
	if (firstErr == nil) == (secondErr == nil) {
		t.Fatalf("CAS errors = (%v, %v), want exactly one success", firstErr, secondErr)
	}
	loser := firstErr
	if loser == nil {
		loser = secondErr
	}
	if !errors.Is(loser, s3disk.ErrPrecondition) {
		t.Fatalf("losing CAS error = %v, want ErrPrecondition", loser)
	}
	final, found, err := left.Load(ctx, "main")
	if err != nil || !found || final.Generation != 2 || (final.Commit != (s3disk.Digest{2}) && final.Commit != (s3disk.Digest{3})) {
		t.Fatalf("final watermark = %+v, %v, %v", final, found, err)
	}
}

type applyThenErrorWatermarkStore struct {
	base     *s3disk.FileWatermarkStore
	failNext bool
}

func (store *applyThenErrorWatermarkStore) Load(ctx context.Context, channel string) (s3disk.Watermark, bool, error) {
	return store.base.Load(ctx, channel)
}

func (store *applyThenErrorWatermarkStore) CompareAndSwap(ctx context.Context, channel string, expected *s3disk.Watermark, next s3disk.Watermark) error {
	err := store.base.CompareAndSwap(ctx, channel, expected, next)
	if err == nil && store.failNext {
		store.failNext = false
		return errInjectedNetwork
	}
	return err
}
