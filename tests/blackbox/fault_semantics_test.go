package s3disk_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

var errInjectedNetwork = errors.New("injected network failure")

type hookedStore struct {
	base s3disk.Store

	get            func(context.Context, string, s3disk.GetOptions) (s3disk.Object, error)
	compareAndSwap func(context.Context, string, *s3disk.Version, []byte) (s3disk.Version, error)
}

func (store *hookedStore) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	if store.get != nil {
		return store.get(ctx, key, options)
	}
	return store.base.Get(ctx, key, options)
}

func (store *hookedStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	return store.base.Head(ctx, key)
}

func (store *hookedStore) PutIfAbsent(ctx context.Context, key string, data []byte) (s3disk.Version, error) {
	return store.base.PutIfAbsent(ctx, key, data)
}

func (store *hookedStore) CompareAndSwap(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
	if store.compareAndSwap != nil {
		return store.compareAndSwap(ctx, key, expected, data)
	}
	return store.base.CompareAndSwap(ctx, key, expected, data)
}

func TestCommitRecoversWhenSuccessfulCASResponseIsLost(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	base := memstore.New()
	store := &hookedStore{base: base}
	loseResponse := true
	store.compareAndSwap = func(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
		version, err := base.CompareAndSwap(ctx, key, expected, data)
		if err == nil && loseResponse {
			loseResponse = false
			return s3disk.Version{}, errInjectedNetwork
		}
		return version, err
	}
	repository, err := s3disk.NewRepository(store, "lost-cas")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data.txt"), []byte("durable data"))

	snapshot, err := publisher.Publish(ctx, source, "main")
	if err != nil {
		t.Fatalf("publish after lost successful CAS response: %v", err)
	}
	if snapshot.Generation != 1 {
		t.Fatalf("generation = %d, want 1", snapshot.Generation)
	}
	consumer := newConsumer(t, repository, "main")
	if result, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	} else if result.Generation != 1 {
		t.Fatalf("consumer generation = %d, want 1", result.Generation)
	}
}

func TestCommitRetryAfterCASRequestIsDropped(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	base := memstore.New()
	store := &hookedStore{base: base}
	dropRequest := true
	store.compareAndSwap = func(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
		if dropRequest {
			dropRequest = false
			return s3disk.Version{}, errInjectedNetwork
		}
		return base.CompareAndSwap(ctx, key, expected, data)
	}
	repository, err := s3disk.NewRepository(store, "dropped-cas")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data.txt"), []byte("retry me"))
	staged, err := publisher.Stage(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Commit(ctx, staged); !errors.Is(err, s3disk.ErrPublishIndeterminate) {
		t.Fatalf("dropped request error = %v, want ErrPublishIndeterminate", err)
	}
	if _, err := base.Get(ctx, repository.ReferenceKey("main"), s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrObjectNotFound) {
		t.Fatalf("reference after dropped request error = %v, want object not found", err)
	}
	snapshot, err := publisher.Commit(ctx, staged)
	if err != nil {
		t.Fatalf("retry after dropped request: %v", err)
	}
	if snapshot.Generation != 1 {
		t.Fatalf("retried generation = %d, want 1", snapshot.Generation)
	}
}

func TestCommitRetryResolvesIndeterminateOutcome(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	base := memstore.New()
	store := &hookedStore{base: base}
	var mu sync.Mutex
	loseResponse := true
	failReconciliation := false
	store.compareAndSwap = func(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
		version, err := base.CompareAndSwap(ctx, key, expected, data)
		mu.Lock()
		defer mu.Unlock()
		if err == nil && loseResponse {
			loseResponse = false
			failReconciliation = true
			return s3disk.Version{}, errInjectedNetwork
		}
		return version, err
	}
	store.get = func(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
		mu.Lock()
		if failReconciliation {
			failReconciliation = false
			mu.Unlock()
			return s3disk.Object{}, errInjectedNetwork
		}
		mu.Unlock()
		return base.Get(ctx, key, options)
	}
	repository, err := s3disk.NewRepository(store, "retry-cas")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data.txt"), []byte("one"))
	staged, err := publisher.Stage(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := publisher.Commit(ctx, staged); !errors.Is(err, s3disk.ErrPublishIndeterminate) {
		t.Fatalf("first commit error = %v, want ErrPublishIndeterminate", err)
	}
	// The exported value is informational. Mutating it must not change the
	// immutable operation retried by Commit.
	staged.Snapshot = s3disk.Snapshot{}
	snapshot, err := publisher.Commit(ctx, staged)
	if err != nil {
		t.Fatalf("retry same staged snapshot: %v", err)
	}
	if snapshot.Generation != 1 || snapshot.Commit.IsZero() {
		t.Fatalf("retried snapshot = %+v, want original generation 1", snapshot)
	}
}

func TestCommitRetryRecognizesPublishedAncestor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	base := memstore.New()
	store := &hookedStore{base: base}
	repository, err := s3disk.NewRepository(store, "cas-ancestor")
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

	writeFile(t, filename, []byte("two"))
	staged, err := publisher.Stage(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	loseResponse := true
	failReconciliation := false
	store.compareAndSwap = func(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
		version, err := base.CompareAndSwap(ctx, key, expected, data)
		mu.Lock()
		defer mu.Unlock()
		if err == nil && loseResponse {
			loseResponse = false
			failReconciliation = true
			return s3disk.Version{}, errInjectedNetwork
		}
		return version, err
	}
	store.get = func(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
		mu.Lock()
		if failReconciliation {
			failReconciliation = false
			mu.Unlock()
			return s3disk.Object{}, errInjectedNetwork
		}
		mu.Unlock()
		return base.Get(ctx, key, options)
	}
	if _, err := publisher.Commit(ctx, staged); !errors.Is(err, s3disk.ErrPublishIndeterminate) {
		t.Fatalf("commit error = %v, want ErrPublishIndeterminate", err)
	}

	writeFile(t, filename, []byte("three"))
	third, err := publisher.Publish(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	if third.Generation != 3 {
		t.Fatalf("latest generation = %d, want 3", third.Generation)
	}
	second, err := publisher.Commit(ctx, staged)
	if err != nil {
		t.Fatalf("retry generation 2 after generation 3: %v", err)
	}
	if second.Generation != 2 {
		t.Fatalf("resolved generation = %d, want 2", second.Generation)
	}
}

func TestConcurrentPublishersHaveOneWinner(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	base := memstore.New()
	repository, err := s3disk.NewRepository(base, "concurrent")
	if err != nil {
		t.Fatal(err)
	}
	publisherA, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	publisherB, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	sourceA := privateTestDirectory(t)
	sourceB := privateTestDirectory(t)
	writeFile(t, filepath.Join(sourceA, "winner.txt"), []byte("A"))
	writeFile(t, filepath.Join(sourceB, "winner.txt"), []byte("B"))
	stagedA, err := publisherA.Stage(ctx, sourceA, "main")
	if err != nil {
		t.Fatal(err)
	}
	stagedB, err := publisherB.Stage(ctx, sourceB, "main")
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, attempt := range []struct {
		publisher *s3disk.Publisher
		staged    *s3disk.StagedSnapshot
	}{{publisherA, stagedA}, {publisherB, stagedB}} {
		attempt := attempt
		go func() {
			<-start
			_, err := attempt.publisher.Commit(ctx, attempt.staged)
			results <- err
		}()
	}
	close(start)
	firstErr, secondErr := <-results, <-results
	if (firstErr == nil) == (secondErr == nil) {
		t.Fatalf("concurrent commit errors = (%v, %v), want exactly one winner", firstErr, secondErr)
	}
	loser := firstErr
	if loser == nil {
		loser = secondErr
	}
	if !errors.Is(loser, s3disk.ErrPublishConflict) {
		t.Fatalf("losing commit error = %v, want ErrPublishConflict", loser)
	}
}

func TestConsumerRejectsHigherGenerationFromDisjointHistory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	base := memstore.New()
	store := &hookedStore{base: base}
	repository, err := s3disk.NewRepository(store, "forked-history")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	sourceA := privateTestDirectory(t)
	fileA := filepath.Join(sourceA, "data.txt")
	writeFile(t, fileA, []byte("base"))
	if _, err := publisher.Publish(ctx, sourceA, "main"); err != nil {
		t.Fatal(err)
	}

	writeFile(t, fileA, []byte("branch-a-two"))
	branchATwo, err := publisher.Stage(ctx, sourceA, "main")
	if err != nil {
		t.Fatal(err)
	}
	sourceB := privateTestDirectory(t)
	writeFile(t, filepath.Join(sourceB, "data.txt"), []byte("branch-b-two"))
	branchBTwo, err := publisher.Stage(ctx, sourceB, "main")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Commit(ctx, branchBTwo); err != nil {
		t.Fatal(err)
	}
	branchBReference, err := base.Get(ctx, repository.ReferenceKey("main"), s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	consumer := newConsumer(t, repository, "main")
	if result, err := consumer.Refresh(ctx); err != nil || result.Generation != 2 {
		t.Fatalf("adopt branch B generation 2: result=%+v err=%v", result, err)
	}

	branchAReference := []byte(fmt.Sprintf(
		`{"format":1,"generation":%d,"commit":%q}`,
		branchATwo.Snapshot.Generation,
		branchATwo.Snapshot.Commit.String(),
	))
	base.ForcePut(repository.ReferenceKey("main"), branchAReference)
	writeFile(t, fileA, []byte("branch-a-three"))
	if snapshot, err := publisher.Publish(ctx, sourceA, "main"); err != nil {
		t.Fatal(err)
	} else if snapshot.Generation != 3 {
		t.Fatalf("branch A generation = %d, want 3", snapshot.Generation)
	}
	branchAThreeReference, err := base.Get(ctx, repository.ReferenceKey("main"), s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	base.ForcePut(repository.ReferenceKey("main"), branchBReference.Data)

	serveFork := true
	store.get = func(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
		if serveFork && key == repository.ReferenceKey("main") {
			return branchAThreeReference, nil
		}
		return base.Get(ctx, key, options)
	}
	if result, err := consumer.Refresh(ctx); !errors.Is(err, s3disk.ErrSplitBrain) {
		t.Fatalf("fork refresh error = %v, want ErrSplitBrain", err)
	} else if result.Generation != 2 {
		t.Fatalf("generation after fork = %d, want 2", result.Generation)
	}
	assertConsumerGeneration(t, consumer, 2)
	if got := string(readFile(t, consumer, "data.txt")); got != "branch-b-two" {
		t.Fatalf("consumer switched histories and read %q", got)
	}
	serveFork = false
}

func TestConsumerPreservesLastKnownGoodSnapshotAcrossFaults(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	base := memstore.New()
	store := &hookedStore{base: base}
	repository, err := s3disk.NewRepository(store, "consumer-faults")
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
	oldReference, err := base.Get(ctx, repository.ReferenceKey("main"), s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	consumer := newConsumer(t, repository, "main")
	if _, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}

	mode := "network"
	store.get = func(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
		if key == repository.ReferenceKey("main") {
			switch mode {
			case "network":
				return s3disk.Object{}, errInjectedNetwork
			case "stale-reference":
				return oldReference, nil
			case "split-brain":
				var value map[string]any
				if err := json.Unmarshal(oldReference.Data, &value); err != nil {
					return s3disk.Object{}, err
				}
				data := []byte(fmt.Sprintf(`{"format":1,"generation":4,"commit":%q}`, value["commit"]))
				return s3disk.Object{Data: data, Version: s3disk.Version{ETag: "split-brain"}}, nil
			}
		}
		object, err := base.Get(ctx, key, options)
		if err != nil {
			return object, err
		}
		if (mode == "corrupt-commit" && strings.Contains(key, "/objects/commit/")) ||
			(mode == "corrupt-directory" && strings.Contains(key, "/objects/dir/")) ||
			(mode == "corrupt-chunk" && strings.Contains(key, "/objects/chunk/")) {
			object.Data[0] ^= 0xff
		}
		return object, nil
	}

	if result, err := consumer.Refresh(ctx); !errors.Is(err, errInjectedNetwork) {
		t.Fatalf("network refresh error = %v", err)
	} else if result.Generation != 1 {
		t.Fatalf("generation after network error = %d, want 1", result.Generation)
	}
	assertConsumerGeneration(t, consumer, 1)

	mode = ""
	writeFile(t, filename, []byte("two"))
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	if result, err := consumer.Refresh(ctx); err != nil || result.Generation != 2 {
		t.Fatalf("adopt generation 2: result=%+v err=%v", result, err)
	}
	mode = "stale-reference"
	if result, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	} else if result.Status != s3disk.RefreshStaleIgnored || result.Generation != 2 {
		t.Fatalf("stale response result = %+v", result)
	}
	assertConsumerGeneration(t, consumer, 2)

	mode = ""
	writeFile(t, filename, []byte("three"))
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	mode = "corrupt-commit"
	if result, err := consumer.Refresh(ctx); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("corrupt commit refresh error = %v", err)
	} else if result.Generation != 2 {
		t.Fatalf("generation after corrupt commit = %d, want 2", result.Generation)
	}
	assertConsumerGeneration(t, consumer, 2)
	mode = ""
	if result, err := consumer.Refresh(ctx); err != nil || result.Generation != 3 {
		t.Fatalf("adopt generation 3: result=%+v err=%v", result, err)
	}

	writeFile(t, filename, []byte("four"))
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	mode = "corrupt-directory"
	if result, err := consumer.Refresh(ctx); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("corrupt directory refresh error = %v", err)
	} else if result.Generation != 3 {
		t.Fatalf("generation after corrupt directory = %d, want 3", result.Generation)
	}
	assertConsumerGeneration(t, consumer, 3)
	mode = ""
	if result, err := consumer.Refresh(ctx); err != nil || result.Generation != 4 {
		t.Fatalf("adopt generation 4: result=%+v err=%v", result, err)
	}

	mode = "split-brain"
	if result, err := consumer.Refresh(ctx); !errors.Is(err, s3disk.ErrSplitBrain) {
		t.Fatalf("split-brain refresh error = %v", err)
	} else if result.Generation != 4 {
		t.Fatalf("generation after split brain = %d, want 4", result.Generation)
	}
	assertConsumerGeneration(t, consumer, 4)

	mode = "corrupt-chunk"
	file, err := consumer.Open(ctx, "data.txt")
	if err != nil {
		t.Fatal(err)
	}
	destination := bytes.Repeat([]byte{0xa5}, int(file.Size()))
	if n, err := file.ReadAtContext(ctx, destination, 0); n != 0 || !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("corrupt chunk read = (%d, %v), want (0, ErrCorruptObject)", n, err)
	}
	if !bytes.Equal(destination, bytes.Repeat([]byte{0xa5}, len(destination))) {
		t.Fatal("corrupt chunk modified the caller buffer")
	}
	mode = ""
	if n, err := file.ReadAtContext(ctx, destination, 0); n != len(destination) || (err != nil && !errors.Is(err, io.EOF)) {
		t.Fatalf("recovered chunk read = (%d, %v)", n, err)
	}
	if string(destination) != "four" {
		t.Fatalf("recovered chunk data = %q", destination)
	}
}

func assertConsumerGeneration(t *testing.T, consumer *s3disk.Consumer, want uint64) {
	t.Helper()
	snapshot, ok := consumer.CurrentSnapshot()
	if !ok || snapshot.Generation != want {
		t.Fatalf("current snapshot = (%+v, %v), want generation %d", snapshot, ok, want)
	}
}

type corruptHitCache struct {
	data []byte
}

func (cache *corruptHitCache) Get(context.Context, s3disk.Digest) ([]byte, bool, error) {
	return append([]byte(nil), cache.data...), true, nil
}

func (*corruptHitCache) Put(context.Context, s3disk.Digest, []byte) error { return nil }

func TestConsumerVerifiesCachedChunkBeforeUse(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	base := memstore.New()
	repository, err := s3disk.NewRepository(base, "cache-fault")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data.txt"), []byte("good-data"))
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	cache := &corruptHitCache{data: []byte("evil-data")}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{Cache: cache})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	file, err := consumer.Open(ctx, "data.txt")
	if err != nil {
		t.Fatal(err)
	}
	destination := bytes.Repeat([]byte{0xa5}, int(file.Size()))
	if n, err := file.ReadAtContext(ctx, destination, 0); n != 0 || !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("read from corrupt cache = (%d, %v), want (0, ErrCorruptObject)", n, err)
	}
}

var _ s3disk.Store = (*hookedStore)(nil)
var _ s3disk.ChunkCache = (*corruptHitCache)(nil)
