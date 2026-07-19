package s3disk_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestPublisherWatchAndConsumerPollConverge(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := memstore.New()
	repo, err := s3disk.NewRepository(store, "live")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repo, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	filename := filepath.Join(source, "live.txt")
	writeFile(t, filename, []byte("one"))

	published := make(chan s3disk.Snapshot, 4)
	watchErrors := make(chan error, 4)
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- publisher.Watch(ctx, source, "main", s3disk.WatchOptions{
			Debounce:          10 * time.Millisecond,
			ReconcileInterval: 50 * time.Millisecond,
			OnPublished: func(snapshot s3disk.Snapshot) {
				published <- snapshot
			},
			OnError: func(err error) { watchErrors <- err },
		})
	}()
	waitSnapshotGeneration(t, published, watchErrors, 1)

	consumer := newConsumer(t, repo, "main")
	updated := make(chan s3disk.RefreshResult, 4)
	pollDone := make(chan error, 1)
	go func() {
		pollDone <- consumer.Poll(ctx, s3disk.PollOptions{
			Interval:       10 * time.Millisecond,
			JitterFraction: -1,
			OnUpdated:      func(result s3disk.RefreshResult) { updated <- result },
		})
	}()
	waitRefreshGeneration(t, updated, 1)

	writeFile(t, filename, []byte("two"))
	waitSnapshotGeneration(t, published, watchErrors, 2)
	waitRefreshGeneration(t, updated, 2)
	if got := string(readFile(t, consumer, "live.txt")); got != "two" {
		t.Fatalf("live read = %q", got)
	}

	cancel()
	if err := <-watchDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("watch stopped with %v", err)
	}
	if err := <-pollDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("poll stopped with %v", err)
	}
}

func TestPublisherWatchSelectedConvergesWithoutExposingSiblings(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "live-selected")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	if err := os.Mkdir(filepath.Join(source, "shared"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(source, "shared", "one.txt"), []byte("one"))
	writeFile(t, filepath.Join(source, "hidden.txt"), []byte("hidden-one"))

	published := make(chan s3disk.Snapshot, 8)
	watchErrors := make(chan error, 8)
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- publisher.WatchSelected(ctx, source, "main", []string{"shared"}, s3disk.WatchOptions{
			Debounce:          10 * time.Millisecond,
			ReconcileInterval: 50 * time.Millisecond,
			OnPublished:       func(snapshot s3disk.Snapshot) { published <- snapshot },
			OnError:           func(err error) { watchErrors <- err },
		})
	}()
	waitSnapshotGeneration(t, published, watchErrors, 1)

	consumer := newConsumer(t, repository, "main")
	if result, err := consumer.Refresh(ctx); err != nil || result.Generation != 1 {
		t.Fatalf("initial selected refresh = %+v, %v", result, err)
	}
	entries, err := consumer.ListDir(ctx, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "shared" || entries[0].Type != s3disk.EntryDir {
		t.Fatalf("selected root entries = %+v, want only shared directory", entries)
	}
	if got := string(readFile(t, consumer, "shared/one.txt")); got != "one" {
		t.Fatalf("initial selected read = %q", got)
	}

	// An unrelated event may wake the watcher, but it must neither enter the
	// projected manifests nor consume a generation by itself.
	writeFile(t, filepath.Join(source, "hidden.txt"), []byte("hidden-two"))
	writeFile(t, filepath.Join(source, "shared", "two.txt"), []byte("two"))
	waitSnapshotGeneration(t, published, watchErrors, 2)
	result, err := consumer.Refresh(ctx)
	if err != nil || result.Generation != 2 {
		t.Fatalf("updated selected refresh = %+v, %v", result, err)
	}
	if got := string(readFile(t, consumer, "shared/two.txt")); got != "two" {
		t.Fatalf("new selected read = %q", got)
	}
	entries, err = consumer.ListDir(ctx, ".")
	if err != nil || len(entries) != 1 || entries[0].Name != "shared" {
		t.Fatalf("updated selected root entries = %+v, %v", entries, err)
	}

	cancel()
	if err := <-watchDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("selected watch stopped with %v", err)
	}
}

func TestPublisherWatchRetriesAfterPublishedForSameGeneration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	repository, err := s3disk.NewRepository(memstore.New(), "watch-after-published-retry")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("unchanged"))

	injected := errors.New("injected acknowledgement failure")
	hookCalls := make(chan s3disk.Snapshot, 4)
	releaseRetry := make(chan struct{})
	published := make(chan s3disk.Snapshot, 2)
	watchErrors := make(chan error, 4)
	watchDone := make(chan error, 1)
	go func() {
		calls := 0
		watchDone <- publisher.Watch(ctx, source, "main", s3disk.WatchOptions{
			Debounce:          time.Millisecond,
			ReconcileInterval: 20 * time.Millisecond,
			AfterPublished: func(hookCtx context.Context, snapshot s3disk.Snapshot) error {
				calls++
				hookCalls <- snapshot
				if calls == 1 {
					return injected
				}
				select {
				case <-releaseRetry:
					return nil
				case <-hookCtx.Done():
					return hookCtx.Err()
				}
			},
			OnPublished: func(snapshot s3disk.Snapshot) { published <- snapshot },
			OnError:     func(err error) { watchErrors <- err },
		})
	}()

	first := waitWatchSnapshot(t, hookCalls, "first AfterPublished call")
	select {
	case err := <-watchErrors:
		if !errors.Is(err, injected) {
			t.Fatalf("watch error = %v, want injected hook error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for AfterPublished failure")
	}
	second := waitWatchSnapshot(t, hookCalls, "retried AfterPublished call")
	if first.Generation != 1 || second.Generation != first.Generation || second.Commit != first.Commit {
		t.Fatalf("hook snapshots = (%+v, %+v), want the same first publication", first, second)
	}
	select {
	case snapshot := <-published:
		t.Fatalf("OnPublished ran before the retried hook succeeded: %+v", snapshot)
	default:
	}
	close(releaseRetry)
	accepted := waitWatchSnapshot(t, published, "OnPublished after hook retry")
	if accepted.Generation != first.Generation || accepted.Commit != first.Commit {
		t.Fatalf("accepted snapshot = %+v, want %+v", accepted, first)
	}

	cancel()
	if err := <-watchDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("watch stopped with %v", err)
	}
}

func TestPublisherWatchCallsOnPublishedOnlyAfterHookReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	repository, err := s3disk.NewRepository(memstore.New(), "watch-after-published-order")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("value"))

	hookStarted := make(chan s3disk.Snapshot, 1)
	releaseHook := make(chan struct{})
	hookReturned := make(chan struct{})
	published := make(chan s3disk.Snapshot, 1)
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- publisher.Watch(ctx, source, "main", s3disk.WatchOptions{
			ReconcileInterval: -1,
			AfterPublished: func(hookCtx context.Context, snapshot s3disk.Snapshot) error {
				hookStarted <- snapshot
				select {
				case <-releaseHook:
					close(hookReturned)
					return nil
				case <-hookCtx.Done():
					return hookCtx.Err()
				}
			},
			OnPublished: func(snapshot s3disk.Snapshot) {
				select {
				case <-hookReturned:
					published <- snapshot
				default:
					panic("OnPublished ran before AfterPublished returned")
				}
			},
		})
	}()

	started := waitWatchSnapshot(t, hookStarted, "AfterPublished start")
	select {
	case snapshot := <-published:
		t.Fatalf("OnPublished ran while AfterPublished was blocked: %+v", snapshot)
	case <-time.After(30 * time.Millisecond):
	}
	close(releaseHook)
	accepted := waitWatchSnapshot(t, published, "ordered OnPublished callback")
	if accepted.Generation != started.Generation || accepted.Commit != started.Commit {
		t.Fatalf("OnPublished snapshot = %+v, want %+v", accepted, started)
	}

	cancel()
	if err := <-watchDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("watch stopped with %v", err)
	}
}

func TestPublisherWatchCancellationReachesAfterPublishedHook(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	repository, err := s3disk.NewRepository(memstore.New(), "watch-after-published-cancel")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("value"))

	hookStarted := make(chan struct{}, 1)
	hookCanceled := make(chan struct{}, 1)
	published := make(chan s3disk.Snapshot, 1)
	watchErrors := make(chan error, 1)
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- publisher.Watch(ctx, source, "main", s3disk.WatchOptions{
			ReconcileInterval: -1,
			AfterPublished: func(hookCtx context.Context, _ s3disk.Snapshot) error {
				hookStarted <- struct{}{}
				<-hookCtx.Done()
				hookCanceled <- struct{}{}
				return hookCtx.Err()
			},
			OnPublished: func(snapshot s3disk.Snapshot) { published <- snapshot },
			OnError:     func(err error) { watchErrors <- err },
		})
	}()

	select {
	case <-hookStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for AfterPublished to start")
	}
	cancel()
	select {
	case <-hookCanceled:
	case <-time.After(5 * time.Second):
		t.Fatal("AfterPublished did not observe watch cancellation")
	}
	if err := <-watchDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("watch stopped with %v", err)
	}
	select {
	case snapshot := <-published:
		t.Fatalf("OnPublished ran after cancellation: %+v", snapshot)
	default:
	}
	select {
	case err := <-watchErrors:
		t.Fatalf("cancellation was reported as a watch error: %v", err)
	default:
	}
}

func TestPublisherWatchWithoutAfterPublishedUsesNormalPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	repository, err := s3disk.NewRepository(memstore.New(), "watch-no-after-published")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("value"))
	published := make(chan s3disk.Snapshot, 1)
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- publisher.Watch(ctx, source, "main", s3disk.WatchOptions{
			ReconcileInterval: -1,
			OnPublished:       func(snapshot s3disk.Snapshot) { published <- snapshot },
		})
	}()
	if snapshot := waitWatchSnapshot(t, published, "ordinary OnPublished callback"); snapshot.Generation != 1 {
		t.Fatalf("ordinary snapshot generation = %d, want 1", snapshot.Generation)
	}
	cancel()
	if err := <-watchDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("watch stopped with %v", err)
	}
}

func TestConsumerPollUsesBoundedExponentialBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := memstore.New()
	store := &hookedStore{base: base}
	store.get = func(context.Context, string, s3disk.GetOptions) (s3disk.Object, error) {
		return s3disk.Object{}, errInjectedNetwork
	}
	repository, err := s3disk.NewRepository(store, "poll-backoff")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	times := make(chan time.Time, 4)
	done := make(chan error, 1)
	failures := 0
	go func() {
		done <- consumer.Poll(ctx, s3disk.PollOptions{
			Interval: 10 * time.Millisecond, MaxInterval: 40 * time.Millisecond,
			BackoffFactor: 2, JitterFraction: -1,
			OnError: func(error) {
				times <- time.Now()
				failures++
				if failures == 4 {
					cancel()
				}
			},
		})
	}()
	observed := make([]time.Time, 0, 4)
	for len(observed) < 4 {
		select {
		case value := <-times:
			observed = append(observed, value)
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for poll failures")
		}
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Poll stopped with %v", err)
	}
	minimumGaps := []time.Duration{5 * time.Millisecond, 12 * time.Millisecond, 25 * time.Millisecond}
	for index, minimum := range minimumGaps {
		if gap := observed[index+1].Sub(observed[index]); gap < minimum {
			t.Fatalf("poll gap %d = %v, want at least %v", index, gap, minimum)
		}
	}
}

func TestPollCallbackPanicIsReportedAndContained(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "poll-callback")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("value"))
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	reported := make(chan error, 1)
	err = consumer.Poll(ctx, s3disk.PollOptions{
		Interval: time.Second, JitterFraction: -1,
		OnUpdated: func(s3disk.RefreshResult) { panic("callback failure") },
		OnError: func(err error) {
			reported <- err
			cancel()
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Poll error = %v, want context cancellation", err)
	}
	select {
	case err := <-reported:
		if err == nil {
			t.Fatal("callback panic was reported as nil")
		}
	default:
		t.Fatal("OnUpdated panic was not reported to OnError")
	}
}

func TestPollOnResultNotifiesBothPollersWhenOneAdopts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "poll-shared-consumer")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("value"))
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}

	results := [2]chan s3disk.RefreshResult{make(chan s3disk.RefreshResult, 1), make(chan s3disk.RefreshResult, 1)}
	updates := make(chan int, 2)
	done := [2]chan error{make(chan error, 1), make(chan error, 1)}
	for index := range done {
		index := index
		go func() {
			done[index] <- consumer.Poll(ctx, s3disk.PollOptions{
				Interval: 5 * time.Millisecond, JitterFraction: -1,
				OnResult: func(result s3disk.RefreshResult) {
					if result.Generation >= 1 {
						select {
						case results[index] <- result:
						default:
						}
					}
				},
				OnUpdated: func(s3disk.RefreshResult) { updates <- index },
			})
		}()
	}

	first := waitPollResult(t, results[0])
	second := waitPollResult(t, results[1])
	if first.Generation != 1 || second.Generation != 1 {
		t.Fatalf("poller results = (%+v, %+v), want generation one for both", first, second)
	}
	cancel()
	for index := range done {
		if err := <-done[index]; !errors.Is(err, context.Canceled) {
			t.Fatalf("poller %d stopped with %v", index, err)
		}
	}
	close(updates)
	updatedCount := 0
	for range updates {
		updatedCount++
	}
	if updatedCount != 1 {
		t.Fatalf("OnUpdated calls = %d, want exactly the adopting poller", updatedCount)
	}
}

func TestPollOnResultSeesSnapshotAdoptedByExternalRefresh(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "poll-external-refresh")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("value"))
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := consumer.Refresh(ctx); err != nil || result.Status != s3disk.RefreshUpdated {
		t.Fatalf("external Refresh = %+v, %v", result, err)
	}

	results := make(chan s3disk.RefreshResult, 1)
	updated := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- consumer.Poll(ctx, s3disk.PollOptions{
			Interval: time.Second, JitterFraction: -1,
			OnResult: func(result s3disk.RefreshResult) {
				results <- result
				cancel()
			},
			OnUpdated: func(s3disk.RefreshResult) { updated <- struct{}{} },
		})
	}()
	result := waitPollResult(t, results)
	if result.Status != s3disk.RefreshUnchanged || result.Generation != 1 {
		t.Fatalf("poll result after external adoption = %+v, want unchanged generation one", result)
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Poll stopped with %v", err)
	}
	select {
	case <-updated:
		t.Fatal("OnUpdated ran for a snapshot adopted by external Refresh")
	default:
	}
}

func TestPollOnResultPanicIsReportedAndContained(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	repository, err := s3disk.NewRepository(memstore.New(), "poll-result-panic")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	reported := make(chan error, 1)
	err = consumer.Poll(ctx, s3disk.PollOptions{
		Interval: time.Second, JitterFraction: -1,
		OnResult: func(s3disk.RefreshResult) { panic("result callback failure") },
		OnError: func(err error) {
			reported <- err
			cancel()
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Poll error = %v, want context cancellation", err)
	}
	select {
	case err := <-reported:
		if err == nil {
			t.Fatal("OnResult panic was reported as nil")
		}
	default:
		t.Fatal("OnResult panic was not reported to OnError")
	}
}

func waitPollResult(t *testing.T, results <-chan s3disk.RefreshResult) s3disk.RefreshResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for poll result")
		return s3disk.RefreshResult{}
	}
}

func waitSnapshotGeneration(t *testing.T, snapshots <-chan s3disk.Snapshot, errs <-chan error, generation uint64) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case snapshot := <-snapshots:
			if snapshot.Generation >= generation {
				return
			}
		case err := <-errs:
			t.Fatalf("watch error: %v", err)
		case <-deadline.C:
			t.Fatalf("timed out waiting for published generation %d", generation)
		}
	}
}

func waitWatchSnapshot(t *testing.T, snapshots <-chan s3disk.Snapshot, operation string) s3disk.Snapshot {
	t.Helper()
	select {
	case snapshot := <-snapshots:
		return snapshot
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", operation)
		return s3disk.Snapshot{}
	}
}

func waitRefreshGeneration(t *testing.T, updates <-chan s3disk.RefreshResult, generation uint64) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case update := <-updates:
			if update.Generation >= generation {
				return
			}
		case <-deadline.C:
			t.Fatalf("timed out waiting for adopted generation %d", generation)
		}
	}
}
