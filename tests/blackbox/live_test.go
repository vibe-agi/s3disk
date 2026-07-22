package s3disk_test

import (
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
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
	publisher, err := s3disk.NewPublisher(repo, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
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

func TestPublisherWatchReinstallsRecreatedDirectoryWatch(t *testing.T) {
	for _, operation := range []string{"remove", "rename"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			repository, err := s3disk.NewRepository(memstore.New(), "watch-recreated-directory-"+operation)
			if err != nil {
				t.Fatal(err)
			}
			publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
				DangerouslyAllowUncommissionedRepository: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			source := privateTestDirectory(t)
			nested := filepath.Join(source, "nested")
			if err := os.Mkdir(nested, 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(nested, "data"), []byte("initial"))

			published := make(chan s3disk.Snapshot, 16)
			watchErrors := make(chan error, 16)
			watchDone := make(chan error, 1)
			go func() {
				watchDone <- publisher.Watch(ctx, source, "main", s3disk.WatchOptions{
					Debounce:          10 * time.Millisecond,
					ReconcileInterval: -1,
					OnPublished:       func(snapshot s3disk.Snapshot) { published <- snapshot },
					OnError:           func(err error) { watchErrors <- err },
				})
			}()
			waitSnapshotGeneration(t, published, watchErrors, 1)
			consumer := newConsumer(t, repository, "main")

			switch operation {
			case "remove":
				if err := retryPermissionDenied(func() error { return os.RemoveAll(nested) }); err != nil {
					t.Fatal(err)
				}
			case "rename":
				moved := filepath.Join(privateTestDirectory(t), "moved")
				if err := retryPermissionDenied(func() error { return os.Rename(nested, moved) }); err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatalf("unknown operation %q", operation)
			}
			waitSnapshotGeneration(t, published, watchErrors, 2)

			// Recreating the empty directory is observed by its watched parent and
			// must reinstall the nested watch, even though the path is unchanged.
			if err := os.Mkdir(nested, 0o700); err != nil {
				t.Fatal(err)
			}
			waitSnapshotGeneration(t, published, watchErrors, 3)

			// These changes are visible only through the reinstalled nested watch;
			// periodic reconciliation is deliberately disabled for this test.
			filename := filepath.Join(nested, "data")
			staged := filepath.Join(privateTestDirectory(t), "created")
			writeFile(t, staged, []byte("created"))
			if err := os.Rename(staged, filename); err != nil {
				t.Fatal(err)
			}
			waitSnapshotFileContent(t, published, watchErrors, consumer, 4, "nested/data", "created")
			staged = filepath.Join(privateTestDirectory(t), "modified")
			writeFile(t, staged, []byte("modified after recreation"))
			if err := os.Remove(filename); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(staged, filename); err != nil {
				t.Fatal(err)
			}
			waitSnapshotFileContent(
				t, published, watchErrors, consumer, 5, "nested/data", "modified after recreation",
			)

			cancel()
			if err := <-watchDone; !errors.Is(err, context.Canceled) {
				t.Fatalf("watch stopped with %v", err)
			}
		})
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
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
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
	result := waitSnapshotFileContent(
		t, published, watchErrors, consumer, 2, "shared/two.txt", "two",
	)
	if result.Generation < 2 {
		t.Fatalf("updated selected refresh = %+v, want generation at least 2", result)
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
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("unchanged"))

	type hookObservation struct {
		snapshot s3disk.Snapshot
		at       time.Time
	}
	injected := errors.New("injected acknowledgement failure")
	hookCalls := make(chan hookObservation, 4)
	releaseRetry := make(chan struct{})
	published := make(chan s3disk.Snapshot, 2)
	watchErrors := make(chan error, 4)
	watchDone := make(chan error, 1)
	go func() {
		calls := 0
		watchDone <- publisher.Watch(ctx, source, "main", s3disk.WatchOptions{
			Debounce: time.Millisecond,
			// Continuously refill publication requests while generation 1 is
			// pending. A ready retry timer must still win without allowing a
			// later source state to cross the acknowledgement barrier.
			ReconcileInterval:                 time.Millisecond,
			AfterPublishedRetryInterval:       40 * time.Millisecond,
			AfterPublishedRetryMaxInterval:    40 * time.Millisecond,
			AfterPublishedRetryJitterFraction: -1,
			AfterPublished: func(hookCtx context.Context, snapshot s3disk.Snapshot) error {
				calls++
				hookCalls <- hookObservation{snapshot: snapshot, at: time.Now()}
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

	waitHook := func(label string) hookObservation {
		t.Helper()
		select {
		case observation := <-hookCalls:
			return observation
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for %s", label)
			return hookObservation{}
		}
	}
	firstCall := waitHook("first AfterPublished call")
	first := firstCall.snapshot
	select {
	case err := <-watchErrors:
		if !errors.Is(err, injected) {
			t.Fatalf("watch error = %v, want injected hook error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for AfterPublished failure")
	}
	// A newer source state must remain behind the failed hook barrier. In the
	// root-share composition this prevents publication N+1 from overtaking a
	// durable root-WAL Pending(N).
	writeFile(t, filepath.Join(source, "data"), []byte("changed behind failed hook"))
	secondCall := waitHook("retried AfterPublished call")
	second := secondCall.snapshot
	if gap := secondCall.at.Sub(firstCall.at); gap < 20*time.Millisecond {
		t.Fatalf("filesystem event bypassed AfterPublished retry backoff: gap=%v", gap)
	}
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
	advanced := waitHook("AfterPublished for accumulated source change").snapshot
	if advanced.Generation != first.Generation+1 || advanced.Commit == first.Commit {
		t.Fatalf("advanced hook snapshot = %+v, want generation %d after %+v", advanced, first.Generation+1, first)
	}
	advancedAccepted := waitWatchSnapshot(t, published, "OnPublished for accumulated source change")
	if advancedAccepted.Generation != advanced.Generation || advancedAccepted.Commit != advanced.Commit {
		t.Fatalf("advanced accepted snapshot = %+v, want %+v", advancedAccepted, advanced)
	}
	consumer := newConsumer(t, repository, "main")
	if result, err := consumer.Refresh(ctx); err != nil || result.Generation != advanced.Generation {
		t.Fatalf("refresh accumulated source change = %+v, %v", result, err)
	}
	if got := string(readFile(t, consumer, "data")); got != "changed behind failed hook" {
		t.Fatalf("accumulated source content = %q", got)
	}

	cancel()
	if err := <-watchDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("watch stopped with %v", err)
	}
}

func TestPublisherWatchRetriesAfterPublishedIndependentlyWithBoundedBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	repository, err := s3disk.NewRepository(memstore.New(), "watch-after-published-independent-retry")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("no filesystem event after initial publish"))

	type hookObservation struct {
		snapshot s3disk.Snapshot
		at       time.Time
	}
	injected := errors.New("injected independent acknowledgement failure")
	hookCalls := make(chan hookObservation, 5)
	published := make(chan s3disk.Snapshot, 1)
	watchErrors := make(chan error, 5)
	watchDone := make(chan error, 1)
	go func() {
		calls := 0
		watchDone <- publisher.Watch(ctx, source, "main", s3disk.WatchOptions{
			ReconcileInterval:                 -1,
			AfterPublishedRetryInterval:       15 * time.Millisecond,
			AfterPublishedRetryMaxInterval:    60 * time.Millisecond,
			AfterPublishedRetryBackoffFactor:  2,
			AfterPublishedRetryJitterFraction: -1,
			AfterPublished: func(_ context.Context, snapshot s3disk.Snapshot) error {
				calls++
				hookCalls <- hookObservation{snapshot: snapshot, at: time.Now()}
				if calls <= 4 {
					return injected
				}
				return nil
			},
			OnPublished: func(snapshot s3disk.Snapshot) { published <- snapshot },
			OnError:     func(err error) { watchErrors <- err },
		})
	}()

	observed := make([]hookObservation, 0, 5)
	for len(observed) < 5 {
		select {
		case call := <-hookCalls:
			observed = append(observed, call)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for independent AfterPublished retries")
		}
	}
	first := observed[0].snapshot
	for index, call := range observed {
		if call.snapshot.Generation != first.Generation || call.snapshot.Commit != first.Commit {
			t.Fatalf("hook call %d snapshot = %+v, want exact %+v", index, call.snapshot, first)
		}
	}
	minimumGaps := []time.Duration{7 * time.Millisecond, 18 * time.Millisecond, 40 * time.Millisecond, 40 * time.Millisecond}
	for index, minimum := range minimumGaps {
		if gap := observed[index+1].at.Sub(observed[index].at); gap < minimum {
			t.Fatalf("independent retry gap %d = %v, want at least %v", index, gap, minimum)
		}
	}
	for index := 0; index < 4; index++ {
		select {
		case err := <-watchErrors:
			if !errors.Is(err, injected) {
				t.Fatalf("watch error %d = %v, want injected hook error", index, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for watch error %d", index)
		}
	}
	accepted := waitWatchSnapshot(t, published, "OnPublished after independent retry")
	if accepted.Generation != first.Generation || accepted.Commit != first.Commit {
		t.Fatalf("accepted snapshot = %+v, want %+v", accepted, first)
	}

	cancel()
	if err := <-watchDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("watch stopped with %v", err)
	}
}

func TestPublisherWatchRetriesPanickingAfterPublishedBeforeAcknowledgement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	repository, err := s3disk.NewRepository(memstore.New(), "watch-after-published-panic-retry")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("retry a panicking hook"))

	type callbackEvent struct {
		kind     string
		snapshot s3disk.Snapshot
		err      error
	}
	hookCalls := make(chan s3disk.Snapshot, 2)
	callbacks := make(chan callbackEvent, 2)
	watchDone := make(chan error, 1)
	go func() {
		calls := 0
		watchDone <- publisher.Watch(ctx, source, "main", s3disk.WatchOptions{
			ReconcileInterval:                 -1,
			AfterPublishedRetryInterval:       20 * time.Millisecond,
			AfterPublishedRetryMaxInterval:    20 * time.Millisecond,
			AfterPublishedRetryJitterFraction: -1,
			AfterPublished: func(_ context.Context, snapshot s3disk.Snapshot) error {
				calls++
				hookCalls <- snapshot
				if calls == 1 {
					panic("injected hook panic")
				}
				return nil
			},
			OnError: func(err error) { callbacks <- callbackEvent{kind: "error", err: err} },
			OnPublished: func(snapshot s3disk.Snapshot) {
				callbacks <- callbackEvent{kind: "published", snapshot: snapshot}
			},
		})
	}()

	hooks := make([]s3disk.Snapshot, 0, 2)
	for len(hooks) < 2 {
		select {
		case snapshot := <-hookCalls:
			hooks = append(hooks, snapshot)
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for hook call %d", len(hooks))
		}
	}
	observedCallbacks := make([]callbackEvent, 0, 2)
	for len(observedCallbacks) < 2 {
		select {
		case event := <-callbacks:
			observedCallbacks = append(observedCallbacks, event)
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for callback event %d", len(observedCallbacks))
		}
	}
	if observedCallbacks[0].kind != "error" || observedCallbacks[1].kind != "published" {
		t.Fatalf("callback order = %+v, want error then published", observedCallbacks)
	}
	if observedCallbacks[0].err == nil || !strings.Contains(observedCallbacks[0].err.Error(), "AfterPublished hook panic") {
		t.Fatalf("panic callback error = %v", observedCallbacks[0].err)
	}
	first, retried, published := hooks[0], hooks[1], observedCallbacks[1].snapshot
	if first.Generation != 1 || retried.Generation != first.Generation || retried.Commit != first.Commit ||
		published.Generation != first.Generation || published.Commit != first.Commit {
		t.Fatalf("panic retry snapshots = first %+v, retried %+v, published %+v", first, retried, published)
	}

	cancel()
	if err := <-watchDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("watch stopped with %v", err)
	}
}

func TestPublisherWatchReportsHookContextCanceledWhileWatchIsActive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	repository, err := s3disk.NewRepository(memstore.New(), "watch-hook-canceled-error")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("hook-local cancellation"))

	hookCalls := make(chan s3disk.Snapshot, 3)
	watchErrors := make(chan error, 2)
	published := make(chan s3disk.Snapshot, 1)
	watchDone := make(chan error, 1)
	go func() {
		calls := 0
		watchDone <- publisher.Watch(ctx, source, "main", s3disk.WatchOptions{
			ReconcileInterval:                 -1,
			AfterPublishedRetryInterval:       10 * time.Millisecond,
			AfterPublishedRetryMaxInterval:    10 * time.Millisecond,
			AfterPublishedRetryJitterFraction: -1,
			AfterPublished: func(_ context.Context, snapshot s3disk.Snapshot) error {
				calls++
				hookCalls <- snapshot
				if calls <= 2 {
					return context.Canceled
				}
				return nil
			},
			OnError:     func(err error) { watchErrors <- err },
			OnPublished: func(snapshot s3disk.Snapshot) { published <- snapshot },
		})
	}()

	observed := make([]s3disk.Snapshot, 0, 3)
	for len(observed) < 3 {
		observed = append(observed, waitWatchSnapshot(t, hookCalls, "canceled hook retry"))
	}
	for index := 0; index < 2; index++ {
		select {
		case err := <-watchErrors:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("hook error %d = %v, want context.Canceled", index, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for hook error %d", index)
		}
	}
	accepted := waitWatchSnapshot(t, published, "publication after canceled hook retries")
	for index, snapshot := range observed {
		if snapshot.Generation != accepted.Generation || snapshot.Commit != accepted.Commit {
			t.Fatalf("hook snapshot %d = %+v, want accepted %+v", index, snapshot, accepted)
		}
	}

	cancel()
	if err := <-watchDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("watch stopped with %v", err)
	}
}

func TestPublisherWatchCancellationStopsAfterPublishedRetryTimer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	repository, err := s3disk.NewRepository(memstore.New(), "watch-after-published-retry-cancel")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("cancel during retry delay"))

	injected := errors.New("injected retry before cancellation")
	hookCalls := make(chan struct{}, 2)
	watchErrors := make(chan error, 1)
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- publisher.Watch(ctx, source, "main", s3disk.WatchOptions{
			ReconcileInterval:                 -1,
			AfterPublishedRetryInterval:       time.Hour,
			AfterPublishedRetryMaxInterval:    time.Hour,
			AfterPublishedRetryJitterFraction: -1,
			AfterPublished: func(context.Context, s3disk.Snapshot) error {
				hookCalls <- struct{}{}
				return injected
			},
			OnError: func(err error) { watchErrors <- err },
		})
	}()
	select {
	case <-hookCalls:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for initial AfterPublished failure")
	}
	select {
	case err := <-watchErrors:
		if !errors.Is(err, injected) {
			t.Fatalf("watch error = %v, want injected failure", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for initial watch error")
	}
	cancel()
	select {
	case err := <-watchDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("watch stopped with %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not stop while an AfterPublished retry timer was pending")
	}
	select {
	case <-hookCalls:
		t.Fatal("AfterPublished retried after watch cancellation")
	default:
	}
}

func TestWatchOptionsValidateAfterPublishedRetryPolicy(t *testing.T) {
	valid := []s3disk.WatchOptions{
		{},
		{ReconcileInterval: -1},
		{AfterPublishedRetryJitterFraction: -1},
		{AfterPublishedRetryBackoffFactor: 1},
		{
			AfterPublishedRetryInterval:       time.Millisecond,
			AfterPublishedRetryMaxInterval:    time.Second,
			AfterPublishedRetryBackoffFactor:  10,
			AfterPublishedRetryJitterFraction: 1,
		},
	}
	for index, options := range valid {
		if err := options.Validate(); err != nil {
			t.Fatalf("valid options %d: %v", index, err)
		}
	}
	invalid := []s3disk.WatchOptions{
		{Debounce: -1},
		{AfterPublishedRetryInterval: -1},
		{AfterPublishedRetryInterval: time.Second, AfterPublishedRetryMaxInterval: time.Millisecond},
		{AfterPublishedRetryBackoffFactor: math.NaN()},
		{AfterPublishedRetryBackoffFactor: math.Inf(1)},
		{AfterPublishedRetryBackoffFactor: 0.5},
		{AfterPublishedRetryBackoffFactor: 11},
		{AfterPublishedRetryJitterFraction: math.NaN()},
		{AfterPublishedRetryJitterFraction: math.Inf(-1)},
		{AfterPublishedRetryJitterFraction: 1.01},
	}
	for index, options := range invalid {
		if err := options.Validate(); err == nil {
			t.Fatalf("invalid options %d were accepted: %+v", index, options)
		}
	}
}

func TestPublisherWatchCallsOnPublishedOnlyAfterHookReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	repository, err := s3disk.NewRepository(memstore.New(), "watch-after-published-order")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
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
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
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
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
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
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
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
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
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
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
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
			// A scan racing the deliberate test mutation must fail closed and
			// report ErrUnstableFile. Watch is expected to reconcile again; the
			// deadline below still proves that it eventually converges.
			if errors.Is(err, s3disk.ErrUnstableFile) {
				continue
			}
			t.Fatalf("watch error: %v", err)
		case <-deadline.C:
			t.Fatalf("timed out waiting for published generation %d", generation)
		}
	}
}

// retryPermissionDenied tolerates the bounded handoff window in which Windows
// is completing an asynchronous ReadDirectoryChangesW request and temporarily
// rejects removal or rename of the watched directory. A persistent sharing or
// handle leak still fails the test after the deadline.
func retryPermissionDenied(operation func() error) error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := operation()
		if err == nil || !errors.Is(err, os.ErrPermission) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitSnapshotFileContent(
	t *testing.T,
	snapshots <-chan s3disk.Snapshot,
	errs <-chan error,
	consumer *s3disk.Consumer,
	generation uint64,
	name, want string,
) s3disk.RefreshResult {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		select {
		case snapshot := <-snapshots:
			if snapshot.Generation < generation {
				continue
			}
			result, err := consumer.Refresh(waitCtx)
			if err != nil {
				t.Fatalf("refresh generation %d: %v", snapshot.Generation, err)
			}
			entry, err := consumer.Stat(waitCtx, name)
			if errors.Is(err, s3disk.ErrPathNotFound) {
				continue
			}
			if err != nil {
				t.Fatalf("stat converging file %q: %v", name, err)
			}
			if entry.Size != int64(len(want)) {
				continue
			}
			file, err := consumer.Open(waitCtx, name)
			if err != nil {
				t.Fatalf("open converging file %q: %v", name, err)
			}
			data := make([]byte, len(want))
			if _, err := file.ReadAtContext(waitCtx, data, 0); err != nil && !errors.Is(err, io.EOF) {
				t.Fatalf("read converging file %q: %v", name, err)
			}
			if string(data) == want {
				return result
			}
		case err := <-errs:
			if errors.Is(err, s3disk.ErrUnstableFile) {
				continue
			}
			t.Fatalf("watch error while awaiting %q: %v", name, err)
		case <-waitCtx.Done():
			t.Fatalf("timed out waiting for %q to converge to %q", name, want)
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
