package s3disk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

const maxWatchDirectories = 100_000

// WatchOptions controls Publisher.Watch.
type WatchOptions struct {
	Debounce          time.Duration
	ReconcileInterval time.Duration
	// AfterPublished is called synchronously after the repository publication
	// succeeds, but before Watch accepts that generation and calls OnPublished.
	// Returning an error rejects only the watch acknowledgement: the repository
	// publication remains committed, OnError reports the failure, and a later
	// reconciliation retries AfterPublished for the same generation.
	//
	// AfterPublished runs in the publication worker while OnPublished and OnError
	// run in the watch loop. A later generation's hook can therefore overlap an
	// earlier callback. All callbacks must be concurrency-safe and return promptly;
	// a blocking callback delays Watch shutdown. AfterPublished must also honor ctx.
	AfterPublished func(ctx context.Context, snapshot Snapshot) error
	OnPublished    func(Snapshot)
	OnError        func(error)
}

// Watch recursively observes a source tree, coalesces bursts, and publishes
// snapshots. Filesystem events reduce latency; a periodic full reconciliation
// is always the correctness fallback unless ReconcileInterval is negative.
func (publisher *Publisher) Watch(ctx context.Context, source, channel string, options WatchOptions) error {
	return publisher.watch(ctx, source, channel, options, func(workerCtx context.Context) (Snapshot, error) {
		return publisher.Publish(workerCtx, source, channel)
	})
}

// WatchSelected recursively observes source but publishes only the exact
// projection described by paths. A selected directory includes its changing
// subtree; a selected file or symlink includes only that node and its
// ancestors. Events elsewhere may prompt a reconciliation, but PublishSelected
// keeps the reference generation unchanged when the selected projection did
// not change.
//
// The selection is validated and compiled before any watcher is created.
func (publisher *Publisher) WatchSelected(
	ctx context.Context,
	source, channel string,
	paths []string,
	options WatchOptions,
) error {
	selection, err := newPathSelectionContext(ctx, paths)
	if err != nil {
		return err
	}
	return publisher.watch(ctx, source, channel, options, func(workerCtx context.Context) (Snapshot, error) {
		staged, err := publisher.stage(workerCtx, source, channel, selection)
		if err != nil {
			return Snapshot{}, err
		}
		return publisher.Commit(workerCtx, staged)
	})
}

func (publisher *Publisher) watch(
	ctx context.Context,
	source, channel string,
	options WatchOptions,
	publish func(context.Context) (Snapshot, error),
) error {
	if ctx == nil {
		return fmt.Errorf("s3disk: watch context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := publisher.repository.validateChannel(channel); err != nil {
		return err
	}
	if publish == nil {
		return fmt.Errorf("s3disk: watch publisher is not configured")
	}
	if options.Debounce == 0 {
		options.Debounce = 250 * time.Millisecond
	}
	if options.Debounce < 0 {
		return fmt.Errorf("s3disk: debounce must not be negative")
	}
	if options.ReconcileInterval == 0 {
		options.ReconcileInterval = 5 * time.Minute
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create filesystem watcher: %w", err)
	}
	defer func() { _ = watcher.Close() }()
	watchTree := newBoundedWatchTree(watcher)
	if err := watchTree.Add(ctx, source); err != nil {
		return err
	}

	type publishResult struct {
		snapshot  Snapshot
		err       error
		reconcile bool
	}
	requests := make(chan struct{}, 1)
	results := make(chan publishResult, 1)
	workerDone := make(chan struct{})
	workerCtx, cancelWorker := context.WithCancel(ctx)
	go func() {
		defer close(workerDone)
		var lastAcknowledged uint64
		var pendingAfterPublished *Snapshot
		for {
			select {
			case <-workerCtx.Done():
				return
			case _, ok := <-requests:
				if !ok {
					return
				}
				// A repository generation which has not passed AfterPublished is
				// a publication barrier. Retry that exact snapshot before scanning
				// and committing a later generation; otherwise a root recovery WAL
				// can retain Pending(N) while the repository advances to N+1.
				if pendingAfterPublished != nil {
					snapshot := *pendingAfterPublished
					err := invokeWatchAfterPublished(workerCtx, options, snapshot)
					reconcile := false
					if err == nil {
						lastAcknowledged = snapshot.Generation
						pendingAfterPublished = nil
						// Reconcile source changes which accumulated behind the
						// barrier without requiring another filesystem event. The
						// watch loop remains the only requests sender.
						reconcile = true
					}
					select {
					case results <- publishResult{snapshot: snapshot, err: err, reconcile: reconcile}:
					case <-workerCtx.Done():
						return
					}
					continue
				}
				snapshot, err := publish(workerCtx)
				if err == nil && snapshot.Generation > lastAcknowledged {
					err = invokeWatchAfterPublished(workerCtx, options, snapshot)
					if err == nil {
						lastAcknowledged = snapshot.Generation
					} else {
						pending := snapshot
						pendingAfterPublished = &pending
					}
				}
				select {
				case results <- publishResult{snapshot: snapshot, err: err}:
				case <-workerCtx.Done():
					return
				}
			}
		}
	}()
	defer func() {
		// Watch can stop because the fsnotify channels failed while the caller's
		// context remains live. Cancel the in-flight publication before waiting,
		// otherwise a blocked store operation could make this return hang forever.
		// requests is intentionally not closed. Cancellation is the sole worker
		// shutdown signal, so no receiver can race with channel teardown.
		cancelWorker()
		<-workerDone
	}()

	requestPublish := func() {
		select {
		case requests <- struct{}{}:
		default:
		}
	}
	requestPublish()

	debounce := time.NewTimer(time.Hour)
	if !debounce.Stop() {
		<-debounce.C
	}
	var debounceChannel <-chan time.Time
	resetDebounce := func() {
		if !debounce.Stop() && debounceChannel != nil {
			select {
			case <-debounce.C:
			default:
			}
		}
		debounce.Reset(options.Debounce)
		debounceChannel = debounce.C
	}
	defer debounce.Stop()

	var reconcileChannel <-chan time.Time
	var reconcile *time.Ticker
	if options.ReconcileInterval > 0 {
		reconcile = time.NewTicker(options.ReconcileInterval)
		reconcileChannel = reconcile.C
		defer reconcile.Stop()
	}
	var lastPublished uint64
	watchEvents := watcher.Events
	watchErrors := watcher.Errors
	rebuildWatchTree := func() error {
		replacement, err := fsnotify.NewWatcher()
		if err != nil {
			return fmt.Errorf("recreate filesystem watcher: %w", err)
		}
		replacementTree := newBoundedWatchTree(replacement)
		if err := replacementTree.Add(ctx, source); err != nil {
			_ = replacement.Close()
			return fmt.Errorf("rebuild filesystem watch tree: %w", err)
		}

		previous := watcher
		watcher = replacement
		watchTree = replacementTree
		watchEvents = replacement.Events
		watchErrors = replacement.Errors
		if err := previous.Close(); err != nil && !errors.Is(err, fsnotify.ErrClosed) {
			return fmt.Errorf("close replaced filesystem watcher: %w", err)
		}
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-watchEvents:
			if !ok {
				return fmt.Errorf("s3disk: filesystem watcher closed")
			}
			if event.Op&(fsnotify.Remove|fsnotify.Rename) != 0 && watchTree.Contains(event.Name) {
				// kqueue and similar backends can retain internal child state after
				// the user-visible directory watch is removed. Rebuild the complete
				// watcher before a same-path incarnation can inherit stale entries.
				if rebuildErr := rebuildWatchTree(); rebuildErr == nil {
					resetDebounce()
					continue
				} else {
					reportWatchError(options, rebuildErr)
				}
			}
			if event.Op&(fsnotify.Create|fsnotify.Remove|fsnotify.Rename) != 0 {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return ctxErr
				}
				info, statErr := os.Lstat(event.Name)
				realDirectory := statErr == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
				if event.Op&(fsnotify.Remove|fsnotify.Rename) != 0 && !realDirectory {
					if removeErr := watchTree.Remove(event.Name); removeErr != nil {
						reportWatchError(options, removeErr)
					}
				}
				if realDirectory {
					if addErr := watchTree.Add(ctx, event.Name); addErr != nil {
						reportWatchError(options, addErr)
					}
				}
			}
			resetDebounce()
		case err, ok := <-watchErrors:
			if !ok {
				// A permanently-ready closed channel would otherwise spin and starve
				// filesystem events until the Events channel also closes.
				watchErrors = nil
				continue
			}
			reportWatchError(options, fmt.Errorf("filesystem watcher: %w", err))
			// Overflow and transient watcher failures are repaired by a full
			// reconciliation rather than trusted as authoritative state.
			requestPublish()
		case <-debounceChannel:
			debounceChannel = nil
			requestPublish()
		case <-reconcileChannel:
			requestPublish()
		case result := <-results:
			// A completed publication can race with caller cancellation. Do not
			// acknowledge it or invoke user callbacks after the watch lifetime ends.
			if err := ctx.Err(); err != nil {
				return err
			}
			if result.err != nil {
				reportWatchError(options, result.err)
				continue
			}
			if result.snapshot.Generation > lastPublished {
				lastPublished = result.snapshot.Generation
				invokeWatchPublished(options, result.snapshot)
			}
			if result.reconcile {
				requestPublish()
			}
		}
	}
}

type boundedWatchTree struct {
	watcher *fsnotify.Watcher
	paths   map[string]os.FileInfo
}

func newBoundedWatchTree(watcher *fsnotify.Watcher) *boundedWatchTree {
	return &boundedWatchTree{watcher: watcher, paths: make(map[string]os.FileInfo)}
}

func (tree *boundedWatchTree) Contains(watchPath string) bool {
	_, exists := tree.paths[filepath.Clean(watchPath)]
	return exists
}

// Add recursively registers a tree while materializing only bounded child
// directory descriptors. It also refuses symlinks and applies the same path,
// depth, and per-directory entry bounds as the publication protocol.
func (tree *boundedWatchTree) Add(ctx context.Context, rootPath string) error {
	if ctx == nil {
		return fmt.Errorf("s3disk: watch-tree context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	absolute, err := filepath.Abs(rootPath)
	if err != nil {
		return fmt.Errorf("resolve watch root: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	rootInfo, err := os.Lstat(absolute)
	if err != nil {
		return fmt.Errorf("inspect watch root %q: %w", absolute, err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: watch root is not a real directory", ErrNotDirectory)
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return fmt.Errorf("open traversal-safe watch root: %w", err)
	}
	defer root.Close()

	revalidate := func(relative string, expected os.FileInfo) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		handle, openErr := root.Open(relative)
		if openErr != nil {
			return fmt.Errorf("%w: reopen watched directory %q: %v", ErrUnstableFile, relative, openErr)
		}
		after, statErr := handle.Stat()
		closeErr := handle.Close()
		current, currentErr := root.Lstat(relative)
		if statErr != nil || closeErr != nil || currentErr != nil ||
			!after.IsDir() || !current.IsDir() ||
			!os.SameFile(expected, after) || !os.SameFile(after, current) ||
			!stableFileInfo(expected, after) || !stableFileInfo(after, current) {
			return fmt.Errorf("%w: watched directory changed during scan: %q", ErrUnstableFile, relative)
		}
		return nil
	}

	var walk func(string, os.FileInfo, int) error
	walk = func(relative string, expected os.FileInfo, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > maxLookupDepth || len(relative) > maxLookupPathBytes {
			return fmt.Errorf("%w: watch path exceeds protocol depth or length", ErrResourceLimit)
		}
		handle, err := root.Open(relative)
		if err != nil {
			return fmt.Errorf("open watched directory %q: %w", relative, err)
		}
		handleOpen := true
		defer func() {
			if handleOpen {
				_ = handle.Close()
			}
		}()
		before, err := handle.Stat()
		if err != nil || !before.IsDir() || !os.SameFile(expected, before) || !stableFileInfo(expected, before) {
			return fmt.Errorf("%w: watched directory changed before scan: %q", ErrUnstableFile, relative)
		}
		absoluteDirectory := absolute
		if relative != "." {
			absoluteDirectory = filepath.Join(absolute, filepath.FromSlash(relative))
		}
		if err := tree.addOne(absoluteDirectory, before); err != nil {
			return err
		}

		type childDirectory struct {
			relative string
			info     os.FileInfo
		}
		children := make([]childDirectory, 0)
		entriesSeen := 0
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			batch, readErr := handle.ReadDir(256)
			entriesSeen += len(batch)
			if entriesSeen > maxDirectoryEntries {
				return fmt.Errorf("%w: watched directory %q exceeds %d entries", ErrResourceLimit, relative, maxDirectoryEntries)
			}
			for _, entry := range batch {
				if err := ctx.Err(); err != nil {
					return err
				}
				name := entry.Name()
				if len(name) == 0 || len(name) > maxEntryNameBytes {
					return fmt.Errorf("%w: invalid watched entry name in %q", ErrResourceLimit, relative)
				}
				if depth >= maxLookupDepth {
					return fmt.Errorf("%w: watched path exceeds %d components", ErrResourceLimit, maxLookupDepth)
				}
				child := path.Join(relative, name)
				if len(child) > maxLookupPathBytes {
					return fmt.Errorf("%w: watched path exceeds %d bytes", ErrResourceLimit, maxLookupPathBytes)
				}
				info, statErr := root.Lstat(child)
				if statErr != nil {
					return fmt.Errorf("inspect watched entry %q: %w", child, statErr)
				}
				if info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
					if len(children) >= maxWatchDirectories {
						return fmt.Errorf("%w: source requires more than %d watched directories", ErrResourceLimit, maxWatchDirectories)
					}
					children = append(children, childDirectory{relative: child, info: info})
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				return fmt.Errorf("read watched directory %q: %w", relative, readErr)
			}
		}
		// Do not retain a descriptor for every ancestor. Each child verifies the
		// identity observed above, and the parent is reopened after each child
		// returns so replacement or metadata changes still fail closed.
		if err := handle.Close(); err != nil {
			return fmt.Errorf("close watched directory %q after scan: %w", relative, err)
		}
		handleOpen = false
		if len(children) == 0 {
			return revalidate(relative, before)
		}
		for _, child := range children {
			if err := walk(child.relative, child.info, depth+1); err != nil {
				return err
			}
			if err := revalidate(relative, before); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(".", rootInfo, 0)
}

func (tree *boundedWatchTree) addOne(watchPath string, expected os.FileInfo) error {
	watchPath = filepath.Clean(watchPath)
	if watched, exists := tree.paths[watchPath]; exists {
		// Backends automatically discard watches when the target disappears.
		// Keep the bounded local index only as a fast path, and confirm both the
		// filesystem incarnation and backend registration before trusting it.
		backendHasPath := false
		for _, existing := range tree.watcher.WatchList() {
			if filepath.Clean(existing) == watchPath {
				backendHasPath = true
				break
			}
		}
		if os.SameFile(watched, expected) && backendHasPath {
			return nil
		}
		if !os.SameFile(watched, expected) {
			// The path now names a different directory. Remove every cached watch
			// below the old incarnation before registering the replacement tree.
			if err := tree.Remove(watchPath); err != nil {
				return err
			}
		} else {
			delete(tree.paths, watchPath)
		}
	}
	if len(tree.paths) >= maxWatchDirectories {
		// Removed/renamed watches may have disappeared in the backend. Rebuild the
		// local index only at the limit, avoiding an O(n^2) WatchList call pattern.
		clear(tree.paths)
		for _, existing := range tree.watcher.WatchList() {
			existing = filepath.Clean(existing)
			info, err := os.Lstat(existing)
			if err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
				tree.paths[existing] = info
			}
		}
		if watched, exists := tree.paths[watchPath]; exists && os.SameFile(watched, expected) {
			return nil
		}
		if len(tree.paths) >= maxWatchDirectories {
			return fmt.Errorf("%w: source requires more than %d watched directories", ErrResourceLimit, maxWatchDirectories)
		}
	}
	if err := tree.watcher.Add(watchPath); err != nil {
		return fmt.Errorf("watch directory %q: %w", watchPath, err)
	}
	tree.paths[watchPath] = expected
	return nil
}

// Remove invalidates watches rooted at a removed or renamed filesystem path.
// A directory watch is not recursive, so every registered descendant must be
// removed as well. Backend removal is best-effort because several fsnotify
// implementations discard the watch before delivering the terminal event.
func (tree *boundedWatchTree) Remove(rootPath string) error {
	rootPath = filepath.Clean(rootPath)
	var firstErr error
	for watchPath := range tree.paths {
		relative, err := filepath.Rel(rootPath, watchPath)
		if err != nil || relative == ".." || filepath.IsAbs(relative) ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			continue
		}
		delete(tree.paths, watchPath)
		if err := tree.watcher.Remove(watchPath); err != nil &&
			!errors.Is(err, fsnotify.ErrNonExistentWatch) && firstErr == nil {
			firstErr = fmt.Errorf("remove stale watch %q: %w", watchPath, err)
		}
	}
	return firstErr
}

func reportWatchError(options WatchOptions, err error) {
	if options.OnError != nil && err != nil && !errors.Is(err, context.Canceled) {
		func() {
			defer func() { _ = recover() }()
			options.OnError(err)
		}()
	}
}

func invokeWatchAfterPublished(ctx context.Context, options WatchOptions, snapshot Snapshot) (err error) {
	if options.AfterPublished == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("s3disk: AfterPublished hook panic: %v", recovered)
		}
	}()
	if err := options.AfterPublished(ctx, snapshot); err != nil {
		return fmt.Errorf("s3disk: AfterPublished hook: %w", err)
	}
	return ctx.Err()
}

func invokeWatchPublished(options WatchOptions, snapshot Snapshot) {
	if options.OnPublished == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			reportWatchError(options, fmt.Errorf("s3disk: OnPublished callback panic: %v", recovered))
		}
	}()
	options.OnPublished(snapshot)
}

// PollOptions controls Consumer.Poll.
type PollOptions struct {
	Interval       time.Duration
	MaxInterval    time.Duration
	BackoffFactor  float64
	JitterFraction float64
	// OnResult is called after every successful Refresh, including unchanged,
	// stale-ignored, and no-snapshot results. This lets independent pollers
	// observe a snapshot which another poller or external Refresh adopted.
	OnResult  func(RefreshResult)
	OnUpdated func(RefreshResult)
	OnError   func(error)
}

// Validate checks PollOptions without starting network I/O. Zero values select
// defaults; a negative JitterFraction disables jitter for deterministic tests.
func (options PollOptions) Validate() error {
	interval := options.Interval
	if interval == 0 {
		interval = time.Second
	}
	maximum := options.MaxInterval
	if maximum == 0 {
		maximum = 30 * time.Second
	}
	factor := options.BackoffFactor
	if factor == 0 {
		factor = 2
	}
	if interval < 0 {
		return fmt.Errorf("s3disk: poll interval must be positive")
	}
	if maximum < interval {
		return fmt.Errorf("s3disk: maximum poll interval must be at least the base interval")
	}
	if math.IsNaN(factor) || math.IsInf(factor, 0) || factor < 1 || factor > 10 {
		return fmt.Errorf("s3disk: backoff factor must be finite and between 1 and 10")
	}
	if math.IsNaN(options.JitterFraction) || math.IsInf(options.JitterFraction, 0) || options.JitterFraction > 1 {
		return fmt.Errorf("s3disk: jitter fraction must be finite and at most 1")
	}
	return nil
}

// Poll performs an immediate refresh and then conditionally polls the small
// channel reference. A successful unchanged poll transfers no object body.
func (consumer *Consumer) Poll(ctx context.Context, options PollOptions) error {
	if err := options.Validate(); err != nil {
		return err
	}
	if options.Interval == 0 {
		options.Interval = time.Second
	}
	if options.MaxInterval == 0 {
		options.MaxInterval = 30 * time.Second
	}
	if options.BackoffFactor == 0 {
		options.BackoffFactor = 2
	}
	if options.JitterFraction == 0 {
		options.JitterFraction = 0.10
	}
	if options.JitterFraction < 0 {
		options.JitterFraction = 0
	}
	delayBase := options.Interval
	for {
		result, err := consumer.Refresh(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if options.OnError != nil {
				invokePollError(options, err)
			}
		} else {
			delayBase = options.Interval
			invokePollResult(options, result)
			if result.Status == RefreshUpdated {
				invokePollUpdated(options, result)
			}
		}
		delay := jitterDuration(delayBase, options.JitterFraction)
		if err != nil && delayBase < options.MaxInterval {
			next := time.Duration(float64(delayBase) * options.BackoffFactor)
			if next <= delayBase || next > options.MaxInterval {
				next = options.MaxInterval
			}
			delayBase = next
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func invokePollResult(options PollOptions, result RefreshResult) {
	if options.OnResult == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			invokePollError(options, fmt.Errorf("s3disk: OnResult callback panic: %v", recovered))
		}
	}()
	options.OnResult(result)
}

func invokePollUpdated(options PollOptions, result RefreshResult) {
	if options.OnUpdated == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			invokePollError(options, fmt.Errorf("s3disk: OnUpdated callback panic: %v", recovered))
		}
	}()
	options.OnUpdated(result)
}

func invokePollError(options PollOptions, err error) {
	if options.OnError == nil || err == nil {
		return
	}
	defer func() { _ = recover() }()
	options.OnError(err)
}

func jitterDuration(interval time.Duration, fraction float64) time.Duration {
	if fraction == 0 {
		return interval
	}
	factor := 1 - fraction + rand.Float64()*(2*fraction)
	return scaleDurationSaturated(interval, factor)
}

func scaleDurationSaturated(duration time.Duration, factor float64) time.Duration {
	scaled := float64(duration) * factor
	if scaled >= float64(math.MaxInt64) {
		return time.Duration(math.MaxInt64)
	}
	if scaled <= 0 {
		return 0
	}
	return time.Duration(scaled)
}
