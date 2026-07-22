//go:build linux || darwin || freebsd

// Package mount exposes a s3disk.Consumer as a read-only FUSE filesystem.
// The public API deliberately does not expose go-fuse types.
package mount

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/vibe-agi/s3disk"
)

type Options struct {
	AttrTTL  time.Duration
	EntryTTL time.Duration
	// NegativeTTL is retained for source compatibility. It must be zero: reverse
	// FUSE invalidation is advisory and some kernels return ENOENT without
	// evicting a negative dentry. Positive values are rejected with
	// ErrNegativeCacheUnsupported rather than weakening refresh freshness.
	NegativeTTL time.Duration
	Poll        s3disk.PollOptions
	Debug       bool
	// DangerouslyAllowMountWithoutDurableWatermark disables the default
	// cross-restart rollback protection requirement. A watermark is an
	// anti-rollback anchor, not an offline last-known-good snapshot.
	DangerouslyAllowMountWithoutDurableWatermark bool
	// DangerouslyAllowMountWithPreservedSymlinks permits a Consumer configured
	// with s3disk.SymlinkPreserve. Such a mount is not a sandbox because the host
	// kernel may follow a link outside the mounted tree.
	DangerouslyAllowMountWithPreservedSymlinks bool
	// KernelCache is retained for source compatibility. Setting it is rejected
	// with ErrKernelCacheUnsupported because page-cache state is shared by inode,
	// while s3disk permits old and new snapshot handles to coexist at one path.
	KernelCache    bool
	FilesystemName string
	// MaxInodeIdentities bounds the number of distinct (snapshot, path, type)
	// identities currently remembered for this mount. Remembering them makes
	// concurrent LOOKUP calls converge on one stable inode without probabilistic
	// hashes. Kernel FORGET events release identities which are no longer
	// reachable; inode numbers themselves remain monotonic and are never reused.
	// Zero selects DefaultMaxInodeIdentities.
	MaxInodeIdentities int
	// MaxInodeIdentityBytes bounds a conservative retained-memory charge for
	// distinct (snapshot, path, type) identities. It is independent of the
	// count limit. Zero selects DefaultMaxInodeIdentityBytes.
	MaxInodeIdentityBytes int64
	// AutoUnmountTimeout bounds retries after the ReadOnly context is canceled
	// or its fixed authorization deadline expires. Zero selects
	// DefaultAutoUnmountTimeout. Explicit UnmountContext calls use their
	// caller-supplied context instead.
	AutoUnmountTimeout time.Duration
}

// Mount is a running read-only filesystem.
type Mount struct {
	server   mountServer
	consumer *s3disk.Consumer
	// cancel stops polling and invalidation after a successful explicit or
	// external unmount. cancelLifetime owns the parent authorization timer and
	// is invoked only after the server is known to have stopped, so an explicit
	// Unmount cannot be misclassified as an automatic lifetime stop.
	cancel         context.CancelFunc
	cancelLifetime context.CancelFunc
	// done is the Consumer poller's completion signal.
	done chan struct{}
	// serverDone closes only after the go-fuse serve loop has stopped. It is
	// separate from unmounted, which also closes as soon as Unmount succeeds so
	// cancellation retry loops can stop promptly.
	serverDone chan struct{}
	// finished closes after the server, poller, and invalidation coordinator all
	// stop. It is the channel exposed by Done.
	finished chan struct{}

	statusMu sync.RWMutex
	status   MountStatus
	inodeIDs *inodeIdentityRegistry

	invalidationWake     chan struct{}
	invalidationDone     chan struct{}
	invalidate           func(context.Context) error
	currentSnapshot      func() (snapshotIdentity, bool)
	invalidationRetryMin time.Duration
	invalidationRetryMax time.Duration

	callbackMu  sync.Mutex
	userError   func(error)
	errorEvents chan error
	errorStop   chan struct{}
	errorOnce   sync.Once

	cancelOnce sync.Once
	unmountMu  sync.Mutex
	// unmountAttempt is a singleflight promise. The mutex is never held while
	// server.Unmount runs, because monitorServer must be able to publish an
	// externally observed stop concurrently with a blocked unmount call.
	unmountAttempt *mountUnmountAttempt
	unmounted      chan struct{}

	autoUnmountTimeout time.Duration
	unmountRetryMin    time.Duration
	unmountRetryMax    time.Duration
}

type mountUnmountAttempt struct {
	done    chan struct{}
	err     error
	waiters int
}

type mountServer interface {
	Wait()
	Unmount() error
}

type fuseMounter func(string, fs.InodeEmbedder, *fs.Options) (mountServer, error)

const (
	initialInvalidationRetryDelay = 100 * time.Millisecond
	maxInvalidationRetryDelay     = 5 * time.Second
	initialUnmountRetryDelay      = 10 * time.Millisecond
	maxUnmountRetryDelay          = time.Second
)

func resolveMountpoint(mountpoint string) (string, error) {
	absolute, err := filepath.Abs(mountpoint)
	if err != nil {
		return "", fmt.Errorf("s3disk mount: resolve mountpoint: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("s3disk mount: resolve mountpoint symlinks: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("s3disk mount: stat resolved mountpoint: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("s3disk mount: resolved mountpoint is not a directory")
	}
	return filepath.Clean(resolved), nil
}

// ReadOnly validates that a snapshot is available and its locally known
// authorization has not expired, mounts it, and starts the Consumer reference
// poller. On Linux this uses the kernel FUSE protocol. On macOS it additionally
// requires a user-installed macFUSE runtime.
func ReadOnly(ctx context.Context, consumer *s3disk.Consumer, mountpoint string, options Options) (*Mount, error) {
	return readOnlyWithMounter(ctx, consumer, mountpoint, options, mountFUSE)
}

func mountFUSE(mountpoint string, root fs.InodeEmbedder, options *fs.Options) (mountServer, error) {
	return fs.Mount(mountpoint, root, options)
}

func readOnlyWithMounter(
	ctx context.Context,
	consumer *s3disk.Consumer,
	mountpoint string,
	options Options,
	mounter fuseMounter,
) (*Mount, error) {
	if ctx == nil {
		return nil, fmt.Errorf("s3disk mount: nil context")
	}
	if consumer == nil {
		return nil, fmt.Errorf("s3disk mount: nil consumer")
	}
	var err error
	options, err = normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	if err := validateReadOnlySecurity(consumer.SecurityStatus(), options); err != nil {
		return nil, fmt.Errorf("s3disk mount: unsafe consumer configuration: %w", err)
	}
	resolvedMountpoint, err := resolveMountpoint(mountpoint)
	if err != nil {
		return nil, err
	}
	initialRefreshContext, cancelInitialRefresh := context.WithTimeout(ctx, options.Poll.AttemptTimeout)
	result, err := consumer.Refresh(initialRefreshContext)
	cancelInitialRefresh()
	if err != nil {
		return nil, fmt.Errorf("s3disk mount: initial refresh: %w", err)
	} else if result.Status == s3disk.RefreshNoSnapshot {
		return nil, s3disk.ErrNoSnapshot
	}
	authorizationExpiresAt, authorizationExpiryKnown := consumer.AuthorizationExpiry()
	lifetimeContext, cancelLifetime, err := newMountLifetimeContext(
		ctx, authorizationExpiresAt, authorizationExpiryKnown, time.Now(),
	)
	if err != nil {
		return nil, fmt.Errorf("s3disk mount: authorization lifetime: %w", err)
	}
	pollContext, cancelPolling := context.WithCancel(lifetimeContext)
	keepContexts := false
	defer func() {
		if !keepContexts {
			cancelPolling()
			cancelLifetime()
		}
	}()
	initialSnapshot, ok := consumer.CurrentSnapshot()
	if !ok {
		return nil, s3disk.ErrNoSnapshot
	}
	initialIdentity := identityOfSnapshot(initialSnapshot)
	root := newRootNode(consumer, options.MaxInodeIdentities, options.MaxInodeIdentityBytes)
	fuseOptions := newFUSEOptions(options)
	if lifetimeErr := lifetimeContext.Err(); lifetimeErr != nil {
		if errors.Is(context.Cause(lifetimeContext), ErrAuthorizationExpired) {
			return nil, fmt.Errorf("s3disk mount: authorization lifetime: %w", ErrAuthorizationExpired)
		}
		return nil, fmt.Errorf("s3disk mount: context ended before FUSE start: %w", lifetimeErr)
	}
	server, err := mounter(resolvedMountpoint, root, fuseOptions)
	if err != nil {
		return nil, fmt.Errorf("s3disk mount: %w", err)
	}
	now := time.Now()
	mounted := &Mount{
		server: server, consumer: consumer, cancel: cancelPolling, cancelLifetime: cancelLifetime,
		done:       make(chan struct{}),
		serverDone: make(chan struct{}), finished: make(chan struct{}), unmounted: make(chan struct{}),
		inodeIDs:         root.inodeIDs,
		invalidationWake: make(chan struct{}, 1), invalidationDone: make(chan struct{}),
		invalidate:           root.invalidateMaterialized,
		invalidationRetryMin: initialInvalidationRetryDelay,
		invalidationRetryMax: maxInvalidationRetryDelay,
		autoUnmountTimeout:   options.AutoUnmountTimeout,
		unmountRetryMin:      initialUnmountRetryDelay, unmountRetryMax: maxUnmountRetryDelay,
		status: MountStatus{
			Lifecycle: LifecycleRunning, ObservedSnapshot: publicSnapshotIdentity(initialIdentity),
			NotifiedSnapshot: publicSnapshotIdentity(initialIdentity),
			InvalidationMode: InvalidationActive, Polling: true,
			AuthorizationExpiresAt:  authorizationExpiresAt,
			Refresh:                 ComponentStatus{LastAttempt: now, LastSuccess: now},
			InodeIdentitiesLimit:    options.MaxInodeIdentities,
			InodeIdentityBytesLimit: options.MaxInodeIdentityBytes,
		},
		errorEvents: make(chan error, 16), errorStop: make(chan struct{}),
	}
	mounted.currentSnapshot = func() (snapshotIdentity, bool) {
		snapshot, ok := consumer.CurrentSnapshot()
		return identityOfSnapshot(snapshot), ok
	}
	userAttempt := options.Poll.OnAttempt
	userResult := options.Poll.OnResult
	userUpdated := options.Poll.OnUpdated
	mounted.userError = options.Poll.OnError
	options.Poll.OnAttempt = func() {
		mounted.recordRefreshAttempt()
		if userAttempt != nil {
			userAttempt()
		}
	}
	options.Poll.OnResult = func(result s3disk.RefreshResult) {
		mounted.recordRefreshSuccess()
		mounted.observeCurrentSnapshot(true)
		if userResult != nil {
			userResult(result)
		}
	}
	options.Poll.OnUpdated = func(result s3disk.RefreshResult) {
		if userUpdated != nil {
			userUpdated(result)
		}
	}
	options.Poll.OnError = func(err error) {
		mounted.handleRefreshFailure(pollContext, err)
	}
	go mounted.runErrorDispatcher()
	go mounted.unmountOnLifetimeDone(lifetimeContext)
	go mounted.monitorServer()
	go mounted.runInvalidationCoordinator(pollContext)
	go func() {
		defer func() {
			mounted.recordPollingStopped()
			close(mounted.done)
		}()
		_ = consumer.Poll(pollContext, options.Poll)
	}()
	go mounted.finishWhenStopped()
	keepContexts = true
	return mounted, nil
}

// newMountLifetimeContext fixes the authorization boundary for one mount. A
// later reader refresh may shorten access at the object service, but it can
// never extend this local deadline. The parent context's earlier deadline or
// cancellation still wins through normal context propagation.
func newMountLifetimeContext(
	parent context.Context,
	authorizationExpiresAt time.Time,
	authorizationExpiryKnown bool,
	now time.Time,
) (context.Context, context.CancelFunc, error) {
	if parent == nil {
		return nil, nil, fmt.Errorf("s3disk mount: nil context")
	}
	if !authorizationExpiryKnown || authorizationExpiresAt.IsZero() {
		lifetime, cancel := context.WithCancel(parent)
		return lifetime, cancel, nil
	}
	if !authorizationExpiresAt.After(now) {
		return nil, nil, ErrAuthorizationExpired
	}
	lifetime, cancel := context.WithDeadlineCause(parent, authorizationExpiresAt, ErrAuthorizationExpired)
	return lifetime, cancel, nil
}

func newFUSEOptions(options Options) *fs.Options {
	return &fs.Options{
		AttrTimeout:     &options.AttrTTL,
		EntryTimeout:    &options.EntryTTL,
		NegativeTimeout: nil,
		NullPermissions: true,
		// Ownership is not part of the portable snapshot format. Mapping zero
		// attributes to the mounting process lets default_permissions apply the
		// published owner bits to the user running this per-user mount.
		UID: uint32(os.Getuid()),
		GID: uint32(os.Getgid()),
		MountOptions: fuse.MountOptions{
			Debug:   options.Debug,
			FsName:  options.FilesystemName,
			Name:    "s3disk",
			Options: kernelMountOptions(),
		},
	}
}

func kernelMountOptions() []string {
	return []string{"ro", "default_permissions"}
}

type snapshotIdentity struct {
	generation uint64
	commit     s3disk.Digest
}

func (identity snapshotIdentity) valid() bool {
	return identity.generation != 0 && !identity.commit.IsZero()
}

func identityOfSnapshot(snapshot s3disk.Snapshot) snapshotIdentity {
	return snapshotIdentity{generation: snapshot.Generation, commit: snapshot.Commit}
}

func publicSnapshotIdentity(identity snapshotIdentity) SnapshotIdentity {
	return SnapshotIdentity{Generation: identity.generation, Commit: identity.commit}
}

type inodeIdentityKey struct {
	snapshot  snapshotIdentity
	path      string
	entryType s3disk.EntryType
}

// inodeIdentityRegistry deliberately uses exact keys and monotonic numbers
// instead of truncating a digest into an inode number. That gives collision-free
// identity within one mount, including simultaneous LOOKUPs which return before
// go-fuse has attached either child to the bridge.
type inodeIdentityRegistry struct {
	mu            sync.Mutex
	limit         int
	byteLimit     int64
	retainedBytes int64
	reclaimed     uint64
	next          uint64
	identities    map[inodeIdentityKey]uint64
}

func newInodeIdentityRegistry(limit int, byteLimit int64) *inodeIdentityRegistry {
	return &inodeIdentityRegistry{
		limit: limit, byteLimit: byteLimit, next: 2,
	}
}

const inodeIdentityEntryOverheadBytes = int64(512)

// inodeIdentityRetainedBytes returns a conservative charge for one exact map
// entry. It counts the inline key and value, clones of both string payloads,
// allocator rounding, and an allowance for map buckets and growth. Cloning the
// strings on insertion prevents the registry from accidentally retaining a
// larger backing allocation owned by a caller.
func inodeIdentityRetainedBytes(value string, entryType s3disk.EntryType) int64 {
	logical := int64(unsafe.Sizeof(inodeIdentityKey{})) + int64(unsafe.Sizeof(uint64(0)))
	logical = saturatingInodeIdentityBytes(logical, int64(len(value)))
	logical = saturatingInodeIdentityBytes(logical, int64(len(entryType)))
	logical = saturatingInodeIdentityBytes(logical, logical)
	return saturatingInodeIdentityBytes(logical, inodeIdentityEntryOverheadBytes)
}

func saturatingInodeIdentityBytes(left, right int64) int64 {
	if left < 0 || right < 0 || left > int64(^uint64(0)>>1)-right {
		return int64(^uint64(0) >> 1)
	}
	return left + right
}

func (registry *inodeIdentityRegistry) stableAttr(identity snapshotIdentity, value string, entryType s3disk.EntryType) (fs.StableAttr, error) {
	if registry == nil {
		return fs.StableAttr{}, fmt.Errorf("s3disk mount: inode identity registry is unavailable")
	}
	if !identity.valid() {
		return fs.StableAttr{}, fmt.Errorf("s3disk mount: invalid snapshot identity for inode %q", value)
	}
	key := inodeIdentityKey{snapshot: identity, path: value, entryType: entryType}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if inodeNumber, ok := registry.identities[key]; ok {
		return fs.StableAttr{Mode: typeMode(entryType), Ino: inodeNumber, Gen: identity.generation}, nil
	}
	requestedBytes := inodeIdentityRetainedBytes(value, entryType)
	if len(registry.identities) >= registry.limit || registry.next == ^uint64(0) {
		return fs.StableAttr{}, fmt.Errorf(
			"%w: identities used=%d limit=%d; retained bytes used=%d limit=%d requested=%d",
			ErrInodeIdentityLimit, len(registry.identities), registry.limit,
			registry.retainedBytes, registry.byteLimit, requestedBytes,
		)
	}
	if requestedBytes > registry.byteLimit || registry.retainedBytes > registry.byteLimit-requestedBytes {
		return fs.StableAttr{}, fmt.Errorf(
			"%w: retained byte budget exceeded: identities used=%d limit=%d; retained bytes used=%d limit=%d requested=%d",
			ErrInodeIdentityLimit, len(registry.identities), registry.limit,
			registry.retainedBytes, registry.byteLimit, requestedBytes,
		)
	}
	inodeNumber := registry.next
	registry.next++
	key.path = strings.Clone(value)
	key.entryType = s3disk.EntryType(strings.Clone(string(entryType)))
	if registry.identities == nil {
		registry.identities = make(map[inodeIdentityKey]uint64)
	}
	registry.identities[key] = inodeNumber
	registry.retainedBytes += requestedBytes
	return fs.StableAttr{Mode: typeMode(entryType), Ino: inodeNumber, Gen: identity.generation}, nil
}

// release forgets one exact identity only while it still names inodeNumber.
// The conditional value check prevents a late or duplicate OnForget from
// deleting a newer allocation for the same snapshot/path/type tuple. Inode
// numbers are deliberately not recycled: an old open file handle may outlive
// the kernel's namespace lookup reference even after FORGET.
func (registry *inodeIdentityRegistry) release(
	identity snapshotIdentity,
	value string,
	entryType s3disk.EntryType,
	inodeNumber uint64,
) bool {
	if registry == nil || !identity.valid() || inodeNumber == 0 {
		return false
	}
	key := inodeIdentityKey{snapshot: identity, path: value, entryType: entryType}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	current, ok := registry.identities[key]
	if !ok || current != inodeNumber {
		return false
	}
	delete(registry.identities, key)
	if len(registry.identities) == 0 {
		// Let the map buckets become collectible after complete churn instead of
		// retaining their historical high-water allocation for the whole mount.
		registry.identities = nil
	}
	charged := inodeIdentityRetainedBytes(key.path, key.entryType)
	if charged >= registry.retainedBytes {
		registry.retainedBytes = 0
	} else {
		registry.retainedBytes -= charged
	}
	registry.reclaimed++
	return true
}

func (registry *inodeIdentityRegistry) usage() (int, int64) {
	used, retainedBytes, _ := registry.stats()
	return used, retainedBytes
}

func (registry *inodeIdentityRegistry) stats() (int, int64, uint64) {
	if registry == nil {
		return 0, 0, 0
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return len(registry.identities), registry.retainedBytes, registry.reclaimed
}

func (registry *inodeIdentityRegistry) used() int {
	used, _ := registry.usage()
	return used
}

func newRootNode(consumer *s3disk.Consumer, maxInodeIdentities int, maxInodeIdentityBytes int64) *node {
	return &node{
		consumer: consumer, path: "", entryType: s3disk.EntryDir,
		inodeIDs: newInodeIdentityRegistry(maxInodeIdentities, maxInodeIdentityBytes),
	}
}

var closedDoneChannel = func() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}()

// Status returns a point-in-time health snapshot without performing I/O.
func (mounted *Mount) Status() MountStatus {
	if mounted == nil {
		return MountStatus{}
	}
	mounted.statusMu.RLock()
	status := mounted.status
	mounted.statusMu.RUnlock()
	if mounted.inodeIDs != nil {
		status.InodeIdentitiesUsed, status.InodeIdentityBytesUsed,
			status.InodeIdentitiesReclaimed = mounted.inodeIDs.stats()
	}
	return status
}

// Done closes only after the FUSE serve loop and both background workers stop.
func (mounted *Mount) Done() <-chan struct{} {
	if mounted == nil {
		return closedDoneChannel
	}
	if mounted.finished != nil {
		return mounted.finished
	}
	// The fallback keeps directly constructed package tests useful. ReadOnly
	// always installs finished.
	if mounted.serverDone != nil {
		return mounted.serverDone
	}
	return closedDoneChannel
}

func (mounted *Mount) Wait() {
	<-mounted.Done()
}

// WaitContext waits for complete shutdown or returns the context error.
func (mounted *Mount) WaitContext(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("s3disk mount: nil wait context")
	}
	select {
	case <-mounted.Done():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Unmount performs one serialized unmount attempt. Concurrent callers join
// the same physical attempt. A failed attempt leaves polling active and may be
// retried by a later call.
func (mounted *Mount) Unmount() error {
	return mounted.unmountOnceContext(context.Background())
}

// UnmountContext retries serialized unmount attempts with bounded exponential
// backoff until the server stops or ctx expires. A timed-out physical attempt
// remains singleflight; later callers join it rather than issuing an unsafe
// overlapping unmount.
func (mounted *Mount) UnmountContext(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("s3disk mount: nil unmount context")
	}
	minimum, maximum := retryBounds(
		mounted.unmountRetryMin, mounted.unmountRetryMax,
		initialUnmountRetryDelay, maxUnmountRetryDelay,
	)
	delay := minimum
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return joinContextError(err, lastErr)
		}
		err := mounted.unmountOnceContext(ctx)
		if err == nil {
			return nil
		}
		lastErr = err
		if ctxErr := ctx.Err(); ctxErr != nil {
			return joinContextError(ctxErr, lastErr)
		}
		mounted.recordUnmountRetry(time.Now().Add(delay))
		timer := time.NewTimer(delay)
		select {
		case <-mounted.unmounted:
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return joinContextError(ctx.Err(), lastErr)
		case <-timer.C:
		}
		delay = nextRetryDelay(delay, maximum)
	}
}

func joinContextError(ctxErr, operationErr error) error {
	if operationErr == nil {
		return ctxErr
	}
	return errors.Join(ctxErr, operationErr)
}

func retryBounds(minimum, maximum, defaultMinimum, defaultMaximum time.Duration) (time.Duration, time.Duration) {
	if minimum <= 0 {
		minimum = defaultMinimum
	}
	if maximum < minimum {
		maximum = defaultMaximum
		if maximum < minimum {
			maximum = minimum
		}
	}
	return minimum, maximum
}

func nextRetryDelay(delay, maximum time.Duration) time.Duration {
	if delay >= maximum/2 {
		return maximum
	}
	return delay * 2
}

func (mounted *Mount) unmountOnceContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	mounted.unmountMu.Lock()
	if channelIsClosed(mounted.unmounted) {
		mounted.unmountMu.Unlock()
		return nil
	}
	attempt := mounted.unmountAttempt
	if attempt == nil {
		attempt = &mountUnmountAttempt{done: make(chan struct{}), waiters: 1}
		mounted.unmountAttempt = attempt
		mounted.unmountMu.Unlock()
		mounted.recordUnmountAttempt()
		go mounted.executeUnmount(attempt)
	} else {
		attempt.waiters++
		mounted.unmountMu.Unlock()
	}
	var result error
	select {
	case <-mounted.unmounted:
		result = nil
	case <-attempt.done:
		result = attempt.err
	case <-ctx.Done():
		select {
		case <-mounted.unmounted:
			result = nil
		case <-attempt.done:
			result = attempt.err
		default:
			result = ctx.Err()
		}
	}
	mounted.unmountMu.Lock()
	attempt.waiters--
	mounted.unmountMu.Unlock()
	return result
}

func (mounted *Mount) executeUnmount(attempt *mountUnmountAttempt) {
	err := mounted.server.Unmount()

	mounted.unmountMu.Lock()
	if channelIsClosed(mounted.unmounted) {
		err = nil
	}
	mounted.unmountMu.Unlock()

	if err == nil {
		mounted.recordUnmountSuccess()
		mounted.cancelPolling()
	} else {
		mounted.recordUnmountFailure(err)
	}

	mounted.unmountMu.Lock()
	// monitorServer may have observed an external stop while the result was
	// being recorded. That terminal observation wins over a late unmount error.
	if channelIsClosed(mounted.unmounted) {
		err = nil
	} else if err == nil {
		close(mounted.unmounted)
	}
	attempt.err = err
	if mounted.unmountAttempt == attempt {
		mounted.unmountAttempt = nil
	}
	close(attempt.done)
	mounted.unmountMu.Unlock()
	if err == nil {
		mounted.cancelMountLifetime()
	}
}

func (mounted *Mount) cancelPolling() {
	mounted.cancelOnce.Do(func() {
		if mounted.cancel != nil {
			mounted.cancel()
		}
	})
}

func (mounted *Mount) cancelMountLifetime() {
	if mounted.cancelLifetime != nil {
		mounted.cancelLifetime()
	}
}

// publishServerStopped atomically publishes the terminal lifecycle and closes
// the unmounted promise under the same serialization lock. Without this,
// executeUnmount could observe the small window between status publication and
// channel closure and return a late server error even though Wait had already
// proved that the mount stopped.
func (mounted *Mount) publishServerStopped() {
	mounted.unmountMu.Lock()
	defer mounted.unmountMu.Unlock()
	now := time.Now()
	mounted.statusMu.Lock()
	mounted.status.Lifecycle = LifecycleStopped
	mounted.status.Polling = false
	mounted.status.Unmount.LastSuccess = now
	mounted.status.Unmount.NextRetry = time.Time{}
	mounted.status.Unmount.ConsecutiveFailures = 0
	mounted.status.Unmount.LastError = ""
	mounted.statusMu.Unlock()
	if !channelIsClosed(mounted.unmounted) {
		close(mounted.unmounted)
	}
}

func channelIsClosed(channel <-chan struct{}) bool {
	if channel == nil {
		return false
	}
	select {
	case <-channel:
		return true
	default:
		return false
	}
}

func (mounted *Mount) monitorServer() {
	mounted.server.Wait()
	mounted.publishServerStopped()
	mounted.cancelPolling()
	mounted.cancelMountLifetime()
	mounted.stopErrorDispatcher()
	close(mounted.serverDone)
}

func (mounted *Mount) unmountOnLifetimeDone(lifetimeContext context.Context) {
	select {
	case <-lifetimeContext.Done():
		// Claim the reason under the same lock which publishes explicit or
		// external stop. This prevents a completed stop from being mislabeled
		// when lifetime cancellation becomes ready at the same time.
		if !mounted.beginAutomaticUnmount(automaticUnmountReason(lifetimeContext)) {
			return
		}
		mounted.cancelPolling()
		mounted.recordUnmountAttempt()
	case <-mounted.unmounted:
		return
	}
	timeout := mounted.autoUnmountTimeout
	if timeout <= 0 {
		timeout = DefaultAutoUnmountTimeout
	}
	autoContext, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := mounted.UnmountContext(autoContext); err != nil {
		wrapped := fmt.Errorf("s3disk mount: automatic unmount: %w", err)
		mounted.recordUnmountFailure(wrapped)
		mounted.reportUserError(wrapped)
	}
}

func automaticUnmountReason(lifetimeContext context.Context) AutomaticUnmountReason {
	if errors.Is(context.Cause(lifetimeContext), ErrAuthorizationExpired) {
		return AutomaticUnmountReasonAuthorizationExpired
	}
	return AutomaticUnmountReasonContextDone
}

func (mounted *Mount) finishWhenStopped() {
	<-mounted.serverDone
	<-mounted.done
	<-mounted.invalidationDone
	close(mounted.finished)
}

func (mounted *Mount) recordRefreshSuccess() {
	now := time.Now()
	mounted.statusMu.Lock()
	mounted.status.Refresh.LastSuccess = now
	mounted.status.Refresh.NextRetry = time.Time{}
	mounted.status.Refresh.ConsecutiveFailures = 0
	mounted.status.Refresh.LastError = ""
	mounted.statusMu.Unlock()
}

func (mounted *Mount) recordRefreshAttempt() {
	mounted.statusMu.Lock()
	mounted.status.Refresh.LastAttempt = time.Now()
	mounted.status.Refresh.NextRetry = time.Time{}
	mounted.statusMu.Unlock()
}

func (mounted *Mount) handleRefreshFailure(pollContext context.Context, err error) {
	if err == nil {
		return
	}
	// Consumer.Poll normally consumes cancellation of its own context before it
	// invokes OnError. Keep this check as a race-safe terminal guard, but do not
	// classify an operation-level context error as mount cancellation merely by
	// its sentinel. S3 clients commonly return DeadlineExceeded while the mount
	// context remains live (for example, an HTTP attempt timeout); that is an
	// observable refresh failure and must degrade health and reach OnError.
	if pollContext != nil && pollContext.Err() != nil {
		return
	}
	mounted.recordRefreshFailure(err)
	mounted.reportUserError(err)
}

func (mounted *Mount) recordRefreshFailure(err error) {
	if err == nil {
		return
	}
	mounted.statusMu.Lock()
	mounted.status.Refresh.ConsecutiveFailures++
	mounted.status.Refresh.LastError = err.Error()
	mounted.statusMu.Unlock()
}

func (mounted *Mount) recordPollingStopped() {
	mounted.statusMu.Lock()
	mounted.status.Polling = false
	mounted.statusMu.Unlock()
}

func (mounted *Mount) recordUnmountAttempt() {
	mounted.statusMu.Lock()
	if mounted.status.Lifecycle != LifecycleStopped {
		mounted.status.Lifecycle = LifecycleStopping
	}
	mounted.status.Unmount.LastAttempt = time.Now()
	mounted.status.Unmount.NextRetry = time.Time{}
	mounted.statusMu.Unlock()
}

func (mounted *Mount) beginAutomaticUnmount(reason AutomaticUnmountReason) bool {
	if reason == AutomaticUnmountReasonNone {
		return false
	}
	mounted.unmountMu.Lock()
	defer mounted.unmountMu.Unlock()
	if channelIsClosed(mounted.unmounted) {
		return false
	}
	mounted.statusMu.Lock()
	if mounted.status.AutomaticUnmountReason == AutomaticUnmountReasonNone {
		mounted.status.AutomaticUnmountReason = reason
	}
	mounted.statusMu.Unlock()
	return true
}

func (mounted *Mount) recordUnmountRetry(next time.Time) {
	mounted.statusMu.Lock()
	if mounted.status.Lifecycle != LifecycleStopped {
		mounted.status.Unmount.NextRetry = next
	}
	mounted.statusMu.Unlock()
}

func (mounted *Mount) recordUnmountSuccess() {
	now := time.Now()
	mounted.statusMu.Lock()
	if mounted.status.Lifecycle != LifecycleStopped {
		mounted.status.Lifecycle = LifecycleStopping
	}
	mounted.status.Unmount.LastAttempt = now
	mounted.status.Unmount.LastSuccess = now
	mounted.status.Unmount.NextRetry = time.Time{}
	mounted.status.Unmount.ConsecutiveFailures = 0
	mounted.status.Unmount.LastError = ""
	mounted.statusMu.Unlock()
}

func (mounted *Mount) recordUnmountFailure(err error) {
	if err == nil {
		return
	}
	mounted.statusMu.Lock()
	if mounted.status.Lifecycle != LifecycleStopped {
		mounted.status.Lifecycle = LifecycleStopFailed
		mounted.status.Unmount.LastAttempt = time.Now()
		mounted.status.Unmount.NextRetry = time.Time{}
		mounted.status.Unmount.ConsecutiveFailures++
		mounted.status.Unmount.LastError = err.Error()
	}
	mounted.statusMu.Unlock()
}

func (mounted *Mount) reportUserError(err error) {
	if mounted.userError == nil || err == nil {
		return
	}
	if mounted.errorEvents != nil && mounted.errorStop != nil {
		select {
		case <-mounted.errorStop:
			return
		default:
		}
		// Health state is authoritative and retains the latest failure. The
		// bounded callback queue is deliberately lossy so a blocked customer
		// callback cannot stop refresh or notification convergence.
		select {
		case mounted.errorEvents <- err:
		default:
		}
		return
	}
	// Directly constructed package tests use the synchronous fallback.
	mounted.callbackMu.Lock()
	defer mounted.callbackMu.Unlock()
	defer func() { _ = recover() }()
	mounted.userError(err)
}

func (mounted *Mount) runErrorDispatcher() {
	for {
		select {
		case <-mounted.errorStop:
			return
		case err := <-mounted.errorEvents:
			mounted.callbackMu.Lock()
			func() {
				defer func() { _ = recover() }()
				mounted.userError(err)
			}()
			mounted.callbackMu.Unlock()
		}
	}
}

func (mounted *Mount) stopErrorDispatcher() {
	mounted.errorOnce.Do(func() {
		if mounted.errorStop != nil {
			close(mounted.errorStop)
		}
	})
}

func (mounted *Mount) observeCurrentSnapshot(wake bool) {
	if mounted.currentSnapshot == nil {
		return
	}
	identity, ok := mounted.currentSnapshot()
	if !ok || !identity.valid() {
		return
	}
	mounted.observeSnapshot(identity, wake)
}

func (mounted *Mount) observeSnapshot(identity snapshotIdentity, wake bool) {
	observed := publicSnapshotIdentity(identity)
	mounted.statusMu.Lock()
	changed := mounted.status.ObservedSnapshot != observed
	mounted.status.ObservedSnapshot = observed
	pending := mounted.status.NotifiedSnapshot != observed
	mounted.statusMu.Unlock()
	if wake && changed && pending {
		mounted.wakeInvalidation()
	}
}

func (mounted *Mount) wakeInvalidation() {
	if mounted.invalidationWake == nil {
		return
	}
	select {
	case mounted.invalidationWake <- struct{}{}:
	default:
	}
}

func (mounted *Mount) invalidationTarget() (snapshotIdentity, bool) {
	if mounted.currentSnapshot != nil {
		if current, ok := mounted.currentSnapshot(); ok && current.valid() {
			mounted.observeSnapshot(current, false)
		}
	}
	mounted.statusMu.RLock()
	observed := mounted.status.ObservedSnapshot
	pending := observed != mounted.status.NotifiedSnapshot
	mounted.statusMu.RUnlock()
	return snapshotIdentity{generation: observed.Generation, commit: observed.Commit}, pending && observed.Generation != 0 && !observed.Commit.IsZero()
}

func (mounted *Mount) recordInvalidationAttempt() {
	mounted.statusMu.Lock()
	mounted.status.Invalidation.LastAttempt = time.Now()
	mounted.status.Invalidation.NextRetry = time.Time{}
	mounted.status.InvalidationMode = InvalidationActive
	mounted.statusMu.Unlock()
}

func (mounted *Mount) recordInvalidationSuccess(identity snapshotIdentity) {
	now := time.Now()
	mounted.statusMu.Lock()
	mounted.status.NotifiedSnapshot = publicSnapshotIdentity(identity)
	mounted.status.Invalidation.LastAttempt = now
	mounted.status.Invalidation.LastSuccess = now
	mounted.status.Invalidation.NextRetry = time.Time{}
	mounted.status.Invalidation.ConsecutiveFailures = 0
	mounted.status.Invalidation.LastError = ""
	mounted.status.InvalidationMode = InvalidationActive
	mounted.statusMu.Unlock()
}

func (mounted *Mount) recordInvalidationFailure(err error, nextRetry time.Time) {
	mounted.statusMu.Lock()
	mounted.status.Invalidation.LastAttempt = time.Now()
	mounted.status.Invalidation.NextRetry = nextRetry
	mounted.status.Invalidation.ConsecutiveFailures++
	mounted.status.Invalidation.LastError = err.Error()
	mounted.status.InvalidationMode = InvalidationBackoff
	mounted.statusMu.Unlock()
}

func (mounted *Mount) recordInvalidationStopped() {
	mounted.statusMu.Lock()
	if mounted.status.ObservedSnapshot != mounted.status.NotifiedSnapshot {
		mounted.status.InvalidationMode = InvalidationTTLFallback
	}
	mounted.status.Invalidation.NextRetry = time.Time{}
	mounted.statusMu.Unlock()
}

func (mounted *Mount) runInvalidationCoordinator(ctx context.Context) {
	defer func() {
		mounted.recordInvalidationStopped()
		close(mounted.invalidationDone)
	}()
	minimum, maximum := retryBounds(
		mounted.invalidationRetryMin, mounted.invalidationRetryMax,
		initialInvalidationRetryDelay, maxInvalidationRetryDelay,
	)
	for {
		select {
		case <-ctx.Done():
			return
		case <-mounted.invalidationWake:
		}
		delay := minimum
		for {
			target, pending := mounted.invalidationTarget()
			if !pending {
				break
			}
			mounted.recordInvalidationAttempt()
			err := mounted.invalidate(ctx)
			if ctx.Err() != nil {
				return
			}
			after, afterOK := mounted.currentSnapshot()
			if afterOK && after.valid() {
				mounted.observeSnapshot(after, false)
			}
			if err == nil && afterOK && after == target {
				mounted.recordInvalidationSuccess(target)
				delay = minimum
				continue
			}
			if err == nil {
				if !afterOK {
					err = s3disk.ErrNoSnapshot
				} else {
					// The Consumer advanced during the advisory sweep. Do not
					// acknowledge a mixed traversal; immediately sweep the latest
					// stable identity instead.
					delay = minimum
					continue
				}
			}
			retryAt := time.Now().Add(delay)
			wrapped := fmt.Errorf("s3disk mount: invalidate refreshed snapshot: %w", err)
			mounted.recordInvalidationFailure(wrapped, retryAt)
			mounted.reportUserError(wrapped)
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-mounted.invalidationWake:
				if !timer.Stop() {
					<-timer.C
				}
				delay = minimum
			case <-timer.C:
				delay = nextRetryDelay(delay, maximum)
			}
		}
	}
}

type node struct {
	fs.Inode
	consumer  *s3disk.Consumer
	path      string
	entryType s3disk.EntryType

	// Non-root inodes are immutable views of one snapshot. Linux does not carry
	// the originating FUSE file handle on GETATTR/fstat, so allowing handles from
	// different generations to share an inode would make pinned metadata
	// ambiguous. Refresh invalidates their kernel dentries and a later lookup
	// lets the go-fuse bridge replace them with generation-specific inodes.
	snapshotBound bool
	snapshot      snapshotIdentity
	snapshotEntry s3disk.Entry
	inodeIDs      *inodeIdentityRegistry
	inodeNumber   uint64
}

func (node *node) entry(ctx context.Context) (s3disk.Entry, error) {
	return node.consumer.Stat(ctx, node.path)
}

func (n *node) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if n.staleBoundSnapshot() {
		return nil, syscall.ESTALE
	}
	value := path.Join(n.path, name)
	entry, identity, err := n.statPinned(ctx, value)
	if n.snapshotBound && identity.valid() && n.snapshot != identity {
		// A lookup through a directory inode from an older generation must not
		// splice current-generation children beneath that old inode.
		return nil, syscall.ESTALE
	}
	if err != nil {
		return nil, errno(err)
	}
	fillEntry(&out.Attr, entry)
	if existing := n.GetChild(name); existing != nil {
		if existingNode, ok := existing.Operations().(*node); ok && existingNode.entryType == entry.Type &&
			existingNode.snapshotBound && existingNode.snapshot == identity {
			out.Attr.Ino = existing.StableAttr().Ino
			return existing, 0
		}
	}
	// Do not notify or detach here. Reverse notifications can deadlock while
	// the kernel is waiting for this LOOKUP, and RmChild has no expected-child
	// guard. The go-fuse bridge replaces the obsolete child under its own locks
	// after this callback returns.
	child := &node{
		consumer: n.consumer, path: value, entryType: entry.Type,
		snapshotBound: true, snapshot: identity, snapshotEntry: entry,
		inodeIDs: n.inodeIDs,
	}
	stable, stableErr := n.inodeIDs.stableAttr(identity, value, entry.Type)
	if stableErr != nil {
		return nil, errno(stableErr)
	}
	child.inodeNumber = stable.Ino
	out.Attr.Ino = stable.Ino
	inode := n.NewInode(ctx, child, stable)
	return inode, 0
}

// OnForget releases only the registry entry owned by this exact inode. The
// allocation counter remains monotonic, so a file handle pinned to an older
// snapshot can safely outlive namespace reclamation without its inode number
// ever being assigned to different content.
func (node *node) OnForget() {
	if node == nil || !node.snapshotBound {
		return
	}
	node.inodeIDs.release(node.snapshot, node.path, node.entryType, node.inodeNumber)
}

func (node *node) Getattr(ctx context.Context, rawHandle fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if node.snapshotBound {
		fillEntry(&out.Attr, node.snapshotEntry)
		return 0
	}
	if handle, ok := rawHandle.(*fileHandle); ok && handle != nil {
		fillEntry(&out.Attr, handle.entry)
		return 0
	}
	entry, err := node.entry(ctx)
	if err != nil {
		return errno(err)
	}
	fillEntry(&out.Attr, entry)
	return 0
}

func (node *node) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	if node.staleBoundSnapshot() {
		return nil, syscall.ESTALE
	}
	entries, identity, err := node.listDirPinned(ctx)
	if node.snapshotBound && identity.valid() && node.snapshot != identity {
		return nil, syscall.ESTALE
	}
	if err != nil {
		return nil, errno(err)
	}
	result := make([]fuse.DirEntry, len(entries))
	for index, entry := range entries {
		result[index] = fuse.DirEntry{Name: entry.Name, Mode: typeMode(entry.Type)}
	}
	return fs.NewListDirStream(result), 0
}

func (node *node) Opendir(ctx context.Context) syscall.Errno {
	if err := ctx.Err(); err != nil {
		return errno(err)
	}
	if node.staleBoundSnapshot() {
		return syscall.ESTALE
	}
	if node.entryType != s3disk.EntryDir {
		return syscall.ENOTDIR
	}
	return 0
}

func (node *node) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	accessMode := flags & uint32(syscall.O_ACCMODE)
	mutationFlags := uint32(syscall.O_APPEND | syscall.O_CREAT | syscall.O_EXCL | syscall.O_TRUNC)
	if accessMode != uint32(syscall.O_RDONLY) || flags&mutationFlags != 0 {
		return nil, 0, syscall.EROFS
	}
	if node.staleBoundSnapshot() {
		return nil, 0, syscall.ESTALE
	}
	file, entry, identity, err := node.openPinned(ctx)
	if node.snapshotBound && identity.valid() && node.snapshot != identity {
		// The consumer advanced before this old inode was detached. Do not place a
		// new-generation handle on an inode which may still serve old fstat calls.
		return nil, 0, syscall.ESTALE
	}
	if err != nil {
		return nil, 0, errno(err)
	}
	return &fileHandle{file: file, entry: entry}, fuse.FOPEN_DIRECT_IO, 0
}

func (node *node) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	if node.staleBoundSnapshot() {
		return nil, syscall.ESTALE
	}
	target, identity, err := node.readlinkPinned(ctx)
	if node.snapshotBound && identity.valid() && node.snapshot != identity {
		return nil, syscall.ESTALE
	}
	if err != nil {
		return nil, errno(err)
	}
	return []byte(target), 0
}

func (node *node) Setattr(context.Context, fs.FileHandle, *fuse.SetAttrIn, *fuse.AttrOut) syscall.Errno {
	return syscall.EROFS
}

func (node *node) Setxattr(context.Context, string, []byte, uint32) syscall.Errno {
	return syscall.EROFS
}

func (node *node) Removexattr(context.Context, string) syscall.Errno { return syscall.EROFS }

func (node *node) Mkdir(context.Context, string, uint32, *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EROFS
}

func (node *node) Mknod(context.Context, string, uint32, uint32, *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EROFS
}

func (node *node) Link(context.Context, fs.InodeEmbedder, string, *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EROFS
}

func (node *node) Symlink(context.Context, string, string, *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.EROFS
}

func (node *node) Create(context.Context, string, uint32, uint32, *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	return nil, nil, 0, syscall.EROFS
}

func (node *node) Unlink(context.Context, string) syscall.Errno { return syscall.EROFS }

func (node *node) Rmdir(context.Context, string) syscall.Errno { return syscall.EROFS }

func (node *node) Rename(context.Context, string, fs.InodeEmbedder, string, uint32) syscall.Errno {
	return syscall.EROFS
}

func (node *node) Write(context.Context, fs.FileHandle, []byte, int64) (uint32, syscall.Errno) {
	return 0, syscall.EROFS
}

func (node *node) Allocate(context.Context, fs.FileHandle, uint64, uint64, uint32) syscall.Errno {
	return syscall.EROFS
}

func (node *node) CopyFileRange(context.Context, fs.FileHandle, uint64, *fs.Inode, fs.FileHandle, uint64, uint64, uint64) (uint32, syscall.Errno) {
	return 0, syscall.EROFS
}

const openSnapshotAttempts = 8

func (n *node) statPinned(ctx context.Context, value string) (s3disk.Entry, snapshotIdentity, error) {
	for range openSnapshotAttempts {
		if err := ctx.Err(); err != nil {
			return s3disk.Entry{}, snapshotIdentity{}, err
		}
		before, beforeOK := n.consumer.CurrentSnapshot()
		if !beforeOK {
			return s3disk.Entry{}, snapshotIdentity{}, s3disk.ErrNoSnapshot
		}
		entry, statErr := n.consumer.Stat(ctx, value)
		after, afterOK := n.consumer.CurrentSnapshot()
		if afterOK && before.Generation == after.Generation && before.Commit == after.Commit {
			return entry, identityOfSnapshot(before), statErr
		}
	}
	return s3disk.Entry{}, snapshotIdentity{}, fmt.Errorf("%w: snapshot changed repeatedly while inspecting %q", s3disk.ErrUnstableFile, value)
}

func (n *node) staleBoundSnapshot() bool {
	if !n.snapshotBound {
		return false
	}
	current, ok := n.consumer.CurrentSnapshot()
	return !ok || n.snapshot != identityOfSnapshot(current)
}

func (n *node) openPinned(ctx context.Context) (*s3disk.File, s3disk.Entry, snapshotIdentity, error) {
	for range openSnapshotAttempts {
		if err := ctx.Err(); err != nil {
			return nil, s3disk.Entry{}, snapshotIdentity{}, err
		}
		before, beforeOK := n.consumer.CurrentSnapshot()
		if !beforeOK {
			return nil, s3disk.Entry{}, snapshotIdentity{}, s3disk.ErrNoSnapshot
		}
		entry, operationErr := n.entry(ctx)
		var file *s3disk.File
		if operationErr == nil {
			file, operationErr = n.consumer.Open(ctx, n.path)
		}
		after, afterOK := n.consumer.CurrentSnapshot()
		if afterOK && before.Generation == after.Generation && before.Commit == after.Commit {
			identity := identityOfSnapshot(before)
			if operationErr != nil {
				return nil, entry, identity, operationErr
			}
			if file.Generation() == before.Generation {
				entry.Size = file.Size()
				return file, entry, identity, nil
			}
		}
	}
	return nil, s3disk.Entry{}, snapshotIdentity{}, fmt.Errorf("%w: snapshot changed repeatedly while opening %q", s3disk.ErrUnstableFile, n.path)
}

func (n *node) listDirPinned(ctx context.Context) ([]s3disk.Entry, snapshotIdentity, error) {
	for range openSnapshotAttempts {
		if err := ctx.Err(); err != nil {
			return nil, snapshotIdentity{}, err
		}
		before, beforeOK := n.consumer.CurrentSnapshot()
		if !beforeOK {
			return nil, snapshotIdentity{}, s3disk.ErrNoSnapshot
		}
		entries, listErr := n.consumer.ListDir(ctx, n.path)
		after, afterOK := n.consumer.CurrentSnapshot()
		if afterOK && before.Generation == after.Generation && before.Commit == after.Commit {
			return entries, identityOfSnapshot(before), listErr
		}
	}
	return nil, snapshotIdentity{}, fmt.Errorf("%w: snapshot changed repeatedly while listing %q", s3disk.ErrUnstableFile, n.path)
}

func (n *node) readlinkPinned(ctx context.Context) (string, snapshotIdentity, error) {
	for range openSnapshotAttempts {
		if err := ctx.Err(); err != nil {
			return "", snapshotIdentity{}, err
		}
		before, beforeOK := n.consumer.CurrentSnapshot()
		if !beforeOK {
			return "", snapshotIdentity{}, s3disk.ErrNoSnapshot
		}
		target, readErr := n.consumer.Readlink(ctx, n.path)
		after, afterOK := n.consumer.CurrentSnapshot()
		if afterOK && before.Generation == after.Generation && before.Commit == after.Commit {
			return target, identityOfSnapshot(before), readErr
		}
	}
	return "", snapshotIdentity{}, fmt.Errorf("%w: snapshot changed repeatedly while reading link %q", s3disk.ErrUnstableFile, n.path)
}

func (n *node) invalidateMaterialized(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	children := n.Children()
	var resultErr error
	currentEntries := make(map[string]s3disk.Entry, len(children))
	if n.entryType == s3disk.EntryDir && len(children) != 0 {
		entries, err := n.consumer.ListDir(ctx, n.path)
		if err != nil {
			return fmt.Errorf("list materialized directory %q: %w", n.path, err)
		}
		for _, entry := range entries {
			if _, materialized := children[entry.Name]; materialized {
				currentEntries[entry.Name] = entry
			}
		}
	}

	childNames := make([]string, 0, len(children))
	for name := range children {
		childNames = append(childNames, name)
	}
	sort.Strings(childNames)
	for _, name := range childNames {
		if err := ctx.Err(); err != nil {
			return invalidationInterrupted(resultErr, err)
		}
		child := children[name]
		childNode, ok := child.Operations().(*node)
		if !ok {
			continue
		}
		entry, exists := currentEntries[name]
		if !exists {
			notifyErr := notificationError("delete entry", path.Join(n.path, name), n.NotifyDelete(name, child))
			resultErr = errors.Join(resultErr, notifyErr)
			continue
		}
		if entry.Type != childNode.entryType {
			notifyErr := notificationError("invalidate changed entry", path.Join(n.path, name), n.NotifyEntry(name))
			resultErr = errors.Join(resultErr, notifyErr)
			continue
		}
		contentErr := notificationError("invalidate content", childNode.path, child.NotifyContent(0, -1))
		entryErr := notificationError("invalidate entry", path.Join(n.path, name), n.NotifyEntry(name))
		resultErr = errors.Join(resultErr, contentErr, entryErr)
		var subtreeErr error
		if childNode.entryType == s3disk.EntryDir {
			if err := childNode.invalidateMaterialized(ctx); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return invalidationInterrupted(resultErr, err)
				}
				subtreeErr = err
				resultErr = errors.Join(resultErr, subtreeErr)
			}
		}
		// A successful entry notification makes the kernel re-run LOOKUP. That
		// callback returns a generation-specific inode and go-fuse replaces the
		// obsolete child atomically. Never call RmChild here: it could remove a
		// concurrently installed new-generation child.
	}
	if err := ctx.Err(); err != nil {
		return invalidationInterrupted(resultErr, err)
	}
	return errors.Join(resultErr, notificationError("invalidate directory content", n.path, n.NotifyContent(0, -1)))
}

func invalidationInterrupted(prior, interrupted error) error {
	return errors.Join(prior, interrupted)
}

func notificationError(operation, value string, notificationErrno syscall.Errno) error {
	if notificationErrno == 0 || notificationErrno == syscall.ENOENT {
		return nil
	}
	return fmt.Errorf("%s %q: %w", operation, value, notificationErrno)
}

func reportInvalidationError(callback func(error), err error) {
	if callback == nil || err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	defer func() { _ = recover() }()
	callback(err)
}

type fileHandle struct {
	file  *s3disk.File
	entry s3disk.Entry
}

func (handle *fileHandle) Read(ctx context.Context, destination []byte, offset int64) (fuse.ReadResult, syscall.Errno) {
	count, err := handle.file.ReadAtContext(ctx, destination, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, errno(err)
	}
	return fuse.ReadResultData(destination[:count]), 0
}

func (handle *fileHandle) Getattr(_ context.Context, out *fuse.AttrOut) syscall.Errno {
	fillEntry(&out.Attr, handle.entry)
	return 0
}

func fillEntry(attribute *fuse.Attr, entry s3disk.Entry) {
	attribute.Mode = typeMode(entry.Type) | entry.Mode
	if entry.Size >= 0 {
		attribute.Size = uint64(entry.Size)
	}
	seconds := entry.ModTime.Unix()
	if seconds >= 0 {
		attribute.Mtime = uint64(seconds)
		attribute.Ctime = uint64(seconds)
		attribute.Atime = uint64(seconds)
		attribute.Atimensec = uint32(entry.ModTime.Nanosecond())
		attribute.Mtimensec = uint32(entry.ModTime.Nanosecond())
		attribute.Ctimensec = uint32(entry.ModTime.Nanosecond())
	}
}

func typeMode(entryType s3disk.EntryType) uint32 {
	switch entryType {
	case s3disk.EntryDir:
		return syscall.S_IFDIR
	case s3disk.EntrySymlink:
		return syscall.S_IFLNK
	default:
		return syscall.S_IFREG
	}
}

func errno(err error) syscall.Errno {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, context.Canceled):
		return syscall.EINTR
	case errors.Is(err, context.DeadlineExceeded):
		// A backend attempt timeout (for example an S3 HTTP request deadline)
		// surfaces here while the mount context is still live; the FUSE op
		// context itself only ever reports Canceled. This is a retryable I/O
		// failure, not a signal interruption, so map it to EIO. EINTR would
		// surface as a spurious hard failure to applications that do not restart
		// interrupted regular-file reads.
		return syscall.EIO
	case errors.Is(err, s3disk.ErrPathNotFound):
		return syscall.ENOENT
	case errors.Is(err, s3disk.ErrObjectNotFound):
		// A referenced immutable object disappearing is a store/integrity
		// failure, not evidence that the filesystem path does not exist.
		return syscall.EIO
	case errors.Is(err, ErrInodeIdentityLimit):
		return syscall.ENOSPC
	case errors.Is(err, s3disk.ErrNotDirectory):
		return syscall.ENOTDIR
	case errors.Is(err, s3disk.ErrIsDirectory):
		return syscall.EISDIR
	case errors.Is(err, s3disk.ErrUnsupportedType):
		return syscall.EINVAL
	default:
		return syscall.EIO
	}
}

var (
	_ fs.NodeLookuper       = (*node)(nil)
	_ fs.NodeGetattrer      = (*node)(nil)
	_ fs.NodeReaddirer      = (*node)(nil)
	_ fs.NodeOpendirer      = (*node)(nil)
	_ fs.NodeOpener         = (*node)(nil)
	_ fs.NodeReadlinker     = (*node)(nil)
	_ fs.NodeSetattrer      = (*node)(nil)
	_ fs.NodeSetxattrer     = (*node)(nil)
	_ fs.NodeRemovexattrer  = (*node)(nil)
	_ fs.NodeMkdirer        = (*node)(nil)
	_ fs.NodeMknoder        = (*node)(nil)
	_ fs.NodeLinker         = (*node)(nil)
	_ fs.NodeSymlinker      = (*node)(nil)
	_ fs.NodeCreater        = (*node)(nil)
	_ fs.NodeUnlinker       = (*node)(nil)
	_ fs.NodeRmdirer        = (*node)(nil)
	_ fs.NodeRenamer        = (*node)(nil)
	_ fs.NodeWriter         = (*node)(nil)
	_ fs.NodeAllocater      = (*node)(nil)
	_ fs.NodeCopyFileRanger = (*node)(nil)
	_ fs.NodeOnForgetter    = (*node)(nil)
	_ fs.FileReader         = (*fileHandle)(nil)
	_ fs.FileGetattrer      = (*fileHandle)(nil)
)
