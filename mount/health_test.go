//go:build linux || darwin || freebsd

package mount

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
)

func TestInvalidationCoordinatorRetriesWithoutAnotherPollResult(t *testing.T) {
	t.Parallel()
	initial := testSnapshotIdentity(1)
	target := testSnapshotIdentity(2)
	current := newControlledSnapshot(initial)
	var attempts atomic.Int32
	retried := make(chan struct{})
	callbackEntered := make(chan struct{})
	releaseCallback := make(chan struct{})
	mounted := newCoordinatorTestMount(initial, current.current, func(context.Context) error {
		if attempts.Add(1) == 1 {
			return errors.New("temporary notification failure")
		}
		select {
		case <-retried:
		default:
			close(retried)
		}
		return nil
	})
	mounted.userError = func(error) {
		close(callbackEntered)
		<-releaseCallback
	}
	mounted.errorEvents = make(chan error, 1)
	mounted.errorStop = make(chan struct{})
	go mounted.runErrorDispatcher()
	defer func() {
		close(releaseCallback)
		mounted.stopErrorDispatcher()
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mounted.runInvalidationCoordinator(ctx)

	current.set(target)
	mounted.observeSnapshot(target, true)
	select {
	case <-callbackEntered:
	case <-time.After(time.Second):
		t.Fatal("invalidation error callback was not invoked")
	}
	select {
	case <-retried:
	case <-time.After(time.Second):
		t.Fatal("invalidation retry was blocked by the customer error callback")
	}
	waitMountCondition(t, func() bool {
		return mounted.Status().NotifiedSnapshot == publicSnapshotIdentity(target)
	}, "advisory notification generation to advance")
	status := mounted.Status()
	if attempts.Load() != 2 {
		t.Fatalf("invalidation attempts = %d, want one failure and one retry", attempts.Load())
	}
	if status.Invalidation.ConsecutiveFailures != 0 || status.Invalidation.LastError != "" ||
		status.InvalidationMode != InvalidationActive {
		t.Fatalf("recovered invalidation status = %+v", status)
	}
	cancel()
	select {
	case <-mounted.invalidationDone:
	case <-time.After(time.Second):
		t.Fatal("invalidation coordinator did not stop after cancellation")
	}
}

func TestInvalidationCoordinatorCoalescesGenerationChangeDuringSweep(t *testing.T) {
	t.Parallel()
	initial := testSnapshotIdentity(1)
	second := testSnapshotIdentity(2)
	latest := testSnapshotIdentity(3)
	current := newControlledSnapshot(initial)
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	var attempts atomic.Int32
	var active atomic.Int32
	var maximumActive atomic.Int32
	mounted := newCoordinatorTestMount(initial, current.current, func(context.Context) error {
		activeNow := active.Add(1)
		for {
			old := maximumActive.Load()
			if activeNow <= old || maximumActive.CompareAndSwap(old, activeNow) {
				break
			}
		}
		defer active.Add(-1)
		if attempts.Add(1) == 1 {
			close(firstEntered)
			<-releaseFirst
		}
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mounted.runInvalidationCoordinator(ctx)

	current.set(second)
	mounted.observeSnapshot(second, true)
	select {
	case <-firstEntered:
	case <-time.After(time.Second):
		t.Fatal("first invalidation sweep did not start")
	}
	current.set(latest)
	mounted.observeSnapshot(latest, true)
	if got := mounted.Status().NotifiedSnapshot; got != publicSnapshotIdentity(initial) {
		t.Fatalf("in-flight mixed sweep prematurely acknowledged %+v", got)
	}
	close(releaseFirst)
	waitMountCondition(t, func() bool {
		return mounted.Status().NotifiedSnapshot == publicSnapshotIdentity(latest)
	}, "latest generation notification sweep")
	if attempts.Load() != 2 {
		t.Fatalf("invalidation attempts = %d, want obsolete sweep plus latest sweep", attempts.Load())
	}
	if maximumActive.Load() != 1 {
		t.Fatalf("concurrent invalidation sweeps = %d, want exactly one", maximumActive.Load())
	}
}

func TestConcurrentUnmountCallersJoinFailedPhysicalAttempt(t *testing.T) {
	t.Parallel()
	want := errors.New("unmount failed")
	server := &joiningUnmountServer{
		firstStarted: make(chan struct{}), releaseFirst: make(chan struct{}),
		results: []error{want, nil},
	}
	var cancelCalls atomic.Int32
	mounted := newUnmountTestMount(server, func() { cancelCalls.Add(1) })

	firstResult := make(chan error, 1)
	go func() { firstResult <- mounted.Unmount() }()
	select {
	case <-server.firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first physical unmount did not start")
	}

	const joiners = 31
	results := make(chan error, joiners)
	for range joiners {
		go func() { results <- mounted.Unmount() }()
	}
	waitMountCondition(t, func() bool {
		mounted.unmountMu.Lock()
		defer mounted.unmountMu.Unlock()
		return mounted.unmountAttempt != nil && mounted.unmountAttempt.waiters == joiners+1
	}, "all concurrent callers to join the in-flight unmount promise")
	close(server.releaseFirst)
	if err := <-firstResult; !errors.Is(err, want) {
		t.Fatalf("first Unmount error = %v, want %v", err, want)
	}
	for range joiners {
		if err := <-results; !errors.Is(err, want) {
			t.Fatalf("joined Unmount error = %v, want %v", err, want)
		}
	}
	if calls := server.calls.Load(); calls != 1 {
		t.Fatalf("physical unmount calls = %d, want one shared failed attempt", calls)
	}
	if cancelCalls.Load() != 0 {
		t.Fatal("failed explicit unmount canceled polling")
	}
	if err := mounted.Unmount(); err != nil {
		t.Fatalf("later retry error = %v", err)
	}
	if calls := server.calls.Load(); calls != 2 {
		t.Fatalf("physical unmount calls after explicit retry = %d, want 2", calls)
	}
	if cancelCalls.Load() != 1 {
		t.Fatalf("successful unmount cancellation calls = %d, want 1", cancelCalls.Load())
	}
}

func TestServerMonitorDoesNotDeadlockBehindBlockedUnmount(t *testing.T) {
	t.Parallel()
	server := &blockedUnmountServer{
		serveDone: make(chan struct{}), unmountStarted: make(chan struct{}),
		releaseUnmount: make(chan struct{}),
	}
	mounted := newUnmountTestMount(server, func() {})
	mounted.serverDone = make(chan struct{})
	go mounted.monitorServer()

	result := make(chan error, 1)
	go func() { result <- mounted.Unmount() }()
	select {
	case <-server.unmountStarted:
	case <-time.After(time.Second):
		t.Fatal("physical unmount did not block")
	}
	close(server.serveDone)
	select {
	case <-mounted.serverDone:
	case <-time.After(time.Second):
		t.Fatal("monitorServer was blocked behind the in-flight unmount mutex")
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Unmount after externally observed stop = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Unmount joiner was not released by external server stop")
	}
	if status := mounted.Status(); status.Lifecycle != LifecycleStopped {
		t.Fatalf("lifecycle = %q, want stopped", status.Lifecycle)
	}
	close(server.releaseUnmount)
}

func TestAutomaticUnmountHasFiniteTimeoutAndObservableFailure(t *testing.T) {
	t.Parallel()
	server := &joiningUnmountServer{results: []error{errors.New("permanent unmount failure")}}
	var cancelCalls atomic.Int32
	mounted := newUnmountTestMount(server, func() { cancelCalls.Add(1) })
	mounted.autoUnmountTimeout = 20 * time.Millisecond
	mounted.unmountRetryMin = time.Millisecond
	mounted.unmountRetryMax = 2 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	finished := make(chan struct{})
	go func() {
		mounted.unmountOnLifetimeDone(ctx)
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("automatic unmount exceeded its configured timeout")
	}
	status := mounted.Status()
	if status.Lifecycle != LifecycleStopFailed || status.Unmount.ConsecutiveFailures == 0 ||
		!strings.Contains(status.Unmount.LastError, "automatic unmount") {
		t.Fatalf("automatic unmount failure status = %+v", status)
	}
	if server.calls.Load() < 2 {
		t.Fatalf("automatic physical attempts = %d, want retries before timeout", server.calls.Load())
	}
	if cancelCalls.Load() != 1 {
		t.Fatalf("poll cancellation calls = %d, want 1", cancelCalls.Load())
	}
}

func TestCompletedStopCannotBeMisclassifiedAsAutomatic(t *testing.T) {
	t.Parallel()
	mounted := &Mount{
		unmounted: make(chan struct{}),
		status: MountStatus{
			Lifecycle: LifecycleRunning,
		},
	}
	mounted.publishServerStopped()
	if mounted.beginAutomaticUnmount(AutomaticUnmountReasonAuthorizationExpired) {
		t.Fatal("automatic stop claimed a mount already published as stopped")
	}
	if reason := mounted.Status().AutomaticUnmountReason; reason != AutomaticUnmountReasonNone {
		t.Fatalf("completed stop was mislabeled with automatic reason %q", reason)
	}
}

func TestStatusAndWaitContextAreConcurrentSafeSnapshots(t *testing.T) {
	t.Parallel()
	finished := make(chan struct{})
	mounted := &Mount{
		finished: finished,
		status: MountStatus{
			Lifecycle: LifecycleRunning, Polling: true,
			InvalidationMode: InvalidationActive,
			Refresh:          ComponentStatus{LastError: "original"},
		},
	}
	status := mounted.Status()
	status.Refresh.LastError = "mutated copy"
	if got := mounted.Status().Refresh.LastError; got != "original" {
		t.Fatalf("Status returned aliased state: %q", got)
	}
	waitContext, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := mounted.WaitContext(waitContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitContext before completion = %v, want deadline exceeded", err)
	}
	close(finished)
	if err := mounted.WaitContext(context.Background()); err != nil {
		t.Fatalf("WaitContext after completion = %v", err)
	}
	select {
	case <-mounted.Done():
	default:
		t.Fatal("Done remained open after completion")
	}
}

func TestRefreshContextErrorIsFailureWhileMountContextIsLive(t *testing.T) {
	t.Parallel()
	for name, sentinel := range map[string]error{
		"attempt canceled": context.Canceled,
		"attempt deadline": context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pollContext, cancel := context.WithCancel(context.Background())
			reported := make(chan error, 1)
			mounted := &Mount{
				status: MountStatus{
					Lifecycle: LifecycleRunning, Polling: true,
					InvalidationMode: InvalidationActive,
				},
				userError: func(err error) { reported <- err },
			}
			operationErr := fmt.Errorf("store request failed: %w", sentinel)
			mounted.handleRefreshFailure(pollContext, operationErr)

			status := mounted.Status()
			if status.Refresh.ConsecutiveFailures != 1 || status.Refresh.LastAttempt.IsZero() ||
				!strings.Contains(status.Refresh.LastError, "store request failed") {
				t.Fatalf("refresh failure status = %+v", status.Refresh)
			}
			if status.Healthy() {
				t.Fatal("mount remained healthy after an operation-level context failure")
			}
			select {
			case got := <-reported:
				if !errors.Is(got, sentinel) {
					t.Fatalf("OnError received %v, want error wrapping %v", got, sentinel)
				}
			default:
				t.Fatal("operation-level context failure did not reach OnError")
			}

			// Once the mount's own poll context has ended, the same sentinel is
			// terminal cancellation rather than a store-health observation.
			before := mounted.Status().Refresh
			cancel()
			mounted.handleRefreshFailure(pollContext, operationErr)
			if after := mounted.Status().Refresh; after != before {
				t.Fatalf("terminal cancellation changed refresh status: before=%+v after=%+v", before, after)
			}
			select {
			case got := <-reported:
				t.Fatalf("terminal cancellation unexpectedly reached OnError: %v", got)
			default:
			}
		})
	}
}

func TestMountStatusHealthyAtRefreshAge(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.July, 18, 12, 0, 0, 0, time.UTC)
	identity := SnapshotIdentity{Generation: 1, Commit: s3disk.Digest{1}}
	base := MountStatus{
		Lifecycle:        LifecycleRunning,
		ObservedSnapshot: identity,
		NotifiedSnapshot: identity,
		InvalidationMode: InvalidationActive,
		Polling:          true,
	}

	tests := []struct {
		name       string
		last       time.Time
		maximumAge time.Duration
		degraded   bool
		want       bool
	}{
		{name: "within bound", last: now.Add(-4 * time.Minute), maximumAge: 5 * time.Minute, want: true},
		{name: "inclusive boundary", last: now.Add(-5 * time.Minute), maximumAge: 5 * time.Minute, want: true},
		{name: "older than boundary", last: now.Add(-5*time.Minute - time.Nanosecond), maximumAge: 5 * time.Minute},
		{name: "future clock skew", last: now.Add(time.Hour), maximumAge: time.Nanosecond, want: true},
		{name: "zero maximum age", last: now, maximumAge: 0},
		{name: "negative maximum age", last: now, maximumAge: -time.Nanosecond},
		{name: "missing last success", maximumAge: 5 * time.Minute},
		{name: "component failure", last: now, maximumAge: 5 * time.Minute, degraded: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status := base
			status.Refresh.LastSuccess = test.last
			if test.degraded {
				status.Refresh.ConsecutiveFailures = 1
				status.Refresh.LastError = "refresh failed"
			}
			if got := status.HealthyAt(now, test.maximumAge); got != test.want {
				t.Fatalf("HealthyAt(%v, %v) = %t, want %t; status=%+v", now, test.maximumAge, got, test.want, status)
			}
		})
	}

	stale := base
	stale.Refresh.LastSuccess = now.Add(-time.Hour)
	if !stale.Healthy() {
		t.Fatal("Healthy changed its age-independent compatibility semantics")
	}
	if stale.HealthyAt(now, time.Minute) {
		t.Fatal("HealthyAt accepted a structurally healthy but stale refresh")
	}

	expired := base
	expired.Refresh.LastSuccess = now
	expired.AuthorizationExpiresAt = now
	if !expired.Healthy() {
		t.Fatal("Healthy changed its time-independent structural semantics at authorization expiry")
	}
	if expired.HealthyAt(now, time.Minute) {
		t.Fatal("HealthyAt accepted a mount at its authorization-expiry boundary")
	}
	expired.AuthorizationExpiresAt = now.Add(time.Nanosecond)
	if !expired.HealthyAt(now, time.Minute) {
		t.Fatal("HealthyAt rejected a mount immediately before authorization expiry")
	}
}

func TestNormalizeOptionsBoundsAutomaticUnmountTimeout(t *testing.T) {
	t.Parallel()
	if _, err := normalizeOptions(Options{AutoUnmountTimeout: -time.Nanosecond}); err == nil {
		t.Fatal("normalizeOptions accepted a negative automatic unmount timeout")
	}
	normalized, err := normalizeOptions(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if normalized.AutoUnmountTimeout != DefaultAutoUnmountTimeout {
		t.Fatalf("default automatic unmount timeout = %v, want %v", normalized.AutoUnmountTimeout, DefaultAutoUnmountTimeout)
	}
}

type controlledSnapshot struct {
	mu       sync.RWMutex
	identity snapshotIdentity
}

func newControlledSnapshot(identity snapshotIdentity) *controlledSnapshot {
	return &controlledSnapshot{identity: identity}
}

func (snapshot *controlledSnapshot) current() (snapshotIdentity, bool) {
	snapshot.mu.RLock()
	defer snapshot.mu.RUnlock()
	return snapshot.identity, true
}

func (snapshot *controlledSnapshot) set(identity snapshotIdentity) {
	snapshot.mu.Lock()
	snapshot.identity = identity
	snapshot.mu.Unlock()
}

func testSnapshotIdentity(generation uint64) snapshotIdentity {
	return snapshotIdentity{generation: generation, commit: s3disk.Digest{byte(generation)}}
}

func newCoordinatorTestMount(initial snapshotIdentity, current func() (snapshotIdentity, bool), invalidate func(context.Context) error) *Mount {
	return &Mount{
		status: MountStatus{
			Lifecycle: LifecycleRunning, Polling: true,
			ObservedSnapshot: publicSnapshotIdentity(initial), NotifiedSnapshot: publicSnapshotIdentity(initial),
			InvalidationMode: InvalidationActive,
		},
		invalidationWake: make(chan struct{}, 1), invalidationDone: make(chan struct{}),
		currentSnapshot: current, invalidate: invalidate,
		invalidationRetryMin: time.Millisecond, invalidationRetryMax: 4 * time.Millisecond,
	}
}

func waitMountCondition(t *testing.T, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

type joiningUnmountServer struct {
	results      []error
	calls        atomic.Int32
	firstStarted chan struct{}
	releaseFirst chan struct{}
}

func (*joiningUnmountServer) Wait() {}

func (server *joiningUnmountServer) Unmount() error {
	call := int(server.calls.Add(1))
	if call == 1 && server.firstStarted != nil {
		close(server.firstStarted)
		<-server.releaseFirst
	}
	if call <= len(server.results) {
		return server.results[call-1]
	}
	if len(server.results) != 0 {
		return server.results[len(server.results)-1]
	}
	return nil
}

type blockedUnmountServer struct {
	serveDone      chan struct{}
	unmountStarted chan struct{}
	releaseUnmount chan struct{}
}

func (server *blockedUnmountServer) Wait() { <-server.serveDone }

func (server *blockedUnmountServer) Unmount() error {
	close(server.unmountStarted)
	<-server.releaseUnmount
	return errors.New("late unmount failure")
}

func newUnmountTestMount(server mountServer, cancel context.CancelFunc) *Mount {
	return &Mount{
		server: server, cancel: cancel, unmounted: make(chan struct{}),
		status: MountStatus{
			Lifecycle: LifecycleRunning, Polling: true,
			InvalidationMode: InvalidationActive,
		},
		unmountRetryMin: time.Millisecond, unmountRetryMax: 4 * time.Millisecond,
	}
}
