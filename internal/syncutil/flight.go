package syncutil

import (
	"context"
	"fmt"
	"sync"
)

// BytesLease keeps the shared download reservation alive while a caller reads
// data. Every successful flight waiter owns exactly one release acknowledgment.
type BytesLease struct {
	data    []byte
	release func()
	once    sync.Once
}

func (lease *BytesLease) Release() {
	if lease == nil {
		return
	}
	lease.once.Do(func() {
		release := lease.release
		lease.data = nil
		lease.release = nil
		release()
	})
}

// Data returns the shared immutable bytes held by the lease.
func (lease *BytesLease) Data() []byte {
	if lease == nil {
		return nil
	}
	return lease.data
}

type FlightLoad func(context.Context) (data []byte, release func(), err error)

type flightCall struct {
	done   chan struct{}
	data   []byte
	err    error
	cancel context.CancelFunc
	users  int

	completed       bool
	finalized       bool
	resourceRelease func()
	afterRelease    func()
}

type FlightGroup[K comparable] struct {
	mu    sync.Mutex
	calls map[K]*flightCall
}

// Do joins one digest+size load. A successful caller must release its lease
// after it has finished reading the shared byte slice.
func (group *FlightGroup[K]) Do(ctx context.Context, key K, load FlightLoad, afterRelease func()) (*BytesLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	group.mu.Lock()
	if group.calls == nil {
		group.calls = make(map[K]*flightCall)
	}
	if existing := group.calls[key]; existing != nil {
		if existing.users > 0 {
			existing.users++
			group.mu.Unlock()
			return group.wait(ctx, existing)
		}
		// All callers abandoned this loader and canceled its context. A later
		// caller must not inherit that canceled operation while it winds down.
		delete(group.calls, key)
	}
	loadCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	call := &flightCall{
		done:         make(chan struct{}),
		cancel:       cancel,
		users:        1,
		afterRelease: afterRelease,
	}
	group.calls[key] = call
	group.mu.Unlock()
	go group.run(key, call, loadCtx, load)
	return group.wait(ctx, call)
}

func (group *FlightGroup[K]) run(key K, call *flightCall, ctx context.Context, load FlightLoad) {
	var data []byte
	var resourceRelease func()
	var loadErr error
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				loadErr = fmt.Errorf("s3disk: chunk loader panic: %v", recovered)
			}
		}()
		data, resourceRelease, loadErr = load(ctx)
	}()

	group.mu.Lock()
	if loadErr == nil {
		call.data = data
	}
	call.err = loadErr
	call.resourceRelease = resourceRelease
	call.completed = true
	if group.calls[key] == call {
		delete(group.calls, key)
	}
	finalize := group.takeFinalizerLocked(call)
	group.mu.Unlock()
	call.cancel()
	if finalize != nil {
		finalize()
	}
	close(call.done)
}

func (group *FlightGroup[K]) wait(ctx context.Context, call *flightCall) (*BytesLease, error) {
	select {
	case <-call.done:
		if call.err != nil {
			return nil, call.err
		}
		return &BytesLease{
			data: call.data,
			release: func() {
				group.releaseUser(call)
			},
		}, nil
	case <-ctx.Done():
		group.abandon(call)
		return nil, ctx.Err()
	}
}

func (group *FlightGroup[K]) releaseUser(call *flightCall) {
	group.mu.Lock()
	if call.users <= 0 {
		group.mu.Unlock()
		panic("s3disk: chunk flight released without a user")
	}
	call.users--
	if call.users == 0 {
		call.data = nil
	}
	finalize := group.takeFinalizerLocked(call)
	group.mu.Unlock()
	if finalize != nil {
		finalize()
	}
}

func (group *FlightGroup[K]) abandon(call *flightCall) {
	group.mu.Lock()
	if call.users <= 0 {
		group.mu.Unlock()
		return
	}
	call.users--
	if call.completed && call.users == 0 {
		call.data = nil
	}
	cancel := !call.completed && call.users == 0
	finalize := group.takeFinalizerLocked(call)
	group.mu.Unlock()
	if cancel {
		call.cancel()
	}
	if finalize != nil {
		finalize()
	}
}

// takeFinalizerLocked transfers finalization ownership exactly once. Successful
// data stays reserved until its last user acknowledges consumption. Failed
// loads never expose data and can be finalized immediately.
func (group *FlightGroup[K]) takeFinalizerLocked(call *flightCall) func() {
	if call.finalized || !call.completed || (call.err == nil && call.users > 0) {
		return nil
	}
	call.finalized = true
	resourceRelease := call.resourceRelease
	afterRelease := call.afterRelease
	call.resourceRelease = nil
	call.afterRelease = nil
	return func() {
		if resourceRelease != nil {
			resourceRelease()
		}
		if afterRelease != nil {
			// Error observers are best effort. A callback panic must not strand
			// another resource waiter after the reservation was released.
			func() {
				defer func() { _ = recover() }()
				afterRelease()
			}()
		}
	}
}

// Users reports the waiter count for an active load. It returns zero after the
// loader completes, even while returned leases still retain the result.
func (group *FlightGroup[K]) Users(key K) int {
	group.mu.Lock()
	defer group.mu.Unlock()
	if call := group.calls[key]; call != nil {
		return call.users
	}
	return 0
}
