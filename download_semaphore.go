package s3disk

import (
	"container/list"
	"context"
	"fmt"
	"sync"
)

// weightedSemaphore is a FIFO byte reservation primitive. Waiters block on
// per-request channels, so cancellation never needs a helper goroutine.
type weightedSemaphore struct {
	mu       sync.Mutex
	capacity int64
	used     int64
	waiters  list.List
}

type weightedSemaphoreWaiter struct {
	weight  int64
	ready   chan struct{}
	element *list.Element
	granted bool
}

func newWeightedSemaphore(capacity int64) *weightedSemaphore {
	return &weightedSemaphore{capacity: capacity}
}

func (semaphore *weightedSemaphore) Acquire(ctx context.Context, weight int64) error {
	if semaphore == nil || weight <= 0 {
		return fmt.Errorf("%w: invalid download byte reservation", ErrResourceLimit)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	semaphore.mu.Lock()
	if err := ctx.Err(); err != nil {
		semaphore.mu.Unlock()
		return err
	}
	if weight > semaphore.capacity {
		semaphore.mu.Unlock()
		return fmt.Errorf("%w: download byte reservation %d exceeds budget %d", ErrResourceLimit, weight, semaphore.capacity)
	}
	if semaphore.waiters.Len() == 0 && weight <= semaphore.capacity-semaphore.used {
		semaphore.used += weight
		semaphore.mu.Unlock()
		return nil
	}
	waiter := &weightedSemaphoreWaiter{weight: weight, ready: make(chan struct{})}
	waiter.element = semaphore.waiters.PushBack(waiter)
	semaphore.mu.Unlock()

	select {
	case <-waiter.ready:
		return nil
	case <-ctx.Done():
		semaphore.mu.Lock()
		if waiter.granted {
			// The grant raced with cancellation. Give the reservation directly
			// to the next waiter instead of making this canceled caller use it.
			semaphore.used -= waiter.weight
		} else if waiter.element != nil {
			semaphore.waiters.Remove(waiter.element)
			waiter.element = nil
		}
		semaphore.grantLocked()
		semaphore.mu.Unlock()
		return ctx.Err()
	}
}

func (semaphore *weightedSemaphore) Release(weight int64) {
	semaphore.mu.Lock()
	if weight <= 0 || weight > semaphore.used {
		semaphore.mu.Unlock()
		panic("s3disk: invalid download byte release")
	}
	semaphore.used -= weight
	semaphore.grantLocked()
	semaphore.mu.Unlock()
}

func (semaphore *weightedSemaphore) grantLocked() {
	for {
		element := semaphore.waiters.Front()
		if element == nil {
			return
		}
		waiter := element.Value.(*weightedSemaphoreWaiter)
		if waiter.weight > semaphore.capacity-semaphore.used {
			return
		}
		semaphore.waiters.Remove(element)
		waiter.element = nil
		waiter.granted = true
		semaphore.used += waiter.weight
		close(waiter.ready)
	}
}
