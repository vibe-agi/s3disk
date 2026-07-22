package syncutil

import (
	"container/list"
	"context"
	"fmt"
	"sync"
)

// WeightedSemaphore is a FIFO byte reservation primitive. Waiters block on
// per-request channels, so cancellation never needs a helper goroutine.
type WeightedSemaphore struct {
	mu       sync.Mutex
	capacity int64
	used     int64
	waiters  list.List
	limitErr error
}

type weightedSemaphoreWaiter struct {
	weight  int64
	ready   chan struct{}
	element *list.Element
	granted bool
}

func NewWeightedSemaphore(capacity int64, limitErr error) *WeightedSemaphore {
	return &WeightedSemaphore{capacity: capacity, limitErr: limitErr}
}

func (semaphore *WeightedSemaphore) Acquire(ctx context.Context, weight int64) error {
	if semaphore == nil || weight <= 0 {
		return fmt.Errorf("%w: invalid download byte reservation", semaphore.limitError())
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
		return fmt.Errorf("%w: download byte reservation %d exceeds budget %d", semaphore.limitError(), weight, semaphore.capacity)
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

func (semaphore *WeightedSemaphore) Release(weight int64) {
	semaphore.mu.Lock()
	if weight <= 0 || weight > semaphore.used {
		semaphore.mu.Unlock()
		panic("s3disk: invalid download byte release")
	}
	semaphore.used -= weight
	semaphore.grantLocked()
	semaphore.mu.Unlock()
}

func (semaphore *WeightedSemaphore) grantLocked() {
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

func (semaphore *WeightedSemaphore) limitError() error {
	if semaphore != nil && semaphore.limitErr != nil {
		return semaphore.limitErr
	}
	return fmt.Errorf("syncutil: reservation exceeds capacity")
}

// Stats returns the current byte usage and queued waiter count atomically.
func (semaphore *WeightedSemaphore) Stats() (used int64, waiters int) {
	if semaphore == nil {
		return 0, 0
	}
	semaphore.mu.Lock()
	defer semaphore.mu.Unlock()
	return semaphore.used, semaphore.waiters.Len()
}

// Capacity returns the immutable reservation capacity.
func (semaphore *WeightedSemaphore) Capacity() int64 {
	if semaphore == nil {
		return 0
	}
	return semaphore.capacity
}
