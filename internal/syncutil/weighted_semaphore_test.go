package syncutil

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWeightedSemaphoreCancellationRemovesWaiter(t *testing.T) {
	limitErr := errors.New("test resource limit")
	semaphore := NewWeightedSemaphore(10, limitErr)
	if err := semaphore.Acquire(t.Context(), 10); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- semaphore.Acquire(ctx, 6) }()
	waitForSemaphoreWaiters(t, semaphore, 1)
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled acquire error = %v, want context.Canceled", err)
	}
	used, waiters := semaphore.Stats()
	if waiters != 0 || used != 10 {
		t.Fatalf("after cancellation waiters=%d used=%d, want 0 and 10", waiters, used)
	}
	semaphore.Release(10)
	if err := semaphore.Acquire(t.Context(), 10); err != nil {
		t.Fatalf("acquire after canceled waiter: %v", err)
	}
	semaphore.Release(10)
}

func TestWeightedSemaphoreWrapsConfiguredLimit(t *testing.T) {
	limitErr := errors.New("test resource limit")
	semaphore := NewWeightedSemaphore(10, limitErr)
	if err := semaphore.Acquire(t.Context(), 11); !errors.Is(err, limitErr) {
		t.Fatalf("oversized acquire error = %v, want configured limit", err)
	}
}

func waitForSemaphoreWaiters(t *testing.T, semaphore *WeightedSemaphore, count int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, got := semaphore.Stats()
		if got == count {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("semaphore waiters = %d, want %d", got, count)
		}
		time.Sleep(time.Millisecond)
	}
}
