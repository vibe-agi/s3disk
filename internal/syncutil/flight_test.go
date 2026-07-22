package syncutil

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestFlightGroupCoalescesAndReleasesAfterLastLease(t *testing.T) {
	var group FlightGroup[string]
	entered := make(chan struct{})
	finish := make(chan struct{})
	released := make(chan struct{})
	var loads atomic.Int32
	load := func(context.Context) ([]byte, func(), error) {
		if loads.Add(1) == 1 {
			close(entered)
		}
		<-finish
		return []byte("shared"), func() { close(released) }, nil
	}

	results := make(chan *BytesLease, 2)
	for range 2 {
		go func() {
			lease, err := group.Do(t.Context(), "key", load, nil)
			if err != nil {
				t.Errorf("Do: %v", err)
			}
			results <- lease
		}()
	}
	<-entered
	waitForFlightUsers(t, &group, "key", 2)
	close(finish)
	first, second := <-results, <-results
	if loads.Load() != 1 {
		t.Fatalf("loads = %d, want 1", loads.Load())
	}
	if string(first.Data()) != "shared" || string(second.Data()) != "shared" {
		t.Fatal("joined leases did not expose the shared result")
	}
	first.Release()
	select {
	case <-released:
		t.Fatal("resource released before the final lease")
	default:
	}
	second.Release()
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatal("resource was not released after the final lease")
	}
}

func waitForFlightUsers[K comparable](t *testing.T, group *FlightGroup[K], key K, count int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for group.Users(key) != count {
		if time.Now().After(deadline) {
			t.Fatalf("flight users = %d, want %d", group.Users(key), count)
		}
		time.Sleep(time.Millisecond)
	}
}
