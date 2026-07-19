package s3disk

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestFlightGroupLoaderPanicReleasesAllWaiters(t *testing.T) {
	t.Parallel()
	var group flightGroup
	digest := digestObject("chunk", []byte("one"))
	entered := make(chan struct{})
	release := make(chan struct{})
	results := make(chan error, 16)
	go func() {
		_, err := group.Do(context.Background(), digest, func(context.Context) ([]byte, error) {
			close(entered)
			<-release
			panic("loader failure")
		})
		results <- err
	}()
	<-entered
	for range 15 {
		go func() {
			_, err := group.Do(context.Background(), digest, func(context.Context) ([]byte, error) {
				t.Error("waiter unexpectedly became a loader")
				return nil, nil
			})
			results <- err
		}()
	}
	deadline := time.Now().Add(time.Second)
	for {
		group.mu.Lock()
		call := group.calls[chunkFlightKey{digest: digest}]
		joined := call != nil && call.waiters == 16
		group.mu.Unlock()
		if joined {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("waiters did not join the shared flight")
		}
		runtime.Gosched()
	}
	close(release)
	for range 16 {
		select {
		case err := <-results:
			if err == nil || !strings.Contains(err.Error(), "loader failure") {
				t.Fatalf("flight result error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("singleflight waiter hung after loader panic")
		}
	}
}

func TestFlightGroupLeaderCancellationDoesNotPoisonFollower(t *testing.T) {
	t.Parallel()
	var group flightGroup
	digest := digestObject("chunk", []byte("shared"))
	entered := make(chan struct{})
	release := make(chan struct{})
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderResult := make(chan error, 1)
	go func() {
		_, err := group.Do(leaderCtx, digest, func(ctx context.Context) ([]byte, error) {
			close(entered)
			select {
			case <-release:
				return []byte("ok"), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
		leaderResult <- err
	}()
	<-entered

	followerResult := make(chan struct {
		data []byte
		err  error
	}, 1)
	go func() {
		data, err := group.Do(context.Background(), digest, func(context.Context) ([]byte, error) {
			t.Error("follower unexpectedly started another loader")
			return nil, nil
		})
		followerResult <- struct {
			data []byte
			err  error
		}{data: data, err: err}
	}()

	deadline := time.Now().Add(time.Second)
	for {
		group.mu.Lock()
		call := group.calls[chunkFlightKey{digest: digest}]
		joined := call != nil && call.waiters == 2
		group.mu.Unlock()
		if joined {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("follower did not join the shared flight")
		}
		runtime.Gosched()
	}
	cancelLeader()
	if err := <-leaderResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v, want context.Canceled", err)
	}
	close(release)
	result := <-followerResult
	if result.err != nil || string(result.data) != "ok" {
		t.Fatalf("follower result = %q, %v, want ok", result.data, result.err)
	}
}
