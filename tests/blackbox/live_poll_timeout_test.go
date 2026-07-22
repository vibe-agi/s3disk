package s3disk_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestConsumerPollBoundsAndObservesEachRefreshAttempt(t *testing.T) {
	t.Parallel()
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()

	store := &hookedStore{base: memstore.New()}
	store.get = func(ctx context.Context, _ string, _ s3disk.GetOptions) (s3disk.Object, error) {
		<-ctx.Done()
		return s3disk.Object{}, ctx.Err()
	}
	repository, err := s3disk.NewRepository(store, "poll-attempt-timeout")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}

	attempts := make(chan time.Time, 1)
	failures := make(chan error, 1)
	done := make(chan error, 1)
	go func() {
		done <- consumer.Poll(parent, s3disk.PollOptions{
			Interval:       time.Second,
			AttemptTimeout: 20 * time.Millisecond,
			JitterFraction: -1,
			OnAttempt: func() {
				attempts <- time.Now()
			},
			OnError: func(err error) {
				failures <- err
				cancelParent()
			},
		})
	}()

	started := <-attempts
	select {
	case err := <-failures:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("attempt error = %v, want context.DeadlineExceeded", err)
		}
		if elapsed := time.Since(started); elapsed < 15*time.Millisecond || elapsed > time.Second {
			t.Fatalf("attempt timeout elapsed = %v, want a bounded timeout near 20ms", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("hung refresh attempt was not canceled")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Poll stopped with %v, want parent cancellation", err)
	}
}

func TestPollAttemptTimeoutValidation(t *testing.T) {
	t.Parallel()
	if err := (s3disk.PollOptions{}).Validate(); err != nil {
		t.Fatalf("zero-value PollOptions = %v", err)
	}
	for _, timeout := range []time.Duration{-time.Nanosecond, s3disk.MaximumPollAttemptTimeout + time.Nanosecond} {
		if err := (s3disk.PollOptions{AttemptTimeout: timeout}).Validate(); err == nil {
			t.Fatalf("AttemptTimeout %v was accepted", timeout)
		}
	}
}

func TestRefreshDeadlineIncludesWaitingForConcurrentRefresh(t *testing.T) {
	t.Parallel()
	store := &hookedStore{base: memstore.New()}
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	store.get = func(context.Context, string, s3disk.GetOptions) (s3disk.Object, error) {
		entered <- struct{}{}
		<-release
		return s3disk.Object{}, errors.New("injected first refresh failure")
	}
	repository, err := s3disk.NewRepository(store, "refresh-gate-timeout")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}

	firstDone := make(chan error, 1)
	go func() {
		_, err := consumer.Refresh(context.Background())
		firstDone <- err
	}()
	<-entered

	waitContext, cancelWait := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelWait()
	started := time.Now()
	_, err = consumer.Refresh(waitContext)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued Refresh error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(started); elapsed < 15*time.Millisecond || elapsed > time.Second {
		t.Fatalf("queued Refresh cancellation elapsed = %v", elapsed)
	}
	select {
	case <-entered:
		t.Fatal("timed-out queued Refresh reached the object store")
	default:
	}
	close(release)
	if err := <-firstDone; err == nil {
		t.Fatal("first Refresh unexpectedly succeeded")
	}
}
