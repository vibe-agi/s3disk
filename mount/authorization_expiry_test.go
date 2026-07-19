//go:build linux || darwin || freebsd

package mount

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestExpiredAuthorizationFailsBeforeFUSEStarts(t *testing.T) {
	t.Parallel()
	consumer, reader := newAuthorizationMountConsumer(t, time.Now().Add(-time.Minute), true)
	var mountCalls atomic.Int32
	mounter := func(string, fs.InodeEmbedder, *fs.Options) (mountServer, error) {
		mountCalls.Add(1)
		return nil, errors.New("FUSE must not start")
	}

	mounted, err := readOnlyWithMounter(
		context.Background(), consumer, t.TempDir(), authorizationMountOptions(), mounter,
	)
	if mounted != nil || !errors.Is(err, ErrAuthorizationExpired) {
		t.Fatalf("ReadOnly = (%v, %v), want (nil, ErrAuthorizationExpired)", mounted, err)
	}
	if calls := mountCalls.Load(); calls != 0 {
		t.Fatalf("FUSE mount calls = %d, want zero", calls)
	}
	if inspections := reader.inspections.Load(); inspections != 1 {
		t.Fatalf("authorization inspections = %d, want one after initial refresh", inspections)
	}
}

func TestAuthorizationExpiryAutomaticallyUnmountsAndCannotBeExtended(t *testing.T) {
	t.Parallel()
	consumer, reader := newAuthorizationMountConsumer(t, time.Now().Add(time.Hour), true)
	expiresAt := time.Now().Add(250 * time.Millisecond)
	reader.setExpiry(expiresAt, true)
	server := newLifetimeMountServer()

	mounted, err := readOnlyWithMounter(
		context.Background(), consumer, t.TempDir(), authorizationMountOptions(),
		func(string, fs.InodeEmbedder, *fs.Options) (mountServer, error) { return server, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := mounted.Status().AuthorizationExpiresAt; !got.Equal(expiresAt) {
		t.Fatalf("authorization expiry = %v, want %v", got, expiresAt)
	}

	// Changing the reader's advertised expiry after mount creation must not
	// renew an already-issued share. A newly authorized session needs a remount.
	reader.setExpiry(time.Now().Add(time.Hour), true)
	waitCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := mounted.WaitContext(waitCtx); err != nil {
		t.Fatalf("WaitContext: %v", err)
	}
	if time.Now().Before(expiresAt) {
		t.Fatalf("mount stopped before its authorization deadline %v", expiresAt)
	}
	if calls := server.unmountCalls.Load(); calls != 1 {
		t.Fatalf("physical unmount calls = %d, want one", calls)
	}
	status := mounted.Status()
	if status.AutomaticUnmountReason != AutomaticUnmountReasonAuthorizationExpired {
		t.Fatalf("automatic unmount reason = %q, want %q", status.AutomaticUnmountReason, AutomaticUnmountReasonAuthorizationExpired)
	}
	if !status.AuthorizationExpiresAt.Equal(expiresAt) {
		t.Fatalf("recorded authorization expiry changed to %v, want immutable %v", status.AuthorizationExpiresAt, expiresAt)
	}
	if inspections := reader.inspections.Load(); inspections != 1 {
		t.Fatalf("authorization inspections = %d, want one immutable mount deadline", inspections)
	}
}

func TestReadOnlyContextStillEndsMountWithEarlierOrUnknownAuthorization(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		expiresAt time.Time
		known     bool
	}{
		{name: "context earlier than authorization", expiresAt: time.Now().Add(time.Hour), known: true},
		{name: "no authorization expiry", known: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			consumer, _ := newAuthorizationMountConsumer(t, test.expiresAt, test.known)
			server := newLifetimeMountServer()
			ctx, cancel := context.WithCancel(context.Background())
			mounted, err := readOnlyWithMounter(
				ctx, consumer, t.TempDir(), authorizationMountOptions(),
				func(string, fs.InodeEmbedder, *fs.Options) (mountServer, error) { return server, nil },
			)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			cancel()
			waitCtx, waitCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer waitCancel()
			if err := mounted.WaitContext(waitCtx); err != nil {
				t.Fatalf("WaitContext: %v", err)
			}
			status := mounted.Status()
			if status.AutomaticUnmountReason != AutomaticUnmountReasonContextDone {
				t.Fatalf("automatic unmount reason = %q, want %q", status.AutomaticUnmountReason, AutomaticUnmountReasonContextDone)
			}
			if test.known {
				if !status.AuthorizationExpiresAt.Equal(test.expiresAt) {
					t.Fatalf("authorization expiry = %v, want %v", status.AuthorizationExpiresAt, test.expiresAt)
				}
			} else if !status.AuthorizationExpiresAt.IsZero() {
				t.Fatalf("unknown authorization recorded deadline %v", status.AuthorizationExpiresAt)
			}
		})
	}
}

func TestEarlierParentDeadlineReportsContextDone(t *testing.T) {
	t.Parallel()
	expiresAt := time.Now().Add(time.Hour)
	consumer, _ := newAuthorizationMountConsumer(t, expiresAt, true)
	server := newLifetimeMountServer()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	mounted, err := readOnlyWithMounter(
		ctx, consumer, t.TempDir(), authorizationMountOptions(),
		func(string, fs.InodeEmbedder, *fs.Options) (mountServer, error) { return server, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer waitCancel()
	if err := mounted.WaitContext(waitCtx); err != nil {
		t.Fatalf("WaitContext: %v", err)
	}
	status := mounted.Status()
	if status.AutomaticUnmountReason != AutomaticUnmountReasonContextDone {
		t.Fatalf("automatic unmount reason = %q, want earlier parent context", status.AutomaticUnmountReason)
	}
	if !status.AuthorizationExpiresAt.Equal(expiresAt) {
		t.Fatalf("authorization expiry = %v, want later deadline %v", status.AuthorizationExpiresAt, expiresAt)
	}
	if calls := server.unmountCalls.Load(); calls != 1 {
		t.Fatalf("physical unmount calls = %d, want one", calls)
	}
}

func TestExplicitUnmountIsNotMisclassifiedAsAutomatic(t *testing.T) {
	t.Parallel()
	expiresAt := time.Now().Add(time.Hour)
	consumer, _ := newAuthorizationMountConsumer(t, expiresAt, true)
	server := newLifetimeMountServer()
	mounted, err := readOnlyWithMounter(
		context.Background(), consumer, t.TempDir(), authorizationMountOptions(),
		func(string, fs.InodeEmbedder, *fs.Options) (mountServer, error) { return server, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := mounted.Unmount(); err != nil {
		t.Fatalf("Unmount: %v", err)
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := mounted.WaitContext(waitCtx); err != nil {
		t.Fatalf("WaitContext: %v", err)
	}
	status := mounted.Status()
	if status.AutomaticUnmountReason != AutomaticUnmountReasonNone {
		t.Fatalf("explicit unmount reason = %q, want empty automatic reason", status.AutomaticUnmountReason)
	}
	if !status.AuthorizationExpiresAt.Equal(expiresAt) {
		t.Fatalf("authorization expiry = %v, want %v", status.AuthorizationExpiresAt, expiresAt)
	}
	if calls := server.unmountCalls.Load(); calls != 1 {
		t.Fatalf("physical unmount calls = %d, want one", calls)
	}
}

func TestMountLifetimeUsesEarlierParentDeadline(t *testing.T) {
	t.Parallel()
	now := time.Now()
	parentDeadline := now.Add(time.Minute)
	parent, cancelParent := context.WithDeadline(context.Background(), parentDeadline)
	defer cancelParent()
	lifetime, cancelLifetime, err := newMountLifetimeContext(
		parent, now.Add(time.Hour), true, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelLifetime()
	got, ok := lifetime.Deadline()
	if !ok || !got.Equal(parentDeadline) {
		t.Fatalf("lifetime deadline = (%v, %t), want earlier parent deadline %v", got, ok, parentDeadline)
	}
}

func newAuthorizationMountConsumer(
	t *testing.T,
	expiresAt time.Time,
	known bool,
) (*s3disk.Consumer, *mutableAuthorizationReader) {
	t.Helper()
	store := memstore.New()
	prefix := "mount-authorization-expiry-" + t.Name()
	writable, err := s3disk.NewRepository(store, prefix)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(writable, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	if err := os.WriteFile(source+"/shared.txt", []byte("short-lived share"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(context.Background(), source, "main"); err != nil {
		t.Fatal(err)
	}
	reader := &mutableAuthorizationReader{reader: store, expiresAt: expiresAt, known: known}
	readOnly, err := s3disk.NewReadOnlyRepository(reader, prefix)
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(readOnly, "main", s3disk.ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return consumer, reader
}

func authorizationMountOptions() Options {
	return Options{
		DangerouslyAllowMountWithoutDurableWatermark: true,
		AutoUnmountTimeout:                           time.Second,
		Poll: s3disk.PollOptions{
			Interval:       10 * time.Millisecond,
			MaxInterval:    10 * time.Millisecond,
			JitterFraction: -1,
		},
	}
}

type mutableAuthorizationReader struct {
	reader      s3disk.ObjectReader
	mu          sync.RWMutex
	expiresAt   time.Time
	known       bool
	inspections atomic.Int32
}

func (reader *mutableAuthorizationReader) Get(
	ctx context.Context,
	key string,
	options s3disk.GetOptions,
) (s3disk.Object, error) {
	return reader.reader.Get(ctx, key, options)
}

func (reader *mutableAuthorizationReader) AuthorizationExpiry() (time.Time, bool) {
	reader.inspections.Add(1)
	reader.mu.RLock()
	defer reader.mu.RUnlock()
	return reader.expiresAt, reader.known
}

func (reader *mutableAuthorizationReader) setExpiry(expiresAt time.Time, known bool) {
	reader.mu.Lock()
	reader.expiresAt = expiresAt
	reader.known = known
	reader.mu.Unlock()
}

type lifetimeMountServer struct {
	stopped      chan struct{}
	stopOnce     sync.Once
	unmountCalls atomic.Int32
}

func newLifetimeMountServer() *lifetimeMountServer {
	return &lifetimeMountServer{stopped: make(chan struct{})}
}

func (server *lifetimeMountServer) Wait() {
	<-server.stopped
}

func (server *lifetimeMountServer) Unmount() error {
	server.unmountCalls.Add(1)
	server.stopOnce.Do(func() { close(server.stopped) })
	return nil
}
