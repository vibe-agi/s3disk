//go:build linux || darwin || freebsd

package mount

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestEveryMutationReturnsReadOnlyFilesystem(t *testing.T) {
	t.Parallel()
	node := &node{}
	ctx := context.Background()
	if errno := node.Setattr(ctx, nil, &fuse.SetAttrIn{}, &fuse.AttrOut{}); errno != syscall.EROFS {
		t.Fatalf("setattr = %v", errno)
	}
	if _, errno := node.Mkdir(ctx, "x", 0o755, &fuse.EntryOut{}); errno != syscall.EROFS {
		t.Fatalf("mkdir = %v", errno)
	}
	if _, errno := node.Mknod(ctx, "x", 0o644, 0, &fuse.EntryOut{}); errno != syscall.EROFS {
		t.Fatalf("mknod = %v", errno)
	}
	if _, errno := node.Link(ctx, nil, "x", &fuse.EntryOut{}); errno != syscall.EROFS {
		t.Fatalf("link = %v", errno)
	}
	if _, errno := node.Symlink(ctx, "target", "x", &fuse.EntryOut{}); errno != syscall.EROFS {
		t.Fatalf("symlink = %v", errno)
	}
	if _, _, _, errno := node.Create(ctx, "x", 0, 0o644, &fuse.EntryOut{}); errno != syscall.EROFS {
		t.Fatalf("create = %v", errno)
	}
	if errno := node.Unlink(ctx, "x"); errno != syscall.EROFS {
		t.Fatalf("unlink = %v", errno)
	}
	if errno := node.Rmdir(ctx, "x"); errno != syscall.EROFS {
		t.Fatalf("rmdir = %v", errno)
	}
	if errno := node.Rename(ctx, "x", nil, "y", 0); errno != syscall.EROFS {
		t.Fatalf("rename = %v", errno)
	}
	if _, errno := node.Write(ctx, nil, []byte("x"), 0); errno != syscall.EROFS {
		t.Fatalf("write = %v", errno)
	}
	if errno := node.Allocate(ctx, nil, 0, 1, 0); errno != syscall.EROFS {
		t.Fatalf("allocate = %v", errno)
	}
	if _, errno := node.CopyFileRange(ctx, nil, 0, nil, nil, 0, 1, 0); errno != syscall.EROFS {
		t.Fatalf("copy_file_range = %v", errno)
	}
	if errno := node.Setxattr(ctx, "x", []byte("y"), 0); errno != syscall.EROFS {
		t.Fatalf("setxattr = %v", errno)
	}
	if errno := node.Removexattr(ctx, "x"); errno != syscall.EROFS {
		t.Fatalf("removexattr = %v", errno)
	}
}

func TestOpenRejectsEveryMutationIntent(t *testing.T) {
	t.Parallel()

	node := &node{}
	for _, test := range []struct {
		name  string
		flags int
	}{
		{name: "write-only", flags: syscall.O_WRONLY},
		{name: "read-write", flags: syscall.O_RDWR},
		{name: "truncate", flags: syscall.O_RDONLY | syscall.O_TRUNC},
		{name: "append", flags: syscall.O_RDONLY | syscall.O_APPEND},
		{name: "create", flags: syscall.O_RDONLY | syscall.O_CREAT},
		{name: "exclusive-create", flags: syscall.O_RDONLY | syscall.O_CREAT | syscall.O_EXCL},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			handle, fuseFlags, errno := node.Open(context.Background(), uint32(test.flags))
			if errno != syscall.EROFS || handle != nil || fuseFlags != 0 {
				t.Fatalf("Open(%#x) = (%v, %#x, %v), want (nil, 0, EROFS)", test.flags, handle, fuseFlags, errno)
			}
		})
	}
}

func TestOpenAlwaysUsesDirectIO(t *testing.T) {
	t.Parallel()
	fixture := newInvalidationFixture(t, memstore.New(), "mount-direct-io")
	fileNode, ok := fixture.fileInode.Operations().(*node)
	if !ok {
		t.Fatalf("file inode operations type = %T, want *node", fixture.fileInode.Operations())
	}
	handle, fuseFlags, errno := fileNode.Open(context.Background(), uint32(syscall.O_RDONLY))
	if errno != 0 || handle == nil {
		t.Fatalf("Open = (%T, %#x, %v), want successful handle", handle, fuseFlags, errno)
	}
	if fuseFlags != fuse.FOPEN_DIRECT_IO {
		t.Fatalf("Open FUSE flags = %#x, want FOPEN_DIRECT_IO (%#x)", fuseFlags, fuse.FOPEN_DIRECT_IO)
	}
}

func TestUnmountIsIdempotentUnderConcurrency(t *testing.T) {
	t.Parallel()

	server := &fakeMountServer{}
	var cancelCalls atomic.Int32
	mounted := &Mount{
		server:    server,
		cancel:    func() { cancelCalls.Add(1) },
		unmounted: make(chan struct{}),
	}
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := mounted.Unmount(); err != nil {
				t.Errorf("Unmount error = %v, want nil", err)
			}
		}()
	}
	wait.Wait()
	if calls := server.calls.Load(); calls != 1 {
		t.Fatalf("server Unmount calls = %d, want 1", calls)
	}
	if calls := cancelCalls.Load(); calls != 1 {
		t.Fatalf("cancel calls = %d, want 1", calls)
	}
}

func TestUnmountFailureKeepsPollingUntilSuccessfulRetry(t *testing.T) {
	t.Parallel()
	want := errors.New("transient unmount failure")
	server := &fakeMountServer{results: []error{want, nil}}
	var cancelCalls atomic.Int32
	mounted := &Mount{
		server:    server,
		cancel:    func() { cancelCalls.Add(1) },
		unmounted: make(chan struct{}),
	}
	if err := mounted.Unmount(); !errors.Is(err, want) {
		t.Fatalf("first Unmount error = %v, want %v", err, want)
	}
	select {
	case <-mounted.unmounted:
		t.Fatal("failed unmount marked the mount as unmounted")
	default:
	}
	if calls := cancelCalls.Load(); calls != 0 {
		t.Fatalf("failed unmount canceled polling %d times, want zero", calls)
	}
	if err := mounted.Unmount(); err != nil {
		t.Fatalf("second Unmount error = %v, want nil", err)
	}
	if err := mounted.Unmount(); err != nil {
		t.Fatalf("third Unmount error = %v, want idempotent nil", err)
	}
	if calls := server.calls.Load(); calls != 2 {
		t.Fatalf("server Unmount calls = %d, want 2", calls)
	}
	if calls := cancelCalls.Load(); calls != 1 {
		t.Fatalf("cancel calls = %d, want 1", calls)
	}
	select {
	case <-mounted.unmounted:
	default:
		t.Fatal("successful retry did not mark the mount as unmounted")
	}
}

func TestContextCancellationRetriesTransientUnmountFailure(t *testing.T) {
	t.Parallel()
	server := &fakeMountServer{results: []error{syscall.EBUSY, nil}}
	var cancelCalls atomic.Int32
	mounted := &Mount{
		server: server, cancel: func() { cancelCalls.Add(1) },
		unmounted: make(chan struct{}), autoUnmountTimeout: time.Second,
		unmountRetryMin: initialUnmountRetryDelay, unmountRetryMax: maxUnmountRetryDelay,
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		mounted.unmountOnLifetimeDone(ctx)
		close(finished)
	}()
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not finish automatic unmount retry")
	}
	if calls := server.calls.Load(); calls != 2 {
		t.Fatalf("server Unmount calls = %d, want initial failure and one retry", calls)
	}
	if calls := cancelCalls.Load(); calls != 1 {
		t.Fatalf("cancel calls = %d, want 1", calls)
	}
	select {
	case <-mounted.unmounted:
	default:
		t.Fatal("automatic retry did not mark the mount as unmounted")
	}
}

func TestUnmountRetryBackoffIsBounded(t *testing.T) {
	t.Parallel()
	delay := initialUnmountRetryDelay
	for index := range 16 {
		if delay <= 0 || delay > maxUnmountRetryDelay {
			t.Fatalf("retry delay %d = %v, want within (0, %v]", index, delay, maxUnmountRetryDelay)
		}
		next := nextRetryDelay(delay, maxUnmountRetryDelay)
		if next < delay {
			t.Fatalf("retry delay decreased from %v to %v", delay, next)
		}
		delay = next
	}
	if delay != maxUnmountRetryDelay {
		t.Fatalf("last retry delay = %v, want capped %v", delay, maxUnmountRetryDelay)
	}
}

func TestServerMonitorRecognizesExternalUnmount(t *testing.T) {
	t.Parallel()
	server := &fakeMountServer{}
	var cancelCalls atomic.Int32
	mounted := &Mount{
		server: server, cancel: func() { cancelCalls.Add(1) },
		serverDone: make(chan struct{}), unmounted: make(chan struct{}),
	}
	mounted.monitorServer()
	for name, closed := range map[string]<-chan struct{}{
		"unmounted":  mounted.unmounted,
		"serverDone": mounted.serverDone,
	} {
		select {
		case <-closed:
		default:
			t.Fatalf("%s channel remained open after server stopped", name)
		}
	}
	if err := mounted.Unmount(); err != nil {
		t.Fatalf("Unmount after external stop error = %v, want nil", err)
	}
	if calls := server.calls.Load(); calls != 0 {
		t.Fatalf("server Unmount calls after external stop = %d, want 0", calls)
	}
	if calls := cancelCalls.Load(); calls != 1 {
		t.Fatalf("cancel calls = %d, want 1", calls)
	}
}

type fakeMountServer struct {
	results []error
	calls   atomic.Int32
}

func (*fakeMountServer) Wait() {}

func (server *fakeMountServer) Unmount() error {
	call := int(server.calls.Add(1))
	if call <= len(server.results) {
		return server.results[call-1]
	}
	return nil
}
