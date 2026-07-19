//go:build linux

package s3disk

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/fsnotify/fsnotify"
)

func TestDeepDirectoryTraversalStaysBelowLowFileDescriptorLimit(t *testing.T) {
	// RLIMIT_NOFILE is process-wide. This test must remain sequential so Go's
	// parallel tests stay suspended until the original limit is restored.
	source := privateTestDirectory(t)
	deepest := source
	const depth = 256
	for range depth {
		deepest = filepath.Join(deepest, "d")
		if err := os.Mkdir(deepest, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(deepest, "leaf"), []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot observe process file descriptors: %v", err)
	}
	var original syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &original); err != nil {
		t.Skipf("cannot read RLIMIT_NOFILE: %v", err)
	}
	const descriptorHeadroom = 64
	target := uint64(len(entries) + descriptorHeadroom)
	if original.Cur <= target || original.Max < target {
		t.Skipf("RLIMIT_NOFILE is already too low to install a deterministic test limit: soft=%d hard=%d target=%d", original.Cur, original.Max, target)
	}
	limited := original
	limited.Cur = target
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limited); err != nil {
		t.Skipf("cannot lower RLIMIT_NOFILE: %v", err)
	}
	defer func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &original); err != nil {
			t.Errorf("restore RLIMIT_NOFILE: %v", err)
		}
	}()

	repository, err := NewRepository(fdLimitStore{}, "bounded-directory-fds")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(repository, PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Stage(context.Background(), source, "main"); err != nil {
		t.Fatalf("publisher traversal exceeded a %d-descriptor headroom: %v", descriptorHeadroom, err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()
	if err := newBoundedWatchTree(watcher).Add(source); err != nil {
		t.Fatalf("watch traversal exceeded a %d-descriptor headroom: %v", descriptorHeadroom, err)
	}
}

type fdLimitStore struct{}

func (fdLimitStore) Get(context.Context, string, GetOptions) (Object, error) {
	return Object{}, ErrObjectNotFound
}

func (fdLimitStore) Head(context.Context, string) (Version, error) {
	return Version{}, ErrObjectNotFound
}

func (fdLimitStore) PutIfAbsent(context.Context, string, []byte) (Version, error) {
	return Version{ETag: "fd-limit"}, nil
}

func (fdLimitStore) CompareAndSwap(context.Context, string, *Version, []byte) (Version, error) {
	return Version{ETag: "fd-limit"}, nil
}

var _ Store = fdLimitStore{}
