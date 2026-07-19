package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
)

func TestPublisherSessionLockLifecycle(t *testing.T) {
	requirePublisherSessionLocks(t)
	firstDirectory := t.TempDir()
	secondDirectory := t.TempDir()

	first, err := acquirePublisherSessionLock(context.Background(), firstDirectory)
	if err != nil {
		t.Fatal(err)
	}
	firstClosed := false
	defer func() {
		if !firstClosed {
			_ = first.Close()
		}
	}()
	lockPath := filepath.Join(firstDirectory, publisherSessionLockFileName)
	info, err := os.Lstat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("publisher session lock mode = %v, want regular 0600", info.Mode())
	}

	result := make(chan error, 1)
	go func() {
		contender, contenderErr := acquirePublisherSessionLock(context.Background(), firstDirectory)
		if contender != nil {
			_ = contender.Close()
		}
		result <- contenderErr
	}()
	select {
	case contenderErr := <-result:
		if !errors.Is(contenderErr, ErrPublisherSessionActive) {
			t.Fatalf("second acquisition error = %v, want ErrPublisherSessionActive", contenderErr)
		}
	case <-time.After(time.Second):
		t.Fatal("second acquisition blocked instead of returning ErrPublisherSessionActive")
	}

	other, err := acquirePublisherSessionLock(context.Background(), secondDirectory)
	if err != nil {
		t.Fatalf("different-share acquisition: %v", err)
	}
	if err := other.Close(); err != nil {
		t.Fatalf("close different-share lock: %v", err)
	}

	var closeGroup sync.WaitGroup
	closeErrors := make(chan error, 8)
	for range 8 {
		closeGroup.Add(1)
		go func() {
			defer closeGroup.Done()
			closeErrors <- first.Close()
		}()
	}
	closeGroup.Wait()
	close(closeErrors)
	for closeErr := range closeErrors {
		if closeErr != nil {
			t.Fatalf("idempotent Close error: %v", closeErr)
		}
	}
	firstClosed = true
	if _, err := os.Lstat(lockPath); err != nil {
		t.Fatalf("Close removed the persistent lock file: %v", err)
	}

	reacquired, err := acquirePublisherSessionLock(context.Background(), firstDirectory)
	if err != nil {
		t.Fatalf("reacquire released lock: %v", err)
	}
	if err := reacquired.Close(); err != nil {
		t.Fatalf("close reacquired lock: %v", err)
	}
	if err := reacquired.Close(); err != nil {
		t.Fatalf("second Close on reacquired lock: %v", err)
	}
}

func TestPublisherSessionLockPreCanceledContextCreatesNothing(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, publisherSessionLockFileName)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lock, err := acquirePublisherSessionLock(ctx, directory)
	if lock != nil {
		_ = lock.Close()
		t.Fatal("pre-canceled acquisition returned a lock")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled acquisition error = %v, want context.Canceled", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pre-canceled acquisition created the lock file: %v", err)
	}
}

func TestPublisherSessionLockRejectsSymlinks(t *testing.T) {
	requirePublisherSessionLocks(t)
	t.Run("lock file", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, publisherSessionLockFileName)
		if err := os.Symlink(target, path); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		lock, err := acquirePublisherSessionLock(context.Background(), directory)
		if lock != nil {
			_ = lock.Close()
			t.Fatal("acquisition accepted a symlink lock file")
		}
		if !errors.Is(err, s3disk.ErrCorruptObject) {
			t.Fatalf("symlink lock error = %v, want ErrCorruptObject", err)
		}
	})

	t.Run("share directory", func(t *testing.T) {
		parent := t.TempDir()
		target := filepath.Join(parent, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(parent, "alias")
		if err := os.Symlink(target, alias); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		lock, err := acquirePublisherSessionLock(context.Background(), alias)
		if lock != nil {
			_ = lock.Close()
			t.Fatal("acquisition accepted a symlink share directory")
		}
		if !errors.Is(err, s3disk.ErrCorruptObject) {
			t.Fatalf("symlink directory error = %v, want ErrCorruptObject", err)
		}
		if _, err := os.Lstat(filepath.Join(target, publisherSessionLockFileName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rejected directory symlink created a target lock file: %v", err)
		}
	})
}

func TestPublisherSessionLockRejectsBroadPermissions(t *testing.T) {
	requirePublisherSessionLocks(t)
	t.Run("lock file", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, publisherSessionLockFileName)
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		lock, err := acquirePublisherSessionLock(context.Background(), directory)
		if lock != nil {
			_ = lock.Close()
			t.Fatal("acquisition accepted a broadly-readable lock file")
		}
		if !errors.Is(err, s3disk.ErrCorruptObject) {
			t.Fatalf("broad lock-file mode error = %v, want ErrCorruptObject", err)
		}
	})

	t.Run("share directory", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o777); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(directory, 0o700)
		lock, err := acquirePublisherSessionLock(context.Background(), directory)
		if lock != nil {
			_ = lock.Close()
			t.Fatal("acquisition accepted a group/world-writable share directory")
		}
		if !errors.Is(err, s3disk.ErrCorruptObject) {
			t.Fatalf("broad directory mode error = %v, want ErrCorruptObject", err)
		}
		if _, err := os.Lstat(filepath.Join(directory, publisherSessionLockFileName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rejected broad directory created the lock file: %v", err)
		}
	})
}

func requirePublisherSessionLocks(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "dragonfly" && runtime.GOOS != "freebsd" &&
		runtime.GOOS != "linux" && runtime.GOOS != "netbsd" && runtime.GOOS != "openbsd" {
		t.Skip("platform intentionally fails closed for publisher session lifecycle locks")
	}
	if err := s3disk.ValidatePrivateSecretDirectory(t.TempDir()); err != nil {
		if errors.Is(err, s3disk.ErrTrustStateUnsupported) {
			t.Skipf("private trust-state validation is unsupported: %v", err)
		}
		t.Fatalf("validate private test directory: %v", err)
	}
}
