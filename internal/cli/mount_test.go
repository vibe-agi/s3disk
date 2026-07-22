package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk/mount"
)

type fakeMountLifecycle struct {
	done   chan struct{}
	mu     sync.RWMutex
	status mount.MountStatus
}

type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (buffer *synchronizedBuffer) Write(value []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Write(value)
}

func (buffer *synchronizedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.String()
}

func (lifecycle *fakeMountLifecycle) Done() <-chan struct{} { return lifecycle.done }

func (lifecycle *fakeMountLifecycle) Status() mount.MountStatus {
	lifecycle.mu.RLock()
	defer lifecycle.mu.RUnlock()
	return lifecycle.status
}

func (lifecycle *fakeMountLifecycle) setStatus(status mount.MountStatus) {
	lifecycle.mu.Lock()
	lifecycle.status = status
	lifecycle.mu.Unlock()
}

func TestMountHealthReporterNeverBlocksWhenFull(t *testing.T) {
	events, report := newMountHealthEvents()
	done := make(chan struct{})
	go func() {
		for index := 0; index < mountHealthEventBuffer+1; index++ {
			report(errors.New("health failure"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("health reporter blocked on its full bounded channel")
	}
	for index := 0; index < mountHealthEventBuffer; index++ {
		select {
		case <-events:
		default:
			t.Fatalf("health event count = %d, want %d", index, mountHealthEventBuffer)
		}
	}
}

func TestWaitForMountLifecycleReportsHealthError(t *testing.T) {
	lifecycle := &fakeMountLifecycle{
		done:   make(chan struct{}),
		status: mount.MountStatus{Lifecycle: mount.LifecycleRunning},
	}
	events, report := newMountHealthEvents()
	var output synchronizedBuffer
	result := make(chan error, 1)
	go func() {
		result <- waitForMountLifecycle(lifecycle, events, &output, time.Millisecond)
	}()
	report(errors.New("refresh unavailable"))
	for deadline := time.Now().Add(time.Second); !strings.Contains(output.String(), "refresh unavailable"); {
		if time.Now().After(deadline) {
			t.Fatalf("health warning was not written: %q", output.String())
		}
		time.Sleep(time.Millisecond)
	}
	lifecycle.setStatus(mount.MountStatus{Lifecycle: mount.LifecycleStopped})
	close(lifecycle.done)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestWaitForMountLifecycleReturnsWhenAutomaticUnmountFails(t *testing.T) {
	lifecycle := &fakeMountLifecycle{
		done: make(chan struct{}),
		status: mount.MountStatus{
			Lifecycle: mount.LifecycleStopFailed,
			Unmount:   mount.ComponentStatus{LastError: "device busy"},
		},
	}
	result := make(chan error, 1)
	go func() {
		result <- waitForMountLifecycle(lifecycle, nil, nil, time.Millisecond)
	}()
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "automatic unmount failed: device busy") {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("wait remained blocked after automatic unmount entered stop_failed")
	}
}

func TestPrepareMountCachePathNamespacesCustomBase(t *testing.T) {
	requirePrivateSecretFiles(t)
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	path, err := prepareConsumerCachePath(base, t.TempDir(), "repository-id", "share-id")
	if err != nil {
		t.Fatal(err)
	}
	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(resolvedBase, "repository-id", "share-id", "cache")
	if path != want {
		t.Fatalf("cache path = %q, want %q", path, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("cache namespace permissions = %#o", info.Mode().Perm())
	}
}

func TestValidateMountRejectsStateCacheOverlap(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	err := validateMountOptions(&MountOptions{
		HandoffPath: "handoff", Mountpoint: filepath.Join(t.TempDir(), "mount"),
		StateDir: state, CacheDir: filepath.Join(state, "cache"), PollInterval: time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "--cache-dir and --state-dir") {
		t.Fatalf("error = %v", err)
	}
}

func TestMountPreflightRejectsSymlinkOverlap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation normally requires additional Windows privilege")
	}
	root := t.TempDir()
	state := filepath.Join(root, "state")
	mountpoint := filepath.Join(state, "mount")
	if err := os.MkdirAll(mountpoint, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "apparently-separate-mount")
	if err := os.Symlink(mountpoint, alias); err != nil {
		t.Fatal(err)
	}
	_, err := preflightMountLocalPaths(MountOptions{StateDir: state, Mountpoint: alias})
	if err == nil || !strings.Contains(err.Error(), "state directory and mountpoint") {
		t.Fatalf("error = %v", err)
	}
}
