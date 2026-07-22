//go:build integration && (linux || darwin)

package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
	"github.com/vibe-agi/s3disk/mount"
)

// TestMountSetSupervisesTwoRealFUSEMounts proves that the same-process
// supervisor can keep two independent kernel mounts live concurrently and
// waits for both automatic unmount lifecycles after graceful cancellation.
func TestMountSetSupervisesTwoRealFUSEMounts(t *testing.T) {
	requireCLIFUSE(t)
	testContext, stopTest := context.WithTimeout(context.Background(), 30*time.Second)
	defer stopTest()
	supervisorContext, stopSupervisor := context.WithCancel(testContext)
	defer stopSupervisor()

	tasks := make([]mountSetTask, 0, 2)
	mountedFiles := make([]string, 0, 2)
	for index := range 2 {
		repository, err := s3disk.NewRepository(memstore.New(), fmt.Sprintf("mount-set-integration-%d", index))
		if err != nil {
			t.Fatal(err)
		}
		publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
			DangerouslyAllowUncommissionedRepository: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		source := t.TempDir()
		contents := fmt.Sprintf("workspace-%d", index)
		if err := os.WriteFile(filepath.Join(source, "item"), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := publisher.Publish(testContext, source, "main"); err != nil {
			t.Fatal(err)
		}
		watermarks, err := s3disk.NewFileWatermarkStore(filepath.Join(t.TempDir(), "watermark.json"))
		if err != nil {
			t.Fatal(err)
		}
		consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
			Watermarks: watermarks, RequirePersistentWatermark: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		mountpoint := cliIntegrationMountpoint(t)
		mountedFiles = append(mountedFiles, filepath.Join(mountpoint, "item"))
		name := fmt.Sprintf("workspace-%d", index)
		tasks = append(tasks, mountSetTask{name: name, run: func(ctx context.Context) error {
			mounted, err := mount.ReadOnly(ctx, consumer, mountpoint, mount.Options{
				MacOSBackend: cliIntegrationMacOSBackend(t),
				AttrTTL:      50 * time.Millisecond, EntryTTL: 50 * time.Millisecond,
				Poll: s3disk.PollOptions{
					Interval: 20 * time.Millisecond, MaxInterval: 200 * time.Millisecond,
					JitterFraction: -1,
				},
			})
			if err != nil {
				return err
			}
			return waitForMountLifecycle(mounted, nil, nil, 10*time.Millisecond)
		}})
	}

	result := make(chan error, 1)
	go func() { result <- superviseMountSet(supervisorContext, tasks) }()
	for index, path := range mountedFiles {
		want := fmt.Sprintf("workspace-%d", index)
		waitForCLIFile(t, testContext, result, path, want)
	}
	stopSupervisor()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("supervisor stop: %v", err)
		}
	case <-testContext.Done():
		t.Fatalf("supervisor did not stop both mounts: %v", testContext.Err())
	}
	for _, path := range mountedFiles {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("mounted path %q remained visible after supervisor stop: %v", path, err)
		}
	}
}

func requireCLIFUSE(t *testing.T) {
	t.Helper()
	err := cliFUSERuntimeAvailable()
	if err == nil {
		return
	}
	if os.Getenv("S3DISK_REQUIRE_FUSE") == "1" {
		t.Fatalf("FUSE runtime is required for the %s mount-set gate: %v", runtime.GOOS, err)
	}
	t.Skipf("FUSE runtime unavailable on %s: %v", runtime.GOOS, err)
}

func cliIntegrationMacOSBackend(t *testing.T) mount.MacOSBackend {
	t.Helper()
	switch value := os.Getenv("S3DISK_TEST_MACOS_BACKEND"); value {
	case "", "auto":
		return mount.MacOSBackendAuto
	case "vfs":
		return mount.MacOSBackendVFS
	case "fskit":
		return mount.MacOSBackendFSKit
	default:
		t.Fatalf("invalid S3DISK_TEST_MACOS_BACKEND %q", value)
		return mount.MacOSBackendAuto
	}
}

func cliIntegrationMountpoint(t *testing.T) string {
	t.Helper()
	root := os.Getenv("S3DISK_TEST_MOUNT_ROOT")
	if root == "" {
		return t.TempDir()
	}
	if !filepath.IsAbs(root) {
		t.Fatalf("S3DISK_TEST_MOUNT_ROOT must be absolute: %q", root)
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		t.Fatalf("S3DISK_TEST_MOUNT_ROOT is not an existing directory: %q: %v", root, err)
	}
	mountpoint, err := os.MkdirTemp(root, "s3disk-mount-set-")
	if err != nil {
		t.Fatalf("create integration mountpoint below %q: %v", root, err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(mountpoint); err != nil {
			t.Errorf("remove integration mountpoint %q: %v", mountpoint, err)
		}
	})
	return mountpoint
}

func cliFUSERuntimeAvailable() error {
	switch runtime.GOOS {
	case "linux":
		device, err := os.OpenFile("/dev/fuse", os.O_RDWR, 0)
		if err != nil {
			return err
		}
		return device.Close()
	case "darwin":
		for _, helper := range []string{
			"/Library/Filesystems/macfuse.fs/Contents/Resources/mount_macfuse",
			"/Library/Filesystems/osxfuse.fs/Contents/Resources/mount_osxfuse",
		} {
			info, err := os.Stat(helper)
			if err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
				return nil
			}
		}
		return fmt.Errorf("no executable macFUSE mount helper found below /Library/Filesystems")
	default:
		return fmt.Errorf("unsupported test platform %s", runtime.GOOS)
	}
}

func waitForCLIFile(t *testing.T, ctx context.Context, supervisor <-chan error, path, want string) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, err := os.ReadFile(path)
		if err == nil && string(data) == want {
			return
		}
		select {
		case supervisorErr := <-supervisor:
			t.Fatalf("supervisor ended before %q became readable: %v", path, supervisorErr)
		case <-ctx.Done():
			t.Fatalf("wait for %q to contain %q: %v (last error: %v)", path, want, ctx.Err(), err)
		case <-ticker.C:
		}
	}
}
