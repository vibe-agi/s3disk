//go:build integration && linux

package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
	"github.com/vibe-agi/s3disk/mount"
)

// TestLinuxMountSetSupervisesTwoRealFUSEMounts proves that the same-process
// supervisor can keep two independent kernel mounts live concurrently and
// waits for both automatic unmount lifecycles after graceful cancellation.
func TestLinuxMountSetSupervisesTwoRealFUSEMounts(t *testing.T) {
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
		mountpoint := t.TempDir()
		mountedFiles = append(mountedFiles, filepath.Join(mountpoint, "item"))
		name := fmt.Sprintf("workspace-%d", index)
		tasks = append(tasks, mountSetTask{name: name, run: func(ctx context.Context) error {
			mounted, err := mount.ReadOnly(ctx, consumer, mountpoint, mount.Options{
				AttrTTL: 50 * time.Millisecond, EntryTTL: 50 * time.Millisecond,
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
	device, err := os.OpenFile("/dev/fuse", os.O_RDWR, 0)
	if err == nil {
		_ = device.Close()
		return
	}
	if os.Getenv("S3DISK_REQUIRE_FUSE") == "1" {
		t.Fatalf("/dev/fuse is required for the Linux mount-set gate: %v", err)
	}
	t.Skipf("/dev/fuse unavailable: %v", err)
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
