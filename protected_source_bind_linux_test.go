//go:build linux

package s3disk_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/vibe-agi/s3disk"
)

func TestPublisherRejectsProtectedSourceDirectFileBindMount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("file bind mount test requires root")
	}
	protectedPath := filepath.Join(privateTestDirectory(t), "protected")
	writeFile(t, protectedPath, []byte("bind-mounted secret"))
	source := privateTestDirectory(t)
	alias := filepath.Join(source, "bind-alias")
	writeFile(t, alias, nil)
	if err := syscall.Mount(protectedPath, alias, "", syscall.MS_BIND, ""); err != nil {
		t.Skipf("file bind mounts are unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := syscall.Unmount(alias, syscall.MNT_DETACH); err != nil {
			t.Errorf("unmount test bind alias: %v", err)
		}
	})

	publisher, store := newProtectedSourcePublisher(t, []s3disk.ProtectedSourceFile{{Path: protectedPath}})
	store.ResetStats()
	if _, err := publisher.Stage(context.Background(), source, "main"); !errors.Is(err, s3disk.ErrProtectedSourceFile) {
		t.Fatalf("Stage bind alias error = %v, want ErrProtectedSourceFile", err)
	}
	if stats := store.Stats(); stats.ChunkPuts != 0 {
		t.Fatalf("chunk puts = %d, want zero before protected bind rejection", stats.ChunkPuts)
	}
}
