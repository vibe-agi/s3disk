//go:build !windows

package s3disk_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vibe-agi/s3disk"
)

func TestDiskCacheRejectsGroupOrWorldWritableRoot(t *testing.T) {
	t.Parallel()
	root := filepath.Join(privateTestDirectory(t), "shared-cache")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := s3disk.NewDiskCache(root); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("NewDiskCache error = %v, want ErrCorruptObject", err)
	}
}
