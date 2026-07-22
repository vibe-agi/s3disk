//go:build windows

package s3disk_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vibe-agi/s3disk"
	"golang.org/x/sys/windows"
)

func TestFileWatermarkStoreUsesWindowsACLInsteadOfUnixMode(t *testing.T) {
	path := filepath.Join(privateTestDirectory(t), "main.watermark")
	store, err := s3disk.NewFileWatermarkStore(path)
	if err != nil {
		t.Fatal(err)
	}
	want := s3disk.Watermark{Generation: 1, Commit: s3disk.Digest{1}}
	if err := store.CompareAndSwap(context.Background(), "main", nil, want); err != nil {
		t.Fatal(err)
	}
	got, found, err := store.Load(context.Background(), "main")
	if err != nil || !found || got != want {
		t.Fatalf("Load = %+v, %v, %v; want %+v, true, nil", got, found, err, want)
	}
}

func TestFileWatermarkStoreRejectsWindowsWritableDirectoryACL(t *testing.T) {
	directory := filepath.Join(privateTestDirectory(t), "shared")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		directory,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		t.Fatal(err)
	}

	_, err = s3disk.NewFileWatermarkStore(filepath.Join(directory, "main.watermark"))
	if !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("NewFileWatermarkStore error = %v, want ErrCorruptObject", err)
	}
}

func TestFileWatermarkStoreRejectsWindowsDirectoryReparsePoint(t *testing.T) {
	root := privateTestDirectory(t)
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "link")
	state := filepath.Join(target, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("directory symlink unavailable: %v", err)
	}
	_, err := s3disk.NewFileWatermarkStore(filepath.Join(link, "state", "main.watermark"))
	if !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("NewFileWatermarkStore error = %v, want ErrCorruptObject", err)
	}
}
