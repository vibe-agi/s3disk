//go:build darwin || linux

package s3disk_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vibe-agi/s3disk"
)

func newPrivateBarrierTestDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "s3disk-private-barrier-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove private-barrier test directory: %v", err)
		}
	})
	return directory
}

func TestFileWatermarkStoreRejectsWritableDirectoryBelowPrivateAncestor(t *testing.T) {
	private := newPrivateBarrierTestDirectory(t)
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	writable := filepath.Join(private, "umask-child")
	if err := os.Mkdir(writable, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o775); err != nil {
		t.Fatal(err)
	}

	// A private ancestor is not enough: another UID may have retained a
	// descriptor for this writable directory before the ancestor was tightened
	// and can use renameat/unlinkat without traversing the current path.
	_, err := s3disk.NewFileWatermarkStore(filepath.Join(writable, "trust", "main.watermark"))
	if !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("NewFileWatermarkStore below private ancestor error = %v, want ErrCorruptObject", err)
	}
}

func TestFileWatermarkStoreRejectsWritableDirectoryBelowSearchableAncestor(t *testing.T) {
	searchable := newPrivateBarrierTestDirectory(t)
	if err := os.Chmod(searchable, 0o711); err != nil {
		t.Fatal(err)
	}
	writable := filepath.Join(searchable, "umask-child")
	if err := os.Mkdir(writable, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o775); err != nil {
		t.Fatal(err)
	}

	_, err := s3disk.NewFileWatermarkStore(filepath.Join(writable, "trust", "main.watermark"))
	if !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("NewFileWatermarkStore below searchable ancestor error = %v, want ErrCorruptObject", err)
	}
}

func TestFileWatermarkStoreRevalidatesWritableIntermediateDirectory(t *testing.T) {
	private := newPrivateBarrierTestDirectory(t)
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := s3disk.NewFileWatermarkStore(filepath.Join(private, "trust", "main.watermark"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(context.Background(), "main"); err != nil {
		t.Fatalf("initial Load: %v", err)
	}

	if err := os.Chmod(private, 0o775); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(context.Background(), "main"); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("Load after making intermediate directory writable error = %v, want ErrCorruptObject", err)
	}
}

func TestFileWatermarkStoreRejectsWritableFinalDirectoryBelowPrivateAncestor(t *testing.T) {
	private := newPrivateBarrierTestDirectory(t)
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	finalDirectory := filepath.Join(private, "writable-final")
	if err := os.Mkdir(finalDirectory, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(finalDirectory, 0o775); err != nil {
		t.Fatal(err)
	}

	_, err := s3disk.NewFileWatermarkStore(filepath.Join(finalDirectory, "main.watermark"))
	if !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("NewFileWatermarkStore in writable final directory error = %v, want ErrCorruptObject", err)
	}
}
