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

func TestFileWatermarkStorePinsIntermediateSymlink(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := privateTestDirectory(t)
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	for _, directory := range []string{first, second} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(first, alias); err != nil {
		t.Fatal(err)
	}
	store, err := s3disk.NewFileWatermarkStore(filepath.Join(alias, "main.watermark"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(second, alias); err != nil {
		t.Fatal(err)
	}
	want := s3disk.Watermark{RepositoryID: s3disk.RepositoryID{1}, Generation: 1, Commit: s3disk.Digest{2}}
	if err := store.CompareAndSwap(ctx, "main", nil, want); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(first, "main.watermark")); err != nil {
		t.Fatalf("canonical target did not receive state: %v", err)
	}
	if _, err := os.Stat(filepath.Join(second, "main.watermark")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replaced symlink target received state: %v", err)
	}
}

func TestFileWatermarkStoreRejectsUntrustedUnixAncestorsAndOwners(t *testing.T) {
	t.Parallel()
	writable := newPrivateBarrierTestDirectory(t)
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := s3disk.NewFileWatermarkStore(filepath.Join(writable, "state")); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("NewFileWatermarkStore writable ancestor error = %v, want ErrCorruptObject", err)
	}

	// A trusted sticky ancestor may contain a newly-created private directory.
	sticky := newPrivateBarrierTestDirectory(t)
	if err := os.Chmod(sticky, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if _, err := s3disk.NewFileWatermarkStore(filepath.Join(sticky, "private", "state")); err != nil {
		t.Fatalf("private state below trusted sticky ancestor: %v", err)
	}

	if os.Geteuid() != 0 {
		return
	}
	foreignDirectory := newPrivateBarrierTestDirectory(t)
	if err := os.Chown(foreignDirectory, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := s3disk.NewFileWatermarkStore(filepath.Join(foreignDirectory, "state")); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("foreign-owned directory error = %v, want ErrCorruptObject", err)
	}

	statePath := filepath.Join(privateTestDirectory(t), "foreign-file.watermark")
	store, err := s3disk.NewFileWatermarkStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	watermark := s3disk.Watermark{RepositoryID: s3disk.RepositoryID{3}, Generation: 1, Commit: s3disk.Digest{4}}
	if err := store.CompareAndSwap(context.Background(), "main", nil, watermark); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(statePath, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(context.Background(), "main"); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("foreign-owned state file error = %v, want ErrCorruptObject", err)
	}
}

func TestFileWatermarkStoreRejectsWritableDirectory(t *testing.T) {
	t.Parallel()

	directory := newPrivateBarrierTestDirectory(t)
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	_, err := s3disk.NewFileWatermarkStore(filepath.Join(directory, "main.watermark"))
	if !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("NewFileWatermarkStore error = %v, want ErrCorruptObject", err)
	}
}
