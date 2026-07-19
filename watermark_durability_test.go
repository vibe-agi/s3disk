package s3disk

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestFileWatermarkLoadRequiresDurableNamespace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := NewFileWatermarkStore(filepath.Join(privateTestDirectory(t), "durability.watermark"))
	if err != nil {
		t.Fatal(err)
	}
	want := Watermark{RepositoryID: RepositoryID{77}, Generation: 1, Commit: Digest{99}}
	errUnsynced := errors.New("test: directory sync interrupted")
	store.syncDirectory = func(string) error { return errUnsynced }
	if err := store.CompareAndSwap(ctx, "main", nil, want); !errors.Is(err, errUnsynced) {
		t.Fatalf("CompareAndSwap error = %v, want injected directory sync error", err)
	}
	if _, found, err := store.Load(ctx, "main"); !errors.Is(err, errUnsynced) || found {
		t.Fatalf("Load before durability barrier = found %v, error %v", found, err)
	}
	store.syncDirectory = syncWatermarkDirectory
	got, found, err := store.Load(ctx, "main")
	if err != nil || !found || got != want {
		t.Fatalf("Load after durability barrier = %+v, found %v, error %v", got, found, err)
	}
}

func TestFileWatermarkIdempotentCASRequiresDurableNamespace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := NewFileWatermarkStore(filepath.Join(privateTestDirectory(t), "idempotent-durability.watermark"))
	if err != nil {
		t.Fatal(err)
	}
	want := Watermark{RepositoryID: RepositoryID{78}, Generation: 1, Commit: Digest{100}}
	errUnsynced := errors.New("test: directory sync interrupted")
	store.syncDirectory = func(string) error { return errUnsynced }
	if err := store.CompareAndSwap(ctx, "main", nil, want); !errors.Is(err, errUnsynced) {
		t.Fatalf("initial CompareAndSwap error = %v, want injected directory sync error", err)
	}

	// The rename above is visible even though its namespace durability is still
	// unknown. A same-state CAS must not turn that observation into success until
	// it has completed the missing parent-directory barrier.
	if err := store.CompareAndSwap(ctx, "main", &want, want); !errors.Is(err, errUnsynced) {
		t.Fatalf("idempotent CompareAndSwap before durability barrier = %v, want injected error", err)
	}
	store.syncDirectory = syncWatermarkDirectory
	if err := store.CompareAndSwap(ctx, "main", &want, want); err != nil {
		t.Fatalf("idempotent CompareAndSwap after durability barrier: %v", err)
	}
	got, found, err := store.Load(ctx, "main")
	if err != nil || !found || got != want {
		t.Fatalf("Load after idempotent durability barrier = %+v, found %v, error %v", got, found, err)
	}
}
