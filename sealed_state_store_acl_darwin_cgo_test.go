//go:build darwin && cgo

package s3disk

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestFileSealedStateStoreRevalidatesDarwinACLs(t *testing.T) {
	newStore := func(t *testing.T) (string, *FileSealedStateStore) {
		t.Helper()
		path := filepath.Join(privateTestDirectory(t), "publisher.state")
		store := newInternalFileSealedStateStore(t, path, []byte("darwin-acl-binding"))
		if _, err := store.CompareAndSwap(context.Background(), nil, []byte("private state")); err != nil {
			t.Fatal(err)
		}
		return path, store
	}

	t.Run("state", func(t *testing.T) {
		path, store := newStore(t)
		addDarwinACLEntry(t, path, "everyone allow write,append")
		if _, _, _, err := store.Load(context.Background()); !errors.Is(err, ErrCorruptObject) {
			t.Fatalf("Load with state ACL error = %v, want ErrCorruptObject", err)
		}
	})

	t.Run("lock", func(t *testing.T) {
		path, store := newStore(t)
		addDarwinACLEntry(t, path+".lock", "everyone allow write,append")
		if _, _, _, err := store.Load(context.Background()); !errors.Is(err, ErrCorruptObject) {
			t.Fatalf("Load with lock ACL error = %v, want ErrCorruptObject", err)
		}
	})
}
