//go:build !windows && !plan9

package s3disk

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileSealedStateStoreRejectsExternalHardLinkBeforeReplacement(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	directory := privateTestDirectory(t)
	path := filepath.Join(directory, "state.sealed")
	store := newInternalFileSealedStateStore(t, path, []byte("single-link-binding"))
	initial := []byte("state which must not be replaced while externally linked")
	revision, err := store.CompareAndSwap(ctx, nil, initial)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(directory, "external-hard-link")
	if err := os.Link(path, alias); err != nil {
		t.Skipf("hard links unavailable on this filesystem: %v", err)
	}

	if candidate, err := store.CompareAndSwap(ctx, &revision, []byte("must not replace linked state")); !candidate.IsZero() || !errors.Is(err, ErrCorruptObject) {
		t.Fatalf("CompareAndSwap with external hard link = candidate %s, error %v; want zero and ErrCorruptObject", candidate, err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("rejected sealed-state replacement changed the current file")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	loaded, loadedRevision, found, err := store.Load(ctx)
	if err != nil || !found || loadedRevision != revision || !bytes.Equal(loaded, initial) {
		t.Fatalf("Load after hard-link removal = %q, %s, %t, %v", loaded, loadedRevision, found, err)
	}
}
