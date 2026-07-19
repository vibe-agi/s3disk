package memstore

import (
	"context"
	"errors"
	"testing"

	"github.com/vibe-agi/s3disk"
)

func TestCompareAndSwapUsesETagAsTheOnlyCondition(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := New()
	initial, err := store.PutIfAbsent(ctx, "key", []byte("initial"))
	if err != nil {
		t.Fatalf("PutIfAbsent: %v", err)
	}

	expected := initial
	expected.VersionID = "different-diagnostic-version"
	replaced, err := store.CompareAndSwap(ctx, "key", &expected, []byte("replacement"))
	if err != nil {
		t.Fatalf("CompareAndSwap with matching ETag: %v", err)
	}
	if replaced.ETag == initial.ETag {
		t.Fatal("replacement did not receive a new ETag")
	}

	stale := replaced
	stale.ETag = initial.ETag
	if _, err := store.CompareAndSwap(ctx, "key", &stale, []byte("stale")); !errors.Is(err, s3disk.ErrPrecondition) {
		t.Fatalf("CompareAndSwap with stale ETag error = %v, want ErrPrecondition", err)
	}

	if _, err := store.CompareAndSwap(ctx, "key", &s3disk.Version{VersionID: replaced.VersionID}, []byte("missing-etag")); err == nil {
		t.Fatal("CompareAndSwap accepted VersionID without an ETag")
	}
	object, err := store.Get(ctx, "key", s3disk.GetOptions{})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got, want := string(object.Data), "replacement"; got != want {
		t.Fatalf("data after rejected CAS = %q, want %q", got, want)
	}
}
