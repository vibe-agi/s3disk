package memstore

import (
	"context"
	"errors"
	"testing"

	"github.com/vibe-agi/s3disk"
)

// The in-memory double must reject writes larger than the real Store's absolute
// object-size limit (protocolMaxObjectBytes) with ErrResourceLimit, so a
// regression that weakens the real adapter's put-size enforcement cannot pass
// unnoticed through memstore-backed tests. ForcePut deliberately stays a raw
// bypass for fault injection and is not covered here.
func TestWritesRejectObjectsBeyondProtocolLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	limit := int(s3disk.ClientEncryptionMaxPlaintextBytes + s3disk.ClientEncryptionCiphertextOverhead)
	oversized := make([]byte, limit+1)

	store := New()
	if _, err := store.PutIfAbsent(ctx, "objects/chunk/aa/bb", oversized); !errors.Is(err, s3disk.ErrResourceLimit) {
		t.Fatalf("PutIfAbsent oversized = %v, want ErrResourceLimit", err)
	}
	if _, err := store.CompareAndSwap(ctx, "shares/x/latest", nil, oversized); !errors.Is(err, s3disk.ErrResourceLimit) {
		t.Fatalf("CompareAndSwap oversized = %v, want ErrResourceLimit", err)
	}

	// An object at exactly the maximum is still accepted: the cap must reject
	// only objects strictly larger than the limit, matching the real Store's `>`.
	atLimit := make([]byte, limit)
	if _, err := store.PutIfAbsent(ctx, "objects/chunk/cc/dd", atLimit); err != nil {
		t.Fatalf("PutIfAbsent maximum-size object = %v, want success", err)
	}
}
