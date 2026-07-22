//go:build linux || darwin || freebsd

package mount

import (
	"context"
	"fmt"
	"syscall"
	"testing"

	"github.com/vibe-agi/s3disk"
)

// A backend chunk fetch that hits its own attempt-level timeout surfaces a
// wrapped context.DeadlineExceeded while the mount context stays live (the
// store wraps the caller context in its own per-operation deadline). That is a
// retryable I/O failure, not a signal interruption, so it must map to EIO.
// EINTR would surface to userspace as a spurious hard failure because regular
// -file reads are not restarted for EINTR.
func TestErrnoMapsBackendDeadlineExceededToEIO(t *testing.T) {
	t.Parallel()
	err := fmt.Errorf("s3store: get %q: %w", "objects/chunk/ab/cd", context.DeadlineExceeded)
	if got := errno(err); got != syscall.EIO {
		t.Fatalf("errno(wrapped DeadlineExceeded) = %v, want EIO", got)
	}
}

// A genuine FUSE request interrupt arrives as context.Canceled and must remain
// EINTR so the kernel can retry the interrupted operation.
func TestErrnoMapsCanceledToEINTR(t *testing.T) {
	t.Parallel()
	if got := errno(context.Canceled); got != syscall.EINTR {
		t.Fatalf("errno(context.Canceled) = %v, want EINTR", got)
	}
}

// A disappeared immutable object remains a store/integrity error (EIO), not a
// path-not-found, guarding the existing distinct mapping alongside the fix.
func TestErrnoKeepsObjectNotFoundAsEIO(t *testing.T) {
	t.Parallel()
	if got := errno(fmt.Errorf("read chunk: %w", s3disk.ErrObjectNotFound)); got != syscall.EIO {
		t.Fatalf("errno(ErrObjectNotFound) = %v, want EIO", got)
	}
}
