//go:build linux || darwin || freebsd

package mount

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/vibe-agi/s3disk"
)

func TestReadOnlyRejectsUnsafeConsumerBeforeMountpointOrStoreIO(t *testing.T) {
	t.Parallel()
	missingMountpoint := filepath.Join(t.TempDir(), "does-not-exist")

	_, err := ReadOnly(context.Background(), &s3disk.Consumer{}, missingMountpoint, Options{})
	if !errors.Is(err, ErrDurableWatermarkRequired) {
		t.Fatalf("ReadOnly error = %v, want pre-I/O ErrDurableWatermarkRequired", err)
	}
}
