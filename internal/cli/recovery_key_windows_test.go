//go:build windows

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/publisherstate"
)

func TestRecoveryKeyFileFailsClosedWithoutAuthenticatedWindowsACLs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery-key.json")
	key, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := writeRecoveryKeyFile(context.Background(), path, key); !errors.Is(err, s3disk.ErrTrustStateUnsupported) {
		t.Fatalf("write error = %v, want ErrTrustStateUnsupported", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported platform exposed recovery key: %v", err)
	}
	if _, err := readRecoveryKeyFile(path); !errors.Is(err, ErrInvalidRecoveryKeyFile) {
		t.Fatalf("read error = %v, want ErrInvalidRecoveryKeyFile", err)
	}
}
