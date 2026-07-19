//go:build windows

package s3disk_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vibe-agi/s3disk"
)

func TestPrivateSecretValidationFailsClosedOnWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := s3disk.ValidatePrivateSecretDirectory(filepath.Dir(path)); !errors.Is(err, s3disk.ErrTrustStateUnsupported) {
		t.Fatalf("directory error = %v, want ErrTrustStateUnsupported", err)
	}
	if err := s3disk.ValidatePrivateSecretFile(path, file); !errors.Is(err, s3disk.ErrTrustStateUnsupported) {
		t.Fatalf("file error = %v, want ErrTrustStateUnsupported", err)
	}
}
