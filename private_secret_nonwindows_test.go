//go:build !windows && !plan9

package s3disk_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vibe-agi/s3disk"
)

func TestValidatePrivateSecretFileRejectsUnsafeLocalBoundaries(t *testing.T) {
	privateDirectory := t.TempDir()
	path := filepath.Join(privateDirectory, "secret")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		t.Fatal(err)
	}
	if err := s3disk.ValidatePrivateSecretDirectory(privateDirectory); err != nil {
		t.Fatalf("ValidatePrivateSecretDirectory: %v", err)
	}
	if err := s3disk.ValidatePrivateSecretFile(path, file); err != nil {
		t.Fatalf("ValidatePrivateSecretFile: %v", err)
	}

	if err := file.Chmod(0o640); err != nil {
		t.Fatal(err)
	}
	if err := s3disk.ValidatePrivateSecretFile(path, file); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("loose-mode error = %v, want ErrCorruptObject", err)
	}
	if err := file.Chmod(0o600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(privateDirectory, "secret-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := s3disk.ValidatePrivateSecretFile(link, file); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("symlink error = %v, want ErrCorruptObject", err)
	}
}

func TestValidatePrivateSecretFileRejectsWritableParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "secret")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := s3disk.ValidatePrivateSecretFile(path, file); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("writable-parent error = %v, want ErrCorruptObject", err)
	}
}

func TestValidatePrivateSecretFileRejectsForeignOwnerWhenTestCanSetOne(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing a file to a foreign owner requires root")
	}
	path := filepath.Join(t.TempDir(), "secret")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Chown(65534, -1); err != nil {
		t.Skipf("foreign chown is unavailable: %v", err)
	}
	if err := s3disk.ValidatePrivateSecretFile(path, file); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("foreign-owner error = %v, want ErrCorruptObject", err)
	}
}
