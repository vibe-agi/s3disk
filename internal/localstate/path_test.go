package localstate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateOpenedPathRequiresStableIdentity(t *testing.T) {
	directory, err := PrepareDirectory(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "watermark")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	linked, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateOpenedPath(path, linked, file, false); err != nil {
		t.Fatalf("stable path rejected: %v", err)
	}

	otherPath := filepath.Join(directory, "other")
	other, err := os.OpenFile(otherPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	otherInfo, err := os.Lstat(otherPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateOpenedPath(path, otherInfo, file, false); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("mismatched identity error = %v, want ErrUnsafe", err)
	}
}
