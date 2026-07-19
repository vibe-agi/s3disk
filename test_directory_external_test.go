package s3disk_test

import (
	"os"
	"runtime"
	"testing"
)

// privateTestDirectory makes the directory containing security-sensitive test
// state independent of the process umask. See the matching internal-package
// helper for the trust-state rationale.
func privateTestDirectory(t testing.TB) string {
	t.Helper()
	directory := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatalf("protect test directory: %v", err)
		}
	}
	return directory
}
