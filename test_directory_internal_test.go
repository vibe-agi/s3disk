package s3disk

import (
	"os"
	"runtime"
	"testing"
)

// privateTestDirectory makes the directory containing security-sensitive test
// state independent of the process umask. testing.T.TempDir's numbered child
// uses 0777 masked by umask, so an umask such as 0002 otherwise produces an
// intentionally rejected group-writable final directory.
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
