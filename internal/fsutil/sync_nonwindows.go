//go:build !windows

package fsutil

import "os"

func SyncDirectory(directory *os.File) error {
	return directory.Sync()
}
