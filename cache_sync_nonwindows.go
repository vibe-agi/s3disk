//go:build !windows

package s3disk

import "os"

func syncCacheDirectory(directory *os.File) error {
	return directory.Sync()
}
