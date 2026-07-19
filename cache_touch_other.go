//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || windows)

package s3disk

import (
	"os"
	"time"
)

func touchCacheFile(_ *os.File, _ time.Time) error {
	return nil
}
