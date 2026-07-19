//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package s3disk

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func touchCacheFile(file *os.File, now time.Time) error {
	timestamp := unix.NsecToTimeval(now.UnixNano())
	return unix.Futimes(int(file.Fd()), []unix.Timeval{timestamp, timestamp})
}
