//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package fsutil

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func TouchFile(file *os.File, now time.Time) error {
	timestamp := unix.NsecToTimeval(now.UnixNano())
	return unix.Futimes(int(file.Fd()), []unix.Timeval{timestamp, timestamp})
}
