//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || windows)

package fsutil

import (
	"os"
	"time"
)

func TouchFile(_ *os.File, _ time.Time) error {
	return nil
}
