//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !windows

package cli

import (
	"fmt"
	"os"
	"runtime"

	"github.com/vibe-agi/s3disk"
)

func publisherSessionLockPlatformCheck() error {
	return fmt.Errorf("%w: publisher session lifecycle locks are unavailable on %s", s3disk.ErrTrustStateUnsupported, runtime.GOOS)
}

func openPublisherSessionLockFile(string) (*os.File, error) {
	return nil, publisherSessionLockPlatformCheck()
}

func tryLockPublisherSessionFile(*os.File) error { return publisherSessionLockPlatformCheck() }

func unlockPublisherSessionFile(*os.File) error { return publisherSessionLockPlatformCheck() }
