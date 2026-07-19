//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/vibe-agi/s3disk"
	"golang.org/x/sys/unix"
)

func publisherSessionLockPlatformCheck() error { return nil }

func openPublisherSessionLockFile(path string) (*os.File, error) {
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	fd, err := unix.Open(path, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Open(path, flags, 0)
	}
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%w: publisher session lock file is a symlink", s3disk.ErrCorruptObject)
		}
		return nil, fmt.Errorf("s3disk: open publisher session lock file: %w", err)
	}
	return os.NewFile(uintptr(fd), path), nil
}

func tryLockPublisherSessionFile(file *os.File) error {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return ErrPublisherSessionActive
	}
	return fmt.Errorf("s3disk: lock publisher session: %w", err)
}

func unlockPublisherSessionFile(file *os.File) error {
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		return fmt.Errorf("s3disk: unlock publisher session: %w", err)
	}
	return nil
}
