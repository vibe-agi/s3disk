package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/vibe-agi/s3disk"
)

const publisherSessionLockFileName = "session.lock"

var ErrPublisherSessionActive = errors.New("s3disk: publisher session is already active")

// publisherSessionLock is held for the complete publish or resume lifecycle.
// The persistent lock file is part of the private share namespace; Close only
// releases the kernel lock and descriptor so its identity can be validated on
// the next acquisition.
type publisherSessionLock struct {
	once    sync.Once
	release func() error
	err     error
}

func acquirePublisherSessionLock(ctx context.Context, shareDirectory string) (*publisherSessionLock, error) {
	if ctx == nil {
		return nil, fmt.Errorf("s3disk: publisher session lock context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := publisherSessionLockPlatformCheck(); err != nil {
		return nil, err
	}
	if shareDirectory == "" {
		return nil, fmt.Errorf("s3disk: publisher session directory is required")
	}
	directory, err := filepath.Abs(shareDirectory)
	if err != nil {
		return nil, fmt.Errorf("s3disk: resolve publisher session directory: %w", err)
	}
	directory = filepath.Clean(directory)
	linkedDirectory, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("s3disk: inspect publisher session directory: %w", err)
	}
	if !linkedDirectory.IsDir() || linkedDirectory.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: publisher session directory is not a real directory", s3disk.ErrCorruptObject)
	}
	if err := s3disk.ValidatePrivateSecretDirectory(directory); err != nil {
		return nil, fmt.Errorf("s3disk: unsafe publisher session directory: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	path := filepath.Join(directory, publisherSessionLockFileName)
	file, err := openPublisherSessionLockFile(path)
	if err != nil {
		return nil, err
	}
	closeFile := true
	defer func() {
		if closeFile {
			_ = file.Close()
		}
	}()
	if err := s3disk.ValidatePrivateSecretFile(path, file); err != nil {
		return nil, fmt.Errorf("s3disk: unsafe publisher session lock file: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := tryLockPublisherSessionFile(file); err != nil {
		return nil, err
	}
	locked := true
	defer func() {
		if locked {
			_ = unlockPublisherSessionFile(file)
		}
	}()
	// Revalidate the name-to-descriptor identity after acquiring the lock. This
	// catches replacement during the open/lock window before authority is handed
	// to the caller.
	if err := s3disk.ValidatePrivateSecretFile(path, file); err != nil {
		return nil, fmt.Errorf("s3disk: revalidate publisher session lock file: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	lock := &publisherSessionLock{release: func() error {
		return errors.Join(unlockPublisherSessionFile(file), file.Close())
	}}
	locked = false
	closeFile = false
	return lock, nil
}

func (lock *publisherSessionLock) Close() error {
	if lock == nil {
		return nil
	}
	lock.once.Do(func() {
		if lock.release != nil {
			lock.err = lock.release()
			lock.release = nil
		}
	})
	return lock.err
}
