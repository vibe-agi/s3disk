//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package s3disk

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

func lockWatermarkFile(ctx context.Context, path string) (func() error, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("s3disk: open watermark lock: %w", err)
	}
	if err := validateWatermarkLockFile(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() error {
				unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				return errors.Join(unlockErr, file.Close())
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, fmt.Errorf("s3disk: lock watermark: %w", err)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			_ = file.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func validateWatermarkLockFile(path string, file *os.File) error {
	linked, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("s3disk: inspect watermark lock: %w", err)
	}
	_, err = validateWatermarkOpenedPath(path, linked, file, false)
	return err
}
