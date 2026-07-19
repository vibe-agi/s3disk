//go:build windows

package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/vibe-agi/s3disk"
	"golang.org/x/sys/windows"
)

func publisherSessionLockPlatformCheck() error { return nil }

func openPublisherSessionLockFile(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("s3disk: encode publisher session lock path: %w", err)
	}
	open := func(disposition uint32) (windows.Handle, error) {
		return windows.CreateFile(
			name,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			nil,
			disposition,
			windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
			0,
		)
	}
	handle, err := open(windows.CREATE_NEW)
	if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		handle, err = open(windows.OPEN_EXISTING)
	}
	if err != nil {
		return nil, fmt.Errorf("s3disk: open publisher session lock file: %w", err)
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("s3disk: inspect publisher session lock file: %w", err)
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("%w: publisher session lock file is a reparse point", s3disk.ErrCorruptObject)
	}
	return os.NewFile(uintptr(handle), path), nil
}

func tryLockPublisherSessionFile(file *os.File) error {
	overlapped := new(windows.Overlapped)
	err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		overlapped,
	)
	if err == nil {
		return nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrPublisherSessionActive
	}
	return fmt.Errorf("s3disk: lock publisher session: %w", err)
}

func unlockPublisherSessionFile(file *os.File) error {
	if err := windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, new(windows.Overlapped)); err != nil {
		return fmt.Errorf("s3disk: unlock publisher session: %w", err)
	}
	return nil
}
