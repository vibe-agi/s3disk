//go:build windows

package s3disk

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsFileDeleteChild windows.ACCESS_MASK = 0x00000040

const windowsWatermarkWriteMask windows.ACCESS_MASK = windows.FILE_WRITE_DATA |
	windows.FILE_APPEND_DATA |
	windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES |
	windowsFileDeleteChild |
	windows.DELETE |
	windows.WRITE_DAC |
	windows.WRITE_OWNER |
	windows.ACCESS_MASK(windows.GENERIC_WRITE) |
	windows.ACCESS_MASK(windows.GENERIC_ALL)

func prepareWatermarkDirectory(directory string) (string, error) {
	missing := make([]string, 0, 4)
	current := filepath.Clean(directory)
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if !info.IsDir() {
				return "", fmt.Errorf("%w: watermark directory ancestor is not a directory", ErrCorruptObject)
			}
			if err := validateWatermarkDirectory(current); err != nil {
				return "", err
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("s3disk: no existing ancestor for watermark directory %q", directory)
		}
		current = parent
	}

	for index := len(missing) - 1; index >= 0; index-- {
		created := missing[index]
		parent := filepath.Dir(created)
		temporary, err := os.MkdirTemp(parent, ".s3disk-watermark-dir-")
		if err != nil {
			return "", err
		}
		removeTemporary := true
		defer func() {
			if removeTemporary {
				_ = os.Remove(temporary)
			}
		}()
		if err := validateWatermarkDirectory(temporary); err != nil {
			return "", err
		}
		err = moveWatermarkPathWindows(temporary, created, false)
		if err != nil {
			if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) && !errors.Is(err, windows.ERROR_FILE_EXISTS) {
				return "", fmt.Errorf("persist watermark directory %q: %w", created, err)
			}
			if removeErr := os.Remove(temporary); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				return "", removeErr
			}
		} else {
			removeTemporary = false
		}
		if err := validateWatermarkDirectory(created); err != nil {
			return "", err
		}
	}
	if err := validateWatermarkDirectory(directory); err != nil {
		return "", err
	}
	return filepath.Clean(directory), nil
}

func validateWatermarkDirectory(path string) error {
	linked, err := os.Lstat(path)
	if err != nil {
		return err
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	_, err = validateWatermarkOpenedPath(path, linked, directory, true)
	return err
}

func validateWatermarkPathSecurity(path string, _, _ os.FileInfo, file *os.File, _ bool) error {
	if err := rejectWindowsWatermarkReparsePath(path); err != nil {
		return err
	}
	return validateWindowsWatermarkACL(windows.Handle(file.Fd()))
}

func rejectWindowsWatermarkReparsePath(path string) error {
	current := filepath.Clean(path)
	for {
		if err := rejectWindowsWatermarkReparsePoint(current); err != nil {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func rejectWindowsWatermarkReparsePoint(path string) error {
	name, err := windows.UTF16PtrFromString(windowsExtendedPath(path))
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		name,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return fmt.Errorf("s3disk: inspect Windows watermark reparse attributes: %w", err)
	}
	defer windows.CloseHandle(handle)
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return fmt.Errorf("s3disk: read Windows watermark attributes: %w", err)
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%w: Windows watermark path component %q is a reparse point", ErrCorruptObject, path)
	}
	return nil
}

func validateWindowsWatermarkACL(handle windows.Handle) error {
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("s3disk: read Windows watermark ACL: %w", err)
	}
	if descriptor == nil || !descriptor.IsValid() {
		return fmt.Errorf("%w: Windows watermark has no valid security descriptor", ErrCorruptObject)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%w: Windows watermark has no restrictive DACL", ErrCorruptObject)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("s3disk: read Windows process identity: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		return fmt.Errorf("%w: Windows watermark has no valid owner", ErrCorruptObject)
	}
	if !allowedWindowsWatermarkWriter(owner, user.User.Sid) {
		return fmt.Errorf("%w: Windows watermark owner %s is not trusted", ErrCorruptObject, owner.String())
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return fmt.Errorf("s3disk: inspect Windows watermark ACE: %w", err)
		}
		if ace.Mask&windowsWatermarkWriteMask == 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return fmt.Errorf("%w: unsupported modifying Windows watermark ACE type %d", ErrCorruptObject, ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return fmt.Errorf("%w: Windows watermark ACL contains an invalid SID", ErrCorruptObject)
		}
		if !allowedWindowsWatermarkWriter(sid, user.User.Sid) {
			return fmt.Errorf("%w: Windows watermark ACL grants modification to %s", ErrCorruptObject, sid.String())
		}
	}
	return nil
}

func allowedWindowsWatermarkWriter(sid, current *windows.SID) bool {
	return sid.Equals(current) ||
		sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
		sid.IsWellKnown(windows.WinCreatorOwnerSid) ||
		sid.IsWellKnown(windows.WinCreatorOwnerRightsSid)
}

func protectWatermarkFile(path string, file *os.File) error {
	linked, err := os.Lstat(path)
	if err != nil {
		return err
	}
	_, err = validateWatermarkOpenedPath(path, linked, file, false)
	return err
}

func installWatermarkFile(temporary, destination string) error {
	return moveWatermarkPathWindows(temporary, destination, true)
}

func moveWatermarkPathWindows(source, destination string, replace bool) error {
	from, err := windows.UTF16PtrFromString(windowsExtendedPath(source))
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(windowsExtendedPath(destination))
	if err != nil {
		return err
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	return windows.MoveFileEx(from, to, flags)
}

func windowsExtendedPath(path string) string {
	if strings.HasPrefix(path, `\\?\`) {
		return path
	}
	if strings.HasPrefix(path, `\\`) {
		return `\\?\UNC\` + strings.TrimPrefix(path, `\\`)
	}
	return `\\?\` + path
}

// Durable watermark namespace changes use MoveFileEx with
// MOVEFILE_WRITE_THROUGH on Windows. Unlike os.File.Sync on a directory, that
// operation has an explicit documented write-through contract, so no separate
// directory flush is needed for the installed state.
func syncWatermarkDirectory(string) error { return nil }
