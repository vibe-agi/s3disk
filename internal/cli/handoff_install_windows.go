//go:build windows

package cli

import (
	"strings"

	"golang.org/x/sys/windows"
)

func installHandoffNoReplace(temporary, destination string) error {
	from, err := windows.UTF16PtrFromString(handoffWindowsExtendedPath(temporary))
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(handoffWindowsExtendedPath(destination))
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}

func handoffWindowsExtendedPath(path string) string {
	if strings.HasPrefix(path, `\\?\`) {
		return path
	}
	if strings.HasPrefix(path, `\\`) {
		return `\\?\UNC\` + strings.TrimPrefix(path, `\\`)
	}
	return `\\?\` + path
}
