//go:build !windows && !plan9

package s3disk

import (
	"fmt"
	"os"
	"syscall"
)

func validatePrivateSecretDirectory(path string) error {
	if err := validateWatermarkDirectory(path); err != nil {
		return fmt.Errorf("s3disk: unsafe private secret directory: %w", err)
	}
	return nil
}

func validatePrivateSecretFile(path string, file *os.File) error {
	linked, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("s3disk: inspect private secret file: %w", err)
	}
	opened, err := validateWatermarkOpenedPath(path, linked, file, false)
	if err != nil {
		return fmt.Errorf("s3disk: validate private secret file: %w", err)
	}
	if linked.Mode().Perm() != 0o600 || opened.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: private secret file permissions must be exactly 0600", ErrCorruptObject)
	}
	if !privateSecretOwnedByCurrentProcess(linked) || !privateSecretOwnedByCurrentProcess(opened) {
		return fmt.Errorf("%w: private secret file is not owned by the current process identity", ErrCorruptObject)
	}
	return nil
}

func privateSecretOwnedByCurrentProcess(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Uid) == uint64(os.Geteuid())
}
