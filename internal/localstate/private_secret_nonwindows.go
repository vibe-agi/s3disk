//go:build !windows && !plan9

package localstate

import (
	"fmt"
	"os"
	"syscall"
)

func ValidatePrivateSecretDirectory(path string) error {
	if err := ValidateDirectory(path); err != nil {
		return fmt.Errorf("s3disk: unsafe private secret directory: %w", err)
	}
	return nil
}

func ValidatePrivateSecretFile(path string, file *os.File) error {
	linked, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("s3disk: inspect private secret file: %w", err)
	}
	opened, err := ValidateOpenedPath(path, linked, file, false)
	if err != nil {
		return fmt.Errorf("s3disk: validate private secret file: %w", err)
	}
	if linked.Mode().Perm() != 0o600 || opened.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: private secret file permissions must be exactly 0600", ErrUnsafe)
	}
	if !privateSecretOwnedByCurrentProcess(linked) || !privateSecretOwnedByCurrentProcess(opened) {
		return fmt.Errorf("%w: private secret file is not owned by the current process identity", ErrUnsafe)
	}
	if !privateSecretHasSingleLink(linked) || !privateSecretHasSingleLink(opened) {
		return fmt.Errorf("%w: private secret file must have exactly one filesystem link", ErrUnsafe)
	}
	return nil
}

func privateSecretOwnedByCurrentProcess(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Uid) == uint64(os.Geteuid())
}

func privateSecretHasSingleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Nlink) == 1
}
