//go:build !windows

package s3disk

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func prepareWatermarkDirectory(directory string) (string, error) {
	missing := make([]string, 0, 4)
	current := filepath.Clean(directory)
	for {
		_, err := os.Lstat(current)
		if err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			current = filepath.Clean(resolved)
			// The nearest existing component is an ancestor of every directory
			// still to create. A trusted sticky directory such as /tmp is safe in
			// that role, but never as the final trust-state directory itself.
			if err := validateWatermarkDirectoryHierarchy(current, true); err != nil {
				return "", err
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		missing = append(missing, filepath.Base(current))
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("s3disk: no existing ancestor for watermark directory %q", directory)
		}
		current = parent
	}

	for index := len(missing) - 1; index >= 0; index-- {
		created := filepath.Join(current, missing[index])
		if err := os.Mkdir(created, 0o700); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return "", err
			}
		} else if err := syncWatermarkDirectory(filepath.Dir(created)); err != nil {
			return "", fmt.Errorf("persist watermark directory %q: %w", created, err)
		}
		if err := validateWatermarkDirectory(created); err != nil {
			return "", err
		}
		current = created
	}
	if err := validateWatermarkDirectory(current); err != nil {
		return "", err
	}
	return current, nil
}

func validateWatermarkDirectory(path string) error {
	return validateWatermarkDirectoryHierarchy(path, false)
}

func validateWatermarkDirectoryHierarchy(path string, allowStickyFinal bool) error {
	components := make([]string, 0, 8)
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		components = append(components, current)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	for index := len(components) - 1; index >= 0; index-- {
		component := components[index]
		linked, err := os.Lstat(component)
		if err != nil {
			return err
		}
		if !linked.IsDir() || linked.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: watermark directory component %q is not a real directory", ErrCorruptObject, component)
		}
		directory, err := os.Open(component)
		if err != nil {
			return err
		}
		opened, statErr := directory.Stat()
		var aclErr error
		if statErr == nil {
			if err := validateUnixWatermarkACL(directory); err != nil {
				aclErr = fmt.Errorf("s3disk: validate watermark directory component %q ACL: %w", component, err)
			}
		}
		closeErr := directory.Close()
		if statErr != nil || aclErr != nil || closeErr != nil {
			return errors.Join(statErr, aclErr, closeErr)
		}
		if !opened.IsDir() || !os.SameFile(linked, opened) {
			return fmt.Errorf("%w: watermark directory component %q changed identity", ErrCorruptObject, component)
		}
		if !trustedWatermarkPathOwner(opened) {
			return fmt.Errorf("%w: watermark directory component %q has an untrusted owner", ErrCorruptObject, component)
		}
		permissions := opened.Mode().Perm()
		if permissions&0o022 != 0 {
			isFinal := index == 0
			// A currently private ancestor is not a substitute for this check:
			// another UID may have retained a descriptor for this component
			// before the ancestor was tightened and can use *at operations through
			// that descriptor without traversing the current path.
			if (isFinal && !allowStickyFinal) || opened.Mode()&os.ModeSticky == 0 {
				return fmt.Errorf("%w: watermark directory component %q is group/world writable", ErrCorruptObject, component)
			}
		}
	}
	return nil
}

func validateWatermarkPathSecurity(path string, linked, opened os.FileInfo, file *os.File, directory bool) error {
	// Mode bits are not a complete authorization signal on every Unix target.
	// In particular, Darwin extended ACLs can grant another UID write access
	// while stat still reports 0600/0700. Validate the already-opened object so
	// this check cannot be redirected through a path race.
	if err := validateUnixWatermarkACL(file); err != nil {
		return err
	}
	if !trustedWatermarkPathOwner(linked) || !trustedWatermarkPathOwner(opened) {
		return fmt.Errorf("%w: watermark path has an untrusted owner", ErrCorruptObject)
	}
	if linked.Mode().Perm()&0o022 != 0 || opened.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: watermark path is group/world writable", ErrCorruptObject)
	}
	if !directory {
		if err := validateWatermarkDirectory(filepath.Dir(path)); err != nil {
			return err
		}
	}
	return nil
}

func protectWatermarkFile(_ string, file *os.File) error {
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	// chmod does not remove an inherited Darwin ACL. Check after chmod so a
	// temporary state file never reaches rename with a hidden foreign writer.
	return validateUnixWatermarkACL(file)
}

func installWatermarkFile(temporary, destination string) error {
	return os.Rename(temporary, destination)
}

func syncWatermarkDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("s3disk: open watermark directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("s3disk: sync watermark directory: %w", err)
	}
	return nil
}
