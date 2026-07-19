package s3disk

import (
	"fmt"
	"path"
	"strings"
	"unicode/utf8"
)

// validateSafeSymlink applies portable POSIX/Windows checks. Backslashes and
// drive-like first components are rejected because their meaning changes when
// a snapshot is mounted on another operating system.
func validateSafeSymlink(linkPath, target string) error {
	if target == "" || !utf8.ValidString(target) || strings.IndexByte(target, 0) >= 0 {
		return fmt.Errorf("%w: empty or invalid target", ErrUnsafeSymlink)
	}
	if strings.ContainsRune(target, '\\') || path.IsAbs(target) || strings.HasPrefix(target, "//") {
		return ErrUnsafeSymlink
	}
	first := target
	if index := strings.IndexByte(first, '/'); index >= 0 {
		first = first[:index]
	}
	if strings.ContainsRune(first, ':') {
		return ErrUnsafeSymlink
	}
	resolved := path.Clean(path.Join(path.Dir(linkPath), target))
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return ErrUnsafeSymlink
	}
	return nil
}
