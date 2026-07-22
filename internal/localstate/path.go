package localstate

import (
	"fmt"
	"os"
)

// ValidateOpenedPath proves that linked and file identify the same regular
// file or directory and then applies the platform security checks.
func ValidateOpenedPath(path string, linked os.FileInfo, file *os.File, directory bool) (os.FileInfo, error) {
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("s3disk: stat watermark path: %w", err)
	}
	kindMatches := linked.Mode().IsRegular() && opened.Mode().IsRegular()
	if directory {
		kindMatches = linked.IsDir() && opened.IsDir()
	}
	if !kindMatches || !os.SameFile(linked, opened) {
		return nil, fmt.Errorf("%w: unsafe watermark path type or identity", ErrUnsafe)
	}
	if err := validateWatermarkPathSecurity(path, linked, opened, file, directory); err != nil {
		return nil, err
	}
	return opened, nil
}
