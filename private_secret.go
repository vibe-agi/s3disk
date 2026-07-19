package s3disk

import (
	"fmt"
	"os"
	"path/filepath"
)

// ValidatePrivateSecretDirectory proves that an existing directory is a safe
// location for a process-owned secret file. The proof is platform specific and
// includes the complete directory hierarchy, ownership, writable permissions,
// and any supported ACL mechanism. Unsupported platforms fail closed.
func ValidatePrivateSecretDirectory(path string) error {
	if path == "" {
		return fmt.Errorf("s3disk: private secret directory is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("s3disk: resolve private secret directory: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return fmt.Errorf("s3disk: resolve private secret directory symlinks: %w", err)
	}
	return validatePrivateSecretDirectory(filepath.Clean(resolved))
}

// ValidatePrivateSecretFile proves that file is the same regular file named by
// path, is owned by the current process identity, has exactly 0600 permissions,
// and resides below a trusted private-secret directory hierarchy. ACLs are
// inspected where the platform exposes a sound implementation. The caller must
// invoke this before writing or reading secret bytes. Unsupported platforms
// fail closed.
func ValidatePrivateSecretFile(path string, file *os.File) error {
	if path == "" || file == nil {
		return fmt.Errorf("s3disk: private secret path and open file are required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("s3disk: resolve private secret file: %w", err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return fmt.Errorf("s3disk: resolve private secret parent symlinks: %w", err)
	}
	return validatePrivateSecretFile(filepath.Join(parent, filepath.Base(absolute)), file)
}
