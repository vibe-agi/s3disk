//go:build !windows

package cli

import "os"

// installPrivateFileNoReplace uses a hard link as a portable Unix no-replace
// namespace operation. Both names are in the same private directory; the
// common writer removes the staging name and syncs the directory afterward.
func installPrivateFileNoReplace(temporary, destination string) error {
	return os.Link(temporary, destination)
}
