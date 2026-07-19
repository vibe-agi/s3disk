//go:build !windows

package cli

import "os"

// installHandoffNoReplace uses a hard link as a portable Unix no-replace
// namespace operation. Both names are in the same private directory. Removing
// the staging name leaves the fully synced inode installed at destination.
func installHandoffNoReplace(temporary, destination string) error {
	if err := os.Link(temporary, destination); err != nil {
		return err
	}
	return os.Remove(temporary)
}
