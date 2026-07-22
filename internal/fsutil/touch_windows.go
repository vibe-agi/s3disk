//go:build windows

package fsutil

import (
	"os"
	"time"
)

func TouchFile(_ *os.File, _ time.Time) error {
	// os.Root.Open intentionally yields a read-only handle. Updating timestamps
	// would require reopening by pathname with FILE_WRITE_ATTRIBUTES, weakening
	// the root confinement guarantee. Recency remains correct in memory.
	return nil
}
