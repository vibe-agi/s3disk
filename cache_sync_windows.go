//go:build windows

package s3disk

import "os"

func syncCacheDirectory(_ *os.File) error {
	// An ordinary Windows directory handle is opened without GENERIC_WRITE,
	// while FlushFileBuffers requires write access. Cache entries are disposable:
	// every temporary file is flushed before a rooted rename, and a lost namespace
	// update after a crash is safely recovered as a cache miss.
	return nil
}
