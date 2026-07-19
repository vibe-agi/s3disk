//go:build plan9

package s3disk

import "os"

// Plan 9 does not expose a numeric uid through os.FileInfo. File trust-state
// there has only the documented process-local/path-mode protection and is not
// a commercial anti-rollback target.
func trustedWatermarkPathOwner(os.FileInfo) bool { return true }
