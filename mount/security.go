package mount

import (
	"errors"
	"fmt"

	"github.com/vibe-agi/s3disk"
)

// validateReadOnlySecurity is deliberately pure. ReadOnly calls it before
// mountpoint inspection, object-store refresh, or FUSE setup.
func validateReadOnlySecurity(status s3disk.ConsumerSecurityStatus, options Options) error {
	var failures []error
	if !status.DurableWatermarkConfigured && !options.DangerouslyAllowMountWithoutDurableWatermark {
		failures = append(failures, fmt.Errorf(
			"%w; Options.DangerouslyAllowMountWithoutDurableWatermark is an explicit rollback-risk opt-out",
			ErrDurableWatermarkRequired,
		))
	}
	if status.SymlinkPolicy == s3disk.SymlinkPreserve && !options.DangerouslyAllowMountWithPreservedSymlinks {
		failures = append(failures, fmt.Errorf(
			"%w; Options.DangerouslyAllowMountWithPreservedSymlinks is an explicit mount-escape-risk opt-out",
			ErrSymlinkPreserveUnsafe,
		))
	}
	return errors.Join(failures...)
}
