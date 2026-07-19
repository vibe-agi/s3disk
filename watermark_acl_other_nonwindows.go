//go:build !darwin && !linux && !windows

package s3disk

import (
	"fmt"
	"os"
	"runtime"
)

func validateUnixWatermarkACL(*os.File) error {
	return fmt.Errorf("%w: extended ACL inspection is unavailable on %s", ErrTrustStateUnsupported, runtime.GOOS)
}
