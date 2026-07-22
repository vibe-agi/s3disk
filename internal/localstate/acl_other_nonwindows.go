//go:build !darwin && !linux && !windows

package localstate

import (
	"fmt"
	"os"
	"runtime"
)

func validateUnixWatermarkACL(*os.File) error {
	return fmt.Errorf("%w: extended ACL inspection is unavailable on %s", ErrUnsupported, runtime.GOOS)
}
