//go:build darwin && !cgo

package localstate

import (
	"fmt"
	"os"
)

func validateUnixWatermarkACL(*os.File) error {
	return fmt.Errorf("%w: Darwin extended ACL inspection requires cgo", ErrUnsupported)
}
