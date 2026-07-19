//go:build plan9

package s3disk

import (
	"fmt"
	"os"
)

func validatePrivateSecretDirectory(string) error {
	return fmt.Errorf("%w: private secret directory ownership cannot be proven on Plan 9", ErrTrustStateUnsupported)
}

func validatePrivateSecretFile(string, *os.File) error {
	return fmt.Errorf("%w: private secret file ownership cannot be proven on Plan 9", ErrTrustStateUnsupported)
}
