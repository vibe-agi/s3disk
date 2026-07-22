//go:build plan9

package localstate

import (
	"fmt"
	"os"
)

func ValidatePrivateSecretDirectory(string) error {
	return fmt.Errorf("%w: private secret directory ownership cannot be proven on Plan 9", ErrUnsupported)
}

func ValidatePrivateSecretFile(string, *os.File) error {
	return fmt.Errorf("%w: private secret file ownership cannot be proven on Plan 9", ErrUnsupported)
}
