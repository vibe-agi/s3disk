//go:build windows

package localstate

import (
	"fmt"
	"os"
)

func ValidatePrivateSecretDirectory(string) error {
	return fmt.Errorf("%w: private secret confidentiality is not yet proven on Windows", ErrUnsupported)
}

func ValidatePrivateSecretFile(string, *os.File) error {
	return fmt.Errorf("%w: private secret confidentiality is not yet proven on Windows", ErrUnsupported)
}
