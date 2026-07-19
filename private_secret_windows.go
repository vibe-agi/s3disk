//go:build windows

package s3disk

import (
	"fmt"
	"os"
)

func validatePrivateSecretDirectory(string) error {
	return fmt.Errorf("%w: private secret confidentiality is not yet proven on Windows", ErrTrustStateUnsupported)
}

func validatePrivateSecretFile(string, *os.File) error {
	return fmt.Errorf("%w: private secret confidentiality is not yet proven on Windows", ErrTrustStateUnsupported)
}
