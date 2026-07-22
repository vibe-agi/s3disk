package s3disk

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/vibe-agi/s3disk/internal/localstate"
)

// translateLocalStateError keeps platform enforcement details private while
// preserving the public error contract used by existing callers.
func translateLocalStateError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, localstate.ErrUnsafe):
		return fmt.Errorf("%w: %w", ErrCorruptObject, err)
	case errors.Is(err, localstate.ErrUnsupported):
		return fmt.Errorf("%w: %w", ErrTrustStateUnsupported, err)
	default:
		return err
	}
}

func prepareWatermarkDirectory(directory string) (string, error) {
	prepared, err := localstate.PrepareDirectory(directory)
	return prepared, translateLocalStateError(err)
}

func validateWatermarkDirectory(path string) error {
	return translateLocalStateError(localstate.ValidateDirectory(path))
}

func validatePrivateSecretDirectory(path string) error {
	return translateLocalStateError(localstate.ValidatePrivateSecretDirectory(path))
}

func validatePrivateSecretFile(path string, file *os.File) error {
	return translateLocalStateError(localstate.ValidatePrivateSecretFile(path, file))
}

func validateWatermarkOpenedPath(path string, linked os.FileInfo, file *os.File, directory bool) (os.FileInfo, error) {
	opened, err := localstate.ValidateOpenedPath(path, linked, file, directory)
	return opened, translateLocalStateError(err)
}

func protectWatermarkFile(path string, file *os.File) error {
	return translateLocalStateError(localstate.ProtectFile(path, file))
}

func installWatermarkFile(temporary, destination string) error {
	return translateLocalStateError(localstate.InstallFile(temporary, destination))
}

func syncWatermarkDirectory(path string) error {
	return translateLocalStateError(localstate.SyncDirectory(path))
}

func lockWatermarkFile(ctx context.Context, path string) (func() error, error) {
	unlock, err := localstate.LockFile(ctx, path)
	if err != nil {
		return nil, translateLocalStateError(err)
	}
	return func() error { return translateLocalStateError(unlock()) }, nil
}
