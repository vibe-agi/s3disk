package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vibe-agi/s3disk"
)

var (
	errPrivateFileExists = errors.New("s3disk: private output already exists")

	ErrPrivateFileInstallIndeterminate = errors.New("s3disk: private output installation is indeterminate")
	ErrPrivateFileInstalledUnconfirmed = errors.New("s3disk: private output is installed but cleanup or durability is unconfirmed")
)

type privateFileInstaller func(temporary, destination string) error

type privateFileWriteResult struct {
	InstallAttempted      bool
	InstallResolved       bool
	NotInstalledConfirmed bool
	Installed             bool
	CleanupConfirmed      bool
	DurabilityConfirmed   bool
}

func (result privateFileWriteResult) needsReconciliation() bool {
	return result.InstallAttempted && (!result.InstallResolved ||
		(result.Installed && (!result.CleanupConfirmed || !result.DurabilityConfirmed)))
}

type privateFileOperations struct {
	install           privateFileInstaller
	remove            func(string) error
	syncDirectory     func(string) error
	beforeSecretWrite func()
	beforeInstall     func()
}

func privateFileOperationsFor(install privateFileInstaller) privateFileOperations {
	return privateFileOperations{install: install, remove: os.Remove, syncDirectory: syncPrivateDirectory}
}

func (operations privateFileOperations) withDefaults() privateFileOperations {
	if operations.remove == nil {
		operations.remove = os.Remove
	}
	if operations.syncDirectory == nil {
		operations.syncDirectory = syncPrivateDirectory
	}
	return operations
}

// writePrivateFileNoReplace writes and syncs a complete secret in the final
// directory before atomically installing its pathname without replacement.
// The caller must resolve the final parent first so staging and installation
// cannot cross filesystems.
func writePrivateFileNoReplace(
	ctx context.Context,
	absolute resolvedPrivatePath,
	encoded []byte,
	maximumBytes int64,
	temporaryPattern string,
	operations privateFileOperations,
) (privateFileWriteResult, error) {
	defer clear(encoded)
	if ctx == nil {
		return privateFileWriteResult{}, fmt.Errorf("s3disk: private output context is required")
	}
	if err := ctx.Err(); err != nil {
		return privateFileWriteResult{}, err
	}
	operations = operations.withDefaults()
	path := string(absolute)
	if path == "" || !filepath.IsAbs(path) || len(encoded) == 0 ||
		int64(len(encoded)) > maximumBytes || maximumBytes < 1 ||
		temporaryPattern == "" || operations.install == nil {
		return privateFileWriteResult{}, fmt.Errorf("s3disk: invalid private output configuration")
	}
	directory := filepath.Dir(path)
	if err := s3disk.ValidatePrivateSecretDirectory(directory); err != nil {
		return privateFileWriteResult{}, fmt.Errorf("s3disk: unsafe private output directory: %w", err)
	}
	if _, err := os.Lstat(path); err == nil {
		return privateFileWriteResult{}, errPrivateFileExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return privateFileWriteResult{}, fmt.Errorf("s3disk: inspect private output: %w", err)
	}

	file, err := os.CreateTemp(directory, temporaryPattern)
	if err != nil {
		return privateFileWriteResult{}, fmt.Errorf("s3disk: create staged private output: %w", err)
	}
	temporary := file.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = operations.remove(temporary)
		}
	}()
	created, statErr := file.Stat()
	if statErr != nil || !created.Mode().IsRegular() {
		_ = file.Close()
		return privateFileWriteResult{}, fmt.Errorf("s3disk: staged private output is not a regular file")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return privateFileWriteResult{}, fmt.Errorf("s3disk: set staged private output permissions: %w", err)
	}
	// Validate the descriptor, current pathname, owner, exact mode, ACL, and
	// complete parent hierarchy before secret bytes cross the filesystem
	// boundary. Unsupported ACL platforms fail here before the first write.
	if err := s3disk.ValidatePrivateSecretFile(temporary, file); err != nil {
		_ = file.Close()
		return privateFileWriteResult{}, fmt.Errorf("s3disk: protect staged private output: %w", err)
	}
	if operations.beforeSecretWrite != nil {
		operations.beforeSecretWrite()
	}
	if err := ctx.Err(); err != nil {
		_ = file.Close()
		return privateFileWriteResult{}, err
	}
	if err := writeAll(file, encoded); err != nil {
		_ = file.Close()
		return privateFileWriteResult{}, fmt.Errorf("s3disk: write staged private output: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return privateFileWriteResult{}, fmt.Errorf("s3disk: sync staged private output: %w", err)
	}
	stagedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return privateFileWriteResult{}, fmt.Errorf("s3disk: stat synced private output: %w", err)
	}
	if !stagedInfo.Mode().IsRegular() {
		_ = file.Close()
		return privateFileWriteResult{}, fmt.Errorf("s3disk: synced private output is not a regular file")
	}
	if err := file.Close(); err != nil {
		return privateFileWriteResult{}, fmt.Errorf("s3disk: close staged private output: %w", err)
	}
	if operations.beforeInstall != nil {
		operations.beforeInstall()
	}
	if err := ctx.Err(); err != nil {
		return privateFileWriteResult{}, err
	}

	result := privateFileWriteResult{InstallAttempted: true}
	installErr := operations.install(temporary, path)
	reconciliation, reconciliationErr := reconcilePrivateFile(path, stagedInfo)
	if !reconciliation.sameStagingFile {
		if errors.Is(installErr, os.ErrExist) && reconciliation.validatedOtherFile {
			result.InstallResolved = true
			result.NotInstalledConfirmed = true
			return result, errPrivateFileExists
		}
		if installErr != nil && errors.Is(reconciliationErr, os.ErrNotExist) {
			result.InstallResolved = true
			result.NotInstalledConfirmed = true
			return result, fmt.Errorf("s3disk: private output installer: %w", installErr)
		}
		if installErr != nil {
			installErr = fmt.Errorf("s3disk: private output installer: %w", installErr)
		}
		if reconciliationErr != nil {
			reconciliationErr = fmt.Errorf("s3disk: reconcile installed private output: %w", reconciliationErr)
		}
		return result, errors.Join(ErrPrivateFileInstallIndeterminate, installErr, reconciliationErr)
	}

	result.InstallResolved = true
	result.Installed = true
	removeErr := operations.remove(temporary)
	if removeErr == nil || errors.Is(removeErr, os.ErrNotExist) {
		removeTemporary = false
		result.CleanupConfirmed = true
	} else {
		removeErr = fmt.Errorf("s3disk: remove staged private output: %w", removeErr)
	}
	syncErr := operations.syncDirectory(directory)
	if syncErr == nil {
		result.DurabilityConfirmed = true
	} else {
		syncErr = fmt.Errorf("s3disk: sync private output directory: %w", syncErr)
	}
	if removeErr != nil || syncErr != nil {
		return result, errors.Join(ErrPrivateFileInstalledUnconfirmed, removeErr, syncErr)
	}
	return result, nil
}

type privateFileReconciliation struct {
	sameStagingFile    bool
	validatedOtherFile bool
}

func reconcilePrivateFile(path string, staged os.FileInfo) (privateFileReconciliation, error) {
	linked, err := os.Lstat(path)
	if err != nil {
		return privateFileReconciliation{}, err
	}
	if linked.Mode()&os.ModeSymlink != 0 || !linked.Mode().IsRegular() {
		return privateFileReconciliation{}, fmt.Errorf("final private output is not a regular non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return privateFileReconciliation{}, err
	}
	defer file.Close()
	if err := s3disk.ValidatePrivateSecretFile(path, file); err != nil {
		return privateFileReconciliation{}, err
	}
	opened, err := file.Stat()
	if err != nil {
		return privateFileReconciliation{}, err
	}
	if os.SameFile(staged, linked) && os.SameFile(staged, opened) {
		return privateFileReconciliation{sameStagingFile: true}, nil
	}
	return privateFileReconciliation{validatedOtherFile: true}, nil
}

// resolvedPrivatePath is deliberately local to prevent an unresolved user
// pathname from being passed to the atomic writer by accident.
type resolvedPrivatePath string

func resolvePrivatePath(path string) (resolvedPrivatePath, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	base := filepath.Base(absolute)
	if base == "." || base == string(os.PathSeparator) || strings.ContainsRune(base, '\x00') {
		return "", fmt.Errorf("invalid final path component")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("parent is not an existing directory")
	}
	return resolvedPrivatePath(filepath.Join(parent, base)), nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		count, err := writer.Write(data)
		if err != nil {
			return err
		}
		if count < 1 || count > len(data) {
			return io.ErrShortWrite
		}
		data = data[count:]
	}
	return nil
}

func syncPrivateDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
