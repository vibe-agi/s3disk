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

const maximumPrivateStagingScanEntries = 100_000

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
		!result.CleanupConfirmed || !result.DurabilityConfirmed)
}

// reconcileInstalledPrivateFileStaging removes only reserved staging names
// which still identify the exact installed inode. This carries a hard-link
// install's cleanup obligation across process restarts without deleting an
// unrelated file which merely happens to match the temporary-name pattern.
// The caller must sync the directory after this returns, whether it succeeds
// or fails, so removals and the installed destination share one durability
// barrier.
func reconcileInstalledPrivateFileStaging(
	ctx context.Context,
	absolute resolvedPrivatePath,
	temporaryPattern string,
	operations privateFileOperations,
) error {
	if ctx == nil {
		return fmt.Errorf("s3disk: private staging reconciliation context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	operations = operations.withDefaults()
	path := string(absolute)
	wildcard := strings.LastIndexByte(temporaryPattern, '*')
	if path == "" || !filepath.IsAbs(path) || wildcard < 0 ||
		strings.Count(temporaryPattern, "*") != 1 ||
		strings.ContainsRune(temporaryPattern, filepath.Separator) {
		return fmt.Errorf("s3disk: invalid private staging reconciliation configuration")
	}
	prefix := temporaryPattern[:wildcard]
	suffix := temporaryPattern[wildcard+1:]
	matchesTemporaryName := func(name string) bool {
		return len(name) > len(prefix)+len(suffix) &&
			strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix)
	}

	directory := filepath.Dir(path)
	if err := s3disk.ValidatePrivateSecretDirectory(directory); err != nil {
		return fmt.Errorf("s3disk: unsafe private staging directory: %w", err)
	}
	installedPathInfo, err := os.Lstat(path)
	if err != nil || installedPathInfo.Mode()&os.ModeSymlink != 0 || !installedPathInfo.Mode().IsRegular() {
		return fmt.Errorf("s3disk: installed private output is not a regular non-symlink file")
	}
	installed, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("s3disk: open installed private output: %w", err)
	}
	installedInfo, statErr := installed.Stat()
	validationErr := s3disk.ValidatePrivateSecretFile(path, installed)
	closeErr := installed.Close()
	if statErr != nil || validationErr != nil || closeErr != nil ||
		!os.SameFile(installedPathInfo, installedInfo) {
		return fmt.Errorf("s3disk: installed private output changed before staging reconciliation")
	}

	directoryFile, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("s3disk: open private staging directory: %w", err)
	}
	directoryOpen := true
	defer func() {
		if directoryOpen {
			_ = directoryFile.Close()
		}
	}()
	entriesSeen := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, readErr := directoryFile.ReadDir(256)
		entriesSeen += len(entries)
		if entriesSeen > maximumPrivateStagingScanEntries {
			return fmt.Errorf("s3disk: %w: private staging directory exceeds %d entries", s3disk.ErrResourceLimit, maximumPrivateStagingScanEntries)
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			name := entry.Name()
			if name == filepath.Base(path) || !matchesTemporaryName(name) {
				continue
			}
			candidate := filepath.Join(directory, name)
			candidateInfo, candidateErr := os.Lstat(candidate)
			if errors.Is(candidateErr, os.ErrNotExist) {
				continue
			}
			if candidateErr != nil {
				return fmt.Errorf("s3disk: inspect staged private output: %w", candidateErr)
			}
			if candidateInfo.Mode()&os.ModeSymlink != 0 || !candidateInfo.Mode().IsRegular() ||
				!os.SameFile(installedInfo, candidateInfo) {
				continue
			}

			// Recheck both pathnames immediately before unlinking. The surrounding
			// private-directory ownership policy excludes untrusted writers; this
			// second identity check also fails closed on accidental concurrent use.
			currentInstalled, installedErr := os.Lstat(path)
			currentCandidate, stagedErr := os.Lstat(candidate)
			if installedErr != nil || stagedErr != nil ||
				!os.SameFile(installedInfo, currentInstalled) ||
				!os.SameFile(installedInfo, currentCandidate) {
				return fmt.Errorf("s3disk: private staging alias changed during reconciliation")
			}
			if err := operations.remove(candidate); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("s3disk: remove installed private staging alias: %w", err)
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return fmt.Errorf("s3disk: read private staging directory: %w", readErr)
		}
	}
	if err := directoryFile.Close(); err != nil {
		return fmt.Errorf("s3disk: close private staging directory: %w", err)
	}
	directoryOpen = false
	return nil
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
	// Once installation has been attempted, every outcome must explicitly
	// settle the staged secret and make both its removal and any destination
	// entry durable. A deferred best-effort unlink is not sufficient evidence
	// for an idempotent caller to turn an ambiguous install into success.
	removeErr := operations.remove(temporary)
	if removeErr == nil || errors.Is(removeErr, os.ErrNotExist) {
		removeTemporary = false
		result.CleanupConfirmed = true
		removeErr = nil
	} else {
		removeErr = fmt.Errorf("s3disk: remove staged private output: %w", removeErr)
	}
	syncErr := operations.syncDirectory(directory)
	if syncErr == nil {
		result.DurabilityConfirmed = true
	} else {
		syncErr = fmt.Errorf("s3disk: sync private output directory: %w", syncErr)
	}
	cleanupBarrierErr := errors.Join(removeErr, syncErr)
	if !reconciliation.sameStagingFile {
		if errors.Is(installErr, os.ErrExist) && reconciliation.validatedOtherFile {
			result.InstallResolved = true
			result.NotInstalledConfirmed = true
			if cleanupBarrierErr != nil {
				return result, errors.Join(ErrPrivateFileInstallIndeterminate, errPrivateFileExists, cleanupBarrierErr)
			}
			return result, errPrivateFileExists
		}
		if installErr != nil && errors.Is(reconciliationErr, os.ErrNotExist) {
			result.InstallResolved = true
			result.NotInstalledConfirmed = true
			classifiedErr := fmt.Errorf("s3disk: private output installer: %w", installErr)
			if cleanupBarrierErr != nil {
				classifiedErr = errors.Join(ErrPrivateFileInstallIndeterminate, classifiedErr, cleanupBarrierErr)
			}
			return result, classifiedErr
		}
		if installErr != nil {
			installErr = fmt.Errorf("s3disk: private output installer: %w", installErr)
		}
		if reconciliationErr != nil {
			reconciliationErr = fmt.Errorf("s3disk: reconcile installed private output: %w", reconciliationErr)
		}
		return result, errors.Join(ErrPrivateFileInstallIndeterminate, installErr, reconciliationErr, cleanupBarrierErr)
	}

	result.InstallResolved = true
	result.Installed = true
	if cleanupBarrierErr != nil {
		return result, errors.Join(ErrPrivateFileInstalledUnconfirmed, cleanupBarrierErr)
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
