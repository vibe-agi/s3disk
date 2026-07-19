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
// which still identify the exact installed inode. It then syncs the directory
// and requires the installed file to pass the strict single-link secret-file
// validation before returning success. This carries a hard-link install's
// cleanup obligation across process restarts without deleting an unrelated
// file which merely happens to match the temporary-name pattern.
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
	directory := filepath.Dir(path)
	if err := s3disk.ValidatePrivateSecretDirectory(directory); err != nil {
		return fmt.Errorf("s3disk: unsafe private staging directory: %w", err)
	}
	installedInfo, cleanupErr := removeInstalledPrivateFileStagingAliases(
		ctx, path, directory, prefix, suffix, operations,
	)
	syncErr := operations.syncDirectory(directory)
	if cleanupErr != nil || syncErr != nil {
		if syncErr != nil {
			syncErr = fmt.Errorf("s3disk: sync private staging directory: %w", syncErr)
		}
		if installedInfo != nil {
			return errors.Join(ErrPrivateFileInstalledUnconfirmed, cleanupErr, syncErr)
		}
		return errors.Join(cleanupErr, syncErr)
	}
	reconciliation, err := reconcilePrivateFile(path, installedInfo)
	if err != nil {
		return fmt.Errorf("s3disk: strictly validate reconciled private output: %w", err)
	}
	if !reconciliation.sameStagingFile {
		return fmt.Errorf("s3disk: installed private output changed during staging reconciliation")
	}
	return nil
}

func removeInstalledPrivateFileStagingAliases(
	ctx context.Context,
	path string,
	directory string,
	prefix string,
	suffix string,
	operations privateFileOperations,
) (os.FileInfo, error) {
	installed, installedInfo, err := openPrivateFileForReconciliation(path)
	if err != nil {
		return nil, fmt.Errorf("s3disk: inspect installed private output: %w", err)
	}
	installedOpen := true
	defer func() {
		if installedOpen {
			_ = installed.Close()
		}
	}()
	matchesTemporaryName := func(name string) bool {
		return len(name) > len(prefix)+len(suffix) &&
			strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix)
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return installedInfo, fmt.Errorf("s3disk: open private staging directory: %w", err)
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
			return installedInfo, err
		}
		entries, readErr := directoryFile.ReadDir(256)
		entriesSeen += len(entries)
		if entriesSeen > maximumPrivateStagingScanEntries {
			return installedInfo, fmt.Errorf("s3disk: %w: private staging directory exceeds %d entries", s3disk.ErrResourceLimit, maximumPrivateStagingScanEntries)
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return installedInfo, err
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
				return installedInfo, fmt.Errorf("s3disk: inspect staged private output: %w", candidateErr)
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
				return installedInfo, fmt.Errorf("s3disk: private staging alias changed during reconciliation")
			}
			if err := operations.remove(candidate); err != nil && !errors.Is(err, os.ErrNotExist) {
				return installedInfo, fmt.Errorf("s3disk: remove installed private staging alias: %w", err)
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return installedInfo, fmt.Errorf("s3disk: read private staging directory: %w", readErr)
		}
	}
	if err := directoryFile.Close(); err != nil {
		return installedInfo, fmt.Errorf("s3disk: close private staging directory: %w", err)
	}
	directoryOpen = false
	if err := installed.Close(); err != nil {
		return installedInfo, fmt.Errorf("s3disk: close installed private output: %w", err)
	}
	installedOpen = false
	return installedInfo, nil
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
	provisional, _ := reconcilePrivateFileIdentity(path, stagedInfo)
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
	var reconciliation privateFileReconciliation
	var reconciliationErr error
	if provisional.sameStagingFile && !result.CleanupConfirmed {
		// A successful Unix no-replace install legitimately has two links until
		// staging cleanup succeeds. Reconfirm only identity in this error state;
		// callers receive InstalledUnconfirmed and must not read it as a secret.
		reconciliation, reconciliationErr = reconcilePrivateFileIdentity(path, stagedInfo)
	} else {
		// Once the staging name is gone, or when the destination is a different
		// inode, require the complete single-link private-file invariant.
		reconciliation, reconciliationErr = reconcilePrivateFile(path, stagedInfo)
	}
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

func openPrivateFileForReconciliation(path string) (*os.File, os.FileInfo, error) {
	linked, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if linked.Mode()&os.ModeSymlink != 0 || !linked.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("final private output is not a regular non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	opened, err := file.Stat()
	current, currentErr := os.Lstat(path)
	if err != nil || currentErr != nil || !opened.Mode().IsRegular() ||
		current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
		!os.SameFile(linked, opened) || !os.SameFile(opened, current) {
		_ = file.Close()
		return nil, nil, fmt.Errorf("final private output changed during identity inspection")
	}
	return file, opened, nil
}

func reconcilePrivateFileIdentity(path string, staged os.FileInfo) (privateFileReconciliation, error) {
	if staged == nil {
		return privateFileReconciliation{}, fmt.Errorf("staged private output identity is required")
	}
	file, opened, err := openPrivateFileForReconciliation(path)
	if err != nil {
		return privateFileReconciliation{}, err
	}
	if err := file.Close(); err != nil {
		return privateFileReconciliation{}, err
	}
	if os.SameFile(staged, opened) {
		return privateFileReconciliation{sameStagingFile: true}, nil
	}
	return privateFileReconciliation{}, nil
}

func reconcilePrivateFile(path string, staged os.FileInfo) (privateFileReconciliation, error) {
	if staged == nil {
		return privateFileReconciliation{}, fmt.Errorf("staged private output identity is required")
	}
	file, opened, err := openPrivateFileForReconciliation(path)
	if err != nil {
		return privateFileReconciliation{}, err
	}
	defer file.Close()
	if err := s3disk.ValidatePrivateSecretFile(path, file); err != nil {
		return privateFileReconciliation{}, err
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, current) {
		return privateFileReconciliation{}, fmt.Errorf("final private output changed during strict validation")
	}
	if os.SameFile(staged, opened) {
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
