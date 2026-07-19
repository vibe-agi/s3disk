package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const privateFileTestMaximumBytes = 4096

func TestPrivateFileReconcilesAppliedInstallerError(t *testing.T) {
	requirePrivateSecretFiles(t)
	path := filepath.Join(t.TempDir(), "private-output")
	encoded := []byte("private material applied before the installer response was lost")
	want := bytes.Clone(encoded)
	lostResponse := errors.New("installer response lost")
	operations := privateFileOperationsFor(func(temporary, destination string) error {
		if err := installPrivateFileNoReplace(temporary, destination); err != nil {
			return err
		}
		return lostResponse
	})

	result, err := writePrivateFileForTest(context.Background(), path, encoded, operations)
	if err != nil {
		t.Fatalf("writePrivateFileNoReplace error = %v, want reconciled success", err)
	}
	if !result.InstallAttempted || !result.InstallResolved || !result.Installed ||
		!result.CleanupConfirmed || !result.DurabilityConfirmed || result.NotInstalledConfirmed {
		t.Fatalf("result = %+v, want fully confirmed installation", result)
	}
	if result.needsReconciliation() {
		t.Fatalf("result = %+v unexpectedly requires reconciliation", result)
	}
	assertPrivateFileContents(t, path, want)
	assertPrivateBytesCleared(t, encoded)
	assertNoPrivateStagingFiles(t, filepath.Dir(path))
}

func TestPrivateFileNilInstallerSuccessIsIndeterminate(t *testing.T) {
	requirePrivateSecretFiles(t)
	path := filepath.Join(t.TempDir(), "private-output")
	encoded := []byte("private material for a no-op installer")
	operations := privateFileOperationsFor(func(string, string) error { return nil })

	result, err := writePrivateFileForTest(context.Background(), path, encoded, operations)
	if !errors.Is(err, ErrPrivateFileInstallIndeterminate) {
		t.Fatalf("error = %v, want ErrPrivateFileInstallIndeterminate", err)
	}
	if !result.InstallAttempted || result.InstallResolved || result.NotInstalledConfirmed || result.Installed {
		t.Fatalf("result = %+v, want unresolved attempted installation", result)
	}
	if !result.needsReconciliation() {
		t.Fatalf("result = %+v should require reconciliation", result)
	}
	assertPrivatePathAbsent(t, path)
	assertPrivateBytesCleared(t, encoded)
	assertNoPrivateStagingFiles(t, filepath.Dir(path))
}

func TestPrivateFileWrongInodeAfterNilInstallerSuccessIsIndeterminate(t *testing.T) {
	requirePrivateSecretFiles(t)
	path := filepath.Join(t.TempDir(), "private-output")
	encoded := []byte("private material that must not be confused with another inode")
	other := []byte("different private file")
	operations := privateFileOperationsFor(func(_ string, destination string) error {
		return os.WriteFile(destination, other, 0o600)
	})

	result, err := writePrivateFileForTest(context.Background(), path, encoded, operations)
	if !errors.Is(err, ErrPrivateFileInstallIndeterminate) {
		t.Fatalf("error = %v, want ErrPrivateFileInstallIndeterminate", err)
	}
	if !result.InstallAttempted || result.InstallResolved || result.NotInstalledConfirmed || result.Installed {
		t.Fatalf("result = %+v, want unresolved attempted installation", result)
	}
	assertPrivateFileContents(t, path, other)
	assertPrivateBytesCleared(t, encoded)
	assertNoPrivateStagingFiles(t, filepath.Dir(path))
}

func TestPrivateFileExistWithValidatedOtherInodeIsNotInstalled(t *testing.T) {
	requirePrivateSecretFiles(t)
	path := filepath.Join(t.TempDir(), "private-output")
	encoded := []byte("private material that loses a no-replace race")
	other := []byte("race winner")
	operations := privateFileOperationsFor(func(_ string, destination string) error {
		if err := os.WriteFile(destination, other, 0o600); err != nil {
			return err
		}
		return os.ErrExist
	})

	result, err := writePrivateFileForTest(context.Background(), path, encoded, operations)
	if !errors.Is(err, errPrivateFileExists) {
		t.Fatalf("error = %v, want errPrivateFileExists", err)
	}
	if !result.InstallAttempted || !result.InstallResolved || !result.NotInstalledConfirmed || result.Installed {
		t.Fatalf("result = %+v, want confirmed not-installed outcome", result)
	}
	if result.needsReconciliation() {
		t.Fatalf("result = %+v unexpectedly requires reconciliation", result)
	}
	assertPrivateFileContents(t, path, other)
	assertPrivateBytesCleared(t, encoded)
	assertNoPrivateStagingFiles(t, filepath.Dir(path))
}

func TestPrivateFileInstallerErrorWithAbsentFinalIsNotInstalled(t *testing.T) {
	requirePrivateSecretFiles(t)
	path := filepath.Join(t.TempDir(), "private-output")
	encoded := []byte("private material rejected before installation")
	installFailure := errors.New("installer rejected request")
	operations := privateFileOperationsFor(func(string, string) error { return installFailure })

	result, err := writePrivateFileForTest(context.Background(), path, encoded, operations)
	if !errors.Is(err, installFailure) {
		t.Fatalf("error = %v, want installer failure", err)
	}
	if errors.Is(err, ErrPrivateFileInstallIndeterminate) || errors.Is(err, ErrPrivateFileInstalledUnconfirmed) {
		t.Fatalf("confirmed-not-installed error has uncertainty sentinel: %v", err)
	}
	if !result.InstallAttempted || !result.InstallResolved || !result.NotInstalledConfirmed || result.Installed {
		t.Fatalf("result = %+v, want confirmed not-installed outcome", result)
	}
	if result.needsReconciliation() {
		t.Fatalf("result = %+v unexpectedly requires reconciliation", result)
	}
	assertPrivatePathAbsent(t, path)
	assertPrivateBytesCleared(t, encoded)
	assertNoPrivateStagingFiles(t, filepath.Dir(path))
}

func TestPrivateFileInstalledUnlinkFailureIsStableUnconfirmedResult(t *testing.T) {
	requirePrivateSecretFiles(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "private-output")
	encoded := []byte("installed private material with an unconfirmed staging unlink")
	want := bytes.Clone(encoded)
	unlinkFailure := errors.New("injected staged unlink failure")
	operations := privateFileOperations{
		install: installPrivateFileNoReplace,
		remove: func(string) error {
			return unlinkFailure
		},
		syncDirectory: func(string) error { return nil },
	}

	result, err := writePrivateFileForTest(context.Background(), path, encoded, operations)
	if !errors.Is(err, ErrPrivateFileInstalledUnconfirmed) || !errors.Is(err, unlinkFailure) {
		t.Fatalf("error = %v, want installed-unconfirmed unlink failure", err)
	}
	if !result.InstallAttempted || !result.InstallResolved || !result.Installed ||
		result.NotInstalledConfirmed || result.CleanupConfirmed || !result.DurabilityConfirmed {
		t.Fatalf("result = %+v, want installed with cleanup unconfirmed", result)
	}
	if !result.needsReconciliation() {
		t.Fatalf("result = %+v should require reconciliation", result)
	}
	assertPrivateFileContents(t, path, want)
	assertPrivateBytesCleared(t, encoded)
	matches := privateStagingFiles(t, directory)
	if len(matches) != 1 {
		t.Fatalf("staging files = %v, want one unconfirmed staging link", matches)
	}
}

func TestPrivateFileInstalledDirectorySyncFailureIsStableUnconfirmedResult(t *testing.T) {
	requirePrivateSecretFiles(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "private-output")
	encoded := []byte("installed private material with unconfirmed directory durability")
	want := bytes.Clone(encoded)
	syncFailure := errors.New("injected directory sync failure")
	operations := privateFileOperationsFor(installPrivateFileNoReplace)
	operations.syncDirectory = func(string) error { return syncFailure }

	result, err := writePrivateFileForTest(context.Background(), path, encoded, operations)
	if !errors.Is(err, ErrPrivateFileInstalledUnconfirmed) || !errors.Is(err, syncFailure) {
		t.Fatalf("error = %v, want installed-unconfirmed sync failure", err)
	}
	if !result.InstallAttempted || !result.InstallResolved || !result.Installed ||
		result.NotInstalledConfirmed || !result.CleanupConfirmed || result.DurabilityConfirmed {
		t.Fatalf("result = %+v, want installed with durability unconfirmed", result)
	}
	if !result.needsReconciliation() {
		t.Fatalf("result = %+v should require reconciliation", result)
	}
	assertPrivateFileContents(t, path, want)
	assertPrivateBytesCleared(t, encoded)
	assertNoPrivateStagingFiles(t, directory)
}

func TestPrivateFileCancellationBoundaries(t *testing.T) {
	requirePrivateSecretFiles(t)

	t.Run("before secret write", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "private-output")
		encoded := []byte("must not be written after cancellation")
		ctx, cancel := context.WithCancel(context.Background())
		installCalled := false
		operations := privateFileOperationsFor(func(string, string) error {
			installCalled = true
			return nil
		})
		operations.beforeSecretWrite = cancel

		result, err := writePrivateFileForTest(ctx, path, encoded, operations)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
		if installCalled {
			t.Fatal("installer called after cancellation before secret write")
		}
		if result != (privateFileWriteResult{}) {
			t.Fatalf("result = %+v, want no install attempt", result)
		}
		assertPrivatePathAbsent(t, path)
		assertPrivateBytesCleared(t, encoded)
		assertNoPrivateStagingFiles(t, directory)
	})

	t.Run("before install", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "private-output")
		encoded := []byte("staged bytes must be removed after cancellation")
		ctx, cancel := context.WithCancel(context.Background())
		installCalled := false
		operations := privateFileOperationsFor(func(string, string) error {
			installCalled = true
			return nil
		})
		operations.beforeInstall = cancel

		result, err := writePrivateFileForTest(ctx, path, encoded, operations)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
		if installCalled {
			t.Fatal("installer called after cancellation before install")
		}
		if result != (privateFileWriteResult{}) {
			t.Fatalf("result = %+v, want no install attempt", result)
		}
		assertPrivatePathAbsent(t, path)
		assertPrivateBytesCleared(t, encoded)
		assertNoPrivateStagingFiles(t, directory)
	})

	t.Run("after install", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "private-output")
		encoded := []byte("installed bytes must win over late context cancellation")
		want := bytes.Clone(encoded)
		ctx, cancel := context.WithCancel(context.Background())
		operations := privateFileOperationsFor(func(temporary, destination string) error {
			if err := installPrivateFileNoReplace(temporary, destination); err != nil {
				return err
			}
			cancel()
			return context.Canceled
		})

		result, err := writePrivateFileForTest(ctx, path, encoded, operations)
		if err != nil {
			t.Fatalf("writePrivateFileNoReplace error = %v, want reconciled success", err)
		}
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("context error = %v, want context.Canceled", ctx.Err())
		}
		if !result.InstallAttempted || !result.InstallResolved || !result.Installed ||
			!result.CleanupConfirmed || !result.DurabilityConfirmed || result.NotInstalledConfirmed {
			t.Fatalf("result = %+v, want fully confirmed installation", result)
		}
		assertPrivateFileContents(t, path, want)
		assertPrivateBytesCleared(t, encoded)
		assertNoPrivateStagingFiles(t, directory)
	})
}

func writePrivateFileForTest(
	ctx context.Context,
	path string,
	encoded []byte,
	operations privateFileOperations,
) (privateFileWriteResult, error) {
	resolved, err := resolvePrivatePath(path)
	if err != nil {
		return privateFileWriteResult{}, err
	}
	return writePrivateFileNoReplace(
		ctx, resolved, encoded, privateFileTestMaximumBytes,
		".s3disk-private-test-*", operations,
	)
}

func assertPrivateBytesCleared(t *testing.T, encoded []byte) {
	t.Helper()
	for index, value := range encoded {
		if value != 0 {
			t.Fatalf("encoded[%d] = %d, want cleared buffer", index, value)
		}
	}
}

func assertPrivateFileContents(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("private output = %q, want %q", got, want)
	}
}

func assertPrivatePathAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private output unexpectedly exists: %v", err)
	}
}

func privateStagingFiles(t *testing.T, directory string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(directory, ".s3disk-private-test-*"))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

func assertNoPrivateStagingFiles(t *testing.T, directory string) {
	t.Helper()
	if matches := privateStagingFiles(t, directory); len(matches) != 0 {
		t.Fatalf("temporary private output files remain: %v", matches)
	}
}
