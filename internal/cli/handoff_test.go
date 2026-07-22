package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/presignedshare"
)

func newTestHandoff(t *testing.T) handoff {
	t.Helper()
	repositoryID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	shareID, err := presignedshare.GenerateShareID()
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := s3disk.GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(time.Hour).UTC().Round(0)
	root, err := presignedshare.DangerouslyNewUncheckedCapability(
		"shares/random/root", "http://127.0.0.1:9000/bucket/shares/random/root?X-Amz-Signature=secret",
		nil, expiresAt, presignedshare.CapabilityOptions{AllowInsecureLoopback: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	bearer, err := root.DangerouslyExportUncheckedBearer()
	if err != nil {
		t.Fatal(err)
	}
	var commit s3disk.Digest
	commit[0] = 1
	return handoff{
		Format: handoffFormat, Profile: handoffProfile, ShareID: shareID.String(),
		AuthorizationExpiresAt: expiresAt,
		RootBearer:             base64.RawURLEncoding.EncodeToString(bearer),
		RepositoryPrefix:       "shares/random",
		ReferenceKey:           "shares/random/.s3disk/v1/signed-refs/v1/bWFpbg",
		Channel:                "main",
		RepositoryID:           repositoryID.String(),
		ReferenceKeyID:         "share-key-1",
		ReferencePublicKey:     base64.RawURLEncoding.EncodeToString(publicKey),
		TrustedCheckpoint:      handoffCheckpoint{Generation: 1, Commit: commit.String()},
		AllowInsecureLoopback:  true,
		ClientEncryptionKey:    clientKey.ExportSecret(),
	}
}

func TestHandoffExclusive0600RoundTrip(t *testing.T) {
	requirePrivateSecretFiles(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "share.handoff")
	want := newTestHandoff(t)
	if err := writeHandoff(context.Background(), path, want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("handoff mode = %#o, want 0600", info.Mode().Perm())
	}
	got, err := readHandoff(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.wire.ShareID != want.ShareID || got.wire.RepositoryID != want.RepositoryID ||
		got.checkpoint.Generation != want.TrustedCheckpoint.Generation || got.profile.RepositoryID() != got.repository {
		t.Fatalf("decoded handoff does not preserve its public bindings: %#v", got.wire)
	}
	if !got.root.ExpiresAt().Equal(want.AuthorizationExpiresAt) {
		t.Fatalf("root expiry = %s, want %s", got.root.ExpiresAt(), want.AuthorizationExpiresAt)
	}
	if len(got.publicKey) != ed25519.PublicKeySize || got.key.ExportSecret() != want.ClientEncryptionKey {
		t.Fatal("decoded key material does not match")
	}
}

func TestHandoffDiagnosticsRedactBearerAndEncryptionKey(t *testing.T) {
	value := newTestHandoff(t)
	diagnosticJSON, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for name, diagnostic := range map[string]string{
		"String":   fmt.Sprint(value),
		"detailed": fmt.Sprintf("%+v", value),
		"GoString": fmt.Sprintf("%#v", value),
		"JSON":     string(diagnosticJSON),
	} {
		if strings.Contains(diagnostic, value.RootBearer) ||
			strings.Contains(diagnostic, value.ClientEncryptionKey) ||
			!strings.Contains(diagnostic, "redacted") {
			t.Fatalf("%s exposed handoff authority: %q", name, diagnostic)
		}
	}
}

func TestHandoffNeverOverwrites(t *testing.T) {
	requirePrivateSecretFiles(t)
	path := filepath.Join(t.TempDir(), "share.handoff")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := writeHandoff(context.Background(), path, newTestHandoff(t))
	if !errors.Is(err, ErrHandoffExists) {
		t.Fatalf("error = %v, want ErrHandoffExists", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "keep" {
		t.Fatalf("existing file changed: data=%q err=%v", data, err)
	}
}

func TestHandoffDigestIsDeterministicAndDomainSeparated(t *testing.T) {
	encoded := []byte("canonical handoff bytes\n")
	first := handoffDigest(encoded)
	second := handoffDigest(bytes.Clone(encoded))
	plain := s3disk.Digest(sha256.Sum256(encoded))
	if first.IsZero() || first != second {
		t.Fatalf("handoff digest is not stable: first=%s second=%s", first, second)
	}
	if first == plain {
		t.Fatal("handoff digest is not domain separated from plain SHA-256")
	}
	encoded[0] ^= 1
	if changed := handoffDigest(encoded); changed == first {
		t.Fatal("handoff digest did not bind the exact bytes")
	}
}

func TestInstallOrVerifyHandoffInstallsThenAcceptsExactExistingFile(t *testing.T) {
	requirePrivateSecretFiles(t)
	path := filepath.Join(t.TempDir(), "share.handoff")
	value := newTestHandoff(t)
	encoded, err := encodeHandoff(value)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	digest := handoffDigest(encoded)

	if err := installOrVerifyHandoff(context.Background(), path, value, digest); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := installOrVerifyHandoff(context.Background(), path, value, digest); err != nil {
		t.Fatalf("verify exact existing handoff: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("exact existing handoff was replaced")
	}
	installed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(installed, encoded) {
		t.Fatal("installed handoff differs from its canonical bytes")
	}
}

func TestInstallOrVerifyHandoffRetriesExistingFileDurabilityBarrier(t *testing.T) {
	requirePrivateSecretFiles(t)
	path := filepath.Join(t.TempDir(), "share.handoff")
	value := newTestHandoff(t)
	encoded, err := encodeHandoff(value)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	durabilityFailure := errors.New("injected first directory sync failure")
	syncCalls := 0
	operations := privateFileOperationsFor(installPrivateFileNoReplace)
	operations.syncDirectory = func(string) error {
		syncCalls++
		if syncCalls == 1 {
			return durabilityFailure
		}
		return nil
	}
	digest := handoffDigest(encoded)
	if err := installOrVerifyHandoffWithOperations(
		context.Background(), path, value, digest, operations,
	); !errors.Is(err, ErrPrivateFileInstalledUnconfirmed) || !errors.Is(err, durabilityFailure) {
		t.Fatalf("first install error = %v, want unconfirmed durability", err)
	}
	if err := installOrVerifyHandoffWithOperations(
		context.Background(), path, value, digest, operations,
	); err != nil {
		t.Fatalf("existing exact handoff did not retry durability barrier: %v", err)
	}
	if syncCalls != 2 {
		t.Fatalf("directory sync calls = %d, want 2", syncCalls)
	}
}

func TestInstallOrVerifyHandoffCarriesStagingCleanupAcrossCalls(t *testing.T) {
	requirePrivateSecretFiles(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "share.handoff")
	value := newTestHandoff(t)
	encoded, err := encodeHandoff(value)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	digest := handoffDigest(encoded)
	unlinkFailure := errors.New("injected staged unlink failure")
	removeCalls := 0
	operations := privateFileOperationsFor(installPrivateFileNoReplace)
	operations.remove = func(path string) error {
		removeCalls++
		// The first call is the explicit cleanup and the second is the
		// best-effort deferred cleanup in the failed invocation.
		if removeCalls <= 2 {
			return unlinkFailure
		}
		return os.Remove(path)
	}

	if err := installOrVerifyHandoffWithOperations(
		context.Background(), path, value, digest, operations,
	); !errors.Is(err, ErrPrivateFileInstalledUnconfirmed) || !errors.Is(err, unlinkFailure) {
		t.Fatalf("first install error = %v, want unconfirmed staging cleanup", err)
	}
	staging := privateHandoffStagingFiles(t, directory)
	if len(staging) != 1 {
		t.Fatalf("staging files after failed cleanup = %v, want one", staging)
	}
	installed, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := os.Stat(staging[0])
	if err != nil || !os.SameFile(installed, staged) {
		t.Fatalf("staging path is not the installed hard-link alias: same=%t err=%v", err == nil && os.SameFile(installed, staged), err)
	}

	// A reserved-looking but unrelated file is not part of this install's
	// cleanup obligation and must never be removed by reconciliation.
	unrelated := filepath.Join(directory, ".s3disk-handoff-unrelated")
	if err := os.WriteFile(unrelated, []byte("unrelated private file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installOrVerifyHandoffWithOperations(
		context.Background(), path, value, digest, operations,
	); err != nil {
		t.Fatalf("retry exact handoff cleanup: %v", err)
	}
	if _, err := os.Lstat(staging[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("installed staging alias remains after retry: %v", err)
	}
	if data, err := os.ReadFile(unrelated); err != nil || string(data) != "unrelated private file" {
		t.Fatalf("unrelated reserved-looking file changed: data=%q err=%v", data, err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(installed, after) {
		t.Fatalf("retry replaced installed handoff: same=%t err=%v", err == nil && os.SameFile(installed, after), err)
	}
}

func TestInstallOrVerifyHandoffRejectsExternalHardLinkAfterReservedCleanup(t *testing.T) {
	requirePrivateSecretFiles(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "share.handoff")
	value := newTestHandoff(t)
	encoded, err := encodeHandoff(value)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	digest := handoffDigest(encoded)
	unlinkFailure := errors.New("injected staged unlink failure")
	removeCalls := 0
	operations := privateFileOperationsFor(installPrivateFileNoReplace)
	operations.remove = func(path string) error {
		removeCalls++
		if removeCalls <= 2 {
			return unlinkFailure
		}
		return os.Remove(path)
	}
	if err := installOrVerifyHandoffWithOperations(
		context.Background(), path, value, digest, operations,
	); !errors.Is(err, ErrPrivateFileInstalledUnconfirmed) {
		t.Fatalf("first install error = %v, want installed-unconfirmed", err)
	}
	staging := privateHandoffStagingFiles(t, directory)
	if len(staging) != 1 {
		t.Fatalf("staging files = %v, want one", staging)
	}
	external := filepath.Join(t.TempDir(), "external-hard-link")
	if err := os.Link(path, external); err != nil {
		t.Skipf("hard links unavailable on this filesystem: %v", err)
	}

	err = installOrVerifyHandoffWithOperations(context.Background(), path, value, digest, operations)
	if !errors.Is(err, ErrHandoffExists) || !errors.Is(err, ErrInvalidHandoff) ||
		!errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("retry with external hard link error = %v, want ErrHandoffExists, ErrInvalidHandoff, and ErrCorruptObject", err)
	}
	if staging := privateHandoffStagingFiles(t, directory); len(staging) != 0 {
		t.Fatalf("reserved staging aliases after reconciliation = %v, want none", staging)
	}
	if _, err := os.Stat(external); err != nil {
		t.Fatalf("external hard link was removed: %v", err)
	}
	if err := os.Remove(external); err != nil {
		t.Fatal(err)
	}
	if err := installOrVerifyHandoffWithOperations(
		context.Background(), path, value, digest, operations,
	); err != nil {
		t.Fatalf("retry after external hard-link removal: %v", err)
	}
}

func TestInstallOrVerifyHandoffRejectsDigestAndExistingContentMismatch(t *testing.T) {
	t.Run("expected digest must bind desired bytes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "share.handoff")
		value := newTestHandoff(t)
		encoded, err := encodeHandoff(value)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(encoded)
		digest := handoffDigest(encoded)
		digest[0] ^= 1
		if err := installOrVerifyHandoff(context.Background(), path, value, digest); !errors.Is(err, ErrInvalidHandoff) {
			t.Fatalf("error = %v, want ErrInvalidHandoff", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("handoff exists after digest rejection: %v", err)
		}
	})

	t.Run("different canonical handoff is a no-replace conflict", func(t *testing.T) {
		requirePrivateSecretFiles(t)
		path := filepath.Join(t.TempDir(), "share.handoff")
		existing := newTestHandoff(t)
		existingBytes, err := encodeHandoff(existing)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(existingBytes)
		if err := installOrVerifyHandoff(context.Background(), path, existing, handoffDigest(existingBytes)); err != nil {
			t.Fatal(err)
		}

		desired := existing
		desired.TrustedCheckpoint.Generation++
		desiredBytes, err := encodeHandoff(desired)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(desiredBytes)
		if err := installOrVerifyHandoff(context.Background(), path, desired, handoffDigest(desiredBytes)); !errors.Is(err, ErrHandoffExists) {
			t.Fatalf("error = %v, want ErrHandoffExists", err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, existingBytes) {
			t.Fatal("conflicting existing handoff was overwritten")
		}
	})
}

func TestInstallOrVerifyHandoffReconcilesIndeterminateInstallOnlyForExactPrivateBytes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the injected alternate-inode installer uses POSIX private-file modes")
	}
	lostResponse := errors.New("injected installer response loss")

	t.Run("exact canonical bytes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "share.handoff")
		value := newTestHandoff(t)
		encoded, err := encodeHandoff(value)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(encoded)
		operations := privateFileOperationsFor(func(temporary, destination string) error {
			staged, err := os.ReadFile(temporary)
			if err != nil {
				return err
			}
			if err := os.WriteFile(destination, staged, 0o600); err != nil {
				return err
			}
			return lostResponse
		})
		if err := installOrVerifyHandoffWithOperations(
			context.Background(), path, value, handoffDigest(encoded), operations,
		); err != nil {
			t.Fatalf("indeterminate exact install did not reconcile: %v", err)
		}
	})

	t.Run("exact bytes do not hide staging cleanup failure", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "share.handoff")
		value := newTestHandoff(t)
		encoded, err := encodeHandoff(value)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(encoded)
		cleanupFailure := errors.New("injected staging cleanup failure")
		syncCalls := 0
		operations := privateFileOperationsFor(func(temporary, destination string) error {
			staged, readErr := os.ReadFile(temporary)
			if readErr != nil {
				return readErr
			}
			if writeErr := os.WriteFile(destination, staged, 0o600); writeErr != nil {
				return writeErr
			}
			return lostResponse
		})
		operations.remove = func(string) error { return cleanupFailure }
		operations.syncDirectory = func(string) error {
			syncCalls++
			return nil
		}
		err = installOrVerifyHandoffWithOperations(
			context.Background(), path, value, handoffDigest(encoded), operations,
		)
		if !errors.Is(err, ErrPrivateFileInstallIndeterminate) || !errors.Is(err, cleanupFailure) {
			t.Fatalf("error = %v, want indeterminate cleanup failure", err)
		}
		if syncCalls != 1 {
			t.Fatalf("directory sync calls = %d, want 1 despite cleanup failure", syncCalls)
		}
	})

	t.Run("exact bytes do not hide directory sync failure", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "share.handoff")
		value := newTestHandoff(t)
		encoded, err := encodeHandoff(value)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(encoded)
		durabilityFailure := errors.New("injected directory sync failure")
		operations := privateFileOperationsFor(func(temporary, destination string) error {
			staged, readErr := os.ReadFile(temporary)
			if readErr != nil {
				return readErr
			}
			if writeErr := os.WriteFile(destination, staged, 0o600); writeErr != nil {
				return writeErr
			}
			return lostResponse
		})
		operations.syncDirectory = func(string) error { return durabilityFailure }
		err = installOrVerifyHandoffWithOperations(
			context.Background(), path, value, handoffDigest(encoded), operations,
		)
		if !errors.Is(err, ErrPrivateFileInstallIndeterminate) || !errors.Is(err, durabilityFailure) {
			t.Fatalf("error = %v, want indeterminate durability failure", err)
		}
	})

	t.Run("different canonical bytes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "share.handoff")
		desired := newTestHandoff(t)
		desiredBytes, err := encodeHandoff(desired)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(desiredBytes)
		other := desired
		other.TrustedCheckpoint.Generation++
		otherBytes, err := encodeHandoff(other)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(otherBytes)
		operations := privateFileOperationsFor(func(_ string, destination string) error {
			if err := os.WriteFile(destination, otherBytes, 0o600); err != nil {
				return err
			}
			return lostResponse
		})
		err = installOrVerifyHandoffWithOperations(
			context.Background(), path, desired, handoffDigest(desiredBytes), operations,
		)
		if err == nil || !errors.Is(err, ErrHandoffExists) {
			t.Fatalf("error = %v, want exact-byte conflict", err)
		}
		got, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Equal(got, otherBytes) {
			t.Fatal("indeterminate conflicting handoff was overwritten")
		}
	})
}

func TestInstallOrVerifyHandoffRejectsInsecureExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not the Windows access-control boundary")
	}
	path := filepath.Join(t.TempDir(), "share.handoff")
	value := newTestHandoff(t)
	encoded, err := encodeHandoff(value)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := installOrVerifyHandoff(context.Background(), path, value, handoffDigest(encoded)); !errors.Is(err, ErrInvalidHandoff) {
		t.Fatalf("error = %v, want ErrInvalidHandoff", err)
	}
}

func TestHandoffFinalPathIsInvisibleUntilAtomicInstall(t *testing.T) {
	requirePrivateSecretFiles(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "share.handoff")
	encoded, err := encodeHandoff(newTestHandoff(t))
	if err != nil {
		t.Fatal(err)
	}
	wantStop := errors.New("stop before atomic install")
	installCalled := false
	var callbackErr error
	err = writeHandoffBytes(context.Background(), path, encoded, func(temporary, destination string) error {
		installCalled = true
		if destination != path {
			callbackErr = fmt.Errorf("install destination = %q, want %q", destination, path)
			return wantStop
		}
		if _, statErr := os.Lstat(destination); !errors.Is(statErr, os.ErrNotExist) {
			callbackErr = fmt.Errorf("final handoff became visible before install: %w", statErr)
			return wantStop
		}
		staged, readErr := os.ReadFile(temporary)
		if readErr != nil {
			callbackErr = readErr
			return wantStop
		}
		if !bytes.Equal(staged, encoded) {
			callbackErr = errors.New("staged handoff is not the complete canonical handoff")
			return wantStop
		}
		info, statErr := os.Stat(temporary)
		if statErr != nil {
			callbackErr = statErr
			return wantStop
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			callbackErr = fmt.Errorf("staged handoff mode = %#o, want 0600", info.Mode().Perm())
		}
		return wantStop
	})
	if !installCalled {
		t.Fatal("atomic installer was not called")
	}
	if !errors.Is(err, wantStop) {
		t.Fatalf("error = %v, want injected stop", err)
	}
	if callbackErr != nil {
		t.Fatal(callbackErr)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("final handoff exists after pre-install failure: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(directory, ".s3disk-handoff-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("staged handoff was not cleaned up: %v", matches)
	}
}

func TestHandoffAtomicInstallLeavesNoTemporarySecret(t *testing.T) {
	requirePrivateSecretFiles(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "share.handoff")
	if err := writeHandoff(context.Background(), path, newTestHandoff(t)); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(directory, ".s3disk-handoff-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary handoff secrets remain: %v", matches)
	}
}

func privateHandoffStagingFiles(t *testing.T, directory string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(directory, ".s3disk-handoff-*"))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

func TestHandoffRejectsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation normally requires additional Windows privilege")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writeHandoff(context.Background(), link, newTestHandoff(t)); err == nil {
		t.Fatal("writeHandoff accepted a symlink target")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "keep" {
		t.Fatalf("symlink target changed: data=%q err=%v", data, err)
	}
	if _, err := readHandoff(link); !errors.Is(err, ErrInvalidHandoff) {
		t.Fatalf("read error = %v, want ErrInvalidHandoff", err)
	}

	realParent := filepath.Join(directory, "real-parent")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(directory, "linked-parent")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	if err := writeHandoff(context.Background(), filepath.Join(linkedParent, "share"), newTestHandoff(t)); err != nil {
		t.Fatalf("write through a resolved parent failed: %v", err)
	}
	if info, err := os.Lstat(filepath.Join(realParent, "share")); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("resolved-parent handoff is not a regular file: info=%v err=%v", info, err)
	}
}

func TestHandoffStrictJSONAndSizeBounds(t *testing.T) {
	requirePrivateSecretFiles(t)
	directory := t.TempDir()
	validPath := filepath.Join(directory, "valid")
	if err := writeHandoff(context.Background(), validPath, newTestHandoff(t)); err != nil {
		t.Fatal(err)
	}
	valid, err := os.ReadFile(validPath)
	if err != nil {
		t.Fatal(err)
	}

	var object map[string]json.RawMessage
	if err := json.Unmarshal(valid, &object); err != nil {
		t.Fatal(err)
	}
	object["unknown"] = json.RawMessage("true")
	withUnknown, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	unknownPath := filepath.Join(directory, "unknown")
	if err := os.WriteFile(unknownPath, withUnknown, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readHandoff(unknownPath); !errors.Is(err, ErrInvalidHandoff) {
		t.Fatalf("unknown-field error = %v", err)
	}

	trailingPath := filepath.Join(directory, "trailing")
	if err := os.WriteFile(trailingPath, append(valid, []byte("{}")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readHandoff(trailingPath); !errors.Is(err, ErrInvalidHandoff) {
		t.Fatalf("trailing-value error = %v", err)
	}
	noncanonicalPath := filepath.Join(directory, "noncanonical")
	if err := os.WriteFile(noncanonicalPath, bytes.TrimSpace(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readHandoff(noncanonicalPath); !errors.Is(err, ErrInvalidHandoff) {
		t.Fatalf("noncanonical error = %v", err)
	}

	largePath := filepath.Join(directory, "large")
	large := strings.Repeat("x", int(maximumHandoffBytes+1))
	if err := os.WriteFile(largePath, []byte(large), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readHandoff(largePath); !errors.Is(err, ErrInvalidHandoff) {
		t.Fatalf("large-file error = %v", err)
	}
}

func TestHandoffAccommodatesMaximumTLSCertificateCount(t *testing.T) {
	requirePrivateSecretFiles(t)
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if len(certificate) == 0 {
		t.Fatal("test certificate PEM is empty")
	}
	certificateCount := presignedshare.MaximumTLSRootCertificates
	maximumCanonicalBundle := bytes.Repeat(certificate, certificateCount)
	if len(maximumCanonicalBundle) > int(presignedshare.MaximumTLSRootCAPEMBytes) {
		t.Fatal("maximum certificate count unexpectedly exceeds the PEM byte bound")
	}
	value := newTestHandoff(t)
	root, err := presignedshare.DangerouslyNewUncheckedCapability(
		"shares/random/root", "https://objects.example.test/bucket/shares/random/root?X-Amz-Signature=secret",
		nil, value.AuthorizationExpiresAt, presignedshare.CapabilityOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	bearer, err := root.DangerouslyExportUncheckedBearer()
	if err != nil {
		t.Fatal(err)
	}
	value.RootBearer = base64.RawURLEncoding.EncodeToString(bearer)
	value.AllowInsecureLoopback = false
	value.TLSRootCAPEM = base64.RawURLEncoding.EncodeToString(maximumCanonicalBundle)
	path := filepath.Join(t.TempDir(), "maximum-ca.handoff")
	if err := writeHandoff(context.Background(), path, value); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > maximumHandoffBytes {
		t.Fatalf("handoff size = %d, maximum = %d", info.Size(), maximumHandoffBytes)
	}
	if _, err := readHandoff(path); err != nil {
		t.Fatal(err)
	}
}

func TestHandoffRejectsReferenceOutsideSignedChannel(t *testing.T) {
	value := newTestHandoff(t)
	value.ReferenceKey = value.RepositoryPrefix + "/.s3disk/v1/refs/bWFpbg"
	if _, err := value.decode(time.Now()); !errors.Is(err, ErrInvalidHandoff) {
		t.Fatalf("error = %v, want ErrInvalidHandoff", err)
	}
}

func TestHandoffRejectsLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not the Windows access-control boundary")
	}
	path := filepath.Join(t.TempDir(), "share.handoff")
	if err := writeHandoff(context.Background(), path, newTestHandoff(t)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readHandoff(path); !errors.Is(err, ErrInvalidHandoff) {
		t.Fatalf("error = %v, want ErrInvalidHandoff", err)
	}
}

func TestHandoffRejectsWritableParentBeforeWritingSecret(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows private-secret validation fails closed before this POSIX-mode case")
	}
	parent := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "share.handoff")
	if err := writeHandoff(context.Background(), path, newTestHandoff(t)); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("error = %v, want ErrCorruptObject", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsafe handoff path remains after rejection: %v", err)
	}
}

func TestHandoffRejectsSystemTrust(t *testing.T) {
	value := newTestHandoff(t)
	value.DangerouslyUseSystemTrust = true
	if _, err := value.decode(time.Now()); !errors.Is(err, ErrInvalidHandoff) {
		t.Fatalf("error = %v, want ErrInvalidHandoff", err)
	}
}

func TestHandoffRejectsExpiredAuthorization(t *testing.T) {
	value := newTestHandoff(t)
	value.AuthorizationExpiresAt = time.Now().Add(-time.Second).UTC().Round(0)
	if _, err := value.decode(time.Now()); !errors.Is(err, ErrInvalidHandoff) {
		t.Fatalf("error = %v, want ErrInvalidHandoff", err)
	}
}
