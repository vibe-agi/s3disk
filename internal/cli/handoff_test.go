package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	directory := t.TempDir()
	path := filepath.Join(directory, "share.handoff")
	want := newTestHandoff(t)
	if err := writeHandoff(path, want); err != nil {
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

func TestHandoffNeverOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "share.handoff")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := writeHandoff(path, newTestHandoff(t))
	if !errors.Is(err, ErrHandoffExists) {
		t.Fatalf("error = %v, want ErrHandoffExists", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "keep" {
		t.Fatalf("existing file changed: data=%q err=%v", data, err)
	}
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
	if err := writeHandoff(link, newTestHandoff(t)); err == nil {
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
	if err := writeHandoff(filepath.Join(linkedParent, "share"), newTestHandoff(t)); err != nil {
		t.Fatalf("write through a resolved parent failed: %v", err)
	}
	if info, err := os.Lstat(filepath.Join(realParent, "share")); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("resolved-parent handoff is not a regular file: info=%v err=%v", info, err)
	}
}

func TestHandoffStrictJSONAndSizeBounds(t *testing.T) {
	directory := t.TempDir()
	validPath := filepath.Join(directory, "valid")
	if err := writeHandoff(validPath, newTestHandoff(t)); err != nil {
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

func TestHandoffAccommodatesMaximumTLSCABound(t *testing.T) {
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
	value.TLSRootCAPEM = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{'x'}, int(presignedshare.MaximumTLSRootCAPEMBytes)))
	path := filepath.Join(t.TempDir(), "maximum-ca.handoff")
	if err := writeHandoff(path, value); err != nil {
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
	if err := writeHandoff(path, newTestHandoff(t)); err != nil {
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
	if err := writeHandoff(path, newTestHandoff(t)); !errors.Is(err, s3disk.ErrCorruptObject) {
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

func TestHandoffDiagnosticsRedactBearerAndEncryptionKey(t *testing.T) {
	value := newTestHandoff(t)
	for _, diagnostic := range []string{fmt.Sprint(value), fmt.Sprintf("%#v", value)} {
		if strings.Contains(diagnostic, value.RootBearer) || strings.Contains(diagnostic, value.ClientEncryptionKey) || !strings.Contains(diagnostic, "redacted") {
			t.Fatalf("unsafe diagnostic: %q", diagnostic)
		}
	}
}

func TestHandoffRejectsExpiredAuthorization(t *testing.T) {
	value := newTestHandoff(t)
	value.AuthorizationExpiresAt = time.Now().Add(-time.Second).UTC().Round(0)
	if _, err := value.decode(time.Now()); !errors.Is(err, ErrInvalidHandoff) {
		t.Fatalf("error = %v, want ErrInvalidHandoff", err)
	}
}
