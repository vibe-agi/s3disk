package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/presignedshare"
)

const (
	handoffFormat  = 1
	handoffProfile = "strict-share-isolation-v1"
	// A 4 MiB TLS CA bundle and 128 KiB bearer both expand under base64.
	// Six MiB leaves a bounded margin for the signed bindings and key material.
	maximumHandoffBytes        int64 = 6 << 20
	maximumHandoffPrefixBytes        = 768
	maximumHandoffChannelBytes       = 256
	maximumHandoffKeyIDBytes         = 128
)

var (
	ErrHandoffExists  = errors.New("s3disk: handoff output already exists")
	ErrInvalidHandoff = errors.New("s3disk: invalid handoff")
)

type handoffCheckpoint struct {
	Generation uint64 `json:"generation"`
	Commit     string `json:"commit"`
}

// handoff is the one secret transferred privately from A to B. Runtime
// synchronization after this transfer uses S3 only. It has no reusable S3
// SecretAccessKey, credential provider, or publisher private signing key. Its
// exact-GET bearer may still disclose the signing access-key ID and, when
// temporary credentials minted it, a session-token query value.
type handoff struct {
	Format                    int               `json:"format"`
	Profile                   string            `json:"profile"`
	ShareID                   string            `json:"share_id"`
	AuthorizationExpiresAt    time.Time         `json:"authorization_expires_at"`
	RootBearer                string            `json:"root_bearer"`
	RepositoryPrefix          string            `json:"repository_prefix"`
	ReferenceKey              string            `json:"reference_key"`
	Channel                   string            `json:"channel"`
	RepositoryID              string            `json:"repository_id"`
	ReferenceKeyID            string            `json:"reference_key_id"`
	ReferencePublicKey        string            `json:"reference_public_key"`
	TrustedCheckpoint         handoffCheckpoint `json:"trusted_checkpoint"`
	TLSRootCAPEM              string            `json:"tls_root_ca_pem,omitempty"`
	DangerouslyUseSystemTrust bool              `json:"dangerously_use_system_trust,omitempty"`
	AllowInsecureLoopback     bool              `json:"allow_insecure_loopback,omitempty"`
	ClientEncryptionKey       string            `json:"client_encryption_key"`
}

func (value handoff) String() string {
	return fmt.Sprintf("s3disk.handoff{format:%d,profile:%q,expires_at:%s,secrets:redacted}",
		value.Format, value.Profile, value.AuthorizationExpiresAt.Format(time.RFC3339Nano))
}

func (value handoff) GoString() string { return value.String() }

type decodedHandoff struct {
	wire       handoff
	shareID    presignedshare.ShareID
	root       presignedshare.Capability
	repository s3disk.RepositoryID
	publicKey  ed25519.PublicKey
	checkpoint s3disk.Watermark
	key        s3disk.ClientEncryptionKey
	profile    *s3disk.ClientEncryptionProfile
	tlsCAPEM   []byte
}

func (value handoff) decode(now time.Time) (decodedHandoff, error) {
	fail := func() (decodedHandoff, error) {
		return decodedHandoff{}, ErrInvalidHandoff
	}
	if value.Format != handoffFormat || value.Profile != handoffProfile {
		return fail()
	}
	// The credential-free mount path is strict S3-only. System trust can invoke
	// platform verification helpers outside Reader's locked dialer, so retain the
	// legacy wire field only to reject such handoffs explicitly.
	if value.DangerouslyUseSystemTrust {
		return fail()
	}
	if value.AuthorizationExpiresAt.IsZero() || !value.AuthorizationExpiresAt.Equal(value.AuthorizationExpiresAt.UTC().Round(0)) ||
		!value.AuthorizationExpiresAt.After(now) || value.AuthorizationExpiresAt.Sub(now) > presignedshare.MaximumCapabilityLifetime {
		return fail()
	}
	if err := validateHandoffText(value.RepositoryPrefix, maximumHandoffPrefixBytes, false); err != nil {
		return fail()
	}
	if strings.Trim(value.RepositoryPrefix, "/") != value.RepositoryPrefix {
		return fail()
	}
	if err := validateHandoffText(value.Channel, maximumHandoffChannelBytes, false); err != nil {
		return fail()
	}
	if err := validateHandoffText(value.ReferenceKey, 1024, false); err != nil {
		return fail()
	}
	if err := validateHandoffText(value.ReferenceKeyID, maximumHandoffKeyIDBytes, false); err != nil {
		return fail()
	}
	expectedReferenceKey := value.RepositoryPrefix + "/.s3disk/v1/signed-refs/v1/" +
		base64.RawURLEncoding.EncodeToString([]byte(value.Channel))
	if value.ReferenceKey != expectedReferenceKey {
		return fail()
	}
	shareID, err := presignedshare.ParseShareID(value.ShareID)
	if err != nil {
		return fail()
	}
	repositoryID, err := s3disk.ParseRepositoryID(value.RepositoryID)
	if err != nil {
		return fail()
	}
	bearer, err := decodeCanonicalBase64(value.RootBearer, presignedshare.MaximumBearerExportBytes)
	if err != nil {
		return fail()
	}
	root, err := presignedshare.ParseBearer(bearer, presignedshare.CapabilityOptions{AllowInsecureLoopback: value.AllowInsecureLoopback})
	if err != nil || !root.ExpiresAt().Equal(value.AuthorizationExpiresAt) {
		return fail()
	}
	_, strictHTTPSErr := presignedshare.ParseBearer(bearer, presignedshare.CapabilityOptions{})
	publicKey, err := decodeCanonicalBase64(value.ReferencePublicKey, ed25519.PublicKeySize)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fail()
	}
	commit, err := s3disk.ParseDigest(value.TrustedCheckpoint.Commit)
	if err != nil || commit.IsZero() || value.TrustedCheckpoint.Generation == 0 {
		return fail()
	}
	clientKey, err := s3disk.ParseClientEncryptionKey(value.ClientEncryptionKey)
	if err != nil {
		return fail()
	}
	profile, err := s3disk.NewClientEncryptionProfile(repositoryID, clientKey)
	if err != nil {
		return fail()
	}
	var tlsCAPEM []byte
	if value.TLSRootCAPEM != "" {
		tlsCAPEM, err = decodeCanonicalBase64(value.TLSRootCAPEM, int(presignedshare.MaximumTLSRootCAPEMBytes))
		if err != nil || len(tlsCAPEM) == 0 {
			return fail()
		}
	}
	if strictHTTPSErr == nil {
		if value.AllowInsecureLoopback || len(tlsCAPEM) == 0 {
			return fail()
		}
	} else if !value.AllowInsecureLoopback || len(tlsCAPEM) != 0 {
		return fail()
	}
	return decodedHandoff{
		wire: value, shareID: shareID, root: root, repository: repositoryID,
		publicKey:  append(ed25519.PublicKey(nil), publicKey...),
		checkpoint: s3disk.Watermark{RepositoryID: repositoryID, Generation: value.TrustedCheckpoint.Generation, Commit: commit},
		key:        clientKey, profile: profile, tlsCAPEM: append([]byte(nil), tlsCAPEM...),
	}, nil
}

func validateHandoffText(value string, maximum int, allowEmpty bool) error {
	if (!allowEmpty && value == "") || len(value) > maximum || !utf8.ValidString(value) || strings.ContainsRune(value, '\x00') || strings.TrimSpace(value) != value {
		return ErrInvalidHandoff
	}
	return nil
}

func decodeCanonicalBase64(value string, maximum int) ([]byte, error) {
	if value == "" || len(value) > base64.RawURLEncoding.EncodedLen(maximum) {
		return nil, ErrInvalidHandoff
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) > maximum || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalidHandoff
	}
	return decoded, nil
}

func writeHandoff(path string, value handoff) error {
	if path == "" {
		return fmt.Errorf("s3disk: handoff output path is required")
	}
	if _, err := value.decode(time.Now()); err != nil {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil || int64(len(encoded)+1) > maximumHandoffBytes {
		return ErrInvalidHandoff
	}
	encoded = append(encoded, '\n')
	absolute, err := resolveHandoffPath(path)
	if err != nil {
		return fmt.Errorf("s3disk: unsafe handoff output path: %w", err)
	}
	if err := s3disk.ValidatePrivateSecretDirectory(filepath.Dir(absolute)); err != nil {
		return fmt.Errorf("s3disk: unsafe handoff output directory: %w", err)
	}
	if _, err := os.Lstat(absolute); err == nil {
		return ErrHandoffExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("s3disk: inspect handoff output: %w", err)
	}
	file, err := os.OpenFile(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ErrHandoffExists
	}
	if err != nil {
		return fmt.Errorf("s3disk: create handoff output: %w", err)
	}
	created, statErr := file.Stat()
	if statErr != nil || !created.Mode().IsRegular() {
		_ = file.Close()
		removeSameFile(absolute, created)
		return fmt.Errorf("s3disk: created handoff output is not a regular file")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		removeSameFile(absolute, created)
		return fmt.Errorf("s3disk: set handoff permissions: %w", err)
	}
	// Validate the already-open descriptor, its current pathname, owner, ACL,
	// exact mode, and parent hierarchy before any bearer or encryption key bytes
	// cross the filesystem boundary.
	if err := s3disk.ValidatePrivateSecretFile(absolute, file); err != nil {
		_ = file.Close()
		removeSameFile(absolute, created)
		return fmt.Errorf("s3disk: protect handoff output: %w", err)
	}
	if err := writeAll(file, encoded); err != nil {
		_ = file.Close()
		removeSameFile(absolute, created)
		return fmt.Errorf("s3disk: write handoff: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		removeSameFile(absolute, created)
		return fmt.Errorf("s3disk: sync handoff: %w", err)
	}
	if err := file.Close(); err != nil {
		removeSameFile(absolute, created)
		return fmt.Errorf("s3disk: close handoff: %w", err)
	}
	if err := syncHandoffDirectory(filepath.Dir(absolute)); err != nil {
		return fmt.Errorf("s3disk: sync handoff directory: %w", err)
	}
	return nil
}

func preflightHandoffOutput(path string) error {
	absolute, err := resolveHandoffPath(path)
	if err != nil {
		return fmt.Errorf("s3disk: unsafe handoff output path: %w", err)
	}
	if err := s3disk.ValidatePrivateSecretDirectory(filepath.Dir(absolute)); err != nil {
		return fmt.Errorf("s3disk: unsafe handoff output directory: %w", err)
	}
	if _, err := os.Lstat(absolute); err == nil {
		return ErrHandoffExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("s3disk: inspect handoff output: %w", err)
	}
	return nil
}

func readHandoff(path string) (decodedHandoff, error) {
	if path == "" {
		return decodedHandoff{}, fmt.Errorf("s3disk: handoff path is required")
	}
	absolute, err := resolveHandoffPath(path)
	if err != nil {
		return decodedHandoff{}, ErrInvalidHandoff
	}
	before, err := os.Lstat(absolute)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return decodedHandoff{}, ErrInvalidHandoff
	}
	file, err := os.Open(absolute)
	if err != nil {
		return decodedHandoff{}, ErrInvalidHandoff
	}
	defer file.Close()
	if err := s3disk.ValidatePrivateSecretFile(absolute, file); err != nil {
		return decodedHandoff{}, fmt.Errorf("%w: private file validation failed: %w", ErrInvalidHandoff, err)
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximumHandoffBytes+1))
	if err != nil || int64(len(encoded)) > maximumHandoffBytes {
		return decodedHandoff{}, ErrInvalidHandoff
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var value handoff
	if err := decoder.Decode(&value); err != nil {
		return decodedHandoff{}, ErrInvalidHandoff
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return decodedHandoff{}, ErrInvalidHandoff
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(encoded, append(canonical, '\n')) {
		return decodedHandoff{}, ErrInvalidHandoff
	}
	return value.decode(time.Now())
}

// resolveHandoffPath resolves the complete existing parent once, then keeps
// the final component unresolved. O_EXCL protects a writer from following an
// existing final-component symlink; readers separately reject that symlink.
// Resolving the parent also avoids rejecting ordinary system paths such as
// macOS /var, which itself is a compatibility symlink.
func resolveHandoffPath(path string) (string, error) {
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
	return filepath.Join(parent, base), nil
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

func removeSameFile(path string, expected os.FileInfo) {
	if expected == nil {
		return
	}
	observed, err := os.Lstat(path)
	if err == nil && os.SameFile(expected, observed) {
		_ = os.Remove(path)
	}
}

func syncHandoffDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
