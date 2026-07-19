package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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

	handoffDigestDomain = "s3disk\x00cli\x00handoff-canonical-bytes\x00v1\x00"
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

type handoffWire handoff

func (value handoff) String() string {
	return fmt.Sprintf("s3disk.handoff{format:%d,profile:%q,expires_at:%s,secrets:redacted}",
		value.Format, value.Profile, value.AuthorizationExpiresAt.Format(time.RFC3339Nano))
}

func (value handoff) GoString() string { return value.String() }

// MarshalJSON is diagnostic-only and never emits bearer, encryption, trust,
// or repository metadata. The handoff persistence codec marshals handoffWire
// explicitly after semantic validation.
func (value handoff) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Format  int       `json:"format"`
		Profile string    `json:"profile"`
		ShareID string    `json:"share_id"`
		Expires time.Time `json:"authorization_expires_at"`
		Secrets string    `json:"secrets"`
	}{
		Format: value.Format, Profile: value.Profile, ShareID: value.ShareID,
		Expires: value.AuthorizationExpiresAt, Secrets: "redacted",
	})
}

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
		canonicalCAPEM, canonicalErr := canonicalTLSRootCAPEM(tlsCAPEM)
		if canonicalErr != nil || !bytes.Equal(canonicalCAPEM, tlsCAPEM) {
			clear(canonicalCAPEM)
			clear(tlsCAPEM)
			return fail()
		}
		clear(canonicalCAPEM)
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

func writeHandoff(ctx context.Context, path string, value handoff) error {
	if path == "" {
		return fmt.Errorf("s3disk: handoff output path is required")
	}
	encoded, err := encodeHandoff(value)
	if err != nil {
		return err
	}
	defer clear(encoded)
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
	return writeHandoffBytes(ctx, absolute, encoded, installPrivateFileNoReplace)
}

func encodeHandoff(value handoff) ([]byte, error) {
	if _, err := value.decode(time.Now()); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(handoffWire(value))
	if err != nil || int64(len(encoded)+1) > maximumHandoffBytes {
		return nil, ErrInvalidHandoff
	}
	return append(encoded, '\n'), nil
}

// handoffDigest binds the exact canonical handoff bytes recorded in the
// publisher session. The length prefix and domain keep this digest distinct
// from object, session, and plain SHA-256 identifiers.
func handoffDigest(encoded []byte) s3disk.Digest {
	hash := sha256.New()
	_, _ = hash.Write([]byte(handoffDigestDomain))
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(encoded)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(encoded)
	var digest s3disk.Digest
	copy(digest[:], hash.Sum(nil))
	return digest
}

// installOrVerifyHandoff is the idempotent recovery write for A's private
// handoff. It never replaces an existing pathname. A prior or concurrently
// installed file is accepted only after the same private-file, strict JSON,
// semantic, canonical-byte, and digest checks used by readHandoff.
func installOrVerifyHandoff(
	ctx context.Context,
	path string,
	value handoff,
	expectedDigest s3disk.Digest,
) error {
	return installOrVerifyHandoffWithOperations(
		ctx, path, value, expectedDigest,
		privateFileOperationsFor(installPrivateFileNoReplace),
	)
}

func installOrVerifyHandoffWithOperations(
	ctx context.Context,
	path string,
	value handoff,
	expectedDigest s3disk.Digest,
	operations privateFileOperations,
) error {
	if ctx == nil {
		return fmt.Errorf("s3disk: install handoff context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if path == "" {
		return fmt.Errorf("s3disk: handoff output path is required")
	}
	encoded, err := encodeHandoff(value)
	if err != nil {
		return err
	}
	defer clear(encoded)
	if expectedDigest.IsZero() || handoffDigest(encoded) != expectedDigest {
		return fmt.Errorf("%w: handoff digest does not bind the canonical bytes", ErrInvalidHandoff)
	}
	operations = operations.withDefaults()
	absolute, err := resolveHandoffPath(path)
	if err != nil {
		return fmt.Errorf("s3disk: unsafe handoff output path: %w", err)
	}

	result, writeErr := writePrivateFileNoReplace(
		ctx,
		resolvedPrivatePath(absolute), bytes.Clone(encoded), maximumHandoffBytes,
		".s3disk-handoff-*", operations,
	)
	if writeErr == nil {
		if err := verifyExactHandoff(absolute, encoded, expectedDigest); err != nil {
			return fmt.Errorf("s3disk: verify installed handoff: %w", err)
		}
		return nil
	}

	if errors.Is(writeErr, errPrivateFileExists) {
		if err := verifyExactHandoff(absolute, encoded, expectedDigest); err != nil {
			return errors.Join(ErrHandoffExists, err)
		}
		if result.needsReconciliation() {
			return writeErr
		}
		cleanupErr := reconcileInstalledPrivateFileStaging(
			ctx, resolvedPrivatePath(absolute), ".s3disk-handoff-*", operations,
		)
		syncErr := operations.syncDirectory(filepath.Dir(absolute))
		if syncErr != nil {
			syncErr = fmt.Errorf("s3disk: sync existing handoff directory: %w", syncErr)
		}
		if cleanupErr != nil || syncErr != nil {
			return errors.Join(
				ErrPrivateFileInstalledUnconfirmed,
				cleanupErr,
				syncErr,
			)
		}
		return nil
	}
	// An installer may have applied the no-replace operation before its
	// response was lost. Only an exact safe reread can turn that uncertainty
	// into success. Cleanup or directory-durability failures remain errors:
	// byte equality alone cannot resolve those obligations.
	if errors.Is(writeErr, ErrPrivateFileInstallIndeterminate) && result.needsReconciliation() {
		if err := verifyExactHandoff(absolute, encoded, expectedDigest); err == nil {
			if !result.CleanupConfirmed || !result.DurabilityConfirmed {
				return writeErr
			}
			return nil
		} else if errors.Is(err, ErrHandoffExists) {
			return errors.Join(ErrHandoffExists, writeErr)
		} else {
			return errors.Join(writeErr, err)
		}
	}
	return writeErr
}

func verifyExactHandoff(path string, expected []byte, expectedDigest s3disk.Digest) error {
	_, observed, err := readCanonicalHandoff(path)
	if err != nil {
		return err
	}
	defer clear(observed)
	if !bytes.Equal(observed, expected) || handoffDigest(observed) != expectedDigest {
		return ErrHandoffExists
	}
	return nil
}

type handoffInstaller = privateFileInstaller

// writeHandoffBytes writes and syncs the complete secret into a private
// temporary file before atomically installing the final pathname. A crash
// before installation can leave, at worst, a private temporary file; it can
// never expose a partial handoff at the path given to B.
func writeHandoffBytes(ctx context.Context, absolute string, encoded []byte, install handoffInstaller) error {
	defer clear(encoded)
	if len(encoded) == 0 || int64(len(encoded)) > maximumHandoffBytes || install == nil {
		return ErrInvalidHandoff
	}
	result, err := writePrivateFileNoReplace(
		ctx,
		resolvedPrivatePath(absolute), encoded, maximumHandoffBytes,
		".s3disk-handoff-*", privateFileOperationsFor(install),
	)
	if errors.Is(err, errPrivateFileExists) {
		if result.needsReconciliation() {
			return fmt.Errorf("s3disk: write handoff atomically: %w", err)
		}
		return ErrHandoffExists
	}
	if err != nil {
		return fmt.Errorf("s3disk: write handoff atomically: %w", err)
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
	decoded, encoded, err := readCanonicalHandoff(path)
	clear(encoded)
	return decoded, err
}

func readCanonicalHandoff(path string) (decodedHandoff, []byte, error) {
	if path == "" {
		return decodedHandoff{}, nil, fmt.Errorf("s3disk: handoff path is required")
	}
	absolute, err := resolveHandoffPath(path)
	if err != nil {
		return decodedHandoff{}, nil, ErrInvalidHandoff
	}
	before, err := os.Lstat(absolute)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return decodedHandoff{}, nil, ErrInvalidHandoff
	}
	file, err := os.Open(absolute)
	if err != nil {
		return decodedHandoff{}, nil, ErrInvalidHandoff
	}
	defer file.Close()
	if err := s3disk.ValidatePrivateSecretFile(absolute, file); err != nil {
		return decodedHandoff{}, nil, fmt.Errorf("%w: private file validation failed: %w", ErrInvalidHandoff, err)
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximumHandoffBytes+1))
	if err != nil || int64(len(encoded)) > maximumHandoffBytes {
		clear(encoded)
		return decodedHandoff{}, nil, ErrInvalidHandoff
	}
	fail := func() (decodedHandoff, []byte, error) {
		clear(encoded)
		return decodedHandoff{}, nil, ErrInvalidHandoff
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var value handoff
	if err := decoder.Decode(&value); err != nil {
		return fail()
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fail()
	}
	canonical, err := json.Marshal(handoffWire(value))
	if err != nil || !bytes.Equal(encoded, append(canonical, '\n')) {
		return fail()
	}
	decoded, err := value.decode(time.Now())
	if err != nil {
		return fail()
	}
	return decoded, encoded, nil
}

// resolveHandoffPath resolves the complete existing parent once, then keeps
// the final component unresolved. O_EXCL protects a writer from following an
// existing final-component symlink; readers separately reject that symlink.
// Resolving the parent also avoids rejecting ordinary system paths such as
// macOS /var, which itself is a compatibility symlink.
func resolveHandoffPath(path string) (string, error) {
	resolved, err := resolvePrivatePath(path)
	return string(resolved), err
}
