package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/publisherstate"
)

const (
	recoveryKeyFileFormat       = 1
	maximumRecoveryKeyFileBytes = 512
	recoveryKeyIDHashBytes      = 24
	recoveryKeyIDPrefix         = "rk1."
)

var (
	ErrRecoveryKeyFileExists  = errors.New("s3disk: recovery-key output already exists")
	ErrInvalidRecoveryKeyFile = errors.New("s3disk: invalid recovery-key file")

	recoveryKeyIDDomain = []byte("s3disk\x00publisher-recovery-key-id\x00v1\x00")
)

type RecoveryKeyGenerateOptions struct {
	Out          string
	StatusWriter io.Writer
}

type recoveryKeyFile struct {
	Format      int    `json:"format"`
	KeyID       string `json:"key_id"`
	RecoveryKey string `json:"recovery_key"`
}

type recoveryKeyFileWire recoveryKeyFile

func (value recoveryKeyFile) String() string {
	return fmt.Sprintf("s3disk.recoveryKeyFile{format:%d,key_id:%q,secrets:redacted}", value.Format, value.KeyID)
}

func (value recoveryKeyFile) GoString() string { return value.String() }

// MarshalJSON is diagnostic-only and never exposes the recovery secret. The
// narrow persistence codec explicitly marshals recoveryKeyFileWire instead.
func (value recoveryKeyFile) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Format  int    `json:"format"`
		KeyID   string `json:"key_id"`
		Secrets string `json:"secrets"`
	}{Format: value.Format, KeyID: value.KeyID, Secrets: "redacted"})
}

type recoveryKeyMaterial struct {
	keyID string
	key   publisherstate.RecoveryKey
}

func (value recoveryKeyMaterial) String() string {
	return fmt.Sprintf("s3disk.recoveryKeyMaterial{key_id:%q,secrets:redacted}", value.keyID)
}

func (value recoveryKeyMaterial) GoString() string { return value.String() }

func runGenerateRecoveryKey(ctx context.Context, options RecoveryKeyGenerateOptions) error {
	return runGenerateRecoveryKeyWithOperations(ctx, options, privateFileOperationsFor(installPrivateFileNoReplace))
}

func runGenerateRecoveryKeyWithOperations(
	ctx context.Context,
	options RecoveryKeyGenerateOptions,
	operations privateFileOperations,
) error {
	if ctx == nil {
		return fmt.Errorf("s3disk share recovery-key generate: context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateRecoveryKeyGenerateOptions(options); err != nil {
		return err
	}
	key, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		return fmt.Errorf("s3disk share recovery-key generate: %w", err)
	}
	material, result, err := writeRecoveryKeyFileWithOperations(ctx, options.Out, key, operations)
	if err != nil {
		if result.needsReconciliation() && material.keyID != "" && options.StatusWriter != nil &&
			(errors.Is(err, ErrPrivateFileInstallIndeterminate) ||
				errors.Is(err, ErrPrivateFileInstalledUnconfirmed)) {
			outcome := "installation_indeterminate"
			if errors.Is(err, ErrPrivateFileInstalledUnconfirmed) {
				outcome = "installed_cleanup_or_durability_unconfirmed"
			}
			_, _ = fmt.Fprintf(options.StatusWriter,
				"reconcile_required: recovery_key_file=%q key_id=%q outcome=%q\n",
				options.Out, material.keyID, outcome)
		}
		return fmt.Errorf("s3disk share recovery-key generate: %w", err)
	}
	if options.StatusWriter != nil {
		_, _ = fmt.Fprintf(options.StatusWriter, "ready: recovery_key_file=%q key_id=%q\n", options.Out, material.keyID)
	}
	return nil
}

func validateRecoveryKeyGenerateOptions(options RecoveryKeyGenerateOptions) error {
	if strings.TrimSpace(options.Out) == "" {
		return fmt.Errorf("s3disk share recovery-key generate: --out is required")
	}
	return nil
}

func writeRecoveryKeyFile(
	ctx context.Context,
	path string,
	key publisherstate.RecoveryKey,
) (recoveryKeyMaterial, privateFileWriteResult, error) {
	return writeRecoveryKeyFileWithOperations(
		ctx, path, key, privateFileOperationsFor(installPrivateFileNoReplace),
	)
}

func writeRecoveryKeyFileWithOperations(
	ctx context.Context,
	path string,
	key publisherstate.RecoveryKey,
	operations privateFileOperations,
) (recoveryKeyMaterial, privateFileWriteResult, error) {
	if path == "" {
		return recoveryKeyMaterial{}, privateFileWriteResult{}, fmt.Errorf("s3disk: recovery-key output path is required")
	}
	absolute, err := resolvePrivatePath(path)
	if err != nil {
		return recoveryKeyMaterial{}, privateFileWriteResult{}, fmt.Errorf("s3disk: unsafe recovery-key output path: %w", err)
	}
	if err := s3disk.ValidatePrivateSecretDirectory(filepath.Dir(string(absolute))); err != nil {
		return recoveryKeyMaterial{}, privateFileWriteResult{}, fmt.Errorf("s3disk: unsafe recovery-key output directory: %w", err)
	}
	if _, err := os.Lstat(string(absolute)); err == nil {
		return recoveryKeyMaterial{}, privateFileWriteResult{}, ErrRecoveryKeyFileExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return recoveryKeyMaterial{}, privateFileWriteResult{}, fmt.Errorf("s3disk: inspect recovery-key output: %w", err)
	}
	encoded, material, err := encodeRecoveryKeyFile(key)
	if err != nil {
		return recoveryKeyMaterial{}, privateFileWriteResult{}, err
	}
	defer clear(encoded)
	result, err := writeRecoveryKeyBytesWithOperations(ctx, string(absolute), encoded, operations)
	if err != nil {
		return material, result, err
	}
	return material, result, nil
}

func encodeRecoveryKeyFile(key publisherstate.RecoveryKey) ([]byte, recoveryKeyMaterial, error) {
	secret := key.ExportSecret()
	if secret == "" {
		return nil, recoveryKeyMaterial{}, publisherstate.ErrInvalidRecoveryKey
	}
	keyID := deriveRecoveryKeyID(secret)
	value := recoveryKeyFile{Format: recoveryKeyFileFormat, KeyID: keyID, RecoveryKey: secret}
	encoded, err := json.Marshal(recoveryKeyFileWire(value))
	if err != nil || len(encoded)+1 > maximumRecoveryKeyFileBytes {
		return nil, recoveryKeyMaterial{}, ErrInvalidRecoveryKeyFile
	}
	encoded = append(encoded, '\n')
	return encoded, recoveryKeyMaterial{keyID: keyID, key: key}, nil
}

func writeRecoveryKeyBytes(
	ctx context.Context,
	absolute string,
	encoded []byte,
	install privateFileInstaller,
) (privateFileWriteResult, error) {
	return writeRecoveryKeyBytesWithOperations(ctx, absolute, encoded, privateFileOperationsFor(install))
}

func writeRecoveryKeyBytesWithOperations(
	ctx context.Context,
	absolute string,
	encoded []byte,
	operations privateFileOperations,
) (privateFileWriteResult, error) {
	if len(encoded) == 0 || len(encoded) > maximumRecoveryKeyFileBytes || operations.install == nil {
		clear(encoded)
		return privateFileWriteResult{}, ErrInvalidRecoveryKeyFile
	}
	result, err := writePrivateFileNoReplace(
		ctx,
		resolvedPrivatePath(absolute), encoded, maximumRecoveryKeyFileBytes,
		".s3disk-recovery-key-*", operations,
	)
	if errors.Is(err, errPrivateFileExists) {
		if result.needsReconciliation() {
			return result, errors.Join(ErrRecoveryKeyFileExists, err)
		}
		return result, ErrRecoveryKeyFileExists
	}
	if err != nil {
		return result, fmt.Errorf("s3disk: write recovery-key file atomically: %w", err)
	}
	return result, nil
}

// readRecoveryKeyFile reads a canonical private recovery-key file. It validates
// the current pathname, owner, exact mode, ACL, and parent hierarchy before
// reading secret bytes, then authenticates the non-secret key ID by recomputing
// it from the canonical recovery-key representation.
func readRecoveryKeyFile(path string) (recoveryKeyMaterial, error) {
	return readRecoveryKeyFileContext(context.Background(), path)
}

func readRecoveryKeyFileContext(ctx context.Context, path string) (recoveryKeyMaterial, error) {
	if ctx == nil {
		return recoveryKeyMaterial{}, fmt.Errorf("s3disk: recovery-key context is required")
	}
	if err := ctx.Err(); err != nil {
		return recoveryKeyMaterial{}, err
	}
	if path == "" {
		return recoveryKeyMaterial{}, fmt.Errorf("s3disk: recovery-key path is required")
	}
	absolute, err := resolvePrivatePath(path)
	if err != nil {
		return recoveryKeyMaterial{}, ErrInvalidRecoveryKeyFile
	}
	if err := reconcileInstalledPrivateFileStaging(
		ctx, absolute, ".s3disk-recovery-key-*", privateFileOperations{},
	); err != nil {
		return recoveryKeyMaterial{}, fmt.Errorf("%w: staging reconciliation failed: %w", ErrInvalidRecoveryKeyFile, err)
	}
	before, err := os.Lstat(string(absolute))
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return recoveryKeyMaterial{}, ErrInvalidRecoveryKeyFile
	}
	file, err := os.Open(string(absolute))
	if err != nil {
		return recoveryKeyMaterial{}, ErrInvalidRecoveryKeyFile
	}
	defer file.Close()
	if err := s3disk.ValidatePrivateSecretFile(string(absolute), file); err != nil {
		return recoveryKeyMaterial{}, fmt.Errorf("%w: private file validation failed: %w", ErrInvalidRecoveryKeyFile, err)
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximumRecoveryKeyFileBytes+1))
	if err != nil || len(encoded) < 1 || len(encoded) > maximumRecoveryKeyFileBytes {
		return recoveryKeyMaterial{}, ErrInvalidRecoveryKeyFile
	}
	defer clear(encoded)
	return decodeRecoveryKeyFile(encoded)
}

func decodeRecoveryKeyFile(encoded []byte) (recoveryKeyMaterial, error) {
	if len(encoded) < 1 || len(encoded) > maximumRecoveryKeyFileBytes {
		return recoveryKeyMaterial{}, ErrInvalidRecoveryKeyFile
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var value recoveryKeyFile
	if err := decoder.Decode(&value); err != nil {
		return recoveryKeyMaterial{}, ErrInvalidRecoveryKeyFile
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return recoveryKeyMaterial{}, ErrInvalidRecoveryKeyFile
	}
	canonical, err := json.Marshal(recoveryKeyFileWire(value))
	defer clear(canonical)
	if err != nil || !bytes.Equal(encoded, append(canonical, '\n')) || value.Format != recoveryKeyFileFormat {
		return recoveryKeyMaterial{}, ErrInvalidRecoveryKeyFile
	}
	key, err := publisherstate.ParseRecoveryKey(value.RecoveryKey)
	if err != nil {
		return recoveryKeyMaterial{}, ErrInvalidRecoveryKeyFile
	}
	wantKeyID := deriveRecoveryKeyID(key.ExportSecret())
	if len(value.KeyID) != len(wantKeyID) ||
		subtle.ConstantTimeCompare([]byte(value.KeyID), []byte(wantKeyID)) != 1 {
		return recoveryKeyMaterial{}, ErrInvalidRecoveryKeyFile
	}
	return recoveryKeyMaterial{keyID: wantKeyID, key: key}, nil
}

func deriveRecoveryKeyID(canonicalSecret string) string {
	hash := sha256.New()
	_, _ = hash.Write(recoveryKeyIDDomain)
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(canonicalSecret)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write([]byte(canonicalSecret))
	digest := hash.Sum(nil)
	keyID := recoveryKeyIDPrefix + base64.RawURLEncoding.EncodeToString(digest[:recoveryKeyIDHashBytes])
	clear(digest)
	return keyID
}
