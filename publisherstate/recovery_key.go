package publisherstate

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	// RecoveryKeyBytes is the exact size of a publisher recovery key.
	RecoveryKeyBytes = 32

	recoveryKeySecretPrefix = "s3disk-publisher-recovery-v1."
)

// RecoveryKey is a random 256-bit secret used only to construct a Protector.
// Ordinary assignment copies its material. Diagnostic formatting is always
// redacted; ExportSecret is the only method which intentionally reveals it.
type RecoveryKey struct {
	material [RecoveryKeyBytes]byte
}

// GenerateRecoveryKey reads a new key from the operating system CSPRNG.
func GenerateRecoveryKey() (RecoveryKey, error) {
	var key RecoveryKey
	if _, err := rand.Read(key.material[:]); err != nil {
		return RecoveryKey{}, fmt.Errorf("publisherstate: generate recovery key: %w", err)
	}
	if !key.configured() {
		return RecoveryKey{}, ErrInvalidRecoveryKey
	}
	return key, nil
}

// ParseRecoveryKey parses the canonical representation returned by
// ExportSecret. Failures never include the supplied value.
func ParseRecoveryKey(secret string) (RecoveryKey, error) {
	if !strings.HasPrefix(secret, recoveryKeySecretPrefix) {
		return RecoveryKey{}, ErrInvalidRecoveryKey
	}
	encoded := strings.TrimPrefix(secret, recoveryKeySecretPrefix)
	if len(encoded) != base64.RawURLEncoding.EncodedLen(RecoveryKeyBytes) {
		return RecoveryKey{}, ErrInvalidRecoveryKey
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != RecoveryKeyBytes || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return RecoveryKey{}, ErrInvalidRecoveryKey
	}
	var key RecoveryKey
	copy(key.material[:], decoded)
	clear(decoded)
	if !key.configured() {
		return RecoveryKey{}, ErrInvalidRecoveryKey
	}
	return key, nil
}

// ExportSecret returns the canonical private representation of key. A zero key
// exports as an empty string.
func (key RecoveryKey) ExportSecret() string {
	if !key.configured() {
		return ""
	}
	return recoveryKeySecretPrefix + base64.RawURLEncoding.EncodeToString(key.material[:])
}

func (key RecoveryKey) configured() bool {
	var zero [RecoveryKeyBytes]byte
	return subtle.ConstantTimeCompare(key.material[:], zero[:]) != 1
}

func (key RecoveryKey) String() string {
	return fmt.Sprintf("publisherstate.RecoveryKey{configured:%t,secrets:redacted}", key.configured())
}

func (key RecoveryKey) GoString() string { return key.String() }

func (key RecoveryKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Configured bool   `json:"configured"`
		Secrets    string `json:"secrets"`
	}{Configured: key.configured(), Secrets: "redacted"})
}
