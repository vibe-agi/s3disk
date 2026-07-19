package publisherstate

import (
	"context"
	"encoding/json"
	"fmt"
)

const (
	// MaximumAESGCMKeyringKeys bounds the active key plus retained keys. Keeping
	// selection local and finite prevents an untrusted envelope selector from
	// becoming an unbounded lookup or an external KMS request.
	MaximumAESGCMKeyringKeys = 32
)

// AESGCMKeyring supports deliberate recovery-key rotation for the built-in v1
// envelope. Seal always uses the active key. Open accepts only the active key
// or an explicitly retained key. The key ID parsed from an envelope is an
// untrusted selector until the selected protector authenticates the envelope.
//
// The keyring is intentionally limited to AESGCMProtector. The general
// Protector interface permits custom envelope formats, which cannot safely be
// selected with the built-in v1 parser.
type AESGCMKeyring struct {
	active *AESGCMProtector
	byID   map[string]*AESGCMProtector
}

// NewAESGCMKeyring copies the active and retained protectors into an immutable,
// concurrent-safe keyring. Every key must have a distinct key ID; rotating key
// material under a reused ID is rejected because both generations could not be
// retained unambiguously.
func NewAESGCMKeyring(active *AESGCMProtector, retained ...*AESGCMProtector) (*AESGCMKeyring, error) {
	if active == nil || !active.configured() {
		return nil, ErrProtectorUnavailable
	}
	if len(retained)+1 > MaximumAESGCMKeyringKeys {
		return nil, fmt.Errorf("%w: too many recovery protectors", ErrResourceLimit)
	}
	keyring := &AESGCMKeyring{byID: make(map[string]*AESGCMProtector, len(retained)+1)}
	all := make([]*AESGCMProtector, 0, len(retained)+1)
	all = append(all, active)
	all = append(all, retained...)
	for index, protector := range all {
		if protector == nil || !protector.configured() {
			return nil, ErrProtectorUnavailable
		}
		if _, exists := keyring.byID[protector.keyID]; exists {
			return nil, ErrProtectorConflict
		}
		cloned := *protector
		keyring.byID[cloned.keyID] = &cloned
		if index == 0 {
			keyring.active = &cloned
		}
	}
	return keyring, nil
}

// KeyID returns the active key selector used by future Seal operations.
func (keyring *AESGCMKeyring) KeyID() string {
	if keyring == nil || keyring.active == nil {
		return ""
	}
	return keyring.active.keyID
}

// Seal always creates a fresh envelope with the active protector.
func (keyring *AESGCMKeyring) Seal(ctx context.Context, binding, plaintext []byte) ([]byte, error) {
	if !keyring.configured() {
		return nil, ErrProtectorUnavailable
	}
	return keyring.active.Seal(ctx, binding, plaintext)
}

// Open authenticates an envelope with its explicitly configured key. Unknown
// selectors never trigger fallback attempts or external lookups.
func (keyring *AESGCMKeyring) Open(ctx context.Context, binding, envelope []byte) ([]byte, error) {
	plaintext, _, err := keyring.openSelected(ctx, binding, envelope)
	return plaintext, err
}

// Rewrap authenticates envelope before deciding whether it already uses the
// active key. An active envelope is returned as an independent byte slice with
// changed=false. A retained-key envelope is decrypted and sealed into a fresh
// active-key envelope with changed=true. Rewrap provides no persistence or
// rollback protection; callers must install its output with a durable CAS.
func (keyring *AESGCMKeyring) Rewrap(ctx context.Context, binding, envelope []byte) ([]byte, bool, error) {
	plaintext, selectedKeyID, err := keyring.openSelected(ctx, binding, envelope)
	if err != nil {
		return nil, false, err
	}
	defer clear(plaintext)
	if selectedKeyID == keyring.active.keyID {
		return append([]byte(nil), envelope...), false, nil
	}
	rewrapped, err := keyring.active.Seal(ctx, binding, plaintext)
	if err != nil {
		return nil, false, err
	}
	return rewrapped, true, nil
}

func (keyring *AESGCMKeyring) openSelected(ctx context.Context, binding, envelope []byte) ([]byte, string, error) {
	if ctx == nil {
		return nil, "", fmt.Errorf("publisherstate: Open context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if !keyring.configured() {
		return nil, "", ErrProtectorUnavailable
	}
	if err := validateBinding(binding); err != nil {
		return nil, "", err
	}
	if len(envelope) > MaximumEnvelopeBytes {
		return nil, "", fmt.Errorf("%w: envelope is too large", ErrResourceLimit)
	}
	parsed, err := parseEnvelope(envelope)
	if err != nil {
		return nil, "", err
	}
	protector, exists := keyring.byID[parsed.keyID]
	if !exists {
		return nil, "", ErrAuthenticationFailed
	}
	plaintext, err := protector.Open(ctx, binding, envelope)
	if err != nil {
		return nil, "", err
	}
	return plaintext, parsed.keyID, nil
}

func (keyring *AESGCMKeyring) configured() bool {
	if keyring == nil || keyring.active == nil || !keyring.active.configured() || len(keyring.byID) < 1 ||
		len(keyring.byID) > MaximumAESGCMKeyringKeys {
		return false
	}
	active, exists := keyring.byID[keyring.active.keyID]
	return exists && active == keyring.active
}

func (keyring AESGCMKeyring) String() string {
	return fmt.Sprintf("publisherstate.AESGCMKeyring{configured:%t,key_count:%d,secrets:redacted}",
		keyring.configured(), len(keyring.byID))
}

func (keyring AESGCMKeyring) GoString() string { return keyring.String() }

func (keyring AESGCMKeyring) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Configured bool   `json:"configured"`
		KeyCount   int    `json:"key_count"`
		Secrets    string `json:"secrets"`
	}{Configured: keyring.configured(), KeyCount: len(keyring.byID), Secrets: "redacted"})
}

var _ Protector = (*AESGCMKeyring)(nil)
