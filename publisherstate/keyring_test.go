package publisherstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestAESGCMKeyringReadsPreviousKeyAndSealsOnlyWithActiveKey(t *testing.T) {
	t.Parallel()

	oldProtector := newTestProtector(t, "recovery-2025")
	activeProtector := newTestProtector(t, "recovery-2026")
	keyring, err := NewAESGCMKeyring(activeProtector, oldProtector)
	if err != nil {
		t.Fatal(err)
	}
	binding := []byte("repository/share/state")
	plaintext := []byte("state protected before rotation")
	oldEnvelope, err := oldProtector.Seal(context.Background(), binding, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := keyring.Open(context.Background(), binding, oldEnvelope)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("open previous envelope = %q, %v", opened, err)
	}

	newEnvelope, err := keyring.Seal(context.Background(), binding, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseEnvelope(newEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.keyID != activeProtector.KeyID() || keyring.KeyID() != activeProtector.KeyID() {
		t.Fatalf("new/active key IDs = %q/%q", parsed.keyID, keyring.KeyID())
	}
	if _, err := oldProtector.Open(context.Background(), binding, newEnvelope); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("previous key opened newly sealed envelope: %v", err)
	}
	if opened, err := activeProtector.Open(context.Background(), binding, newEnvelope); err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("active key could not open newly sealed envelope: %v", err)
	}
}

func TestAESGCMKeyringRejectsUnknownAndTamperedSelectors(t *testing.T) {
	t.Parallel()

	active := newTestProtector(t, "active-key")
	unknown := newTestProtector(t, "former-key")
	keyring, err := NewAESGCMKeyring(active)
	if err != nil {
		t.Fatal(err)
	}
	binding := []byte("binding")
	envelope, err := unknown.Seal(context.Background(), binding, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyring.Open(context.Background(), binding, envelope); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("unknown selector error = %v, want ErrAuthenticationFailed", err)
	}

	tampered := append([]byte(nil), envelope...)
	copy(tampered[envelopeHeaderBytes:envelopeHeaderBytes+len("former-key")], "active-key")
	if _, err := keyring.Open(context.Background(), binding, tampered); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("tampered selector error = %v, want ErrAuthenticationFailed", err)
	}
}

func TestAESGCMKeyringRejectsInvalidAndAmbiguousConfiguration(t *testing.T) {
	t.Parallel()

	active := newTestProtector(t, "same-key")
	duplicate := newTestProtector(t, "same-key")
	var typedNil *AESGCMProtector
	for name, build := range map[string]func() error{
		"nil active": func() error {
			_, err := NewAESGCMKeyring(nil)
			return err
		},
		"typed-nil active": func() error {
			_, err := NewAESGCMKeyring(typedNil)
			return err
		},
		"typed-nil previous": func() error {
			_, err := NewAESGCMKeyring(active, typedNil)
			return err
		},
		"duplicate selector": func() error {
			_, err := NewAESGCMKeyring(active, duplicate)
			return err
		},
	} {
		err := build()
		if name == "duplicate selector" {
			if !errors.Is(err, ErrProtectorConflict) {
				t.Errorf("%s error = %v, want ErrProtectorConflict", name, err)
			}
		} else if !errors.Is(err, ErrProtectorUnavailable) {
			t.Errorf("%s error = %v, want ErrProtectorUnavailable", name, err)
		}
	}
	retained := make([]*AESGCMProtector, MaximumAESGCMKeyringKeys)
	for index := range retained {
		retained[index] = newTestProtector(t, fmt.Sprintf("retained-%d", index))
	}
	if _, err := NewAESGCMKeyring(active, retained...); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("oversized keyring error = %v, want ErrResourceLimit", err)
	}
}

func TestAESGCMKeyringRewrapAuthenticatesBeforeChangingOrNoOp(t *testing.T) {
	t.Parallel()

	oldProtector := newTestProtector(t, "old-key")
	activeProtector := newTestProtector(t, "new-key")
	keyring, err := NewAESGCMKeyring(activeProtector, oldProtector)
	if err != nil {
		t.Fatal(err)
	}
	binding := []byte("rewrap-binding")
	plaintext := []byte("rewrap-secret")
	oldEnvelope, err := oldProtector.Seal(context.Background(), binding, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	rewrapped, changed, err := keyring.Rewrap(context.Background(), binding, oldEnvelope)
	if err != nil || !changed {
		t.Fatalf("Rewrap old envelope = changed %v, error %v", changed, err)
	}
	if bytes.Equal(rewrapped, oldEnvelope) {
		t.Fatal("rewrapped envelope did not change")
	}
	if opened, err := activeProtector.Open(context.Background(), binding, rewrapped); err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("active key cannot open rewrapped envelope: %v", err)
	}
	if _, err := oldProtector.Open(context.Background(), binding, rewrapped); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("old key opened rewrapped envelope: %v", err)
	}

	second, changed, err := keyring.Rewrap(context.Background(), binding, rewrapped)
	if err != nil || changed || !bytes.Equal(second, rewrapped) {
		t.Fatalf("second Rewrap = changed %v, error %v", changed, err)
	}
	second[0] ^= 1
	if bytes.Equal(second, rewrapped) {
		t.Fatal("no-op Rewrap output aliases its input")
	}

	tamperedActive := append([]byte(nil), rewrapped...)
	tamperedActive[len(tamperedActive)-1] ^= 1
	if _, changed, err := keyring.Rewrap(context.Background(), binding, tamperedActive); !errors.Is(err, ErrAuthenticationFailed) || changed {
		t.Fatalf("tampered active Rewrap = changed %v, error %v", changed, err)
	}
}

func TestAESGCMKeyringDiagnosticsDoNotTraverseKeys(t *testing.T) {
	t.Parallel()

	active := newTestProtector(t, "diagnostic-active")
	previous := newTestProtector(t, "diagnostic-previous")
	keyring, err := NewAESGCMKeyring(active, previous)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(keyring)
	if err != nil {
		t.Fatal(err)
	}
	for _, diagnostic := range []string{fmt.Sprint(keyring), fmt.Sprintf("%#v", keyring), string(encoded)} {
		if !strings.Contains(diagnostic, "redacted") ||
			strings.Contains(diagnostic, active.key.ExportSecret()) ||
			strings.Contains(diagnostic, previous.key.ExportSecret()) {
			t.Fatalf("unsafe keyring diagnostic: %q", diagnostic)
		}
	}
}
