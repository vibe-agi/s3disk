package publisherstate

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestAESGCMProtectorRoundTripAndRandomizesEveryEnvelope(t *testing.T) {
	t.Parallel()

	protector := newTestProtector(t, "recovery-key-2026")
	binding := []byte("repository-id/share-id/share-state")
	plaintext := []byte("publisher private state including binary:\x00\xff")
	first, err := protector.Seal(context.Background(), binding, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	second, err := protector.Seal(context.Background(), binding, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two seals of the same plaintext produced an identical envelope")
	}
	if bytes.Contains(first, plaintext) || bytes.Contains(second, plaintext) {
		t.Fatal("sealed envelope contained plaintext")
	}
	for _, envelope := range [][]byte{first, second} {
		opened, err := protector.Open(context.Background(), binding, envelope)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(opened, plaintext) {
			t.Fatalf("Open = %q, want %q", opened, plaintext)
		}
	}
	if protector.KeyID() != "recovery-key-2026" {
		t.Fatalf("KeyID = %q", protector.KeyID())
	}
}

func TestAESGCMProtectorBindsKeyKeyIDAndCallerBinding(t *testing.T) {
	t.Parallel()

	key, err := GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	protector, err := NewAESGCMProtector("active-key", key)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := protector.Seal(context.Background(), []byte("share-A"), []byte("secret state"))
	if err != nil {
		t.Fatal(err)
	}

	wrongKey := newTestProtector(t, "active-key")
	wrongID, err := NewAESGCMProtector("different-key-id", key)
	if err != nil {
		t.Fatal(err)
	}
	for name, open := range map[string]func() error{
		"wrong recovery key": func() error {
			_, err := wrongKey.Open(context.Background(), []byte("share-A"), envelope)
			return err
		},
		"wrong key ID": func() error {
			_, err := wrongID.Open(context.Background(), []byte("share-A"), envelope)
			return err
		},
		"wrong caller binding": func() error {
			_, err := protector.Open(context.Background(), []byte("share-B"), envelope)
			return err
		},
	} {
		if err := open(); !errors.Is(err, ErrAuthenticationFailed) {
			t.Errorf("%s error = %v, want ErrAuthenticationFailed", name, err)
		}
	}
}

func TestAESGCMProtectorRejectsTamperingAndNonCanonicalEnvelopes(t *testing.T) {
	t.Parallel()

	protector := newTestProtector(t, "canonical-key")
	binding := []byte("canonical-binding")
	envelope, err := protector.Seal(context.Background(), binding, []byte("canonical plaintext"))
	if err != nil {
		t.Fatal(err)
	}

	tamperedSalt := append([]byte(nil), envelope...)
	saltOffset := envelopeHeaderBytes + len(protector.keyID)
	tamperedSalt[saltOffset] ^= 0x80
	tamperedCiphertext := append([]byte(nil), envelope...)
	tamperedCiphertext[len(tamperedCiphertext)-1] ^= 0x01
	tamperedKeyID := append([]byte(nil), envelope...)
	tamperedKeyID[envelopeHeaderBytes] = 'x'
	for name, candidate := range map[string][]byte{
		"salt": tamperedSalt, "ciphertext": tamperedCiphertext, "key ID": tamperedKeyID,
	} {
		if _, err := protector.Open(context.Background(), binding, candidate); !errors.Is(err, ErrAuthenticationFailed) {
			t.Errorf("tampered %s error = %v, want ErrAuthenticationFailed", name, err)
		}
	}

	badMagic := append([]byte(nil), envelope...)
	badMagic[0] ^= 0x01
	badVersion := append([]byte(nil), envelope...)
	binary.BigEndian.PutUint16(badVersion[envelopeVersionOffset:], envelopeFormatVersion+1)
	badReserved := append([]byte(nil), envelope...)
	binary.BigEndian.PutUint16(badReserved[envelopeReservedOffset:], 1)
	badSaltLength := append([]byte(nil), envelope...)
	binary.BigEndian.PutUint16(badSaltLength[envelopeSaltLengthOffset:], recoverySaltBytes-1)
	badCipherLength := append([]byte(nil), envelope...)
	binary.BigEndian.PutUint64(badCipherLength[envelopeCiphertextLengthOffset:], uint64(len(envelope)))
	withTrailingByte := append(append([]byte(nil), envelope...), 0)
	for name, candidate := range map[string][]byte{
		"magic": badMagic, "version": badVersion, "reserved": badReserved,
		"salt length": badSaltLength, "ciphertext length": badCipherLength,
		"trailing byte": withTrailingByte,
	} {
		if _, err := protector.Open(context.Background(), binding, candidate); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("non-canonical %s error = %v, want ErrInvalidEnvelope", name, err)
		}
	}
}

func TestAESGCMProtectorRejectsEveryTruncation(t *testing.T) {
	t.Parallel()

	protector := newTestProtector(t, "truncate-key")
	binding := []byte("truncate-binding")
	envelope, err := protector.Seal(context.Background(), binding, []byte("truncate this envelope"))
	if err != nil {
		t.Fatal(err)
	}
	for length := 0; length < len(envelope); length++ {
		if _, err := protector.Open(context.Background(), binding, envelope[:length]); err == nil {
			t.Fatalf("Open accepted envelope truncated to %d bytes", length)
		}
	}
}

func TestAESGCMProtectorBoundsInputsAndHonorsCancellation(t *testing.T) {
	protector := newTestProtector(t, "bounded-key")
	binding := []byte("bounded-binding")
	valid, err := protector.Seal(context.Background(), binding, []byte("valid"))
	if err != nil {
		t.Fatal(err)
	}

	oversized := make([]byte, MaximumEnvelopeBytes+1)
	if _, err := protector.Seal(context.Background(), binding, oversized[:MaximumPlaintextBytes+1]); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("oversized plaintext error = %v, want ErrResourceLimit", err)
	}
	if _, err := protector.Open(context.Background(), binding, oversized); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("oversized envelope error = %v, want ErrResourceLimit", err)
	}
	if _, err := protector.Seal(context.Background(), nil, []byte("value")); !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("empty binding error = %v, want ErrInvalidBinding", err)
	}
	if _, err := protector.Open(context.Background(), make([]byte, MaximumBindingBytes+1), valid); !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("oversized binding error = %v, want ErrInvalidBinding", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := protector.Seal(canceled, binding, []byte("secret")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Seal error = %v", err)
	}
	if _, err := protector.Open(canceled, binding, valid); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Open error = %v", err)
	}
	if _, err := protector.Seal(nil, binding, []byte("secret")); err == nil {
		t.Fatal("Seal accepted a nil context")
	}
	if _, err := protector.Open(nil, binding, valid); err == nil {
		t.Fatal("Open accepted a nil context")
	}
}

func TestAESGCMProtectorRejectsInvalidConfigurationWithoutSecretDiagnostics(t *testing.T) {
	t.Parallel()

	key, err := GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	secret := key.ExportSecret()
	for _, keyID := range []string{"", strings.Repeat("k", MaximumKeyIDBytes+1), "unsafe/key"} {
		if _, err := NewAESGCMProtector(keyID, key); !errors.Is(err, ErrInvalidKeyID) {
			t.Errorf("NewAESGCMProtector invalid key ID error = %v, want ErrInvalidKeyID", err)
		} else if strings.Contains(err.Error(), secret) {
			t.Error("protector configuration error exposed the recovery key")
		}
	}
	var zero RecoveryKey
	if _, err := NewAESGCMProtector("valid-key", zero); !errors.Is(err, ErrInvalidRecoveryKey) {
		t.Fatalf("zero recovery key error = %v, want ErrInvalidRecoveryKey", err)
	}
}

func TestAESGCMProtectorErrorsDoNotContainCallerSecrets(t *testing.T) {
	t.Parallel()

	protector := newTestProtector(t, "diagnostic-key")
	binding := []byte("private-caller-binding-value")
	plaintext := []byte("private-publisher-state-value")
	envelope, err := protector.Seal(context.Background(), binding, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	envelope[len(envelope)-1] ^= 1
	_, err = protector.Open(context.Background(), binding, envelope)
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("tampered envelope error = %v", err)
	}
	for _, secret := range [][]byte{binding, plaintext, []byte(protector.key.ExportSecret())} {
		if bytes.Contains([]byte(err.Error()), secret) {
			t.Fatal("authentication error contained caller secret material")
		}
	}
}

func FuzzAESGCMProtectorOpenNeverPanics(f *testing.F) {
	protector := newTestProtector(f, "fuzz-key")
	validBinding := []byte("fuzz-binding")
	validEnvelope, err := protector.Seal(context.Background(), validBinding, []byte("fuzz plaintext"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(validBinding, validEnvelope)
	f.Add([]byte{}, []byte{})
	f.Add([]byte("other-binding"), append([]byte(nil), validEnvelope...))

	f.Fuzz(func(t *testing.T, binding, envelope []byte) {
		plaintext, err := protector.Open(context.Background(), binding, envelope)
		if err == nil && len(plaintext) > MaximumPlaintextBytes {
			t.Fatalf("Open returned %d plaintext bytes", len(plaintext))
		}
	})
}

func newTestProtector(t testing.TB, keyID string) *AESGCMProtector {
	t.Helper()
	key, err := GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	protector, err := NewAESGCMProtector(keyID, key)
	if err != nil {
		t.Fatal(err)
	}
	return protector
}
