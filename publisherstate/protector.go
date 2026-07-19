package publisherstate

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

const (
	// MaximumKeyIDBytes bounds the non-secret key selector embedded in an
	// envelope. Key IDs use a deliberately small portable character set.
	MaximumKeyIDBytes = 128
	// MaximumBindingBytes bounds caller-controlled authenticated context. The
	// binding is not stored in the envelope and must be supplied again to Open.
	MaximumBindingBytes = 4 << 10
	// MaximumPlaintextBytes permits the largest current flat share root while
	// keeping all cryptographic allocation finite.
	MaximumPlaintextBytes = 64 << 20

	recoverySaltBytes              = 16
	randomNonceBytes               = 12
	gcmTagBytes                    = 16
	randomNonceGCMOverhead         = randomNonceBytes + gcmTagBytes
	envelopeFormatVersion          = uint16(1)
	envelopeMagicBytes             = 8
	envelopeVersionOffset          = envelopeMagicBytes
	envelopeReservedOffset         = envelopeVersionOffset + 2
	envelopeKeyIDLengthOffset      = envelopeReservedOffset + 2
	envelopeSaltLengthOffset       = envelopeKeyIDLengthOffset + 2
	envelopeCiphertextLengthOffset = envelopeSaltLengthOffset + 2
	envelopeHeaderBytes            = envelopeCiphertextLengthOffset + 8

	// MaximumEnvelopeBytes is the largest encoded envelope accepted by Open.
	MaximumEnvelopeBytes = envelopeHeaderBytes + MaximumKeyIDBytes + recoverySaltBytes + MaximumPlaintextBytes + randomNonceGCMOverhead
)

var (
	envelopeMagic = [envelopeMagicBytes]byte{'s', '3', 'd', 'p', 's', 0, 1, 0}
	kdfDomain     = []byte("s3disk\x00publisher-state\x00recovery-kdf\x00v1\x00")
	aadDomain     = []byte("s3disk\x00publisher-state\x00envelope-aad\x00v1\x00")
)

// Protector seals and opens bounded publisher-state values. Callers must use a
// stable, non-secret KeyID and must construct a non-empty binding containing the
// state role and durable share/repository identities.
type Protector interface {
	KeyID() string
	Seal(ctx context.Context, binding, plaintext []byte) ([]byte, error)
	Open(ctx context.Context, binding, envelope []byte) ([]byte, error)
}

// AESGCMProtector is the built-in Protector using HKDF-SHA256 and AES-256-GCM.
// Each Seal generates a new 16-byte KDF salt and a new random GCM nonce.
type AESGCMProtector struct {
	keyID string
	key   RecoveryKey
}

// NewAESGCMProtector validates configuration without performing I/O.
func NewAESGCMProtector(keyID string, key RecoveryKey) (*AESGCMProtector, error) {
	if !validKeyID(keyID) {
		return nil, ErrInvalidKeyID
	}
	if !key.configured() {
		return nil, ErrInvalidRecoveryKey
	}
	return &AESGCMProtector{keyID: keyID, key: key}, nil
}

func (protector *AESGCMProtector) KeyID() string {
	if protector == nil {
		return ""
	}
	return protector.keyID
}

// Seal encrypts and authenticates plaintext for exactly binding.
func (protector *AESGCMProtector) Seal(ctx context.Context, binding, plaintext []byte) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("publisherstate: Seal context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !protector.configured() {
		return nil, ErrProtectorUnavailable
	}
	if err := validateBinding(binding); err != nil {
		return nil, err
	}
	if len(plaintext) > MaximumPlaintextBytes {
		return nil, fmt.Errorf("%w: plaintext is too large", ErrResourceLimit)
	}

	var salt [recoverySaltBytes]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, fmt.Errorf("publisherstate: generate envelope salt: %w", err)
	}
	aead, err := protector.aead(salt[:])
	if err != nil {
		return nil, err
	}
	if aead.NonceSize() != 0 || aead.Overhead() != randomNonceGCMOverhead {
		return nil, fmt.Errorf("publisherstate: unexpected AES-GCM construction")
	}
	ciphertextLength := len(plaintext) + aead.Overhead()
	prefix := encodeEnvelopePrefix(protector.keyID, salt[:], ciphertextLength)
	aad := envelopeAssociatedData(prefix, binding)
	ciphertext := aead.Seal(nil, nil, plaintext, aad)
	clear(aad)
	if len(ciphertext) != ciphertextLength {
		clear(ciphertext)
		return nil, fmt.Errorf("publisherstate: unexpected AES-GCM output length")
	}
	if err := ctx.Err(); err != nil {
		clear(ciphertext)
		return nil, err
	}
	envelope := make([]byte, 0, len(prefix)+len(ciphertext))
	envelope = append(envelope, prefix...)
	envelope = append(envelope, ciphertext...)
	clear(ciphertext)
	return envelope, nil
}

// Open authenticates envelope for exactly binding and returns independently
// owned plaintext. Wrong keys, key IDs, or bindings share one failure class.
func (protector *AESGCMProtector) Open(ctx context.Context, binding, envelope []byte) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("publisherstate: Open context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !protector.configured() {
		return nil, ErrProtectorUnavailable
	}
	if err := validateBinding(binding); err != nil {
		return nil, err
	}
	if len(envelope) > MaximumEnvelopeBytes {
		return nil, fmt.Errorf("%w: envelope is too large", ErrResourceLimit)
	}
	parsed, err := parseEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	if len(parsed.keyID) != len(protector.keyID) ||
		subtle.ConstantTimeCompare([]byte(parsed.keyID), []byte(protector.keyID)) != 1 {
		return nil, ErrAuthenticationFailed
	}
	aead, err := protector.aead(parsed.salt)
	if err != nil {
		return nil, err
	}
	aad := envelopeAssociatedData(parsed.prefix, binding)
	plaintext, err := aead.Open(nil, nil, parsed.ciphertext, aad)
	clear(aad)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	if len(plaintext) > MaximumPlaintextBytes {
		clear(plaintext)
		return nil, fmt.Errorf("%w: plaintext is too large", ErrResourceLimit)
	}
	if err := ctx.Err(); err != nil {
		clear(plaintext)
		return nil, err
	}
	return plaintext, nil
}

func (protector *AESGCMProtector) configured() bool {
	return protector != nil && validKeyID(protector.keyID) && protector.key.configured()
}

func (protector *AESGCMProtector) aead(salt []byte) (cipher.AEAD, error) {
	info := kdfInfo(protector.keyID)
	material, err := hkdf.Key(sha256.New, protector.key.material[:], salt, string(info), RecoveryKeyBytes)
	clear(info)
	if err != nil {
		return nil, fmt.Errorf("publisherstate: derive envelope key: %w", err)
	}
	defer clear(material)
	block, err := aes.NewCipher(material)
	if err != nil {
		return nil, fmt.Errorf("publisherstate: initialize AES: %w", err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("publisherstate: initialize AES-GCM: %w", err)
	}
	return aead, nil
}

func (protector AESGCMProtector) String() string {
	return fmt.Sprintf("publisherstate.AESGCMProtector{configured:%t,secrets:redacted}", protector.configured())
}

func (protector AESGCMProtector) GoString() string { return protector.String() }

func (protector AESGCMProtector) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Configured bool   `json:"configured"`
		Secrets    string `json:"secrets"`
	}{Configured: protector.configured(), Secrets: "redacted"})
}

type decodedEnvelope struct {
	keyID      string
	salt       []byte
	prefix     []byte
	ciphertext []byte
}

func parseEnvelope(envelope []byte) (decodedEnvelope, error) {
	minimum := envelopeHeaderBytes + 1 + recoverySaltBytes + randomNonceGCMOverhead
	if len(envelope) < minimum {
		return decodedEnvelope{}, ErrInvalidEnvelope
	}
	if !bytes.Equal(envelope[:envelopeMagicBytes], envelopeMagic[:]) ||
		binary.BigEndian.Uint16(envelope[envelopeVersionOffset:]) != envelopeFormatVersion ||
		binary.BigEndian.Uint16(envelope[envelopeReservedOffset:]) != 0 {
		return decodedEnvelope{}, ErrInvalidEnvelope
	}
	keyIDLength := int(binary.BigEndian.Uint16(envelope[envelopeKeyIDLengthOffset:]))
	saltLength := int(binary.BigEndian.Uint16(envelope[envelopeSaltLengthOffset:]))
	ciphertextLength := binary.BigEndian.Uint64(envelope[envelopeCiphertextLengthOffset:])
	if keyIDLength < 1 || keyIDLength > MaximumKeyIDBytes || saltLength != recoverySaltBytes ||
		ciphertextLength < randomNonceGCMOverhead || ciphertextLength > uint64(MaximumPlaintextBytes+randomNonceGCMOverhead) {
		return decodedEnvelope{}, ErrInvalidEnvelope
	}
	prefixLength := envelopeHeaderBytes + keyIDLength + saltLength
	if prefixLength > len(envelope) || uint64(len(envelope)-prefixLength) != ciphertextLength {
		return decodedEnvelope{}, ErrInvalidEnvelope
	}
	keyID := string(envelope[envelopeHeaderBytes : envelopeHeaderBytes+keyIDLength])
	if !validKeyID(keyID) {
		return decodedEnvelope{}, ErrInvalidEnvelope
	}
	saltStart := envelopeHeaderBytes + keyIDLength
	salt := envelope[saltStart:prefixLength]
	canonical := encodeEnvelopePrefix(keyID, salt, int(ciphertextLength))
	if !bytes.Equal(canonical, envelope[:prefixLength]) {
		return decodedEnvelope{}, ErrInvalidEnvelope
	}
	return decodedEnvelope{
		keyID: keyID, salt: salt, prefix: envelope[:prefixLength], ciphertext: envelope[prefixLength:],
	}, nil
}

func encodeEnvelopePrefix(keyID string, salt []byte, ciphertextLength int) []byte {
	prefix := make([]byte, envelopeHeaderBytes+len(keyID)+len(salt))
	copy(prefix[:envelopeMagicBytes], envelopeMagic[:])
	binary.BigEndian.PutUint16(prefix[envelopeVersionOffset:], envelopeFormatVersion)
	// Reserved bytes are already canonical zero.
	binary.BigEndian.PutUint16(prefix[envelopeKeyIDLengthOffset:], uint16(len(keyID)))
	binary.BigEndian.PutUint16(prefix[envelopeSaltLengthOffset:], uint16(len(salt)))
	binary.BigEndian.PutUint64(prefix[envelopeCiphertextLengthOffset:], uint64(ciphertextLength))
	copy(prefix[envelopeHeaderBytes:], keyID)
	copy(prefix[envelopeHeaderBytes+len(keyID):], salt)
	return prefix
}

func envelopeAssociatedData(prefix, binding []byte) []byte {
	aad := make([]byte, 0, len(aadDomain)+8+len(prefix)+len(binding))
	aad = append(aad, aadDomain...)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(prefix)))
	aad = append(aad, length[:]...)
	aad = append(aad, prefix...)
	binary.BigEndian.PutUint32(length[:], uint32(len(binding)))
	aad = append(aad, length[:]...)
	aad = append(aad, binding...)
	return aad
}

func kdfInfo(keyID string) []byte {
	info := make([]byte, 0, len(kdfDomain)+4+len(keyID))
	info = append(info, kdfDomain...)
	var version [2]byte
	binary.BigEndian.PutUint16(version[:], envelopeFormatVersion)
	info = append(info, version[:]...)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(keyID)))
	info = append(info, length[:]...)
	info = append(info, keyID...)
	return info
}

func validateBinding(binding []byte) error {
	if len(binding) < 1 || len(binding) > MaximumBindingBytes {
		return ErrInvalidBinding
	}
	return nil
}

func validKeyID(keyID string) bool {
	if len(keyID) < 1 || len(keyID) > MaximumKeyIDBytes {
		return false
	}
	for index := 0; index < len(keyID); index++ {
		character := keyID[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' ||
			character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}

var _ Protector = (*AESGCMProtector)(nil)
