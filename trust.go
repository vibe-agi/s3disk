package s3disk

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	repositoryIDSize          = 32
	maxReferenceKeyIDBytes    = 128
	maxReferenceSignatureSize = 512
)

var signedReferenceDomain = []byte("s3disk\x00signed-reference\x00v1\x00")

// RepositoryID is a random, out-of-band identity used to prevent a valid
// signed reference from being replayed into another repository. It is not a
// secret and must be provisioned together with the trusted public keys.
type RepositoryID [repositoryIDSize]byte

// GenerateRepositoryID returns a cryptographically random repository identity.
func GenerateRepositoryID() (RepositoryID, error) {
	var id RepositoryID
	if _, err := rand.Read(id[:]); err != nil {
		return RepositoryID{}, fmt.Errorf("s3disk: generate repository ID: %w", err)
	}
	return id, nil
}

// ParseRepositoryID parses a hexadecimal repository identity.
func ParseRepositoryID(value string) (RepositoryID, error) {
	var id RepositoryID
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(id) {
		return RepositoryID{}, fmt.Errorf("s3disk: invalid repository ID %q", value)
	}
	copy(id[:], decoded)
	return id, nil
}

func (id RepositoryID) String() string { return hex.EncodeToString(id[:]) }

func (id RepositoryID) IsZero() bool { return id == RepositoryID{} }

func (id RepositoryID) MarshalJSON() ([]byte, error) { return json.Marshal(id.String()) }

func (id *RepositoryID) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	parsed, err := ParseRepositoryID(value)
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

// ReferenceSigner signs already-domain-separated canonical reference bytes.
// Implementations may delegate to an HSM or KMS. RepositoryID and KeyID must
// remain stable for the lifetime of a Publisher.
type ReferenceSigner interface {
	RepositoryID() RepositoryID
	KeyID() string
	Sign(ctx context.Context, message []byte) ([]byte, error)
}

// ReferenceVerifier verifies reference signatures against a caller-provisioned
// trust root. It must never discover trusted keys from the object store being
// verified.
type ReferenceVerifier interface {
	RepositoryID() RepositoryID
	Verify(ctx context.Context, keyID string, message, signature []byte) error
}

// Ed25519ReferenceSigner is the built-in in-process signing implementation.
type Ed25519ReferenceSigner struct {
	repositoryID RepositoryID
	keyID        string
	privateKey   ed25519.PrivateKey
}

func NewEd25519ReferenceSigner(repositoryID RepositoryID, keyID string, privateKey ed25519.PrivateKey) (*Ed25519ReferenceSigner, error) {
	if repositoryID.IsZero() {
		return nil, fmt.Errorf("s3disk: repository ID must not be zero")
	}
	if err := validateReferenceKeyID(keyID); err != nil {
		return nil, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("s3disk: invalid Ed25519 private key length")
	}
	return &Ed25519ReferenceSigner{
		repositoryID: repositoryID,
		keyID:        keyID,
		privateKey:   append(ed25519.PrivateKey(nil), privateKey...),
	}, nil
}

func (signer *Ed25519ReferenceSigner) RepositoryID() RepositoryID { return signer.repositoryID }

func (signer *Ed25519ReferenceSigner) KeyID() string { return signer.keyID }

func (signer *Ed25519ReferenceSigner) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return ed25519.Sign(signer.privateKey, message), nil
}

// Ed25519ReferenceVerifier verifies against a finite caller-managed keyring.
// Rotation is performed by provisioning an overlap keyring, switching the
// publisher signer, and removing the old key only after the retention window.
type Ed25519ReferenceVerifier struct {
	repositoryID RepositoryID
	publicKeys   map[string]ed25519.PublicKey
}

// IsOfflineReferenceVerifier reports whether verifier is exactly the built-in
// local Ed25519 implementation. It does not invoke verifier methods. An exact
// dynamic-type check is intentional: an exported marker interface could be
// embedded by an external wrapper which overrides Verify with a network
// callback while still satisfying that interface.
func IsOfflineReferenceVerifier(verifier ReferenceVerifier) bool {
	_, ok := verifier.(*Ed25519ReferenceVerifier)
	return ok
}

func NewEd25519ReferenceVerifier(repositoryID RepositoryID, publicKeys map[string]ed25519.PublicKey) (*Ed25519ReferenceVerifier, error) {
	if repositoryID.IsZero() {
		return nil, fmt.Errorf("s3disk: repository ID must not be zero")
	}
	if len(publicKeys) == 0 || len(publicKeys) > 1024 {
		return nil, fmt.Errorf("s3disk: Ed25519 keyring must contain between 1 and 1024 keys")
	}
	cloned := make(map[string]ed25519.PublicKey, len(publicKeys))
	for keyID, publicKey := range publicKeys {
		if err := validateReferenceKeyID(keyID); err != nil {
			return nil, err
		}
		if len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("s3disk: invalid Ed25519 public key length for %q", keyID)
		}
		cloned[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	return &Ed25519ReferenceVerifier{repositoryID: repositoryID, publicKeys: cloned}, nil
}

func (verifier *Ed25519ReferenceVerifier) RepositoryID() RepositoryID {
	return verifier.repositoryID
}

func (verifier *Ed25519ReferenceVerifier) Verify(ctx context.Context, keyID string, message, signature []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	publicKey, ok := verifier.publicKeys[keyID]
	if !ok {
		return fmt.Errorf("%w: unknown reference key %q", ErrUntrustedReference, keyID)
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, message, signature) {
		return fmt.Errorf("%w: invalid Ed25519 signature", ErrUntrustedReference)
	}
	return nil
}

type signedReferencePayload struct {
	Format       int          `json:"format"`
	RepositoryID RepositoryID `json:"repository_id"`
	Channel      string       `json:"channel"`
	Generation   uint64       `json:"generation"`
	Commit       Digest       `json:"commit"`
	KeyID        string       `json:"key_id"`
}

type signedReferenceEnvelope struct {
	Format    int                    `json:"format"`
	Reference signedReferencePayload `json:"reference"`
	Signature []byte                 `json:"signature"`
}

func signSnapshotReference(ctx context.Context, channel string, reference snapshotReference, signer ReferenceSigner, verifier ReferenceVerifier) ([]byte, error) {
	if signer == nil || verifier == nil || signer.RepositoryID().IsZero() || signer.RepositoryID() != verifier.RepositoryID() {
		return nil, fmt.Errorf("%w: mismatched reference signer and verifier", ErrUntrustedReference)
	}
	if err := validateReferenceKeyID(signer.KeyID()); err != nil {
		return nil, err
	}
	payload := signedReferencePayload{
		Format: objectFormatVersion, RepositoryID: signer.RepositoryID(),
		Channel: channel, Generation: reference.Generation, Commit: reference.Commit,
		KeyID: signer.KeyID(),
	}
	payloadData, err := canonicalJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("encode signed reference payload: %w", err)
	}
	message := referenceSigningMessage(payloadData)
	signature, err := signer.Sign(ctx, message)
	if err != nil {
		return nil, fmt.Errorf("sign snapshot reference: %w", err)
	}
	if len(signature) == 0 || len(signature) > maxReferenceSignatureSize {
		return nil, fmt.Errorf("%w: invalid reference signature length", ErrUntrustedReference)
	}
	// Verify what will be published. This catches a misconfigured HSM/keyring
	// before an otherwise irreversible signed history update is attempted.
	if err := verifier.Verify(ctx, payload.KeyID, message, signature); err != nil {
		return nil, fmt.Errorf("verify publisher reference signature: %w", err)
	}
	return canonicalJSON(signedReferenceEnvelope{
		Format: objectFormatVersion, Reference: payload, Signature: signature,
	})
}

func verifySignedSnapshotReference(ctx context.Context, data []byte, channel string, verifier ReferenceVerifier) (snapshotReference, error) {
	if verifier == nil || verifier.RepositoryID().IsZero() {
		return snapshotReference{}, fmt.Errorf("%w: missing reference verifier", ErrUntrustedReference)
	}
	var envelope signedReferenceEnvelope
	if err := decodeJSON(data, &envelope); err != nil {
		return snapshotReference{}, fmt.Errorf("%w: %w", ErrInvalidReference, err)
	}
	payload := envelope.Reference
	if envelope.Format != objectFormatVersion || payload.Format != objectFormatVersion ||
		payload.RepositoryID != verifier.RepositoryID() || payload.Channel != channel ||
		payload.Generation == 0 || payload.Commit.IsZero() || len(envelope.Signature) == 0 ||
		len(envelope.Signature) > maxReferenceSignatureSize {
		return snapshotReference{}, fmt.Errorf("%w: %w: signed reference context mismatch", ErrInvalidReference, ErrUntrustedReference)
	}
	if err := validateReferenceKeyID(payload.KeyID); err != nil {
		return snapshotReference{}, fmt.Errorf("%w: %w", ErrInvalidReference, err)
	}
	payloadData, err := canonicalJSON(payload)
	if err != nil {
		return snapshotReference{}, fmt.Errorf("%w: encode signed payload: %v", ErrInvalidReference, err)
	}
	if err := verifier.Verify(ctx, payload.KeyID, referenceSigningMessage(payloadData), envelope.Signature); err != nil {
		return snapshotReference{}, fmt.Errorf("%w: %w", ErrInvalidReference, err)
	}
	return snapshotReference{
		Format: payload.Format, Generation: payload.Generation, Commit: payload.Commit,
	}, nil
}

func referenceSigningMessage(payload []byte) []byte {
	message := make([]byte, 0, len(signedReferenceDomain)+8+len(payload))
	message = append(message, signedReferenceDomain...)
	message = binary.BigEndian.AppendUint64(message, uint64(len(payload)))
	return append(message, payload...)
}

func validateReferenceKeyID(keyID string) error {
	if keyID == "" || len(keyID) > maxReferenceKeyIDBytes {
		return fmt.Errorf("%w: invalid reference key ID", ErrUntrustedReference)
	}
	for _, character := range keyID {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-", character) {
			return fmt.Errorf("%w: invalid reference key ID", ErrUntrustedReference)
		}
	}
	return nil
}

var (
	_ ReferenceSigner   = (*Ed25519ReferenceSigner)(nil)
	_ ReferenceVerifier = (*Ed25519ReferenceVerifier)(nil)
)
