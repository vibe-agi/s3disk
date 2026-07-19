package s3disk

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	clientEncryptionKeyBytes  = 32
	clientEncryptionSaltBytes = 16

	// ClientEncryptionMaxPlaintextBytes is the largest plaintext accepted by
	// the built-in client-side encryption profile. It matches the protocol's
	// largest object and keeps decrypt-before-validate allocation finite.
	ClientEncryptionMaxPlaintextBytes int64 = 64 << 20

	// ClientEncryptionCiphertextOverhead is the fixed expansion added by the
	// current envelope: an eight-byte format header, a random per-message KDF
	// salt, and AES-GCM's random nonce and authentication tag.
	ClientEncryptionCiphertextOverhead int64 = 8 + clientEncryptionSaltBytes + 12 + 16
)

const clientEncryptionSecretPrefix = "s3disk-client-encryption-v1."

var (
	clientEncryptionEnvelopeHeader = [8]byte{'s', '3', 'd', 'c', 'e', 0, 1, 0}
	clientEncryptionMasterDomain   = []byte("s3disk\x00client-encryption\x00master\x00v1\x00")
	clientEncryptionIndexDomain    = []byte("s3disk\x00client-encryption\x00index\x00v1\x00")
	clientEncryptionObjectDomain   = []byte("s3disk\x00client-encryption\x00object\x00v1\x00")
	clientEncryptionClosureDomain  = []byte("s3disk\x00client-encryption\x00snapshot-closure\x00v1\x00")
)

// ClientEncryptionKey is a random, per-share 256-bit secret. It is a value
// type so ordinary assignment makes an independent copy of the key material.
// String, GoString, and JSON diagnostics are deliberately redacted; callers
// must opt in to secret handling through ExportSecret.
type ClientEncryptionKey struct {
	material [clientEncryptionKeyBytes]byte
}

// GenerateClientEncryptionKey creates a new per-share encryption key from the
// operating system's cryptographic random source.
func GenerateClientEncryptionKey() (ClientEncryptionKey, error) {
	var key ClientEncryptionKey
	if _, err := rand.Read(key.material[:]); err != nil {
		return ClientEncryptionKey{}, fmt.Errorf("s3disk: generate client encryption key: %w", err)
	}
	if key.isZero() {
		return ClientEncryptionKey{}, fmt.Errorf("s3disk: cryptographic random source returned an invalid client encryption key")
	}
	return key, nil
}

// ParseClientEncryptionKey parses the canonical secret produced by
// ExportSecret. Parse failures never include the supplied secret.
func ParseClientEncryptionKey(secret string) (ClientEncryptionKey, error) {
	if !strings.HasPrefix(secret, clientEncryptionSecretPrefix) {
		return ClientEncryptionKey{}, fmt.Errorf("s3disk: invalid client encryption key")
	}
	encoded := strings.TrimPrefix(secret, clientEncryptionSecretPrefix)
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != clientEncryptionKeyBytes || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return ClientEncryptionKey{}, fmt.Errorf("s3disk: invalid client encryption key")
	}
	var key ClientEncryptionKey
	copy(key.material[:], decoded)
	if key.isZero() {
		return ClientEncryptionKey{}, fmt.Errorf("s3disk: invalid client encryption key")
	}
	return key, nil
}

// ExportSecret returns the canonical handoff representation of the key. It is
// the only API on ClientEncryptionKey which intentionally reveals the secret.
func (key ClientEncryptionKey) ExportSecret() string {
	if key.isZero() {
		return ""
	}
	return clientEncryptionSecretPrefix + base64.RawURLEncoding.EncodeToString(key.material[:])
}

func (key ClientEncryptionKey) isZero() bool {
	var zero [clientEncryptionKeyBytes]byte
	return subtle.ConstantTimeCompare(key.material[:], zero[:]) == 1
}

func (key ClientEncryptionKey) String() string {
	return fmt.Sprintf("s3disk.ClientEncryptionKey{configured:%t,secrets:redacted}", !key.isZero())
}

func (key ClientEncryptionKey) GoString() string { return key.String() }

func (key ClientEncryptionKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Configured bool   `json:"configured"`
		Secrets    string `json:"secrets"`
	}{
		Configured: !key.isZero(),
		Secrets:    "redacted",
	})
}

// ClientEncryptionProfile is the built-in strict-share-isolation encryption
// profile. A profile is bound to one repository identity and one per-share
// key. Reusing it under a dedicated random repository prefix preserves lazy
// loading and within-share deduplication without exposing plaintext digests or
// equality across independently keyed shares.
type ClientEncryptionProfile struct {
	repositoryID     RepositoryID
	encryptionMaster [clientEncryptionKeyBytes]byte
	indexKey         [clientEncryptionKeyBytes]byte
}

// NewClientEncryptionProfile derives independent encryption and opaque-index
// keys for one repository identity. The supplied per-share key is not retained.
func NewClientEncryptionProfile(repositoryID RepositoryID, key ClientEncryptionKey) (*ClientEncryptionProfile, error) {
	if repositoryID.IsZero() {
		return nil, fmt.Errorf("s3disk: repository ID must not be zero")
	}
	if key.isZero() {
		return nil, fmt.Errorf("s3disk: client encryption key must not be zero")
	}
	encryptionMaster, err := hkdf.Key(sha256.New, key.material[:], repositoryID[:], string(clientEncryptionMasterDomain), clientEncryptionKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("s3disk: derive client encryption master: %w", err)
	}
	indexKey, err := hkdf.Key(sha256.New, key.material[:], repositoryID[:], string(clientEncryptionIndexDomain), clientEncryptionKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("s3disk: derive client encryption index: %w", err)
	}
	profile := &ClientEncryptionProfile{repositoryID: repositoryID}
	copy(profile.encryptionMaster[:], encryptionMaster)
	copy(profile.indexKey[:], indexKey)
	return profile, nil
}

// RepositoryID returns the public repository identity bound into every
// ciphertext. It is not secret.
func (profile *ClientEncryptionProfile) RepositoryID() RepositoryID {
	if profile == nil {
		return RepositoryID{}
	}
	return profile.repositoryID
}

// Equivalent reports whether two profiles contain the same derived
// repository and share-key configuration. It reveals no key bytes.
func (profile *ClientEncryptionProfile) Equivalent(other *ClientEncryptionProfile) bool {
	if !profile.configured() || !other.configured() || profile.repositoryID != other.repositoryID {
		return false
	}
	return subtle.ConstantTimeCompare(profile.encryptionMaster[:], other.encryptionMaster[:]) == 1 &&
		subtle.ConstantTimeCompare(profile.indexKey[:], other.indexKey[:]) == 1
}

func (profile *ClientEncryptionProfile) configured() bool {
	if profile == nil || profile.repositoryID.IsZero() {
		return false
	}
	var zero [clientEncryptionKeyBytes]byte
	return subtle.ConstantTimeCompare(profile.encryptionMaster[:], zero[:]) != 1 &&
		subtle.ConstantTimeCompare(profile.indexKey[:], zero[:]) != 1
}

func validateClientEncryptionObjectKey(objectKey string) error {
	if objectKey == "" || len(objectKey) > maxObjectKeyBytes || !utf8.ValidString(objectKey) || strings.ContainsRune(objectKey, '\x00') {
		return fmt.Errorf("%w: invalid encrypted object key", ErrInvalidPath)
	}
	return nil
}

func (profile *ClientEncryptionProfile) objectAEAD(objectKey string, messageSalt []byte) (cipher.AEAD, error) {
	if !profile.configured() {
		return nil, fmt.Errorf("s3disk: client encryption profile is not configured")
	}
	if err := validateClientEncryptionObjectKey(objectKey); err != nil {
		return nil, err
	}
	if len(messageSalt) != clientEncryptionSaltBytes {
		return nil, fmt.Errorf("s3disk: invalid client encryption message salt")
	}
	keyInfo := profile.objectAssociatedData(objectKey, messageSalt)
	objectKeyMaterial, err := hkdf.Key(
		sha256.New,
		profile.encryptionMaster[:],
		messageSalt,
		string(keyInfo),
		clientEncryptionKeyBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("s3disk: derive encrypted object key: %w", err)
	}
	block, err := aes.NewCipher(objectKeyMaterial)
	if err != nil {
		return nil, fmt.Errorf("s3disk: initialize object encryption: %w", err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("s3disk: initialize object encryption: %w", err)
	}
	return aead, nil
}

func (profile *ClientEncryptionProfile) objectAssociatedData(objectKey string, messageSalt []byte) []byte {
	associatedData := make([]byte, 0, len(clientEncryptionObjectDomain)+len(profile.repositoryID)+4+len(objectKey)+len(messageSalt))
	associatedData = append(associatedData, clientEncryptionObjectDomain...)
	associatedData = append(associatedData, profile.repositoryID[:]...)
	associatedData = append(associatedData, messageSalt...)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(objectKey)))
	associatedData = append(associatedData, length[:]...)
	associatedData = append(associatedData, objectKey...)
	return associatedData
}

// SealObject encrypts and authenticates one logical object with a fresh random
// nonce. The object key and repository identity are authenticated associated
// data and therefore cannot be substituted without detection.
func (profile *ClientEncryptionProfile) SealObject(objectKey string, plaintext []byte) ([]byte, error) {
	if int64(len(plaintext)) > ClientEncryptionMaxPlaintextBytes {
		return nil, fmt.Errorf("%w: encrypted plaintext exceeds %d bytes", ErrResourceLimit, ClientEncryptionMaxPlaintextBytes)
	}
	messageSalt := make([]byte, clientEncryptionSaltBytes)
	if _, err := rand.Read(messageSalt); err != nil {
		return nil, fmt.Errorf("s3disk: generate client encryption message salt: %w", err)
	}
	aead, err := profile.objectAEAD(objectKey, messageSalt)
	if err != nil {
		return nil, err
	}
	envelope := make([]byte, 0, int64(len(plaintext))+ClientEncryptionCiphertextOverhead)
	envelope = append(envelope, clientEncryptionEnvelopeHeader[:]...)
	envelope = append(envelope, messageSalt...)
	envelope = aead.Seal(envelope, nil, plaintext, profile.objectAssociatedData(objectKey, messageSalt))
	return envelope, nil
}

// OpenObject authenticates and decrypts one current-format object envelope.
// Authentication, format, key, and binding failures are intentionally
// collapsed into ErrCorruptObject without exposing secret material.
func (profile *ClientEncryptionProfile) OpenObject(objectKey string, envelope []byte) ([]byte, error) {
	if int64(len(envelope)) > ClientEncryptionMaxPlaintextBytes+ClientEncryptionCiphertextOverhead {
		return nil, fmt.Errorf("%w: encrypted object exceeds the ciphertext limit", ErrResourceLimit)
	}
	if len(envelope) < int(ClientEncryptionCiphertextOverhead) ||
		subtle.ConstantTimeCompare(envelope[:len(clientEncryptionEnvelopeHeader)], clientEncryptionEnvelopeHeader[:]) != 1 {
		return nil, fmt.Errorf("%w: invalid client encryption envelope", ErrCorruptObject)
	}
	saltStart := len(clientEncryptionEnvelopeHeader)
	saltEnd := saltStart + clientEncryptionSaltBytes
	messageSalt := envelope[saltStart:saltEnd]
	aead, err := profile.objectAEAD(objectKey, messageSalt)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nil, envelope[saltEnd:], profile.objectAssociatedData(objectKey, messageSalt))
	if err != nil {
		return nil, fmt.Errorf("%w: client encryption authentication failed", ErrCorruptObject)
	}
	if int64(len(plaintext)) > ClientEncryptionMaxPlaintextBytes {
		return nil, fmt.Errorf("%w: decrypted object exceeds %d bytes", ErrResourceLimit, ClientEncryptionMaxPlaintextBytes)
	}
	return plaintext, nil
}

func (profile *ClientEncryptionProfile) opaqueObjectID(kind string, digest Digest) string {
	mac := hmac.New(sha256.New, profile.indexKey[:])
	_, _ = mac.Write(clientEncryptionIndexDomain)
	_, _ = mac.Write([]byte(kind))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(digest[:])
	return hex.EncodeToString(mac.Sum(nil))
}

func (profile *ClientEncryptionProfile) snapshotClosureBinding() [sha256.Size]byte {
	if !profile.configured() {
		return [sha256.Size]byte{}
	}
	mac := hmac.New(sha256.New, profile.encryptionMaster[:])
	_, _ = mac.Write(clientEncryptionClosureDomain)
	_, _ = mac.Write(profile.repositoryID[:])
	_, _ = mac.Write(profile.indexKey[:])
	var binding [sha256.Size]byte
	copy(binding[:], mac.Sum(nil))
	return binding
}

func (profile ClientEncryptionProfile) String() string {
	return fmt.Sprintf("s3disk.ClientEncryptionProfile{configured:%t,secrets:redacted}", profile.configured())
}

func (profile ClientEncryptionProfile) GoString() string { return profile.String() }

func (profile ClientEncryptionProfile) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Configured bool   `json:"configured"`
		Profile    string `json:"profile"`
		Secrets    string `json:"secrets"`
	}{
		Configured: profile.configured(),
		Profile:    "strict-share-isolation-v1",
		Secrets:    "redacted",
	})
}

type clientEncryptedObjectReader struct {
	reader  ObjectReader
	profile *ClientEncryptionProfile
}

type clientEncryptionAppliedReader interface {
	ClientEncryptionApplied(*ClientEncryptionProfile) bool
}

func clientEncryptionAlreadyApplied(reader ObjectReader, profile *ClientEncryptionProfile) bool {
	applied, ok := reader.(clientEncryptionAppliedReader)
	return ok && applied.ClientEncryptionApplied(profile)
}

func builtInClientEncryptionWrapper(reader ObjectReader) bool {
	switch reader.(type) {
	case *ClientEncryptedStore, *clientEncryptedObjectReader:
		return true
	default:
		return false
	}
}

func newClientEncryptedObjectReader(reader ObjectReader, profile *ClientEncryptionProfile) (*clientEncryptedObjectReader, error) {
	if reader == nil {
		return nil, fmt.Errorf("s3disk: nil object reader")
	}
	if !interfaceDependencyConfigured(reader) {
		return nil, fmt.Errorf("s3disk: object reader must not be a typed nil")
	}
	if !profile.configured() {
		return nil, fmt.Errorf("s3disk: client encryption profile is not configured")
	}
	return &clientEncryptedObjectReader{reader: reader, profile: profile}, nil
}

func (reader *clientEncryptedObjectReader) Get(ctx context.Context, objectKey string, options GetOptions) (Object, error) {
	if err := ctx.Err(); err != nil {
		return Object{}, err
	}
	if options.MaxBytes < 0 {
		return Object{}, fmt.Errorf("%w: negative plaintext read limit", ErrResourceLimit)
	}
	plaintextLimit := options.MaxBytes
	if plaintextLimit == 0 || plaintextLimit > ClientEncryptionMaxPlaintextBytes {
		plaintextLimit = ClientEncryptionMaxPlaintextBytes
	}
	object, err := reader.reader.Get(ctx, objectKey, GetOptions{
		IfNoneMatch: options.IfNoneMatch,
		MaxBytes:    plaintextLimit + ClientEncryptionCiphertextOverhead,
	})
	if err != nil {
		return Object{}, err
	}
	plaintext, err := reader.profile.OpenObject(objectKey, object.Data)
	if err != nil {
		return Object{}, err
	}
	if options.MaxBytes > 0 && int64(len(plaintext)) > options.MaxBytes {
		return Object{}, fmt.Errorf("%w: plaintext object exceeds %d bytes", ErrResourceLimit, options.MaxBytes)
	}
	if err := ctx.Err(); err != nil {
		return Object{}, err
	}
	return Object{Data: plaintext, Version: object.Version}, nil
}

// ClientEncryptedStore applies client-side authenticated encryption to every
// object body while preserving the backing Store's keys, versions, CAS
// semantics, and conditional reads. It intentionally does not implement
// ObjectDeleter: optional delete authority is not widened by this wrapper.
type ClientEncryptedStore struct {
	*clientEncryptedObjectReader
	store Store
}

// NewClientEncryptedStore wraps a writable Store with the current client-side
// encryption profile.
func NewClientEncryptedStore(store Store, profile *ClientEncryptionProfile) (*ClientEncryptedStore, error) {
	if store == nil {
		return nil, fmt.Errorf("s3disk: nil store")
	}
	if !interfaceDependencyConfigured(store) {
		return nil, fmt.Errorf("s3disk: store must not be a typed nil")
	}
	// Writable encryption can only be elided for this package's concrete,
	// audited wrapper. Store interfaces are structural in Go; trusting an
	// arbitrary external ClientEncryptionApplied method here would let a custom
	// Store silently bypass encryption while RepositoryOptions still requested it.
	if existing, ok := store.(*ClientEncryptedStore); ok {
		if existing.ClientEncryptionApplied(profile) {
			return existing, nil
		}
		return nil, fmt.Errorf("%w: store already applies a different client encryption profile", ErrStoreMisconfigured)
	}
	reader, err := newClientEncryptedObjectReader(store, profile)
	if err != nil {
		return nil, err
	}
	return &ClientEncryptedStore{clientEncryptedObjectReader: reader, store: store}, nil
}

// ClientEncryptionApplied lets repository construction avoid accidentally
// wrapping an already encrypted data boundary a second time.
func (store *ClientEncryptedStore) ClientEncryptionApplied(profile *ClientEncryptionProfile) bool {
	return store != nil && store.clientEncryptedObjectReader != nil && store.profile.Equivalent(profile)
}

func (store *ClientEncryptedStore) Head(ctx context.Context, objectKey string) (Version, error) {
	return store.store.Head(ctx, objectKey)
}

func (store *ClientEncryptedStore) PutIfAbsent(ctx context.Context, objectKey string, plaintext []byte) (Version, error) {
	if err := ctx.Err(); err != nil {
		return Version{}, err
	}
	envelope, err := store.profile.SealObject(objectKey, plaintext)
	if err != nil {
		return Version{}, err
	}
	if err := ctx.Err(); err != nil {
		return Version{}, err
	}
	return store.store.PutIfAbsent(ctx, objectKey, envelope)
}

func (store *ClientEncryptedStore) CompareAndSwap(ctx context.Context, objectKey string, expected *Version, plaintext []byte) (Version, error) {
	if err := ctx.Err(); err != nil {
		return Version{}, err
	}
	envelope, err := store.profile.SealObject(objectKey, plaintext)
	if err != nil {
		return Version{}, err
	}
	if err := ctx.Err(); err != nil {
		return Version{}, err
	}
	return store.store.CompareAndSwap(ctx, objectKey, expected, envelope)
}

func (store ClientEncryptedStore) String() string {
	configured := store.store != nil && store.clientEncryptedObjectReader != nil && store.profile.configured()
	return fmt.Sprintf("s3disk.ClientEncryptedStore{configured:%t,secrets:redacted}", configured)
}

func (store ClientEncryptedStore) GoString() string { return store.String() }

func (store ClientEncryptedStore) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Configured bool   `json:"configured"`
		Secrets    string `json:"secrets"`
	}{
		Configured: store.store != nil && store.clientEncryptedObjectReader != nil && store.profile.configured(),
		Secrets:    "redacted",
	})
}

var _ Store = (*ClientEncryptedStore)(nil)
