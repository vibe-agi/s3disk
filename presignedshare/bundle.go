package presignedshare

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vibe-agi/s3disk"
)

const (
	BundleFormat               = 1
	MaximumBundleBytes         = 64 << 20
	MaximumBundleCapabilities  = 65_536
	maximumReferenceBytes      = 4 << 10
	maximumObjectKeyBytes      = 1024
	maximumShareSignatureBytes = 512
	maximumShareKeyIDBytes     = 128
	repositoryNamespace        = ".s3disk/v1"
)

var (
	ErrInvalidBundle    = errors.New("presignedshare: invalid bundle")
	ErrUntrustedBundle  = errors.New("presignedshare: untrusted bundle")
	bundleSigningDomain = []byte("s3disk\x00presigned-share-bundle\x00v1\x00")
)

// ShareID is a random, non-secret identity provisioned with the root
// capability. It prevents a signed bundle for one share from being replayed
// through another share rooted in the same repository.
type ShareID [16]byte

func GenerateShareID() (ShareID, error) {
	var identifier ShareID
	if _, err := rand.Read(identifier[:]); err != nil {
		return ShareID{}, fmt.Errorf("presignedshare: generate share ID: %w", err)
	}
	return identifier, nil
}

func ParseShareID(value string) (ShareID, error) {
	var identifier ShareID
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != len(identifier) {
		return ShareID{}, fmt.Errorf("presignedshare: invalid share ID")
	}
	copy(identifier[:], decoded)
	if identifier.IsZero() {
		return ShareID{}, fmt.Errorf("presignedshare: invalid share ID")
	}
	return identifier, nil
}

func (identifier ShareID) IsZero() bool { return identifier == ShareID{} }

func (identifier ShareID) String() string { return base64.RawURLEncoding.EncodeToString(identifier[:]) }

func (identifier ShareID) MarshalJSON() ([]byte, error) { return json.Marshal(identifier.String()) }

func (identifier *ShareID) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	parsed, err := ParseShareID(value)
	if err != nil {
		return err
	}
	*identifier = parsed
	return nil
}

// ExactCapability binds one safely minted bearer capability to one exact
// immutable object key in the signed bundle. Build verifies the key recorded
// by the in-module mint path instead of trusting this label alone.
type ExactCapability struct {
	Key        string
	Capability Capability
}

// BuildInput is the complete signed state of one share-bundle revision. The
// root capability is used only to enforce origin and lifetime confinement and
// is not embedded in the bundle.
type BuildInput struct {
	RootCapability         Capability
	RootKey                string
	RepositoryPrefix       string
	ReferenceKey           string
	ShareID                ShareID
	Revision               uint64
	ReferenceGeneration    uint64
	ReferenceCommit        s3disk.Digest
	Reference              s3disk.Object
	AuthorizationExpiresAt time.Time
	Capabilities           []ExactCapability
	// DangerouslyAllowUncheckedCapabilities permits values constructed through
	// DangerouslyNewUncheckedCapability. It is an interoperability escape hatch
	// for a separately commissioned custom presigner; normal production code
	// must leave it false.
	DangerouslyAllowUncheckedCapabilities bool
}

// DecodeOptions binds untrusted bundle bytes to out-of-band share state.
type DecodeOptions struct {
	RootCapability        Capability
	RepositoryPrefix      string
	ReferenceKey          string
	ShareID               ShareID
	AllowInsecureLoopback bool
	// DangerouslyAllowCustomReferenceVerifier permits Decode to invoke a
	// verifier other than the exact built-in Ed25519 implementation. Verify
	// receives the signed payload, which contains bearer URLs and headers; a
	// custom callback can exfiltrate it or contact a non-S3 control plane.
	DangerouslyAllowCustomReferenceVerifier bool
}

// Bundle is an immutable, verified bundle. Accessors return copies and never
// expose the encoded bearer URL or headers.
type Bundle struct {
	repositoryPrefix       string
	referenceKey           string
	shareID                ShareID
	revision               uint64
	referenceGeneration    uint64
	referenceCommit        s3disk.Digest
	reference              s3disk.Object
	authorizationExpiresAt time.Time
	capabilities           map[string]Capability
}

func (bundle *Bundle) RepositoryPrefix() string          { return bundle.repositoryPrefix }
func (bundle *Bundle) ReferenceKey() string              { return bundle.referenceKey }
func (bundle *Bundle) ShareID() ShareID                  { return bundle.shareID }
func (bundle *Bundle) Revision() uint64                  { return bundle.revision }
func (bundle *Bundle) ReferenceGeneration() uint64       { return bundle.referenceGeneration }
func (bundle *Bundle) ReferenceCommit() s3disk.Digest    { return bundle.referenceCommit }
func (bundle *Bundle) AuthorizationExpiresAt() time.Time { return bundle.authorizationExpiresAt }
func (bundle *Bundle) CapabilityCount() int              { return len(bundle.capabilities) }

func (bundle *Bundle) Reference() s3disk.Object {
	result := bundle.reference
	result.Data = append([]byte(nil), bundle.reference.Data...)
	return result
}

func (bundle Bundle) String() string {
	return fmt.Sprintf("presignedshare.Bundle{revision:%d,generation:%d,capabilities:%d,secrets:redacted}",
		bundle.revision, bundle.referenceGeneration, len(bundle.capabilities))
}

func (bundle Bundle) GoString() string { return bundle.String() }

func (bundle Bundle) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Format              int    `json:"format"`
		Revision            uint64 `json:"revision"`
		ReferenceGeneration uint64 `json:"reference_generation"`
		CapabilityCount     int    `json:"capability_count"`
		Secrets             string `json:"secrets"`
	}{BundleFormat, bundle.revision, bundle.referenceGeneration, len(bundle.capabilities), "redacted"})
}

type bundlePayload struct {
	Format                 int                   `json:"format"`
	RepositoryID           s3disk.RepositoryID   `json:"repository_id"`
	RepositoryPrefix       string                `json:"repository_prefix"`
	ReferenceKey           string                `json:"reference_key"`
	ShareID                ShareID               `json:"share_id"`
	Revision               uint64                `json:"revision"`
	ReferenceGeneration    uint64                `json:"reference_generation"`
	ReferenceCommit        s3disk.Digest         `json:"reference_commit"`
	Reference              wireObject            `json:"reference"`
	AuthorizationExpiresAt time.Time             `json:"authorization_expires_at"`
	KeyID                  string                `json:"key_id"`
	Capabilities           []wireExactCapability `json:"capabilities"`
}

type wireObject struct {
	Data      []byte `json:"data"`
	ETag      string `json:"etag"`
	VersionID string `json:"version_id,omitempty"`
}

type wireExactCapability struct {
	Key       string       `json:"key"`
	URL       string       `json:"url"`
	Headers   []wireHeader `json:"headers"`
	ExpiresAt time.Time    `json:"expires_at"`
}

type signedBundle struct {
	Format    int           `json:"format"`
	Payload   bundlePayload `json:"payload"`
	Signature []byte        `json:"signature"`
}

// Build produces canonical signed bytes and verifies the newly produced
// signature before returning them.
func Build(ctx context.Context, input BuildInput, signer s3disk.ReferenceSigner, verifier s3disk.ReferenceVerifier) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", ErrInvalidBundle)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !configuredInterface(signer) || !configuredInterface(verifier) || signer.RepositoryID().IsZero() || signer.RepositoryID() != verifier.RepositoryID() {
		return nil, fmt.Errorf("%w: signer and verifier trust roots do not match", ErrUntrustedBundle)
	}
	if err := validateKeyID(signer.KeyID()); err != nil {
		return nil, err
	}
	if err := preflightBuildInput(ctx, input); err != nil {
		return nil, err
	}
	payload, _, err := payloadFromInput(ctx, input, signer.RepositoryID(), signer.KeyID(), verifier, time.Now())
	if err != nil {
		return nil, err
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: encode payload", ErrInvalidBundle)
	}
	signature, err := signer.Sign(ctx, bundleSigningMessage(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: signing failed", ErrUntrustedBundle)
	}
	if len(signature) == 0 || len(signature) > maximumShareSignatureBytes {
		return nil, fmt.Errorf("%w: signature length is invalid", ErrUntrustedBundle)
	}
	if err := verifier.Verify(ctx, signer.KeyID(), bundleSigningMessage(payloadBytes), signature); err != nil {
		return nil, fmt.Errorf("%w: self-verification failed", ErrUntrustedBundle)
	}
	encoded, err := json.Marshal(signedBundle{Format: BundleFormat, Payload: payload, Signature: append([]byte(nil), signature...)})
	if err != nil {
		return nil, fmt.Errorf("%w: encode envelope", ErrInvalidBundle)
	}
	if len(encoded) > MaximumBundleBytes {
		return nil, fmt.Errorf("%w: encoded bytes exceed %d", ErrInvalidBundle, MaximumBundleBytes)
	}
	return encoded, nil
}

// Decode strictly decodes canonical bytes, verifies their domain-separated
// signature, and enforces all out-of-band share bindings.
func Decode(ctx context.Context, data []byte, verifier s3disk.ReferenceVerifier, options DecodeOptions) (*Bundle, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", ErrInvalidBundle)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > MaximumBundleBytes {
		return nil, fmt.Errorf("%w: byte length is outside the permitted bound", ErrInvalidBundle)
	}
	if !configuredInterface(verifier) {
		return nil, fmt.Errorf("%w: verifier is required", ErrUntrustedBundle)
	}
	if !s3disk.IsOfflineReferenceVerifier(verifier) && !options.DangerouslyAllowCustomReferenceVerifier {
		return nil, fmt.Errorf("%w: custom verifier requires DangerouslyAllowCustomReferenceVerifier and breaks the S3-only boundary", ErrUntrustedBundle)
	}
	if verifier.RepositoryID().IsZero() {
		return nil, fmt.Errorf("%w: verifier is required", ErrUntrustedBundle)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var envelope signedBundle
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("%w: malformed encoding", ErrInvalidBundle)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if decoder.Decode(&struct{}{}) == nil {
		return nil, fmt.Errorf("%w: trailing JSON value", ErrInvalidBundle)
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: encoding is not canonical", ErrInvalidBundle)
	}
	if envelope.Format != BundleFormat || envelope.Payload.Format != BundleFormat || len(envelope.Signature) == 0 || len(envelope.Signature) > maximumShareSignatureBytes {
		return nil, fmt.Errorf("%w: format or signature length is invalid", ErrInvalidBundle)
	}
	if envelope.Payload.RepositoryID != verifier.RepositoryID() {
		return nil, fmt.Errorf("%w: repository trust root does not match", ErrUntrustedBundle)
	}
	if err := validateKeyID(envelope.Payload.KeyID); err != nil {
		return nil, err
	}
	payloadBytes, err := json.Marshal(envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: encode signed payload", ErrInvalidBundle)
	}
	if err := verifier.Verify(ctx, envelope.Payload.KeyID, bundleSigningMessage(payloadBytes), envelope.Signature); err != nil {
		return nil, fmt.Errorf("%w: signature verification failed", ErrUntrustedBundle)
	}
	bundle, err := bundleFromPayload(ctx, envelope.Payload, options, verifier, time.Now())
	if err != nil {
		return nil, err
	}
	return bundle, nil
}

func payloadFromInput(ctx context.Context, input BuildInput, repositoryID s3disk.RepositoryID, keyID string, verifier s3disk.ReferenceVerifier, now time.Time) (bundlePayload, map[string]Capability, error) {
	prefix, err := validateBundleBindings(input.RepositoryPrefix, input.ReferenceKey, input.ShareID, input.Revision, input.ReferenceGeneration)
	if err != nil {
		return bundlePayload{}, nil, err
	}
	if !input.RootCapability.Configured() {
		return bundlePayload{}, nil, fmt.Errorf("%w: root capability is required", ErrInvalidBundle)
	}
	if !validObjectKey(input.RootKey) || input.RootCapability.exactKey != input.RootKey {
		return bundlePayload{}, nil, fmt.Errorf("%w: root capability exact key does not match", ErrInvalidBundle)
	}
	if input.RootCapability.provenance != capabilityProvenanceExactGET && !input.DangerouslyAllowUncheckedCapabilities {
		return bundlePayload{}, nil, fmt.Errorf("%w: root capability lacks verified exact-GET mint provenance", ErrInvalidBundle)
	}
	authorizationExpiry := input.AuthorizationExpiresAt.UTC().Round(0)
	if authorizationExpiry.IsZero() || !authorizationExpiry.After(now) || !authorizationExpiry.Equal(input.RootCapability.expiresAt) || authorizationExpiry.Sub(now) > MaximumCapabilityLifetime {
		return bundlePayload{}, nil, fmt.Errorf("%w: authorization expiry is invalid", ErrInvalidBundle)
	}
	if err := validateReference(ctx, input.Reference, prefix, input.ReferenceKey, input.ReferenceGeneration, input.ReferenceCommit, verifier); err != nil {
		return bundlePayload{}, nil, err
	}
	if len(input.Capabilities) < 1 || len(input.Capabilities) > MaximumBundleCapabilities {
		return bundlePayload{}, nil, fmt.Errorf("%w: capability count is outside the permitted bound", ErrInvalidBundle)
	}
	capabilities := append([]ExactCapability(nil), input.Capabilities...)
	sort.Slice(capabilities, func(left, right int) bool { return capabilities[left].Key < capabilities[right].Key })
	wireCapabilities := make([]wireExactCapability, 0, len(capabilities))
	decoded := make(map[string]Capability, len(capabilities))
	previous := ""
	for index, entry := range capabilities {
		if index&255 == 0 {
			if err := ctx.Err(); err != nil {
				return bundlePayload{}, nil, err
			}
		}
		if err := validateImmutableKey(prefix, entry.Key); err != nil {
			return bundlePayload{}, nil, err
		}
		if entry.Key == previous {
			return bundlePayload{}, nil, fmt.Errorf("%w: duplicate exact object key", ErrInvalidBundle)
		}
		previous = entry.Key
		capability := entry.Capability
		if !capability.Configured() || capability.origin != input.RootCapability.origin {
			return bundlePayload{}, nil, fmt.Errorf("%w: capability origin does not match root", ErrInvalidBundle)
		}
		if capability.exactKey != entry.Key {
			return bundlePayload{}, nil, fmt.Errorf("%w: capability exact key does not match bundle key", ErrInvalidBundle)
		}
		if capability.provenance != capabilityProvenanceExactGET && !input.DangerouslyAllowUncheckedCapabilities {
			return bundlePayload{}, nil, fmt.Errorf("%w: object capability lacks verified exact-GET mint provenance", ErrInvalidBundle)
		}
		// An extracted bearer must not outlive the advertised share. Requiring
		// equality is stronger than merely requiring it not to expire early.
		if !capability.expiresAt.Equal(authorizationExpiry) {
			return bundlePayload{}, nil, fmt.Errorf("%w: capability expiry must equal authorization expiry", ErrInvalidBundle)
		}
		decoded[entry.Key] = capability
		wireCapabilities = append(wireCapabilities, wireExactCapability{
			Key: entry.Key, URL: capability.rawURL, Headers: headersToWire(capability.headers), ExpiresAt: capability.expiresAt,
		})
	}
	return bundlePayload{
		Format: BundleFormat, RepositoryID: repositoryID, RepositoryPrefix: prefix,
		ReferenceKey: input.ReferenceKey, ShareID: input.ShareID, Revision: input.Revision,
		ReferenceGeneration:    input.ReferenceGeneration,
		ReferenceCommit:        input.ReferenceCommit,
		Reference:              wireObject{Data: append([]byte(nil), input.Reference.Data...), ETag: input.Reference.Version.ETag, VersionID: input.Reference.Version.VersionID},
		AuthorizationExpiresAt: authorizationExpiry, KeyID: keyID, Capabilities: wireCapabilities,
	}, decoded, nil
}

func bundleFromPayload(ctx context.Context, payload bundlePayload, options DecodeOptions, verifier s3disk.ReferenceVerifier, now time.Time) (*Bundle, error) {
	prefix, err := validateBundleBindings(payload.RepositoryPrefix, payload.ReferenceKey, payload.ShareID, payload.Revision, payload.ReferenceGeneration)
	if err != nil {
		return nil, err
	}
	expectedPrefix := strings.Trim(options.RepositoryPrefix, "/")
	if prefix != expectedPrefix || payload.ReferenceKey != options.ReferenceKey || payload.ShareID != options.ShareID || options.ShareID.IsZero() {
		return nil, fmt.Errorf("%w: out-of-band share binding does not match", ErrUntrustedBundle)
	}
	if !options.RootCapability.Configured() {
		return nil, fmt.Errorf("%w: root capability is required", ErrInvalidBundle)
	}
	authorizationExpiry := payload.AuthorizationExpiresAt.UTC().Round(0)
	if authorizationExpiry.IsZero() || !authorizationExpiry.After(now) || !authorizationExpiry.Equal(options.RootCapability.expiresAt) || authorizationExpiry.Sub(now) > MaximumCapabilityLifetime {
		return nil, fmt.Errorf("%w: authorization expiry is invalid", ErrInvalidBundle)
	}
	reference := s3disk.Object{Data: append([]byte(nil), payload.Reference.Data...), Version: s3disk.Version{ETag: payload.Reference.ETag, VersionID: payload.Reference.VersionID}}
	if err := validateReference(ctx, reference, prefix, payload.ReferenceKey, payload.ReferenceGeneration, payload.ReferenceCommit, verifier); err != nil {
		return nil, err
	}
	if len(payload.Capabilities) < 1 || len(payload.Capabilities) > MaximumBundleCapabilities {
		return nil, fmt.Errorf("%w: capability count is outside the permitted bound", ErrInvalidBundle)
	}
	capabilities := make(map[string]Capability, len(payload.Capabilities))
	previous := ""
	for index, entry := range payload.Capabilities {
		if index&255 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if entry.Key <= previous && previous != "" {
			return nil, fmt.Errorf("%w: capability keys are not uniquely sorted", ErrInvalidBundle)
		}
		previous = entry.Key
		if err := validateImmutableKey(prefix, entry.Key); err != nil {
			return nil, err
		}
		headers, err := headersFromWire(entry.Headers)
		if err != nil {
			return nil, fmt.Errorf("%w: capability headers are invalid", ErrInvalidBundle)
		}
		capability, err := newCapability(
			entry.Key, entry.URL, headers, entry.ExpiresAt,
			CapabilityOptions{AllowInsecureLoopback: options.AllowInsecureLoopback}, now,
			capabilityProvenanceAuthenticatedBundle,
		)
		if err != nil {
			return nil, fmt.Errorf("%w: encoded capability is invalid", ErrInvalidBundle)
		}
		if capability.origin != options.RootCapability.origin {
			return nil, fmt.Errorf("%w: capability origin does not match root", ErrInvalidBundle)
		}
		if !capability.expiresAt.Equal(authorizationExpiry) {
			return nil, fmt.Errorf("%w: capability expiry must equal authorization expiry", ErrInvalidBundle)
		}
		capabilities[entry.Key] = capability
	}
	return &Bundle{
		repositoryPrefix: prefix, referenceKey: payload.ReferenceKey, shareID: payload.ShareID,
		revision: payload.Revision, referenceGeneration: payload.ReferenceGeneration, referenceCommit: payload.ReferenceCommit,
		reference: reference, authorizationExpiresAt: authorizationExpiry, capabilities: capabilities,
	}, nil
}

func validateBundleBindings(prefix, referenceKey string, shareID ShareID, revision, generation uint64) (string, error) {
	if !utf8.ValidString(prefix) || strings.ContainsRune(prefix, '\x00') {
		return "", fmt.Errorf("%w: repository prefix is invalid", ErrInvalidBundle)
	}
	prefix = strings.Trim(prefix, "/")
	if shareID.IsZero() || revision == 0 || generation == 0 {
		return "", fmt.Errorf("%w: share ID, revision, and generation must be nonzero", ErrInvalidBundle)
	}
	if !validObjectKey(referenceKey) {
		return "", fmt.Errorf("%w: reference key is invalid", ErrInvalidBundle)
	}
	namespace := repositoryObjectNamespace(prefix)
	relative := strings.TrimPrefix(referenceKey, namespace)
	if relative == referenceKey || !validReferenceRemainder(relative) {
		return "", fmt.Errorf("%w: reference key is outside the repository reference namespace", ErrInvalidBundle)
	}
	return prefix, nil
}

func validateImmutableKey(prefix, key string) error {
	if !validObjectKey(key) {
		return fmt.Errorf("%w: exact object key is invalid", ErrInvalidBundle)
	}
	relative := strings.TrimPrefix(key, repositoryObjectNamespace(prefix))
	if relative == key || !validImmutableRemainder(relative) {
		return fmt.Errorf("%w: capability key is outside the immutable object namespace", ErrInvalidBundle)
	}
	return nil
}

func repositoryObjectNamespace(prefix string) string {
	if prefix == "" {
		return repositoryNamespace + "/"
	}
	return prefix + "/" + repositoryNamespace + "/"
}

func validObjectKey(key string) bool {
	return key != "" && len(key) <= maximumObjectKeyBytes && utf8.ValidString(key) && !strings.ContainsRune(key, '\x00')
}

func validateReference(ctx context.Context, reference s3disk.Object, prefix, referenceKey string, generation uint64, commit s3disk.Digest, verifier s3disk.ReferenceVerifier) error {
	if len(reference.Data) == 0 || len(reference.Data) > maximumReferenceBytes {
		return fmt.Errorf("%w: reference byte length is invalid", ErrInvalidBundle)
	}
	if reference.Version.ETag == "" || len(reference.Version.ETag) > s3disk.MaxStoreVersionTokenBytes || len(reference.Version.VersionID) > s3disk.MaxStoreVersionTokenBytes || strings.ContainsAny(reference.Version.ETag+reference.Version.VersionID, "\x00\r\n") {
		return fmt.Errorf("%w: reference version is invalid", ErrInvalidBundle)
	}
	relative := strings.TrimPrefix(referenceKey, repositoryObjectNamespace(prefix))
	channel, signed, err := channelFromReferenceRemainder(relative)
	if err != nil {
		return fmt.Errorf("%w: reference channel encoding is invalid", ErrInvalidBundle)
	}
	var referenceVerifier s3disk.ReferenceVerifier
	if signed {
		referenceVerifier = verifier
	}
	info, err := s3disk.VerifySnapshotReference(ctx, reference.Data, channel, referenceVerifier)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if errors.Is(err, s3disk.ErrUntrustedReference) {
			return fmt.Errorf("%w: embedded signed reference verification failed", ErrUntrustedBundle)
		}
		return fmt.Errorf("%w: embedded reference encoding is invalid", ErrInvalidBundle)
	}
	if generation == 0 || commit.IsZero() || info.Generation != generation || info.Commit != commit {
		return fmt.Errorf("%w: embedded reference identity does not match generation and commit", ErrInvalidBundle)
	}
	return nil
}

func validateKeyID(keyID string) error {
	if keyID == "" || len(keyID) > maximumShareKeyIDBytes {
		return fmt.Errorf("%w: signing key ID is invalid", ErrUntrustedBundle)
	}
	for _, character := range keyID {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-", character) {
			return fmt.Errorf("%w: signing key ID is invalid", ErrUntrustedBundle)
		}
	}
	return nil
}

func validReferenceRemainder(relative string) bool {
	_, _, err := channelFromReferenceRemainder(relative)
	return err == nil
}

func channelFromReferenceRemainder(relative string) (string, bool, error) {
	encodedChannel := ""
	signed := false
	switch {
	case strings.HasPrefix(relative, "refs/"):
		encodedChannel = strings.TrimPrefix(relative, "refs/")
	case strings.HasPrefix(relative, "signed-refs/v1/"):
		encodedChannel = strings.TrimPrefix(relative, "signed-refs/v1/")
		signed = true
	default:
		return "", false, ErrInvalidBundle
	}
	if encodedChannel == "" || strings.ContainsRune(encodedChannel, '/') {
		return "", false, ErrInvalidBundle
	}
	channelBytes, err := base64.RawURLEncoding.DecodeString(encodedChannel)
	if err != nil || len(channelBytes) == 0 || len(channelBytes) > 1024 || !utf8.Valid(channelBytes) ||
		bytes.ContainsRune(channelBytes, '\x00') || base64.RawURLEncoding.EncodeToString(channelBytes) != encodedChannel {
		return "", false, ErrInvalidBundle
	}
	return string(channelBytes), signed, nil
}

func validImmutableRemainder(relative string) bool {
	parts := strings.Split(relative, "/")
	if len(parts) != 5 || parts[0] != "objects" || (parts[2] != "sha256" && parts[2] != "hmac-sha256") {
		return false
	}
	switch parts[1] {
	case "commit", "dir", "file", "symlink", "chunk":
	default:
		return false
	}
	shard, digest := parts[3], parts[4]
	if len(shard) != 2 || len(digest) != 64 || shard != digest[:2] {
		return false
	}
	return lowercaseHex(shard) && lowercaseHex(digest)
}

func lowercaseHex(value string) bool {
	for index := 0; index < len(value); index++ {
		if !((value[index] >= '0' && value[index] <= '9') || (value[index] >= 'a' && value[index] <= 'f')) {
			return false
		}
	}
	return true
}

// preflightBuildInput bounds the secret material before Build clones slices or
// asks encoding/json to allocate a second representation. jsonStringBytes is
// an upper bound for encoding/json's HTML-safe string escaping.
func preflightBuildInput(ctx context.Context, input BuildInput) error {
	if len(input.Capabilities) < 1 || len(input.Capabilities) > MaximumBundleCapabilities {
		return fmt.Errorf("%w: capability count is outside the permitted bound", ErrInvalidBundle)
	}
	if len(input.Reference.Data) == 0 || len(input.Reference.Data) > maximumReferenceBytes {
		return fmt.Errorf("%w: reference byte length is invalid", ErrInvalidBundle)
	}
	total := int64(8 << 10)
	add := func(size int64) bool {
		if size < 0 || total > int64(MaximumBundleBytes)-size {
			return false
		}
		total += size
		return true
	}
	if !add(int64(base64.StdEncoding.EncodedLen(len(input.Reference.Data)))) ||
		!add(jsonStringBytes(input.RepositoryPrefix)) || !add(jsonStringBytes(input.ReferenceKey)) ||
		!add(jsonStringBytes(input.Reference.Version.ETag)) || !add(jsonStringBytes(input.Reference.Version.VersionID)) {
		return fmt.Errorf("%w: estimated encoded bytes exceed %d", ErrInvalidBundle, MaximumBundleBytes)
	}
	for index, entry := range input.Capabilities {
		if index&255 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if !add(256) || !add(jsonStringBytes(entry.Key)) || !add(jsonStringBytes(entry.Capability.rawURL)) {
			return fmt.Errorf("%w: estimated encoded bytes exceed %d", ErrInvalidBundle, MaximumBundleBytes)
		}
		for name, values := range entry.Capability.headers {
			if !add(64) || !add(jsonStringBytes(name)) {
				return fmt.Errorf("%w: estimated encoded bytes exceed %d", ErrInvalidBundle, MaximumBundleBytes)
			}
			for _, value := range values {
				if !add(2) || !add(jsonStringBytes(value)) {
					return fmt.Errorf("%w: estimated encoded bytes exceed %d", ErrInvalidBundle, MaximumBundleBytes)
				}
			}
		}
	}
	return nil
}

func jsonStringBytes(value string) int64 {
	// Match encoding/json's HTML-safe string escaping without allocating the
	// escaped copy. The surrounding structural estimate remains conservative.
	size := int64(2) // quotes
	for index := 0; index < len(value); {
		character := value[index]
		if character < utf8.RuneSelf {
			index++
			switch character {
			case '\b', '\f', '\n', '\r', '\t', '\\', '"':
				size += 2
			case '<', '>', '&':
				size += 6
			default:
				if character < 0x20 {
					size += 6
				} else {
					size++
				}
			}
			continue
		}
		decoded, width := utf8.DecodeRuneInString(value[index:])
		if decoded == utf8.RuneError && width == 1 {
			size += 6
			index++
			continue
		}
		if decoded == '\u2028' || decoded == '\u2029' {
			size += 6
		} else {
			size += int64(width)
		}
		index += width
	}
	return size
}

func bundleSigningMessage(payload []byte) []byte {
	message := make([]byte, 0, len(bundleSigningDomain)+8+len(payload))
	message = append(message, bundleSigningDomain...)
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(payload)))
	message = append(message, size[:]...)
	message = append(message, payload...)
	return message
}

func configuredInterface(value any) bool {
	if value == nil {
		return false
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !reflected.IsNil()
	default:
		return true
	}
}
