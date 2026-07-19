package s3disk

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	repositoryNamespace = ".s3disk/v1"
	// Amazon S3 counts the caller prefix, delimiters, and protocol suffix in
	// the 1,024-byte UTF-8 object-key limit. Compatible stores must support at
	// least this S3 limit; keeping the protocol within it avoids late uploads
	// failing after an otherwise successful source scan.
	maxObjectKeyBytes = 1024
)

// Repository maps protocol object keys into a caller-selected store prefix.
// A Repository created by NewReadOnlyRepository contains only read authority
// and is suitable for Consumer but not Publisher or the full compatibility
// probe.
type Repository struct {
	reader           ObjectReader
	store            Store
	prefix           string
	clientEncryption *ClientEncryptionProfile
}

// RepositoryOptions selects an explicit, versioned repository storage
// profile. A non-nil ClientEncryption profile encrypts every object body and
// replaces plaintext digest keys with keyed opaque identifiers. Encrypted and
// unencrypted repositories must use different caller-provided prefixes.
type RepositoryOptions struct {
	ClientEncryption *ClientEncryptionProfile
}

// NewRepository constructs a repository with full publication authority.
func NewRepository(store Store, prefix string) (*Repository, error) {
	return NewRepositoryWithOptions(store, prefix, RepositoryOptions{})
}

// NewRepositoryWithOptions constructs a repository with full publication
// authority and the selected storage profile.
func NewRepositoryWithOptions(store Store, prefix string, options RepositoryOptions) (*Repository, error) {
	if store == nil {
		return nil, fmt.Errorf("s3disk: nil store")
	}
	if !interfaceDependencyConfigured(store) {
		return nil, fmt.Errorf("s3disk: store must not be a typed nil")
	}
	reader := ObjectReader(store)
	writable := store
	if options.ClientEncryption != nil {
		encrypted, err := NewClientEncryptedStore(store, options.ClientEncryption)
		if err != nil {
			return nil, err
		}
		reader = encrypted
		writable = encrypted
	}
	return newRepository(reader, writable, prefix, options)
}

// NewReadOnlyRepository constructs a least-privilege repository for Consumer.
// It retains only ObjectReader capability: even when reader's concrete value
// also implements Store, Publisher and the destructive full compatibility
// probe remain unavailable through the returned Repository.
func NewReadOnlyRepository(reader ObjectReader, prefix string) (*Repository, error) {
	return NewReadOnlyRepositoryWithOptions(reader, prefix, RepositoryOptions{})
}

// NewReadOnlyRepositoryWithOptions constructs a least-privilege repository
// with the selected storage profile. The returned Repository never retains
// Head, write, or delete authority from the supplied reader.
func NewReadOnlyRepositoryWithOptions(reader ObjectReader, prefix string, options RepositoryOptions) (*Repository, error) {
	if reader == nil {
		return nil, fmt.Errorf("s3disk: nil object reader")
	}
	if !interfaceDependencyConfigured(reader) {
		return nil, fmt.Errorf("s3disk: object reader must not be a typed nil")
	}
	if options.ClientEncryption != nil {
		if !clientEncryptionAlreadyApplied(reader, options.ClientEncryption) {
			encrypted, err := newClientEncryptedObjectReader(reader, options.ClientEncryption)
			if err != nil {
				return nil, err
			}
			reader = encrypted
		}
	}
	return newRepository(reader, nil, prefix, options)
}

func newRepository(reader ObjectReader, store Store, prefix string, options RepositoryOptions) (*Repository, error) {
	prefix = strings.Trim(prefix, "/")
	if !utf8.ValidString(prefix) || strings.ContainsRune(prefix, '\x00') {
		return nil, fmt.Errorf("%w: invalid repository prefix", ErrInvalidPath)
	}
	if options.ClientEncryption != nil && prefix == "" {
		return nil, fmt.Errorf("%w: client-encrypted repositories require a dedicated non-empty prefix", ErrInvalidPath)
	}
	if options.ClientEncryption != nil && !options.ClientEncryption.configured() {
		return nil, fmt.Errorf("s3disk: client encryption profile is not configured")
	}
	repository := &Repository{
		reader:           reader,
		store:            store,
		prefix:           prefix,
		clientEncryption: options.ClientEncryption,
	}
	if len(repository.objectKey("symlink", Digest{})) > maxObjectKeyBytes {
		return nil, fmt.Errorf("%w: repository prefix leaves no room for protocol object keys", ErrInvalidPath)
	}
	return repository, nil
}

func (repository *Repository) key(relative string) string {
	base := repositoryNamespace
	if repository.prefix != "" {
		base = repository.prefix + "/" + base
	}
	return base + "/" + relative
}

// ReferenceKey returns the exact store key used for a channel's mutable
// reference. It is useful when constructing IAM policies and diagnostics.
func (repository *Repository) ReferenceKey(channel string) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(channel))
	return repository.key("refs/" + encoded)
}

// SignedReferenceKey returns the independent mutable key used by authenticated
// publishers and consumers. Trusted consumers never fall back to ReferenceKey.
func (repository *Repository) SignedReferenceKey(channel string) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(channel))
	return repository.key("signed-refs/v1/" + encoded)
}

func validateChannel(channel string) error {
	if channel == "" || !utf8.ValidString(channel) || strings.ContainsRune(channel, '\x00') || len(channel) > 1024 {
		return fmt.Errorf("%w: invalid channel", ErrInvalidPath)
	}
	return nil
}

func (repository *Repository) validateChannel(channel string) error {
	if err := validateChannel(channel); err != nil {
		return err
	}
	// Signed references have the longest mutable-reference namespace. Use it
	// for both modes so enabling authentication later cannot invalidate an
	// otherwise accepted channel name.
	if len(repository.SignedReferenceKey(channel)) > maxObjectKeyBytes {
		return fmt.Errorf("%w: channel and repository prefix exceed the object-key limit", ErrInvalidPath)
	}
	return nil
}

func (repository *Repository) objectKey(kind string, digest Digest) string {
	value := digest.String()
	if repository.clientEncryption != nil {
		value = repository.clientEncryption.opaqueObjectID(kind, digest)
		return repository.key("objects/" + kind + "/hmac-sha256/" + value[:2] + "/" + value)
	}
	return repository.key("objects/" + kind + "/sha256/" + value[:2] + "/" + value)
}

func (repository *Repository) putImmutable(ctx context.Context, kind string, data []byte) (Digest, error) {
	digest := digestObject(kind, data)
	key := repository.objectKey(kind, digest)
	if version, err := repository.store.Head(ctx, key); err == nil {
		if err := validateStoreVersion("HEAD immutable "+kind, version); err != nil {
			return Digest{}, err
		}
		return digest, nil
	} else if !errors.Is(err, ErrObjectNotFound) {
		return Digest{}, fmt.Errorf("head immutable %s: %w", kind, err)
	}
	version, err := repository.store.PutIfAbsent(ctx, key, data)
	if err == nil {
		if err := validateStoreVersion("PutIfAbsent immutable "+kind, version); err != nil {
			return Digest{}, err
		}
		return digest, nil
	}
	if !errors.Is(err, ErrPrecondition) {
		return Digest{}, fmt.Errorf("put immutable %s: %w", kind, err)
	}
	// A concurrent immutable writer won between HEAD and PutIfAbsent. Observe
	// its version so a VersionID-only or otherwise invalid adapter cannot bypass
	// the successful-operation version contract through this race path.
	version, err = repository.store.Head(ctx, key)
	if err != nil {
		return Digest{}, fmt.Errorf("head immutable %s after precondition: %w", kind, err)
	}
	if err := validateStoreVersion("HEAD immutable "+kind+" after precondition", version); err != nil {
		return Digest{}, err
	}
	return digest, nil
}

func (repository *Repository) putManifest(ctx context.Context, kind string, value any) (Digest, error) {
	data, err := canonicalJSON(value)
	if err != nil {
		return Digest{}, fmt.Errorf("encode %s manifest: %w", kind, err)
	}
	if len(data) > maxMetadataObjectBytes {
		return Digest{}, fmt.Errorf("%w: %s manifest is %d bytes (maximum %d)", ErrResourceLimit, kind, len(data), maxMetadataObjectBytes)
	}
	return repository.putImmutable(ctx, kind, data)
}

func (repository *Repository) getImmutable(ctx context.Context, kind string, digest Digest) ([]byte, error) {
	limit := int64(maxMetadataObjectBytes)
	if kind == "chunk" {
		limit = maxChunkObjectBytes
	}
	return repository.getImmutableLimited(ctx, kind, digest, limit)
}

// getImmutableExact bounds adapter buffering at the size authenticated by the
// caller's already-validated manifest and then verifies the returned size.
func (repository *Repository) getImmutableExact(ctx context.Context, kind string, digest Digest, expectedSize int64) ([]byte, error) {
	maximum := int64(maxMetadataObjectBytes)
	if kind == "chunk" {
		maximum = maxChunkObjectBytes
	}
	if expectedSize < 1 || expectedSize > maximum {
		return nil, fmt.Errorf("%w: invalid %s object size %d", ErrResourceLimit, kind, expectedSize)
	}
	data, err := repository.getImmutableLimited(ctx, kind, digest, expectedSize)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != expectedSize {
		return nil, fmt.Errorf("%w: %s object size is %d, expected %d", ErrCorruptObject, kind, len(data), expectedSize)
	}
	return data, nil
}

func (repository *Repository) getImmutableLimited(ctx context.Context, kind string, digest Digest, limit int64) ([]byte, error) {
	object, err := repository.reader.Get(ctx, repository.objectKey(kind, digest), GetOptions{MaxBytes: limit})
	if err != nil {
		return nil, fmt.Errorf("get immutable %s %s: %w", kind, digest, err)
	}
	if err := validateStoreVersion("GET immutable "+kind, object.Version); err != nil {
		return nil, err
	}
	if int64(len(object.Data)) > limit {
		return nil, fmt.Errorf("%w: %s object exceeds %d bytes", ErrResourceLimit, kind, limit)
	}
	if actual := digestObject(kind, object.Data); actual != digest {
		return nil, fmt.Errorf("%w: %s object %s hashed to %s", ErrCorruptObject, kind, digest, actual)
	}
	return object.Data, nil
}

func (repository *Repository) getManifest(ctx context.Context, kind string, digest Digest, value any) error {
	data, err := repository.getImmutable(ctx, kind, digest)
	if err != nil {
		return err
	}
	return decodeJSON(data, value)
}

func (repository *Repository) getReference(ctx context.Context, channel string, ifNoneMatch string) (snapshotReference, Object, error) {
	return repository.getReferenceWithVerifier(ctx, channel, ifNoneMatch, nil)
}

func (repository *Repository) getReferenceWithVerifier(ctx context.Context, channel string, ifNoneMatch string, verifier ReferenceVerifier) (snapshotReference, Object, error) {
	if verifier != nil && !interfaceDependencyConfigured(verifier) {
		return snapshotReference{}, Object{}, fmt.Errorf("s3disk: reference verifier must not be a typed nil")
	}
	key := repository.ReferenceKey(channel)
	if verifier != nil {
		key = repository.SignedReferenceKey(channel)
	}
	object, err := repository.reader.Get(ctx, key, GetOptions{
		IfNoneMatch: ifNoneMatch,
		MaxBytes:    maxReferenceBytes,
	})
	if err != nil {
		return snapshotReference{}, Object{}, err
	}
	if err := validateStoreVersion("GET mutable reference", object.Version); err != nil {
		return snapshotReference{}, Object{}, err
	}
	identity, err := VerifySnapshotReference(ctx, object.Data, channel, verifier)
	if err != nil {
		return snapshotReference{}, Object{}, err
	}
	return snapshotReference{
		Format:     objectFormatVersion,
		Generation: identity.Generation,
		Commit:     identity.Commit,
	}, object, nil
}

func (repository *Repository) compareAndSwap(
	ctx context.Context,
	key string,
	expected *Version,
	data []byte,
) (Version, error) {
	version, err := repository.store.CompareAndSwap(ctx, key, expected, data)
	if err != nil {
		return Version{}, err
	}
	if err := validateStoreVersion("CompareAndSwap", version); err != nil {
		return Version{}, err
	}
	return version, nil
}
