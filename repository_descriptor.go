package s3disk

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	// RepositoryDescriptorFormat is the current write-once repository
	// commissioning record format.
	RepositoryDescriptorFormat = 1
	// MaximumRepositoryDescriptorBytes bounds the complete plaintext
	// commissioning record before an ObjectReader may return it.
	MaximumRepositoryDescriptorBytes = 16 << 10

	repositoryChunkingAlgorithm = "rabin-v1"
)

// RepositoryStorageProfile names the complete on-object storage semantics for
// one repository prefix. A prefix cannot change profile in place.
type RepositoryStorageProfile string

const (
	// RepositoryStorageProfilePlaintextV1 retains plaintext object bodies and
	// SHA-256-derived immutable object names.
	RepositoryStorageProfilePlaintextV1 RepositoryStorageProfile = "plaintext-v1"
	// RepositoryStorageProfileStrictShareIsolationV1 uses the built-in
	// per-share encryption and opaque immutable object identifiers.
	RepositoryStorageProfileStrictShareIsolationV1 RepositoryStorageProfile = "strict-share-isolation-v1"
)

// RepositoryConfig contains the caller-held configuration which must exactly
// match a prefix's durable RepositoryDescriptor. RepositoryID is required even
// for plaintext repositories so signed trust state cannot be transplanted.
type RepositoryConfig struct {
	RepositoryID     RepositoryID
	ClientEncryption *ClientEncryptionProfile
	Chunking         ChunkingOptions
}

// RepositoryInitializationOptions contains the explicit authorization needed
// to commission a prefix which has no descriptor. ConfirmEmptyPrefix is a
// caller assertion: Store intentionally has no List authority, so s3disk cannot
// prove that an uncommissioned prefix contains no legacy protocol objects.
type RepositoryInitializationOptions struct {
	ConfirmEmptyPrefix bool
}

// RepositoryChunkingDescriptor is the canonical, versioned chunking profile
// stored in a RepositoryDescriptor.
type RepositoryChunkingDescriptor struct {
	Algorithm   string `json:"algorithm"`
	MinSize     int    `json:"minimum_size"`
	AverageSize int    `json:"average_size"`
	MaxSize     int    `json:"maximum_size"`
	Polynomial  uint64 `json:"polynomial"`
}

// RepositoryDescriptor is the immutable commissioning record for one exact
// repository prefix. It contains no secret or provider-specific configuration.
type RepositoryDescriptor struct {
	Format           int                          `json:"format"`
	RepositoryID     RepositoryID                 `json:"repository_id"`
	RepositoryPrefix string                       `json:"repository_prefix"`
	StorageProfile   RepositoryStorageProfile     `json:"storage_profile"`
	Chunking         RepositoryChunkingDescriptor `json:"chunking"`
}

// ChunkingOptions returns the normalized options bound by descriptor.
func (descriptor RepositoryDescriptor) ChunkingOptions() ChunkingOptions {
	return ChunkingOptions{
		MinSize: descriptor.Chunking.MinSize, AverageSize: descriptor.Chunking.AverageSize,
		MaxSize: descriptor.Chunking.MaxSize, Polynomial: descriptor.Chunking.Polynomial,
	}
}

// InitializeRepository creates a write-once descriptor for a caller-confirmed
// empty prefix or opens an identical existing one. A failed PutIfAbsent is
// reconciled through an exact bounded GET so a timeout after an applied S3 write
// is safe to retry.
func InitializeRepository(
	ctx context.Context,
	store Store,
	prefix string,
	config RepositoryConfig,
	options RepositoryInitializationOptions,
) (*Repository, RepositoryDescriptor, error) {
	if ctx == nil {
		return nil, RepositoryDescriptor{}, fmt.Errorf("s3disk: repository initialization context is required")
	}
	repository, expected, err := configuredWritableRepository(store, prefix, config)
	if err != nil {
		return nil, RepositoryDescriptor{}, err
	}
	actual, found, err := repository.loadDescriptor(ctx)
	if err != nil {
		return nil, RepositoryDescriptor{}, fmt.Errorf("s3disk: read repository descriptor: %w", err)
	}
	if found {
		return acceptRepositoryDescriptor(repository, expected, actual)
	}
	if !options.ConfirmEmptyPrefix {
		return nil, RepositoryDescriptor{}, fmt.Errorf(
			"%w: descriptor is absent; creating one requires explicit confirmation that the prefix is empty",
			ErrRepositoryNotInitialized,
		)
	}

	data, err := canonicalJSON(expected)
	if err != nil {
		return nil, RepositoryDescriptor{}, fmt.Errorf("s3disk: encode repository descriptor: %w", err)
	}
	version, putErr := repository.store.PutIfAbsent(ctx, repository.DescriptorKey(), data)
	if putErr == nil {
		if err := validateStoreVersion("PutIfAbsent repository descriptor", version); err != nil {
			return nil, RepositoryDescriptor{}, err
		}
		repository.setDescriptor(expected)
		return repository, expected, nil
	}

	actual, found, readErr := repository.loadDescriptor(ctx)
	if readErr == nil && found {
		return acceptRepositoryDescriptor(repository, expected, actual)
	}
	if readErr == nil {
		readErr = ErrRepositoryNotInitialized
	}
	return nil, RepositoryDescriptor{}, fmt.Errorf(
		"%w: reconcile descriptor after PutIfAbsent: %w",
		ErrRepositoryInitializationIndeterminate,
		errors.Join(putErr, readErr),
	)
}

// OpenRepository validates an existing descriptor and returns a repository
// retaining full publication authority. It never creates a missing descriptor.
func OpenRepository(
	ctx context.Context,
	store Store,
	prefix string,
	config RepositoryConfig,
) (*Repository, RepositoryDescriptor, error) {
	if ctx == nil {
		return nil, RepositoryDescriptor{}, fmt.Errorf("s3disk: repository open context is required")
	}
	repository, expected, err := configuredWritableRepository(store, prefix, config)
	if err != nil {
		return nil, RepositoryDescriptor{}, err
	}
	return openConfiguredRepository(ctx, repository, expected)
}

// OpenReadOnlyRepository validates an existing descriptor while retaining only
// exact ObjectReader authority. It never retains Head or write capabilities
// from the reader's concrete value.
func OpenReadOnlyRepository(
	ctx context.Context,
	reader ObjectReader,
	prefix string,
	config RepositoryConfig,
) (*Repository, RepositoryDescriptor, error) {
	if ctx == nil {
		return nil, RepositoryDescriptor{}, fmt.Errorf("s3disk: read-only repository open context is required")
	}
	repository, expected, err := configuredReadOnlyRepository(reader, prefix, config)
	if err != nil {
		return nil, RepositoryDescriptor{}, err
	}
	return openConfiguredRepository(ctx, repository, expected)
}

func configuredWritableRepository(store Store, prefix string, config RepositoryConfig) (*Repository, RepositoryDescriptor, error) {
	expected, options, err := descriptorConfiguration(prefix, config)
	if err != nil {
		return nil, RepositoryDescriptor{}, err
	}
	repository, err := NewRepositoryWithOptions(store, prefix, options)
	if err != nil {
		return nil, RepositoryDescriptor{}, err
	}
	expected.RepositoryPrefix = repository.prefix
	return repository, expected, nil
}

func configuredReadOnlyRepository(reader ObjectReader, prefix string, config RepositoryConfig) (*Repository, RepositoryDescriptor, error) {
	expected, options, err := descriptorConfiguration(prefix, config)
	if err != nil {
		return nil, RepositoryDescriptor{}, err
	}
	repository, err := NewReadOnlyRepositoryWithOptions(reader, prefix, options)
	if err != nil {
		return nil, RepositoryDescriptor{}, err
	}
	expected.RepositoryPrefix = repository.prefix
	return repository, expected, nil
}

func descriptorConfiguration(prefix string, config RepositoryConfig) (RepositoryDescriptor, RepositoryOptions, error) {
	if config.RepositoryID.IsZero() {
		return RepositoryDescriptor{}, RepositoryOptions{}, fmt.Errorf(
			"%w: repository ID must not be zero", ErrRepositoryConfigurationMismatch,
		)
	}
	chunking, err := config.Chunking.normalized()
	if err != nil {
		return RepositoryDescriptor{}, RepositoryOptions{}, err
	}
	profile := RepositoryStorageProfilePlaintextV1
	if config.ClientEncryption != nil {
		if !config.ClientEncryption.configured() || config.ClientEncryption.RepositoryID() != config.RepositoryID {
			return RepositoryDescriptor{}, RepositoryOptions{}, fmt.Errorf(
				"%w: client encryption and repository identities differ",
				ErrRepositoryConfigurationMismatch,
			)
		}
		profile = RepositoryStorageProfileStrictShareIsolationV1
	}
	prefix = strings.Trim(prefix, "/")
	descriptor := RepositoryDescriptor{
		Format: RepositoryDescriptorFormat, RepositoryID: config.RepositoryID,
		RepositoryPrefix: prefix, StorageProfile: profile,
		Chunking: RepositoryChunkingDescriptor{
			Algorithm: repositoryChunkingAlgorithm, MinSize: chunking.MinSize,
			AverageSize: chunking.AverageSize, MaxSize: chunking.MaxSize,
			Polynomial: chunking.Polynomial,
		},
	}
	return descriptor, RepositoryOptions{ClientEncryption: config.ClientEncryption}, nil
}

func openConfiguredRepository(
	ctx context.Context,
	repository *Repository,
	expected RepositoryDescriptor,
) (*Repository, RepositoryDescriptor, error) {
	actual, found, err := repository.loadDescriptor(ctx)
	if err != nil {
		return nil, RepositoryDescriptor{}, fmt.Errorf("s3disk: read repository descriptor: %w", err)
	}
	if !found {
		return nil, RepositoryDescriptor{}, ErrRepositoryNotInitialized
	}
	return acceptRepositoryDescriptor(repository, expected, actual)
}

func acceptRepositoryDescriptor(
	repository *Repository,
	expected, actual RepositoryDescriptor,
) (*Repository, RepositoryDescriptor, error) {
	if actual != expected {
		return nil, RepositoryDescriptor{}, fmt.Errorf(
			"%w: stored descriptor differs from requested configuration",
			ErrRepositoryConfigurationMismatch,
		)
	}
	repository.setDescriptor(actual)
	return repository, actual, nil
}

func (repository *Repository) loadDescriptor(ctx context.Context) (RepositoryDescriptor, bool, error) {
	object, err := repository.reader.Get(ctx, repository.DescriptorKey(), GetOptions{MaxBytes: MaximumRepositoryDescriptorBytes})
	if errors.Is(err, ErrObjectNotFound) {
		return RepositoryDescriptor{}, false, nil
	}
	if err != nil {
		return RepositoryDescriptor{}, false, err
	}
	if err := validateStoreVersion("GET repository descriptor", object.Version); err != nil {
		return RepositoryDescriptor{}, false, err
	}
	if len(object.Data) == 0 || len(object.Data) > MaximumRepositoryDescriptorBytes {
		return RepositoryDescriptor{}, false, fmt.Errorf(
			"%w: repository descriptor exceeds its byte limit", ErrCorruptObject,
		)
	}
	var descriptor RepositoryDescriptor
	if err := decodeJSON(object.Data, &descriptor); err != nil {
		return RepositoryDescriptor{}, false, fmt.Errorf("decode repository descriptor: %w", err)
	}
	if err := validateRepositoryDescriptor(descriptor); err != nil {
		return RepositoryDescriptor{}, false, err
	}
	return descriptor, true, nil
}

func validateRepositoryDescriptor(descriptor RepositoryDescriptor) error {
	if descriptor.Format != RepositoryDescriptorFormat || descriptor.RepositoryID.IsZero() {
		return fmt.Errorf("%w: invalid repository descriptor identity", ErrCorruptObject)
	}
	if descriptor.RepositoryPrefix != strings.Trim(descriptor.RepositoryPrefix, "/") ||
		!utf8.ValidString(descriptor.RepositoryPrefix) || strings.ContainsRune(descriptor.RepositoryPrefix, '\x00') {
		return fmt.Errorf("%w: invalid repository descriptor prefix", ErrCorruptObject)
	}
	switch descriptor.StorageProfile {
	case RepositoryStorageProfilePlaintextV1:
	case RepositoryStorageProfileStrictShareIsolationV1:
		if descriptor.RepositoryPrefix == "" {
			return fmt.Errorf("%w: encrypted descriptor requires a prefix", ErrCorruptObject)
		}
	default:
		return fmt.Errorf("%w: unknown repository storage profile", ErrCorruptObject)
	}
	if descriptor.Chunking.Algorithm != repositoryChunkingAlgorithm {
		return fmt.Errorf("%w: unknown repository chunking algorithm", ErrCorruptObject)
	}
	chunking := descriptor.ChunkingOptions()
	normalized, err := chunking.normalized()
	if err != nil || normalized != chunking {
		return fmt.Errorf("%w: invalid repository chunking profile", ErrCorruptObject)
	}
	return nil
}

func (repository *Repository) setDescriptor(descriptor RepositoryDescriptor) {
	repository.descriptor = &descriptor
}
