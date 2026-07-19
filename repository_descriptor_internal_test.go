package s3disk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync/atomic"
	"testing"
)

func TestRepositoryDescriptorRejectsCorruptBoundaries(t *testing.T) {
	t.Parallel()

	repositoryID, err := GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	config := RepositoryConfig{RepositoryID: repositoryID}
	valid, _, err := descriptorConfiguration("tenant/descriptor-boundaries", config)
	if err != nil {
		t.Fatal(err)
	}
	validData, err := canonicalJSON(valid)
	if err != nil {
		t.Fatal(err)
	}

	unknownFormat := valid
	unknownFormat.Format = RepositoryDescriptorFormat + 1
	unknownFormatData, err := canonicalJSON(unknownFormat)
	if err != nil {
		t.Fatal(err)
	}
	unknownProfile := valid
	unknownProfile.StorageProfile = RepositoryStorageProfile("future-profile-v9")
	unknownProfileData, err := canonicalJSON(unknownProfile)
	if err != nil {
		t.Fatal(err)
	}
	zeroID := valid
	zeroID.RepositoryID = RepositoryID{}
	zeroIDData, err := canonicalJSON(zeroID)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{name: "non-canonical JSON", data: append(append([]byte(nil), validData...), ' ')},
		{name: "unknown format", data: unknownFormatData},
		{name: "unknown storage profile", data: unknownProfileData},
		{name: "zero repository ID", data: zeroIDData},
		{name: "oversized object", data: bytes.Repeat([]byte{'x'}, MaximumRepositoryDescriptorBytes+1)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &repositoryDescriptorBoundaryStore{data: append([]byte(nil), test.data...)}
			if _, _, err := OpenRepository(
				context.Background(), store, "tenant/descriptor-boundaries", config,
			); !errors.Is(err, ErrCorruptObject) {
				t.Fatalf("OpenRepository error = %v, want ErrCorruptObject", err)
			}
			if got := store.calls.Load(); got != 1 {
				t.Fatalf("Store calls = %d, want one bounded descriptor GET", got)
			}
		})
	}
}

func TestRepositoryDescriptorAPIsRejectNilContextBeforeIO(t *testing.T) {
	t.Parallel()

	repositoryID, err := GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	config := RepositoryConfig{RepositoryID: repositoryID}
	tests := []struct {
		name string
		call func(*repositoryDescriptorBoundaryStore) error
	}{
		{
			name: "initialize",
			call: func(store *repositoryDescriptorBoundaryStore) error {
				_, _, err := InitializeRepository(
					nil, store, "tenant/nil-context", config,
					RepositoryInitializationOptions{ConfirmEmptyPrefix: true},
				)
				return err
			},
		},
		{
			name: "open writable",
			call: func(store *repositoryDescriptorBoundaryStore) error {
				_, _, err := OpenRepository(nil, store, "tenant/nil-context", config)
				return err
			},
		},
		{
			name: "open read-only",
			call: func(store *repositoryDescriptorBoundaryStore) error {
				_, _, err := OpenReadOnlyRepository(nil, store, "tenant/nil-context", config)
				return err
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := new(repositoryDescriptorBoundaryStore)
			if err := test.call(store); err == nil {
				t.Fatal("nil context was accepted")
			}
			if got := store.calls.Load(); got != 0 {
				t.Fatalf("nil-context call performed %d Store operations", got)
			}
		})
	}
}

func TestRepositoryDescriptorConfigurationIdentityMismatchHasNoIO(t *testing.T) {
	t.Parallel()

	profileRepositoryID, err := GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	configuredRepositoryID, err := GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	key, err := GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewClientEncryptionProfile(profileRepositoryID, key)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		config RepositoryConfig
	}{
		{name: "zero repository ID", config: RepositoryConfig{}},
		{
			name: "client encryption repository ID mismatch",
			config: RepositoryConfig{
				RepositoryID: configuredRepositoryID, ClientEncryption: profile,
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			for _, operation := range []struct {
				name string
				call func(*repositoryDescriptorBoundaryStore) error
			}{
				{
					name: "initialize",
					call: func(store *repositoryDescriptorBoundaryStore) error {
						_, _, err := InitializeRepository(
							context.Background(), store, "tenant/identity-mismatch", test.config,
							RepositoryInitializationOptions{ConfirmEmptyPrefix: true},
						)
						return err
					},
				},
				{
					name: "open writable",
					call: func(store *repositoryDescriptorBoundaryStore) error {
						_, _, err := OpenRepository(context.Background(), store, "tenant/identity-mismatch", test.config)
						return err
					},
				},
				{
					name: "open read-only",
					call: func(store *repositoryDescriptorBoundaryStore) error {
						_, _, err := OpenReadOnlyRepository(context.Background(), store, "tenant/identity-mismatch", test.config)
						return err
					},
				},
			} {
				t.Run(operation.name, func(t *testing.T) {
					t.Parallel()
					store := new(repositoryDescriptorBoundaryStore)
					if err := operation.call(store); !errors.Is(err, ErrRepositoryConfigurationMismatch) {
						t.Fatalf("error = %v, want ErrRepositoryConfigurationMismatch", err)
					}
					if got := store.calls.Load(); got != 0 {
						t.Fatalf("invalid configuration performed %d Store operations", got)
					}
				})
			}
		})
	}
}

func TestConsumerRejectsVerifierRepositoryIDDifferentFromDescriptor(t *testing.T) {
	t.Parallel()

	descriptorRepositoryID, err := GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	store := new(repositoryDescriptorBoundaryStore)
	repository, descriptor, err := configuredWritableRepository(
		store,
		"tenant/consumer-descriptor",
		RepositoryConfig{RepositoryID: descriptorRepositoryID},
	)
	if err != nil {
		t.Fatal(err)
	}
	repository.setDescriptor(descriptor)

	verifierRepositoryID, err := GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewEd25519ReferenceVerifier(
		verifierRepositoryID,
		map[string]ed25519.PublicKey{"consumer-mismatch": publicKey},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewConsumer(repository, "main", ConsumerOptions{
		ReferenceVerifier: verifier,
	}); !errors.Is(err, ErrUntrustedReference) {
		t.Fatalf("NewConsumer error = %v, want ErrUntrustedReference", err)
	}
	if got := store.calls.Load(); got != 0 {
		t.Fatalf("verifier mismatch performed %d Store operations", got)
	}
}

func FuzzOpenRepositoryDescriptorNeverPanics(f *testing.F) {
	var repositoryID RepositoryID
	repositoryID[0] = 1
	config := RepositoryConfig{RepositoryID: repositoryID}
	valid, _, err := descriptorConfiguration("tenant/fuzz-descriptor", config)
	if err != nil {
		f.Fatal(err)
	}
	validData, err := canonicalJSON(valid)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{})
	f.Add([]byte("{}"))
	f.Add(validData)

	f.Fuzz(func(t *testing.T, data []byte) {
		store := &repositoryDescriptorBoundaryStore{data: append([]byte{}, data...)}
		_, _, _ = OpenRepository(context.Background(), store, "tenant/fuzz-descriptor", config)
	})
}

type repositoryDescriptorBoundaryStore struct {
	data  []byte
	calls atomic.Int64
}

func (store *repositoryDescriptorBoundaryStore) Get(ctx context.Context, _ string, _ GetOptions) (Object, error) {
	store.calls.Add(1)
	if err := ctx.Err(); err != nil {
		return Object{}, err
	}
	if store.data == nil {
		return Object{}, ErrObjectNotFound
	}
	return Object{
		Data: append([]byte(nil), store.data...),
		Version: Version{
			ETag: "repository-descriptor-boundary",
		},
	}, nil
}

func (store *repositoryDescriptorBoundaryStore) Head(ctx context.Context, _ string) (Version, error) {
	store.calls.Add(1)
	if err := ctx.Err(); err != nil {
		return Version{}, err
	}
	return Version{}, ErrObjectNotFound
}

func (store *repositoryDescriptorBoundaryStore) PutIfAbsent(ctx context.Context, _ string, _ []byte) (Version, error) {
	store.calls.Add(1)
	if err := ctx.Err(); err != nil {
		return Version{}, err
	}
	return Version{ETag: "repository-descriptor-boundary-put"}, nil
}

func (store *repositoryDescriptorBoundaryStore) CompareAndSwap(ctx context.Context, _ string, _ *Version, _ []byte) (Version, error) {
	store.calls.Add(1)
	if err := ctx.Err(); err != nil {
		return Version{}, err
	}
	return Version{ETag: "repository-descriptor-boundary-cas"}, nil
}
