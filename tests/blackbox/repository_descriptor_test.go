package s3disk_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestRepositoryDescriptorInitializeOpenAndIdempotent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memstore.New()
	config := newDescriptorTestConfig(t, nil)

	repository, descriptor, err := s3disk.InitializeRepository(
		ctx, store, "tenant/descriptor", config,
		s3disk.RepositoryInitializationOptions{ConfirmEmptyPrefix: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	assertRepositoryDescriptor(t, repository, descriptor)
	if got, want := repository.DescriptorKey(), "tenant/descriptor/.s3disk/v1/repository"; got != want {
		t.Fatalf("descriptor key = %q, want %q", got, want)
	}

	again, againDescriptor, err := s3disk.InitializeRepository(
		ctx, store, "tenant/descriptor", config, s3disk.RepositoryInitializationOptions{},
	)
	if err != nil {
		t.Fatalf("idempotent initialize: %v", err)
	}
	assertRepositoryDescriptor(t, again, againDescriptor)
	if !reflect.DeepEqual(againDescriptor, descriptor) {
		t.Fatalf("idempotent descriptor = %#v, want %#v", againDescriptor, descriptor)
	}
	if got := store.Stats().Puts; got != 1 {
		t.Fatalf("descriptor puts = %d, want exactly one", got)
	}

	opened, openedDescriptor, err := s3disk.OpenRepository(ctx, store, "tenant/descriptor", config)
	if err != nil {
		t.Fatalf("open initialized repository: %v", err)
	}
	assertRepositoryDescriptor(t, opened, openedDescriptor)
	if !reflect.DeepEqual(openedDescriptor, descriptor) {
		t.Fatalf("opened descriptor = %#v, want %#v", openedDescriptor, descriptor)
	}

	readOnly, readOnlyDescriptor, err := s3disk.OpenReadOnlyRepository(ctx, store, "tenant/descriptor", config)
	if err != nil {
		t.Fatalf("open read-only initialized repository: %v", err)
	}
	assertRepositoryDescriptor(t, readOnly, readOnlyDescriptor)
	if _, err := s3disk.NewPublisher(readOnly, s3disk.PublisherOptions{}); !errors.Is(err, s3disk.ErrRepositoryReadOnly) {
		t.Fatalf("publisher over read-only repository error = %v, want ErrRepositoryReadOnly", err)
	}

	if _, _, err := s3disk.OpenRepository(ctx, store, "tenant/missing", config); !errors.Is(err, s3disk.ErrRepositoryNotInitialized) {
		t.Fatalf("open missing repository error = %v, want ErrRepositoryNotInitialized", err)
	}
}

func TestRepositoryDescriptorRequiresEmptyPrefixConfirmationBeforeCreate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memstore.New()
	config := newDescriptorTestConfig(t, nil)
	if _, _, err := s3disk.InitializeRepository(
		ctx, store, "tenant/unconfirmed-empty-prefix", config,
		s3disk.RepositoryInitializationOptions{},
	); !errors.Is(err, s3disk.ErrRepositoryNotInitialized) {
		t.Fatalf("unconfirmed initialize error = %v, want ErrRepositoryNotInitialized", err)
	}
	stats := store.Stats()
	if stats.Puts != 0 || stats.BytesWritten != 0 {
		t.Fatalf("unconfirmed initialization wrote descriptor data: %+v", stats)
	}
}

func TestRepositoryDescriptorRejectsDifferentConfiguration(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memstore.New()
	config := newDescriptorTestConfig(t, nil)
	_, original, err := s3disk.InitializeRepository(
		ctx, store, "tenant/configuration", config,
		s3disk.RepositoryInitializationOptions{ConfirmEmptyPrefix: true},
	)
	if err != nil {
		t.Fatal(err)
	}

	different := config
	different.Chunking = s3disk.ChunkingOptions{
		MinSize: 128 << 10, AverageSize: 2 << 20, MaxSize: 8 << 20,
	}
	if _, _, err := s3disk.InitializeRepository(
		ctx, store, "tenant/configuration", different, s3disk.RepositoryInitializationOptions{},
	); !errors.Is(err, s3disk.ErrRepositoryConfigurationMismatch) {
		t.Fatalf("different initialize error = %v, want ErrRepositoryConfigurationMismatch", err)
	}
	if _, _, err := s3disk.OpenRepository(ctx, store, "tenant/configuration", different); !errors.Is(err, s3disk.ErrRepositoryConfigurationMismatch) {
		t.Fatalf("different open error = %v, want ErrRepositoryConfigurationMismatch", err)
	}

	opened, got, err := s3disk.OpenRepository(ctx, store, "tenant/configuration", config)
	if err != nil {
		t.Fatalf("open original after mismatched attempts: %v", err)
	}
	assertRepositoryDescriptor(t, opened, got)
	if !reflect.DeepEqual(got, original) {
		t.Fatalf("descriptor changed after mismatch: got %#v, want %#v", got, original)
	}
	if gotPuts := store.Stats().Puts; gotPuts != 1 {
		t.Fatalf("puts after mismatched attempts = %d, want 1", gotPuts)
	}
}

func TestRepositoryDescriptorConcurrentInitializationIsIdempotent(t *testing.T) {
	t.Parallel()

	const workers = 16
	ctx := context.Background()
	store := memstore.New()
	config := newDescriptorTestConfig(t, nil)
	start := make(chan struct{})
	errorsByWorker := make(chan error, workers)
	descriptors := make(chan s3disk.RepositoryDescriptor, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			repository, descriptor, err := s3disk.InitializeRepository(
				ctx, store, "tenant/concurrent", config,
				s3disk.RepositoryInitializationOptions{ConfirmEmptyPrefix: true},
			)
			if err == nil {
				if observed, ok := repository.Descriptor(); !ok || !reflect.DeepEqual(observed, descriptor) {
					err = errors.New("initialized repository did not retain its descriptor")
				}
			}
			if err != nil {
				errorsByWorker <- err
				return
			}
			descriptors <- descriptor
		}()
	}
	close(start)
	wait.Wait()
	close(errorsByWorker)
	close(descriptors)
	for err := range errorsByWorker {
		t.Errorf("concurrent initialize: %v", err)
	}
	var first *s3disk.RepositoryDescriptor
	for descriptor := range descriptors {
		if first == nil {
			copy := descriptor
			first = &copy
			continue
		}
		if !reflect.DeepEqual(descriptor, *first) {
			t.Errorf("concurrent descriptor = %#v, want %#v", descriptor, *first)
		}
	}
	if first == nil {
		t.Fatal("no concurrent initializer succeeded")
	}
	if got := store.Stats().Puts; got != 1 {
		t.Fatalf("concurrent descriptor puts = %d, want 1", got)
	}
}

func TestEncryptedRepositoryDescriptorIsCiphertextAndRejectsWrongKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memstore.New()
	repositoryID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	key, err := s3disk.GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := s3disk.NewClientEncryptionProfile(repositoryID, key)
	if err != nil {
		t.Fatal(err)
	}
	config := s3disk.RepositoryConfig{RepositoryID: repositoryID, ClientEncryption: profile}
	repository, descriptor, err := s3disk.InitializeRepository(
		ctx, store, "tenant/encrypted-descriptor", config,
		s3disk.RepositoryInitializationOptions{ConfirmEmptyPrefix: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	assertRepositoryDescriptor(t, repository, descriptor)

	raw, err := store.Get(ctx, repository.DescriptorKey(), s3disk.GetOptions{MaxBytes: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw.Data, []byte(repositoryID.String())) || bytes.Contains(raw.Data, []byte("repository_id")) {
		t.Fatal("raw descriptor exposed canonical plaintext")
	}
	plaintext, err := profile.OpenObject(repository.DescriptorKey(), raw.Data)
	if err != nil {
		t.Fatalf("open raw descriptor envelope: %v", err)
	}
	if !bytes.Contains(plaintext, []byte(repositoryID.String())) || !bytes.Contains(plaintext, []byte("repository_id")) {
		t.Fatalf("opened descriptor does not contain expected canonical identity: %q", plaintext)
	}

	wrongKey, err := s3disk.GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	wrongProfile, err := s3disk.NewClientEncryptionProfile(repositoryID, wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongConfig := config
	wrongConfig.ClientEncryption = wrongProfile
	if _, _, err := s3disk.OpenRepository(ctx, store, "tenant/encrypted-descriptor", wrongConfig); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("wrong-key open error = %v, want ErrCorruptObject", err)
	}
	if _, _, err := s3disk.OpenReadOnlyRepository(ctx, store, "tenant/encrypted-descriptor", wrongConfig); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("wrong-key read-only open error = %v, want ErrCorruptObject", err)
	}
}

func TestRepositoryDescriptorRejectsUnannouncedEncryptedStoreWithoutIO(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backing := memstore.New()
	repositoryID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	key, err := s3disk.GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := s3disk.NewClientEncryptionProfile(repositoryID, key)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := s3disk.NewClientEncryptedStore(backing, profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s3disk.InitializeRepository(ctx, wrapped, "tenant/unannounced-encryption", s3disk.RepositoryConfig{
		RepositoryID: repositoryID,
	}, s3disk.RepositoryInitializationOptions{ConfirmEmptyPrefix: true}); !errors.Is(err, s3disk.ErrRepositoryConfigurationMismatch) {
		t.Fatalf("InitializeRepository error = %v, want ErrRepositoryConfigurationMismatch", err)
	}
	stats := backing.Stats()
	if stats.Gets != 0 || stats.Heads != 0 || stats.Puts != 0 || stats.BytesRead != 0 || stats.BytesWritten != 0 {
		t.Fatalf("invalid initialization performed backing I/O: %+v", stats)
	}
}

func TestRepositoryDescriptorReconcilesLostPutResponse(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backing := memstore.New()
	store := &descriptorLostPutResponseStore{Store: backing}
	config := newDescriptorTestConfig(t, nil)
	repository, descriptor, err := s3disk.InitializeRepository(
		ctx, store, "tenant/lost-put", config,
		s3disk.RepositoryInitializationOptions{ConfirmEmptyPrefix: true},
	)
	if err != nil {
		t.Fatalf("initialize after applied PutIfAbsent response loss: %v", err)
	}
	assertRepositoryDescriptor(t, repository, descriptor)
	if got := backing.Stats().Puts; got != 1 {
		t.Fatalf("backing puts = %d, want 1", got)
	}
	if got := store.losses.Load(); got != 1 {
		t.Fatalf("injected lost responses = %d, want 1", got)
	}

	indeterminate := &descriptorIndeterminateStore{Store: memstore.New()}
	if _, _, err := s3disk.InitializeRepository(
		ctx, indeterminate, "tenant/indeterminate", config,
		s3disk.RepositoryInitializationOptions{ConfirmEmptyPrefix: true},
	); !errors.Is(err, s3disk.ErrRepositoryInitializationIndeterminate) {
		t.Fatalf("unreconciled initialize error = %v, want ErrRepositoryInitializationIndeterminate", err)
	}
}

func TestPublisherBindsRepositoryDescriptorChunkingAndSignerIdentity(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memstore.New()
	config := newDescriptorTestConfig(t, nil)
	repository, _, err := s3disk.InitializeRepository(
		ctx, store, "tenant/publisher-bindings", config,
		s3disk.RepositoryInitializationOptions{ConfirmEmptyPrefix: true},
	)
	if err != nil {
		t.Fatal(err)
	}

	differentChunking := s3disk.ChunkingOptions{
		MinSize: 128 << 10, AverageSize: 2 << 20, MaxSize: 8 << 20,
	}
	if _, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{Chunking: differentChunking}); !errors.Is(err, s3disk.ErrRepositoryConfigurationMismatch) {
		t.Fatalf("publisher chunking mismatch error = %v, want ErrRepositoryConfigurationMismatch", err)
	}

	wrongID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	wrongSigner, wrongVerifier := descriptorTestSigner(t, wrongID, "wrong-repository")
	wrongJournal, err := s3disk.NewFilePublicationJournal(privateTestDirectory(t) + "/wrong-repository.journal")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: wrongSigner, ReferenceVerifier: wrongVerifier,
		PublicationJournal: wrongJournal, AllowTrustOnFirstUse: true,
	}); !errors.Is(err, s3disk.ErrUntrustedReference) {
		t.Fatalf("publisher signer repository mismatch error = %v, want ErrUntrustedReference", err)
	}

	matchingSigner, matchingVerifier := descriptorTestSigner(t, config.RepositoryID, "matching-repository")
	matchingJournal, err := s3disk.NewFilePublicationJournal(privateTestDirectory(t) + "/matching-repository.journal")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: matchingSigner, ReferenceVerifier: matchingVerifier,
		PublicationJournal: matchingJournal, AllowTrustOnFirstUse: true,
	}); err != nil {
		t.Fatalf("publisher with descriptor-matching signer: %v", err)
	}
}

func newDescriptorTestConfig(t testing.TB, profile *s3disk.ClientEncryptionProfile) s3disk.RepositoryConfig {
	t.Helper()
	repositoryID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	if profile != nil {
		repositoryID = profile.RepositoryID()
	}
	return s3disk.RepositoryConfig{RepositoryID: repositoryID, ClientEncryption: profile}
}

func assertRepositoryDescriptor(t testing.TB, repository *s3disk.Repository, want s3disk.RepositoryDescriptor) {
	t.Helper()
	if repository == nil {
		t.Fatal("repository is nil")
	}
	got, ok := repository.Descriptor()
	if !ok {
		t.Fatal("repository does not retain a verified descriptor")
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("repository descriptor = %#v, want %#v", got, want)
	}
}

func descriptorTestSigner(t testing.TB, repositoryID s3disk.RepositoryID, keyID string) (s3disk.ReferenceSigner, s3disk.ReferenceVerifier) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := s3disk.NewEd25519ReferenceSigner(repositoryID, keyID, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := s3disk.NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{keyID: publicKey})
	if err != nil {
		t.Fatal(err)
	}
	return signer, verifier
}

var errDescriptorPutResponseLost = errors.New("test: descriptor PutIfAbsent response lost")

type descriptorLostPutResponseStore struct {
	*memstore.Store
	lost   atomic.Bool
	losses atomic.Int64
}

func (store *descriptorLostPutResponseStore) PutIfAbsent(ctx context.Context, key string, data []byte) (s3disk.Version, error) {
	version, err := store.Store.PutIfAbsent(ctx, key, data)
	if err == nil && store.lost.CompareAndSwap(false, true) {
		store.losses.Add(1)
		return s3disk.Version{}, errDescriptorPutResponseLost
	}
	return version, err
}

type descriptorIndeterminateStore struct {
	*memstore.Store
	putAttempted atomic.Bool
}

func (store *descriptorIndeterminateStore) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	if store.putAttempted.Load() {
		return s3disk.Object{}, s3disk.ErrStoreUnavailable
	}
	return store.Store.Get(ctx, key, options)
}

func (store *descriptorIndeterminateStore) PutIfAbsent(context.Context, string, []byte) (s3disk.Version, error) {
	store.putAttempted.Store(true)
	return s3disk.Version{}, s3disk.ErrStoreUnavailable
}
