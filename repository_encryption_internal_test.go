package s3disk

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRepositoryClientEncryptionUsesOpaqueStableObjectKeys(t *testing.T) {
	repositoryID, err := GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	key, err := GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewClientEncryptionProfile(repositoryID, key)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewRepositoryWithOptions(repositoryEncryptionNoopStore{}, "private/share", RepositoryOptions{
		ClientEncryption: profile,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := digestObject("chunk", []byte("predictable customer content"))
	physicalKey := repository.objectKey("chunk", digest)
	if !strings.Contains(physicalKey, "/objects/chunk/hmac-sha256/") {
		t.Fatalf("opaque object key = %q", physicalKey)
	}
	if strings.Contains(physicalKey, digest.String()) {
		t.Fatalf("opaque object key exposed plaintext digest %s", digest)
	}
	if again := repository.objectKey("chunk", digest); again != physicalKey {
		t.Fatalf("opaque object key changed: %q != %q", again, physicalKey)
	}

	otherKey, err := GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	otherProfile, err := NewClientEncryptionProfile(repositoryID, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	otherRepository, err := NewRepositoryWithOptions(repositoryEncryptionNoopStore{}, "private/share", RepositoryOptions{
		ClientEncryption: otherProfile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if otherRepository.objectKey("chunk", digest) == physicalKey {
		t.Fatal("different share keys produced the same physical object key")
	}

	plainRepository, err := NewRepository(repositoryEncryptionNoopStore{}, "private/share")
	if err != nil {
		t.Fatal(err)
	}
	if plainKey := plainRepository.objectKey("chunk", digest); !strings.Contains(plainKey, "/objects/chunk/sha256/") ||
		!strings.Contains(plainKey, digest.String()) {
		t.Fatalf("legacy repository key changed unexpectedly: %q", plainKey)
	}
}

func TestRepositoryClientEncryptionRequiresDedicatedPrefix(t *testing.T) {
	repositoryID, err := GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	key, err := GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewClientEncryptionProfile(repositoryID, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepositoryWithOptions(repositoryEncryptionNoopStore{}, "", RepositoryOptions{ClientEncryption: profile}); err == nil {
		t.Fatal("client-encrypted repository accepted an empty shared namespace")
	}
}

func TestRepositoryClientEncryptionIgnoresExternalAppliedClaim(t *testing.T) {
	repositoryID, err := GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	key, err := GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewClientEncryptionProfile(repositoryID, key)
	if err != nil {
		t.Fatal(err)
	}
	backing := &repositoryEncryptionLyingStore{}
	repository, err := NewRepositoryWithOptions(backing, "private/lying-store", RepositoryOptions{
		ClientEncryption: profile,
	})
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("a structural marker must not bypass writable encryption")
	digest, err := repository.putImmutable(context.Background(), "chunk", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	wantKey := repository.objectKey("chunk", digest)
	if backing.putKey != wantKey {
		t.Fatalf("backing PutIfAbsent key = %q, want %q", backing.putKey, wantKey)
	}
	if bytes.Equal(backing.putData, plaintext) || bytes.Contains(backing.putData, plaintext) {
		t.Fatal("lying Store received plaintext after claiming client encryption was already applied")
	}
	opened, err := profile.OpenObject(wantKey, backing.putData)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("backing ciphertext opened to %q, want %q", opened, plaintext)
	}
}

type repositoryEncryptionNoopStore struct{}

func (repositoryEncryptionNoopStore) Get(context.Context, string, GetOptions) (Object, error) {
	return Object{}, ErrObjectNotFound
}

func (repositoryEncryptionNoopStore) Head(context.Context, string) (Version, error) {
	return Version{}, ErrObjectNotFound
}

func (repositoryEncryptionNoopStore) PutIfAbsent(context.Context, string, []byte) (Version, error) {
	return Version{ETag: "noop"}, nil
}

func (repositoryEncryptionNoopStore) CompareAndSwap(context.Context, string, *Version, []byte) (Version, error) {
	return Version{ETag: "noop"}, nil
}

type repositoryEncryptionLyingStore struct {
	putKey  string
	putData []byte
}

func (*repositoryEncryptionLyingStore) ClientEncryptionApplied(*ClientEncryptionProfile) bool {
	return true
}

func (*repositoryEncryptionLyingStore) Get(context.Context, string, GetOptions) (Object, error) {
	return Object{}, ErrObjectNotFound
}

func (*repositoryEncryptionLyingStore) Head(context.Context, string) (Version, error) {
	return Version{}, ErrObjectNotFound
}

func (store *repositoryEncryptionLyingStore) PutIfAbsent(_ context.Context, key string, data []byte) (Version, error) {
	store.putKey = key
	store.putData = append([]byte(nil), data...)
	return Version{ETag: "lying-store-put"}, nil
}

func (*repositoryEncryptionLyingStore) CompareAndSwap(context.Context, string, *Version, []byte) (Version, error) {
	return Version{ETag: "lying-store-cas"}, nil
}
