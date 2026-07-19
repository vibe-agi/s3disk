package presignedshare

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestRootPublisherClientEncryptionIsOpaqueAndReconcilesLostResponse(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	key, err := s3disk.GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := s3disk.NewClientEncryptionProfile(fixture.verifier.RepositoryID(), key)
	if err != nil {
		t.Fatal(err)
	}
	fixture.repository, err = s3disk.NewRepositoryWithOptions(fixture.base, fixture.repositoryPrefix,
		s3disk.RepositoryOptions{ClientEncryption: profile})
	if err != nil {
		t.Fatal(err)
	}
	fixture.snapshotPublisher, err = s3disk.NewPublisher(fixture.repository, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	closure := fixture.publish(t, "root bundle customer plaintext")
	faultStore := &rootPublisherFaultStore{base: fixture.base, losePutResponse: true}
	config := fixture.config(faultStore, 0)
	config.ClientEncryption = profile
	publisher, err := NewRootPublisher(config)
	if err != nil {
		t.Fatal(err)
	}

	publication, err := publisher.Create(context.Background(), closure)
	if err != nil {
		t.Fatal(err)
	}
	if !publication.Updated || publication.Revision != 1 || faultStore.putCalls.Load() != 1 {
		t.Fatalf("encrypted reconciled publication = %+v, puts=%d", publication, faultStore.putCalls.Load())
	}
	raw, err := fixture.base.Get(context.Background(), fixture.rootKey, s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw.Data, []byte("root bundle customer plaintext")) || bytes.Contains(raw.Data, []byte(`"payload"`)) {
		t.Fatal("raw S3 root exposed signed bundle or customer plaintext")
	}
	opened, err := profile.OpenObject(fixture.rootKey, raw.Data)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Decode(context.Background(), opened, fixture.verifier, DecodeOptions{
		RootCapability: fixture.rootCapability, RepositoryPrefix: fixture.repositoryPrefix,
		ReferenceKey: fixture.referenceKey, ShareID: fixture.shareID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Revision() != 1 || bundle.ReferenceCommit() != closure.Snapshot.Commit {
		t.Fatalf("decrypted bundle = %s", bundle)
	}
	if idempotent, err := publisher.Create(context.Background(), closure); err != nil || idempotent.Updated || idempotent.Revision != 1 {
		t.Fatalf("encrypted idempotent create = %+v, %v", idempotent, err)
	}
}

func TestRootPublisherRejectsSnapshotClosureEncryptionProfileMismatch(t *testing.T) {
	t.Run("encrypted root with plaintext closure", func(t *testing.T) {
		fixture := newRootPublisherFixture(t)
		closure := fixture.publish(t, "plaintext repository")
		profile := newRootPublisherEncryptionProfile(t, fixture)
		config := fixture.config(fixture.base, 0)
		config.ClientEncryption = profile
		publisher, err := NewRootPublisher(config)
		if err != nil {
			t.Fatal(err)
		}
		assertRootPublisherProfileMismatch(t, fixture, publisher, closure)
	})

	t.Run("plaintext root with encrypted closure", func(t *testing.T) {
		fixture := newRootPublisherFixture(t)
		profile := newRootPublisherEncryptionProfile(t, fixture)
		var err error
		fixture.repository, err = s3disk.NewRepositoryWithOptions(fixture.base, fixture.repositoryPrefix,
			s3disk.RepositoryOptions{ClientEncryption: profile})
		if err != nil {
			t.Fatal(err)
		}
		fixture.snapshotPublisher, err = s3disk.NewPublisher(fixture.repository, s3disk.PublisherOptions{})
		if err != nil {
			t.Fatal(err)
		}
		closure := fixture.publish(t, "encrypted repository")
		publisher := fixture.newPublisher(t, fixture.base, 0)
		assertRootPublisherProfileMismatch(t, fixture, publisher, closure)
	})
}

func newRootPublisherEncryptionProfile(t *testing.T, fixture *rootPublisherFixture) *s3disk.ClientEncryptionProfile {
	t.Helper()
	key, err := s3disk.GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := s3disk.NewClientEncryptionProfile(fixture.verifier.RepositoryID(), key)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func assertRootPublisherProfileMismatch(
	t *testing.T,
	fixture *rootPublisherFixture,
	publisher *RootPublisher,
	closure s3disk.SnapshotClosure,
) {
	t.Helper()
	before := fixture.presigner.callCount()
	for _, operation := range []struct {
		name string
		run  func() (RootPublication, error)
	}{
		{name: "Create", run: func() (RootPublication, error) {
			return publisher.Create(context.Background(), closure)
		}},
		{name: "Update", run: func() (RootPublication, error) {
			return publisher.Update(context.Background(), closure)
		}},
	} {
		t.Run(operation.name, func(t *testing.T) {
			if _, err := operation.run(); !errors.Is(err, s3disk.ErrInvalidSnapshotClosure) {
				t.Fatalf("%s profile mismatch error = %v, want ErrInvalidSnapshotClosure", operation.name, err)
			}
		})
	}
	if calls := fixture.presigner.callCount(); calls != before {
		t.Fatalf("profile mismatch minted %d exact capabilities", calls-before)
	}
	if _, err := fixture.base.Get(context.Background(), fixture.rootKey, s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrObjectNotFound) {
		t.Fatalf("profile mismatch wrote a share root: %v", err)
	}
}

func TestOnlyS3ReaderClientEncryptionKeepsImmutableObjectsLazy(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
	defer fixture.close()
	key, err := s3disk.GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := s3disk.NewClientEncryptionProfile(fixture.verifier.RepositoryID(), key)
	if err != nil {
		t.Fatal(err)
	}
	fixture.readerConfig.ClientEncryption = profile

	base := memstore.New()
	repository, err := s3disk.NewRepositoryWithOptions(base, "repo", s3disk.RepositoryOptions{ClientEncryption: profile})
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	const fileContents = "encrypted content fetched only when opened"
	if err := os.WriteFile(filepath.Join(source, "shared.txt"), []byte(fileContents), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := publisher.PublishSelected(context.Background(), source, "main", []string{"shared.txt"})
	if err != nil {
		t.Fatal(err)
	}
	closure, err := repository.ResolveSnapshotClosure(context.Background(), "main", s3disk.SnapshotClosureOptions{})
	if err != nil {
		t.Fatal(err)
	}

	objectPaths := make(map[string]string, len(closure.ObjectKeys))
	chunkPath := ""
	for index, objectKey := range closure.ObjectKeys {
		raw, err := base.Get(context.Background(), objectKey, s3disk.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		path := fmt.Sprintf("/object/%d", index)
		objectPaths[objectKey] = path
		fixture.store.setObject(path, objectResponse{data: raw.Data, etag: fmt.Sprintf(`"object-%d"`, index)})
		if bytes.Contains(raw.Data, []byte(fileContents)) {
			t.Fatalf("raw S3 object %q exposed customer plaintext", objectKey)
		}
		if bytes.Contains([]byte(objectKey), []byte(snapshot.Commit.String())) {
			t.Fatalf("physical object key exposed a plaintext digest: %q", objectKey)
		}
		if bytes.Contains([]byte(objectKey), []byte("/objects/chunk/")) {
			chunkPath = path
		}
	}
	if chunkPath == "" {
		t.Fatal("encrypted closure has no chunk")
	}
	plainRoot := fixture.publish(t, 1, snapshot.Generation, closure.ReferenceData, objectPaths, `"encrypted-root"`)
	encryptedRoot, err := profile.SealObject(readerRootKey, plainRoot)
	if err != nil {
		t.Fatal(err)
	}
	fixture.store.mu.Lock()
	fixture.store.bundle = encryptedRoot
	fixture.store.mu.Unlock()
	if bytes.Contains(encryptedRoot, closure.ReferenceData) || bytes.Contains(encryptedRoot, []byte(`"capabilities"`)) {
		t.Fatal("raw S3 root exposed reference metadata or capabilities")
	}

	reader := fixture.reader(t)
	recipientRepository, err := s3disk.NewReadOnlyRepositoryWithOptions(reader, "repo", s3disk.RepositoryOptions{ClientEncryption: profile})
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(recipientRepository, "main", s3disk.ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests := fixture.store.pathRequests(chunkPath); requests != 0 {
		t.Fatalf("metadata refresh eagerly fetched encrypted chunk %d times", requests)
	}
	file, err := consumer.Open(context.Background(), "shared.txt")
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, file.Size())
	if _, err := file.ReadAtContext(context.Background(), buffer, 0); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != fileContents || fixture.store.pathRequests(chunkPath) != 1 {
		t.Fatalf("lazy encrypted read = %q, chunk requests=%d", buffer, fixture.store.pathRequests(chunkPath))
	}
	if fixture.store.sawAuthorization() {
		t.Fatal("encrypted recipient added S3 credentials or an Authorization header")
	}

	wrongKey, err := s3disk.GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	wrongProfile, err := s3disk.NewClientEncryptionProfile(fixture.verifier.RepositoryID(), wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongConfig := fixture.readerConfig
	wrongConfig.ClientEncryption = wrongProfile
	wrongReader, err := NewReader(wrongConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongReader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("wrong share seed root error = %v, want ErrCorruptObject", err)
	}
}

func TestClientEncryptionIdentityBindingsAreFailClosed(t *testing.T) {
	fixture := newRootPublisherFixture(t)
	otherRepositoryID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	key, err := s3disk.GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := s3disk.NewClientEncryptionProfile(otherRepositoryID, key)
	if err != nil {
		t.Fatal(err)
	}
	config := fixture.config(fixture.base, 0)
	config.ClientEncryption = profile
	if _, err := NewRootPublisher(config); !errors.Is(err, ErrUntrustedBundle) {
		t.Fatalf("mismatched root publisher encryption identity error = %v", err)
	}

	readerFixture := newReaderFixture(t, time.Now().Add(time.Minute), ReaderConfig{})
	defer readerFixture.close()
	readerConfig := readerFixture.readerConfig
	readerConfig.ClientEncryption = profile
	if _, err := NewReader(readerConfig); err == nil {
		t.Fatal("NewReader accepted a client encryption profile for another repository identity")
	}
}
