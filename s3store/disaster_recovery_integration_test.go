//go:build integration

package s3store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/vibe-agi/s3disk"
)

// TestMinIODisasterBackupRestoreAndKeyRetirement exercises a complete logical
// current-state backup and restore against real S3 semantics. It deliberately
// uses the provider API for inventory because s3disk's runtime Store has no
// List authority. The drill also restores the publisher journal and consumer
// watermark, retires the old reference-signing key, continues publication, and
// proves both stale and incomplete restores fail closed.
func TestMinIODisasterBackupRestoreAndKeyRetirement(t *testing.T) {
	endpoint := os.Getenv("S3DISK_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("S3DISK_TEST_S3_ENDPOINT is not set")
	}
	accessKey := envOr("S3DISK_TEST_S3_ACCESS_KEY", "s3disk")
	secretKey := envOr("S3DISK_TEST_S3_SECRET_KEY", "s3disk-secret")
	stamp := time.Now().UnixNano()
	sourceBucket := fmt.Sprintf("s3disk-dr-source-%d", stamp)
	backupBucket := fmt.Sprintf("s3disk-dr-backup-%d", stamp)
	restoredBucket := fmt.Sprintf("s3disk-dr-restored-%d", stamp)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	for _, bucket := range []string{sourceBucket, backupBucket, restoredBucket} {
		createBucketWithRetry(t, ctx, endpoint, accessKey, secretKey, bucket)
	}
	rawClient := minIOIntegrationClient(t, ctx, endpoint, accessKey, secretKey)

	sourceStore := newMinIOIntegrationStore(t, ctx, endpoint, accessKey, secretKey, sourceBucket)
	repositoryID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	const (
		repositoryPrefix = "disaster-recovery"
		channel          = "main"
		sharedPath       = "workspace/shared.txt"
	)
	config := s3disk.RepositoryConfig{RepositoryID: repositoryID}
	sourceRepository, _, err := s3disk.InitializeRepository(
		ctx, sourceStore, repositoryPrefix, config,
		s3disk.RepositoryInitializationOptions{ConfirmEmptyPrefix: true},
	)
	if err != nil {
		t.Fatal(err)
	}

	oldPublic, oldPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPublic, newPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldSigner, err := s3disk.NewEd25519ReferenceSigner(repositoryID, "reference-2026-old", oldPrivate)
	if err != nil {
		t.Fatal(err)
	}
	newSigner, err := s3disk.NewEd25519ReferenceSigner(repositoryID, "reference-2026-new", newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	overlapVerifier, err := s3disk.NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{
		"reference-2026-old": oldPublic,
		"reference-2026-new": newPublic,
	})
	if err != nil {
		t.Fatal(err)
	}
	newOnlyVerifier, err := s3disk.NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{
		"reference-2026-new": newPublic,
	})
	if err != nil {
		t.Fatal(err)
	}

	liveStateDirectory := privateIntegrationDirectory(t)
	journalPath := filepath.Join(liveStateDirectory, "publisher.journal")
	watermarkPath := filepath.Join(liveStateDirectory, "consumer.watermark")
	journal, err := s3disk.NewFilePublicationJournal(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	oldPublisher, err := s3disk.NewPublisher(sourceRepository, s3disk.PublisherOptions{
		ReferenceSigner: oldSigner, ReferenceVerifier: overlapVerifier,
		PublicationJournal: journal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	source := privateIntegrationDirectory(t)
	writeDisasterRecoveryFile(t, filepath.Join(source, sharedPath), "generation one: old signing key")
	first, err := oldPublisher.Publish(ctx, source, channel)
	if err != nil {
		t.Fatal(err)
	}
	oldEnvelope, err := sourceStore.Get(ctx, sourceRepository.SignedReferenceKey(channel), s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	watermarks, err := s3disk.NewFileWatermarkStore(watermarkPath)
	if err != nil {
		t.Fatal(err)
	}
	firstCheckpoint := s3disk.Watermark{
		RepositoryID: repositoryID, Generation: first.Generation, Commit: first.Commit,
	}
	consumer, err := s3disk.NewConsumer(sourceRepository, channel, s3disk.ConsumerOptions{
		ReferenceVerifier: overlapVerifier, Watermarks: watermarks,
		RequirePersistentWatermark: true, TrustedCheckpoint: &firstCheckpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := consumer.Refresh(ctx); err != nil || result.Generation != 1 {
		t.Fatalf("initial signed refresh = %+v, %v", result, err)
	}

	rotatingPublisher, err := s3disk.NewPublisher(sourceRepository, s3disk.PublisherOptions{
		ReferenceSigner: newSigner, ReferenceVerifier: overlapVerifier,
		PublicationJournal: journal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resigned, err := rotatingPublisher.ResignReference(ctx, channel); err != nil || resigned.Generation != 1 {
		t.Fatalf("resign generation one = %+v, %v", resigned, err)
	}
	resignedEnvelope, err := sourceStore.Get(ctx, sourceRepository.SignedReferenceKey(channel), s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s3disk.VerifySnapshotReference(ctx, oldEnvelope.Data, channel, newOnlyVerifier); !errors.Is(err, s3disk.ErrUntrustedReference) {
		t.Fatalf("retired old signing key verification error = %v, want ErrUntrustedReference", err)
	}
	if identity, err := s3disk.VerifySnapshotReference(ctx, resignedEnvelope.Data, channel, newOnlyVerifier); err != nil || identity.Generation != 1 {
		t.Fatalf("new signing key verification = %+v, %v", identity, err)
	}

	writeDisasterRecoveryFile(t, filepath.Join(source, sharedPath), "generation two: backed up")
	second, err := rotatingPublisher.Publish(ctx, source, channel)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := consumer.Refresh(ctx); err != nil || result.Generation != second.Generation {
		t.Fatalf("pre-backup refresh = %+v, %v", result, err)
	}
	assertDisasterRecoveryFile(t, ctx, consumer, sharedPath, "generation two: backed up")

	backupStateDirectory := privateIntegrationDirectory(t)
	copyDurableStateFile(t, journalPath, filepath.Join(backupStateDirectory, "publisher.journal"))
	copyDurableStateFile(t, watermarkPath, filepath.Join(backupStateDirectory, "consumer.watermark"))
	sourceInventory := copyMinIOBucket(t, ctx, rawClient, sourceBucket, backupBucket)
	if len(sourceInventory) < 4 {
		t.Fatalf("backup inventory contains only %d objects", len(sourceInventory))
	}
	if backupInventory := inventoryMinIOBucket(t, ctx, rawClient, backupBucket); !equalObjectInventories(sourceInventory, backupInventory) {
		t.Fatal("backup bucket inventory differs from the source inventory")
	}

	deleteMinIOBucketContents(t, ctx, rawClient, sourceBucket)
	if remaining := inventoryMinIOBucket(t, ctx, rawClient, sourceBucket); len(remaining) != 0 {
		t.Fatalf("destroyed source bucket retains %d objects", len(remaining))
	}
	if err := os.RemoveAll(liveStateDirectory); err != nil {
		t.Fatalf("remove simulated lost local state: %v", err)
	}

	restoredInventory := copyMinIOBucket(t, ctx, rawClient, backupBucket, restoredBucket)
	if !equalObjectInventories(sourceInventory, restoredInventory) {
		t.Fatal("restored bucket inventory differs from the backed-up inventory")
	}
	restoredStateDirectory := privateIntegrationDirectory(t)
	restoredJournalPath := filepath.Join(restoredStateDirectory, "publisher.journal")
	restoredWatermarkPath := filepath.Join(restoredStateDirectory, "consumer.watermark")
	copyDurableStateFile(t, filepath.Join(backupStateDirectory, "publisher.journal"), restoredJournalPath)
	copyDurableStateFile(t, filepath.Join(backupStateDirectory, "consumer.watermark"), restoredWatermarkPath)

	restoredStore := newMinIOIntegrationStore(t, ctx, endpoint, accessKey, secretKey, restoredBucket)
	restoredRepository, _, err := s3disk.OpenRepository(ctx, restoredStore, repositoryPrefix, config)
	if err != nil {
		t.Fatal(err)
	}
	restoredWatermarks, err := s3disk.NewFileWatermarkStore(restoredWatermarkPath)
	if err != nil {
		t.Fatal(err)
	}
	restoredConsumer, err := s3disk.NewConsumer(restoredRepository, channel, s3disk.ConsumerOptions{
		ReferenceVerifier: newOnlyVerifier, Watermarks: restoredWatermarks,
		RequirePersistentWatermark: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := restoredConsumer.Refresh(ctx); err != nil || result.Generation != second.Generation {
		t.Fatalf("post-restore refresh = %+v, %v", result, err)
	}
	assertDisasterRecoveryFile(t, ctx, restoredConsumer, sharedPath, "generation two: backed up")

	restoredJournal, err := s3disk.NewFilePublicationJournal(restoredJournalPath)
	if err != nil {
		t.Fatal(err)
	}
	restoredPublisher, err := s3disk.NewPublisher(restoredRepository, s3disk.PublisherOptions{
		ReferenceSigner: newSigner, ReferenceVerifier: newOnlyVerifier,
		PublicationJournal: restoredJournal,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeDisasterRecoveryFile(t, filepath.Join(source, sharedPath), "generation three: continued after restore")
	third, err := restoredPublisher.Publish(ctx, source, channel)
	if err != nil {
		t.Fatal(err)
	}
	if third.Generation != second.Generation+1 {
		t.Fatalf("continued generation = %d, want %d", third.Generation, second.Generation+1)
	}
	if result, err := restoredConsumer.Refresh(ctx); err != nil || result.Generation != third.Generation {
		t.Fatalf("continued refresh = %+v, %v", result, err)
	}
	assertDisasterRecoveryFile(t, ctx, restoredConsumer, sharedPath, "generation three: continued after restore")

	currentEnvelope, err := restoredStore.Get(ctx, restoredRepository.SignedReferenceKey(channel), s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	staleVersion, err := restoredStore.CompareAndSwap(
		ctx, restoredRepository.SignedReferenceKey(channel), &currentEnvelope.Version, resignedEnvelope.Data,
	)
	if err != nil {
		t.Fatal(err)
	}
	restartedConsumer, err := s3disk.NewConsumer(restoredRepository, channel, s3disk.ConsumerOptions{
		ReferenceVerifier: newOnlyVerifier, Watermarks: restoredWatermarks,
		RequirePersistentWatermark: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restartedConsumer.Refresh(ctx); !errors.Is(err, s3disk.ErrRollbackDetected) {
		t.Fatalf("stale remote restore error = %v, want ErrRollbackDetected", err)
	}
	if _, err := restoredStore.CompareAndSwap(
		ctx, restoredRepository.SignedReferenceKey(channel), &staleVersion, currentEnvelope.Data,
	); err != nil {
		t.Fatalf("restore current reference after rollback check: %v", err)
	}

	closure, err := restoredRepository.ResolveSnapshotClosure(ctx, channel, s3disk.SnapshotClosureOptions{
		ReferenceVerifier: newOnlyVerifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	chunkKey := ""
	for _, key := range closure.ObjectKeys {
		if strings.Contains(key, "/objects/chunk/") {
			chunkKey = key
			break
		}
	}
	if chunkKey == "" {
		t.Fatal("restored snapshot closure contains no chunk object")
	}
	if err := restoredStore.Delete(ctx, chunkKey); err != nil {
		t.Fatal(err)
	}
	freshWatermarks, err := s3disk.NewFileWatermarkStore(filepath.Join(privateIntegrationDirectory(t), "incomplete.watermark"))
	if err != nil {
		t.Fatal(err)
	}
	thirdCheckpoint := s3disk.Watermark{
		RepositoryID: repositoryID, Generation: third.Generation, Commit: third.Commit,
	}
	incompleteConsumer, err := s3disk.NewConsumer(restoredRepository, channel, s3disk.ConsumerOptions{
		ReferenceVerifier: newOnlyVerifier, Watermarks: freshWatermarks,
		RequirePersistentWatermark: true, TrustedCheckpoint: &thirdCheckpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := incompleteConsumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	file, err := incompleteConsumer.Open(ctx, sharedPath)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, file.Size())
	if _, err := file.ReadAtContext(ctx, data, 0); !errors.Is(err, s3disk.ErrObjectNotFound) {
		t.Fatalf("incomplete restore read error = %v, want ErrObjectNotFound", err)
	}
}

func minIOIntegrationClient(t *testing.T, ctx context.Context, endpoint, accessKey, secretKey string) *s3.Client {
	t.Helper()
	configuration, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	if err != nil {
		t.Fatal(err)
	}
	return s3.NewFromConfig(configuration, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(endpoint)
		options.UsePathStyle = true
	})
}

func newMinIOIntegrationStore(t *testing.T, ctx context.Context, endpoint, accessKey, secretKey, bucket string) *Store {
	t.Helper()
	store, err := New(ctx, Config{
		Bucket: bucket, Region: "us-east-1", Endpoint: endpoint, UsePathStyle: true,
		CredentialsProvider: CredentialsProviderFunc(func(context.Context) (Credentials, error) {
			return Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func copyMinIOBucket(t *testing.T, ctx context.Context, client *s3.Client, source, destination string) map[string][sha256.Size]byte {
	t.Helper()
	inventory := make(map[string][sha256.Size]byte)
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: aws.String(source)})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			t.Fatalf("list backup source %q: %v", source, err)
		}
		for _, listed := range page.Contents {
			key := aws.ToString(listed.Key)
			object, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(source), Key: aws.String(key)})
			if err != nil {
				t.Fatalf("read backup object %q: %v", key, err)
			}
			data, readErr := io.ReadAll(io.LimitReader(object.Body, protocolMaxObjectBytes+1))
			closeErr := object.Body.Close()
			if readErr != nil || closeErr != nil {
				t.Fatalf("read backup object body %q: %v", key, errors.Join(readErr, closeErr))
			}
			if int64(len(data)) > protocolMaxObjectBytes {
				t.Fatalf("backup object %q exceeds adapter limit", key)
			}
			if _, err := client.PutObject(ctx, &s3.PutObjectInput{
				Bucket: aws.String(destination), Key: aws.String(key), Body: bytes.NewReader(data),
			}); err != nil {
				t.Fatalf("write backup object %q: %v", key, err)
			}
			inventory[key] = sha256.Sum256(data)
		}
	}
	return inventory
}

func inventoryMinIOBucket(t *testing.T, ctx context.Context, client *s3.Client, bucket string) map[string][sha256.Size]byte {
	t.Helper()
	inventory := make(map[string][sha256.Size]byte)
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			t.Fatalf("list bucket %q: %v", bucket, err)
		}
		for _, listed := range page.Contents {
			key := aws.ToString(listed.Key)
			object, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
			if err != nil {
				t.Fatalf("inventory object %q: %v", key, err)
			}
			data, readErr := io.ReadAll(io.LimitReader(object.Body, protocolMaxObjectBytes+1))
			closeErr := object.Body.Close()
			if readErr != nil || closeErr != nil {
				t.Fatalf("inventory object body %q: %v", key, errors.Join(readErr, closeErr))
			}
			if int64(len(data)) > protocolMaxObjectBytes {
				t.Fatalf("inventory object %q exceeds adapter limit", key)
			}
			inventory[key] = sha256.Sum256(data)
		}
	}
	return inventory
}

func deleteMinIOBucketContents(t *testing.T, ctx context.Context, client *s3.Client, bucket string) {
	t.Helper()
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			t.Fatalf("list destroyed bucket %q: %v", bucket, err)
		}
		for _, listed := range page.Contents {
			key := aws.ToString(listed.Key)
			if _, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}); err != nil {
				t.Fatalf("delete source object %q: %v", key, err)
			}
		}
	}
}

func equalObjectInventories(left, right map[string][sha256.Size]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for key, digest := range left {
		if right[key] != digest {
			return false
		}
	}
	return true
}

func copyDurableStateFile(t *testing.T, source, destination string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read durable state backup: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		t.Fatalf("create durable state restore directory: %v", err)
	}
	if err := os.WriteFile(destination, data, 0o600); err != nil {
		t.Fatalf("write durable state backup: %v", err)
	}
}

func writeDisasterRecoveryFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertDisasterRecoveryFile(t *testing.T, ctx context.Context, consumer *s3disk.Consumer, path, expected string) {
	t.Helper()
	file, err := consumer.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, file.Size())
	if _, err := file.ReadAtContext(ctx, data, 0); err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if string(data) != expected {
		t.Fatalf("restored file = %q, want %q", data, expected)
	}
}
