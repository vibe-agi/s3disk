//go:build integration

package s3store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/vibe-agi/s3disk"
)

func TestMinIOAtomicPublishAndLazyRead(t *testing.T) {
	endpoint := os.Getenv("S3DISK_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("S3DISK_TEST_S3_ENDPOINT is not set")
	}
	accessKey := envOr("S3DISK_TEST_S3_ACCESS_KEY", "s3disk")
	secretKey := envOr("S3DISK_TEST_S3_SECRET_KEY", "s3disk-secret")
	bucket := fmt.Sprintf("s3disk-test-%d", time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	createBucketWithRetry(t, ctx, endpoint, accessKey, secretKey, bucket)

	store, err := New(ctx, Config{
		Bucket:   bucket,
		Region:   "us-east-1",
		Endpoint: endpoint,
		CredentialsProvider: CredentialsProviderFunc(func(context.Context) (Credentials, error) {
			return Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}, nil
		}),
		UsePathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := s3disk.NewRepository(store, "integration")
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.CheckStoreCompatibility(ctx); err != nil {
		t.Fatalf("store compatibility: %v", err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "hello.txt"), []byte("hello from MinIO"), 0o644); err != nil {
		t.Fatal(err)
	}

	first, err := publisher.Stage(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Commit(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "hello.txt"), []byte("stale candidate"), 0o644); err != nil {
		t.Fatal(err)
	}
	staleStage, err := publisher.Stage(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "hello.txt"), []byte("winner candidate"), 0o644); err != nil {
		t.Fatal(err)
	}
	winnerStage, err := publisher.Stage(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Commit(ctx, winnerStage); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Commit(ctx, staleStage); !errors.Is(err, s3disk.ErrPublishConflict) {
		t.Fatalf("losing conditional commit error = %v, want publish conflict", err)
	}

	cache, err := s3disk.NewDiskCache(privateIntegrationDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cache.Close() })
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{Cache: cache})
	if err != nil {
		t.Fatal(err)
	}
	result, err := consumer.Refresh(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Generation != 2 {
		t.Fatalf("generation = %d, want 2", result.Generation)
	}
	file, err := consumer.Open(ctx, "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, file.Size())
	if _, err := file.ReadAtContext(ctx, data, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(data) != "winner candidate" {
		t.Fatalf("read = %q", data)
	}

	// Exercise the independent authenticated-reference namespace against the
	// real conditional S3 adapter as well as the in-memory fault tests.
	repositoryID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := s3disk.NewEd25519ReferenceSigner(repositoryID, "minio-online", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := s3disk.NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{"minio-online": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	signedRepository, err := s3disk.NewRepository(store, "integration-signed")
	if err != nil {
		t.Fatal(err)
	}
	publicationJournal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateIntegrationDirectory(t), "signed-publisher.journal"))
	if err != nil {
		t.Fatal(err)
	}
	signedPublisher, err := s3disk.NewPublisher(signedRepository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ReferenceSigner:                          signer, ReferenceVerifier: verifier,
		PublicationJournal: publicationJournal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	signedSnapshot, err := signedPublisher.Publish(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	watermarks, err := s3disk.NewFileWatermarkStore(filepath.Join(privateIntegrationDirectory(t), "signed.watermark"))
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := s3disk.Watermark{
		RepositoryID: repositoryID, Generation: signedSnapshot.Generation, Commit: signedSnapshot.Commit,
	}
	signedConsumer, err := s3disk.NewConsumer(signedRepository, "main", s3disk.ConsumerOptions{
		ReferenceVerifier: verifier, Watermarks: watermarks, TrustedCheckpoint: &checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := signedConsumer.Refresh(ctx); err != nil || result.Generation != 1 {
		t.Fatalf("signed MinIO refresh = %+v, %v", result, err)
	}
}

func createBucketWithRetry(t *testing.T, ctx context.Context, endpoint, accessKey, secretKey, bucket string) {
	t.Helper()
	configuration, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	if err != nil {
		t.Fatal(err)
	}
	client := s3.NewFromConfig(configuration, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(endpoint)
		options.UsePathStyle = true
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("create MinIO test bucket: %v", err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func privateIntegrationDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("protect integration-test state directory: %v", err)
	}
	return directory
}
