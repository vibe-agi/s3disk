//go:build integration

package cli

import (
	"context"
	"crypto/ed25519"
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
	"github.com/vibe-agi/s3disk/presignedshare"
)

// TestMinIOCLIContinuousHandoffAndCredentialFreeRead exercises the real A-side CLI
// pipeline and reconstructs B's credential-free reader entirely from the
// generated handoff, then proves an A-side edit advances B through S3 alone.
// FUSE itself remains covered by mount's Linux integration.
func TestMinIOCLIContinuousHandoffAndCredentialFreeRead(t *testing.T) {
	endpoint := os.Getenv("S3DISK_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("S3DISK_TEST_S3_ENDPOINT is not set")
	}
	accessKey := integrationEnvOr("S3DISK_TEST_S3_ACCESS_KEY", "s3disk")
	secretKey := integrationEnvOr("S3DISK_TEST_S3_SECRET_KEY", "s3disk-secret")
	t.Setenv("AWS_ACCESS_KEY_ID", accessKey)
	t.Setenv("AWS_SECRET_ACCESS_KEY", secretKey)
	t.Setenv("AWS_REGION", defaultRegion)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	bucket := fmt.Sprintf("s3disk-cli-%d", time.Now().UnixNano())
	createIntegrationBucket(t, ctx, endpoint, accessKey, secretKey, bucket)

	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "hello.txt"), []byte("encrypted lazy hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	handoffPath := filepath.Join(t.TempDir(), "share.handoff")
	stateDir := filepath.Join(t.TempDir(), "state")
	publishContext, stopPublish := context.WithCancel(ctx)
	publishDone := make(chan error, 1)
	publisherStopped := false
	go func() {
		publishDone <- runPublish(publishContext, PublishOptions{
			Source: source, All: true, Bucket: bucket, Prefix: "cli-integration",
			Region: defaultRegion, Endpoint: endpoint, UsePathStyle: true, AllowInsecureEndpoint: true,
			Channel: defaultChannel, ExpiresIn: 10 * time.Minute, HandoffOut: handoffPath,
			StateDir: stateDir,
		})
	}()
	t.Cleanup(func() {
		if publisherStopped {
			return
		}
		stopPublish()
		select {
		case <-publishDone:
		case <-time.After(10 * time.Second):
			t.Error("continuous publisher did not stop")
		}
	})
	var (
		share decodedHandoff
		err   error
	)
	for deadline := time.Now().Add(20 * time.Second); ; {
		share, err = readHandoff(handoffPath)
		if err == nil {
			break
		}
		select {
		case publishErr := <-publishDone:
			publisherStopped = true
			t.Fatalf("publisher stopped before handoff: %v", publishErr)
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("handoff was not published: %v", err)
		}
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "B-MUST-NOT-HAVE-S3-CREDENTIALS")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "B-MUST-NOT-HAVE-S3-CREDENTIALS")
	verifier, err := s3disk.NewEd25519ReferenceVerifier(share.repository, map[string]ed25519.PublicKey{
		share.wire.ReferenceKeyID: share.publicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := presignedshare.NewReader(presignedshare.ReaderConfig{
		RootCapability: share.root, RepositoryPrefix: share.wire.RepositoryPrefix,
		ReferenceKey: share.wire.ReferenceKey, ShareID: share.shareID, Verifier: verifier,
		ClientEncryption: share.profile, AllowInsecureLoopback: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := s3disk.NewReadOnlyRepositoryWithOptions(reader, share.wire.RepositoryPrefix,
		s3disk.RepositoryOptions{ClientEncryption: share.profile})
	if err != nil {
		t.Fatal(err)
	}
	watermarks, err := s3disk.NewFileWatermarkStore(filepath.Join(t.TempDir(), "watermark.json"))
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, share.wire.Channel, s3disk.ConsumerOptions{
		Watermarks: watermarks, RequirePersistentWatermark: true,
		ReferenceVerifier: verifier, TrustedCheckpoint: &share.checkpoint,
		Symlinks: s3disk.SymlinkRejectExternal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	file, err := consumer.Open(ctx, "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, file.Size())
	if _, err := file.ReadAtContext(ctx, data, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(data) != "encrypted lazy hello" {
		t.Fatalf("read = %q", data)
	}
	if err := os.WriteFile(filepath.Join(source, "hello.txt"), []byte("updated only through S3"), 0o600); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(20 * time.Second); ; {
		if _, err := consumer.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		file, err = consumer.Open(ctx, "hello.txt")
		if err != nil {
			t.Fatal(err)
		}
		data = make([]byte, file.Size())
		if _, err := file.ReadAtContext(ctx, data, 0); err != nil && err != io.EOF {
			t.Fatal(err)
		}
		if string(data) == "updated only through S3" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("B did not observe A's update; last read = %q", data)
		}
		time.Sleep(100 * time.Millisecond)
	}
	stopPublish()
	if err := <-publishDone; err != nil {
		t.Fatalf("continuous publisher shutdown: %v", err)
	}
	publisherStopped = true
}

func createIntegrationBucket(t *testing.T, ctx context.Context, endpoint, accessKey, secretKey, bucket string) {
	t.Helper()
	configuration, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(defaultRegion),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	if err != nil {
		t.Fatal(err)
	}
	client := s3.NewFromConfig(configuration, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(endpoint)
		options.UsePathStyle = true
	})
	var lastErr error
	for attempt := 0; attempt < 50; attempt++ {
		_, lastErr = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
		if lastErr == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("create MinIO bucket: %v", lastErr)
}

func integrationEnvOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
