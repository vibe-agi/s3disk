//go:build integration

package webdav

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
	"github.com/vibe-agi/s3disk/s3store"
)

func TestMinIOWebDAVEndToEnd(t *testing.T) {
	endpoint := os.Getenv("S3DISK_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("S3DISK_TEST_S3_ENDPOINT is not set")
	}
	accessKey := webDAVIntegrationEnv("S3DISK_TEST_S3_ACCESS_KEY", "s3disk")
	secretKey := webDAVIntegrationEnv("S3DISK_TEST_S3_SECRET_KEY", "s3disk-secret")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	bucket := fmt.Sprintf("s3disk-webdav-%d", time.Now().UnixNano())
	createWebDAVMinIOBucket(t, ctx, endpoint, accessKey, secretKey, bucket)

	store, err := s3store.New(ctx, s3store.Config{
		Bucket: bucket, Region: "us-east-1", Endpoint: endpoint, UsePathStyle: true,
		AllowInsecureEndpoint: true,
		CredentialsProvider: s3store.CredentialsProviderFunc(func(context.Context) (s3store.Credentials, error) {
			return s3store.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := s3disk.NewRepository(store, "webdav-minio-integration")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	filePath := filepath.Join(source, "workspace.txt")
	if err := os.WriteFile(filePath, []byte("generation one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	watermarks, err := s3disk.NewFileWatermarkStore(filepath.Join(state, "watermark.json"))
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
		Watermarks: watermarks, RequirePersistentWatermark: true,
		Symlinks: s3disk.SymlinkRejectExternal,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(consumer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	if got := getWebDAVIntegrationFile(t, server.URL+"/workspace.txt"); got != "generation one" {
		t.Fatalf("initial WebDAV bytes = %q", got)
	}

	if err := os.WriteFile(filePath, []byte("generation two"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	if _, err := handler.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if got := getWebDAVIntegrationFile(t, server.URL+"/workspace.txt"); got != "generation two" {
		t.Fatalf("refreshed WebDAV bytes = %q", got)
	}
}

func getWebDAVIntegrationFile(t *testing.T, url string) string {
	t.Helper()
	response, err := http.Get(url) // #nosec G107 -- httptest loopback URL.
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d body = %q", response.StatusCode, contents)
	}
	return string(contents)
}

func createWebDAVMinIOBucket(
	t *testing.T,
	ctx context.Context,
	endpoint string,
	accessKey string,
	secretKey string,
	bucket string,
) {
	t.Helper()
	configuration, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	if err != nil {
		t.Fatal(err)
	}
	client := s3.NewFromConfig(configuration, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(strings.TrimRight(endpoint, "/"))
		options.UsePathStyle = true
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("create MinIO bucket: %v", err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func webDAVIntegrationEnv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
