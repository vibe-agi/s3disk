//go:build integration

package s3store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestMinIOPresignedGetCompatibility commissions the real anonymous GET path,
// including MinIO's SigV4 validation. The unit service intentionally exercises
// report branches without implementing SigV4 cryptography; this integration
// test samples that the bearer URL works without B-side credentials; rejects
// unsigned GET/PUT/DELETE, one expiry-query mutation, path mutation, HEAD, and
// zero-byte plus non-empty PUT; confines eleven named method/path override
// headers; and leaves both sampled objects' bytes and versions unchanged.
func TestMinIOPresignedGetCompatibility(t *testing.T) {
	endpoint := os.Getenv("S3DISK_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("S3DISK_TEST_S3_ENDPOINT is not set")
	}
	accessKey := envOr("S3DISK_TEST_S3_ACCESS_KEY", "s3disk")
	secretKey := envOr("S3DISK_TEST_S3_SECRET_KEY", "s3disk-secret")
	bucket := fmt.Sprintf("s3disk-presigned-compat-%d", time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	createBucketWithRetry(t, ctx, endpoint, accessKey, secretKey, bucket)

	store, err := New(ctx, Config{
		Bucket: bucket, Region: "us-east-1", Endpoint: endpoint, UsePathStyle: true,
		CredentialsProvider: CredentialsProviderFunc(func(context.Context) (Credentials, error) {
			return Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := store.ProbePresignedGetCompatibilityWithOptions(ctx, PresignedGetCompatibilityProbeOptions{
		ObjectKeyPrefix: "integration/presigned-get",
		TotalTimeout:    30 * time.Second, CapabilityLifetime: 2 * time.Minute,
		CleanupTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("presigned GET compatibility: %v; report=%s", err, report)
	}
	if report.Status != PresignedGetCompatibilityPassed || !report.Compatible || !report.Complete {
		t.Fatalf("presigned GET compatibility report = %s", report)
	}
	if report.Cleanup.Status != PresignedGetCompatibilityCleanupSucceeded {
		t.Fatalf("presigned GET compatibility cleanup = %s", report.Cleanup)
	}
}
