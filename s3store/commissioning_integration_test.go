//go:build integration

package s3store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
)

// TestMinIOS3Commissioning samples the combined writable Store and anonymous
// presigned-GET contracts against a real SigV4 implementation. Unit tests
// retain the exhaustive fault matrix; this test proves both phases share one
// repository-scoped invocation and leave no current canary objects behind.
func TestMinIOS3Commissioning(t *testing.T) {
	endpoint := os.Getenv("S3DISK_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("S3DISK_TEST_S3_ENDPOINT is not set")
	}
	accessKey := envOr("S3DISK_TEST_S3_ACCESS_KEY", "s3disk")
	secretKey := envOr("S3DISK_TEST_S3_SECRET_KEY", "s3disk-secret")
	bucket := fmt.Sprintf("s3disk-commissioning-%d", time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
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
	report, err := store.ProbeCommissioning(ctx, S3CommissioningProbeOptions{
		RepositoryPrefix: "integration/commissioning",
		PresignedGet: PresignedGetCompatibilityProbeOptions{
			TotalTimeout: 25 * time.Second, CapabilityLifetime: 2 * time.Minute,
			CleanupTimeout: 10 * time.Second,
		},
		DeploymentFingerprint: strings.Repeat("a", 64),
		EvidenceID:            "minio-combined-commissioning",
		ImplementationVersion: "integration-test",
		TotalTimeout:          60 * time.Second,
		WritableStoreTimeout:  25 * time.Second,
	})
	if err != nil {
		t.Fatalf("combined S3 commissioning: %v; report=%s", err, report)
	}
	if report.Status != S3CommissioningPassed || !report.Compatible || !report.Complete ||
		report.WritableStoreOutcome != S3CommissioningStagePassed ||
		report.PresignedGetOutcome != S3CommissioningStagePassed ||
		!report.Evidence.FullyBound || !report.Evidence.PresignedPrefixDerived ||
		!report.Evidence.PresignedPrefixRepositoryScoped {
		t.Fatalf("combined S3 commissioning report = %s", report)
	}
	if report.WritableStore.RequiredChecks != s3disk.StoreCompatibilityRequiredChecks ||
		len(report.WritableStore.Checks) != report.WritableStore.RequiredChecks ||
		len(report.PresignedGet.Checks) != report.PresignedGet.RequiredChecks {
		t.Fatalf("combined check counts = writable %d/%d, presigned %d/%d",
			len(report.WritableStore.Checks), report.WritableStore.RequiredChecks,
			len(report.PresignedGet.Checks), report.PresignedGet.RequiredChecks)
	}
	if report.WritableStore.Cleanup.Status != s3disk.StoreCompatibilityCleanupSucceeded ||
		report.PresignedGet.Cleanup.Status != PresignedGetCompatibilityCleanupSucceeded ||
		report.Cleanup.CurrentObjectsMayRemain {
		t.Fatalf("combined cleanup = %+v", report.Cleanup)
	}
}
