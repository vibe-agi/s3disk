//go:build integration

package s3store

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/vibe-agi/s3disk"
)

// TestMinIOSplitWriterPresignerCommissioning exercises the production role
// split against real SigV4 enforcement. The fixture gives the writer full
// bucket data-plane access and the presigner only s3:GetObject on this bucket.
// The isolated negative checks are deployment-policy evidence; the library
// probe itself never invokes the presigning Store's credentialed data-plane
// client.
func TestMinIOSplitWriterPresignerCommissioning(t *testing.T) {
	endpoint := os.Getenv("S3DISK_TEST_S3_ENDPOINT")
	bucket := os.Getenv("S3DISK_TEST_S3_SPLIT_BUCKET")
	signerAccessKey := os.Getenv("S3DISK_TEST_S3_SIGNER_ACCESS_KEY")
	signerSecretKey := os.Getenv("S3DISK_TEST_S3_SIGNER_SECRET_KEY")
	if endpoint == "" || bucket == "" || signerAccessKey == "" || signerSecretKey == "" {
		t.Skip("split-identity MinIO environment is not configured")
	}
	writerAccessKey := envOr("S3DISK_TEST_S3_ACCESS_KEY", "s3disk")
	writerSecretKey := envOr("S3DISK_TEST_S3_SECRET_KEY", "s3disk-secret")
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()

	writerStore, err := New(ctx, Config{
		Bucket: bucket, Region: "us-east-1", Endpoint: endpoint, UsePathStyle: true,
		CredentialsProvider: CredentialsProviderFunc(func(context.Context) (Credentials, error) {
			return Credentials{AccessKeyID: writerAccessKey, SecretAccessKey: writerSecretKey}, nil
		}),
	})
	if err != nil {
		t.Fatal("configure split writer Store")
	}
	signerHTTPTransport := http.DefaultTransport.(*http.Transport).Clone()
	t.Cleanup(signerHTTPTransport.CloseIdleConnections)
	signerTransport := &countingSplitIntegrationRoundTripper{delegate: signerHTTPTransport}
	presigningStore, err := New(ctx, Config{
		Bucket: bucket, Region: "us-east-1", Endpoint: endpoint, UsePathStyle: true,
		HTTPClient: &http.Client{Transport: signerTransport},
		CredentialsProvider: CredentialsProviderFunc(func(context.Context) (Credentials, error) {
			return Credentials{AccessKeyID: signerAccessKey, SecretAccessKey: signerSecretKey}, nil
		}),
	})
	if err != nil {
		t.Fatal("configure split presigning Store")
	}

	// These destructive authorization samples run only in the isolated MinIO
	// harness. AccessDenied on finite samples complements, but does not replace,
	// production IAM inventory and policy analysis.
	if _, err := presigningStore.PutIfAbsent(ctx, "integration/split/forbidden-put", []byte("must-not-exist")); !errors.Is(err, s3disk.ErrAccessDenied) {
		t.Fatal("GetObject-only MinIO principal did not deny PutObject")
	}
	if err := presigningStore.Delete(ctx, "integration/split/forbidden-delete"); !errors.Is(err, s3disk.ErrAccessDenied) {
		t.Fatal("GetObject-only MinIO principal did not deny DeleteObject")
	}
	_, listErr := presigningStore.sdkClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
	})
	if listErr == nil || !errors.Is(classifyError("list", "", listErr), s3disk.ErrAccessDenied) {
		t.Fatal("GetObject-only MinIO principal did not deny ListBucket")
	}
	signerTransport.calls.Store(0)

	report, err := writerStore.ProbeCommissioningWithPresigningStore(ctx, presigningStore, S3CommissioningProbeOptions{
		RepositoryPrefix: "integration/split-commissioning",
		PresignedGet: PresignedGetCompatibilityProbeOptions{
			TotalTimeout: 25 * time.Second, CapabilityLifetime: 2 * time.Minute,
			CleanupTimeout: 10 * time.Second,
		},
		DeploymentFingerprint: strings.Repeat("b", 64),
		EvidenceID:            "minio-split-writer-presigner",
		ImplementationVersion: "integration-test",
		TotalTimeout:          60 * time.Second,
		WritableStoreTimeout:  25 * time.Second,
	})
	if signerTransport.calls.Load() != 0 {
		t.Fatalf("split probe made %d credentialed presigning Store data-plane calls", signerTransport.calls.Load())
	}
	if err != nil {
		t.Fatalf("split MinIO commissioning failed with status %q", report.Status)
	}
	if report.Status != S3CommissioningPassed || !report.Compatible || !report.Complete ||
		report.WritableStoreOutcome != S3CommissioningStagePassed ||
		report.PresignedGetOutcome != S3CommissioningStagePassed ||
		!report.Evidence.FullyBound ||
		report.Evidence.PresigningTopology != PresignedGetCompatibilitySeparateStore ||
		!report.Evidence.PresigningStoreInputDistinct ||
		!report.Evidence.CrossConfigurationCanaryBindingObserved ||
		report.PresignedGet.Scope != PresignedGetCompatibilityCrossConfigurationFiniteProbe ||
		!report.PresignedGet.Evidence.CrossConfigurationCanaryBindingObserved {
		t.Fatalf("split MinIO commissioning report = %s", report)
	}
	if report.WritableStore.Cleanup.Status != s3disk.StoreCompatibilityCleanupSucceeded ||
		report.PresignedGet.Cleanup.Status != PresignedGetCompatibilityCleanupSucceeded ||
		report.Cleanup.CurrentObjectsMayRemain {
		t.Fatalf("split MinIO cleanup = %+v", report.Cleanup)
	}
}

type countingSplitIntegrationRoundTripper struct {
	delegate http.RoundTripper
	calls    atomic.Int64
}

func (transport *countingSplitIntegrationRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.calls.Add(1)
	return transport.delegate.RoundTrip(request)
}
