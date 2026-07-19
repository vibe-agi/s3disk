//go:build integration

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
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
	"github.com/vibe-agi/s3disk/presignedshare"
	"github.com/vibe-agi/s3disk/s3store"
)

// TestMinIOCLIDoctorCommissioning proves the CLI accepts the real combined
// evidence envelope rather than only structurally convenient unit fakes.
func TestMinIOCLIDoctorCommissioning(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	bucket := fmt.Sprintf("s3disk-cli-doctor-%d", time.Now().UnixNano())
	createIntegrationBucket(t, ctx, endpoint, accessKey, secretKey, bucket)

	var stdout, stderr bytes.Buffer
	err := runDoctor(ctx, DoctorOptions{
		Bucket: bucket, Prefix: "cli-doctor/commissioning", Region: defaultRegion,
		Endpoint: endpoint, UsePathStyle: true, AllowInsecureEndpoint: true,
		PresignedTimeout: 25 * time.Second, TotalTimeout: 60 * time.Second,
		CapabilityLifetime: 2 * time.Minute, CleanupTimeout: 10 * time.Second,
		DeploymentFingerprint: strings.Repeat("d", 64),
		EvidenceID:            "minio-cli-doctor",
		ImplementationVersion: "integration-test",
		ErrorWriter:           &stderr,
	}, &stdout)
	if err != nil {
		t.Fatalf("doctor: %v; stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	var report s3store.S3CommissioningReport
	if err := decoder.Decode(&report); err != nil {
		t.Fatalf("decode doctor report: %v", err)
	}
	if report.Status != s3store.S3CommissioningPassed || !report.Compatible || !report.Complete ||
		!report.Evidence.FullyBound || report.WritableStoreOutcome != s3store.S3CommissioningStagePassed ||
		report.PresignedGetOutcome != s3store.S3CommissioningStagePassed {
		t.Fatalf("doctor report = %s", report)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("doctor stdout contains another JSON value: %v", err)
	}
}

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
	recoveryKeyPath := filepath.Join(t.TempDir(), "publisher-recovery-key.json")
	if err := runGenerateRecoveryKey(ctx, RecoveryKeyGenerateOptions{Out: recoveryKeyPath}); err != nil {
		t.Fatalf("generate publisher recovery key: %v", err)
	}
	publishContext, stopPublish := context.WithCancel(ctx)
	publishDone := make(chan error, 1)
	publisherStopped := false
	go func() {
		publishDone <- runPublish(publishContext, PublishOptions{
			Source: source, All: true, Bucket: bucket, Prefix: "cli-integration",
			Region: defaultRegion, Endpoint: endpoint, UsePathStyle: true, AllowInsecureEndpoint: true,
			Channel: defaultChannel, ExpiresIn: 10 * time.Minute, HandoffOut: handoffPath,
			StateDir: stateDir, RecoveryKey: recoveryKeyPath,
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
	rawStore, err := s3store.New(ctx, s3store.Config{
		Bucket: bucket, Region: defaultRegion, Endpoint: endpoint, UsePathStyle: true,
		AllowInsecureEndpoint: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	commissioned, descriptor, err := s3disk.OpenRepository(ctx, rawStore, share.wire.RepositoryPrefix, s3disk.RepositoryConfig{
		RepositoryID: share.repository, ClientEncryption: share.profile,
	})
	if err != nil {
		t.Fatalf("open CLI repository descriptor: %v", err)
	}
	if descriptor.RepositoryID != share.repository || descriptor.StorageProfile != s3disk.RepositoryStorageProfileStrictShareIsolationV1 {
		t.Fatalf("CLI repository descriptor = %#v", descriptor)
	}
	rawDescriptor, err := rawStore.Get(ctx, commissioned.DescriptorKey(), s3disk.GetOptions{MaxBytes: 64 << 10})
	if err != nil {
		t.Fatalf("read raw repository descriptor: %v", err)
	}
	if string(rawDescriptor.Data) == "" || rawDescriptor.Data[0] == '{' {
		t.Fatal("repository descriptor was not encrypted at rest")
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

// TestMinIOCLIOneShotPublishAndResume proves a completed one-shot publisher
// can restart from only its private state directory, canonical share identity,
// and recovery-key file. The source is deliberately removed before recovery;
// resume must reconcile the already-durable result without replacing either
// the local handoff or the exact encrypted S3 root object.
func TestMinIOCLIOneShotPublishAndResume(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	bucket := fmt.Sprintf("s3disk-cli-resume-%d", time.Now().UnixNano())
	createIntegrationBucket(t, ctx, endpoint, accessKey, secretKey, bucket)

	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "one-shot.txt"), []byte("durable one-shot snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	handoffPath := filepath.Join(t.TempDir(), "share.handoff")
	stateDir := filepath.Join(t.TempDir(), "state")
	recoveryKeyPath := filepath.Join(t.TempDir(), "publisher-recovery-key.json")
	if err := runGenerateRecoveryKey(ctx, RecoveryKeyGenerateOptions{Out: recoveryKeyPath}); err != nil {
		t.Fatalf("generate publisher recovery key: %v", err)
	}
	if err := runPublish(ctx, PublishOptions{
		Source: source, All: true, Bucket: bucket, Prefix: "cli-resume-integration",
		Region: defaultRegion, Endpoint: endpoint, UsePathStyle: true, AllowInsecureEndpoint: true,
		Channel: defaultChannel, ExpiresIn: 10 * time.Minute, HandoffOut: handoffPath,
		StateDir: stateDir, RecoveryKey: recoveryKeyPath, Once: true,
	}); err != nil {
		t.Fatalf("one-shot publish: %v", err)
	}

	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !entries[0].IsDir() || entries[0].Type()&os.ModeSymlink != 0 {
		t.Fatalf("publisher state entries = %v, want one real share directory", entries)
	}
	shareName := entries[0].Name()
	shareID, err := presignedshare.ParseShareID(shareName)
	if err != nil || shareID.String() != shareName {
		t.Fatalf("state directory share identity %q is not canonical: %v", shareName, err)
	}
	shareDirectory := filepath.Join(stateDir, shareName)
	recoveryMaterial, err := readRecoveryKeyFile(recoveryKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	sessionStore, err := newPublisherSessionSealedStore(shareDirectory, shareID, recoveryMaterial)
	if err != nil {
		t.Fatal(err)
	}
	beforeSession, found, err := loadPublisherSession(ctx, sessionStore, time.Now())
	if err != nil || !found {
		t.Fatalf("load completed publisher session: found=%t err=%v", found, err)
	}
	if beforeSession.state.Phase != publisherSessionCompleted || !beforeSession.state.Once {
		t.Fatalf("one-shot session phase=%q once=%t, want completed one-shot", beforeSession.state.Phase, beforeSession.state.Once)
	}

	handoffBefore, err := os.ReadFile(handoffPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(handoffBefore)
	handoffInfoBefore, err := os.Stat(handoffPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readHandoff(handoffPath); err != nil {
		t.Fatalf("published handoff is not canonical: %v", err)
	}
	rawStore, err := s3store.New(ctx, s3store.Config{
		Bucket: bucket, Region: defaultRegion, Endpoint: endpoint, UsePathStyle: true,
		AllowInsecureEndpoint: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	rootBefore, err := rawStore.Get(ctx, beforeSession.state.RootKey, s3disk.GetOptions{
		MaxBytes: presignedshare.MaximumBundleBytes + (1 << 20),
	})
	if err != nil {
		t.Fatalf("read encrypted root before resume: %v", err)
	}
	defer clear(rootBefore.Data)

	if err := os.RemoveAll(source); err != nil {
		t.Fatalf("remove one-shot source before resume: %v", err)
	}
	if err := runResume(ctx, ResumeOptions{
		StateDir: stateDir, ShareID: shareName, RecoveryKey: recoveryKeyPath,
	}); err != nil {
		t.Fatalf("resume completed one-shot publisher: %v", err)
	}

	handoffAfter, err := os.ReadFile(handoffPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(handoffAfter)
	if !bytes.Equal(handoffAfter, handoffBefore) {
		t.Fatal("resume changed the exact canonical handoff bytes")
	}
	handoffInfoAfter, err := os.Stat(handoffPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(handoffInfoBefore, handoffInfoAfter) {
		t.Fatal("resume replaced the existing handoff file")
	}
	rootAfter, err := rawStore.Get(ctx, beforeSession.state.RootKey, s3disk.GetOptions{
		MaxBytes: presignedshare.MaximumBundleBytes + (1 << 20),
	})
	if err != nil {
		t.Fatalf("read encrypted root after resume: %v", err)
	}
	defer clear(rootAfter.Data)
	if !bytes.Equal(rootAfter.Data, rootBefore.Data) || rootAfter.Version != rootBefore.Version {
		t.Fatalf("resume changed root bytes or version: before=%+v after=%+v", rootBefore.Version, rootAfter.Version)
	}
	afterSession, found, err := loadPublisherSession(ctx, sessionStore, time.Now())
	if err != nil || !found {
		t.Fatalf("reload completed publisher session: found=%t err=%v", found, err)
	}
	if afterSession.state.Phase != publisherSessionCompleted || !afterSession.state.Once {
		t.Fatalf("resumed session phase=%q once=%t, want completed one-shot", afterSession.state.Phase, afterSession.state.Once)
	}
	if afterSession.revision != beforeSession.revision ||
		afterSession.authenticatedDigest != beforeSession.authenticatedDigest ||
		afterSession.state.Sequence != beforeSession.state.Sequence {
		t.Fatal("resume rewrote the already-completed sealed session")
	}
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
