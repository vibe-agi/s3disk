//go:build integration && (linux || darwin)

package mount_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
	"github.com/vibe-agi/s3disk/mount"
	"github.com/vibe-agi/s3disk/s3store"
)

func TestMinIOFUSEEndToEnd(t *testing.T) {
	requireFUSE(t)
	endpoint := os.Getenv("S3DISK_TEST_S3_ENDPOINT")
	if endpoint == "" {
		if os.Getenv("S3DISK_REQUIRE_FUSE") == "1" {
			t.Fatal("S3DISK_TEST_S3_ENDPOINT is required for the Linux MinIO/FUSE gate")
		}
		t.Skip("S3DISK_TEST_S3_ENDPOINT is not set")
	}
	accessKey := integrationEnv("S3DISK_TEST_S3_ACCESS_KEY", "s3disk")
	secretKey := integrationEnv("S3DISK_TEST_S3_SECRET_KEY", "s3disk-secret")

	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	transport := &networkGateTransport{base: http.DefaultTransport.(*http.Transport).Clone()}
	t.Cleanup(transport.CloseIdleConnections)
	httpClient := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	bucket := fmt.Sprintf("s3disk-mount-%d", time.Now().UnixNano())
	createMinIOBucket(t, ctx, httpClient, endpoint, accessKey, secretKey, bucket)

	backend, err := s3store.New(ctx, s3store.Config{
		Bucket: bucket, Region: "us-east-1", Endpoint: endpoint,
		CredentialsProvider: s3store.CredentialsProviderFunc(func(context.Context) (s3store.Credentials, error) {
			return s3store.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}, nil
		}),
		UsePathStyle: true, HTTPClient: httpClient, AllowInsecureEndpoint: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &chunkCountingStore{base: backend}
	repository, err := s3disk.NewRepository(store, "mount-minio-integration")
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.CheckStoreCompatibility(ctx); err != nil {
		t.Fatalf("MinIO store compatibility: %v", err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		Chunking: s3disk.ChunkingOptions{
			MinSize: 1 << 20, AverageSize: 2 << 20, MaxSize: 4 << 20,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	sourcePath := filepath.Join(source, "large.bin")
	firstData := deterministicBytes(5 << 20)
	firstMarker := []byte("minio-fuse-generation-one")
	copy(firstData[64:], firstMarker)
	if err := os.WriteFile(sourcePath, firstData, 0o644); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	} else if snapshot.Generation != 1 {
		t.Fatalf("initial generation = %d, want 1", snapshot.Generation)
	}

	cacheRoot := privateIntegrationDirectory(t)
	cacheOptions := s3disk.DiskCacheOptions{
		MaxBytes: 16 << 20, MaxChunkBytes: 4 << 20, MaxEntries: 64,
	}
	cache, err := s3disk.NewDiskCacheWithOptions(cacheRoot, cacheOptions)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cache.Close() })
	watermarkPath := filepath.Join(privateIntegrationDirectory(t), "main.watermark")
	watermarks, err := s3disk.NewFileWatermarkStore(watermarkPath)
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
		Cache: cache, Watermarks: watermarks, RequirePersistentWatermark: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	updates := make(chan s3disk.RefreshResult, 4)
	mountpoint := t.TempDir()
	mounted, err := mount.ReadOnly(ctx, consumer, mountpoint, minIOFUSEOptions(updates))
	if err != nil {
		if os.Getenv("S3DISK_REQUIRE_FUSE") == "1" {
			t.Fatalf("mount MinIO-backed FUSE filesystem: %v", err)
		}
		t.Skipf("FUSE mount unavailable: %v", err)
	}
	mountActive := true
	defer func() {
		if mountActive {
			stopMounted(t, mounted)
		}
	}()
	mountedPath := filepath.Join(mountpoint, "large.bin")

	if got := store.chunkGets.Load(); got != 0 {
		t.Fatalf("mount metadata initialization fetched %d chunks, want 0", got)
	}
	got, err := readRange(mountedPath, 64, len(firstMarker))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, firstMarker) {
		t.Fatalf("initial mounted marker = %q", got)
	}
	if got := store.chunkGets.Load(); got != 1 {
		t.Fatalf("one small mounted read fetched %d chunks, want 1", got)
	}
	if _, err := readRange(mountedPath, 64, len(firstMarker)); err != nil {
		t.Fatal(err)
	}
	if got := store.chunkGets.Load(); got != 1 {
		t.Fatalf("cached mounted read increased chunk GETs to %d", got)
	}
	if err := os.WriteFile(mountedPath, []byte("forbidden"), 0o644); !errors.Is(err, syscall.EROFS) {
		t.Fatalf("write through MinIO mount error = %v, want EROFS", err)
	}

	secondData := append([]byte(nil), firstData...)
	secondMarker := []byte("minio-fuse-generation-two")
	copy(secondData[64:], secondMarker)
	if err := os.WriteFile(sourcePath, secondData, 0o644); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	} else if snapshot.Generation != 2 {
		t.Fatalf("updated generation = %d, want 2", snapshot.Generation)
	}
	waitForRefreshGeneration(t, ctx, updates, 2)
	waitForRange(t, ctx, mountedPath, 64, secondMarker)
	if got := store.chunkGets.Load(); got != 2 {
		t.Fatalf("updated small mounted read fetched %d total chunks, want 2", got)
	}

	// Cut every HTTP request, including reference polling. Direct I/O forces the
	// read back through FUSE, where the verified disk cache must satisfy it.
	transport.SetOffline(true)
	got, err = readRange(mountedPath, 64, len(secondMarker))
	if err != nil {
		t.Fatalf("read cached range with MinIO offline: %v", err)
	}
	if !bytes.Equal(got, secondMarker) {
		t.Fatalf("offline cached marker = %q", got)
	}
	if got := store.chunkGets.Load(); got != 2 {
		t.Fatalf("offline cached read attempted another successful chunk GET: %d", got)
	}

	stopMounted(t, mounted)
	mountActive = false
	if err := cache.Close(); err != nil {
		t.Fatalf("close first disk cache before restart: %v", err)
	}
	transport.SetOffline(false)

	// Re-open both persistent stores and recreate the Consumer, then mount the
	// same empty mountpoint again. The chunk must remain locally reusable.
	restartedCache, err := s3disk.NewDiskCacheWithOptions(cacheRoot, cacheOptions)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restartedCache.Close() })
	restartedWatermarks, err := s3disk.NewFileWatermarkStore(watermarkPath)
	if err != nil {
		t.Fatal(err)
	}
	restartedConsumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
		Cache: restartedCache, Watermarks: restartedWatermarks, RequirePersistentWatermark: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := mount.ReadOnly(ctx, restartedConsumer, mountpoint, minIOFUSEOptions(nil))
	if err != nil {
		t.Fatalf("remount MinIO-backed FUSE filesystem: %v", err)
	}
	restartActive := true
	defer func() {
		if restartActive {
			stopMounted(t, restarted)
		}
	}()
	chunkGetsBeforeRemountRead := store.chunkGets.Load()
	waitForRange(t, ctx, mountedPath, 64, secondMarker)
	if got := store.chunkGets.Load(); got != chunkGetsBeforeRemountRead {
		t.Fatalf("remount missed persistent chunk cache: GETs advanced from %d to %d", chunkGetsBeforeRemountRead, got)
	}
	stopMounted(t, restarted)
	restartActive = false
}

func TestFUSEMountRefreshAndSnapshotPinning(t *testing.T) {
	requireFUSE(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "mount-integration")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	sourcePath := filepath.Join(source, "item")
	if err := os.WriteFile(sourcePath, []byte("version one"), 0o644); err != nil {
		t.Fatal(err)
	}
	privateSourcePath := filepath.Join(source, "owner-only")
	if err := os.WriteFile(privateSourcePath, []byte("private value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}

	cache, err := s3disk.NewDiskCacheWithOptions(privateIntegrationDirectory(t), s3disk.DiskCacheOptions{
		MaxBytes: 8 << 20, MaxChunkBytes: 4 << 20, MaxEntries: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cache.Close() })
	watermarks, err := s3disk.NewFileWatermarkStore(filepath.Join(privateIntegrationDirectory(t), "main.watermark"))
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
		Cache: cache, Watermarks: watermarks, RequirePersistentWatermark: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	mountpoint := t.TempDir()
	mounted, err := mount.ReadOnly(ctx, consumer, mountpoint, mount.Options{
		Debug:   os.Getenv("S3DISK_TEST_FUSE_DEBUG") == "1",
		AttrTTL: 50 * time.Millisecond, EntryTTL: 50 * time.Millisecond,
		// The test materializes more than four generation/path identities. It can
		// finish only if kernel FORGET events reclaim obsolete registry entries.
		MaxInodeIdentities: 4,
		// Missing names are deliberately not cached. Reverse invalidation is only
		// an optimization; correctness must survive unavailable or ineffective
		// negative-dentry notifications.
		NegativeTTL: 0,
		Poll: s3disk.PollOptions{
			Interval: 20 * time.Millisecond, MaxInterval: 200 * time.Millisecond,
			JitterFraction: -1,
		},
	})
	if err != nil {
		if os.Getenv("S3DISK_REQUIRE_FUSE") == "1" {
			t.Fatalf("mount FUSE filesystem: %v", err)
		}
		t.Skipf("FUSE mount unavailable: %v", err)
	}
	defer func() {
		if err := mounted.Unmount(); err != nil {
			t.Errorf("unmount: %v", err)
		}
		mounted.Wait()
	}()

	mountedPath := filepath.Join(mountpoint, "item")
	waitForFile(t, ctx, mountedPath, "version one")
	privateMountedPath := filepath.Join(mountpoint, "owner-only")
	waitForFile(t, ctx, privateMountedPath, "private value")
	privateInfo, err := os.Stat(privateMountedPath)
	if err != nil {
		t.Fatal(err)
	}
	privateStat, ok := privateInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("mounted private file has unexpected stat payload %T", privateInfo.Sys())
	}
	if privateStat.Uid != uint32(os.Getuid()) || privateStat.Gid != uint32(os.Getgid()) {
		t.Fatalf("mounted private owner = %d:%d, want mounting process %d:%d", privateStat.Uid, privateStat.Gid, os.Getuid(), os.Getgid())
	}
	if got := privateInfo.Mode().Perm(); got != 0o400 {
		t.Fatalf("mounted private permissions = %#o, want read-only owner mode 0400", got)
	}
	oldHandle, err := os.Open(mountedPath)
	if err != nil {
		t.Fatal(err)
	}
	defer oldHandle.Close()
	pinnedInfo, err := oldHandle.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mountedPath, []byte("forbidden"), 0o644); !errors.Is(err, syscall.EROFS) {
		t.Fatalf("write through mount error = %v, want EROFS", err)
	}

	if err := os.WriteFile(sourcePath, []byte("version two"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	waitForFile(t, ctx, mountedPath, "version two")
	oldBytes, err := io.ReadAll(oldHandle)
	if err != nil {
		t.Fatal(err)
	}
	if string(oldBytes) != "version one" {
		t.Fatalf("old open handle read %q, want snapshot-pinned version one", oldBytes)
	}
	assertSamePinnedFileInfo(t, oldHandle, pinnedInfo, "after content refresh")

	if err := os.Remove(sourcePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sourcePath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourcePath, "child"), []byte("nested"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	waitForDirectory(t, ctx, mountedPath)
	waitForFile(t, ctx, filepath.Join(mountedPath, "child"), "nested")

	if err := os.RemoveAll(sourcePath); err != nil {
		t.Fatal(err)
	}
	renamedPath := filepath.Join(mountpoint, "renamed")
	if _, err := os.Stat(renamedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("prime negative dentry for new name: %v", err)
	}
	if err := os.WriteFile(filepath.Join(source, "renamed"), []byte("final"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	waitForMissing(t, ctx, mountedPath)
	waitForFile(t, ctx, renamedPath, "final")
	assertSamePinnedFileInfo(t, oldHandle, pinnedInfo, "after path deletion")
	waitFor(t, ctx, func() bool {
		return mounted.Status().InodeIdentitiesReclaimed >= 2
	}, "mount to reclaim obsolete inode identities")
}

func assertSamePinnedFileInfo(t *testing.T, file *os.File, want os.FileInfo, phase string) {
	t.Helper()
	got, err := file.Stat()
	if err != nil {
		t.Fatalf("fstat old handle %s: %v", phase, err)
	}
	if got.Size() != want.Size() || got.Mode() != want.Mode() || !got.ModTime().Equal(want.ModTime()) {
		t.Fatalf("old handle metadata %s = size %d mode %v mtime %v, want size %d mode %v mtime %v",
			phase, got.Size(), got.Mode(), got.ModTime(), want.Size(), want.Mode(), want.ModTime())
	}
}

var errInjectedOffline = errors.New("MinIO network disabled by integration test")

type networkGateTransport struct {
	base    *http.Transport
	offline atomic.Bool
}

func (transport *networkGateTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if transport.offline.Load() {
		return nil, errInjectedOffline
	}
	return transport.base.RoundTrip(request)
}

func (transport *networkGateTransport) SetOffline(offline bool) {
	transport.offline.Store(offline)
	transport.base.CloseIdleConnections()
}

func (transport *networkGateTransport) CloseIdleConnections() {
	transport.base.CloseIdleConnections()
}

type chunkCountingStore struct {
	base      *s3store.Store
	chunkGets atomic.Int64
}

func (store *chunkCountingStore) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	if strings.Contains(key, "/objects/chunk/") {
		store.chunkGets.Add(1)
	}
	return store.base.Get(ctx, key, options)
}

func (store *chunkCountingStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	return store.base.Head(ctx, key)
}

func (store *chunkCountingStore) PutIfAbsent(ctx context.Context, key string, data []byte) (s3disk.Version, error) {
	return store.base.PutIfAbsent(ctx, key, data)
}

func (store *chunkCountingStore) CompareAndSwap(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
	return store.base.CompareAndSwap(ctx, key, expected, data)
}

func (store *chunkCountingStore) Delete(ctx context.Context, key string) error {
	return store.base.Delete(ctx, key)
}

func createMinIOBucket(t *testing.T, ctx context.Context, httpClient *http.Client, endpoint, accessKey, secretKey, bucket string) {
	t.Helper()
	configuration, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
		awsconfig.WithHTTPClient(httpClient),
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

func minIOFUSEOptions(updates chan<- s3disk.RefreshResult) mount.Options {
	options := mount.Options{
		AttrTTL: 30 * time.Millisecond, EntryTTL: 30 * time.Millisecond,
		NegativeTTL: 0, FilesystemName: "s3disk-minio-test",
		Poll: s3disk.PollOptions{
			Interval: 20 * time.Millisecond, MaxInterval: 200 * time.Millisecond,
			JitterFraction: -1,
		},
	}
	if updates != nil {
		options.Poll.OnUpdated = func(result s3disk.RefreshResult) {
			select {
			case updates <- result:
			default:
			}
		}
	}
	return options
}

func deterministicBytes(size int) []byte {
	data := make([]byte, size)
	for index := range data {
		data[index] = byte((index*31 + index/251) & 0xff)
	}
	return data
}

func readRange(path string, offset int64, length int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data := make([]byte, length)
	count, err := file.ReadAt(data, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if count != len(data) {
		return nil, fmt.Errorf("read %d bytes at %d, want %d", count, offset, len(data))
	}
	return data, nil
}

func waitForRange(t *testing.T, ctx context.Context, path string, offset int64, want []byte) {
	t.Helper()
	waitFor(t, ctx, func() bool {
		data, err := readRange(path, offset, len(want))
		return err == nil && bytes.Equal(data, want)
	}, "file %q range at %d to contain %q", path, offset, want)
}

func waitForRefreshGeneration(t *testing.T, ctx context.Context, updates <-chan s3disk.RefreshResult, generation uint64) {
	t.Helper()
	for {
		select {
		case result := <-updates:
			if result.Generation >= generation {
				return
			}
		case <-ctx.Done():
			t.Fatalf("wait for mounted generation %d: %v", generation, ctx.Err())
		}
	}
}

func stopMounted(t *testing.T, mounted *mount.Mount) {
	t.Helper()
	err := mounted.Unmount()
	mounted.Wait()
	if err != nil {
		t.Errorf("clean FUSE unmount: %v", err)
	}
}

func integrationEnv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func requireFUSE(t *testing.T) {
	t.Helper()
	err := fuseRuntimeAvailable()
	if err == nil {
		return
	}
	if os.Getenv("S3DISK_REQUIRE_FUSE") == "1" {
		t.Fatalf("FUSE runtime is required for the %s mount gate: %v", runtime.GOOS, err)
	}
	t.Skipf("FUSE runtime unavailable on %s: %v", runtime.GOOS, err)
}

func fuseRuntimeAvailable() error {
	switch runtime.GOOS {
	case "linux":
		info, err := os.Stat("/dev/fuse")
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeCharDevice == 0 {
			return fmt.Errorf("/dev/fuse is not a character device")
		}
		device, err := os.OpenFile("/dev/fuse", os.O_RDWR, 0)
		if err != nil {
			return err
		}
		return device.Close()
	case "darwin":
		for _, helper := range []string{
			"/Library/Filesystems/macfuse.fs/Contents/Resources/mount_macfuse",
			"/Library/Filesystems/osxfuse.fs/Contents/Resources/mount_osxfuse",
		} {
			info, err := os.Stat(helper)
			if err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
				return nil
			}
		}
		return fmt.Errorf("no executable macFUSE mount helper found below /Library/Filesystems")
	default:
		return fmt.Errorf("unsupported test platform %s", runtime.GOOS)
	}
}

var (
	_ http.RoundTripper    = (*networkGateTransport)(nil)
	_ s3disk.Store         = (*chunkCountingStore)(nil)
	_ s3disk.ObjectDeleter = (*chunkCountingStore)(nil)
)

func waitForFile(t *testing.T, ctx context.Context, path, want string) {
	t.Helper()
	waitFor(t, ctx, func() bool {
		data, err := os.ReadFile(path)
		return err == nil && string(data) == want
	}, "file %q to contain %q", path, want)
}

func waitForDirectory(t *testing.T, ctx context.Context, path string) {
	t.Helper()
	waitFor(t, ctx, func() bool {
		info, err := os.Stat(path)
		return err == nil && info.IsDir()
	}, "path %q to become a directory", path)
}

func waitForMissing(t *testing.T, ctx context.Context, path string) {
	t.Helper()
	waitFor(t, ctx, func() bool {
		_, err := os.Stat(path)
		return errors.Is(err, os.ErrNotExist)
	}, "path %q to disappear", path)
}

func waitFor(t *testing.T, ctx context.Context, condition func() bool, format string, values ...any) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf(format+": %v", append(values, ctx.Err())...)
		case <-ticker.C:
		}
	}
}

func privateIntegrationDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("protect integration-test state directory: %v", err)
	}
	return directory
}
