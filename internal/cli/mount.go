package cli

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/mount"
	"github.com/vibe-agi/s3disk/presignedshare"
)

const (
	mountHealthEventBuffer  = 16
	mountStatusPollInterval = 250 * time.Millisecond
)

type mountLifecycle interface {
	Done() <-chan struct{}
	Status() mount.MountStatus
}

func runMount(ctx context.Context, options MountOptions) error {
	if ctx == nil {
		return fmt.Errorf("s3disk mount: context is required")
	}
	if err := validateMountOptions(&options); err != nil {
		return err
	}
	localPaths, err := preflightMountLocalPaths(options)
	if err != nil {
		return fmt.Errorf("s3disk mount: local preflight: %w", err)
	}
	share, err := readHandoff(options.HandoffPath)
	if err != nil {
		return err
	}
	if share.wire.DangerouslyUseSystemTrust {
		return fmt.Errorf("s3disk mount: system TLS trust is incompatible with the S3-only CLI profile")
	}
	verifier, err := s3disk.NewEd25519ReferenceVerifier(share.repository, map[string]ed25519.PublicKey{
		share.wire.ReferenceKeyID: share.publicKey,
	})
	if err != nil {
		return fmt.Errorf("s3disk mount: create offline verifier: %w", err)
	}
	reader, err := presignedshare.NewReader(presignedshare.ReaderConfig{
		RootCapability: share.root, RepositoryPrefix: share.wire.RepositoryPrefix,
		ReferenceKey: share.wire.ReferenceKey, ShareID: share.shareID, Verifier: verifier,
		ClientEncryption: share.profile, TLSRootCAPEM: share.tlsCAPEM,
		AllowInsecureLoopback: share.wire.AllowInsecureLoopback,
	})
	if err != nil {
		return fmt.Errorf("s3disk mount: create credential-free reader: %w", err)
	}
	repository, err := s3disk.NewReadOnlyRepositoryWithOptions(reader, share.wire.RepositoryPrefix,
		s3disk.RepositoryOptions{ClientEncryption: share.profile})
	if err != nil {
		return fmt.Errorf("s3disk mount: create read-only repository: %w", err)
	}
	baseStateDir, err := preparePrivateDirectory(localPaths.stateDir)
	if err != nil {
		return fmt.Errorf("s3disk mount: state directory: %w", err)
	}
	if pathsOverlap(baseStateDir, localPaths.mountpoint) {
		return fmt.Errorf("s3disk mount: resolved state directory and mountpoint must not contain one another")
	}
	shareStateDir, err := preparePrivateSubdirectories(baseStateDir, share.wire.RepositoryID, share.wire.ShareID)
	if err != nil {
		return fmt.Errorf("s3disk mount: isolated state directory: %w", err)
	}
	watermarks, err := s3disk.NewFileWatermarkStore(filepath.Join(shareStateDir, "watermark.json"))
	if err != nil {
		return err
	}
	cachePath, err := prepareMountCachePath(localPaths.cacheBase, shareStateDir, share.wire.RepositoryID, share.wire.ShareID)
	if err != nil {
		return fmt.Errorf("s3disk mount: isolated cache directory: %w", err)
	}
	if localPaths.cacheBase != "" && (pathsOverlap(cachePath, baseStateDir) || pathsOverlap(cachePath, localPaths.mountpoint)) {
		return fmt.Errorf("s3disk mount: resolved cache directory overlaps state or mountpoint")
	}
	cache, err := s3disk.NewDiskCache(cachePath)
	if err != nil {
		return fmt.Errorf("s3disk mount: create cache: %w", err)
	}
	defer cache.Close()
	consumer, err := s3disk.NewConsumer(repository, share.wire.Channel, s3disk.ConsumerOptions{
		Cache: cache, Watermarks: watermarks, RequirePersistentWatermark: true,
		ReferenceVerifier: verifier, TrustedCheckpoint: &share.checkpoint,
		Symlinks: s3disk.SymlinkRejectExternal,
	})
	if err != nil {
		return fmt.Errorf("s3disk mount: create consumer: %w", err)
	}
	healthEvents, reportHealthError := newMountHealthEvents()
	mounted, err := mount.ReadOnly(ctx, consumer, localPaths.mountpoint, mount.Options{
		Poll: s3disk.PollOptions{Interval: options.PollInterval, OnError: reportHealthError},
	})
	if err != nil {
		return err
	}
	if options.StatusWriter != nil {
		_, _ = fmt.Fprintf(options.StatusWriter, "mounted: mountpoint=%q expires_at=%s read_only=true\n",
			localPaths.mountpoint, share.wire.AuthorizationExpiresAt.Format(time.RFC3339))
	}
	return waitForMountLifecycle(mounted, healthEvents, options.ErrorWriter, mountStatusPollInterval)
}

func prepareMountCachePath(cacheBase, shareStateDir, repositoryID, shareID string) (string, error) {
	if cacheBase == "" {
		return filepath.Join(shareStateDir, "cache"), nil
	}
	base, err := preparePrivateDirectory(cacheBase)
	if err != nil {
		return "", err
	}
	return preparePrivateSubdirectories(base, repositoryID, shareID, "cache")
}

func newMountHealthEvents() (<-chan error, func(error)) {
	events := make(chan error, mountHealthEventBuffer)
	report := func(err error) {
		if err == nil {
			return
		}
		select {
		case events <- err:
		default:
		}
	}
	return events, report
}

func waitForMountLifecycle(
	mounted mountLifecycle,
	healthEvents <-chan error,
	errorWriter io.Writer,
	checkInterval time.Duration,
) error {
	if mounted == nil {
		return fmt.Errorf("s3disk mount: lifecycle is unavailable")
	}
	if checkInterval <= 0 {
		checkInterval = mountStatusPollInterval
	}
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-mounted.Done():
			return mountLifecycleFailure(mounted.Status())
		case err, ok := <-healthEvents:
			if !ok {
				healthEvents = nil
				continue
			}
			if errorWriter != nil && err != nil {
				_, _ = fmt.Fprintf(errorWriter, "s3disk mount: warning: %v\n", err)
			}
			if failure := mountLifecycleFailure(mounted.Status()); failure != nil {
				return failure
			}
		case <-ticker.C:
			if failure := mountLifecycleFailure(mounted.Status()); failure != nil {
				return failure
			}
		}
	}
}

func mountLifecycleFailure(status mount.MountStatus) error {
	if status.Lifecycle != mount.LifecycleStopFailed {
		return nil
	}
	if status.Unmount.LastError == "" {
		return fmt.Errorf("s3disk mount: automatic unmount failed")
	}
	return fmt.Errorf("s3disk mount: automatic unmount failed: %s", status.Unmount.LastError)
}

func preparePrivateSubdirectories(base string, names ...string) (string, error) {
	current := base
	for _, name := range names {
		if name == "" || filepath.Base(name) != name {
			return "", fmt.Errorf("invalid state namespace")
		}
		current = filepath.Join(current, name)
		if err := os.Mkdir(current, 0o700); err != nil && !os.IsExist(err) {
			return "", err
		}
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("state namespace is not a private directory")
		}
	}
	return current, nil
}
