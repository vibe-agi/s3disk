package cli

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/mount"
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
	return runPreparedMount(ctx, options, localPaths, share)
}

func runPreparedMount(ctx context.Context, options MountOptions, localPaths mountLocalPaths, share decodedHandoff) error {
	runtime, err := prepareConsumerRuntime(ctx, share, localPaths.stateDir, localPaths.cacheBase)
	if err != nil {
		return fmt.Errorf("s3disk mount: %w", err)
	}
	defer runtime.Close()
	baseStateDir, err := preparePrivateDirectory(localPaths.stateDir)
	if err != nil {
		return fmt.Errorf("s3disk mount: resolve state directory: %w", err)
	}
	if pathsOverlap(baseStateDir, localPaths.mountpoint) {
		return fmt.Errorf("s3disk mount: resolved state directory and mountpoint must not contain one another")
	}
	if localPaths.cacheBase != "" {
		cacheBase, resolveErr := preparePrivateDirectory(localPaths.cacheBase)
		if resolveErr != nil {
			return fmt.Errorf("s3disk mount: resolve cache directory: %w", resolveErr)
		}
		if pathsOverlap(cacheBase, baseStateDir) || pathsOverlap(cacheBase, localPaths.mountpoint) {
			return fmt.Errorf("s3disk mount: resolved cache directory overlaps state or mountpoint")
		}
	}
	healthEvents, reportHealthError := newMountHealthEvents()
	mounted, err := mount.ReadOnly(ctx, runtime.consumer, localPaths.mountpoint, mount.Options{
		Poll: s3disk.PollOptions{
			Interval: options.PollInterval, AttemptTimeout: options.PollTimeout, OnError: reportHealthError,
		},
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
