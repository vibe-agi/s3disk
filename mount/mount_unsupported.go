//go:build !linux && !darwin && !freebsd

package mount

import (
	"context"
	"fmt"
	"time"

	"github.com/vibe-agi/s3disk"
)

type Options struct {
	AttrTTL  time.Duration
	EntryTTL time.Duration
	// NegativeTTL is retained for source compatibility. Supported adapters
	// require zero so refresh never depends on negative-dentry invalidation.
	NegativeTTL time.Duration
	Poll        s3disk.PollOptions
	Debug       bool
	// DangerouslyAllowMountWithoutDurableWatermark is the native adapters'
	// explicit rollback-risk opt-out.
	DangerouslyAllowMountWithoutDurableWatermark bool
	// DangerouslyAllowMountWithPreservedSymlinks is the native adapters'
	// explicit mount-escape-risk opt-out.
	DangerouslyAllowMountWithPreservedSymlinks bool
	// KernelCache is retained for source compatibility. Supported mount adapters
	// reject it because it cannot preserve snapshot-pinned handle semantics.
	KernelCache    bool
	FilesystemName string
	// MaxInodeIdentities bounds currently remembered generation-specific inode
	// identities on native adapters. Zero selects DefaultMaxInodeIdentities.
	MaxInodeIdentities int
	// MaxInodeIdentityBytes bounds the conservative retained-memory charge for
	// native adapters. Zero selects DefaultMaxInodeIdentityBytes.
	MaxInodeIdentityBytes int64
	// AutoUnmountTimeout is used by native adapters for both context and
	// authorization-expiry stops. Zero selects DefaultAutoUnmountTimeout.
	AutoUnmountTimeout time.Duration
}

type Mount struct{}

func ReadOnly(ctx context.Context, consumer *s3disk.Consumer, _ string, options Options) (*Mount, error) {
	if ctx == nil {
		return nil, fmt.Errorf("s3disk mount: nil context")
	}
	if consumer == nil {
		return nil, fmt.Errorf("s3disk mount: nil consumer")
	}
	var err error
	options, err = normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	if err := validateReadOnlySecurity(consumer.SecurityStatus(), options); err != nil {
		return nil, fmt.Errorf("s3disk mount: unsafe consumer configuration: %w", err)
	}
	if expiresAt, known := consumer.AuthorizationExpiry(); known && !expiresAt.After(time.Now()) {
		return nil, fmt.Errorf("s3disk mount: authorization lifetime: %w", ErrAuthorizationExpired)
	}
	return nil, ErrUnsupportedPlatform
}

var unsupportedDone = func() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}()

func (*Mount) Status() MountStatus {
	return MountStatus{Lifecycle: LifecycleStopped, Polling: false}
}

func (*Mount) Done() <-chan struct{} { return unsupportedDone }

func (*Mount) Wait() {}

func (*Mount) WaitContext(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("s3disk mount: nil wait context")
	}
	return ErrUnsupportedPlatform
}

func (*Mount) Unmount() error { return ErrUnsupportedPlatform }

func (*Mount) UnmountContext(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("s3disk mount: nil unmount context")
	}
	return ErrUnsupportedPlatform
}
