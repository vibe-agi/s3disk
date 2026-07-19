package presignedshare

import (
	"context"
	"errors"
	"fmt"

	"github.com/vibe-agi/s3disk"
)

// CreatePublishedSnapshot resolves the authenticated reference which was just
// returned by Publisher, requires that complete snapshot identity to remain
// unchanged, and creates the S3 share root from its exact sealed closure.
//
// This is the safe high-level A-side path for an initial selected publication.
// The expected value prevents a mutable-reference race from turning the root
// signer into an oracle for a different S3 state. Closure discovery uses the
// RootPublisher's verifier and the flat bundle's exact capability limit.
func (publisher *RootPublisher) CreatePublishedSnapshot(
	ctx context.Context,
	repository *s3disk.Repository,
	channel string,
	expected s3disk.Snapshot,
) (RootPublication, error) {
	closure, err := publisher.resolvePublishedSnapshot(ctx, repository, channel, expected)
	if err != nil {
		return RootPublication{}, err
	}
	return publisher.Create(ctx, closure)
}

// UpdatePublishedSnapshot performs the authenticated resolve-and-bind step for
// a later Publisher result and conditionally advances the existing S3 root.
// It is suitable for WatchOptions.AfterPublished: returning an error leaves
// Watch's acknowledgement pending so the same generation can be retried.
func (publisher *RootPublisher) UpdatePublishedSnapshot(
	ctx context.Context,
	repository *s3disk.Repository,
	channel string,
	expected s3disk.Snapshot,
) (RootPublication, error) {
	closure, err := publisher.resolvePublishedSnapshot(ctx, repository, channel, expected)
	if err != nil {
		return RootPublication{}, err
	}
	return publisher.Update(ctx, closure)
}

func (publisher *RootPublisher) resolvePublishedSnapshot(
	ctx context.Context,
	repository *s3disk.Repository,
	channel string,
	expected s3disk.Snapshot,
) (s3disk.SnapshotClosure, error) {
	if publisher == nil || !configuredInterface(publisher.verifier) {
		return s3disk.SnapshotClosure{}, fmt.Errorf("%w: root publisher is not configured", s3disk.ErrStoreMisconfigured)
	}
	if ctx == nil {
		return s3disk.SnapshotClosure{}, fmt.Errorf("presignedshare: published snapshot context is required")
	}
	if err := ctx.Err(); err != nil {
		return s3disk.SnapshotClosure{}, err
	}
	if repository == nil {
		return s3disk.SnapshotClosure{}, fmt.Errorf("%w: published snapshot repository is required", s3disk.ErrStoreMisconfigured)
	}
	if expected.Generation == 0 || expected.Commit.IsZero() || expected.Root.IsZero() || expected.PublishedAt.IsZero() {
		return s3disk.SnapshotClosure{}, fmt.Errorf("%w: expected published snapshot identity is incomplete", ErrInvalidBundle)
	}
	// A commercial automatic share must resolve the signed namespace. The
	// RootPublisher constructor independently rejects an unsigned ReferenceKey
	// unless its explicitly dangerous compatibility option is selected.
	if repository.SignedReferenceKey(channel) != publisher.referenceKey {
		return s3disk.SnapshotClosure{}, fmt.Errorf("%w: repository channel does not match the authenticated root reference", ErrInvalidBundle)
	}
	closure, err := repository.ResolveSnapshotClosure(ctx, channel, s3disk.SnapshotClosureOptions{
		ReferenceVerifier: publisher.verifier,
		MaxObjects:        MaximumBundleCapabilities,
	})
	if err != nil {
		return s3disk.SnapshotClosure{}, fmt.Errorf("presignedshare: resolve authenticated published snapshot: %w", safePublishedSnapshotError(err))
	}
	if !samePublishedSnapshot(closure.Snapshot, expected) {
		return s3disk.SnapshotClosure{}, fmt.Errorf("%w: authenticated reference changed before share-root publication", s3disk.ErrPublishConflict)
	}
	return closure, nil
}

func samePublishedSnapshot(observed, expected s3disk.Snapshot) bool {
	return observed.Generation == expected.Generation &&
		observed.Commit == expected.Commit &&
		observed.Root == expected.Root &&
		observed.PublishedAt.Equal(expected.PublishedAt)
}

func safePublishedSnapshotError(err error) error {
	for _, sentinel := range []error{
		context.Canceled,
		context.DeadlineExceeded,
		s3disk.ErrObjectNotFound,
		s3disk.ErrNotModified,
		s3disk.ErrAccessDenied,
		s3disk.ErrRateLimited,
		s3disk.ErrStoreUnavailable,
		s3disk.ErrStoreMisconfigured,
		s3disk.ErrBucketNotFound,
		s3disk.ErrStoreIncompatible,
		s3disk.ErrStoreOperationUnsupported,
		s3disk.ErrResourceLimit,
		s3disk.ErrCorruptObject,
		s3disk.ErrUntrustedReference,
		s3disk.ErrRollbackDetected,
		s3disk.ErrSplitBrain,
		s3disk.ErrInvalidSnapshotClosure,
	} {
		if errors.Is(err, sentinel) {
			return sentinel
		}
	}
	return s3disk.ErrStoreUnavailable
}
