package presignedshare

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vibe-agi/s3disk"
)

// ExactGETPresigner is the safe A-side capability mint used by
// BuildSnapshotBundle. Implementations must return a capability whose private
// mint provenance and exact key match the requested key. s3store.PresignSession
// is the built-in implementation.
type ExactGETPresigner interface {
	PresignGet(ctx context.Context, key string) (Capability, error)
	AuthorizationExpiry() (time.Time, bool)
}

// SnapshotBundleInput binds one root object and share revision to an exact,
// sealed closure returned by s3disk.Repository.ResolveSnapshotClosure.
type SnapshotBundleInput struct {
	RootKey          string
	RootCapability   Capability
	RepositoryPrefix string
	ShareID          ShareID
	Revision         uint64
	Closure          s3disk.SnapshotClosure
	Presigner        ExactGETPresigner
}

// BuildSnapshotBundle presigns every key in an unchanged resolved closure,
// and no other key, then builds the authenticated bundle. All closure, root,
// trust, and fixed-expiry validation happens before the first object presign.
// It performs no Store reads, lists, heads, or writes.
func BuildSnapshotBundle(
	ctx context.Context,
	input SnapshotBundleInput,
	signer s3disk.ReferenceSigner,
	verifier s3disk.ReferenceVerifier,
) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", ErrInvalidBundle)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !configuredInterface(input.Presigner) {
		return nil, fmt.Errorf("%w: exact-GET presigner is required", ErrInvalidBundle)
	}
	if err := input.Closure.ValidateResolved(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidBundle, err)
	}
	prefix, err := validateBundleBindings(
		input.RepositoryPrefix,
		input.Closure.ReferenceKey,
		input.ShareID,
		input.Revision,
		input.Closure.Snapshot.Generation,
	)
	if err != nil {
		return nil, err
	}
	if !validObjectKey(input.RootKey) || !input.RootCapability.Configured() ||
		input.RootCapability.provenance != capabilityProvenanceExactGET ||
		input.RootCapability.exactKey != input.RootKey {
		return nil, fmt.Errorf("%w: root is not a safely minted exact-GET capability", ErrInvalidBundle)
	}
	expiresAt, known := input.Presigner.AuthorizationExpiry()
	expiresAt = expiresAt.UTC().Round(0)
	if !known || expiresAt.IsZero() || !expiresAt.Equal(input.RootCapability.expiresAt) || !expiresAt.After(time.Now()) {
		return nil, fmt.Errorf("%w: presigner and root capability expiry do not match", ErrInvalidBundle)
	}
	if err := validateReference(
		ctx,
		s3disk.Object{Data: input.Closure.ReferenceData, Version: input.Closure.ReferenceVersion},
		prefix,
		input.Closure.ReferenceKey,
		input.Closure.Snapshot.Generation,
		input.Closure.Snapshot.Commit,
		verifier,
	); err != nil {
		return nil, err
	}
	if len(input.Closure.ObjectKeys) < 1 || len(input.Closure.ObjectKeys) > MaximumBundleCapabilities {
		return nil, fmt.Errorf("%w: closure capability count is outside the flat bundle bound", ErrInvalidBundle)
	}
	previous := ""
	for index, key := range input.Closure.ObjectKeys {
		if index&255 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if key <= previous && previous != "" {
			return nil, fmt.Errorf("%w: closure object keys are not uniquely sorted", ErrInvalidBundle)
		}
		previous = key
		if err := validateImmutableKey(prefix, key); err != nil {
			return nil, err
		}
	}

	capabilities := make([]ExactCapability, 0, len(input.Closure.ObjectKeys))
	for index, key := range input.Closure.ObjectKeys {
		if index&255 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		capability, err := input.Presigner.PresignGet(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("presignedshare: presign closure object %d failed: %w", index, safePresignError(err))
		}
		if !capability.Configured() || capability.provenance != capabilityProvenanceExactGET ||
			capability.exactKey != key || capability.origin != input.RootCapability.origin ||
			!capability.expiresAt.Equal(expiresAt) {
			return nil, fmt.Errorf("%w: presigner returned a mismatched exact capability at index %d", ErrInvalidBundle, index)
		}
		capabilities = append(capabilities, ExactCapability{Key: key, Capability: capability})
	}
	return Build(ctx, BuildInput{
		RootCapability:      input.RootCapability,
		RootKey:             input.RootKey,
		RepositoryPrefix:    input.RepositoryPrefix,
		ReferenceKey:        input.Closure.ReferenceKey,
		ShareID:             input.ShareID,
		Revision:            input.Revision,
		ReferenceGeneration: input.Closure.Snapshot.Generation,
		ReferenceCommit:     input.Closure.Snapshot.Commit,
		Reference: s3disk.Object{
			Data:    append([]byte(nil), input.Closure.ReferenceData...),
			Version: input.Closure.ReferenceVersion,
		},
		AuthorizationExpiresAt: expiresAt,
		Capabilities:           capabilities,
	}, signer, verifier)
}

func safePresignError(err error) error {
	for _, sentinel := range []error{
		context.Canceled,
		context.DeadlineExceeded,
		s3disk.ErrAccessDenied,
		s3disk.ErrRateLimited,
		s3disk.ErrStoreUnavailable,
		s3disk.ErrStoreMisconfigured,
		s3disk.ErrStoreIncompatible,
		s3disk.ErrStoreOperationUnsupported,
		s3disk.ErrResourceLimit,
		s3disk.ErrInvalidPath,
	} {
		if errors.Is(err, sentinel) {
			return sentinel
		}
	}
	return s3disk.ErrStoreMisconfigured
}
