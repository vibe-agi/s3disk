package s3disk

import (
	"context"
	"fmt"
)

// SnapshotReferenceIdentity is the immutable identity asserted by canonical
// reference bytes. Authenticated is true only when VerifySnapshotReference was
// given a verifier and successfully checked the signed-reference envelope.
type SnapshotReferenceIdentity struct {
	RepositoryID  RepositoryID
	Generation    uint64
	Commit        Digest
	Authenticated bool
}

// VerifySnapshotReference parses canonical reference bytes for channel and,
// when verifier is non-nil, verifies the publisher signature and repository
// binding. It performs no Store, network, or filesystem I/O other than calls
// made by the caller-supplied verifier.
//
// This helper lets authenticated transport envelopes bind their own generation
// and commit fields to the embedded s3disk reference instead of trusting
// duplicated metadata.
func VerifySnapshotReference(
	ctx context.Context,
	data []byte,
	channel string,
	verifier ReferenceVerifier,
) (SnapshotReferenceIdentity, error) {
	if ctx == nil {
		return SnapshotReferenceIdentity{}, fmt.Errorf("s3disk: nil reference verification context")
	}
	if err := ctx.Err(); err != nil {
		return SnapshotReferenceIdentity{}, err
	}
	if err := validateChannel(channel); err != nil {
		return SnapshotReferenceIdentity{}, err
	}
	if len(data) == 0 || len(data) > maxReferenceBytes {
		return SnapshotReferenceIdentity{}, ErrInvalidReference
	}
	if verifier != nil && !interfaceDependencyConfigured(verifier) {
		return SnapshotReferenceIdentity{}, fmt.Errorf("s3disk: reference verifier must not be a typed nil")
	}
	var reference snapshotReference
	if verifier == nil {
		if err := decodeJSON(data, &reference); err != nil {
			return SnapshotReferenceIdentity{}, fmt.Errorf("%w: %v", ErrInvalidReference, err)
		}
	} else {
		verified, err := verifySignedSnapshotReference(ctx, data, channel, verifier)
		if err != nil {
			return SnapshotReferenceIdentity{}, err
		}
		reference = verified
	}
	if reference.Format != objectFormatVersion || reference.Generation == 0 || reference.Commit.IsZero() {
		return SnapshotReferenceIdentity{}, ErrInvalidReference
	}
	identity := SnapshotReferenceIdentity{Generation: reference.Generation, Commit: reference.Commit}
	if verifier != nil {
		identity.RepositoryID = verifier.RepositoryID()
		identity.Authenticated = true
	}
	return identity, nil
}
