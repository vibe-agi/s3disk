package cli

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/presignedshare"
)

type publisherIdentity struct {
	repositoryID   s3disk.RepositoryID
	shareID        presignedshare.ShareID
	clientKey      s3disk.ClientEncryptionKey
	profile        *s3disk.ClientEncryptionProfile
	privateKey     ed25519.PrivateKey
	publicKey      ed25519.PublicKey
	signer         s3disk.ReferenceSigner
	verifier       s3disk.ReferenceVerifier
	rootCapability presignedshare.Capability
}

func reconstructPublisherIdentity(state publisherSession, now time.Time) (publisherIdentity, error) {
	rootCapability, err := state.RequireActive(now)
	if err != nil {
		return publisherIdentity{}, err
	}
	repositoryID, err := s3disk.ParseRepositoryID(state.RepositoryID)
	if err != nil {
		return publisherIdentity{}, ErrInvalidPublisherSession
	}
	shareID, err := presignedshare.ParseShareID(state.ShareID)
	if err != nil {
		return publisherIdentity{}, ErrInvalidPublisherSession
	}
	clientKey, err := s3disk.ParseClientEncryptionKey(state.ClientEncryptionKey)
	if err != nil {
		return publisherIdentity{}, ErrInvalidPublisherSession
	}
	profile, err := s3disk.NewClientEncryptionProfile(repositoryID, clientKey)
	if err != nil {
		return publisherIdentity{}, ErrInvalidPublisherSession
	}
	if len(state.ReferencePrivateSeed) != ed25519.SeedSize {
		return publisherIdentity{}, ErrInvalidPublisherSession
	}
	privateKey := ed25519.NewKeyFromSeed(state.ReferencePrivateSeed)
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return publisherIdentity{}, ErrInvalidPublisherSession
	}
	signer, err := s3disk.NewEd25519ReferenceSigner(repositoryID, state.ReferenceKeyID, privateKey)
	if err != nil {
		return publisherIdentity{}, ErrInvalidPublisherSession
	}
	verifier, err := s3disk.NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{
		state.ReferenceKeyID: publicKey,
	})
	if err != nil {
		return publisherIdentity{}, ErrInvalidPublisherSession
	}
	return publisherIdentity{
		repositoryID: repositoryID, shareID: shareID, clientKey: clientKey, profile: profile,
		privateKey: privateKey, publicKey: append(ed25519.PublicKey(nil), publicKey...),
		signer: signer, verifier: verifier, rootCapability: rootCapability,
	}, nil
}

func buildPublisherHandoff(state publisherSession) (handoff, []byte, s3disk.Digest, error) {
	if err := validatePublisherSession(state); err != nil {
		return handoff{}, nil, s3disk.Digest{}, err
	}
	if state.TrustedCheckpoint == nil {
		return handoff{}, nil, s3disk.Digest{}, fmt.Errorf("%w: initial checkpoint is absent", ErrInvalidPublisherSession)
	}
	privateKey := ed25519.NewKeyFromSeed(state.ReferencePrivateSeed)
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return handoff{}, nil, s3disk.Digest{}, ErrInvalidPublisherSession
	}
	value := handoff{
		Format: handoffFormat, Profile: handoffProfile, ShareID: state.ShareID,
		AuthorizationExpiresAt: state.AuthorizationExpiresAt,
		RootBearer:             base64.RawURLEncoding.EncodeToString(state.RootBearer),
		RepositoryPrefix:       state.RepositoryPrefix, ReferenceKey: state.ReferenceKey,
		Channel: state.Channel, RepositoryID: state.RepositoryID, ReferenceKeyID: state.ReferenceKeyID,
		ReferencePublicKey:    base64.RawURLEncoding.EncodeToString(publicKey),
		TrustedCheckpoint:     *state.TrustedCheckpoint,
		TLSRootCAPEM:          base64.RawURLEncoding.EncodeToString(state.TLSRootCAPEM),
		AllowInsecureLoopback: state.AllowInsecureEndpoint,
		ClientEncryptionKey:   state.ClientEncryptionKey,
	}
	encoded, err := encodeHandoff(value)
	if err != nil {
		return handoff{}, nil, s3disk.Digest{}, err
	}
	return value, encoded, handoffDigest(encoded), nil
}

func publisherTrustedCheckpoint(state publisherSession, repositoryID s3disk.RepositoryID) (*s3disk.Watermark, error) {
	if state.TrustedCheckpoint == nil {
		return nil, nil
	}
	commit, err := s3disk.ParseDigest(state.TrustedCheckpoint.Commit)
	if err != nil || commit.IsZero() || state.TrustedCheckpoint.Generation == 0 {
		return nil, ErrInvalidPublisherSession
	}
	return &s3disk.Watermark{
		RepositoryID: repositoryID,
		Generation:   state.TrustedCheckpoint.Generation,
		Commit:       commit,
	}, nil
}

func snapshotMatchesCheckpoint(snapshot s3disk.Snapshot, checkpoint handoffCheckpoint) bool {
	return snapshot.Generation == checkpoint.Generation && snapshot.Commit.String() == checkpoint.Commit
}
