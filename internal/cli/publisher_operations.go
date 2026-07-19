package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/presignedshare"
	"github.com/vibe-agi/s3disk/s3store"
)

// publisherS3Config is the authenticated session's complete non-credential S3
// configuration. Credentials are intentionally resolved afresh from A's
// environment and are never persisted in publisherSession.
type publisherS3Config struct {
	bucket                string
	region                string
	endpoint              string
	expectedBucketOwner   string
	usePathStyle          bool
	allowInsecureEndpoint bool
	tlsRootCAPEM          []byte
}

// publisherS3Handle separates constructing A's writable Store from freezing a
// presigning credential set. The abstraction is private: it exists so ordering
// and crash tests can use a real protocol Store without invoking an SDK or
// process-global hooks.
type publisherS3Handle struct {
	store             s3disk.Store
	newPresignSession func(context.Context, time.Time) (presignedshare.ExactGETPresigner, error)
}

type publisherOperations struct {
	now                 func() time.Time
	openS3              func(context.Context, publisherS3Config) (publisherS3Handle, error)
	afterExternalEffect func(context.Context, publisherExternalEffect) error
	afterDurablePhase   func(context.Context, publisherSessionPhase) error
}

type publisherExternalEffect string

const (
	publisherEffectRepositoryReady         publisherExternalEffect = "repository_ready"
	publisherEffectJournalReady            publisherExternalEffect = "journal_ready"
	publisherEffectInitialPublicationReady publisherExternalEffect = "initial_publication_ready"
	publisherEffectInitialRootReady        publisherExternalEffect = "initial_root_ready"
	publisherEffectHandoffReady            publisherExternalEffect = "handoff_ready"
)

func productionPublisherOperations() publisherOperations {
	return publisherOperations{
		now: time.Now,
		openS3: func(ctx context.Context, config publisherS3Config) (publisherS3Handle, error) {
			httpClient, err := s3HTTPClient(config.tlsRootCAPEM)
			if err != nil {
				return publisherS3Handle{}, fmt.Errorf("TLS CA: %w", err)
			}
			raw, err := s3store.New(ctx, s3store.Config{
				Bucket: config.bucket, Region: config.region, Endpoint: config.endpoint,
				ExpectedBucketOwner: config.expectedBucketOwner, UsePathStyle: config.usePathStyle,
				AllowInsecureEndpoint: config.allowInsecureEndpoint, HTTPClient: httpClient,
			})
			if err != nil {
				return publisherS3Handle{}, err
			}
			return publisherS3Handle{
				store: raw,
				newPresignSession: func(sessionContext context.Context, expiresAt time.Time) (presignedshare.ExactGETPresigner, error) {
					return raw.NewPresignSession(sessionContext, expiresAt)
				},
			}, nil
		},
		afterExternalEffect: func(context.Context, publisherExternalEffect) error { return nil },
		afterDurablePhase:   func(context.Context, publisherSessionPhase) error { return nil },
	}
}

func validatePublisherOperations(operations publisherOperations) error {
	if operations.now == nil || operations.openS3 == nil ||
		operations.afterExternalEffect == nil || operations.afterDurablePhase == nil {
		return fmt.Errorf("s3disk: publisher operations are incomplete")
	}
	return nil
}

func validatePublisherS3Handle(handle publisherS3Handle) error {
	if !publisherSessionDependencyConfigured(handle.store) || handle.newPresignSession == nil {
		return fmt.Errorf("s3disk: publisher S3 handle is incomplete")
	}
	return nil
}

func validatePublisherPresigner(presigner presignedshare.ExactGETPresigner) error {
	if !publisherSessionDependencyConfigured(presigner) {
		return fmt.Errorf("s3disk: publisher presigner is incomplete")
	}
	return nil
}

func publisherSessionS3Config(state publisherSession) publisherS3Config {
	return publisherS3Config{
		bucket: state.Bucket, region: state.Region, endpoint: state.Endpoint,
		expectedBucketOwner: state.ExpectedBucketOwner, usePathStyle: state.UsePathStyle,
		allowInsecureEndpoint: state.AllowInsecureEndpoint,
		tlsRootCAPEM:          append([]byte(nil), state.TLSRootCAPEM...),
	}
}

func requirePublisherAuthorization(ctx context.Context, expiresAt time.Time, now func() time.Time) error {
	if ctx == nil {
		return fmt.Errorf("s3disk: publisher context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if now == nil || expiresAt.IsZero() || !expiresAt.After(now()) {
		return ErrPublisherSessionExpired
	}
	return nil
}

func publisherPhaseAtLeast(phase, threshold publisherSessionPhase) bool {
	rank, ok := publisherSessionPhaseRank(phase)
	thresholdRank, thresholdOK := publisherSessionPhaseRank(threshold)
	return ok && thresholdOK && rank >= thresholdRank
}
