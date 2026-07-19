package s3store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/internal/presignedcap"
	"github.com/vibe-agi/s3disk/presignedshare"
)

const maxPresignedObjectKeyBytes = 1024

type presignGetAPI interface {
	PresignGetObject(context.Context, *s3.GetObjectInput, ...func(*s3.PresignOptions)) (*awsv4.PresignedHTTPRequest, error)
}

// PresignSession creates exact-key GET capabilities which all share one fixed
// SigV4 signing instant and absolute expiry. A fixed instant matters for large
// bundles: independently signed requests can otherwise cross a wall-clock
// second and acquire different service-side expiry times.
//
// The session contains credential-bearing AWS SDK state. Its String, GoString,
// and JSON diagnostics deliberately expose only safe lifecycle metadata.
type PresignSession struct {
	client           presignGetAPI
	clientOptions    s3.Options
	bucket           string
	expiresAt        time.Time
	signingTime      time.Time
	operationTimeout time.Duration
}

// NewPresignSession freezes the Store's current credentials and constructs a
// fixed-time SigV4 presigner. expiresAt is normalized down to a UTC whole
// second. The returned session reports that exact effective deadline.
//
// Temporary credentials must remain valid through expiresAt. This is required
// because S3 rejects a presigned URL when its issuing session token expires,
// even if X-Amz-Expires advertises a later time.
func (store *Store) NewPresignSession(ctx context.Context, expiresAt time.Time) (*PresignSession, error) {
	if ctx == nil {
		return nil, fmt.Errorf("s3store: nil presign context")
	}
	if store == nil || store.sdkClient == nil {
		return nil, fmt.Errorf("%w: s3store was not constructed with an SDK client", s3disk.ErrStoreMisconfigured)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	signingTime := time.Now().UTC().Truncate(time.Second)
	expiresAt = expiresAt.UTC().Truncate(time.Second)
	lifetime := expiresAt.Sub(signingTime)
	if lifetime <= 0 || lifetime > presignedshare.MaximumCapabilityLifetime {
		return nil, fmt.Errorf(
			"%w: presign expiry must be after now and no more than %s",
			s3disk.ErrResourceLimit,
			presignedshare.MaximumCapabilityLifetime,
		)
	}

	clientOptions := store.sdkClient.Options()
	if clientOptions.Credentials == nil {
		return nil, fmt.Errorf("%w: S3 client has no credentials provider", s3disk.ErrAccessDenied)
	}
	credentials, err := clientOptions.Credentials.Retrieve(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		// A custom provider error is not a safe diagnostic boundary: it may
		// include raw credential material. Return only a stable classification.
		return nil, fmt.Errorf("s3store: retrieve credentials for presigning failed: %w", s3disk.ErrAccessDenied)
	}
	if !credentials.HasKeys() {
		return nil, fmt.Errorf("%w: S3 credentials are empty", s3disk.ErrAccessDenied)
	}
	if credentials.CanExpire && credentials.Expires.Before(expiresAt) {
		return nil, fmt.Errorf(
			"%w: issuing credentials expire before the requested share",
			s3disk.ErrAccessDenied,
		)
	}
	// Freeze one retrieved credential value for the entire capability set. A
	// rotation halfway through a large bundle would otherwise produce a set of
	// URLs with different token lifetimes and authorization identities.
	clientOptions.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return credentials, nil
	})
	return newFrozenPresignSession(clientOptions, store.bucket, signingTime, expiresAt, store.operationTimeout)
}

func newFrozenPresignSession(
	clientOptions s3.Options,
	bucket string,
	signingTime time.Time,
	expiresAt time.Time,
	operationTimeout time.Duration,
) (*PresignSession, error) {
	expiresAt = expiresAt.UTC().Truncate(time.Second)
	lifetime := expiresAt.Sub(signingTime)
	if lifetime <= 0 || lifetime > presignedshare.MaximumCapabilityLifetime {
		return nil, fmt.Errorf(
			"%w: presign expiry must be after the frozen signing time and no more than %s",
			s3disk.ErrResourceLimit,
			presignedshare.MaximumCapabilityLifetime,
		)
	}
	sessionClient := s3.New(clientOptions)
	fixedSigner := &fixedTimePresigner{
		signingTime: signingTime,
		delegate: awsv4.NewSigner(func(options *awsv4.SignerOptions) {
			options.DisableURIPathEscaping = true
		}),
	}
	presigner := s3.NewPresignClient(sessionClient, func(options *s3.PresignOptions) {
		options.Expires = lifetime
		options.Presigner = fixedSigner
	})
	return &PresignSession{
		client: presigner, clientOptions: clientOptions, bucket: bucket,
		expiresAt: expiresAt, signingTime: signingTime, operationTimeout: operationTimeout,
	}, nil
}

// withExpiry derives a control session with the same frozen credentials,
// signing instant, endpoint/options, and signed-header policy. Only the valid
// service-side expiry and resulting signature differ. It is internal to
// commissioning so callers cannot accidentally split a production bundle's
// single absolute authorization deadline.
func (session *PresignSession) withExpiry(expiresAt time.Time) (*PresignSession, error) {
	if session == nil || session.clientOptions.Credentials == nil || session.bucket == "" || session.signingTime.IsZero() {
		return nil, fmt.Errorf("%w: presign session cannot derive a control expiry", s3disk.ErrStoreMisconfigured)
	}
	return newFrozenPresignSession(
		session.clientOptions, session.bucket, session.signingTime,
		expiresAt, session.operationTimeout,
	)
}

// AuthorizationExpiry returns the common effective service-side expiry of
// every capability produced by this session without performing I/O.
func (session *PresignSession) AuthorizationExpiry() (time.Time, bool) {
	if session == nil || session.expiresAt.IsZero() {
		return time.Time{}, false
	}
	return session.expiresAt, true
}

// PresignGet creates one exact-key GET bearer. It grants no List, Head, write,
// prefix, or wildcard authority. ExpectedBucketOwner is deliberately omitted:
// signing it can require an extra root-link header, while the signed request
// already binds the resolved bucket endpoint and exact object key.
func (session *PresignSession) PresignGet(ctx context.Context, key string) (presignedshare.Capability, error) {
	if ctx == nil {
		return presignedshare.Capability{}, fmt.Errorf("s3store: nil presign context")
	}
	if session == nil || session.client == nil || session.bucket == "" || session.expiresAt.IsZero() {
		return presignedshare.Capability{}, fmt.Errorf("%w: presign session is not configured", s3disk.ErrStoreMisconfigured)
	}
	if err := validatePresignedObjectKey(key); err != nil {
		return presignedshare.Capability{}, err
	}
	if !time.Now().Before(session.expiresAt) {
		return presignedshare.Capability{}, fmt.Errorf("%w: presign session has expired", s3disk.ErrAccessDenied)
	}
	timeout := session.operationTimeout
	if timeout <= 0 {
		timeout = DefaultOperationTimeout
	}
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := session.client.PresignGetObject(requestContext, &s3.GetObjectInput{
		Bucket: aws.String(session.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if requestContext.Err() != nil {
			return presignedshare.Capability{}, requestContext.Err()
		}
		// SDK/middleware errors can contain a request URL. Never wrap a possibly
		// secret partial bearer into an ordinary error.
		return presignedshare.Capability{}, fmt.Errorf("s3store: presign exact GET failed: %w", s3disk.ErrStoreMisconfigured)
	}
	if request == nil || request.Method != http.MethodGet {
		return presignedshare.Capability{}, fmt.Errorf("%w: S3 presigner returned a non-GET request", s3disk.ErrStoreIncompatible)
	}
	observedExpiry, err := sigV4PresignedExpiry(request.URL)
	if err != nil || !observedExpiry.Equal(session.expiresAt) {
		return presignedshare.Capability{}, fmt.Errorf(
			"%w: S3 presigner did not bind the requested absolute expiry",
			s3disk.ErrStoreIncompatible,
		)
	}
	signedHeaders := request.SignedHeader.Clone()
	if signedHost := signedHeaders.Values("Host"); len(signedHost) != 0 {
		parsedURL, parseErr := url.Parse(request.URL)
		if parseErr != nil || len(signedHost) != 1 || !strings.EqualFold(signedHost[0], parsedURL.Host) {
			return presignedshare.Capability{}, fmt.Errorf(
				"%w: S3 presigner returned a mismatched signed Host header",
				s3disk.ErrStoreIncompatible,
			)
		}
		// net/http derives the Host request field from the URL. Retaining Host in
		// http.Header is both ineffective and rejected as a request-smuggling
		// hazard by Capability validation; removing this matching duplicate does
		// not change the bytes used by SigV4 verification.
		signedHeaders.Del("Host")
	}
	capability, err := presignedshare.NewCapabilityFromExactGET(
		presignedcap.NewExactGET(key, request.URL, signedHeaders, session.expiresAt),
		presignedshare.CapabilityOptions{AllowInsecureLoopback: true},
	)
	if err != nil {
		// Capability validation errors contain only a fixed reason and never echo
		// the bearer URL or signed headers.
		return presignedshare.Capability{}, fmt.Errorf("%w: invalid S3 presigned request: %v", s3disk.ErrStoreIncompatible, err)
	}
	return capability, nil
}

// String uses a value receiver so an ordinary diagnostic of a copied session
// cannot recursively expose the frozen SDK credential state.
func (session PresignSession) String() string {
	return fmt.Sprintf(
		"s3store.PresignSession{configured:%t,signing_time:%s,expires_at:%s,secrets:redacted}",
		session.client != nil,
		session.signingTime.Format(time.RFC3339),
		session.expiresAt.Format(time.RFC3339),
	)
}

func (session PresignSession) GoString() string { return session.String() }

func (session PresignSession) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Configured  bool      `json:"configured"`
		SigningTime time.Time `json:"signing_time"`
		ExpiresAt   time.Time `json:"expires_at"`
		Secrets     string    `json:"secrets"`
	}{session.client != nil, session.signingTime, session.expiresAt, "redacted"})
}

type fixedTimePresigner struct {
	signingTime time.Time
	delegate    s3.HTTPPresignerV4
}

func (presigner *fixedTimePresigner) PresignHTTP(
	ctx context.Context,
	credentials aws.Credentials,
	request *http.Request,
	payloadHash string,
	service string,
	region string,
	_ time.Time,
	optionFunctions ...func(*awsv4.SignerOptions),
) (string, http.Header, error) {
	return presigner.delegate.PresignHTTP(
		ctx, credentials, request, payloadHash, service, region,
		presigner.signingTime, optionFunctions...,
	)
}

func sigV4PresignedExpiry(rawURL string) (time.Time, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return time.Time{}, errors.New("invalid presigned URL")
	}
	query := parsed.Query()
	signedAt, err := time.Parse("20060102T150405Z", query.Get("X-Amz-Date"))
	if err != nil {
		return time.Time{}, errors.New("missing SigV4 signing time")
	}
	seconds, err := strconv.ParseInt(query.Get("X-Amz-Expires"), 10, 64)
	if err != nil || seconds <= 0 || seconds > int64(presignedshare.MaximumCapabilityLifetime/time.Second) {
		return time.Time{}, errors.New("invalid SigV4 expiry")
	}
	return signedAt.Add(time.Duration(seconds) * time.Second).UTC(), nil
}

func validatePresignedObjectKey(key string) error {
	if key == "" || len(key) > maxPresignedObjectKeyBytes || !utf8.ValidString(key) || strings.ContainsRune(key, '\x00') {
		return fmt.Errorf("%w: invalid exact S3 object key", s3disk.ErrInvalidPath)
	}
	return nil
}

var _ presignedshare.ExactGETPresigner = (*PresignSession)(nil)

var _ s3disk.AuthorizationExpirySource = (*PresignSession)(nil)
