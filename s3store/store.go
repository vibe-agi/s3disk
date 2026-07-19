// Package s3store adapts AWS S3 and compatible services to s3disk.Store.
package s3store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsretry "github.com/aws/aws-sdk-go-v2/aws/retry"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/vibe-agi/s3disk"
)

const (
	// The application protocol permits 64 MiB plaintext objects. Reserve the
	// fixed current client-encryption envelope overhead at the raw S3 adapter
	// boundary so an exactly maximum-sized chunk remains representable.
	protocolMaxObjectBytes int64 = (64 << 20) + s3disk.ClientEncryptionCiphertextOverhead
	defaultRetryAttempts         = 3
	maximumRetryAttempts         = 10
	// DefaultOperationTimeout bounds one complete S3 data-plane call, including
	// reading a GET response body, when the caller supplies no earlier deadline.
	DefaultOperationTimeout = 2 * time.Minute
	// MaximumOperationTimeout prevents a configuration mistake from silently
	// disabling request-level liveness for operationally relevant periods.
	MaximumOperationTimeout = 30 * time.Minute
)

// Credentials is one short-lived result from a CredentialsProvider. Keep the
// value local to the provider call and do not log it. Expires is optional; a
// zero value means the credentials do not advertise an expiry time.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expires         time.Time
}

// MarshalJSON protects the credential value itself from common accidental
// logging paths. It exposes only lifecycle metadata.
func (credentials Credentials) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Configured      bool      `json:"configured"`
		HasSessionToken bool      `json:"has_session_token"`
		CanExpire       bool      `json:"can_expire"`
		Expires         time.Time `json:"expires,omitempty"`
	}{
		Configured:      credentials.AccessKeyID != "" || credentials.SecretAccessKey != "",
		HasSessionToken: credentials.SessionToken != "",
		CanExpire:       !credentials.Expires.IsZero(),
		Expires:         credentials.Expires,
	})
}

func (credentials Credentials) String() string {
	encoded, err := credentials.MarshalJSON()
	if err != nil {
		return "s3store.Credentials{redacted}"
	}
	return "s3store.Credentials(" + string(encoded) + ")"
}

func (credentials Credentials) GoString() string { return credentials.String() }

// CredentialsProvider supplies credentials at request time so an embedding
// application can rotate them without reconstructing Store. The AWS SDK wraps
// this provider in its concurrency-safe expiry-aware cache.
type CredentialsProvider interface {
	RetrieveCredentials(context.Context) (Credentials, error)
}

// CredentialsProviderFunc adapts a function to CredentialsProvider.
type CredentialsProviderFunc func(context.Context) (Credentials, error)

func (provider CredentialsProviderFunc) RetrieveCredentials(ctx context.Context) (Credentials, error) {
	return provider(ctx)
}

// Config is independent of AWS SDK public types so applications can replace
// SDK versions without changing their s3disk-facing API.
type Config struct {
	Bucket                string
	Region                string
	Endpoint              string
	ExpectedBucketOwner   string
	CredentialsProvider   CredentialsProvider
	UsePathStyle          bool
	HTTPClient            *http.Client
	RetryMaxAttempts      int
	OperationTimeout      time.Duration
	AllowInsecureEndpoint bool
}

// MarshalJSON deliberately omits credentials and concrete provider/client
// values. This protects common diagnostic logging; applications must still
// avoid reflection-based dumps of configuration memory.
func (config Config) MarshalJSON() ([]byte, error) {
	credentialSource := "default_chain"
	if config.CredentialsProvider != nil {
		credentialSource = "provider"
	}
	return json.Marshal(struct {
		Bucket                string `json:"bucket"`
		Region                string `json:"region"`
		Endpoint              string `json:"endpoint,omitempty"`
		ExpectedBucketOwner   string `json:"expected_bucket_owner,omitempty"`
		CredentialSource      string `json:"credential_source"`
		UsePathStyle          bool   `json:"use_path_style"`
		HTTPClientConfigured  bool   `json:"http_client_configured"`
		RetryMaxAttempts      int    `json:"retry_max_attempts"`
		OperationTimeout      string `json:"operation_timeout"`
		AllowInsecureEndpoint bool   `json:"allow_insecure_endpoint"`
	}{
		Bucket:                config.Bucket,
		Region:                config.Region,
		Endpoint:              config.Endpoint,
		ExpectedBucketOwner:   config.ExpectedBucketOwner,
		CredentialSource:      credentialSource,
		UsePathStyle:          config.UsePathStyle,
		HTTPClientConfigured:  config.HTTPClient != nil,
		RetryMaxAttempts:      config.RetryMaxAttempts,
		OperationTimeout:      config.OperationTimeout.String(),
		AllowInsecureEndpoint: config.AllowInsecureEndpoint,
	})
}

func (config Config) String() string {
	encoded, err := config.MarshalJSON()
	if err != nil {
		return "s3store.Config{redacted}"
	}
	return "s3store.Config(" + string(encoded) + ")"
}

func (config Config) GoString() string { return config.String() }

type api interface {
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

func (store *Store) Delete(ctx context.Context, key string) error {
	ctx, cancel := store.operationContext(ctx)
	defer cancel()
	_, err := store.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket:              aws.String(store.bucket),
		Key:                 aws.String(key),
		ExpectedBucketOwner: optionalString(store.expectedBucketOwner),
	})
	if err != nil {
		return classifyError("delete", key, err)
	}
	return nil
}

type Store struct {
	bucket              string
	expectedBucketOwner string
	client              api
	// sdkClient is retained only for constructing fixed-time, exact-key
	// presigning sessions. Runtime Store operations continue through client so
	// adapter tests can supply narrow fakes.
	sdkClient        *s3.Client
	presignedHTTPS   bool
	maxObjectBytes   int64
	operationTimeout time.Duration
}

// String deliberately exposes only bounded, non-secret status. Use a value
// receiver so formatting either the constructor-returned pointer or a copied
// value cannot recursively print the SDK client or credential-provider state.
func (store Store) String() string {
	encoded, err := store.MarshalJSON()
	if err != nil {
		return "s3store.Store{secrets:redacted}"
	}
	return "s3store.Store(" + string(encoded) + ")"
}

func (store Store) GoString() string { return store.String() }

func (store Store) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Configured       bool   `json:"configured"`
		MaxObjectBytes   int64  `json:"max_object_bytes"`
		OperationTimeout string `json:"operation_timeout"`
		Secrets          string `json:"secrets"`
	}{
		Configured:       store.bucket != "" && store.client != nil,
		MaxObjectBytes:   store.maxObjectBytes,
		OperationTimeout: store.operationTimeout.String(),
		Secrets:          "redacted",
	})
}

func New(ctx context.Context, config Config) (*Store, error) {
	if config.Bucket == "" {
		return nil, fmt.Errorf("s3store: bucket is required")
	}
	if config.Region == "" {
		config.Region = "us-east-1"
	}
	if credentialsProviderIsNil(config.CredentialsProvider) {
		return nil, fmt.Errorf("s3store: credentials provider must not be a typed nil")
	}
	if err := validateExpectedBucketOwner(config.ExpectedBucketOwner); err != nil {
		return nil, err
	}
	if config.RetryMaxAttempts == 0 {
		config.RetryMaxAttempts = defaultRetryAttempts
	}
	if config.RetryMaxAttempts < 1 || config.RetryMaxAttempts > maximumRetryAttempts {
		return nil, fmt.Errorf("s3store: retry max attempts must be between 1 and %d", maximumRetryAttempts)
	}
	if config.OperationTimeout == 0 {
		config.OperationTimeout = DefaultOperationTimeout
	}
	if config.OperationTimeout < 0 || config.OperationTimeout > MaximumOperationTimeout {
		return nil, fmt.Errorf("s3store: operation timeout must be positive and at most %s", MaximumOperationTimeout)
	}
	if err := validateEndpoint(config.Endpoint, config.AllowInsecureEndpoint); err != nil {
		return nil, err
	}
	retryAttempts := config.RetryMaxAttempts
	loadOptions := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(config.Region),
		awsconfig.WithRetryer(func() aws.Retryer {
			return awsretry.NewStandard(func(options *awsretry.StandardOptions) {
				options.MaxAttempts = retryAttempts
			})
		}),
	}
	if config.CredentialsProvider != nil {
		provider := aws.NewCredentialsCache(credentialsProviderAdapter{provider: config.CredentialsProvider})
		loadOptions = append(loadOptions, awsconfig.WithCredentialsProvider(provider))
	}
	if config.HTTPClient != nil {
		loadOptions = append(loadOptions, awsconfig.WithHTTPClient(config.HTTPClient))
	}
	awsConfiguration, err := awsconfig.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return nil, fmt.Errorf("s3store: load AWS configuration: %w", err)
	}
	client := s3.NewFromConfig(awsConfiguration, func(options *s3.Options) {
		options.UsePathStyle = config.UsePathStyle
		if config.Endpoint != "" {
			options.BaseEndpoint = aws.String(strings.TrimRight(config.Endpoint, "/"))
		}
	})
	presignedHTTPS := true
	if config.Endpoint != "" {
		endpointURL, _ := url.Parse(config.Endpoint) // validated above
		presignedHTTPS = endpointURL.Scheme == "https"
	}
	return &Store{
		bucket:              config.Bucket,
		expectedBucketOwner: config.ExpectedBucketOwner,
		client:              client,
		sdkClient:           client,
		presignedHTTPS:      presignedHTTPS,
		maxObjectBytes:      protocolMaxObjectBytes,
		operationTimeout:    config.OperationTimeout,
	}, nil
}

func credentialsProviderIsNil(provider CredentialsProvider) bool {
	if provider == nil {
		return false
	}
	value := reflect.ValueOf(provider)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (store *Store) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := store.operationTimeout
	if timeout <= 0 {
		timeout = DefaultOperationTimeout
	}
	return context.WithTimeout(ctx, timeout)
}

type credentialsProviderAdapter struct {
	provider CredentialsProvider
}

func (adapter credentialsProviderAdapter) Retrieve(ctx context.Context) (aws.Credentials, error) {
	credentials, err := adapter.provider.RetrieveCredentials(ctx)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("s3store: retrieve credentials: %w", err)
	}
	if credentials.AccessKeyID == "" || credentials.SecretAccessKey == "" {
		return aws.Credentials{}, fmt.Errorf("s3store: credentials provider returned an empty access key or secret key")
	}
	return aws.Credentials{
		AccessKeyID:     credentials.AccessKeyID,
		SecretAccessKey: credentials.SecretAccessKey,
		SessionToken:    credentials.SessionToken,
		Source:          "s3disk CredentialsProvider",
		CanExpire:       !credentials.Expires.IsZero(),
		Expires:         credentials.Expires,
	}, nil
}

func validateExpectedBucketOwner(owner string) error {
	if owner == "" {
		return nil
	}
	if len(owner) != 12 {
		return fmt.Errorf("s3store: expected bucket owner must be a 12-digit AWS account ID")
	}
	for _, character := range owner {
		if character < '0' || character > '9' {
			return fmt.Errorf("s3store: expected bucket owner must be a 12-digit AWS account ID")
		}
	}
	return nil
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return aws.String(value)
}

func validateEndpoint(endpoint string, allowInsecure bool) error {
	if endpoint == "" {
		return nil
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return fmt.Errorf("s3store: endpoint must be an absolute HTTP(S) URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("s3store: endpoint must not contain credentials, query, or fragment")
	}
	if parsed.Scheme == "http" && !allowInsecure && !isLoopbackHost(parsed.Hostname()) {
		return fmt.Errorf("s3store: refusing insecure non-loopback endpoint; set AllowInsecureEndpoint explicitly")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func (store *Store) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	if options.MaxBytes < 0 {
		return s3disk.Object{}, fmt.Errorf("s3store: max bytes must not be negative")
	}
	limit := store.maxObjectBytes
	if options.MaxBytes > 0 && options.MaxBytes < limit {
		limit = options.MaxBytes
	}
	ctx, cancel := store.operationContext(ctx)
	defer cancel()
	input := &s3.GetObjectInput{
		Bucket:              aws.String(store.bucket),
		Key:                 aws.String(key),
		ExpectedBucketOwner: optionalString(store.expectedBucketOwner),
	}
	if options.IfNoneMatch != "" {
		input.IfNoneMatch = aws.String(options.IfNoneMatch)
	}
	output, err := store.client.GetObject(ctx, input)
	if err != nil {
		return s3disk.Object{}, classifyError("get", key, err)
	}
	defer output.Body.Close()
	version, err := responseVersion("get", key, aws.ToString(output.ETag), aws.ToString(output.VersionId))
	if err != nil {
		return s3disk.Object{}, err
	}
	if output.ContentLength != nil && *output.ContentLength > limit {
		return s3disk.Object{}, fmt.Errorf("%w: s3store object %q exceeds %d bytes", s3disk.ErrResourceLimit, key, limit)
	}
	readLimit := limit
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	data, err := io.ReadAll(io.LimitReader(output.Body, readLimit))
	if err != nil {
		return s3disk.Object{}, fmt.Errorf("s3store: read %q: %w", key, err)
	}
	if int64(len(data)) > limit {
		return s3disk.Object{}, fmt.Errorf("%w: s3store object %q exceeds %d bytes", s3disk.ErrResourceLimit, key, limit)
	}
	return s3disk.Object{
		Data:    data,
		Version: version,
	}, nil
}

func (store *Store) Head(ctx context.Context, key string) (s3disk.Version, error) {
	ctx, cancel := store.operationContext(ctx)
	defer cancel()
	output, err := store.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket:              aws.String(store.bucket),
		Key:                 aws.String(key),
		ExpectedBucketOwner: optionalString(store.expectedBucketOwner),
	})
	if err != nil {
		return s3disk.Version{}, classifyError("head", key, err)
	}
	return responseVersion("head", key, aws.ToString(output.ETag), aws.ToString(output.VersionId))
}

func (store *Store) PutIfAbsent(ctx context.Context, key string, data []byte) (s3disk.Version, error) {
	return store.put(ctx, key, data, "", "*")
}

func (store *Store) CompareAndSwap(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
	if expected == nil {
		return store.put(ctx, key, data, "", "*")
	}
	if expected.ETag == "" {
		return s3disk.Version{}, fmt.Errorf("s3store: compare-and-swap requires an ETag")
	}
	if len(expected.ETag) > s3disk.MaxStoreVersionTokenBytes {
		return s3disk.Version{}, fmt.Errorf("%w: s3store compare-and-swap ETag exceeds %d bytes", s3disk.ErrResourceLimit, s3disk.MaxStoreVersionTokenBytes)
	}
	version, err := store.put(ctx, key, data, expected.ETag, "")
	// Some compatible servers (including MinIO releases) report NoSuchKey
	// instead of HTTP 412 when If-Match is evaluated against a missing object.
	// Both observations prove that the condition failed and no replacement was
	// applied, so normalize the provider difference at the adapter boundary.
	if errors.Is(err, s3disk.ErrObjectNotFound) {
		return s3disk.Version{}, fmt.Errorf("s3store: missing object does not satisfy If-Match: %w: %w", s3disk.ErrPrecondition, err)
	}
	return version, err
}

func (store *Store) put(ctx context.Context, key string, data []byte, ifMatch, ifNoneMatch string) (s3disk.Version, error) {
	if int64(len(data)) > store.maxObjectBytes {
		return s3disk.Version{}, fmt.Errorf("%w: s3store object %q exceeds %d bytes", s3disk.ErrResourceLimit, key, store.maxObjectBytes)
	}
	ctx, cancel := store.operationContext(ctx)
	defer cancel()
	input := &s3.PutObjectInput{
		Bucket:              aws.String(store.bucket),
		Key:                 aws.String(key),
		Body:                bytes.NewReader(data),
		ContentLength:       aws.Int64(int64(len(data))),
		ContentType:         aws.String("application/octet-stream"),
		ExpectedBucketOwner: optionalString(store.expectedBucketOwner),
	}
	if ifMatch != "" {
		input.IfMatch = aws.String(ifMatch)
	}
	if ifNoneMatch != "" {
		input.IfNoneMatch = aws.String(ifNoneMatch)
	}
	output, err := store.client.PutObject(ctx, input)
	if err != nil {
		return s3disk.Version{}, classifyError("put", key, err)
	}
	return responseVersion("put", key, aws.ToString(output.ETag), aws.ToString(output.VersionId))
}

func responseVersion(operation, key, etag, versionID string) (s3disk.Version, error) {
	version := s3disk.Version{ETag: etag, VersionID: versionID}
	if version.ETag == "" {
		return s3disk.Version{}, fmt.Errorf("%w: s3store %s %q returned an empty ETag", s3disk.ErrStoreIncompatible, operation, key)
	}
	if len(version.ETag) > s3disk.MaxStoreVersionTokenBytes || len(version.VersionID) > s3disk.MaxStoreVersionTokenBytes {
		return s3disk.Version{}, fmt.Errorf("%w: s3store %s %q returned an oversized version token", s3disk.ErrStoreIncompatible, operation, key)
	}
	return version, nil
}

func classifyError(operation, key string, err error) error {
	status := 0
	var responseError *smithyhttp.ResponseError
	if errors.As(err, &responseError) {
		status = responseError.HTTPStatusCode()
	}
	code := ""
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		code = apiError.ErrorCode()
	}
	var sentinel error
	switch {
	case status == http.StatusNotModified || code == "NotModified":
		sentinel = s3disk.ErrNotModified
	case code == "NoSuchBucket":
		sentinel = s3disk.ErrBucketNotFound
	case status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented ||
		code == "MethodNotAllowed" || code == "NotImplemented" || code == "NotSupported" || code == "UnsupportedOperation":
		sentinel = s3disk.ErrStoreOperationUnsupported
	case status == http.StatusMovedPermanently || status == http.StatusTemporaryRedirect ||
		code == "AuthorizationHeaderMalformed" || code == "IllegalLocationConstraintException" ||
		code == "InvalidLocationConstraint" || code == "PermanentRedirect" ||
		code == "IncorrectEndpoint" || code == "InvalidEndpoint" || code == "InvalidBucketName":
		sentinel = s3disk.ErrStoreMisconfigured
	case status == http.StatusUnauthorized || status == http.StatusForbidden || code == "AccessDenied" ||
		code == "InvalidAccessKeyId" || code == "SignatureDoesNotMatch" || code == "ExpiredToken" ||
		code == "InvalidToken" || code == "TokenRefreshRequired":
		sentinel = s3disk.ErrAccessDenied
	case status == http.StatusTooManyRequests || code == "SlowDown" || code == "Throttling":
		sentinel = s3disk.ErrRateLimited
	case code == "ConditionalRequestConflict" || code == "OperationAborted":
		// Both named 409 responses describe a conflicting operation which may
		// succeed when retried. They are not proof that If-Match or
		// If-None-Match evaluated false.
		sentinel = s3disk.ErrStoreUnavailable
	case code == "PreconditionFailed":
		sentinel = s3disk.ErrPrecondition
	case status == http.StatusRequestTimeout || status >= http.StatusInternalServerError ||
		code == "RequestTimeout" || code == "InternalError" || code == "ServiceUnavailable":
		sentinel = s3disk.ErrStoreUnavailable
	case code == "NoSuchKey" ||
		((code == "NotFound" || status == http.StatusNotFound) && (operation == "get" || operation == "head")):
		sentinel = s3disk.ErrObjectNotFound
	case status == http.StatusNotFound || code == "NotFound":
		sentinel = s3disk.ErrStoreMisconfigured
	case status == http.StatusPreconditionFailed:
		sentinel = s3disk.ErrPrecondition
	case status == http.StatusConflict:
		// A status-only 409 cannot establish which condition failed. AWS also
		// uses 409 for retryable conflicts such as OperationAborted.
		sentinel = s3disk.ErrStoreUnavailable
	default:
		return fmt.Errorf("s3store: %s %q: %w", operation, key, err)
	}
	if sentinel == s3disk.ErrObjectNotFound {
		return fmt.Errorf("s3store: %s %q: %w", operation, key, s3disk.ClassifyObjectNotFound(err))
	}
	return fmt.Errorf("s3store: %s %q: %w: %w", operation, key, sentinel, err)
}

var (
	_ s3disk.Store         = (*Store)(nil)
	_ s3disk.ObjectDeleter = (*Store)(nil)
)
