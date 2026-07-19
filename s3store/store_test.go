package s3store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/vibe-agi/s3disk"
)

func TestConfigDiagnosticsRedactCredentials(t *testing.T) {
	t.Parallel()
	provider := &diagnosticCredentialsProvider{
		accessKey: "AKIA-DO-NOT-LOG", secretKey: "secret-do-not-log", token: "token-do-not-log",
	}
	config := Config{
		Bucket:              "customer-bucket",
		CredentialsProvider: provider,
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	outputs := []string{
		string(encoded),
		fmt.Sprint(config),
		fmt.Sprintf("%+v", config),
		fmt.Sprintf("%#v", config),
	}
	for _, output := range outputs {
		for _, secret := range []string{provider.accessKey, provider.secretKey, provider.token} {
			if strings.Contains(output, secret) {
				t.Fatalf("diagnostic output exposed credentials: %q", output)
			}
		}
		if !strings.Contains(output, "provider") {
			t.Fatalf("diagnostic output did not identify redacted credential source: %q", output)
		}
	}
}

func TestStoreDiagnosticsRedactPointerAndCopiedValue(t *testing.T) {
	t.Parallel()
	const (
		secretClient = "store-client-secret-do-not-log"
		secretBucket = "store-bucket-secret-do-not-log"
		secretOwner  = "store-owner-secret-do-not-log"
	)
	store := &Store{
		bucket: secretBucket, expectedBucketOwner: secretOwner,
		client: &diagnosticStoreAPI{secret: secretClient}, sdkClient: &s3.Client{},
		maxObjectBytes: 1024, operationTimeout: time.Minute,
	}
	value := *store
	pointerJSON, err := json.Marshal(store)
	if err != nil {
		t.Fatalf("Marshal pointer: %v", err)
	}
	valueJSON, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal copied value: %v", err)
	}
	for _, output := range []string{
		fmt.Sprint(store), fmt.Sprintf("%+v", store), fmt.Sprintf("%#v", store),
		fmt.Sprint(value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value),
		string(pointerJSON), string(valueJSON),
	} {
		for _, secret := range []string{secretClient, secretBucket, secretOwner} {
			if strings.Contains(output, secret) {
				t.Fatalf("Store diagnostic exposed %q: %s", secret, output)
			}
		}
		if !strings.Contains(output, "redacted") {
			t.Fatalf("Store diagnostic omitted redaction marker: %s", output)
		}
	}
}

type diagnosticStoreAPI struct {
	api
	secret string
}

type diagnosticCredentialsProvider struct {
	accessKey string
	secretKey string
	token     string
}

func (provider *diagnosticCredentialsProvider) RetrieveCredentials(context.Context) (Credentials, error) {
	return Credentials{
		AccessKeyID: provider.accessKey, SecretAccessKey: provider.secretKey, SessionToken: provider.token,
	}, nil
}

func TestCredentialsProviderAdapter(t *testing.T) {
	t.Parallel()
	expires := time.Unix(1_900_000_000, 0).UTC()
	adapter := credentialsProviderAdapter{provider: CredentialsProviderFunc(func(context.Context) (Credentials, error) {
		return Credentials{
			AccessKeyID:     "rotating-access",
			SecretAccessKey: "rotating-secret",
			SessionToken:    "rotating-token",
			Expires:         expires,
		}, nil
	})}
	got, err := adapter.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if got.AccessKeyID != "rotating-access" || got.SecretAccessKey != "rotating-secret" ||
		got.SessionToken != "rotating-token" || !got.CanExpire || !got.Expires.Equal(expires) {
		t.Fatalf("credentials = %+v, want rotating expiring credentials", got)
	}

	providerCause := errors.New("credential service unavailable")
	_, err = (credentialsProviderAdapter{provider: CredentialsProviderFunc(func(context.Context) (Credentials, error) {
		return Credentials{}, providerCause
	})}).Retrieve(context.Background())
	if !errors.Is(err, providerCause) {
		t.Fatalf("provider error = %v, want preserved cause", err)
	}
	_, err = (credentialsProviderAdapter{provider: CredentialsProviderFunc(func(context.Context) (Credentials, error) {
		return Credentials{AccessKeyID: "access-only"}, nil
	})}).Retrieve(context.Background())
	if err == nil {
		t.Fatal("provider with an empty secret key was accepted")
	}
}

func TestCredentialValueDiagnosticsAreRedacted(t *testing.T) {
	t.Parallel()
	credentials := Credentials{
		AccessKeyID: "provider-access-do-not-log", SecretAccessKey: "provider-secret-do-not-log",
		SessionToken: "provider-token-do-not-log", Expires: time.Unix(1_900_000_000, 0).UTC(),
	}
	encoded, err := json.Marshal(credentials)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	for _, output := range []string{string(encoded), fmt.Sprint(credentials), fmt.Sprintf("%+v", credentials), fmt.Sprintf("%#v", credentials)} {
		for _, secret := range []string{credentials.AccessKeyID, credentials.SecretAccessKey, credentials.SessionToken} {
			if strings.Contains(output, secret) {
				t.Fatalf("credential diagnostic output exposed a secret: %q", output)
			}
		}
		if !strings.Contains(output, "has_session_token") {
			t.Fatalf("credential diagnostic output omitted safe lifecycle metadata: %q", output)
		}
	}
}

func TestConfigRejectsUnsafeValues(t *testing.T) {
	t.Parallel()
	var nilProvider CredentialsProviderFunc
	for _, test := range []struct {
		name   string
		config Config
		want   string
	}{
		{name: "typed-nil-provider", config: Config{Bucket: "bucket", CredentialsProvider: nilProvider}, want: "typed nil"},
		{name: "retry-too-small", config: Config{Bucket: "bucket", RetryMaxAttempts: -1}, want: "retry max attempts"},
		{name: "retry-too-large", config: Config{Bucket: "bucket", RetryMaxAttempts: maximumRetryAttempts + 1}, want: "retry max attempts"},
		{name: "negative-operation-timeout", config: Config{Bucket: "bucket", OperationTimeout: -time.Nanosecond}, want: "operation timeout"},
		{name: "excessive-operation-timeout", config: Config{Bucket: "bucket", OperationTimeout: MaximumOperationTimeout + time.Nanosecond}, want: "operation timeout"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(context.Background(), test.config)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("New error = %v, want text %q", err, test.want)
			}
		})
	}
}

type blockingGetAPI struct{ api }

func (*blockingGetAPI) GetObject(ctx context.Context, _ *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type blockingBodyGetAPI struct{ api }

func (*blockingBodyGetAPI) GetObject(ctx context.Context, _ *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{
		Body: &contextBlockingBody{ctx: ctx}, ETag: aws.String("etag"),
	}, nil
}

type contextBlockingBody struct {
	ctx context.Context
}

func (body *contextBlockingBody) Read([]byte) (int, error) {
	<-body.ctx.Done()
	return 0, body.ctx.Err()
}

func (*contextBlockingBody) Close() error { return nil }

func TestStoreAppliesPerOperationDeadline(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		client api
	}{
		{name: "before-headers", client: &blockingGetAPI{}},
		{name: "response-body", client: &blockingBodyGetAPI{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &Store{
				bucket: "bucket", client: test.client, maxObjectBytes: 1024,
				operationTimeout: 20 * time.Millisecond,
			}
			started := time.Now()
			_, err := store.Get(context.Background(), "blocked", s3disk.GetOptions{})
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Get error = %v, want context deadline", err)
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("operation timeout took %s, want well below one second", elapsed)
			}
		})
	}
}

func TestStorePreservesEarlierCallerCancellation(t *testing.T) {
	t.Parallel()
	store := &Store{
		bucket: "bucket", client: &blockingGetAPI{}, maxObjectBytes: 1024,
		operationTimeout: time.Minute,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := store.Get(ctx, "blocked", s3disk.GetOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Get error = %v, want caller cancellation", err)
	}
}

func TestExpectedBucketOwnerValidation(t *testing.T) {
	t.Parallel()
	for _, owner := range []string{"", "123456789012"} {
		if err := validateExpectedBucketOwner(owner); err != nil {
			t.Errorf("validateExpectedBucketOwner(%q) = %v", owner, err)
		}
	}
	for _, owner := range []string{"123", "12345678901x", "１２３４５６７８９０１２"} {
		if err := validateExpectedBucketOwner(owner); err == nil {
			t.Errorf("invalid expected owner %q was accepted", owner)
		}
	}
}

type ownerCapturingAPI struct {
	api
	getOwner    string
	headOwner   string
	putOwner    string
	deleteOwner string
}

func (client *ownerCapturingAPI) GetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	client.getOwner = aws.ToString(input.ExpectedBucketOwner)
	return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader("body")), ETag: aws.String("etag")}, nil
}

func (client *ownerCapturingAPI) HeadObject(_ context.Context, input *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	client.headOwner = aws.ToString(input.ExpectedBucketOwner)
	return &s3.HeadObjectOutput{ETag: aws.String("etag")}, nil
}

func (client *ownerCapturingAPI) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	client.putOwner = aws.ToString(input.ExpectedBucketOwner)
	return &s3.PutObjectOutput{ETag: aws.String("etag")}, nil
}

func (client *ownerCapturingAPI) DeleteObject(_ context.Context, input *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	client.deleteOwner = aws.ToString(input.ExpectedBucketOwner)
	return &s3.DeleteObjectOutput{}, nil
}

func TestExpectedBucketOwnerIsSentOnEveryOperation(t *testing.T) {
	t.Parallel()
	client := &ownerCapturingAPI{}
	store := &Store{
		bucket:              "bucket",
		expectedBucketOwner: "123456789012",
		client:              client,
		maxObjectBytes:      1024,
	}
	ctx := context.Background()
	if _, err := store.Get(ctx, "key", s3disk.GetOptions{}); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := store.Head(ctx, "key"); err != nil {
		t.Fatalf("Head: %v", err)
	}
	if _, err := store.PutIfAbsent(ctx, "key", []byte("body")); err != nil {
		t.Fatalf("PutIfAbsent: %v", err)
	}
	if err := store.Delete(ctx, "key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	for operation, owner := range map[string]string{
		"GET": client.getOwner, "HEAD": client.headOwner,
		"PUT": client.putOwner, "DELETE": client.deleteOwner,
	} {
		if owner != store.expectedBucketOwner {
			t.Errorf("%s expected owner = %q, want %q", operation, owner, store.expectedBucketOwner)
		}
	}
}

type getOnlyAPI struct {
	api
	body          string
	contentLength *int64
}

func (client *getOnlyAPI) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{
		Body:          io.NopCloser(strings.NewReader(client.body)),
		ContentLength: client.contentLength,
		ETag:          aws.String("etag"),
	}, nil
}

func TestGetEnforcesPerRequestLimit(t *testing.T) {
	t.Parallel()
	for _, contentLength := range []*int64{aws.Int64(8), nil} {
		store := &Store{bucket: "bucket", client: &getOnlyAPI{body: "12345678", contentLength: contentLength}, maxObjectBytes: 1024}
		if _, err := store.Get(context.Background(), "key", s3disk.GetOptions{MaxBytes: 4}); !errors.Is(err, s3disk.ErrResourceLimit) {
			t.Fatalf("Get with content length %v error = %v, want ErrResourceLimit", contentLength, err)
		}
	}
}

func TestGetMaxInt64LimitDoesNotOverflow(t *testing.T) {
	t.Parallel()
	store := &Store{
		bucket:         "bucket",
		client:         &getOnlyAPI{body: "not empty"},
		maxObjectBytes: math.MaxInt64,
	}

	object, err := store.Get(context.Background(), "key", s3disk.GetOptions{})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got, want := string(object.Data), "not empty"; got != want {
		t.Fatalf("Get data = %q, want %q", got, want)
	}
}

type putOnlyAPI struct {
	api
	input *s3.PutObjectInput
}

type putErrorAPI struct {
	api
	err error
}

func (client *putErrorAPI) PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return nil, client.err
}

type versionIDOnlyAPI struct{ api }

func (*versionIDOnlyAPI) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{
		Body:      io.NopCloser(strings.NewReader("body")),
		VersionId: aws.String("version-only"),
	}, nil
}

func (*versionIDOnlyAPI) HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	return &s3.HeadObjectOutput{VersionId: aws.String("version-only")}, nil
}

func (*versionIDOnlyAPI) PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return &s3.PutObjectOutput{VersionId: aws.String("version-only")}, nil
}

func TestSuccessfulOperationsRejectVersionIDWithoutETag(t *testing.T) {
	t.Parallel()
	store := &Store{bucket: "bucket", client: &versionIDOnlyAPI{}, maxObjectBytes: 1024}
	ctx := context.Background()
	if _, err := store.Get(ctx, "key", s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("Get error = %v, want ErrStoreIncompatible", err)
	}
	if _, err := store.Head(ctx, "key"); !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("Head error = %v, want ErrStoreIncompatible", err)
	}
	if _, err := store.PutIfAbsent(ctx, "key", []byte("body")); !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("PutIfAbsent error = %v, want ErrStoreIncompatible", err)
	}
}

func (client *putOnlyAPI) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	client.input = input
	return &s3.PutObjectOutput{ETag: aws.String("new-etag"), VersionId: aws.String("new-version-id")}, nil
}

func TestCompareAndSwapUsesETagAsTheOnlyCondition(t *testing.T) {
	t.Parallel()
	client := &putOnlyAPI{}
	store := &Store{bucket: "bucket", client: client, maxObjectBytes: 1024}

	version, err := store.CompareAndSwap(context.Background(), "key", &s3disk.Version{
		ETag:      "old-etag",
		VersionID: "diagnostic-only",
	}, []byte("next"))
	if err != nil {
		t.Fatalf("CompareAndSwap: %v", err)
	}
	if client.input == nil || aws.ToString(client.input.IfMatch) != "old-etag" {
		t.Fatalf("IfMatch = %q, want old-etag", aws.ToString(client.input.IfMatch))
	}
	if version.ETag != "new-etag" || version.VersionID != "new-version-id" {
		t.Fatalf("version = %+v, want returned ETag and diagnostic VersionID", version)
	}

	_, err = store.CompareAndSwap(context.Background(), "key", &s3disk.Version{VersionID: "not-a-cas-token"}, []byte("next"))
	if err == nil {
		t.Fatal("CompareAndSwap accepted VersionID without an ETag")
	}

	oversized := strings.Repeat("x", s3disk.MaxStoreVersionTokenBytes+1)
	_, err = store.CompareAndSwap(context.Background(), "key", &s3disk.Version{ETag: oversized}, []byte("next"))
	if !errors.Is(err, s3disk.ErrResourceLimit) {
		t.Fatalf("CompareAndSwap oversized ETag error = %v, want ErrResourceLimit", err)
	}
}

func TestPutRejectsBodyBeyondProtocolLimitBeforeIO(t *testing.T) {
	t.Parallel()
	client := &putOnlyAPI{}
	store := &Store{bucket: "bucket", client: client, maxObjectBytes: 4}
	if _, err := store.PutIfAbsent(context.Background(), "key", []byte("12345")); !errors.Is(err, s3disk.ErrResourceLimit) {
		t.Fatalf("PutIfAbsent error = %v, want ErrResourceLimit", err)
	}
	if client.input != nil {
		t.Fatal("oversized Put reached the S3 client")
	}
}

func TestCompareAndSwapNormalizesMissingIfMatch(t *testing.T) {
	t.Parallel()
	providerError := &smithy.GenericAPIError{Code: "NoSuchKey", Message: "missing"}
	store := &Store{
		bucket:         "bucket",
		client:         &putErrorAPI{err: providerError},
		maxObjectBytes: 1024,
	}

	_, err := store.CompareAndSwap(context.Background(), "missing", &s3disk.Version{ETag: "old"}, []byte("next"))
	if !errors.Is(err, s3disk.ErrPrecondition) {
		t.Fatalf("CompareAndSwap missing error = %v, want ErrPrecondition", err)
	}
	if !errors.Is(err, s3disk.ErrObjectNotFound) {
		t.Fatalf("CompareAndSwap missing error lost provider classification: %v", err)
	}
	var apiError smithy.APIError
	if !errors.As(err, &apiError) || apiError.ErrorCode() != "NoSuchKey" {
		t.Fatalf("CompareAndSwap missing error lost provider cause: %v", err)
	}
}

func TestEndpointSecurityValidation(t *testing.T) {
	t.Parallel()
	for _, endpoint := range []string{"", "https://s3.example.com", "http://127.0.0.1:9000", "http://localhost:9000"} {
		if err := validateEndpoint(endpoint, false); err != nil {
			t.Errorf("validateEndpoint(%q) = %v", endpoint, err)
		}
	}
	if err := validateEndpoint("http://s3.example.com", false); err == nil {
		t.Fatal("insecure remote endpoint was accepted without opt-in")
	}
	if err := validateEndpoint("http://s3.example.com", true); err != nil {
		t.Fatalf("explicit insecure endpoint opt-in: %v", err)
	}
	for _, endpoint := range []string{"s3.example.com", "ftp://s3.example.com", "https://user:secret@s3.example.com", "https://s3.example.com?secret=x"} {
		if err := validateEndpoint(endpoint, false); err == nil {
			t.Errorf("invalid endpoint %q was accepted", endpoint)
		}
	}
}

func TestClassifyStoreErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		code string
		want error
	}{
		{code: "NoSuchBucket", want: s3disk.ErrBucketNotFound},
		{code: "AuthorizationHeaderMalformed", want: s3disk.ErrStoreMisconfigured},
		{code: "NoSuchKey", want: s3disk.ErrObjectNotFound},
		{code: "AccessDenied", want: s3disk.ErrAccessDenied},
		{code: "ExpiredToken", want: s3disk.ErrAccessDenied},
		{code: "SlowDown", want: s3disk.ErrRateLimited},
		{code: "RequestTimeout", want: s3disk.ErrStoreUnavailable},
		{code: "InternalError", want: s3disk.ErrStoreUnavailable},
		{code: "ServiceUnavailable", want: s3disk.ErrStoreUnavailable},
		{code: "NotImplemented", want: s3disk.ErrStoreOperationUnsupported},
		{code: "MethodNotAllowed", want: s3disk.ErrStoreOperationUnsupported},
		{code: "PreconditionFailed", want: s3disk.ErrPrecondition},
		{code: "ConditionalRequestConflict", want: s3disk.ErrStoreUnavailable},
		{code: "OperationAborted", want: s3disk.ErrStoreUnavailable},
	}
	for _, test := range cases {
		err := classifyError("get", "key", &smithy.GenericAPIError{Code: test.code, Message: "test"})
		if !errors.Is(err, test.want) {
			t.Errorf("classify %s = %v, want %v", test.code, err, test.want)
		}
	}
}

func TestClassifyConflictUsesNamedS3Semantics(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		status int
		code   string
		want   error
	}{
		{name: "status-only-409", status: http.StatusConflict, want: s3disk.ErrStoreUnavailable},
		{name: "status-only-412", status: http.StatusPreconditionFailed, want: s3disk.ErrPrecondition},
		{name: "named-precondition-on-409", status: http.StatusConflict, code: "PreconditionFailed", want: s3disk.ErrPrecondition},
		{name: "named-conditional-conflict-on-412", status: http.StatusPreconditionFailed, code: "ConditionalRequestConflict", want: s3disk.ErrStoreUnavailable},
		{name: "named-operation-aborted-on-412", status: http.StatusPreconditionFailed, code: "OperationAborted", want: s3disk.ErrStoreUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			underlying := error(&smithy.GenericAPIError{Code: test.code, Message: "provider detail"})
			if test.code == "" {
				underlying = errors.New("status-only provider detail")
			}
			responseError := &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: test.status}},
				Err:      underlying,
			}
			err := classifyError("put", "key", responseError)
			if !errors.Is(err, test.want) || !errors.Is(err, underlying) {
				t.Fatalf("classify status=%d code=%q = %v, want %v and preserved cause", test.status, test.code, err, test.want)
			}
			other := s3disk.ErrPrecondition
			if test.want == s3disk.ErrPrecondition {
				other = s3disk.ErrStoreUnavailable
			}
			if errors.Is(err, other) {
				t.Fatalf("classify status=%d code=%q also matched %v: %v", test.status, test.code, other, err)
			}
		})
	}
}

func TestClassifyStoreErrorPreservesTemporaryHTTPFailure(t *testing.T) {
	t.Parallel()
	underlying := errors.New("provider request id is preserved")
	responseError := &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusBadGateway}},
		Err:      underlying,
	}

	err := classifyError("put", "probe", responseError)
	if !errors.Is(err, s3disk.ErrStoreUnavailable) {
		t.Fatalf("classify 502 = %v, want ErrStoreUnavailable", err)
	}
	if !errors.Is(err, underlying) {
		t.Fatalf("classify 502 lost underlying cause: %v", err)
	}
}

func TestClassifyStatusOnlyNotFoundByOperation(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		operation string
		want      error
	}{
		{operation: "get", want: s3disk.ErrObjectNotFound},
		{operation: "head", want: s3disk.ErrObjectNotFound},
		{operation: "put", want: s3disk.ErrStoreMisconfigured},
		{operation: "delete", want: s3disk.ErrStoreMisconfigured},
	} {
		underlying := errors.New("status-only provider error")
		responseError := &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusNotFound}},
			Err:      underlying,
		}
		err := classifyError(test.operation, "key", responseError)
		if !errors.Is(err, test.want) || !errors.Is(err, underlying) {
			t.Errorf("classify %s 404 = %v, want %v and preserved cause", test.operation, err, test.want)
		}
	}

	err := classifyError("put", "key", &smithy.GenericAPIError{Code: "NotFound", Message: "generic"})
	if !errors.Is(err, s3disk.ErrStoreMisconfigured) {
		t.Fatalf("classify PUT NotFound = %v, want ErrStoreMisconfigured", err)
	}
}

func TestClassifyObjectNotFoundUsesDefinitiveMarkerAndPreservesCause(t *testing.T) {
	t.Parallel()
	providerError := &smithy.GenericAPIError{Code: "NoSuchKey", Message: "provider diagnostic"}

	err := classifyError("head", "key", providerError)
	if !errors.Is(err, s3disk.ErrObjectNotFound) || !errors.Is(err, providerError) {
		t.Fatalf("classify NoSuchKey = %v, want ErrObjectNotFound and preserved provider cause", err)
	}
	var preserved *smithy.GenericAPIError
	if !errors.As(err, &preserved) || preserved != providerError {
		t.Fatalf("classify NoSuchKey errors.As = %v, want original provider error", preserved)
	}
	if _, joined := err.(interface{ Unwrap() []error }); joined {
		t.Fatalf("classify NoSuchKey returned an ambiguous joined root: %T", err)
	}
	classified := errors.Unwrap(err)
	if classified == nil {
		t.Fatal("classify NoSuchKey omitted the definitive classification wrapper")
	}
	if _, joined := classified.(interface{ Unwrap() []error }); joined {
		t.Fatalf("classify NoSuchKey marker used joined provider siblings: %T", classified)
	}
}
