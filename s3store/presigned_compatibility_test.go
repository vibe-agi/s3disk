package s3store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
)

func TestProbePresignedGetCompatibilityAnonymousOnlyS3Semantics(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "PROBE-ACCESS-DO-NOT-LOG", "probe-secret-do-not-log", "probe-token-do-not-log")
	anonymousClient := &http.Client{}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(serverURL, []*http.Cookie{{Name: "ambient-session", Value: "must-not-be-sent"}})
	anonymousClient.Jar = jar

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), PresignedGetCompatibilityProbeOptions{
		ObjectKeyPrefix: "private/probes",
		TotalTimeout:    5 * time.Second, CapabilityLifetime: time.Minute,
		CleanupTimeout: time.Second, HTTPClient: anonymousClient,
	})
	if err != nil {
		t.Fatalf("ProbePresignedGetCompatibilityWithOptions: %v", err)
	}
	if report.Scope != PresignedGetCompatibilitySingleEndpointFiniteProbe ||
		report.Evidence.PresigningTopology != PresignedGetCompatibilitySameStore ||
		report.Evidence.PresigningStoreInputDistinct || report.Evidence.CrossConfigurationCanaryBindingObserved ||
		report.Status != PresignedGetCompatibilityPassed || !report.Compatible || !report.Complete ||
		report.RequiredChecks != PresignedGetCompatibilityRequiredChecks || len(report.Checks) != PresignedGetCompatibilityRequiredChecks {
		t.Fatalf("report = %+v", report)
	}
	wantIDs := []PresignedGetCompatibilityCheckID{
		PresignedGetCompatibilityCheckConfiguration,
		PresignedGetCompatibilityCheckProbeObjectCreate,
		PresignedGetCompatibilityCheckExactGetPresign,
		PresignedGetCompatibilityCheckAnonymousHeaders,
		PresignedGetCompatibilityCheckInitialGet,
		PresignedGetCompatibilityCheckSameURLReplacement,
		PresignedGetCompatibilityCheckCurrentETagConditional,
		PresignedGetCompatibilityCheckStaleETagConditional,
		PresignedGetCompatibilityCheckAuthorizationQueryBinding,
		PresignedGetCompatibilityCheckAnonymousPolicyRejected,
		PresignedGetCompatibilityCheckNamedUnsignedHeaderOverrides,
		PresignedGetCompatibilityCheckExactPathBinding,
		PresignedGetCompatibilityCheckHEADMutationRejected,
		PresignedGetCompatibilityCheckPUTRejectedUnchanged,
	}
	for index, check := range report.Checks {
		if check.ID != wantIDs[index] || check.Status != PresignedGetCompatibilityPassed || check.Reason != "" || check.Summary == "" {
			t.Errorf("check[%d] = %+v, want passed %q", index, check, wantIDs[index])
		}
	}
	if len(report.Limitations) != 10 ||
		report.Limitations[0] != PresignedGetCompatibilityLimitationFutureStatesNotProven ||
		report.Limitations[1] != PresignedGetCompatibilityLimitationExpiryNotSampled ||
		report.Limitations[2] != PresignedGetCompatibilityLimitationOtherMethodsNotSampled ||
		report.Limitations[3] != PresignedGetCompatibilityLimitationArbitraryQueryBindingNotProven ||
		report.Limitations[4] != PresignedGetCompatibilityLimitationHEADAndBodylessStatusWireBodyNotVisible ||
		report.Limitations[5] != PresignedGetCompatibilityLimitationDiscardedWireMetadataAndExtraBytes ||
		report.Limitations[6] != PresignedGetCompatibilityLimitationBucketPublicAccessPolicyNotFullyProven ||
		report.Limitations[7] != PresignedGetCompatibilityLimitationPUTPayloadVariantsBeyondNamedSamples ||
		report.Limitations[8] != PresignedGetCompatibilityLimitationArbitraryUnsignedHeaderOverrideBinding ||
		report.Limitations[9] != PresignedGetCompatibilityLimitationBucketAndOriginBindingNotSampled {
		t.Fatalf("limitations = %v", report.Limitations)
	}
	if report.Cleanup.Status != PresignedGetCompatibilityCleanupSucceeded || report.Cleanup.Attempted != 2 ||
		report.Cleanup.Succeeded != 2 || report.Cleanup.Failed != 0 || report.Cleanup.CurrentObjectsMayRemain ||
		!report.Cleanup.HistoricalVersionsMayRemain {
		t.Fatalf("cleanup = %+v", report.Cleanup)
	}

	service.mu.Lock()
	anonymousRequests := service.anonymousRequests
	unsignedRequests := service.unsignedRequests
	credentialedGets := service.credentialedGets
	forbiddenHeaders := service.anonymousForbiddenHeaders
	missingRuntimeHeaders := service.anonymousMissingRuntimeHeaders
	requestsWithoutClose := service.anonymousRequestsWithoutClose
	remaining := len(service.objects)
	service.mu.Unlock()
	if anonymousRequests != 55 {
		t.Fatalf("signed anonymous S3 requests = %d, want 55", anonymousRequests)
	}
	if unsignedRequests != 5 {
		t.Fatalf("unsigned anonymous S3 requests = %d, want 5", unsignedRequests)
	}
	if credentialedGets != 40 {
		t.Fatalf("credentialed exact read-backs = %d, want 40", credentialedGets)
	}
	if forbiddenHeaders != 0 {
		t.Fatalf("anonymous requests with credential/cookie headers = %d, want 0", forbiddenHeaders)
	}
	if missingRuntimeHeaders != 0 {
		t.Fatalf("anonymous requests missing cache-bypass/identity headers = %d, want 0", missingRuntimeHeaders)
	}
	if requestsWithoutClose != 0 {
		t.Fatalf("anonymous requests that allowed connection reuse = %d, want 0", requestsWithoutClose)
	}
	if remaining != 0 {
		t.Fatalf("remaining current objects = %d, want 0", remaining)
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	diagnostics := []string{string(encoded), fmt.Sprint(report), fmt.Sprintf("%+v", report), fmt.Sprintf("%#v", report), fmt.Sprint(report.Cleanup)}
	for _, check := range report.Checks {
		diagnostics = append(diagnostics, fmt.Sprint(check), fmt.Sprintf("%#v", check))
	}
	for _, diagnostic := range diagnostics {
		assertPresignedGetProbeDiagnosticRedacted(t, diagnostic)
	}
}

func TestProbePresignedGetCompatibilityWithSeparatePresigningStore(t *testing.T) {
	t.Parallel()
	const (
		writerAccess = "WRITER-ACCESS-DO-NOT-LOG"
		writerSecret = "writer-secret-do-not-log"
		signerAccess = "SIGNER-ACCESS-DO-NOT-LOG"
		signerSecret = "signer-secret-do-not-log"
		signerToken  = "signer-token-do-not-log"
	)
	service := newPresignedGetProbeTestService(t)
	var writerRequests, signerBearerRequests, wrongIdentityRequests atomic.Int64
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if credential := request.URL.Query().Get("X-Amz-Credential"); credential != "" {
			if strings.HasPrefix(credential, signerAccess+"/") {
				signerBearerRequests.Add(1)
			} else {
				wrongIdentityRequests.Add(1)
			}
		}
		if authorization := request.Header.Get("Authorization"); authorization != "" {
			if strings.Contains(authorization, "Credential="+writerAccess+"/") {
				writerRequests.Add(1)
			} else {
				wrongIdentityRequests.Add(1)
			}
		}
		service.ServeHTTP(writer, request)
	})
	writerServer := httptest.NewServer(handler)
	t.Cleanup(writerServer.Close)
	presigningServer := httptest.NewServer(handler)
	t.Cleanup(presigningServer.Close)

	writerStore := newPresignedGetProbeTestStore(t, writerServer, writerAccess, writerSecret, "")
	signerTransport := &countingRejectingPresignedGetRoundTripper{}
	presigningStore, err := New(context.Background(), Config{
		Bucket: "probe-bucket", Region: "us-east-1", Endpoint: presigningServer.URL, UsePathStyle: true,
		HTTPClient: &http.Client{Transport: signerTransport}, OperationTimeout: 2 * time.Second,
		CredentialsProvider: CredentialsProviderFunc(func(context.Context) (Credentials, error) {
			return Credentials{AccessKeyID: signerAccess, SecretAccessKey: signerSecret, SessionToken: signerToken}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	report, err := writerStore.ProbePresignedGetCompatibilityWithPresigningStore(
		context.Background(), presigningStore, PresignedGetCompatibilityProbeOptions{
			ObjectKeyPrefix: "private/probes", TotalTimeout: 5 * time.Second,
			CapabilityLifetime: time.Minute, CleanupTimeout: time.Second,
		},
	)
	if err != nil {
		t.Fatalf("split presigned GET compatibility: %v", err)
	}
	if report.Scope != PresignedGetCompatibilityCrossConfigurationFiniteProbe ||
		report.Status != PresignedGetCompatibilityPassed || !report.Compatible || !report.Complete ||
		report.Evidence.PresigningTopology != PresignedGetCompatibilitySeparateStore ||
		!report.Evidence.PresigningStoreInputDistinct ||
		!report.Evidence.CrossConfigurationCanaryBindingObserved {
		t.Fatalf("split report = %+v", report)
	}
	if len(report.Limitations) != 10 ||
		report.Limitations[9] != PresignedGetCompatibilityLimitationCrossConfigurationBindingNotAuthenticated {
		t.Fatalf("split limitations = %v", report.Limitations)
	}
	if report.Cleanup.Status != PresignedGetCompatibilityCleanupSucceeded {
		t.Fatalf("split cleanup = %+v", report.Cleanup)
	}
	if signerTransport.calls.Load() != 0 {
		t.Fatalf("presigning Store data-plane calls = %d, want 0", signerTransport.calls.Load())
	}
	if writerRequests.Load() == 0 || signerBearerRequests.Load() == 0 || wrongIdentityRequests.Load() != 0 {
		t.Fatalf("request identities: writer=%d signer-bearer=%d wrong=%d",
			writerRequests.Load(), signerBearerRequests.Load(), wrongIdentityRequests.Load())
	}

	encoded, marshalErr := json.Marshal(report)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, diagnostic := range []string{string(encoded), report.String(), fmt.Sprintf("%+v", report), fmt.Sprintf("%#v", report)} {
		for _, secret := range []string{
			writerAccess, writerSecret, signerAccess, signerSecret, signerToken,
			writerServer.URL, presigningServer.URL, "probe-bucket", "private/probes", "X-Amz-Credential", "X-Amz-Signature",
		} {
			if strings.Contains(diagnostic, secret) {
				t.Fatalf("split diagnostic leaked %q: %s", secret, diagnostic)
			}
		}
	}
}

func TestProbePresignedGetCompatibilityWithPresigningStoreRejectsInvalidPairsBeforeIO(t *testing.T) {
	t.Parallel()
	var requests atomic.Int64
	service := newPresignedGetProbeTestService(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		service.ServeHTTP(writer, request)
	}))
	t.Cleanup(server.Close)
	writerStore := newPresignedGetProbeTestStore(t, server, "writer", "writer-secret", "")
	validSigner := newPresignedGetProbeTestStore(t, server, "signer", "signer-secret", "")
	sharedSDKClient := *writerStore
	differentBucket := *validSigner
	differentBucket.bucket = "different-bucket"
	var nilWriter *Store

	tests := []struct {
		name         string
		writer       *Store
		signer       *Store
		wantScope    PresignedGetCompatibilityScope
		wantTopology PresignedGetCompatibilityPresigningTopology
		wantDistinct bool
	}{
		{name: "nil writer", writer: nilWriter, signer: validSigner, wantScope: PresignedGetCompatibilitySingleEndpointFiniteProbe},
		{name: "nil signer", writer: writerStore, signer: nil, wantScope: PresignedGetCompatibilitySingleEndpointFiniteProbe},
		{name: "same Store", writer: writerStore, signer: writerStore, wantScope: PresignedGetCompatibilitySingleEndpointFiniteProbe, wantTopology: PresignedGetCompatibilitySameStore},
		{name: "shared SDK client", writer: writerStore, signer: &sharedSDKClient, wantScope: PresignedGetCompatibilityCrossConfigurationFiniteProbe, wantTopology: PresignedGetCompatibilitySeparateStore, wantDistinct: true},
		{name: "different bucket", writer: writerStore, signer: &differentBucket, wantScope: PresignedGetCompatibilityCrossConfigurationFiniteProbe, wantTopology: PresignedGetCompatibilitySeparateStore, wantDistinct: true},
		{name: "unconfigured signer", writer: writerStore, signer: &Store{}, wantScope: PresignedGetCompatibilityCrossConfigurationFiniteProbe, wantTopology: PresignedGetCompatibilitySeparateStore, wantDistinct: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report, err := test.writer.ProbePresignedGetCompatibilityWithPresigningStore(
				context.Background(), test.signer, shortPresignedGetProbeOptions(server.Client()),
			)
			if !errors.Is(err, s3disk.ErrStoreMisconfigured) ||
				report.Status != PresignedGetCompatibilityConfigurationError || report.Compatible || report.Complete ||
				report.Scope != test.wantScope || report.Evidence.PresigningTopology != test.wantTopology ||
				report.Evidence.PresigningStoreInputDistinct != test.wantDistinct ||
				report.Evidence.CrossConfigurationCanaryBindingObserved ||
				report.Cleanup.Status != PresignedGetCompatibilityCleanupNotAttempted ||
				len(report.Checks) != 1 || report.Checks[0].ID != PresignedGetCompatibilityCheckConfiguration {
				t.Fatalf("invalid pair: report=%+v err=%v", report, err)
			}
			if requests.Load() != 0 {
				t.Fatalf("invalid pair performed %d S3 requests", requests.Load())
			}
		})
	}
}

func TestProbePresignedGetCompatibilityWithPresigningStoreUsesSignerTLSRequirementBeforeIO(t *testing.T) {
	t.Parallel()
	var requests atomic.Int64
	service := newPresignedGetProbeTestService(t)
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		service.ServeHTTP(writer, request)
	})
	writerServer := httptest.NewServer(handler)
	t.Cleanup(writerServer.Close)
	presigningServer := httptest.NewTLSServer(handler)
	t.Cleanup(presigningServer.Close)
	writerStore := newPresignedGetProbeTestStore(t, writerServer, "writer", "writer-secret", "")
	presigningStore, err := New(context.Background(), Config{
		Bucket: "probe-bucket", Region: "us-east-1", Endpoint: presigningServer.URL, UsePathStyle: true,
		HTTPClient: presigningServer.Client(), OperationTimeout: 2 * time.Second,
		CredentialsProvider: CredentialsProviderFunc(func(context.Context) (Credentials, error) {
			return Credentials{AccessKeyID: "signer", SecretAccessKey: "signer-secret"}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	report, probeErr := writerStore.ProbePresignedGetCompatibilityWithPresigningStore(
		context.Background(), presigningStore, shortPresignedGetProbeOptions(nil),
	)
	if probeErr == nil || report.Status != PresignedGetCompatibilityConfigurationError ||
		report.Evidence.PresigningTopology != PresignedGetCompatibilitySeparateStore ||
		!report.Evidence.PresigningStoreInputDistinct || report.Evidence.CrossConfigurationCanaryBindingObserved ||
		report.Cleanup.Status != PresignedGetCompatibilityCleanupNotAttempted {
		t.Fatalf("signer TLS requirement: report=%+v err=%v", report, probeErr)
	}
	if requests.Load() != 0 {
		t.Fatalf("missing signer TLS roots performed %d S3 requests", requests.Load())
	}
}

func TestProbePresignedGetCompatibilityWithPresigningStoreCredentialFailureCleansAndRedacts(t *testing.T) {
	t.Parallel()
	const hostileCredentialError = "SIGNER-CREDENTIAL-PROVIDER-SECRET-DO-NOT-LOG"
	service := newPresignedGetProbeTestService(t)
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	writerStore := newPresignedGetProbeTestStore(t, server, "writer", "writer-secret", "")
	signerTransport := &countingRejectingPresignedGetRoundTripper{}
	presigningStore, err := New(context.Background(), Config{
		Bucket: "probe-bucket", Region: "us-east-1", Endpoint: server.URL, UsePathStyle: true,
		HTTPClient: &http.Client{Transport: signerTransport}, OperationTimeout: 2 * time.Second,
		CredentialsProvider: CredentialsProviderFunc(func(context.Context) (Credentials, error) {
			return Credentials{}, errors.New(hostileCredentialError)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	report, probeErr := writerStore.ProbePresignedGetCompatibilityWithPresigningStore(
		context.Background(), presigningStore, shortPresignedGetProbeOptions(nil),
	)
	if !errors.Is(probeErr, s3disk.ErrAccessDenied) ||
		report.Status != PresignedGetCompatibilityPermissionDenied || report.Compatible || report.Complete ||
		report.Evidence.PresigningTopology != PresignedGetCompatibilitySeparateStore ||
		!report.Evidence.PresigningStoreInputDistinct || report.Evidence.CrossConfigurationCanaryBindingObserved ||
		len(report.Checks) != 3 || report.Checks[2].ID != PresignedGetCompatibilityCheckExactGetPresign ||
		report.Cleanup.Status != PresignedGetCompatibilityCleanupSucceeded {
		t.Fatalf("signer credential failure: report=%+v err=%v", report, probeErr)
	}
	if signerTransport.calls.Load() != 0 {
		t.Fatalf("presigning Store data-plane calls = %d, want 0", signerTransport.calls.Load())
	}
	service.mu.Lock()
	remaining := len(service.objects)
	service.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("writer cleanup left %d canaries", remaining)
	}
	for _, diagnostic := range []string{report.String(), probeErr.Error(), fmt.Sprintf("%+v", report), fmt.Sprintf("%#v", probeErr)} {
		for _, secret := range []string{hostileCredentialError, server.URL, "probe-bucket", "private/probes"} {
			if strings.Contains(diagnostic, secret) {
				t.Fatalf("credential failure diagnostic leaked %q: %s", secret, diagnostic)
			}
		}
	}
}

func TestProbePresignedGetCompatibilityWithPresigningStoreDetectsDifferentDataOrigin(t *testing.T) {
	t.Parallel()
	writerService := newPresignedGetProbeTestService(t)
	writerServer := httptest.NewServer(writerService)
	t.Cleanup(writerServer.Close)
	presigningService := newPresignedGetProbeTestService(t)
	presigningServer := httptest.NewServer(presigningService)
	t.Cleanup(presigningServer.Close)
	writerStore := newPresignedGetProbeTestStore(t, writerServer, "writer", "writer-secret", "")
	presigningStore := newPresignedGetProbeTestStore(t, presigningServer, "signer", "signer-secret", "")

	report, err := writerStore.ProbePresignedGetCompatibilityWithPresigningStore(
		context.Background(), presigningStore, shortPresignedGetProbeOptions(nil),
	)
	if !errors.Is(err, s3disk.ErrStoreIncompatible) ||
		report.Status != PresignedGetCompatibilityIncompatible || report.Compatible || report.Complete ||
		report.Evidence.PresigningTopology != PresignedGetCompatibilitySeparateStore ||
		!report.Evidence.PresigningStoreInputDistinct || report.Evidence.CrossConfigurationCanaryBindingObserved ||
		len(report.Checks) != 5 || report.Checks[4].ID != PresignedGetCompatibilityCheckInitialGet ||
		report.Cleanup.Status != PresignedGetCompatibilityCleanupSucceeded {
		t.Fatalf("different data origin: report=%+v err=%v", report, err)
	}
	writerService.mu.Lock()
	writerRemaining := len(writerService.objects)
	writerService.mu.Unlock()
	if writerRemaining != 0 {
		t.Fatalf("writer cleanup left %d canaries", writerRemaining)
	}
}

func TestProbePresignedGetCompatibilityDefaults(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibility(context.Background())
	if err != nil || report.Status != PresignedGetCompatibilityPassed || !report.Compatible || !report.Complete {
		t.Fatalf("default probe = %+v, %v", report, err)
	}
	if report.Cleanup.Status != PresignedGetCompatibilityCleanupSucceeded {
		t.Fatalf("default cleanup = %+v", report.Cleanup)
	}
}

func TestProbePresignedGetCompatibilityRequiresExplicitHTTPSRootsBeforeIO(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	server := httptest.NewTLSServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(nil))
	if err == nil || report.Status != PresignedGetCompatibilityConfigurationError ||
		report.Cleanup.Status != PresignedGetCompatibilityCleanupNotAttempted {
		t.Fatalf("missing explicit roots: report=%+v err=%v", report, err)
	}
	service.mu.Lock()
	remaining := len(service.objects)
	service.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("configuration error performed object writes: %d objects", remaining)
	}
}

func TestProbePresignedGetCompatibilityExplainsStaleSameURL(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.serveStaleAfterReplacement = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("error = %v, want ErrStoreIncompatible", err)
	}
	var compatibilityErr *PresignedGetCompatibilityError
	if !errors.As(err, &compatibilityErr) || compatibilityErr.CheckID != PresignedGetCompatibilityCheckSameURLReplacement ||
		compatibilityErr.Status != PresignedGetCompatibilityIncompatible || compatibilityErr.Reason != PresignedGetCompatibilityReasonSemanticViolation {
		t.Fatalf("compatibility error = %+v", compatibilityErr)
	}
	if report.Status != PresignedGetCompatibilityIncompatible || report.Compatible || report.Complete || len(report.Checks) != 6 {
		t.Fatalf("report = %+v", report)
	}
	if report.Checks[len(report.Checks)-1].Detail != "the fixed presigned URL did not expose v2 with a changed ETag after A-side replacement" {
		t.Fatalf("failure detail = %q", report.Checks[len(report.Checks)-1].Detail)
	}
	if report.Cleanup.Status != PresignedGetCompatibilityCleanupSucceeded {
		t.Fatalf("cleanup = %+v", report.Cleanup)
	}
}

func TestProbePresignedGetCompatibilityRejectsUnboundAuthorizationQuery(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.allowTamperedQuery = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("error = %v, want ErrStoreIncompatible", err)
	}
	var compatibilityErr *PresignedGetCompatibilityError
	if !errors.As(err, &compatibilityErr) ||
		compatibilityErr.CheckID != PresignedGetCompatibilityCheckAuthorizationQueryBinding {
		t.Fatalf("error = %+v", compatibilityErr)
	}
	if report.Compatible || report.Checks[len(report.Checks)-1].ID != PresignedGetCompatibilityCheckAuthorizationQueryBinding {
		t.Fatalf("report = %+v", report)
	}
}

func TestProbePresignedGetCompatibilityRejectsQueryTargetDisclosure(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.discloseRejectedQueryTargetHeader = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("error = %v, want ErrStoreIncompatible", err)
	}
	last := report.Checks[len(report.Checks)-1]
	if last.ID != PresignedGetCompatibilityCheckAuthorizationQueryBinding ||
		last.Detail != "rejected authorization-query mutation disclosed sampled object bytes or version" {
		t.Fatalf("failure check = %+v", last)
	}
}

func TestProbePresignedGetCompatibilityDetectsQueryTargetSideEffect(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.mutateTargetThenRejectQuery = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("error = %v, want ErrStoreIncompatible", err)
	}
	last := report.Checks[len(report.Checks)-1]
	if last.ID != PresignedGetCompatibilityCheckAuthorizationQueryBinding ||
		last.Detail != "the sampled target bytes or version changed during the authorization-query check" {
		t.Fatalf("failure check = %+v", last)
	}
}

func TestProbePresignedGetCompatibilityRejectsPublicAnonymousPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		configure func(*presignedGetProbeTestService)
	}{
		{name: "GET", configure: func(service *presignedGetProbeTestService) { service.allowUnsignedGet = true }},
		{name: "PUT", configure: func(service *presignedGetProbeTestService) { service.allowUnsignedPut = true }},
		{name: "DELETE", configure: func(service *presignedGetProbeTestService) { service.allowUnsignedDelete = true }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := newPresignedGetProbeTestService(t)
			test.configure(service)
			server := httptest.NewServer(service)
			t.Cleanup(server.Close)
			store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

			report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
			if !errors.Is(err, s3disk.ErrStoreIncompatible) {
				t.Fatalf("error = %v, want ErrStoreIncompatible", err)
			}
			last := report.Checks[len(report.Checks)-1]
			if last.ID != PresignedGetCompatibilityCheckAnonymousPolicyRejected ||
				last.Status != PresignedGetCompatibilityIncompatible ||
				last.Reason != PresignedGetCompatibilityReasonSemanticViolation {
				t.Fatalf("failure check = %+v", last)
			}
			if !strings.Contains(last.Detail, "instead of 400, 401, or 403") {
				t.Fatalf("failure detail = %q", last.Detail)
			}
		})
	}
}

func TestProbePresignedGetCompatibilityRejectsNamedUnsignedHeaderOverride(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		header string
		path   bool
	}{
		{name: "method", header: "X-HTTP-Method-Override"},
		{name: "path", header: "X-Rewrite-Url", path: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := newPresignedGetProbeTestService(t)
			service.honorNamedOverrideHeader = test.header
			service.honorNamedOverrideAsPath = test.path
			server := httptest.NewServer(service)
			t.Cleanup(server.Close)
			store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

			report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
			if !errors.Is(err, s3disk.ErrStoreIncompatible) {
				t.Fatalf("error = %v, want ErrStoreIncompatible", err)
			}
			last := report.Checks[len(report.Checks)-1]
			if last.ID != PresignedGetCompatibilityCheckNamedUnsignedHeaderOverrides ||
				last.Status != PresignedGetCompatibilityIncompatible ||
				last.Reason != PresignedGetCompatibilityReasonSemanticViolation {
				t.Fatalf("failure check = %+v", last)
			}
		})
	}
}

func TestProbePresignedGetCompatibilityRejectsForeignBearerAuthorityDisclosure(t *testing.T) {
	t.Parallel()
	tests := []struct {
		part    string
		channel string
	}{
		{part: "url", channel: "body"},
		{part: "url", channel: "header"},
		{part: "url", channel: "trailer"},
		{part: "signature", channel: "body"},
		{part: "signature", channel: "header"},
		{part: "signature", channel: "trailer"},
		{part: "path", channel: "header"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.part+"/"+test.channel, func(t *testing.T) {
			t.Parallel()
			service := newPresignedGetProbeTestService(t)
			service.discloseTargetAuthorityPart = test.part
			service.discloseTargetAuthorityChannel = test.channel
			server := httptest.NewServer(service)
			t.Cleanup(server.Close)
			store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

			report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
			if !errors.Is(err, s3disk.ErrStoreIncompatible) {
				t.Fatalf("error = %v, want ErrStoreIncompatible", err)
			}
			last := report.Checks[len(report.Checks)-1]
			if last.ID != PresignedGetCompatibilityCheckAnonymousPolicyRejected &&
				last.ID != PresignedGetCompatibilityCheckNamedUnsignedHeaderOverrides ||
				last.Status != PresignedGetCompatibilityIncompatible ||
				last.Reason != PresignedGetCompatibilityReasonSemanticViolation ||
				!strings.Contains(last.Detail, "bearer authority") {
				t.Fatalf("failure check = %+v", last)
			}
			service.mu.Lock()
			foreignURL := service.seenTargetBearerURL
			service.mu.Unlock()
			for _, diagnostic := range []string{fmt.Sprint(report), err.Error()} {
				if foreignURL != "" && strings.Contains(diagnostic, foreignURL) {
					t.Fatalf("diagnostic leaked foreign bearer URL: %s", diagnostic)
				}
			}
		})
	}
}

func TestProbePresignedGetCompatibilityMatchesReaderResponseHeaderContract(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		configure func(*presignedGetProbeTestService)
	}{
		{name: "duplicate ETag", configure: func(service *presignedGetProbeTestService) { service.duplicateResponseETag = true }},
		{name: "duplicate version ID", configure: func(service *presignedGetProbeTestService) { service.duplicateResponseVersionID = true }},
		{name: "too many headers", configure: func(service *presignedGetProbeTestService) { service.tooManyResponseHeaders = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := newPresignedGetProbeTestService(t)
			test.configure(service)
			server := httptest.NewServer(service)
			t.Cleanup(server.Close)
			store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

			report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
			if err == nil || report.Compatible || report.Status == PresignedGetCompatibilityPassed {
				t.Fatalf("invalid Reader response contract passed: report=%+v err=%v", report, err)
			}
			if report.Checks[len(report.Checks)-1].ID != PresignedGetCompatibilityCheckInitialGet {
				t.Fatalf("failure check = %+v", report.Checks[len(report.Checks)-1])
			}
		})
	}
}

func TestProbePresignedGetCompatibilityRejectsUnboundPath(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.allowTamperedPath = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("error = %v, want ErrStoreIncompatible", err)
	}
	var compatibilityErr *PresignedGetCompatibilityError
	if !errors.As(err, &compatibilityErr) || compatibilityErr.CheckID != PresignedGetCompatibilityCheckExactPathBinding {
		t.Fatalf("error = %+v", compatibilityErr)
	}
	if report.Complete || len(report.Checks) != report.RequiredChecks-2 || report.Compatible {
		t.Fatalf("report = %+v", report)
	}
	if report.Cleanup.Status != PresignedGetCompatibilityCleanupSucceeded {
		t.Fatalf("cleanup = %+v", report.Cleanup)
	}
}

func TestProbePresignedGetCompatibilityRequiresReadableTargetBearer(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.allowTamperedPath = true
	service.rejectCorrectTargetBearer = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if err == nil || report.Compatible || report.Status == PresignedGetCompatibilityPassed {
		t.Fatalf("probe passed without a readable target bearer: report=%+v err=%v", report, err)
	}
	if report.Checks[len(report.Checks)-1].ID != PresignedGetCompatibilityCheckExactPathBinding {
		t.Fatalf("failure check = %+v", report.Checks[len(report.Checks)-1])
	}
}

func TestProbePresignedGetCompatibilityRevalidatesTargetAfterPathSample(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.allowTamperedPath = true
	service.rejectTargetAnonymousAfter = 13
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if err == nil || report.Compatible || report.Status == PresignedGetCompatibilityPassed {
		t.Fatalf("one-shot target policy produced a pass: report=%+v err=%v", report, err)
	}
	last := report.Checks[len(report.Checks)-1]
	if last.ID != PresignedGetCompatibilityCheckExactPathBinding ||
		last.Detail != "the correct target GET bearer was not live immediately after the path-mutation sample" {
		t.Fatalf("failure check = %+v", last)
	}
}

func TestProbePresignedGetCompatibilityRejectsExpiredNegativeSample(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	// All source/target, unsigned-policy, and named-header controls succeed.
	// Every signed request from the path mutation onward is rejected, simulating
	// early bearer revocation without turning that rejection into binding proof.
	service.rejectAnonymousAfter = 44
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if err == nil || report.Compatible || report.Status == PresignedGetCompatibilityPassed {
		t.Fatalf("revoked bearer produced a pass: report=%+v err=%v", report, err)
	}
	last := report.Checks[len(report.Checks)-1]
	if last.ID != PresignedGetCompatibilityCheckExactPathBinding ||
		last.Detail != "the correct target GET bearer was not live immediately after the path-mutation sample" {
		t.Fatalf("failure check = %+v", last)
	}
}

func TestProbePresignedGetCompatibilityRequiresTargetToRemainPresent(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.allowTamperedPath = true
	service.deleteTargetOnPathMutation = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if err == nil || report.Compatible || report.Status == PresignedGetCompatibilityPassed {
		t.Fatalf("missing target produced a pass: report=%+v err=%v", report, err)
	}
	last := report.Checks[len(report.Checks)-1]
	if last.ID != PresignedGetCompatibilityCheckExactPathBinding ||
		last.Detail != "credentialed exact read-back could not prove the target still existed after the path-mutation sample" {
		t.Fatalf("failure check = %+v", last)
	}
}

func TestProbePresignedGetCompatibilityRejectsPathMutationResponseDisclosure(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		body    bool
		etag    bool
		header  bool
		trailer bool
	}{
		{name: "body", body: true},
		{name: "etag", etag: true},
		{name: "other header", header: true},
		{name: "trailer", trailer: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := newPresignedGetProbeTestService(t)
			service.discloseRejectedPathBody = test.body
			service.discloseRejectedPathETag = test.etag
			service.discloseRejectedPathHeader = test.header
			service.discloseRejectedPathTrailer = test.trailer
			server := httptest.NewServer(service)
			t.Cleanup(server.Close)
			store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

			report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
			if !errors.Is(err, s3disk.ErrStoreIncompatible) {
				t.Fatalf("error = %v, want ErrStoreIncompatible", err)
			}
			var compatibilityErr *PresignedGetCompatibilityError
			if !errors.As(err, &compatibilityErr) ||
				compatibilityErr.CheckID != PresignedGetCompatibilityCheckExactPathBinding ||
				compatibilityErr.Status != PresignedGetCompatibilityIncompatible ||
				compatibilityErr.Reason != PresignedGetCompatibilityReasonSemanticViolation {
				t.Fatalf("error = %+v", compatibilityErr)
			}
			const detail = "rejected path mutation disclosed sampled object bytes or version"
			if compatibilityErr.Detail != detail || report.Checks[len(report.Checks)-1].Detail != detail {
				t.Fatalf("failure detail = %q, report = %+v", compatibilityErr.Detail, report)
			}
			assertPresignedGetProbeDiagnosticRedacted(t, fmt.Sprint(report))
			assertPresignedGetProbeDiagnosticRedacted(t, err.Error())
		})
	}
}

func TestProbePresignedGetCompatibilityRejectsSuccessfulSourceCrossObjectDisclosure(t *testing.T) {
	t.Parallel()
	for _, channel := range []string{"header", "trailer", "status"} {
		channel := channel
		t.Run(channel, func(t *testing.T) {
			t.Parallel()
			service := newPresignedGetProbeTestService(t)
			service.discloseSuccessfulSourceResponse = channel
			server := httptest.NewServer(service)
			t.Cleanup(server.Close)
			store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

			report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
			if !errors.Is(err, s3disk.ErrStoreIncompatible) {
				t.Fatalf("error = %v, want ErrStoreIncompatible", err)
			}
			var compatibilityErr *PresignedGetCompatibilityError
			if !errors.As(err, &compatibilityErr) ||
				compatibilityErr.CheckID != PresignedGetCompatibilityCheckInitialGet ||
				compatibilityErr.Status != PresignedGetCompatibilityIncompatible ||
				compatibilityErr.Reason != PresignedGetCompatibilityReasonSemanticViolation {
				t.Fatalf("error = %+v", compatibilityErr)
			}
			const detail = "anonymous source GET disclosed the independently sampled target object"
			if compatibilityErr.Detail != detail || report.Checks[len(report.Checks)-1].Detail != detail {
				t.Fatalf("failure detail = %q, report = %+v", compatibilityErr.Detail, report)
			}
			assertPresignedGetProbeDiagnosticRedacted(t, fmt.Sprint(report))
			assertPresignedGetProbeDiagnosticRedacted(t, err.Error())
		})
	}
}

func TestProbePresignedGetCompatibilityRejectsSuccessfulTargetCrossObjectDisclosure(t *testing.T) {
	t.Parallel()
	for _, channel := range []string{"header", "trailer", "status"} {
		channel := channel
		t.Run(channel, func(t *testing.T) {
			t.Parallel()
			service := newPresignedGetProbeTestService(t)
			service.discloseSuccessfulTargetResponse = channel
			server := httptest.NewServer(service)
			t.Cleanup(server.Close)
			store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

			report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
			if !errors.Is(err, s3disk.ErrStoreIncompatible) {
				t.Fatalf("error = %v, want ErrStoreIncompatible", err)
			}
			var compatibilityErr *PresignedGetCompatibilityError
			if !errors.As(err, &compatibilityErr) ||
				compatibilityErr.CheckID != PresignedGetCompatibilityCheckExactPathBinding ||
				compatibilityErr.Status != PresignedGetCompatibilityIncompatible ||
				compatibilityErr.Reason != PresignedGetCompatibilityReasonSemanticViolation {
				t.Fatalf("error = %+v", compatibilityErr)
			}
			const detail = "correct target-key GET disclosed the independently sampled source object"
			if compatibilityErr.Detail != detail || report.Checks[len(report.Checks)-1].Detail != detail {
				t.Fatalf("failure detail = %q, report = %+v", compatibilityErr.Detail, report)
			}
			assertPresignedGetProbeDiagnosticRedacted(t, fmt.Sprint(report))
			assertPresignedGetProbeDiagnosticRedacted(t, err.Error())
		})
	}
}

func TestProbeSuccessfulResponseCrossObjectDisclosureSharedVersionTokens(t *testing.T) {
	t.Parallel()
	const sharedETag = `"shared-etag"`
	const sharedVersionID = "null"
	expectedVersion := s3disk.Version{ETag: sharedETag, VersionID: sharedVersionID}
	forbiddenVersion := expectedVersion
	response := presignedGetProbeHTTPResult{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		ETag:       sharedETag,
		VersionID:  sharedVersionID,
		Body:       []byte("allowed-source-body"),
		Headers:    make(http.Header),
	}
	response.Headers.Set("ETag", sharedETag)
	response.Headers.Set("X-Amz-Version-Id", sharedVersionID)
	if probeSuccessfulResponseDisclosesOtherObject(
		response, expectedVersion, []byte("forbidden-target-body"), forbiddenVersion,
	) {
		t.Fatal("the response's own shared opaque version fields were treated as a cross-object disclosure")
	}

	response.Headers.Set("X-Probe-Leak", sharedVersionID)
	if !probeSuccessfulResponseDisclosesOtherObject(
		response, expectedVersion, []byte("forbidden-target-body"), forbiddenVersion,
	) {
		t.Fatal("the shared opaque token in a non-version metadata field was not detected")
	}
}

func TestProbeForeignBearerAuthorityFingerprintExcludesSharedSigningContext(t *testing.T) {
	t.Parallel()
	foreign := presignedGetProbeBearer{
		URL: "https://s3.example.test/bucket/random/target?X-Amz-Credential=shared&X-Amz-Date=shared&X-Amz-Signature=target-signature-unique",
		Headers: http.Header{
			"X-Probe-Shared": {"shared-header-value"},
			"X-Probe-Unique": {"target-header-value-unique"},
		},
	}
	allowed := presignedGetProbeBearer{
		URL: "https://s3.example.test/bucket/random/source?X-Amz-Credential=shared&X-Amz-Date=shared&X-Amz-Signature=source-signature-unique",
		Headers: http.Header{
			"X-Probe-Shared": {"shared-header-value"},
			"X-Probe-Unique": {"source-header-value-unique"},
		},
	}
	fingerprint, err := newPresignedGetProbeAuthorityFingerprint(foreign, allowed, "random/target")
	if err != nil {
		t.Fatal(err)
	}
	shared := presignedGetProbeHTTPResult{Status: "200 OK", Headers: http.Header{"X-Leak": {"shared-header-value"}}}
	if probeResponseDisclosesAuthority(shared, fingerprint, true) {
		t.Fatal("a signing-context value shared by both bearers was treated as foreign authority")
	}
	for name, value := range map[string]string{
		"signature":    "target-signature-unique",
		"signed value": "target-header-value-unique",
		"escaped path": "/bucket/random/target",
	} {
		response := presignedGetProbeHTTPResult{Status: "200 OK", Headers: http.Header{"X-Leak": {value}}}
		if !probeResponseDisclosesAuthority(response, fingerprint, true) {
			t.Errorf("%s was not detected", name)
		}
	}
}

func TestProbePresignedGetCompatibilityCannotPassEncodedPathRejection(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.encodeRejectedPathResponse = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if err == nil || report.Compatible || report.Status != PresignedGetCompatibilityIndeterminate {
		t.Fatalf("encoded rejection produced a definitive pass: report=%+v err=%v", report, err)
	}
	last := report.Checks[len(report.Checks)-1]
	if last.ID != PresignedGetCompatibilityCheckExactPathBinding ||
		last.Detail != "rejected path mutation used an encoded response that could not be inspected safely" {
		t.Fatalf("failure check = %+v", last)
	}
}

func TestProbePresignedGetCompatibilityCannotPassInformationalResponse(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.discloseRejectedPathInformational = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if err == nil || report.Compatible || report.Status == PresignedGetCompatibilityPassed {
		t.Fatalf("informational response produced a pass: report=%+v err=%v", report, err)
	}
	if report.Checks[len(report.Checks)-1].ID != PresignedGetCompatibilityCheckExactPathBinding {
		t.Fatalf("failure check = %+v", report.Checks[len(report.Checks)-1])
	}
}

func TestProbePresignedGetCompatibilityRejectsUnboundMethod(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.allowTamperedMethod = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("error = %v, want ErrStoreIncompatible", err)
	}
	var compatibilityErr *PresignedGetCompatibilityError
	if !errors.As(err, &compatibilityErr) || compatibilityErr.CheckID != PresignedGetCompatibilityCheckHEADMutationRejected {
		t.Fatalf("error = %+v", compatibilityErr)
	}
	if report.Complete || len(report.Checks) != report.RequiredChecks-1 || report.Compatible {
		t.Fatalf("report = %+v", report)
	}
	if report.Cleanup.Status != PresignedGetCompatibilityCleanupSucceeded {
		t.Fatalf("cleanup = %+v", report.Cleanup)
	}
}

func TestProbePresignedGetCompatibilityRejectsHEADMutationETagDisclosure(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.discloseRejectedHEADETag = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("error = %v, want ErrStoreIncompatible", err)
	}
	var compatibilityErr *PresignedGetCompatibilityError
	if !errors.As(err, &compatibilityErr) ||
		compatibilityErr.CheckID != PresignedGetCompatibilityCheckHEADMutationRejected ||
		compatibilityErr.Status != PresignedGetCompatibilityIncompatible ||
		compatibilityErr.Reason != PresignedGetCompatibilityReasonSemanticViolation {
		t.Fatalf("error = %+v", compatibilityErr)
	}
	const detail = "rejected HEAD mutation disclosed sampled object bytes or version"
	if compatibilityErr.Detail != detail || report.Checks[len(report.Checks)-1].Detail != detail {
		t.Fatalf("failure detail = %q, report = %+v", compatibilityErr.Detail, report)
	}
	assertPresignedGetProbeDiagnosticRedacted(t, fmt.Sprint(report))
	assertPresignedGetProbeDiagnosticRedacted(t, err.Error())
}

func TestProbePresignedGetCompatibilityRejectsHEADTargetDisclosure(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.discloseRejectedHEADTargetHeader = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("error = %v, want ErrStoreIncompatible", err)
	}
	last := report.Checks[len(report.Checks)-1]
	if last.ID != PresignedGetCompatibilityCheckHEADMutationRejected ||
		last.Detail != "rejected HEAD mutation disclosed sampled object bytes or version" {
		t.Fatalf("failure check = %+v", last)
	}
}

func TestProbePresignedGetCompatibilityDetectsHEADTargetSideEffect(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.mutateTargetThenRejectHEAD = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("error = %v, want ErrStoreIncompatible", err)
	}
	last := report.Checks[len(report.Checks)-1]
	if last.ID != PresignedGetCompatibilityCheckHEADMutationRejected ||
		last.Detail != "the sampled target bytes or version changed during the rejected HEAD mutation" {
		t.Fatalf("failure check = %+v", last)
	}
}

func TestProbePresignedGetCompatibilityCannotPassDeclaredHEADBody(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.declareRejectedHEADBody = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if err == nil || report.Compatible || report.Status != PresignedGetCompatibilityIndeterminate {
		t.Fatalf("declared HEAD body produced a pass: report=%+v err=%v", report, err)
	}
	last := report.Checks[len(report.Checks)-1]
	if last.ID != PresignedGetCompatibilityCheckHEADMutationRejected ||
		last.Detail != "rejected HEAD mutation declared a response body that net/http cannot inspect" {
		t.Fatalf("failure check = %+v", last)
	}
}

func TestProbePresignedGetCompatibilityRejectsUnboundWrite(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.allowTamperedWrite = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("error = %v, want ErrStoreIncompatible", err)
	}
	var compatibilityErr *PresignedGetCompatibilityError
	if !errors.As(err, &compatibilityErr) || compatibilityErr.CheckID != PresignedGetCompatibilityCheckZeroBytePUTRejectedUnchanged {
		t.Fatalf("error = %+v", compatibilityErr)
	}
	if !report.Complete || len(report.Checks) != report.RequiredChecks || report.Compatible {
		t.Fatalf("report = %+v", report)
	}
	if report.Cleanup.Status != PresignedGetCompatibilityCleanupSucceeded {
		t.Fatalf("cleanup = %+v", report.Cleanup)
	}
}

func TestProbePresignedGetCompatibilityRejectsNonEmptyPUTSpecialCase(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.allowNonEmptyTamperedWrite = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("error = %v, want ErrStoreIncompatible", err)
	}
	last := report.Checks[len(report.Checks)-1]
	if last.ID != PresignedGetCompatibilityCheckPUTRejectedUnchanged ||
		last.Status != PresignedGetCompatibilityIncompatible ||
		!strings.Contains(last.Detail, "non-empty PUT") {
		t.Fatalf("failure check = %+v", last)
	}
}

func TestProbePresignedGetCompatibilityDetectsMutateThenRejectWrite(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.mutateThenRejectWrite = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("error = %v, want ErrStoreIncompatible", err)
	}
	var compatibilityErr *PresignedGetCompatibilityError
	if !errors.As(err, &compatibilityErr) ||
		compatibilityErr.CheckID != PresignedGetCompatibilityCheckZeroBytePUTRejectedUnchanged ||
		compatibilityErr.Status != PresignedGetCompatibilityIncompatible ||
		compatibilityErr.Reason != PresignedGetCompatibilityReasonSemanticViolation {
		t.Fatalf("error = %+v", compatibilityErr)
	}
	if compatibilityErr.Detail != "the sampled source bytes or version changed during the rejected zero-byte PUT" {
		t.Fatalf("detail = %q", compatibilityErr.Detail)
	}
	if !report.Complete || report.Compatible || len(report.Checks) != report.RequiredChecks {
		t.Fatalf("report = %+v", report)
	}
	if report.Cleanup.Status != PresignedGetCompatibilityCleanupSucceeded {
		t.Fatalf("cleanup = %+v", report.Cleanup)
	}
}

func TestProbePresignedGetCompatibilityRejectsPUTResponseDisclosure(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		source bool
		target bool
	}{
		{name: "source", source: true},
		{name: "target", target: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := newPresignedGetProbeTestService(t)
			service.discloseRejectedPUTSourceHeader = test.source
			service.discloseRejectedPUTTargetHeader = test.target
			server := httptest.NewServer(service)
			t.Cleanup(server.Close)
			store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

			report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
			if !errors.Is(err, s3disk.ErrStoreIncompatible) {
				t.Fatalf("error = %v, want ErrStoreIncompatible", err)
			}
			last := report.Checks[len(report.Checks)-1]
			if last.ID != PresignedGetCompatibilityCheckZeroBytePUTRejectedUnchanged ||
				last.Detail != "rejected zero-byte PUT mutation disclosed sampled object bytes or version" {
				t.Fatalf("failure check = %+v", last)
			}
		})
	}
}

func TestProbePresignedGetCompatibilityCannotPassEncodedPUTRejection(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.encodeRejectedPUTResponse = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if err == nil || report.Compatible || report.Status != PresignedGetCompatibilityIndeterminate {
		t.Fatalf("encoded PUT rejection produced a definitive pass: report=%+v err=%v", report, err)
	}
	last := report.Checks[len(report.Checks)-1]
	if last.ID != PresignedGetCompatibilityCheckZeroBytePUTRejectedUnchanged ||
		last.Detail != "rejected zero-byte PUT mutation used an encoded response that could not be inspected safely" {
		t.Fatalf("failure check = %+v", last)
	}
}

func TestProbePresignedGetCompatibilityDetectsPUTTargetSideEffect(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.mutateTargetThenRejectWrite = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("error = %v, want ErrStoreIncompatible", err)
	}
	last := report.Checks[len(report.Checks)-1]
	if last.ID != PresignedGetCompatibilityCheckZeroBytePUTRejectedUnchanged ||
		last.Detail != "the sampled target bytes or version changed during the rejected zero-byte PUT" {
		t.Fatalf("failure check = %+v", last)
	}
}

func TestProbePresignedGetCompatibilityTransportErrorIsRedacted(t *testing.T) {
	t.Parallel()
	const (
		accessKey = "LEAK-ACCESS-KEY"
		secretKey = "leak-secret-key"
		token     = "leak-session-token"
	)
	service := newPresignedGetProbeTestService(t)
	service.closeAnonymous = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, accessKey, secretKey, token)
	options := shortPresignedGetProbeOptions(server.Client())

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), options)
	if err == nil {
		t.Fatal("probe unexpectedly succeeded")
	}
	if report.Checks[len(report.Checks)-1].ID != PresignedGetCompatibilityCheckInitialGet ||
		report.Checks[len(report.Checks)-1].Reason != PresignedGetCompatibilityReasonNetworkError {
		t.Fatalf("failure check = %+v", report.Checks[len(report.Checks)-1])
	}
	encoded, marshalErr := json.Marshal(report)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, diagnostic := range []string{
		err.Error(), fmt.Sprint(err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err),
		string(encoded), fmt.Sprint(report), fmt.Sprintf("%+v", report), fmt.Sprintf("%#v", report),
		fmt.Sprint(report.Checks[len(report.Checks)-1]), fmt.Sprintf("%#v", report.Checks[len(report.Checks)-1]),
	} {
		for _, secret := range []string{accessKey, secretKey, token, "X-Amz-Credential", "X-Amz-Signature"} {
			if strings.Contains(diagnostic, secret) {
				t.Fatalf("diagnostic leaked %q: %s", secret, diagnostic)
			}
		}
	}
}

func TestProbePresignedGetCompatibilityContextDeadlineAndCleanup(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.getDelay = 250 * time.Millisecond
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")
	options := shortPresignedGetProbeOptions(server.Client())
	options.TotalTimeout = 40 * time.Millisecond

	started := time.Now()
	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), options)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context deadline", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("probe returned after %s", elapsed)
	}
	last := report.Checks[len(report.Checks)-1]
	if last.ID != PresignedGetCompatibilityCheckInitialGet || last.Status != PresignedGetCompatibilityIndeterminate ||
		last.Reason != PresignedGetCompatibilityReasonDeadlineExceeded {
		t.Fatalf("deadline check = %+v", last)
	}
	if report.Cleanup.Status != PresignedGetCompatibilityCleanupSucceeded {
		t.Fatalf("cleanup after main deadline = %+v", report.Cleanup)
	}
}

func TestProbePresignedGetCompatibilityCleanupFailureDoesNotRewritePass(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.failDelete = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	options := shortPresignedGetProbeOptions(server.Client())
	options.CleanupTimeout = 50 * time.Millisecond
	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), options)
	if err != nil || report.Status != PresignedGetCompatibilityPassed || !report.Compatible || !report.Complete {
		t.Fatalf("probe = %+v, %v", report, err)
	}
	if report.Cleanup.Status != PresignedGetCompatibilityCleanupFailed || report.Cleanup.Failed != 2 ||
		!report.Cleanup.CurrentObjectsMayRemain || report.Cleanup.Cause == nil {
		t.Fatalf("cleanup = %+v", report.Cleanup)
	}
	assertPresignedGetProbeDiagnosticRedacted(t, fmt.Sprintf("%#v", report.Cleanup))
}

func TestProbePresignedGetCompatibilityReconcilesLostCreateResponse(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.loseNextPutResponse = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if err != nil || !report.Compatible || report.Status != PresignedGetCompatibilityPassed {
		t.Fatalf("lost-response reconciliation: report=%+v err=%v", report, err)
	}
	if report.Cleanup.Status != PresignedGetCompatibilityCleanupSucceeded || report.Cleanup.Attempted != 2 ||
		report.Cleanup.Succeeded != 2 || report.Cleanup.CurrentObjectsMayRemain {
		t.Fatalf("cleanup = %+v", report.Cleanup)
	}
	service.mu.Lock()
	remaining := len(service.objects)
	service.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("remaining objects = %d, want 0", remaining)
	}
}

func TestProbePresignedGetCompatibilityDoesNotDeleteUnownedAmbiguousCreate(t *testing.T) {
	t.Parallel()
	service := newPresignedGetProbeTestService(t)
	service.loseNextPutResponse = true
	service.corruptLostPutObject = true
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	store := newPresignedGetProbeTestStore(t, server, "access", "secret", "")

	report, err := store.ProbePresignedGetCompatibilityWithOptions(context.Background(), shortPresignedGetProbeOptions(server.Client()))
	if err == nil || report.Compatible {
		t.Fatalf("ambiguous foreign object unexpectedly passed: report=%+v err=%v", report, err)
	}
	if report.Cleanup.Status != PresignedGetCompatibilityCleanupFailed || report.Cleanup.Attempted != 1 ||
		report.Cleanup.Failed != 1 || !report.Cleanup.CurrentObjectsMayRemain {
		t.Fatalf("cleanup = %+v", report.Cleanup)
	}
	service.mu.Lock()
	remaining := len(service.objects)
	service.mu.Unlock()
	if remaining != 1 {
		t.Fatalf("unowned ambiguous object count = %d, want 1", remaining)
	}
}

func TestProbePresignedGetCompatibilityRejectsInvalidConfigurationBeforeIO(t *testing.T) {
	t.Parallel()
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	withTransport := func(transport http.RoundTripper) PresignedGetCompatibilityProbeOptions {
		return PresignedGetCompatibilityProbeOptions{HTTPClient: &http.Client{Transport: transport}}
	}
	withTLS := func(config *tls.Config) PresignedGetCompatibilityProbeOptions {
		return withTransport(&http.Transport{TLSClientConfig: config})
	}
	tests := []struct {
		name    string
		store   *Store
		ctx     context.Context
		options PresignedGetCompatibilityProbeOptions
	}{
		{name: "nil context", store: &Store{}, ctx: nil},
		{name: "typed nil context", store: &Store{}, ctx: (*nilPresignedGetContext)(nil)},
		{name: "nil store", store: nil, ctx: context.Background()},
		{name: "negative timeout", store: &Store{}, ctx: context.Background(), options: PresignedGetCompatibilityProbeOptions{TotalTimeout: -time.Second}},
		{name: "oversized timeout", store: &Store{}, ctx: context.Background(), options: PresignedGetCompatibilityProbeOptions{TotalTimeout: PresignedGetCompatibilityMaximumTimeout + time.Second}},
		{name: "short capability", store: &Store{}, ctx: context.Background(), options: PresignedGetCompatibilityProbeOptions{CapabilityLifetime: time.Second}},
		{name: "capability shorter than probe", store: &Store{}, ctx: context.Background(), options: PresignedGetCompatibilityProbeOptions{TotalTimeout: time.Minute, CapabilityLifetime: time.Minute}},
		{name: "oversized capability", store: &Store{}, ctx: context.Background(), options: PresignedGetCompatibilityProbeOptions{CapabilityLifetime: 8 * 24 * time.Hour}},
		{name: "invalid prefix", store: &Store{}, ctx: context.Background(), options: PresignedGetCompatibilityProbeOptions{ObjectKeyPrefix: "../secret"}},
		{name: "typed nil transport", store: &Store{}, ctx: context.Background(), options: withTransport((*nilPresignedGetRoundTripper)(nil))},
		{name: "custom transport", store: &Store{}, ctx: context.Background(), options: withTransport(leakingPresignedGetRoundTripper{err: errors.New("unused")})},
		{name: "insecure TLS", store: &Store{}, ctx: context.Background(), options: withTLS(&tls.Config{InsecureSkipVerify: true})}, //nolint:gosec -- rejection fixture
		{name: "custom TLS dialer", store: &Store{}, ctx: context.Background(), options: withTransport(&http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unused") }})},
		{name: "custom TCP dialer", store: &Store{}, ctx: context.Background(), options: withTransport(&http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unused") }})},
		{name: "proxy routing", store: &Store{}, ctx: context.Background(), options: withTransport(&http.Transport{Proxy: http.ProxyFromEnvironment})},
		{name: "custom protocols", store: &Store{}, ctx: context.Background(), options: withTransport(&http.Transport{Protocols: protocols})},
		{name: "client certificate", store: &Store{}, ctx: context.Background(), options: withTLS(&tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{{1}}}}})},
		{name: "client certificate callback", store: &Store{}, ctx: context.Background(), options: withTLS(&tls.Config{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil }})},
		{name: "peer verification callback", store: &Store{}, ctx: context.Background(), options: withTLS(&tls.Config{VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error { return nil }})},
		{name: "connection verification callback", store: &Store{}, ctx: context.Background(), options: withTLS(&tls.Config{VerifyConnection: func(tls.ConnectionState) error { return nil }})},
		{name: "client config callback", store: &Store{}, ctx: context.Background(), options: withTLS(&tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, nil }})},
		{name: "TLS secret logging", store: &Store{}, ctx: context.Background(), options: withTLS(&tls.Config{KeyLogWriter: io.Discard})},
		{name: "client session callback", store: &Store{}, ctx: context.Background(), options: withTLS(&tls.Config{ClientSessionCache: tls.NewLRUClientSessionCache(1)})},
		{name: "unwrap session callback", store: &Store{}, ctx: context.Background(), options: withTLS(&tls.Config{UnwrapSession: func([]byte, tls.ConnectionState) (*tls.SessionState, error) { return nil, nil }})},
		{name: "wrap session callback", store: &Store{}, ctx: context.Background(), options: withTLS(&tls.Config{WrapSession: func(tls.ConnectionState, *tls.SessionState) ([]byte, error) { return nil, nil }})},
		{name: "custom cipher", store: &Store{}, ctx: context.Background(), options: withTLS(&tls.Config{CipherSuites: []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}})},
		{name: "custom curve", store: &Store{}, ctx: context.Background(), options: withTLS(&tls.Config{CurvePreferences: []tls.CurveID{tls.CurveP256}})},
		{name: "custom ALPN", store: &Store{}, ctx: context.Background(), options: withTLS(&tls.Config{NextProtos: []string{"malicious"}})},
		{name: "custom ECH", store: &Store{}, ctx: context.Background(), options: withTLS(&tls.Config{EncryptedClientHelloConfigList: []byte{1}})},
		{name: "ECH rejection callback", store: &Store{}, ctx: context.Background(), options: withTLS(&tls.Config{EncryptedClientHelloRejectionVerify: func(tls.ConnectionState) error { return nil }})},
		{name: "malformed TLS root PEM", store: &Store{}, ctx: context.Background(), options: PresignedGetCompatibilityProbeOptions{TLSRootCAPEM: []byte("not a certificate")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report, err := test.store.ProbePresignedGetCompatibilityWithOptions(test.ctx, test.options)
			if err == nil {
				t.Fatal("probe unexpectedly succeeded")
			}
			var compatibilityErr *PresignedGetCompatibilityError
			if !errors.As(err, &compatibilityErr) || compatibilityErr.CheckID != PresignedGetCompatibilityCheckConfiguration ||
				compatibilityErr.Status != PresignedGetCompatibilityConfigurationError ||
				compatibilityErr.Reason != PresignedGetCompatibilityReasonInvalidConfiguration {
				t.Fatalf("error = %+v", compatibilityErr)
			}
			if report.Status != PresignedGetCompatibilityConfigurationError || report.Complete || len(report.Checks) != 1 ||
				report.Cleanup.Status != PresignedGetCompatibilityCleanupNotAttempted {
				t.Fatalf("report = %+v", report)
			}
		})
	}
}

func TestPresignedGetCompatibilityHelpersAreBoundedAndAuthless(t *testing.T) {
	t.Parallel()
	for _, headers := range []http.Header{
		{"Authorization": {"secret"}},
		{"Proxy-Authorization": {"secret"}},
		{"Cookie": {"secret"}},
		{"Set-Cookie": {"secret"}},
	} {
		if err := validatePresignedGetProbeAnonymousHeaders(headers); err == nil {
			t.Fatalf("headers %v unexpectedly accepted", headers)
		}
	}
	if err := validatePresignedGetProbeAnonymousHeaders(http.Header{"If-None-Match": {`"etag"`}}); err != nil {
		t.Fatalf("runtime conditional header rejected: %v", err)
	}
	if _, err := replacePresignedGetProbePath(
		"https://example.invalid/bucket/right?secret=yes",
		"https://example.invalid/bucket/target?secret=target",
		"wrong", "target",
	); err == nil {
		t.Fatal("path replacement accepted a URL for another source key")
	}
	mutated, err := replacePresignedGetProbePath(
		"https://example.invalid/bucket/prefix/source?X-Amz-Signature=secret",
		"https://example.invalid/bucket/prefix/target?X-Amz-Signature=other",
		"prefix/source", "prefix/target",
	)
	if err != nil {
		t.Fatal(err)
	}
	if mutated != "https://example.invalid/bucket/prefix/target?X-Amz-Signature=secret" {
		t.Fatalf("mutated URL = %q", mutated)
	}
	mutated, err = replacePresignedGetProbePath(
		"https://example.invalid/tenant%2Fgateway/bucket/prefix/source?X-Amz-Signature=secret",
		"https://example.invalid/tenant%2Fgateway/bucket/prefix/target?X-Amz-Signature=other",
		"prefix/source", "prefix/target",
	)
	if err != nil {
		t.Fatal(err)
	}
	if mutated != "https://example.invalid/tenant%2Fgateway/bucket/prefix/target?X-Amz-Signature=secret" {
		t.Fatalf("escaped-base mutated URL = %q", mutated)
	}
	queryMutated, err := mutatePresignedGetProbeAuthorizationQuery(
		"https://example.invalid/bucket/source?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=59&X-Amz-Signature=short",
		"https://example.invalid/bucket/source?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=60&X-Amz-Signature=long",
	)
	if err != nil {
		t.Fatal(err)
	}
	if queryMutated != "https://example.invalid/bucket/source?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=60&X-Amz-Signature=short" {
		t.Fatalf("query-mutated URL = %q", queryMutated)
	}
	if _, err := mutatePresignedGetProbeAuthorizationQuery(
		"https://example.invalid/bucket/source?X-Amz-Date=20260718T000000Z&X-Amz-Expires=59&X-Amz-Signature=short",
		"https://example.invalid/bucket/source?X-Amz-Date=20260718T000001Z&X-Amz-Expires=60&X-Amz-Signature=long",
	); err == nil {
		t.Fatal("query mutator accepted controls with different signing instants")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := clonePresignedGetProbeHTTPClient(&http.Client{Transport: &http.Transport{}, Jar: jar}, nil)
	if err != nil {
		t.Fatal(err)
	}
	guard, ok := client.Transport.(presignedGetAnonymousTransport)
	if !ok {
		t.Fatalf("cloned transport = %T", client.Transport)
	}
	transport, ok := guard.delegate.(*http.Transport)
	if !ok {
		t.Fatalf("guard transport = %T, want *http.Transport", guard.delegate)
	}
	//lint:ignore SA1019 Deprecated dialer fields must remain empty on the constructed transport.
	legacyDialerConfigured := transport.Dial != nil || transport.DialTLS != nil
	if transport.Proxy != nil || transport.DialContext == nil || transport.DialTLSContext != nil ||
		legacyDialerConfigured || transport.TLSNextProto != nil ||
		transport.ProxyConnectHeader != nil || transport.GetProxyConnectHeader != nil || transport.Protocols != nil ||
		client.Jar != nil || client.CheckRedirect == nil {
		t.Fatal("anonymous client retained routing, protocol, cookie, or redirect authority")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("anonymous client did not construct a verified private TLS configuration")
	}
	dialer := newPresignedGetProbeNetworkDialer()
	if dialer.Resolver == nil || dialer.Resolver == net.DefaultResolver || !dialer.Resolver.PreferGo || dialer.Resolver.Dial != nil {
		t.Fatal("anonymous client dialer does not use a private callback-free DNS resolver")
	}
}

func TestPresignedGetCompatibilityHTTPClassificationsAreStable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		status     int
		wantStatus PresignedGetCompatibilityStatus
		wantReason PresignedGetCompatibilityReason
	}{
		{http.StatusForbidden, PresignedGetCompatibilityPermissionDenied, PresignedGetCompatibilityReasonAccessDenied},
		{http.StatusMethodNotAllowed, PresignedGetCompatibilityIncompatible, PresignedGetCompatibilityReasonOperationUnsupported},
		{http.StatusRequestTimeout, PresignedGetCompatibilityIndeterminate, PresignedGetCompatibilityReasonDeadlineExceeded},
		{http.StatusTooManyRequests, PresignedGetCompatibilityIndeterminate, PresignedGetCompatibilityReasonRateLimited},
		{http.StatusServiceUnavailable, PresignedGetCompatibilityIndeterminate, PresignedGetCompatibilityReasonStoreUnavailable},
		{http.StatusTemporaryRedirect, PresignedGetCompatibilityConfigurationError, PresignedGetCompatibilityReasonInvalidConfiguration},
		{http.StatusNotFound, PresignedGetCompatibilityIncompatible, PresignedGetCompatibilityReasonSemanticViolation},
	}
	for _, test := range tests {
		status, reason := presignedGetHTTPFailureClassification(test.status)
		if status != test.wantStatus || reason != test.wantReason {
			t.Errorf("HTTP %d = (%q, %q), want (%q, %q)", test.status, status, reason, test.wantStatus, test.wantReason)
		}
	}
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		if !presignedGetPathMutationRejectionStatus(status) {
			t.Errorf("HTTP %d should prove path mutation was rejected", status)
		}
	}
	for _, status := range []int{http.StatusOK, http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError} {
		if presignedGetPathMutationRejectionStatus(status) {
			t.Errorf("HTTP %d should be inconclusive for path binding", status)
		}
	}
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden} {
		if !presignedGetAuthorizationQueryMutationRejectionStatus(status) {
			t.Errorf("HTTP %d should prove the authorization-query mutation was rejected", status)
		}
	}
	for _, status := range []int{http.StatusOK, http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusInternalServerError} {
		if presignedGetAuthorizationQueryMutationRejectionStatus(status) {
			t.Errorf("HTTP %d should be inconclusive for authorization-query binding", status)
		}
	}
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusMethodNotAllowed} {
		if !presignedGetMethodMutationRejectionStatus(status) {
			t.Errorf("HTTP %d should prove method mutation was rejected", status)
		}
	}
	for _, status := range []int{http.StatusOK, http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError} {
		if presignedGetMethodMutationRejectionStatus(status) {
			t.Errorf("HTTP %d should be inconclusive for method binding", status)
		}
	}
}

func TestPresignedGetCompatibilityConcurrentHTTPClientClone(t *testing.T) {
	t.Parallel()
	shared := &http.Client{Transport: &http.Transport{ForceAttemptHTTP2: true}}
	const contenders = 16
	start := make(chan struct{})
	errorsFound := make(chan error, contenders)
	var wait sync.WaitGroup
	for contender := 0; contender < contenders; contender++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := clonePresignedGetProbeHTTPClient(shared, nil)
			errorsFound <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Errorf("concurrent HTTP client clone: %v", err)
		}
	}
}

func TestPresignedGetCompatibilityRejectsCallerDialer(t *testing.T) {
	t.Parallel()
	var customDialCalled atomic.Bool
	_, err := clonePresignedGetProbeHTTPClient(&http.Client{Transport: &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			customDialCalled.Store(true)
			return nil, errors.New("caller dialer must not run")
		},
	}}, nil)
	if err == nil {
		t.Fatal("custom caller dialer was accepted")
	}
	if customDialCalled.Load() {
		t.Fatal("probe invoked rejected caller-supplied DialContext")
	}
}

func TestPresignedGetCompatibilityRejectsCallerCertPoolConstraint(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	var constraintCalls atomic.Int32
	rootCAs := x509.NewCertPool()
	rootCAs.AddCertWithConstraint(server.Certificate(), func([]*x509.Certificate) error {
		constraintCalls.Add(1)
		return nil
	})

	_, err := clonePresignedGetProbeHTTPClient(&http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: rootCAs},
	}}, nil)
	if err == nil {
		t.Fatal("caller-created certificate pool was accepted")
	}
	if constraintCalls.Load() != 0 {
		t.Fatalf("certificate-pool constraint calls = %d, want 0", constraintCalls.Load())
	}
}

func TestPresignedGetCompatibilityAcceptsParsedTLSRootPEM(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("ETag", `"tls-root"`)
		_, _ = writer.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := clonePresignedGetProbeHTTPClient(&http.Client{Transport: &http.Transport{}}, rootPEM)
	if err != nil {
		t.Fatalf("clone with PEM root: %v", err)
	}
	result, err := doPresignedGetProbeRequest(context.Background(), client, server.URL, nil, "")
	if err != nil {
		t.Fatalf("TLS request with PEM root: %v", err)
	}
	if result.StatusCode != http.StatusOK || string(result.Body) != "ok" || result.ETag != `"tls-root"` {
		t.Fatalf("TLS result = %+v", result)
	}
}

func TestPresignedGetCompatibilityRejectsHiddenTLSRootPEMMaterial(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if len(certificate) == 0 {
		t.Fatal("test certificate PEM is empty")
	}

	valid := append([]byte(" \t\r\n"), certificate...)
	valid = append(valid, '\n')
	if _, err := parsePresignedGetProbeTLSRootCAPEM(valid); err != nil {
		t.Fatalf("strict parser rejected whitespace-separated certificate PEM: %v", err)
	}

	for _, test := range []struct {
		name           string
		prefix, suffix []byte
	}{
		{name: "arbitrary leading bytes", prefix: []byte("AWS_SECRET_ACCESS_KEY=must-not-be-ignored\n")},
		{name: "unclosed leading certificate", prefix: []byte("-----BEGIN CERTIFICATE-----\ninvalid\n")},
		{name: "arbitrary trailing bytes", suffix: []byte("AWS_SECRET_ACCESS_KEY=must-not-be-ignored\n")},
		{name: "private key", suffix: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("must-not-be-ignored")})},
		{name: "certificate headers", suffix: pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Headers: map[string]string{"Secret": "must-not-be-ignored"}, Bytes: server.Certificate().Raw,
		})},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := append(append([]byte(nil), test.prefix...), certificate...)
			input = append(input, test.suffix...)
			if _, err := parsePresignedGetProbeTLSRootCAPEM(input); err == nil {
				t.Fatal("strict parser accepted hidden non-certificate material")
			}
		})
	}
	firstWithoutLineEnd := bytes.TrimSuffix(certificate, []byte{'\n'})
	sameLine := append(append([]byte(nil), firstWithoutLineEnd...), certificate...)
	if _, err := parsePresignedGetProbeTLSRootCAPEM(sameLine); err == nil {
		t.Fatal("strict parser accepted two certificate boundaries on the same line")
	}
}

func TestPresignedGetCompatibilityBoundsTLSRootCertificateCount(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if len(certificate) == 0 {
		t.Fatal("test certificate PEM is empty")
	}
	encoded := bytes.Repeat(certificate, maximumPresignedGetProbeTLSRootCertificates+1)
	if len(encoded) > maximumPresignedGetProbeTLSRootCAPEMBytes {
		t.Fatal("certificate-count fixture unexpectedly exceeded the byte limit")
	}
	if _, err := parsePresignedGetProbeTLSRootCAPEM(encoded); err == nil {
		t.Fatal("strict parser accepted too many TLS root certificates")
	}
}

func TestPresignedGetCompatibilityStripsHTTPTraceValues(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("ETag", `"trace-free"`)
		_, _ = writer.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)
	client, err := clonePresignedGetProbeHTTPClient(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var callbacks atomic.Int32
	trace := &httptrace.ClientTrace{
		GetConn:      func(string) { callbacks.Add(1) },
		GotConn:      func(httptrace.GotConnInfo) { callbacks.Add(1) },
		WroteRequest: func(httptrace.WroteRequestInfo) { callbacks.Add(1) },
	}
	ctx := httptrace.WithClientTrace(context.Background(), trace)
	result, err := doPresignedGetProbeRequest(ctx, client, server.URL, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusOK || string(result.Body) != "ok" {
		t.Fatalf("result = %+v", result)
	}
	if callbacks.Load() != 0 {
		t.Fatalf("inherited httptrace callbacks = %d, want 0", callbacks.Load())
	}
	directRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	directResponse, err := client.Do(directRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = directResponse.Body.Close()
	if callbacks.Load() != 0 {
		t.Fatalf("transport-inherited httptrace callbacks = %d, want 0", callbacks.Load())
	}
}

func shortPresignedGetProbeOptions(_ *http.Client) PresignedGetCompatibilityProbeOptions {
	return PresignedGetCompatibilityProbeOptions{
		ObjectKeyPrefix: "private/probes", TotalTimeout: 5 * time.Second,
		CapabilityLifetime: time.Minute, CleanupTimeout: time.Second,
	}
}

func assertPresignedGetProbeDiagnosticRedacted(t *testing.T, diagnostic string) {
	t.Helper()
	for _, secret := range []string{
		"PROBE-ACCESS-DO-NOT-LOG", "probe-secret-do-not-log", "probe-token-do-not-log",
		"X-Amz-Signature", "X-Amz-Credential", "private/probes",
	} {
		if strings.Contains(diagnostic, secret) {
			t.Fatalf("diagnostic leaked %q: %s", secret, diagnostic)
		}
	}
}

type nilPresignedGetRoundTripper struct{}

func (*nilPresignedGetRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, nil }

type nilPresignedGetContext struct{}

func (*nilPresignedGetContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*nilPresignedGetContext) Done() <-chan struct{}       { return nil }
func (*nilPresignedGetContext) Err() error                  { return nil }
func (*nilPresignedGetContext) Value(any) any               { return nil }

type leakingPresignedGetRoundTripper struct{ err error }

func (transport leakingPresignedGetRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, transport.err
}

type countingRejectingPresignedGetRoundTripper struct {
	calls atomic.Int64
}

func (transport *countingRejectingPresignedGetRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls.Add(1)
	return nil, errors.New("unexpected presigning Store data-plane request")
}

type presignedGetProbeTestObject struct {
	body         []byte
	etag         string
	previous     []byte
	previousETag string
}

type presignedGetProbeTestBinding struct {
	method   string
	path     string
	rawQuery string
}

type presignedGetProbeTestService struct {
	t                                 *testing.T
	mu                                sync.Mutex
	objects                           map[string]presignedGetProbeTestObject
	signatureBindings                 map[string]presignedGetProbeTestBinding
	nextETag                          int
	anonymousRequests                 int
	unsignedRequests                  int
	credentialedGets                  int
	anonymousForbiddenHeaders         int
	anonymousMissingRuntimeHeaders    int
	anonymousRequestsWithoutClose     int
	serveStaleAfterReplacement        bool
	allowTamperedPath                 bool
	allowTamperedMethod               bool
	allowTamperedWrite                bool
	allowNonEmptyTamperedWrite        bool
	allowTamperedQuery                bool
	allowUnsignedGet                  bool
	allowUnsignedPut                  bool
	allowUnsignedDelete               bool
	honorNamedOverrideHeader          string
	honorNamedOverrideAsPath          bool
	mutateThenRejectWrite             bool
	mutateTargetThenRejectQuery       bool
	mutateTargetThenRejectHEAD        bool
	mutateTargetThenRejectWrite       bool
	discloseRejectedPathBody          bool
	discloseRejectedPathETag          bool
	discloseRejectedPathHeader        bool
	discloseRejectedPathTrailer       bool
	discloseRejectedPathInformational bool
	encodeRejectedPathResponse        bool
	discloseRejectedHEADETag          bool
	discloseRejectedQueryTargetHeader bool
	discloseRejectedHEADTargetHeader  bool
	discloseRejectedPUTSourceHeader   bool
	discloseRejectedPUTTargetHeader   bool
	encodeRejectedPUTResponse         bool
	discloseSuccessfulSourceResponse  string
	discloseSuccessfulTargetResponse  string
	discloseTargetAuthorityChannel    string
	discloseTargetAuthorityPart       string
	seenSourceBearerURL               string
	seenTargetBearerURL               string
	declareRejectedHEADBody           bool
	duplicateResponseETag             bool
	duplicateResponseVersionID        bool
	tooManyResponseHeaders            bool
	rejectAnonymousAfter              int
	rejectCorrectTargetBearer         bool
	rejectTargetAnonymousAfterFirst   bool
	rejectTargetAnonymousAfter        int
	targetAnonymousRequests           int
	deleteTargetOnPathMutation        bool
	loseNextPutResponse               bool
	corruptLostPutObject              bool
	closeAnonymous                    bool
	failDelete                        bool
	getDelay                          time.Duration
}

func newPresignedGetProbeTestService(t *testing.T) *presignedGetProbeTestService {
	return &presignedGetProbeTestService{
		t: t, objects: make(map[string]presignedGetProbeTestObject), signatureBindings: make(map[string]presignedGetProbeTestBinding),
	}
}

func (service *presignedGetProbeTestService) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	key, ok := strings.CutPrefix(request.URL.Path, "/probe-bucket/")
	if !ok || key == "" {
		writePresignedGetProbeTestError(writer, http.StatusNotFound, "NoSuchKey")
		return
	}
	switch request.Method {
	case http.MethodPut:
		if request.URL.Query().Get("X-Amz-Signature") != "" {
			service.anonymousPut(writer, request, key)
		} else {
			service.put(writer, request, key)
		}
	case http.MethodGet:
		service.get(writer, request, key)
	case http.MethodHead:
		if request.URL.Query().Get("X-Amz-Signature") != "" {
			service.anonymousHead(writer, request, key)
		} else {
			service.head(writer, request, key)
		}
	case http.MethodDelete:
		service.delete(writer, request, key)
	default:
		writePresignedGetProbeTestError(writer, http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}

func (service *presignedGetProbeTestService) put(writer http.ResponseWriter, request *http.Request, key string) {
	if request.Header.Get("Authorization") == "" {
		service.mu.Lock()
		service.unsignedRequests++
		service.recordAnonymousRequestLocked(request)
		allowed := service.allowUnsignedPut
		service.mu.Unlock()
		if !allowed {
			writePresignedGetProbeTestError(writer, http.StatusForbidden, "AccessDenied")
			return
		}
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		service.t.Errorf("read PUT body: %v", err)
		writePresignedGetProbeTestError(writer, http.StatusInternalServerError, "InternalError")
		return
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	current, exists := service.objects[key]
	if request.Header.Get("If-None-Match") == "*" && exists {
		writePresignedGetProbeTestError(writer, http.StatusPreconditionFailed, "PreconditionFailed")
		return
	}
	if expected := request.Header.Get("If-Match"); expected != "" && (!exists || current.etag != expected) {
		writePresignedGetProbeTestError(writer, http.StatusPreconditionFailed, "PreconditionFailed")
		return
	}
	service.nextETag++
	digest := sha256.Sum256(append([]byte(fmt.Sprintf("%d:", service.nextETag)), body...))
	etag := `"` + hex.EncodeToString(digest[:8]) + `"`
	service.objects[key] = presignedGetProbeTestObject{
		body: append([]byte(nil), body...), etag: etag,
		previous: append([]byte(nil), current.body...), previousETag: current.etag,
	}
	if service.loseNextPutResponse {
		service.loseNextPutResponse = false
		if service.corruptLostPutObject {
			object := service.objects[key]
			object.body = []byte("foreign-object-after-ambiguous-create")
			service.objects[key] = object
		}
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			service.t.Error("test response writer does not support hijacking")
			return
		}
		connection, _, err := hijacker.Hijack()
		if err != nil {
			service.t.Errorf("hijack credentialed PUT connection: %v", err)
			return
		}
		_ = connection.Close()
		return
	}
	writer.Header().Set("ETag", etag)
	writer.WriteHeader(http.StatusOK)
}

func (service *presignedGetProbeTestService) get(writer http.ResponseWriter, request *http.Request, key string) {
	anonymous := request.URL.Query().Get("X-Amz-Signature") != ""
	unsigned := !anonymous && request.Header.Get("Authorization") == ""
	if anonymous {
		if !service.authorizeAnonymous(writer, request) {
			return
		}
	} else if unsigned {
		service.mu.Lock()
		service.unsignedRequests++
		service.recordAnonymousRequestLocked(request)
		allowed := service.allowUnsignedGet
		service.mu.Unlock()
		if !allowed {
			writePresignedGetProbeTestError(writer, http.StatusForbidden, "AccessDenied")
			return
		}
	} else {
		service.mu.Lock()
		service.credentialedGets++
		service.mu.Unlock()
	}
	service.mu.Lock()
	delay := service.getDelay
	closeAnonymous := service.closeAnonymous
	service.mu.Unlock()
	if closeAnonymous {
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			service.t.Error("test response writer does not support hijacking")
			return
		}
		connection, _, err := hijacker.Hijack()
		if err != nil {
			service.t.Errorf("hijack anonymous connection: %v", err)
			return
		}
		_ = connection.Close()
		return
	}
	if delay > 0 {
		select {
		case <-request.Context().Done():
			return
		case <-time.After(delay):
		}
	}
	service.mu.Lock()
	if anonymous && service.honorNamedOverrideHeader != "" && request.Header.Get(service.honorNamedOverrideHeader) != "" {
		if service.honorNamedOverrideAsPath {
			for candidateKey, candidate := range service.objects {
				if bytes.HasPrefix(candidate.body, []byte("s3disk-presigned-get-target:")) {
					key = candidateKey
					break
				}
			}
		} else {
			service.mutatePresignedGetProbeTargetLocked()
			service.mu.Unlock()
			writer.WriteHeader(http.StatusForbidden)
			return
		}
	}
	object, exists := service.objects[key]
	if exists && service.serveStaleAfterReplacement && len(object.previous) != 0 {
		object.body = append([]byte(nil), object.previous...)
		object.etag = object.previousETag
	}
	disclosureChannel := ""
	disclosedObject := presignedGetProbeTestObject{}
	authorityDisclosureChannel := ""
	authorityDisclosureValue := ""
	if (anonymous || unsigned) && exists {
		isTarget := bytes.HasPrefix(object.body, []byte("s3disk-presigned-get-target:"))
		if isTarget {
			disclosureChannel = service.discloseSuccessfulTargetResponse
		} else {
			disclosureChannel = service.discloseSuccessfulSourceResponse
		}
		if disclosureChannel != "" {
			for _, candidate := range service.objects {
				candidateIsTarget := bytes.HasPrefix(candidate.body, []byte("s3disk-presigned-get-target:"))
				if candidateIsTarget != isTarget {
					disclosedObject = presignedGetProbeTestObject{
						body: append([]byte(nil), candidate.body...),
						etag: candidate.etag,
					}
					break
				}
			}
		}
		if anonymous && !isTarget && service.discloseTargetAuthorityChannel != "" && service.seenTargetBearerURL != "" {
			authorityDisclosureChannel = service.discloseTargetAuthorityChannel
			switch service.discloseTargetAuthorityPart {
			case "url":
				authorityDisclosureValue = service.seenTargetBearerURL
			case "signature":
				targetURL, parseErr := url.Parse(service.seenTargetBearerURL)
				if parseErr == nil {
					authorityDisclosureValue = targetURL.Query().Get("X-Amz-Signature")
				}
			case "path":
				targetURL, parseErr := url.Parse(service.seenTargetBearerURL)
				if parseErr == nil {
					authorityDisclosureValue = targetURL.EscapedPath()
				}
			}
		}
	}
	service.mu.Unlock()
	if !exists {
		writePresignedGetProbeTestError(writer, http.StatusNotFound, "NoSuchKey")
		return
	}
	if disclosureChannel == "status" && len(disclosedObject.body) != 0 {
		service.writeSuccessfulStatusDisclosure(writer, object, disclosedObject)
		return
	}
	writer.Header().Set("ETag", object.etag)
	if disclosureChannel == "header" && len(disclosedObject.body) != 0 {
		writer.Header().Set("X-Probe-Leak", string(disclosedObject.body))
	}
	if disclosureChannel == "trailer" && len(disclosedObject.body) != 0 {
		writer.Header().Set("Trailer", "X-Probe-Leak")
	}
	if authorityDisclosureChannel == "header" && authorityDisclosureValue != "" {
		writer.Header().Set("X-Probe-Authority-Leak", authorityDisclosureValue)
	}
	if authorityDisclosureChannel == "trailer" && authorityDisclosureValue != "" {
		writer.Header().Set("Trailer", "X-Probe-Authority-Leak")
	}
	if service.duplicateResponseETag {
		writer.Header().Add("ETag", `"duplicate"`)
	}
	if service.duplicateResponseVersionID {
		writer.Header().Set("X-Amz-Version-Id", "test-version")
		writer.Header().Add("X-Amz-Version-Id", "duplicate-version")
	}
	if service.tooManyResponseHeaders {
		for index := 0; index <= maximumPresignedGetProbeHeaderCount; index++ {
			writer.Header().Set(fmt.Sprintf("X-Probe-%03d", index), "x")
		}
	}
	if request.Header.Get("If-None-Match") == object.etag {
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(object.body)
	if authorityDisclosureChannel == "body" && authorityDisclosureValue != "" {
		_, _ = writer.Write([]byte(authorityDisclosureValue))
	}
	if disclosureChannel == "trailer" && len(disclosedObject.body) != 0 {
		writer.Header().Set("X-Probe-Leak", string(disclosedObject.body))
	}
	if authorityDisclosureChannel == "trailer" && authorityDisclosureValue != "" {
		writer.Header().Set("X-Probe-Authority-Leak", authorityDisclosureValue)
	}
}

func (service *presignedGetProbeTestService) writeSuccessfulStatusDisclosure(
	writer http.ResponseWriter,
	object presignedGetProbeTestObject,
	disclosedObject presignedGetProbeTestObject,
) {
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		service.t.Error("test response writer does not support status-disclosure hijacking")
		return
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		service.t.Errorf("hijack successful disclosure response: %v", err)
		return
	}
	defer connection.Close()
	if _, err := fmt.Fprintf(
		buffered,
		"HTTP/1.1 200 %s\r\nETag: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		string(disclosedObject.body), object.etag, len(object.body),
	); err != nil {
		service.t.Errorf("write successful disclosure status: %v", err)
		return
	}
	if _, err := buffered.Write(object.body); err != nil {
		service.t.Errorf("write successful disclosure body: %v", err)
		return
	}
	if err := buffered.Flush(); err != nil {
		service.t.Errorf("flush successful disclosure response: %v", err)
	}
}

func (service *presignedGetProbeTestService) anonymousHead(writer http.ResponseWriter, request *http.Request, key string) {
	if !service.authorizeAnonymous(writer, request) {
		return
	}
	service.mu.Lock()
	object, exists := service.objects[key]
	service.mu.Unlock()
	if !exists {
		writePresignedGetProbeTestError(writer, http.StatusNotFound, "NoSuchKey")
		return
	}
	writer.Header().Set("ETag", object.etag)
	writer.WriteHeader(http.StatusOK)
}

func (service *presignedGetProbeTestService) anonymousPut(writer http.ResponseWriter, request *http.Request, key string) {
	if !service.authorizeAnonymous(writer, request) {
		return
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if _, exists := service.objects[key]; !exists {
		writePresignedGetProbeTestError(writer, http.StatusNotFound, "NoSuchKey")
		return
	}
	service.nextETag++
	digest := sha256.Sum256([]byte(fmt.Sprintf("anonymous-put:%d", service.nextETag)))
	etag := `"` + hex.EncodeToString(digest[:8]) + `"`
	service.objects[key] = presignedGetProbeTestObject{etag: etag}
	writer.Header().Set("ETag", etag)
	writer.WriteHeader(http.StatusOK)
}

func (service *presignedGetProbeTestService) recordAnonymousRequestLocked(request *http.Request) {
	for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie"} {
		if request.Header.Get(name) != "" {
			service.anonymousForbiddenHeaders++
		}
	}
	if request.Header.Get("Accept-Encoding") != "identity" || request.Header.Get("Cache-Control") != "no-cache" ||
		request.Header.Get("Pragma") != "no-cache" {
		service.anonymousMissingRuntimeHeaders++
	}
	if !request.Close {
		service.anonymousRequestsWithoutClose++
	}
}

func (service *presignedGetProbeTestService) authorizeAnonymous(writer http.ResponseWriter, request *http.Request) bool {
	signature := request.URL.Query().Get("X-Amz-Signature")
	if signature == "" {
		writePresignedGetProbeTestError(writer, http.StatusForbidden, "AccessDenied")
		return false
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	service.anonymousRequests++
	service.recordAnonymousRequestLocked(request)
	if service.rejectAnonymousAfter > 0 && service.anonymousRequests > service.rejectAnonymousAfter {
		writePresignedGetProbeTestError(writer, http.StatusForbidden, "ExpiredToken")
		return false
	}
	key, _ := strings.CutPrefix(request.URL.Path, "/probe-bucket/")
	if bytes.HasPrefix(service.objects[key].body, []byte("s3disk-presigned-get-target:")) {
		service.targetAnonymousRequests++
		if service.rejectCorrectTargetBearer ||
			service.rejectTargetAnonymousAfterFirst && service.targetAnonymousRequests > 1 ||
			service.rejectTargetAnonymousAfter > 0 && service.targetAnonymousRequests > service.rejectTargetAnonymousAfter {
			writePresignedGetProbeTestError(writer, http.StatusForbidden, "AccessDenied")
			return false
		}
	}
	binding := presignedGetProbeTestBinding{method: request.Method, path: request.URL.Path, rawQuery: request.URL.RawQuery}
	if signedBinding, exists := service.signatureBindings[signature]; exists && signedBinding != binding {
		samePath := signedBinding.path == binding.path
		sameQuery := signedBinding.rawQuery == binding.rawQuery
		pathMutation := !samePath
		methodMutation := samePath && sameQuery && signedBinding.method != binding.method
		queryMutation := samePath && signedBinding.method == binding.method && !sameQuery
		if pathMutation && service.deleteTargetOnPathMutation {
			delete(service.objects, key)
		}
		methodMutationAllowed := methodMutation && ((service.allowTamperedMethod && request.Method == http.MethodHead) ||
			(request.Method == http.MethodPut && (service.allowTamperedWrite ||
				service.allowNonEmptyTamperedWrite && request.ContentLength > 0)))
		if methodMutation && service.mutateThenRejectWrite && request.Method == http.MethodPut {
			current, exists := service.objects[key]
			if exists {
				service.nextETag++
				digest := sha256.Sum256([]byte(fmt.Sprintf("mutate-then-reject:%d", service.nextETag)))
				service.objects[key] = presignedGetProbeTestObject{
					etag:     `"` + hex.EncodeToString(digest[:8]) + `"`,
					previous: append([]byte(nil), current.body...), previousETag: current.etag,
				}
			}
			writePresignedGetProbeTestError(writer, http.StatusForbidden, "SignatureDoesNotMatch")
			return false
		}
		if queryMutation && service.mutateTargetThenRejectQuery ||
			methodMutation && request.Method == http.MethodHead && service.mutateTargetThenRejectHEAD ||
			methodMutation && request.Method == http.MethodPut && service.mutateTargetThenRejectWrite {
			service.mutatePresignedGetProbeTargetLocked()
			if request.Method == http.MethodHead {
				writer.WriteHeader(http.StatusForbidden)
				return false
			}
			writePresignedGetProbeTestError(writer, http.StatusForbidden, "SignatureDoesNotMatch")
			return false
		}
		mutationAllowed := pathMutation && service.allowTamperedPath || methodMutationAllowed ||
			queryMutation && service.allowTamperedQuery
		if !mutationAllowed {
			object := service.objects[key]
			targetObject := presignedGetProbeTestObject{}
			for _, candidate := range service.objects {
				if bytes.HasPrefix(candidate.body, []byte("s3disk-presigned-get-target:")) {
					targetObject = candidate
					break
				}
			}
			if pathMutation && service.discloseRejectedPathInformational {
				writer.Header().Set("X-Probe-Leak", string(object.body))
				writer.WriteHeader(http.StatusEarlyHints)
				writer.Header().Del("X-Probe-Leak")
			}
			if pathMutation && service.discloseRejectedPathETag ||
				methodMutation && request.Method == http.MethodHead && service.discloseRejectedHEADETag {
				writer.Header().Set("ETag", object.etag)
			}
			if pathMutation && service.discloseRejectedPathBody {
				writer.Header().Set("Content-Type", "application/octet-stream")
				writer.WriteHeader(http.StatusForbidden)
				_, _ = writer.Write(object.body)
				return false
			}
			if pathMutation && service.discloseRejectedPathHeader {
				writer.Header().Set("X-Probe-Leak", string(object.body))
			}
			if pathMutation && service.encodeRejectedPathResponse {
				writer.Header().Set("Content-Encoding", "gzip")
			}
			if queryMutation && service.discloseRejectedQueryTargetHeader ||
				methodMutation && request.Method == http.MethodHead && service.discloseRejectedHEADTargetHeader ||
				methodMutation && request.Method == http.MethodPut && service.discloseRejectedPUTTargetHeader {
				writer.Header().Set("X-Probe-Leak", string(targetObject.body))
			}
			if methodMutation && request.Method == http.MethodPut && service.discloseRejectedPUTSourceHeader {
				writer.Header().Set("X-Probe-Leak", string(object.body))
			}
			if methodMutation && request.Method == http.MethodPut && service.encodeRejectedPUTResponse {
				writer.Header().Set("Content-Encoding", "gzip")
			}
			if pathMutation && service.discloseRejectedPathTrailer {
				writer.Header().Set("Trailer", "X-Probe-Leak")
				writer.Header().Set("Content-Type", "application/xml")
				writer.WriteHeader(http.StatusForbidden)
				_, _ = writer.Write([]byte("<Error><Code>SignatureDoesNotMatch</Code></Error>"))
				writer.Header().Set("X-Probe-Leak", string(object.body))
				return false
			}
			if methodMutation && request.Method == http.MethodHead {
				if service.declareRejectedHEADBody {
					writer.Header().Set("Content-Length", "123")
				}
				writer.WriteHeader(http.StatusForbidden)
				return false
			}
			writePresignedGetProbeTestError(writer, http.StatusForbidden, "SignatureDoesNotMatch")
			return false
		}
	}
	if _, exists := service.signatureBindings[signature]; !exists {
		service.signatureBindings[signature] = binding
		if request.Method == http.MethodGet {
			scheme := "http"
			if request.TLS != nil {
				scheme = "https"
			}
			absoluteURL := scheme + "://" + request.Host + request.URL.RequestURI()
			if bytes.HasPrefix(service.objects[key].body, []byte("s3disk-presigned-get-target:")) {
				if service.seenTargetBearerURL == "" {
					service.seenTargetBearerURL = absoluteURL
				}
			} else if service.seenSourceBearerURL == "" {
				service.seenSourceBearerURL = absoluteURL
			}
		}
	}
	return true
}

// mutatePresignedGetProbeTargetLocked corrupts the independently sampled
// target while service.mu is held. It models a gateway that applies a side
// effect to a different key and still returns a signature rejection.
func (service *presignedGetProbeTestService) mutatePresignedGetProbeTargetLocked() {
	for key, object := range service.objects {
		if !bytes.HasPrefix(object.body, []byte("s3disk-presigned-get-target:")) {
			continue
		}
		service.nextETag++
		digest := sha256.Sum256([]byte(fmt.Sprintf("mutated-target:%d", service.nextETag)))
		service.objects[key] = presignedGetProbeTestObject{
			body:         []byte("foreign-target-after-rejected-mutation"),
			etag:         `"` + hex.EncodeToString(digest[:8]) + `"`,
			previous:     append([]byte(nil), object.body...),
			previousETag: object.etag,
		}
		return
	}
}

func (service *presignedGetProbeTestService) head(writer http.ResponseWriter, request *http.Request, key string) {
	if request.Header.Get("Authorization") == "" {
		writePresignedGetProbeTestError(writer, http.StatusForbidden, "AccessDenied")
		return
	}
	service.mu.Lock()
	object, exists := service.objects[key]
	service.mu.Unlock()
	if !exists {
		writePresignedGetProbeTestError(writer, http.StatusNotFound, "NoSuchKey")
		return
	}
	writer.Header().Set("ETag", object.etag)
	writer.WriteHeader(http.StatusOK)
}

func (service *presignedGetProbeTestService) delete(writer http.ResponseWriter, request *http.Request, key string) {
	if request.Header.Get("Authorization") == "" {
		service.mu.Lock()
		service.unsignedRequests++
		service.recordAnonymousRequestLocked(request)
		allowed := service.allowUnsignedDelete
		service.mu.Unlock()
		if !allowed {
			writePresignedGetProbeTestError(writer, http.StatusForbidden, "AccessDenied")
			return
		}
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.failDelete {
		writePresignedGetProbeTestError(writer, http.StatusInternalServerError, "InternalError")
		return
	}
	delete(service.objects, key)
	writer.WriteHeader(http.StatusNoContent)
}

func writePresignedGetProbeTestError(writer http.ResponseWriter, status int, code string) {
	writer.Header().Set("Content-Type", "application/xml")
	writer.WriteHeader(status)
	_, _ = fmt.Fprintf(writer, "<Error><Code>%s</Code><Message>test</Message></Error>", code)
}

func newPresignedGetProbeTestStore(t *testing.T, server *httptest.Server, accessKey, secretKey, token string) *Store {
	t.Helper()
	store, err := New(context.Background(), Config{
		Bucket: "probe-bucket", Region: "us-east-1", Endpoint: server.URL, UsePathStyle: true,
		HTTPClient: server.Client(), OperationTimeout: 2 * time.Second,
		CredentialsProvider: CredentialsProviderFunc(func(context.Context) (Credentials, error) {
			return Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey, SessionToken: token}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}
