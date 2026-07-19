package s3store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
)

const (
	commissioningTestRepositoryPrefix = "private/commissioning-repository"
	commissioningTestPresignedPrefix  = "private/commissioning-repository/presigned"
	commissioningTestAccessKey        = "COMMISSIONING-ACCESS-DO-NOT-LOG"
	commissioningTestSecretKey        = "commissioning-secret-do-not-log"
	commissioningTestSessionToken     = "commissioning-token-do-not-log"
)

type commissioningTestRequestHook func(http.ResponseWriter, *http.Request) bool

func newCommissioningTestRig(
	t *testing.T,
	hookFactory func(*presignedGetProbeTestService) commissioningTestRequestHook,
) (*presignedGetProbeTestService, *httptest.Server, *Store, S3CommissioningProbeOptions) {
	t.Helper()
	service := newPresignedGetProbeTestService(t)
	var hook commissioningTestRequestHook
	if hookFactory != nil {
		hook = hookFactory(service)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if hook != nil && hook(writer, request) {
			return
		}
		service.ServeHTTP(writer, request)
	}))
	t.Cleanup(server.Close)
	store, err := New(context.Background(), Config{
		Bucket: "probe-bucket", Region: "us-east-1", Endpoint: server.URL, UsePathStyle: true,
		HTTPClient: server.Client(), RetryMaxAttempts: 1, OperationTimeout: 2 * time.Second,
		CredentialsProvider: CredentialsProviderFunc(func(context.Context) (Credentials, error) {
			return Credentials{
				AccessKeyID: commissioningTestAccessKey, SecretAccessKey: commissioningTestSecretKey,
				SessionToken: commissioningTestSessionToken,
			}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, server, store, S3CommissioningProbeOptions{
		RepositoryPrefix: commissioningTestRepositoryPrefix,
		PresignedGet: PresignedGetCompatibilityProbeOptions{
			ObjectKeyPrefix: commissioningTestPresignedPrefix,
			TotalTimeout:    5 * time.Second, CapabilityLifetime: time.Minute, CleanupTimeout: time.Second,
		},
		DeploymentFingerprint: strings.Repeat("a", 64),
		EvidenceID:            "commissioning-run:001",
		ImplementationVersion: "v0.0.0+commissioning",
		TotalTimeout:          12 * time.Second,
	}
}

func TestProbeCommissioningBothPhasesPass(t *testing.T) {
	t.Parallel()
	_, server, store, options := newCommissioningTestRig(t, nil)

	report, err := store.ProbeCommissioning(context.Background(), options)
	if err != nil {
		t.Fatalf("ProbeCommissioning: %v", err)
	}
	if report.SchemaVersion != S3CommissioningReportSchemaVersion ||
		report.Scope != S3CommissioningSingleProcessDualFiniteProbe ||
		report.Status != S3CommissioningPassed || !report.Compatible || !report.Complete ||
		report.WritableStoreOutcome != S3CommissioningStagePassed || report.PresignedGetOutcome != S3CommissioningStagePassed {
		t.Fatalf("aggregate report = %+v", report)
	}
	if report.Evidence.PresigningTopology != PresignedGetCompatibilitySameStore ||
		report.Evidence.PresigningStoreInputDistinct || report.Evidence.CrossConfigurationCanaryBindingObserved ||
		report.PresignedGet.Evidence.PresigningTopology != PresignedGetCompatibilitySameStore ||
		report.PresignedGet.Evidence.PresigningStoreInputDistinct ||
		report.PresignedGet.Evidence.CrossConfigurationCanaryBindingObserved {
		t.Fatalf("same-store commissioning evidence = %+v / %+v", report.Evidence, report.PresignedGet.Evidence)
	}
	if report.WritableStore.Status != s3disk.StoreCompatibilityPassed || !report.WritableStore.Compatible ||
		!report.WritableStore.Complete || report.WritableStore.RequiredChecks != 31 || len(report.WritableStore.Checks) != 31 {
		t.Fatalf("writable report = %+v", report.WritableStore)
	}
	if report.PresignedGet.Status != PresignedGetCompatibilityPassed || !report.PresignedGet.Compatible ||
		!report.PresignedGet.Complete || report.PresignedGet.RequiredChecks != 14 || len(report.PresignedGet.Checks) != 14 {
		t.Fatalf("presigned report = %+v", report.PresignedGet)
	}
	if report.Evidence.SchemaVersion != S3CommissioningReportSchemaVersion ||
		report.Evidence.StartedAt.IsZero() || report.Evidence.DurationNanoseconds < 0 ||
		len(report.Evidence.RunID) != 48 || !report.Evidence.FullyBound {
		t.Fatalf("evidence = %+v", report.Evidence)
	}
	if _, err := hex.DecodeString(report.Evidence.RunID); err != nil {
		t.Fatalf("run ID is not canonical hex: %q", report.Evidence.RunID)
	}
	if report.Evidence.RepositoryPrefixFingerprint == "" || report.Evidence.PresignedPrefixFingerprint == "" ||
		report.Evidence.RepositoryPrefixFingerprint == report.Evidence.PresignedPrefixFingerprint {
		t.Fatalf("namespace fingerprints are missing or not domain-separated: %+v", report.Evidence)
	}
	if report.Evidence.DeploymentFingerprint != options.DeploymentFingerprint ||
		report.Evidence.EvidenceID != options.EvidenceID ||
		report.Evidence.ImplementationVersion != options.ImplementationVersion ||
		report.Evidence.PresignedPrefixDerived || !report.Evidence.PresignedPrefixRepositoryScoped {
		t.Fatalf("evidence bindings = %+v", report.Evidence)
	}
	if report.Cleanup.WritableStoreStatus != s3disk.StoreCompatibilityCleanupSucceeded ||
		report.Cleanup.PresignedGetStatus != PresignedGetCompatibilityCleanupSucceeded ||
		report.Cleanup.CurrentObjectsMayRemain || !report.Cleanup.HistoricalVersionsMayRemain || !report.Cleanup.AttentionRequired {
		t.Fatalf("cleanup summary = %+v", report.Cleanup)
	}

	assertS3CommissioningDiagnosticsRedacted(t, report, nil, options, server.URL)
}

func TestProbeCommissioningWithSeparatePresigningStore(t *testing.T) {
	t.Parallel()
	const (
		signerAccess = "COMMISSIONING-SIGNER-ACCESS-DO-NOT-LOG"
		signerSecret = "commissioning-signer-secret-do-not-log"
		signerToken  = "commissioning-signer-token-do-not-log"
	)
	var writerRequests, signerBearerRequests, wrongIdentityRequests atomic.Int64
	_, server, writerStore, options := newCommissioningTestRig(t, func(*presignedGetProbeTestService) commissioningTestRequestHook {
		return func(_ http.ResponseWriter, request *http.Request) bool {
			if credential := request.URL.Query().Get("X-Amz-Credential"); credential != "" {
				if strings.HasPrefix(credential, signerAccess+"/") {
					signerBearerRequests.Add(1)
				} else {
					wrongIdentityRequests.Add(1)
				}
			}
			if authorization := request.Header.Get("Authorization"); authorization != "" {
				if strings.Contains(authorization, "Credential="+commissioningTestAccessKey+"/") {
					writerRequests.Add(1)
				} else {
					wrongIdentityRequests.Add(1)
				}
			}
			return false
		}
	})
	signerTransport := &countingRejectingPresignedGetRoundTripper{}
	presigningStore, err := New(context.Background(), Config{
		Bucket: "probe-bucket", Region: "us-east-1", Endpoint: server.URL, UsePathStyle: true,
		HTTPClient: &http.Client{Transport: signerTransport}, RetryMaxAttempts: 1, OperationTimeout: 2 * time.Second,
		CredentialsProvider: CredentialsProviderFunc(func(context.Context) (Credentials, error) {
			return Credentials{AccessKeyID: signerAccess, SecretAccessKey: signerSecret, SessionToken: signerToken}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	report, err := writerStore.ProbeCommissioningWithPresigningStore(context.Background(), presigningStore, options)
	if err != nil {
		t.Fatalf("split commissioning: %v; report=%s", err, report)
	}
	if report.Status != S3CommissioningPassed || !report.Compatible || !report.Complete ||
		report.WritableStoreOutcome != S3CommissioningStagePassed ||
		report.PresignedGetOutcome != S3CommissioningStagePassed ||
		report.Evidence.PresigningTopology != PresignedGetCompatibilitySeparateStore ||
		!report.Evidence.PresigningStoreInputDistinct ||
		!report.Evidence.CrossConfigurationCanaryBindingObserved ||
		report.PresignedGet.Scope != PresignedGetCompatibilityCrossConfigurationFiniteProbe ||
		report.PresignedGet.Evidence.PresigningTopology != PresignedGetCompatibilitySeparateStore ||
		!report.PresignedGet.Evidence.PresigningStoreInputDistinct ||
		!report.PresignedGet.Evidence.CrossConfigurationCanaryBindingObserved {
		t.Fatalf("split commissioning report = %+v", report)
	}
	if signerTransport.calls.Load() != 0 {
		t.Fatalf("presigning Store data-plane calls = %d, want 0", signerTransport.calls.Load())
	}
	if writerRequests.Load() == 0 || signerBearerRequests.Load() == 0 || wrongIdentityRequests.Load() != 0 {
		t.Fatalf("request identities: writer=%d signer-bearer=%d wrong=%d",
			writerRequests.Load(), signerBearerRequests.Load(), wrongIdentityRequests.Load())
	}
	assertS3CommissioningDiagnosticsRedacted(t, report, nil, options, server.URL)
	for _, diagnostic := range []string{report.String(), fmt.Sprintf("%+v", report), fmt.Sprintf("%#v", report)} {
		assertS3CommissioningTextRedacted(t, diagnostic, signerAccess, signerSecret, signerToken)
	}
}

func TestProbeCommissioningWithPresigningStoreRejectsSameStoreBeforeIO(t *testing.T) {
	t.Parallel()
	var requests atomic.Int64
	_, _, store, options := newCommissioningTestRig(t, func(*presignedGetProbeTestService) commissioningTestRequestHook {
		return func(_ http.ResponseWriter, _ *http.Request) bool {
			requests.Add(1)
			return false
		}
	})
	report, err := store.ProbeCommissioningWithPresigningStore(context.Background(), store, options)
	if !errors.Is(err, s3disk.ErrStoreMisconfigured) || report.Status != S3CommissioningConfigurationError ||
		report.WritableStoreOutcome != S3CommissioningStageNotRun || report.PresignedGetOutcome != S3CommissioningStageNotRun ||
		report.Evidence.PresigningTopology != PresignedGetCompatibilitySameStore ||
		report.Evidence.PresigningStoreInputDistinct || report.Evidence.CrossConfigurationCanaryBindingObserved {
		t.Fatalf("same Store split commissioning: report=%+v err=%v", report, err)
	}
	if requests.Load() != 0 {
		t.Fatalf("same Store split commissioning performed %d S3 requests", requests.Load())
	}
}

func TestProbeCommissioningWithPresigningStoreCleanupRemainsOperationalEvidence(t *testing.T) {
	t.Parallel()
	service, server, writerStore, options := newCommissioningTestRig(t, nil)
	service.mu.Lock()
	service.failDelete = true
	service.mu.Unlock()
	presigningStore := newPresignedGetProbeTestStore(t, server, "separate-signer", "signer-secret", "")

	report, err := writerStore.ProbeCommissioningWithPresigningStore(
		context.Background(), presigningStore, options,
	)
	if err != nil || report.Status != S3CommissioningPassed || !report.Compatible || !report.Complete ||
		!report.Evidence.CrossConfigurationCanaryBindingObserved ||
		!report.PresignedGet.Evidence.CrossConfigurationCanaryBindingObserved {
		t.Fatalf("split cleanup rewrote compatibility: report=%+v err=%v", report, err)
	}
	if report.WritableStore.Cleanup.Status != s3disk.StoreCompatibilityCleanupFailed ||
		report.PresignedGet.Cleanup.Status != PresignedGetCompatibilityCleanupFailed ||
		!report.Cleanup.CurrentObjectsMayRemain || !report.Cleanup.AttentionRequired {
		t.Fatalf("split cleanup evidence = %+v", report.Cleanup)
	}
}

func TestProbeCommissioningCleanupDoesNotChangeVerdict(t *testing.T) {
	t.Parallel()
	service, _, store, options := newCommissioningTestRig(t, nil)
	service.mu.Lock()
	service.failDelete = true
	service.mu.Unlock()

	report, err := store.ProbeCommissioning(context.Background(), options)
	if err != nil || report.Status != S3CommissioningPassed || !report.Compatible || !report.Complete {
		t.Fatalf("cleanup rewrote aggregate verdict: report=%+v err=%v", report, err)
	}
	if report.WritableStore.Cleanup.Status != s3disk.StoreCompatibilityCleanupFailed {
		t.Fatalf("writable cleanup = %+v", report.WritableStore.Cleanup)
	}
	if report.PresignedGet.Cleanup.Status != PresignedGetCompatibilityCleanupFailed {
		t.Fatalf("presigned cleanup = %+v", report.PresignedGet.Cleanup)
	}
	if report.Cleanup.WritableStoreStatus != s3disk.StoreCompatibilityCleanupFailed ||
		report.Cleanup.PresignedGetStatus != PresignedGetCompatibilityCleanupFailed ||
		!report.Cleanup.CurrentObjectsMayRemain || !report.Cleanup.HistoricalVersionsMayRemain || !report.Cleanup.AttentionRequired {
		t.Fatalf("aggregate cleanup = %+v", report.Cleanup)
	}
}

func TestProbeCommissioningDerivesScopedPresignedPrefix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		repositoryPrefix string
		wantPrefix       string
	}{
		{
			name:             "repository prefix",
			repositoryPrefix: commissioningTestRepositoryPrefix,
			wantPrefix:       commissioningTestRepositoryPrefix + "/.s3disk/v1/probes/presigned-get",
		},
		{
			name:             "bucket root",
			repositoryPrefix: "",
			wantPrefix:       ".s3disk/v1/probes/presigned-get",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var derivedBearerRequests atomic.Int64
			_, _, store, options := newCommissioningTestRig(t, func(*presignedGetProbeTestService) commissioningTestRequestHook {
				return func(_ http.ResponseWriter, request *http.Request) bool {
					if request.URL.Query().Get("X-Amz-Signature") != "" &&
						strings.Contains(request.URL.Path, "/"+test.wantPrefix+"/") {
						derivedBearerRequests.Add(1)
					}
					return false
				}
			})
			options.RepositoryPrefix = test.repositoryPrefix
			options.PresignedGet.ObjectKeyPrefix = ""

			report, err := store.ProbeCommissioning(context.Background(), options)
			if err != nil || !report.Compatible {
				t.Fatalf("derived commissioning: report=%+v err=%v", report, err)
			}
			if derivedBearerRequests.Load() == 0 {
				t.Fatalf("no bearer request used derived prefix %q", test.wantPrefix)
			}
			if !report.Evidence.PresignedPrefixDerived || !report.Evidence.PresignedPrefixRepositoryScoped ||
				report.Evidence.PresignedPrefixFingerprint != s3CommissioningPrefixFingerprint(s3CommissioningPresignedPrefixFingerprintDomain, test.wantPrefix) {
				t.Fatalf("derived evidence = %+v", report.Evidence)
			}
			if options.PresignedGet.ObjectKeyPrefix != "" {
				t.Fatalf("caller options were mutated: %+v", options)
			}
			encoded, marshalErr := json.Marshal(report)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			assertS3CommissioningTextRedacted(t, string(encoded), test.wantPrefix, test.repositoryPrefix)
		})
	}
}

func TestProbeCommissioningWritableTimeoutDefaultExplicitAndMarshal(t *testing.T) {
	t.Parallel()
	_, _, store, options := newCommissioningTestRig(t, nil)
	options.WritableStoreTimeout = 0
	normalizedOptions := cloneS3CommissioningProbeOptions(options)
	normalized, err := normalizeS3CommissioningProbeOptions(store, &normalizedOptions, commissioningTestRepositoryPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.WritableStoreTimeout != S3CommissioningDefaultWritableStoreTimeout {
		t.Fatalf("default writable timeout = %s, want %s", normalized.WritableStoreTimeout, S3CommissioningDefaultWritableStoreTimeout)
	}

	options.WritableStoreTimeout = 17 * time.Millisecond
	options.PresignedGet.ObjectKeyPrefix = commissioningTestRepositoryPrefix
	normalizedOptions = cloneS3CommissioningProbeOptions(options)
	normalized, err = normalizeS3CommissioningProbeOptions(store, &normalizedOptions, commissioningTestRepositoryPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.WritableStoreTimeout != 17*time.Millisecond {
		t.Fatalf("explicit writable timeout = %s", normalized.WritableStoreTimeout)
	}
	if normalized.PresignedPrefixDerived || !normalized.PresignedPrefixRepositoryScoped {
		t.Fatalf("repository-equal explicit presigned prefix was not accepted as scoped: %+v", normalized)
	}
	encoded, err := json.Marshal(options)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"writable_store_timeout_nanoseconds":17000000`) {
		t.Fatalf("options JSON omitted writable timeout: %s", encoded)
	}
}

func TestProbeCommissioningWritablePhaseTimeoutStillRunsPresigned(t *testing.T) {
	t.Parallel()
	_, _, store, options := newCommissioningTestRig(t, nil)
	options.WritableStoreTimeout = time.Nanosecond

	report, err := store.ProbeCommissioning(context.Background(), options)
	if !errors.Is(err, context.DeadlineExceeded) || report.Status != S3CommissioningIndeterminate ||
		report.WritableStoreOutcome != S3CommissioningStageFailed || report.PresignedGetOutcome != S3CommissioningStagePassed {
		t.Fatalf("phase timeout: report=%+v err=%v", report, err)
	}
}

func TestProbeCommissioningCompleteIsIndependentOfCompatibility(t *testing.T) {
	t.Parallel()
	_, _, store, options := newCommissioningTestRig(t, func(service *presignedGetProbeTestService) commissioningTestRequestHook {
		service.mu.Lock()
		service.allowTamperedWrite = true
		service.mu.Unlock()
		return nil
	})

	report, err := store.ProbeCommissioning(context.Background(), options)
	if !errors.Is(err, s3disk.ErrStoreIncompatible) || report.Compatible || !report.Complete ||
		!report.WritableStore.Complete || !report.PresignedGet.Complete {
		t.Fatalf("complete/incompatible report=%+v err=%v", report, err)
	}
	if report.WritableStoreOutcome != S3CommissioningStagePassed || report.PresignedGetOutcome != S3CommissioningStageFailed {
		t.Fatalf("stage outcomes = writable=%s presigned=%s", report.WritableStoreOutcome, report.PresignedGetOutcome)
	}
}

func TestProbeCommissioningWritableIncompatibleStillRunsPresigned(t *testing.T) {
	t.Parallel()
	_, server, store, options := newCommissioningTestRig(t, func(*presignedGetProbeTestService) commissioningTestRequestHook {
		return func(writer http.ResponseWriter, request *http.Request) bool {
			if commissioningWritableRequest(request) && request.Method == http.MethodHead {
				writer.Header().Set("ETag", `"unexpected-object"`)
				writer.WriteHeader(http.StatusOK)
				return true
			}
			return false
		}
	})

	report, err := store.ProbeCommissioning(context.Background(), options)
	if !errors.Is(err, s3disk.ErrStoreIncompatible) || report.Status != S3CommissioningIncompatible ||
		report.Compatible || report.Complete {
		t.Fatalf("aggregate = %+v, err=%v", report, err)
	}
	if report.WritableStore.Status != s3disk.StoreCompatibilityIncompatible {
		t.Fatalf("writable report = %+v", report.WritableStore)
	}
	if report.PresignedGet.Status != PresignedGetCompatibilityPassed || !report.PresignedGet.Complete {
		t.Fatalf("presigned phase was not retained after writable failure: %+v", report.PresignedGet)
	}
	if report.WritableStoreOutcome != S3CommissioningStageFailed || report.PresignedGetOutcome != S3CommissioningStagePassed {
		t.Fatalf("stage outcomes = writable=%s presigned=%s", report.WritableStoreOutcome, report.PresignedGetOutcome)
	}
	var writableErr *s3disk.StoreCompatibilityError
	if !errors.As(err, &writableErr) {
		t.Fatalf("aggregate does not retain writable typed error: %T %v", err, err)
	}
	assertS3CommissioningDiagnosticsRedacted(t, report, err, options, server.URL)
}

func TestProbeCommissioningWritableIndeterminateStillRunsPresigned(t *testing.T) {
	t.Parallel()
	_, _, store, options := newCommissioningTestRig(t, func(*presignedGetProbeTestService) commissioningTestRequestHook {
		return func(writer http.ResponseWriter, request *http.Request) bool {
			if commissioningWritableRequest(request) && request.Method == http.MethodHead {
				writePresignedGetProbeTestError(writer, http.StatusServiceUnavailable, "ServiceUnavailable")
				return true
			}
			return false
		}
	})

	report, err := store.ProbeCommissioning(context.Background(), options)
	if err == nil || !errors.Is(err, s3disk.ErrStoreUnavailable) || report.Status != S3CommissioningIndeterminate ||
		report.Compatible || report.Complete {
		t.Fatalf("aggregate = %+v, err=%v", report, err)
	}
	if report.WritableStore.Status != s3disk.StoreCompatibilityIndeterminate ||
		report.PresignedGet.Status != PresignedGetCompatibilityPassed {
		t.Fatalf("nested reports = writable=%+v presigned=%+v", report.WritableStore, report.PresignedGet)
	}
	if report.WritableStoreOutcome != S3CommissioningStageFailed || report.PresignedGetOutcome != S3CommissioningStagePassed {
		t.Fatalf("stage outcomes = writable=%s presigned=%s", report.WritableStoreOutcome, report.PresignedGetOutcome)
	}
}

func TestProbeCommissioningPresignedIncompatibleRetainsWritable(t *testing.T) {
	t.Parallel()
	_, _, store, options := newCommissioningTestRig(t, func(service *presignedGetProbeTestService) commissioningTestRequestHook {
		return func(_ http.ResponseWriter, request *http.Request) bool {
			if commissioningPresignedBearerRequest(request) {
				service.mu.Lock()
				service.serveStaleAfterReplacement = true
				service.mu.Unlock()
			}
			return false
		}
	})

	report, err := store.ProbeCommissioning(context.Background(), options)
	if !errors.Is(err, s3disk.ErrStoreIncompatible) || report.Status != S3CommissioningIncompatible ||
		report.Compatible || report.Complete {
		t.Fatalf("aggregate = %+v, err=%v", report, err)
	}
	if report.WritableStore.Status != s3disk.StoreCompatibilityPassed || !report.WritableStore.Complete {
		t.Fatalf("writable report was not retained: %+v", report.WritableStore)
	}
	if report.PresignedGet.Status != PresignedGetCompatibilityIncompatible {
		t.Fatalf("presigned report = %+v", report.PresignedGet)
	}
	if report.WritableStoreOutcome != S3CommissioningStagePassed || report.PresignedGetOutcome != S3CommissioningStageFailed {
		t.Fatalf("stage outcomes = writable=%s presigned=%s", report.WritableStoreOutcome, report.PresignedGetOutcome)
	}
	var presignedErr *PresignedGetCompatibilityError
	if !errors.As(err, &presignedErr) {
		t.Fatalf("aggregate does not retain presigned typed error: %T %v", err, err)
	}
}

func TestProbeCommissioningPresignedIndeterminateRetainsWritable(t *testing.T) {
	t.Parallel()
	_, _, store, options := newCommissioningTestRig(t, func(*presignedGetProbeTestService) commissioningTestRequestHook {
		return func(writer http.ResponseWriter, request *http.Request) bool {
			if commissioningPresignedBearerRequest(request) && request.Method == http.MethodGet {
				writePresignedGetProbeTestError(writer, http.StatusServiceUnavailable, "ServiceUnavailable")
				return true
			}
			return false
		}
	})

	report, err := store.ProbeCommissioning(context.Background(), options)
	if err == nil || report.Status != S3CommissioningIndeterminate || report.Compatible || report.Complete {
		t.Fatalf("aggregate = %+v, err=%v", report, err)
	}
	if report.WritableStore.Status != s3disk.StoreCompatibilityPassed ||
		report.PresignedGet.Status != PresignedGetCompatibilityIndeterminate {
		t.Fatalf("nested reports = writable=%+v presigned=%+v", report.WritableStore, report.PresignedGet)
	}
	if report.WritableStoreOutcome != S3CommissioningStagePassed || report.PresignedGetOutcome != S3CommissioningStageFailed {
		t.Fatalf("stage outcomes = writable=%s presigned=%s", report.WritableStoreOutcome, report.PresignedGetOutcome)
	}
	var presignedErr *PresignedGetCompatibilityError
	if !errors.As(err, &presignedErr) || presignedErr.Reason != PresignedGetCompatibilityReasonStoreUnavailable {
		t.Fatalf("presigned error = %+v", presignedErr)
	}
}

func TestProbeCommissioningRetainsBothPhaseErrors(t *testing.T) {
	t.Parallel()
	_, _, store, options := newCommissioningTestRig(t, func(*presignedGetProbeTestService) commissioningTestRequestHook {
		return func(writer http.ResponseWriter, request *http.Request) bool {
			switch {
			case commissioningWritableRequest(request) && request.Method == http.MethodHead:
				writePresignedGetProbeTestError(writer, http.StatusServiceUnavailable, "ServiceUnavailable")
				return true
			case commissioningPresignedBearerRequest(request) && request.Method == http.MethodGet:
				writePresignedGetProbeTestError(writer, http.StatusServiceUnavailable, "ServiceUnavailable")
				return true
			default:
				return false
			}
		}
	})

	report, err := store.ProbeCommissioning(context.Background(), options)
	if err == nil || report.WritableStore.Status != s3disk.StoreCompatibilityIndeterminate ||
		report.PresignedGet.Status != PresignedGetCompatibilityIndeterminate {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if report.WritableStoreOutcome != S3CommissioningStageFailed || report.PresignedGetOutcome != S3CommissioningStageFailed {
		t.Fatalf("stage outcomes = writable=%s presigned=%s", report.WritableStoreOutcome, report.PresignedGetOutcome)
	}
	var aggregate *S3CommissioningError
	var writableErr *s3disk.StoreCompatibilityError
	var presignedErr *PresignedGetCompatibilityError
	if !errors.As(err, &aggregate) || !errors.As(err, &writableErr) || !errors.As(err, &presignedErr) {
		t.Fatalf("typed errors not retained: aggregate=%+v writable=%+v presigned=%+v", aggregate, writableErr, presignedErr)
	}
	if len(aggregate.Unwrap()) != 2 {
		t.Fatalf("unwrapped phase errors = %d, want 2", len(aggregate.Unwrap()))
	}
}

func TestProbeCommissioningOverallCancellationStopsNextPhase(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cancelOnce sync.Once
	var bearerRequests atomic.Int64
	_, _, store, options := newCommissioningTestRig(t, func(*presignedGetProbeTestService) commissioningTestRequestHook {
		return func(writer http.ResponseWriter, request *http.Request) bool {
			if request.URL.Query().Get("X-Amz-Signature") != "" {
				bearerRequests.Add(1)
			}
			if commissioningWritableRequest(request) && request.Method == http.MethodHead {
				cancelOnce.Do(cancel)
				writePresignedGetProbeTestError(writer, http.StatusServiceUnavailable, "ServiceUnavailable")
				return true
			}
			return false
		}
	})

	report, err := store.ProbeCommissioning(ctx, options)
	if !errors.Is(err, context.Canceled) || report.Status != S3CommissioningIndeterminate {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if len(report.WritableStore.Checks) == 0 {
		t.Fatal("writable phase did not begin before cancellation")
	}
	if len(report.PresignedGet.Checks) != 0 || bearerRequests.Load() != 0 {
		t.Fatalf("presigned phase ran after overall cancellation: report=%+v bearer_requests=%d", report.PresignedGet, bearerRequests.Load())
	}
	if report.WritableStoreOutcome != S3CommissioningStageFailed || report.PresignedGetOutcome != S3CommissioningStageNotRun {
		t.Fatalf("canceled stage outcomes = writable=%s presigned=%s", report.WritableStoreOutcome, report.PresignedGetOutcome)
	}
	var aggregate *S3CommissioningError
	if !errors.As(err, &aggregate) || aggregate.WritableStoreOutcome != report.WritableStoreOutcome ||
		aggregate.PresignedGetOutcome != report.PresignedGetOutcome ||
		!errors.Is(aggregate.OverallError(), context.Canceled) ||
		!strings.Contains(err.Error(), "presigned_get=not_run") {
		t.Fatalf("canceled aggregate error = %+v (%v)", aggregate, err)
	}
}

func TestProbeCommissioningRejectsInvalidOptionsBeforeIO(t *testing.T) {
	var requests atomic.Int64
	_, _, store, valid := newCommissioningTestRig(t, func(*presignedGetProbeTestService) commissioningTestRequestHook {
		return func(_ http.ResponseWriter, _ *http.Request) bool {
			requests.Add(1)
			return false
		}
	})
	with := func(change func(*S3CommissioningProbeOptions)) S3CommissioningProbeOptions {
		candidate := cloneS3CommissioningProbeOptions(valid)
		change(&candidate)
		return candidate
	}
	typedNilTransport := http.RoundTripper((*nilPresignedGetRoundTripper)(nil))
	tests := []struct {
		name              string
		options           S3CommissioningProbeOptions
		wantResourceLimit bool
	}{
		{name: "negative overall timeout", options: with(func(value *S3CommissioningProbeOptions) { value.TotalTimeout = -time.Nanosecond })},
		{name: "oversized overall timeout", options: with(func(value *S3CommissioningProbeOptions) {
			value.TotalTimeout = S3CommissioningMaximumTimeout + time.Nanosecond
		})},
		{name: "negative writable timeout", options: with(func(value *S3CommissioningProbeOptions) {
			value.WritableStoreTimeout = -time.Nanosecond
		})},
		{name: "oversized writable timeout", options: with(func(value *S3CommissioningProbeOptions) {
			value.WritableStoreTimeout = s3disk.StoreCompatibilityMaximumTimeout + time.Nanosecond
		})},
		{name: "uppercase deployment digest", options: with(func(value *S3CommissioningProbeOptions) { value.DeploymentFingerprint = strings.Repeat("A", 64) })},
		{name: "invalid evidence ID", options: with(func(value *S3CommissioningProbeOptions) { value.EvidenceID = "-not-canonical" })},
		{name: "oversized evidence ID", options: with(func(value *S3CommissioningProbeOptions) {
			value.EvidenceID = "a" + strings.Repeat("b", s3disk.StoreCompatibilityEvidenceIDMaxBytes)
		})},
		{name: "invalid implementation version", options: with(func(value *S3CommissioningProbeOptions) { value.ImplementationVersion = "build:secret" })},
		{name: "invalid repository prefix", options: with(func(value *S3CommissioningProbeOptions) { value.RepositoryPrefix = "raw-secret\x00prefix" })},
		{name: "oversized repository prefix", options: with(func(value *S3CommissioningProbeOptions) { value.RepositoryPrefix = strings.Repeat("r", 1024) })},
		{name: "repository prefix outside canonical presigned syntax", options: with(func(value *S3CommissioningProbeOptions) {
			value.RepositoryPrefix = "资料"
			value.PresignedGet.ObjectKeyPrefix = ""
		})},
		{name: "invalid presigned prefix", options: with(func(value *S3CommissioningProbeOptions) { value.PresignedGet.ObjectKeyPrefix = "../raw-secret" })},
		{name: "presigned prefix outside repository", options: with(func(value *S3CommissioningProbeOptions) {
			value.PresignedGet.ObjectKeyPrefix = commissioningTestRepositoryPrefix + "-evil/hostile-secret-outside"
		})},
		{name: "negative presigned cleanup timeout", options: with(func(value *S3CommissioningProbeOptions) { value.PresignedGet.CleanupTimeout = -time.Nanosecond })},
		{name: "malformed TLS roots", options: with(func(value *S3CommissioningProbeOptions) { value.PresignedGet.TLSRootCAPEM = []byte("RAW-TLS-SECRET") })},
		{name: "oversized TLS roots", options: with(func(value *S3CommissioningProbeOptions) {
			value.PresignedGet.TLSRootCAPEM = make([]byte, maximumPresignedGetProbeTLSRootCAPEMBytes+1)
		}), wantResourceLimit: true},
		{name: "typed-nil HTTP transport", options: with(func(value *S3CommissioningProbeOptions) {
			value.PresignedGet.HTTPClient = &http.Client{Transport: typedNilTransport}
		})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := requests.Load()
			report, err := store.ProbeCommissioning(context.Background(), test.options)
			if err == nil || !errors.Is(err, s3disk.ErrStoreMisconfigured) {
				t.Fatalf("error = %v, want ErrStoreMisconfigured", err)
			}
			if errors.Is(err, s3disk.ErrResourceLimit) != test.wantResourceLimit {
				t.Fatalf("resource-limit classification = %v, error = %v", errors.Is(err, s3disk.ErrResourceLimit), err)
			}
			var aggregate *S3CommissioningError
			if !errors.As(err, &aggregate) || aggregate.Status != S3CommissioningConfigurationError {
				t.Fatalf("aggregate error = %+v", aggregate)
			}
			if report.SchemaVersion != S3CommissioningReportSchemaVersion ||
				report.Evidence.SchemaVersion != S3CommissioningReportSchemaVersion || len(report.Evidence.RunID) != 48 ||
				report.Status != S3CommissioningConfigurationError || report.Complete || report.Compatible ||
				report.WritableStoreOutcome != S3CommissioningStageNotRun || report.PresignedGetOutcome != S3CommissioningStageNotRun ||
				report.WritableStore.ContractVersion != s3disk.StoreCompatibilityContractVersion ||
				report.WritableStore.Scope != s3disk.StoreCompatibilitySingleClientFiniteProbe ||
				report.WritableStore.Status != s3disk.StoreCompatibilityIndeterminate ||
				report.WritableStore.RequiredChecks != s3disk.StoreCompatibilityRequiredChecks ||
				report.WritableStore.Cleanup.Status != s3disk.StoreCompatibilityCleanupNotAttempted ||
				report.PresignedGet.Cleanup.Status != PresignedGetCompatibilityCleanupNotAttempted {
				t.Fatalf("configuration report = %+v", report)
			}
			if after := requests.Load(); after != before {
				t.Fatalf("invalid options performed %d Store requests", after-before)
			}
			encodedReport, marshalErr := json.Marshal(report)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			encodedError, marshalErr := json.Marshal(err)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			for _, diagnostic := range []string{
				err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err), string(encodedError),
				report.String(), fmt.Sprintf("%#v", report), string(encodedReport), test.options.String(),
			} {
				assertS3CommissioningTextRedacted(t, diagnostic, "raw-secret", "RAW-TLS-SECRET", "hostile-secret-outside")
			}
		})
	}
}

func TestProbeCommissioningNilTypedNilAndPreCanceledInputs(t *testing.T) {
	_, _, store, options := newCommissioningTestRig(t, nil)
	tests := []struct {
		name  string
		store *Store
		ctx   context.Context
		is    error
	}{
		{name: "nil store", store: nil, ctx: context.Background(), is: s3disk.ErrStoreMisconfigured},
		{name: "nil context", store: store, ctx: nil, is: s3disk.ErrStoreMisconfigured},
		{name: "typed nil context", store: store, ctx: (*nilPresignedGetContext)(nil), is: s3disk.ErrStoreMisconfigured},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report, err := test.store.ProbeCommissioning(test.ctx, options)
			if err == nil || !errors.Is(err, test.is) || report.SchemaVersion != S3CommissioningReportSchemaVersion {
				t.Fatalf("report=%+v err=%v", report, err)
			}
			assertS3CommissioningEarlyEnvelope(t, report)
		})
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := store.ProbeCommissioning(canceled, options)
	if !errors.Is(err, context.Canceled) || len(report.WritableStore.Checks) != 0 || len(report.PresignedGet.Checks) != 0 {
		t.Fatalf("pre-canceled report=%+v err=%v", report, err)
	}
	assertS3CommissioningEarlyEnvelope(t, report)
	var aggregate *S3CommissioningError
	if !errors.As(err, &aggregate) || aggregate.WritableStoreOutcome != S3CommissioningStageNotRun ||
		aggregate.PresignedGetOutcome != S3CommissioningStageNotRun || !strings.Contains(err.Error(), "writable_store=not_run") {
		t.Fatalf("pre-canceled aggregate = %+v (%v)", aggregate, err)
	}
}

func TestS3CommissioningAliasesAndFingerprintDomains(t *testing.T) {
	t.Parallel()
	originalRoots := []byte("caller-owned-roots")
	options := S3CommissioningProbeOptions{
		PresignedGet: PresignedGetCompatibilityProbeOptions{TLSRootCAPEM: originalRoots},
	}
	cloned := cloneS3CommissioningProbeOptions(options)
	originalRoots[0] = 'X'
	if string(cloned.PresignedGet.TLSRootCAPEM) != "caller-owned-roots" {
		t.Fatalf("cloned TLS roots aliased caller bytes: %q", cloned.PresignedGet.TLSRootCAPEM)
	}
	cloned.PresignedGet.TLSRootCAPEM[1] = 'Y'
	if options.PresignedGet.TLSRootCAPEM[1] == 'Y' {
		t.Fatal("caller TLS roots alias cloned options")
	}
	callerTransport := &http.Transport{MaxIdleConns: 7}
	callerClient := &http.Client{Transport: callerTransport, Timeout: 3 * time.Second}
	options.PresignedGet.HTTPClient = callerClient
	cloned = cloneS3CommissioningProbeOptions(options)
	callerClient.Timeout = 9 * time.Second
	callerTransport.MaxIdleConns = 99
	clonedTransport, ok := cloned.PresignedGet.HTTPClient.Transport.(*http.Transport)
	if !ok || cloned.PresignedGet.HTTPClient == callerClient || clonedTransport == callerTransport ||
		cloned.PresignedGet.HTTPClient.Timeout != 3*time.Second || clonedTransport.MaxIdleConns != 7 {
		t.Fatalf("HTTP client snapshot aliases caller state: client=%+v transport=%+v", cloned.PresignedGet.HTTPClient, clonedTransport)
	}

	first := newS3CommissioningReport(time.Unix(1, 0), PresignedGetCompatibilityEvidence{})
	second := newS3CommissioningReport(time.Unix(2, 0), PresignedGetCompatibilityEvidence{})
	first.PresignedGet.Limitations[0] = "mutated"
	if second.PresignedGet.Limitations[0] == "mutated" {
		t.Fatal("independent reports alias limitation slices")
	}

	writableCause := errors.New("writable")
	presignedCause := errors.New("presigned")
	errorReport := newS3CommissioningReport(time.Unix(3, 0), PresignedGetCompatibilityEvidence{})
	errorReport.WritableStoreOutcome = S3CommissioningStageFailed
	errorReport.PresignedGetOutcome = S3CommissioningStageFailed
	aggregate := newS3CommissioningReportError(errorReport, nil, writableCause, presignedCause).(*S3CommissioningError)
	unwrapped := aggregate.Unwrap()
	unwrapped[0] = nil
	if aggregate.Unwrap()[0] == nil {
		t.Fatal("Unwrap returned an aliased mutable slice")
	}

	repositoryFingerprint := s3CommissioningPrefixFingerprint(s3CommissioningRepositoryPrefixFingerprintDomain, "same-prefix")
	presignedFingerprint := s3CommissioningPrefixFingerprint(s3CommissioningPresignedPrefixFingerprintDomain, "same-prefix")
	if repositoryFingerprint == presignedFingerprint || len(repositoryFingerprint) != 64 || len(presignedFingerprint) != 64 {
		t.Fatalf("fingerprints are not canonical and domain-separated: %q %q", repositoryFingerprint, presignedFingerprint)
	}
}

func TestS3CommissioningErrorDiagnosticsAreRedactedButUnwrap(t *testing.T) {
	t.Parallel()
	rawCause := &hostileS3CommissioningCause{
		secret: "https://access.example.invalid/private?X-Amz-Credential=ACCESS&X-Amz-Signature=SIGNED-SECRET",
		target: s3disk.ErrStoreUnavailable,
	}
	report := newS3CommissioningReport(time.Unix(4, 0), PresignedGetCompatibilityEvidence{})
	report.WritableStoreOutcome = S3CommissioningStageFailed
	err := newS3CommissioningReportError(report, nil, rawCause, nil)
	if !errors.Is(err, s3disk.ErrStoreUnavailable) {
		t.Fatalf("aggregate did not retain errors.Is: %v", err)
	}
	var aggregate *S3CommissioningError
	if !errors.As(err, &aggregate) || aggregate.WritableStoreError() != rawCause {
		t.Fatalf("aggregate did not retain errors.As/accessor: %+v", aggregate)
	}
	var hostile *hostileS3CommissioningCause
	if !errors.As(err, &hostile) || hostile != rawCause {
		t.Fatalf("aggregate did not retain typed underlying cause: %+v", hostile)
	}
	copied := *aggregate
	if !errors.Is(copied, s3disk.ErrStoreUnavailable) || copied.WritableStoreError() != rawCause {
		t.Fatalf("copied aggregate did not retain Is/accessor: %+v", copied)
	}
	var copiedHostile *hostileS3CommissioningCause
	if !errors.As(copied, &copiedHostile) || copiedHostile != rawCause {
		t.Fatalf("copied aggregate did not retain errors.As: %+v", copiedHostile)
	}
	encodedPointer, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	encodedValue, marshalErr := json.Marshal(copied)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if string(encodedPointer) != string(encodedValue) {
		t.Fatalf("pointer/value JSON schema differs: pointer=%s value=%s", encodedPointer, encodedValue)
	}
	for _, diagnostic := range []string{
		err.Error(), fmt.Sprint(err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err), string(encodedPointer),
		copied.Error(), fmt.Sprint(copied), fmt.Sprintf("%+v", copied), fmt.Sprintf("%#v", copied), string(encodedValue),
	} {
		assertS3CommissioningTextRedacted(t, diagnostic,
			"access.example.invalid", "X-Amz-Credential", "X-Amz-Signature", "SIGNED-SECRET", "ACCESS")
	}
	if !strings.Contains(copied.Error(), "writable_store=failed") || !strings.Contains(copied.Error(), "presigned_get=not_run") ||
		!strings.Contains(string(encodedValue), `"presigned_get_outcome":"not_run"`) {
		t.Fatalf("copied error lost stage outcomes: error=%s json=%s", copied.Error(), encodedValue)
	}
}

type hostileS3CommissioningCause struct {
	secret string
	target error
}

func (cause *hostileS3CommissioningCause) Error() string { return cause.secret }
func (cause *hostileS3CommissioningCause) Unwrap() error { return cause.target }
func (cause *hostileS3CommissioningCause) GoString() string {
	return "hostileS3CommissioningCause{" + cause.secret + "}"
}

func commissioningWritableRequest(request *http.Request) bool {
	return strings.Contains(request.URL.Path, "/"+commissioningTestRepositoryPrefix+"/.s3disk/v1/probes/") &&
		request.URL.Query().Get("X-Amz-Signature") == ""
}

func commissioningPresignedBearerRequest(request *http.Request) bool {
	return strings.Contains(request.URL.Path, "/"+commissioningTestPresignedPrefix+"/") &&
		request.URL.Query().Get("X-Amz-Signature") != ""
}

func assertS3CommissioningEarlyEnvelope(t *testing.T, report S3CommissioningReport) {
	t.Helper()
	if report.WritableStoreOutcome != S3CommissioningStageNotRun || report.PresignedGetOutcome != S3CommissioningStageNotRun ||
		report.Complete || report.Compatible {
		t.Fatalf("early stage envelope = %+v", report)
	}
	if report.WritableStore.ContractVersion != s3disk.StoreCompatibilityContractVersion ||
		report.WritableStore.Scope != s3disk.StoreCompatibilitySingleClientFiniteProbe ||
		report.WritableStore.Status != s3disk.StoreCompatibilityIndeterminate ||
		report.WritableStore.RequiredChecks != s3disk.StoreCompatibilityRequiredChecks ||
		report.WritableStore.Contenders != s3CommissioningWritableStoreContenders ||
		report.WritableStore.Checks == nil || len(report.WritableStore.Checks) != 0 ||
		report.WritableStore.Cleanup.Status != s3disk.StoreCompatibilityCleanupNotAttempted {
		t.Fatalf("early writable envelope = %+v", report.WritableStore)
	}
	if report.PresignedGet.Scope != PresignedGetCompatibilitySingleEndpointFiniteProbe ||
		report.PresignedGet.Status != PresignedGetCompatibilityIndeterminate ||
		report.PresignedGet.RequiredChecks != PresignedGetCompatibilityRequiredChecks ||
		report.PresignedGet.Checks == nil || len(report.PresignedGet.Checks) != 0 ||
		report.PresignedGet.Cleanup.Status != PresignedGetCompatibilityCleanupNotAttempted {
		t.Fatalf("early presigned envelope = %+v", report.PresignedGet)
	}
	if report.Cleanup.WritableStoreStatus != s3disk.StoreCompatibilityCleanupNotAttempted ||
		report.Cleanup.PresignedGetStatus != PresignedGetCompatibilityCleanupNotAttempted ||
		report.Cleanup.CurrentObjectsMayRemain || report.Cleanup.HistoricalVersionsMayRemain || report.Cleanup.AttentionRequired {
		t.Fatalf("early cleanup summary = %+v", report.Cleanup)
	}
}

func assertS3CommissioningDiagnosticsRedacted(
	t *testing.T,
	report S3CommissioningReport,
	probeErr error,
	options S3CommissioningProbeOptions,
	endpoint string,
) {
	t.Helper()
	encodedReport, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	encodedOptions, err := json.Marshal(options)
	if err != nil {
		t.Fatal(err)
	}
	diagnostics := []string{
		string(encodedReport), report.String(), fmt.Sprint(report), fmt.Sprintf("%+v", report), fmt.Sprintf("%#v", report),
		string(encodedOptions), options.String(), fmt.Sprint(options), fmt.Sprintf("%+v", options), fmt.Sprintf("%#v", options),
	}
	if probeErr != nil {
		encodedError, marshalErr := json.Marshal(probeErr)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		diagnostics = append(diagnostics,
			probeErr.Error(), fmt.Sprint(probeErr), fmt.Sprintf("%+v", probeErr), fmt.Sprintf("%#v", probeErr), string(encodedError))
	}
	for _, diagnostic := range diagnostics {
		assertS3CommissioningTextRedacted(t, diagnostic,
			commissioningTestRepositoryPrefix, commissioningTestPresignedPrefix,
			commissioningTestAccessKey, commissioningTestSecretKey, commissioningTestSessionToken,
			"probe-bucket", endpoint, "X-Amz-Signature", "X-Amz-Credential")
	}
}

func assertS3CommissioningTextRedacted(t *testing.T, diagnostic string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if secret != "" && strings.Contains(diagnostic, secret) {
			t.Fatalf("diagnostic leaked %q: %s", secret, diagnostic)
		}
	}
}
