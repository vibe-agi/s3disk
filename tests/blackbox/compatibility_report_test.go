package s3disk_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

type reportHostileCause struct {
	diagnostic string
}

func (cause *reportHostileCause) Error() string { return cause.diagnostic }

func (cause *reportHostileCause) Unwrap() error { return s3disk.ErrStoreUnavailable }

func (cause *reportHostileCause) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Diagnostic string `json:"diagnostic"`
	}{Diagnostic: cause.diagnostic})
}

func TestPreReleaseCompatibilityContractRemainsVersionOne(t *testing.T) {
	t.Parallel()
	if s3disk.StoreCompatibilityContractVersion != 1 {
		t.Fatalf("pre-release compatibility contract version = %d, want 1; refine v1 until the first public release", s3disk.StoreCompatibilityContractVersion)
	}
	if s3disk.StoreCompatibilityRequiredChecks != 31 {
		t.Fatalf("required compatibility checks = %d, want 31", s3disk.StoreCompatibilityRequiredChecks)
	}
}

func TestStoreCompatibilityDiagnosticsRedactHostileCauses(t *testing.T) {
	t.Parallel()
	const (
		hostileEndpoint  = "https://secret-endpoint.example.invalid/private-object"
		hostileAccessKey = "HOSTILE-ACCESS-KEY-DO-NOT-LOG"
		hostileSignature = "HOSTILE-SIGNATURE-DO-NOT-LOG"
		hostileSecret    = "HOSTILE-SDK-SECRET-DO-NOT-LOG"
	)
	hostileDiagnostic := hostileEndpoint +
		"?X-Amz-Credential=" + hostileAccessKey +
		"&X-Amz-Signature=" + hostileSignature +
		"&secret=" + hostileSecret
	cause := &reportHostileCause{diagnostic: hostileDiagnostic}
	check := s3disk.StoreCompatibilityCheck{
		ID:      s3disk.StoreCompatibilityCheckMissingObjectMapping,
		Status:  s3disk.StoreCompatibilityIndeterminate,
		Reason:  s3disk.StoreCompatibilityReasonStoreUnavailable,
		Summary: "verify missing-object behavior",
		Detail:  "provider operation failed",
		Hint:    "retry against the commissioned endpoint",
		Cause:   cause,
	}
	cleanup := s3disk.StoreCompatibilityCleanupReport{
		Status:                  s3disk.StoreCompatibilityCleanupFailed,
		Reason:                  s3disk.StoreCompatibilityCleanupReasonStoreUnavailable,
		Detail:                  "cleanup could not be verified",
		Attempted:               1,
		Failed:                  1,
		VerificationFailures:    1,
		CurrentObjectsMayRemain: true,
		Cause:                   cause,
	}
	report := s3disk.StoreCompatibilityReport{
		ContractVersion: s3disk.StoreCompatibilityContractVersion,
		Scope:           s3disk.StoreCompatibilitySingleClientFiniteProbe,
		Status:          s3disk.StoreCompatibilityIndeterminate,
		RequiredChecks:  s3disk.StoreCompatibilityRequiredChecks,
		Checks:          []s3disk.StoreCompatibilityCheck{check},
		Cleanup:         cleanup,
	}
	compatibilityErr := &s3disk.StoreCompatibilityError{
		CheckID: check.ID,
		Status:  check.Status,
		Reason:  check.Reason,
		Detail:  check.Detail,
		Hint:    check.Hint,
		Cause:   cause,
	}

	values := []any{
		check, &check,
		cleanup, &cleanup,
		report, &report,
		compatibilityErr, *compatibilityErr,
	}
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal %T: %v", value, err)
		}
		for _, diagnostic := range []string{
			fmt.Sprintf("%v", value),
			fmt.Sprintf("%+v", value),
			fmt.Sprintf("%#v", value),
			string(encoded),
		} {
			for _, secret := range []string{
				hostileEndpoint,
				hostileAccessKey,
				hostileSignature,
				hostileSecret,
				"X-Amz-Credential",
				"X-Amz-Signature",
			} {
				if strings.Contains(diagnostic, secret) {
					t.Fatalf("%T diagnostic leaked %q: %s", value, secret, diagnostic)
				}
			}
		}
	}

	if !strings.Contains(compatibilityErr.Error(), "cause redacted") ||
		!strings.Contains(fmt.Sprintf("%#v", compatibilityErr), "cause redacted") {
		t.Fatalf("compatibility error did not disclose that its cause was redacted: %v", compatibilityErr)
	}
	encodedError, err := json.Marshal(compatibilityErr)
	if err != nil {
		t.Fatal(err)
	}
	for _, stable := range []string{
		`"check_id":"missing-object-error-mapping"`,
		`"status":"indeterminate"`,
		`"reason":"store_unavailable"`,
		`"cause_present":true`,
	} {
		if !strings.Contains(string(encodedError), stable) {
			t.Fatalf("compatibility error JSON omitted stable field %s: %s", stable, encodedError)
		}
	}
	if !errors.Is(compatibilityErr, cause) || !errors.Is(compatibilityErr, s3disk.ErrStoreUnavailable) {
		t.Fatalf("redaction broke errors.Is traversal: %v", compatibilityErr)
	}
	var retained *reportHostileCause
	if !errors.As(compatibilityErr, &retained) || retained != cause {
		t.Fatalf("redaction broke errors.As traversal: got %p, want %p", retained, cause)
	}
}

func TestStoreCompatibilityReportSuccessAndCleanup(t *testing.T) {
	t.Parallel()
	base := memstore.New()
	repository := reportTestRepository(t, base, "report-success")

	report, err := repository.ProbeStoreCompatibility(context.Background())
	if err != nil {
		t.Fatalf("ProbeStoreCompatibility: %v", err)
	}
	if report.ContractVersion != s3disk.StoreCompatibilityContractVersion {
		t.Fatalf("ContractVersion = %d, want %d", report.ContractVersion, s3disk.StoreCompatibilityContractVersion)
	}
	if report.RequiredChecks != s3disk.StoreCompatibilityRequiredChecks {
		t.Fatalf("RequiredChecks = %d, want exported contract value %d", report.RequiredChecks, s3disk.StoreCompatibilityRequiredChecks)
	}
	if report.Scope != s3disk.StoreCompatibilitySingleClientFiniteProbe {
		t.Fatalf("Scope = %q, want single-client finite probe", report.Scope)
	}
	if report.Status != s3disk.StoreCompatibilityPassed || !report.Compatible || !report.Complete {
		t.Fatalf("report verdict = (%q, compatible=%v, complete=%v), want passed/true/true", report.Status, report.Compatible, report.Complete)
	}
	if len(report.ProbeID) != 48 {
		t.Fatalf("ProbeID length = %d, want 48 hex characters", len(report.ProbeID))
	}
	if len(report.Checks) == 0 {
		t.Fatal("successful report contains no checks")
	}
	if report.RequiredChecks != len(report.Checks) {
		t.Fatalf("RequiredChecks = %d, checks = %d", report.RequiredChecks, len(report.Checks))
	}
	if report.Contenders != 8 {
		t.Fatalf("Contenders = %d, want 8", report.Contenders)
	}
	seen := make(map[s3disk.StoreCompatibilityCheckID]struct{}, len(report.Checks))
	for _, check := range report.Checks {
		if check.Status != s3disk.StoreCompatibilityPassed {
			t.Fatalf("check %q status = %q, want passed", check.ID, check.Status)
		}
		if check.Summary == "" {
			t.Fatalf("check %q has no summary", check.ID)
		}
		if _, duplicate := seen[check.ID]; duplicate {
			t.Fatalf("check %q was reported more than once", check.ID)
		}
		seen[check.ID] = struct{}{}
	}
	if report.Cleanup.Status != s3disk.StoreCompatibilityCleanupSucceeded ||
		report.Cleanup.Reason != "" ||
		report.Cleanup.Detail == "" ||
		report.Cleanup.Attempted == 0 ||
		report.Cleanup.Succeeded != report.Cleanup.Attempted ||
		report.Cleanup.Failed != 0 ||
		report.Cleanup.DeleteFailures != 0 ||
		report.Cleanup.CurrentObjectsStillVisible != 0 ||
		report.Cleanup.VerificationFailures != 0 ||
		report.Cleanup.CurrentObjectsMayRemain ||
		!report.Cleanup.HistoricalVersionsMayRemain {
		t.Fatalf("cleanup = %+v, want all current probe objects deleted with conservative history warning", report.Cleanup)
	}

	conditionalKey := "report-success/.s3disk/v1/probes/" + report.ProbeID + "/conditional"
	if _, err := base.Head(context.Background(), conditionalKey); !errors.Is(err, s3disk.ErrObjectNotFound) {
		t.Fatalf("HEAD cleaned probe key error = %v, want ErrObjectNotFound", err)
	}
}

func TestStoreCompatibilityReportOperationalFailuresPreserveCause(t *testing.T) {
	t.Parallel()
	unknownCause := errors.New("opaque SDK credential-chain failure")
	tests := []struct {
		name   string
		cause  error
		want   error
		status s3disk.StoreCompatibilityStatus
		reason s3disk.StoreCompatibilityReason
	}{
		{
			name:   "configuration",
			cause:  fmt.Errorf("wrong region: %w", s3disk.ErrStoreMisconfigured),
			want:   s3disk.ErrStoreMisconfigured,
			status: s3disk.StoreCompatibilityConfigurationError,
			reason: s3disk.StoreCompatibilityReasonInvalidConfiguration,
		},
		{
			name:   "bucket-not-found",
			cause:  fmt.Errorf("selected bucket: %w", s3disk.ErrBucketNotFound),
			want:   s3disk.ErrBucketNotFound,
			status: s3disk.StoreCompatibilityConfigurationError,
			reason: s3disk.StoreCompatibilityReasonBucketNotFound,
		},
		{
			name:   "permission",
			cause:  fmt.Errorf("provider rejected probe: %w", s3disk.ErrAccessDenied),
			want:   s3disk.ErrAccessDenied,
			status: s3disk.StoreCompatibilityPermissionDenied,
			reason: s3disk.StoreCompatibilityReasonAccessDenied,
		},
		{
			name:   "unavailable",
			cause:  fmt.Errorf("provider 503: %w", s3disk.ErrStoreUnavailable),
			want:   s3disk.ErrStoreUnavailable,
			status: s3disk.StoreCompatibilityIndeterminate,
			reason: s3disk.StoreCompatibilityReasonStoreUnavailable,
		},
		{
			name:   "timeout",
			cause:  fmt.Errorf("transport timed out: %w", context.DeadlineExceeded),
			want:   context.DeadlineExceeded,
			status: s3disk.StoreCompatibilityIndeterminate,
			reason: s3disk.StoreCompatibilityReasonDeadlineExceeded,
		},
		{
			name:   "unknown-operational",
			cause:  unknownCause,
			want:   unknownCause,
			status: s3disk.StoreCompatibilityIndeterminate,
			reason: s3disk.StoreCompatibilityReasonUnknownOperational,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &reportHeadFailureStore{Store: memstore.New(), err: test.cause}
			repository := reportTestRepository(t, store, "operational-"+test.name)

			report, err := repository.ProbeStoreCompatibility(context.Background())
			compatibilityErr := reportRequireCompatibilityError(t, report, err, s3disk.StoreCompatibilityCheckMissingObjectMapping, test.status)
			if compatibilityErr.Reason != test.reason {
				t.Fatalf("reason = %q, want %q", compatibilityErr.Reason, test.reason)
			}
			if errors.Is(err, s3disk.ErrStoreIncompatible) {
				t.Fatalf("error = %v, transient/configuration failure must not match ErrStoreIncompatible", err)
			}
			if !errors.Is(err, test.want) || !errors.Is(compatibilityErr.Cause, test.want) {
				t.Fatalf("cause chain = %v, want errors.Is(..., %v)", err, test.want)
			}
			last := report.Checks[len(report.Checks)-1]
			if !errors.Is(last.Cause, test.want) {
				t.Fatalf("reported check cause = %v, want errors.Is(..., %v)", last.Cause, test.want)
			}
			encoded, marshalErr := json.Marshal(report)
			if marshalErr != nil {
				t.Fatalf("marshal compatibility report: %v", marshalErr)
			}
			if strings.Contains(string(encoded), test.cause.Error()) {
				t.Fatalf("JSON report exposed provider-specific cause: %s", encoded)
			}
			if !strings.Contains(string(encoded), `"reason":"`+string(test.reason)+`"`) {
				t.Fatalf("JSON report omitted stable reason %q: %s", test.reason, encoded)
			}
		})
	}
}

func TestStoreCompatibilityReportSemanticFailureHasExactCheckID(t *testing.T) {
	t.Parallel()
	store := &reportUnconditionalCreateStore{Store: memstore.New()}
	repository := reportTestRepository(t, store, "semantic-failure")

	report, err := repository.ProbeStoreCompatibility(context.Background())
	compatibilityErr := reportRequireCompatibilityError(
		t,
		report,
		err,
		s3disk.StoreCompatibilityCheckDuplicateCreate,
		s3disk.StoreCompatibilityIncompatible,
	)
	if !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("error = %v, want ErrStoreIncompatible", err)
	}
	if compatibilityErr.Hint == "" || report.Checks[len(report.Checks)-1].Hint == "" {
		t.Fatal("semantic failure omitted its remediation hint")
	}
	if compatibilityErr.Reason != s3disk.StoreCompatibilityReasonSemanticViolation {
		t.Fatalf("reason = %q, want semantic_violation", compatibilityErr.Reason)
	}
}

func TestStoreCompatibilityReportClassifiesUnsupportedOperation(t *testing.T) {
	t.Parallel()
	store := &reportHeadFailureStore{
		Store: memstore.New(),
		err:   fmt.Errorf("provider NotImplemented: %w", s3disk.ErrStoreOperationUnsupported),
	}
	repository := reportTestRepository(t, store, "unsupported-operation")

	report, err := repository.ProbeStoreCompatibility(context.Background())
	compatibilityErr := reportRequireCompatibilityError(
		t,
		report,
		err,
		s3disk.StoreCompatibilityCheckMissingObjectMapping,
		s3disk.StoreCompatibilityIncompatible,
	)
	if compatibilityErr.Reason != s3disk.StoreCompatibilityReasonOperationUnsupported ||
		!errors.Is(err, s3disk.ErrStoreIncompatible) ||
		!errors.Is(err, s3disk.ErrStoreOperationUnsupported) {
		t.Fatalf("error = %v, reason = %q; want unsupported incompatibility", err, compatibilityErr.Reason)
	}
}

func TestStoreCompatibilityReportCleanupIsNonVerdict(t *testing.T) {
	t.Parallel()
	t.Run("delete failure", func(t *testing.T) {
		t.Parallel()
		deleteCause := errors.New("delete denied by probe policy")
		store := &reportDeleteFailureStore{
			Store: memstore.New(),
			err:   fmt.Errorf("cleanup request: %w", deleteCause),
		}
		repository := reportTestRepository(t, store, "cleanup-failure")

		report, err := repository.ProbeStoreCompatibility(context.Background())
		if err != nil {
			t.Fatalf("ProbeStoreCompatibility: %v", err)
		}
		if report.Status != s3disk.StoreCompatibilityPassed || !report.Compatible || !report.Complete {
			t.Fatalf("cleanup failure changed compatibility verdict: %+v", report)
		}
		if report.Cleanup.Status != s3disk.StoreCompatibilityCleanupFailed ||
			report.Cleanup.Reason != s3disk.StoreCompatibilityCleanupReasonMultipleFailures ||
			report.Cleanup.Detail == "" ||
			report.Cleanup.Attempted == 0 ||
			report.Cleanup.Failed != report.Cleanup.Attempted ||
			report.Cleanup.Succeeded != 0 ||
			report.Cleanup.DeleteFailures != report.Cleanup.Attempted ||
			report.Cleanup.CurrentObjectsStillVisible != report.Cleanup.Attempted-1 ||
			report.Cleanup.VerificationFailures != 0 ||
			!report.Cleanup.CurrentObjectsMayRemain ||
			!report.Cleanup.HistoricalVersionsMayRemain {
			t.Fatalf("cleanup = %+v, want failed cleanup with possible retained objects", report.Cleanup)
		}
		if !errors.Is(report.Cleanup.Cause, deleteCause) {
			t.Fatalf("cleanup cause = %v, want errors.Is(..., %v)", report.Cleanup.Cause, deleteCause)
		}
	})

	t.Run("delete unsupported", func(t *testing.T) {
		t.Parallel()
		store := &reportNoDeleteStore{Store: memstore.New()}
		repository := reportTestRepository(t, store, "cleanup-unsupported")

		report, err := repository.ProbeStoreCompatibility(context.Background())
		if err != nil {
			t.Fatalf("ProbeStoreCompatibility: %v", err)
		}
		if report.Status != s3disk.StoreCompatibilityPassed || !report.Compatible || !report.Complete {
			t.Fatalf("missing Delete changed compatibility verdict: %+v", report)
		}
		if report.Cleanup.Status != s3disk.StoreCompatibilityCleanupNotSupported ||
			report.Cleanup.Reason != s3disk.StoreCompatibilityCleanupReasonDeleteNotSupported ||
			report.Cleanup.Detail == "" ||
			report.Cleanup.Attempted != 0 ||
			report.Cleanup.Succeeded != 0 ||
			report.Cleanup.Failed != 0 ||
			!report.Cleanup.CurrentObjectsMayRemain ||
			!report.Cleanup.HistoricalVersionsMayRemain {
			t.Fatalf("cleanup = %+v, want unsupported cleanup with possible retained objects", report.Cleanup)
		}
	})
}

func TestStoreCompatibilityReportCleanupVerifiesCurrentObjectAbsence(t *testing.T) {
	t.Parallel()

	t.Run("nil no-op delete leaves objects visible", func(t *testing.T) {
		t.Parallel()
		store := &reportNoOpDeleteStore{Store: memstore.New()}
		repository := reportTestRepository(t, store, "cleanup-no-op")

		report, err := repository.ProbeStoreCompatibility(context.Background())
		if err != nil || report.Status != s3disk.StoreCompatibilityPassed || !report.Compatible {
			t.Fatalf("cleanup warning changed probe verdict: report=%+v error=%v", report, err)
		}
		if report.Cleanup.Status != s3disk.StoreCompatibilityCleanupFailed ||
			report.Cleanup.Reason != s3disk.StoreCompatibilityCleanupReasonCurrentObjectStillVisible ||
			report.Cleanup.Failed != report.Cleanup.Attempted-1 ||
			report.Cleanup.Succeeded != 1 ||
			report.Cleanup.DeleteFailures != 0 ||
			report.Cleanup.CurrentObjectsStillVisible != report.Cleanup.Attempted-1 ||
			report.Cleanup.VerificationFailures != 0 ||
			!report.Cleanup.CurrentObjectsMayRemain {
			t.Fatalf("cleanup = %+v, want HEAD-verified no-op deletion failure", report.Cleanup)
		}
		encoded, marshalErr := json.Marshal(report)
		if marshalErr != nil {
			t.Fatalf("marshal report: %v", marshalErr)
		}
		if strings.Contains(string(encoded), "cleanup-no-op/.s3disk/") {
			t.Fatalf("cleanup JSON exposed a probe object key: %s", encoded)
		}
	})

	for _, test := range []struct {
		name       string
		cause      error
		want       error
		wantReason s3disk.StoreCompatibilityCleanupReason
	}{
		{
			name:       "HEAD access denied",
			cause:      fmt.Errorf("provider key detail must remain private: %w", s3disk.ErrAccessDenied),
			want:       s3disk.ErrAccessDenied,
			wantReason: s3disk.StoreCompatibilityCleanupReasonAccessDenied,
		},
		{
			name:       "HEAD network failure",
			cause:      fmt.Errorf("provider endpoint detail must remain private: %w", reportCleanupNetworkError{}),
			want:       reportCleanupNetworkError{},
			wantReason: s3disk.StoreCompatibilityCleanupReasonNetworkError,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &reportCleanupHeadFailureStore{Store: memstore.New(), err: test.cause}
			repository := reportTestRepository(t, store, "cleanup-head-verification")

			report, err := repository.ProbeStoreCompatibility(context.Background())
			if err != nil || report.Status != s3disk.StoreCompatibilityPassed || !report.Compatible {
				t.Fatalf("cleanup warning changed probe verdict: report=%+v error=%v", report, err)
			}
			if report.Cleanup.Status != s3disk.StoreCompatibilityCleanupFailed ||
				report.Cleanup.Reason != test.wantReason ||
				report.Cleanup.Failed != report.Cleanup.Attempted ||
				report.Cleanup.DeleteFailures != 0 ||
				report.Cleanup.CurrentObjectsStillVisible != 0 ||
				report.Cleanup.VerificationFailures != report.Cleanup.Attempted ||
				!report.Cleanup.CurrentObjectsMayRemain ||
				!errors.Is(report.Cleanup.Cause, test.want) {
				t.Fatalf("cleanup = %+v, want redacted HEAD verification failure %q", report.Cleanup, test.wantReason)
			}
			encoded, marshalErr := json.Marshal(report)
			if marshalErr != nil {
				t.Fatalf("marshal report: %v", marshalErr)
			}
			if strings.Contains(string(encoded), test.cause.Error()) || strings.Contains(string(encoded), "cleanup-head-verification/.s3disk/") {
				t.Fatalf("cleanup JSON exposed provider detail or a probe object key: %s", encoded)
			}
			if !strings.Contains(string(encoded), `"reason":"`+string(test.wantReason)+`"`) {
				t.Fatalf("cleanup JSON omitted stable reason %q: %s", test.wantReason, encoded)
			}
		})
	}
}

func TestStoreCompatibilityReportVersionedDeleteMarkerVerifiesCurrentAbsence(t *testing.T) {
	t.Parallel()
	base := memstore.New()
	store := &reportVersionedDeleteMarkerStore{Store: base, markers: make(map[string]struct{})}
	repository := reportTestRepository(t, store, "cleanup-versioned")

	report, err := repository.ProbeStoreCompatibility(context.Background())
	if err != nil || report.Status != s3disk.StoreCompatibilityPassed || !report.Compatible {
		t.Fatalf("ProbeStoreCompatibility: report=%+v error=%v", report, err)
	}
	if report.Cleanup.Status != s3disk.StoreCompatibilityCleanupSucceeded ||
		report.Cleanup.Failed != 0 || report.Cleanup.Succeeded != report.Cleanup.Attempted ||
		report.Cleanup.CurrentObjectsMayRemain || !report.Cleanup.HistoricalVersionsMayRemain {
		t.Fatalf("cleanup = %+v, want current objects absent with retained-history warning", report.Cleanup)
	}

	key := "cleanup-versioned/.s3disk/v1/probes/" + report.ProbeID + "/conditional"
	if _, err := store.Head(context.Background(), key); !errors.Is(err, s3disk.ErrObjectNotFound) {
		t.Fatalf("versioned current HEAD error = %v, want delete-marker ErrObjectNotFound", err)
	}
	if _, err := base.Head(context.Background(), key); err != nil {
		t.Fatalf("simulated noncurrent version was not retained: %v", err)
	}
}

func TestStoreCompatibilityReportRejectsOversizedVersionTokens(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"etag", "version-id"} {
		field := field
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			store := &reportOversizedVersionStore{Store: memstore.New(), field: field}
			repository := reportTestRepository(t, store, "oversized-"+field)

			report, err := repository.ProbeStoreCompatibility(context.Background())
			reportRequireCompatibilityError(
				t,
				report,
				err,
				s3disk.StoreCompatibilityCheckConditionalCreate,
				s3disk.StoreCompatibilityIncompatible,
			)
			if !errors.Is(err, s3disk.ErrStoreIncompatible) {
				t.Fatalf("error = %v, want ErrStoreIncompatible", err)
			}
		})
	}
}

func TestStoreCompatibilityReportRejectsAlwaysNotModified(t *testing.T) {
	t.Parallel()
	store := &reportAlwaysNotModifiedStore{Store: memstore.New()}
	repository := reportTestRepository(t, store, "always-not-modified")

	report, err := repository.ProbeStoreCompatibility(context.Background())
	reportRequireCompatibilityError(
		t,
		report,
		err,
		s3disk.StoreCompatibilityCheckConditionalGetStale,
		s3disk.StoreCompatibilityIncompatible,
	)
	if !errors.Is(err, s3disk.ErrStoreIncompatible) || !errors.Is(err, s3disk.ErrNotModified) {
		t.Fatalf("error = %v, want both ErrStoreIncompatible and retained ErrNotModified cause", err)
	}
}

func TestStoreCompatibilityReportRejectsVersionIDStrengthening(t *testing.T) {
	t.Parallel()
	store := &reportVersionIDStrengtheningStore{Store: memstore.New()}
	repository := reportTestRepository(t, store, "version-id-condition")

	report, err := repository.ProbeStoreCompatibility(context.Background())
	reportRequireCompatibilityError(
		t,
		report,
		err,
		s3disk.StoreCompatibilityCheckReplacementCAS,
		s3disk.StoreCompatibilityIncompatible,
	)
	if !errors.Is(err, s3disk.ErrStoreIncompatible) || !errors.Is(err, s3disk.ErrPrecondition) {
		t.Fatalf("error = %v, want incompatible verdict with retained ErrPrecondition cause", err)
	}
}

func TestStoreCompatibilityReportVerifiesConcurrentWinnerIdentity(t *testing.T) {
	t.Parallel()
	store := newReportFailedWriterStore()
	repository := reportTestRepository(t, store, "failed-writer")

	report, err := repository.ProbeStoreCompatibility(context.Background())
	reportRequireCompatibilityError(
		t,
		report,
		err,
		s3disk.StoreCompatibilityCheckReadAfterConcurrentPut,
		s3disk.StoreCompatibilityIncompatible,
	)
	if !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("error = %v, want ErrStoreIncompatible", err)
	}
}

func TestStoreCompatibilityReportReconcilesAppliedAmbiguousSequentialWrites(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		mode  string
		check s3disk.StoreCompatibilityCheckID
	}{
		{name: "conditional-create", mode: "conditional-create", check: s3disk.StoreCompatibilityCheckConditionalCreate},
		{name: "replacement-cas", mode: "replacement-cas", check: s3disk.StoreCompatibilityCheckReplacementCAS},
		{name: "nil-cas-create", mode: "nil-cas-create", check: s3disk.StoreCompatibilityCheckNilCASCreate},
		{name: "replacement-seed", mode: "replacement-seed", check: s3disk.StoreCompatibilityCheckConcurrentReplacementSeed},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &reportAmbiguousAppliedStore{Store: memstore.New(), mode: test.mode}
			repository := reportTestRepository(t, store, "ambiguous-sequential-"+test.name)

			report, err := repository.ProbeStoreCompatibility(context.Background())
			if err != nil {
				t.Fatalf("ProbeStoreCompatibility: %v", err)
			}
			if report.Status != s3disk.StoreCompatibilityPassed || !report.Compatible || !report.Complete {
				t.Fatalf("reconciled report = %+v, want complete pass", report)
			}
			check := reportFindCheck(t, report, test.check)
			if !strings.Contains(check.Detail, "response was ambiguous") ||
				!strings.Contains(check.Detail, "does not establish network stability") {
				t.Fatalf("reconciled check detail = %q", check.Detail)
			}
		})
	}
}

func TestStoreCompatibilityReportReconcilesZeroSuccessConcurrentWrites(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mode   string
		check  s3disk.StoreCompatibilityCheckID
		suffix string
	}{
		{name: "put-if-absent", mode: "concurrent-put", check: s3disk.StoreCompatibilityCheckConcurrentPutIfAbsent, suffix: "/concurrent-put-if-absent"},
		{name: "nil-cas", mode: "concurrent-nil-cas", check: s3disk.StoreCompatibilityCheckConcurrentNilCAS, suffix: "/concurrent-nil-cas"},
		{name: "replacement-cas", mode: "concurrent-replacement", check: s3disk.StoreCompatibilityCheckConcurrentReplacementCAS, suffix: "/concurrent-replace-cas"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &reportAmbiguousAppliedStore{Store: memstore.New(), mode: test.mode, countedSuffix: test.suffix}
			repository := reportTestRepository(t, store, "ambiguous-concurrent-"+test.name)

			report, err := repository.ProbeStoreCompatibility(context.Background())
			if err != nil {
				t.Fatalf("ProbeStoreCompatibility: %v", err)
			}
			check := reportFindCheck(t, report, test.check)
			if !strings.Contains(check.Detail, "all responses were ambiguous") ||
				!strings.Contains(check.Detail, "does not establish network stability") {
				t.Fatalf("reconciled concurrent detail = %q", check.Detail)
			}
			store.mu.Lock()
			getCalls := store.countedGets
			store.mu.Unlock()
			if getCalls != 1 {
				t.Fatalf("GET calls for reconciled concurrent key = %d, want one reused observation", getCalls)
			}
		})
	}
}

func TestStoreCompatibilityReportAmbiguousWriteVerdictOrdering(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name           string
		mode           string
		wantStatus     s3disk.StoreCompatibilityStatus
		wantReason     s3disk.StoreCompatibilityReason
		wantCause      error
		incompatible   bool
		detailContains string
	}{
		{
			name: "operational-not-applied", mode: "unavailable-not-applied",
			wantStatus: s3disk.StoreCompatibilityIndeterminate, wantReason: s3disk.StoreCompatibilityReasonStoreUnavailable,
			wantCause: s3disk.ErrStoreUnavailable, detailContains: "remains absent",
		},
		{
			name: "precondition-not-applied", mode: "precondition-not-applied",
			wantStatus: s3disk.StoreCompatibilityIncompatible, wantReason: s3disk.StoreCompatibilityReasonSemanticViolation,
			wantCause: s3disk.ErrPrecondition, incompatible: true, detailContains: "remains absent",
		},
		{
			name: "reconciliation-read-unavailable", mode: "applied-then-get-unavailable",
			wantStatus: s3disk.StoreCompatibilityIndeterminate, wantReason: s3disk.StoreCompatibilityReasonStoreUnavailable,
			wantCause: s3disk.ErrStoreUnavailable, detailContains: "could not be read",
		},
		{
			name: "foreign-bytes-outrank-operational", mode: "foreign-bytes",
			wantStatus: s3disk.StoreCompatibilityIncompatible, wantReason: s3disk.StoreCompatibilityReasonSemanticViolation,
			wantCause: s3disk.ErrStoreUnavailable, incompatible: true, detailContains: "neither the attempted payload",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &reportAmbiguousFailureStore{Store: memstore.New(), mode: test.mode}
			repository := reportTestRepository(t, store, "ambiguous-order-"+test.name)

			report, err := repository.ProbeStoreCompatibility(context.Background())
			compatibilityErr := reportRequireCompatibilityError(
				t, report, err, s3disk.StoreCompatibilityCheckConditionalCreate, test.wantStatus,
			)
			if compatibilityErr.Reason != test.wantReason || !errors.Is(err, test.wantCause) {
				t.Fatalf("error = %v, reason = %q; want cause %v and reason %q", err, compatibilityErr.Reason, test.wantCause, test.wantReason)
			}
			if errors.Is(err, s3disk.ErrStoreIncompatible) != test.incompatible {
				t.Fatalf("ErrStoreIncompatible match = %v, want %v: %v", errors.Is(err, s3disk.ErrStoreIncompatible), test.incompatible, err)
			}
			if !strings.Contains(compatibilityErr.Detail, test.detailContains) {
				t.Fatalf("detail = %q, want substring %q", compatibilityErr.Detail, test.detailContains)
			}
			if test.mode == "applied-then-get-unavailable" && !errors.Is(err, s3disk.ErrPrecondition) {
				t.Fatalf("reconciliation error lost ambiguous precondition cause: %v", err)
			}
		})
	}
}

func reportFindCheck(t *testing.T, report s3disk.StoreCompatibilityReport, id s3disk.StoreCompatibilityCheckID) s3disk.StoreCompatibilityCheck {
	t.Helper()
	for _, check := range report.Checks {
		if check.ID == id {
			return check
		}
	}
	t.Fatalf("report omitted check %q", id)
	return s3disk.StoreCompatibilityCheck{}
}

func reportTestRepository(t *testing.T, store s3disk.Store, prefix string) *s3disk.Repository {
	t.Helper()
	repository, err := s3disk.NewRepository(store, prefix)
	if err != nil {
		t.Fatalf("NewRepository: %v", err)
	}
	return repository
}

func reportRequireCompatibilityError(
	t *testing.T,
	report s3disk.StoreCompatibilityReport,
	err error,
	wantID s3disk.StoreCompatibilityCheckID,
	wantStatus s3disk.StoreCompatibilityStatus,
) *s3disk.StoreCompatibilityError {
	t.Helper()
	if err == nil {
		t.Fatal("ProbeStoreCompatibility unexpectedly succeeded")
	}
	var compatibilityErr *s3disk.StoreCompatibilityError
	if !errors.As(err, &compatibilityErr) {
		t.Fatalf("error type = %T, want *StoreCompatibilityError", err)
	}
	if compatibilityErr.CheckID != wantID || compatibilityErr.Status != wantStatus {
		t.Fatalf("compatibility error = (check=%q, status=%q), want (%q, %q)", compatibilityErr.CheckID, compatibilityErr.Status, wantID, wantStatus)
	}
	if report.Status != wantStatus || report.Compatible || report.Complete {
		t.Fatalf("report verdict = (%q, compatible=%v, complete=%v), want (%q, false, false)", report.Status, report.Compatible, report.Complete, wantStatus)
	}
	if len(report.Checks) == 0 {
		t.Fatal("failed report contains no checks")
	}
	last := report.Checks[len(report.Checks)-1]
	if last.ID != wantID || last.Status != wantStatus {
		t.Fatalf("last check = (%q, %q), want (%q, %q)", last.ID, last.Status, wantID, wantStatus)
	}
	if last.Summary == "" || last.Detail == "" || last.Hint == "" {
		t.Fatalf("failed check omitted diagnostics: %+v", last)
	}
	return compatibilityErr
}

type reportHeadFailureStore struct {
	s3disk.Store
	err error
}

func (store *reportHeadFailureStore) Head(context.Context, string) (s3disk.Version, error) {
	return s3disk.Version{}, store.err
}

type reportUnconditionalCreateStore struct {
	Store *memstore.Store
}

func (store *reportUnconditionalCreateStore) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	return store.Store.Get(ctx, key, options)
}

func (store *reportUnconditionalCreateStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	return store.Store.Head(ctx, key)
}

func (store *reportUnconditionalCreateStore) PutIfAbsent(ctx context.Context, key string, data []byte) (s3disk.Version, error) {
	if err := ctx.Err(); err != nil {
		return s3disk.Version{}, err
	}
	store.Store.ForcePut(key, data)
	object, err := store.Store.Get(ctx, key, s3disk.GetOptions{})
	return object.Version, err
}

func (store *reportUnconditionalCreateStore) CompareAndSwap(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
	return store.Store.CompareAndSwap(ctx, key, expected, data)
}

func (store *reportUnconditionalCreateStore) Delete(ctx context.Context, key string) error {
	return store.Store.Delete(ctx, key)
}

type reportDeleteFailureStore struct {
	s3disk.Store
	err error
}

func (store *reportDeleteFailureStore) Delete(context.Context, string) error {
	return store.err
}

type reportNoOpDeleteStore struct {
	*memstore.Store
}

func (store *reportNoOpDeleteStore) Delete(ctx context.Context, _ string) error {
	return ctx.Err()
}

type reportCleanupHeadFailureStore struct {
	*memstore.Store
	mu      sync.Mutex
	cleanup bool
	err     error
}

func (store *reportCleanupHeadFailureStore) Delete(ctx context.Context, key string) error {
	if err := store.Store.Delete(ctx, key); err != nil {
		return err
	}
	store.mu.Lock()
	store.cleanup = true
	store.mu.Unlock()
	return nil
}

func (store *reportCleanupHeadFailureStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	store.mu.Lock()
	cleanup := store.cleanup
	store.mu.Unlock()
	if cleanup {
		return s3disk.Version{}, store.err
	}
	return store.Store.Head(ctx, key)
}

type reportVersionedDeleteMarkerStore struct {
	*memstore.Store
	mu      sync.Mutex
	markers map[string]struct{}
}

func (store *reportVersionedDeleteMarkerStore) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	store.markers[key] = struct{}{}
	store.mu.Unlock()
	return nil
}

func (store *reportVersionedDeleteMarkerStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	if err := ctx.Err(); err != nil {
		return s3disk.Version{}, err
	}
	store.mu.Lock()
	_, deleted := store.markers[key]
	store.mu.Unlock()
	if deleted {
		return s3disk.Version{}, s3disk.ErrObjectNotFound
	}
	return store.Store.Head(ctx, key)
}

type reportCleanupNetworkError struct{}

func (reportCleanupNetworkError) Error() string { return "cleanup verification network failure" }
func (reportCleanupNetworkError) Timeout() bool { return false }
func (reportCleanupNetworkError) Temporary() bool {
	return true
}

// Embedding only the narrow Store interface deliberately hides an underlying
// ObjectDeleter so the dynamic adapter does not advertise cleanup support.
type reportNoDeleteStore struct {
	s3disk.Store
}

type reportOversizedVersionStore struct {
	Store *memstore.Store
	field string
}

func (store *reportOversizedVersionStore) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	return store.Store.Get(ctx, key, options)
}

func (store *reportOversizedVersionStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	return store.Store.Head(ctx, key)
}

func (store *reportOversizedVersionStore) PutIfAbsent(ctx context.Context, key string, data []byte) (s3disk.Version, error) {
	version, err := store.Store.PutIfAbsent(ctx, key, data)
	if err != nil {
		return version, err
	}
	oversized := strings.Repeat("x", s3disk.MaxStoreVersionTokenBytes+1)
	if store.field == "etag" {
		version.ETag = oversized
	} else {
		version.VersionID = oversized
	}
	return version, nil
}

func (store *reportOversizedVersionStore) CompareAndSwap(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
	return store.Store.CompareAndSwap(ctx, key, expected, data)
}

func (store *reportOversizedVersionStore) Delete(ctx context.Context, key string) error {
	return store.Store.Delete(ctx, key)
}

type reportAlwaysNotModifiedStore struct {
	Store *memstore.Store
}

func (store *reportAlwaysNotModifiedStore) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	if options.IfNoneMatch != "" {
		return s3disk.Object{}, s3disk.ErrNotModified
	}
	return store.Store.Get(ctx, key, options)
}

func (store *reportAlwaysNotModifiedStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	return store.Store.Head(ctx, key)
}

func (store *reportAlwaysNotModifiedStore) PutIfAbsent(ctx context.Context, key string, data []byte) (s3disk.Version, error) {
	return store.Store.PutIfAbsent(ctx, key, data)
}

func (store *reportAlwaysNotModifiedStore) CompareAndSwap(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
	return store.Store.CompareAndSwap(ctx, key, expected, data)
}

func (store *reportAlwaysNotModifiedStore) Delete(ctx context.Context, key string) error {
	return store.Store.Delete(ctx, key)
}

type reportVersionIDStrengtheningStore struct {
	Store *memstore.Store
}

func (store *reportVersionIDStrengtheningStore) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	return store.Store.Get(ctx, key, options)
}

func (store *reportVersionIDStrengtheningStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	return store.Store.Head(ctx, key)
}

func (store *reportVersionIDStrengtheningStore) PutIfAbsent(ctx context.Context, key string, data []byte) (s3disk.Version, error) {
	return store.Store.PutIfAbsent(ctx, key, data)
}

func (store *reportVersionIDStrengtheningStore) CompareAndSwap(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
	if expected != nil {
		current, err := store.Store.Head(ctx, key)
		if err == nil && current.ETag == expected.ETag && current.VersionID != expected.VersionID {
			return s3disk.Version{}, s3disk.ErrPrecondition
		}
	}
	return store.Store.CompareAndSwap(ctx, key, expected, data)
}

func (store *reportVersionIDStrengtheningStore) Delete(ctx context.Context, key string) error {
	return store.Store.Delete(ctx, key)
}

type reportFailedWriterStore struct {
	Store *memstore.Store

	mu         sync.Mutex
	arrived    int
	allArrived chan struct{}
	winnerDone chan struct{}
}

type reportAmbiguousAppliedStore struct {
	Store *memstore.Store
	mode  string

	mu            sync.Mutex
	injected      bool
	countedSuffix string
	countedGets   int
}

func (store *reportAmbiguousAppliedStore) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	if store.countedSuffix != "" && strings.HasSuffix(key, store.countedSuffix) {
		store.mu.Lock()
		store.countedGets++
		store.mu.Unlock()
	}
	return store.Store.Get(ctx, key, options)
}

func (store *reportAmbiguousAppliedStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	return store.Store.Head(ctx, key)
}

func (store *reportAmbiguousAppliedStore) PutIfAbsent(ctx context.Context, key string, data []byte) (s3disk.Version, error) {
	version, err := store.Store.PutIfAbsent(ctx, key, data)
	if err == nil && (store.mode == "conditional-create" && strings.HasSuffix(key, "/conditional") ||
		store.mode == "concurrent-put" && strings.HasSuffix(key, "/concurrent-put-if-absent")) && store.markInjected() {
		return s3disk.Version{}, s3disk.ErrPrecondition
	}
	return version, err
}

func (store *reportAmbiguousAppliedStore) CompareAndSwap(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
	version, err := store.Store.CompareAndSwap(ctx, key, expected, data)
	if err != nil {
		return version, err
	}
	match := false
	switch store.mode {
	case "replacement-cas":
		match = expected != nil && strings.HasSuffix(key, "/conditional")
	case "nil-cas-create":
		match = expected == nil && strings.HasSuffix(key, "/nil-cas")
	case "replacement-seed":
		match = expected == nil && strings.HasSuffix(key, "/concurrent-replace-cas")
	case "concurrent-nil-cas":
		match = expected == nil && strings.HasSuffix(key, "/concurrent-nil-cas")
	case "concurrent-replacement":
		match = expected != nil && strings.HasSuffix(key, "/concurrent-replace-cas")
	}
	if match && store.markInjected() {
		return s3disk.Version{}, s3disk.ErrPrecondition
	}
	return version, nil
}

func (store *reportAmbiguousAppliedStore) Delete(ctx context.Context, key string) error {
	return store.Store.Delete(ctx, key)
}

func (store *reportAmbiguousAppliedStore) markInjected() bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.injected {
		return false
	}
	store.injected = true
	return true
}

type reportAmbiguousFailureStore struct {
	Store *memstore.Store
	mode  string

	mu               sync.Mutex
	injected         bool
	failReconcileGet bool
}

func (store *reportAmbiguousFailureStore) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	store.mu.Lock()
	fail := store.failReconcileGet && strings.HasSuffix(key, "/conditional")
	if fail {
		store.failReconcileGet = false
	}
	store.mu.Unlock()
	if fail {
		return s3disk.Object{}, s3disk.ErrStoreUnavailable
	}
	return store.Store.Get(ctx, key, options)
}

func (store *reportAmbiguousFailureStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	return store.Store.Head(ctx, key)
}

func (store *reportAmbiguousFailureStore) PutIfAbsent(ctx context.Context, key string, data []byte) (s3disk.Version, error) {
	if !strings.HasSuffix(key, "/conditional") || !store.markInjected() {
		return store.Store.PutIfAbsent(ctx, key, data)
	}
	switch store.mode {
	case "unavailable-not-applied":
		return s3disk.Version{}, s3disk.ErrStoreUnavailable
	case "precondition-not-applied":
		return s3disk.Version{}, s3disk.ErrPrecondition
	case "applied-then-get-unavailable":
		if _, err := store.Store.PutIfAbsent(ctx, key, data); err != nil {
			return s3disk.Version{}, err
		}
		store.mu.Lock()
		store.failReconcileGet = true
		store.mu.Unlock()
		return s3disk.Version{}, s3disk.ErrPrecondition
	case "foreign-bytes":
		store.Store.ForcePut(key, []byte("foreign probe bytes"))
		return s3disk.Version{}, s3disk.ErrStoreUnavailable
	default:
		return s3disk.Version{}, errors.New("unknown ambiguous failure test mode")
	}
}

func (store *reportAmbiguousFailureStore) CompareAndSwap(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
	return store.Store.CompareAndSwap(ctx, key, expected, data)
}

func (store *reportAmbiguousFailureStore) Delete(ctx context.Context, key string) error {
	return store.Store.Delete(ctx, key)
}

func (store *reportAmbiguousFailureStore) markInjected() bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.injected {
		return false
	}
	store.injected = true
	return true
}

func newReportFailedWriterStore() *reportFailedWriterStore {
	return &reportFailedWriterStore{
		Store:      memstore.New(),
		allArrived: make(chan struct{}),
		winnerDone: make(chan struct{}),
	}
}

func (store *reportFailedWriterStore) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	return store.Store.Get(ctx, key, options)
}

func (store *reportFailedWriterStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	return store.Store.Head(ctx, key)
}

func (store *reportFailedWriterStore) PutIfAbsent(ctx context.Context, key string, data []byte) (s3disk.Version, error) {
	if !strings.HasSuffix(key, "/concurrent-put-if-absent") {
		return store.Store.PutIfAbsent(ctx, key, data)
	}
	contender := int(data[len(data)-1])
	store.mu.Lock()
	store.arrived++
	if store.arrived == 8 {
		close(store.allArrived)
	}
	allArrived := store.allArrived
	winnerDone := store.winnerDone
	store.mu.Unlock()
	select {
	case <-allArrived:
	case <-ctx.Done():
		return s3disk.Version{}, ctx.Err()
	}
	if contender == 0 {
		store.Store.ForcePut(key, data)
		object, err := store.Store.Get(ctx, key, s3disk.GetOptions{})
		close(winnerDone)
		return object.Version, err
	}
	select {
	case <-winnerDone:
	case <-ctx.Done():
		return s3disk.Version{}, ctx.Err()
	}
	if contender == 7 {
		// This write is deliberately dishonest: the contender mutates the
		// object and then reports that its precondition failed.
		store.Store.ForcePut(key, data)
	}
	return s3disk.Version{}, s3disk.ErrPrecondition
}

func (store *reportFailedWriterStore) CompareAndSwap(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
	return store.Store.CompareAndSwap(ctx, key, expected, data)
}

func (store *reportFailedWriterStore) Delete(ctx context.Context, key string) error {
	return store.Store.Delete(ctx, key)
}
