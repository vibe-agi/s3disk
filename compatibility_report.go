package s3disk

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// StoreCompatibilityStatus is the result of a compatibility check or of the
// probe as a whole. A transient or configuration failure is not evidence that
// an endpoint violates the Store contract.
type StoreCompatibilityStatus string

const (
	// StoreCompatibilityContractVersion identifies the probe contract
	// represented by the stable check IDs in this release.
	// This project has not published its first compatibility contract yet, so
	// all pre-release refinements remain version 1. Increment only after a
	// released contract requires an incompatible successor.
	StoreCompatibilityContractVersion = 1
	compatibilityRequiredChecks       = 31
)

// StoreCompatibilityScope states what population a probe sampled. A passed
// single-client finite probe must not be presented as proof about every client,
// gateway node, failure schedule, or future provider behavior.
type StoreCompatibilityScope string

const StoreCompatibilitySingleClientFiniteProbe StoreCompatibilityScope = "single_client_finite_probe"

const (
	StoreCompatibilityPassed             StoreCompatibilityStatus = "passed"
	StoreCompatibilityIncompatible       StoreCompatibilityStatus = "incompatible"
	StoreCompatibilityIndeterminate      StoreCompatibilityStatus = "indeterminate"
	StoreCompatibilityConfigurationError StoreCompatibilityStatus = "configuration_error"
	StoreCompatibilityPermissionDenied   StoreCompatibilityStatus = "permission_denied"
)

// StoreCompatibilityCheckID is a stable machine-readable probe capability.
// New IDs may be added in later releases; existing IDs retain their meaning.
type StoreCompatibilityCheckID string

// StoreCompatibilityReason is a stable, redacted machine-readable explanation
// that remains in JSON after provider-specific Cause has been omitted.
type StoreCompatibilityReason string

const (
	StoreCompatibilityReasonSemanticViolation    StoreCompatibilityReason = "semantic_violation"
	StoreCompatibilityReasonOperationUnsupported StoreCompatibilityReason = "operation_unsupported"
	StoreCompatibilityReasonInvalidConfiguration StoreCompatibilityReason = "invalid_configuration"
	StoreCompatibilityReasonBucketNotFound       StoreCompatibilityReason = "bucket_not_found"
	StoreCompatibilityReasonAccessDenied         StoreCompatibilityReason = "access_denied"
	StoreCompatibilityReasonRateLimited          StoreCompatibilityReason = "rate_limited"
	StoreCompatibilityReasonStoreUnavailable     StoreCompatibilityReason = "store_unavailable"
	StoreCompatibilityReasonCanceled             StoreCompatibilityReason = "canceled"
	StoreCompatibilityReasonDeadlineExceeded     StoreCompatibilityReason = "deadline_exceeded"
	StoreCompatibilityReasonNetworkError         StoreCompatibilityReason = "network_error"
	StoreCompatibilityReasonLocalProbeFailure    StoreCompatibilityReason = "local_probe_failure"
	StoreCompatibilityReasonUnknownOperational   StoreCompatibilityReason = "unknown_operational_error"
)

const (
	StoreCompatibilityCheckConfiguration                  StoreCompatibilityCheckID = "configuration"
	StoreCompatibilityCheckProbeKey                       StoreCompatibilityCheckID = "probe-key-generation"
	StoreCompatibilityCheckMissingObjectMapping           StoreCompatibilityCheckID = "missing-object-error-mapping"
	StoreCompatibilityCheckConditionalCreate              StoreCompatibilityCheckID = "conditional-create"
	StoreCompatibilityCheckHeadAfterCreate                StoreCompatibilityCheckID = "head-after-create"
	StoreCompatibilityCheckReadAfterCreate                StoreCompatibilityCheckID = "read-after-create"
	StoreCompatibilityCheckInputBufferOwnership           StoreCompatibilityCheckID = "put-input-buffer-ownership"
	StoreCompatibilityCheckCASInputBufferOwnership        StoreCompatibilityCheckID = "cas-input-buffer-ownership"
	StoreCompatibilityCheckDuplicateCreate                StoreCompatibilityCheckID = "duplicate-create-rejection"
	StoreCompatibilityCheckBoundedGet                     StoreCompatibilityCheckID = "bounded-get"
	StoreCompatibilityCheckOutputBufferOwnership          StoreCompatibilityCheckID = "output-buffer-ownership"
	StoreCompatibilityCheckStaleCAS                       StoreCompatibilityCheckID = "stale-cas-rejection"
	StoreCompatibilityCheckFailedCASPreservesObject       StoreCompatibilityCheckID = "failed-cas-preserves-object"
	StoreCompatibilityCheckReplacementCAS                 StoreCompatibilityCheckID = "replacement-cas"
	StoreCompatibilityCheckReadAfterReplacement           StoreCompatibilityCheckID = "read-after-replacement"
	StoreCompatibilityCheckHeadAfterReplacement           StoreCompatibilityCheckID = "head-after-replacement"
	StoreCompatibilityCheckConditionalGetCurrent          StoreCompatibilityCheckID = "conditional-get-current-token"
	StoreCompatibilityCheckConditionalGetStale            StoreCompatibilityCheckID = "conditional-get-stale-token"
	StoreCompatibilityCheckNilCASCreate                   StoreCompatibilityCheckID = "nil-cas-create"
	StoreCompatibilityCheckNilCASDuplicate                StoreCompatibilityCheckID = "nil-cas-duplicate-rejection"
	StoreCompatibilityCheckNilCASPreservesObject          StoreCompatibilityCheckID = "failed-nil-cas-preserves-object"
	StoreCompatibilityCheckMissingKeyCAS                  StoreCompatibilityCheckID = "missing-key-cas-rejection"
	StoreCompatibilityCheckConcurrentPutIfAbsent          StoreCompatibilityCheckID = "concurrent-put-if-absent-atomicity"
	StoreCompatibilityCheckReadAfterConcurrentPut         StoreCompatibilityCheckID = "read-after-concurrent-put-if-absent"
	StoreCompatibilityCheckConcurrentNilCAS               StoreCompatibilityCheckID = "concurrent-nil-cas-atomicity"
	StoreCompatibilityCheckReadAfterConcurrentNilCAS      StoreCompatibilityCheckID = "read-after-concurrent-nil-cas"
	StoreCompatibilityCheckHeadAfterConcurrentNilCAS      StoreCompatibilityCheckID = "head-after-concurrent-nil-cas"
	StoreCompatibilityCheckConcurrentReplacementSeed      StoreCompatibilityCheckID = "concurrent-replacement-seed"
	StoreCompatibilityCheckConcurrentReplacementCAS       StoreCompatibilityCheckID = "concurrent-replacement-cas-atomicity"
	StoreCompatibilityCheckReadAfterConcurrentReplacement StoreCompatibilityCheckID = "read-after-concurrent-replacement"
	StoreCompatibilityCheckHeadAfterConcurrentReplacement StoreCompatibilityCheckID = "head-after-concurrent-replacement"
)

// StoreCompatibilityCheck describes one completed probe assertion. Cause is
// excluded from JSON so a report can be serialized without accidentally
// flattening provider-specific errors or endpoint details; inspect it with
// errors.Is/errors.As when handling the report in process.
type StoreCompatibilityCheck struct {
	ID      StoreCompatibilityCheckID `json:"id"`
	Status  StoreCompatibilityStatus  `json:"status"`
	Reason  StoreCompatibilityReason  `json:"reason,omitempty"`
	Summary string                    `json:"summary"`
	Detail  string                    `json:"detail,omitempty"`
	Hint    string                    `json:"hint,omitempty"`
	Cause   error                     `json:"-"`
}

// StoreCompatibilityCleanupStatus reports only probe-key cleanup. Cleanup is
// not part of the publication protocol and cannot make an otherwise compatible
// store incompatible.
type StoreCompatibilityCleanupStatus string

const (
	StoreCompatibilityCleanupNotAttempted StoreCompatibilityCleanupStatus = "not_attempted"
	StoreCompatibilityCleanupNotSupported StoreCompatibilityCleanupStatus = "not_supported"
	StoreCompatibilityCleanupSucceeded    StoreCompatibilityCleanupStatus = "succeeded"
	StoreCompatibilityCleanupFailed       StoreCompatibilityCleanupStatus = "failed"
)

// StoreCompatibilityCleanupReason is a stable, redacted machine-readable
// explanation for cleanup state. Provider errors and random object keys remain
// available only through Cause in process and are never copied into JSON.
type StoreCompatibilityCleanupReason string

const (
	StoreCompatibilityCleanupReasonDeleteNotSupported        StoreCompatibilityCleanupReason = "delete_not_supported"
	StoreCompatibilityCleanupReasonDeleteFailed              StoreCompatibilityCleanupReason = "delete_failed"
	StoreCompatibilityCleanupReasonCurrentObjectStillVisible StoreCompatibilityCleanupReason = "current_object_still_visible"
	StoreCompatibilityCleanupReasonVerificationFailed        StoreCompatibilityCleanupReason = "verification_failed"
	StoreCompatibilityCleanupReasonAccessDenied              StoreCompatibilityCleanupReason = "access_denied"
	StoreCompatibilityCleanupReasonConfigurationError        StoreCompatibilityCleanupReason = "configuration_error"
	StoreCompatibilityCleanupReasonDeadlineExceeded          StoreCompatibilityCleanupReason = "deadline_exceeded"
	StoreCompatibilityCleanupReasonStoreUnavailable          StoreCompatibilityCleanupReason = "store_unavailable"
	StoreCompatibilityCleanupReasonNetworkError              StoreCompatibilityCleanupReason = "network_error"
	StoreCompatibilityCleanupReasonMultipleFailures          StoreCompatibilityCleanupReason = "multiple_failures"
)

// StoreCompatibilityCleanupReport records cleanup without exposing random
// object keys. Succeeded counts only keys whose Delete result was acceptable
// and whose following Head returned ErrObjectNotFound. HistoricalVersionsMayRemain
// is conservative: current-object absence cannot prove that a versioned backend
// purged noncurrent versions or delete markers.
type StoreCompatibilityCleanupReport struct {
	Status                      StoreCompatibilityCleanupStatus `json:"status"`
	Reason                      StoreCompatibilityCleanupReason `json:"reason,omitempty"`
	Detail                      string                          `json:"detail,omitempty"`
	Attempted                   int                             `json:"attempted"`
	Succeeded                   int                             `json:"succeeded"`
	Failed                      int                             `json:"failed"`
	DeleteFailures              int                             `json:"delete_failures"`
	CurrentObjectsStillVisible  int                             `json:"current_objects_still_visible"`
	VerificationFailures        int                             `json:"verification_failures"`
	CurrentObjectsMayRemain     bool                            `json:"current_objects_may_remain"`
	HistoricalVersionsMayRemain bool                            `json:"historical_versions_may_remain"`
	Cause                       error                           `json:"-"`
}

// StoreCompatibilityReport is a fail-fast commissioning result. Evidence is
// redacted audit metadata, not a signature or a verified provider identity.
// Complete is true when all RequiredChecks ran, even if the final check failed.
// It is false when fail-fast behavior left later checks unexecuted.
type StoreCompatibilityReport struct {
	ContractVersion int                             `json:"contract_version"`
	Scope           StoreCompatibilityScope         `json:"scope"`
	Evidence        StoreCompatibilityEvidence      `json:"evidence"`
	ProbeID         string                          `json:"probe_id,omitempty"`
	Status          StoreCompatibilityStatus        `json:"status"`
	Compatible      bool                            `json:"compatible"`
	Complete        bool                            `json:"complete"`
	RequiredChecks  int                             `json:"required_checks"`
	Contenders      int                             `json:"contenders"`
	Checks          []StoreCompatibilityCheck       `json:"checks"`
	Cleanup         StoreCompatibilityCleanupReport `json:"cleanup"`
}

// StoreCompatibilityError identifies the exact failed or inconclusive check.
// For an incompatible result it matches ErrStoreIncompatible. It always
// unwraps Cause, allowing callers to distinguish context cancellation,
// permissions, throttling, and provider-specific errors.
type StoreCompatibilityError struct {
	CheckID StoreCompatibilityCheckID
	Status  StoreCompatibilityStatus
	Reason  StoreCompatibilityReason
	Detail  string
	Hint    string
	Cause   error
}

func (err *StoreCompatibilityError) Error() string {
	if err == nil {
		return "<nil>"
	}
	message := fmt.Sprintf("s3disk: compatibility check %q %s", err.CheckID, err.Status)
	if err.Reason != "" {
		message += " (" + string(err.Reason) + ")"
	}
	if err.Detail != "" {
		message += ": " + err.Detail
	}
	if err.Cause != nil {
		message += ": " + err.Cause.Error()
	}
	return message
}

func (err *StoreCompatibilityError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

func (err *StoreCompatibilityError) Is(target error) bool {
	return err != nil && target == ErrStoreIncompatible && err.Status == StoreCompatibilityIncompatible
}

type compatibilityRecorder struct {
	report *StoreCompatibilityReport
}

func (recorder compatibilityRecorder) pass(id StoreCompatibilityCheckID) {
	recorder.passDetail(id, "")
}

func (recorder compatibilityRecorder) passDetail(id StoreCompatibilityCheckID, detail string) {
	summary, _ := compatibilityCheckMetadata(id)
	recorder.report.Checks = append(recorder.report.Checks, StoreCompatibilityCheck{
		ID:      id,
		Status:  StoreCompatibilityPassed,
		Summary: summary,
		Detail:  detail,
	})
	recorder.report.Complete = len(recorder.report.Checks) == recorder.report.RequiredChecks
}

func (recorder compatibilityRecorder) incompatible(id StoreCompatibilityCheckID, detail string, cause error) error {
	return recorder.problem(id, StoreCompatibilityIncompatible, detail, cause)
}

func (recorder compatibilityRecorder) operationFailure(id StoreCompatibilityCheckID, detail string, cause error) error {
	return recorder.problem(id, compatibilityStatusForCause(cause), detail, cause)
}

func (recorder compatibilityRecorder) problem(id StoreCompatibilityCheckID, status StoreCompatibilityStatus, detail string, cause error) error {
	summary, capabilityHint := compatibilityCheckMetadata(id)
	reason := compatibilityReasonFor(id, status, cause)
	hint := compatibilityProblemHint(capabilityHint, reason)
	check := StoreCompatibilityCheck{
		ID:      id,
		Status:  status,
		Reason:  reason,
		Summary: summary,
		Detail:  detail,
		Hint:    hint,
		Cause:   cause,
	}
	recorder.report.Checks = append(recorder.report.Checks, check)
	recorder.report.Status = status
	recorder.report.Compatible = false
	recorder.report.Complete = len(recorder.report.Checks) == recorder.report.RequiredChecks
	return &StoreCompatibilityError{
		CheckID: id,
		Status:  status,
		Reason:  reason,
		Detail:  detail,
		Hint:    hint,
		Cause:   cause,
	}
}

func compatibilityStatusForCause(cause error) StoreCompatibilityStatus {
	if errors.Is(cause, ErrStoreIncompatible) {
		return StoreCompatibilityIncompatible
	}
	if errors.Is(cause, ErrStoreOperationUnsupported) {
		return StoreCompatibilityIncompatible
	}
	if errors.Is(cause, ErrPrecondition) || errors.Is(cause, ErrObjectNotFound) ||
		errors.Is(cause, ErrNotModified) || errors.Is(cause, ErrResourceLimit) {
		return StoreCompatibilityIncompatible
	}
	if errors.Is(cause, ErrAccessDenied) {
		return StoreCompatibilityPermissionDenied
	}
	if errors.Is(cause, ErrBucketNotFound) || errors.Is(cause, ErrStoreMisconfigured) {
		return StoreCompatibilityConfigurationError
	}
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) ||
		errors.Is(cause, ErrRateLimited) || errors.Is(cause, ErrStoreUnavailable) {
		return StoreCompatibilityIndeterminate
	}
	var networkError net.Error
	if errors.As(cause, &networkError) {
		return StoreCompatibilityIndeterminate
	}
	return StoreCompatibilityIndeterminate
}

func compatibilityReasonFor(id StoreCompatibilityCheckID, status StoreCompatibilityStatus, cause error) StoreCompatibilityReason {
	switch status {
	case StoreCompatibilityIncompatible:
		if errors.Is(cause, ErrStoreOperationUnsupported) {
			return StoreCompatibilityReasonOperationUnsupported
		}
		return StoreCompatibilityReasonSemanticViolation
	case StoreCompatibilityConfigurationError:
		if errors.Is(cause, ErrBucketNotFound) {
			return StoreCompatibilityReasonBucketNotFound
		}
		return StoreCompatibilityReasonInvalidConfiguration
	case StoreCompatibilityPermissionDenied:
		return StoreCompatibilityReasonAccessDenied
	case StoreCompatibilityIndeterminate:
		switch {
		case errors.Is(cause, context.DeadlineExceeded):
			return StoreCompatibilityReasonDeadlineExceeded
		case errors.Is(cause, context.Canceled):
			return StoreCompatibilityReasonCanceled
		case errors.Is(cause, ErrRateLimited):
			return StoreCompatibilityReasonRateLimited
		case errors.Is(cause, ErrStoreUnavailable):
			return StoreCompatibilityReasonStoreUnavailable
		}
		var networkError net.Error
		if errors.As(cause, &networkError) {
			return StoreCompatibilityReasonNetworkError
		}
		if id == StoreCompatibilityCheckProbeKey {
			return StoreCompatibilityReasonLocalProbeFailure
		}
		return StoreCompatibilityReasonUnknownOperational
	default:
		return ""
	}
}

func compatibilityProblemHint(capabilityHint string, reason StoreCompatibilityReason) string {
	switch reason {
	case StoreCompatibilityReasonInvalidConfiguration:
		return "verify the bucket, region, endpoint URL, path-style setting, prefix, and signing configuration, then rerun the probe"
	case StoreCompatibilityReasonBucketNotFound:
		return "create or select the configured bucket and verify its region and endpoint before rerunning the probe"
	case StoreCompatibilityReasonAccessDenied:
		return "grant the commissioning identity the required probe-prefix GET, HEAD, and conditional PUT permissions, then rerun"
	case StoreCompatibilityReasonRateLimited:
		return "apply provider backoff, reduce concurrent commissioning work, and rerun; no compatibility verdict was made"
	case StoreCompatibilityReasonStoreUnavailable:
		return "wait for the provider or gateway to recover and rerun; a 5xx response is not evidence of semantic incompatibility"
	case StoreCompatibilityReasonCanceled:
		return "rerun with a live context; the canceled probe made no compatibility verdict"
	case StoreCompatibilityReasonDeadlineExceeded:
		return "check endpoint latency and timeout policy, then rerun; do not classify one timeout as incompatibility"
	case StoreCompatibilityReasonNetworkError:
		return "verify DNS, TLS trust, routing, proxy, and connection health, then rerun the probe"
	case StoreCompatibilityReasonLocalProbeFailure:
		return "repair the local cryptographic random source and rerun; no store operation was attempted"
	case StoreCompatibilityReasonUnknownOperational:
		return "inspect the preserved cause and provider request diagnostics, classify the adapter error, and rerun before certification"
	default:
		return capabilityHint
	}
}

func compatibilityCheckMetadata(id StoreCompatibilityCheckID) (summary, hint string) {
	switch id {
	case StoreCompatibilityCheckConfiguration:
		return "repository and store configuration is usable", "construct a repository with a non-nil Store and a valid isolated prefix"
	case StoreCompatibilityCheckProbeKey:
		return "a collision-resistant isolated probe namespace can be created", "check the local cryptographic random source and retry; no store verdict was made"
	case StoreCompatibilityCheckMissingObjectMapping:
		return "missing GET and HEAD results map to ErrObjectNotFound", "fix the adapter's HTTP/S3 error classification; the core depends on a portable missing-object result"
	case StoreCompatibilityCheckConditionalCreate:
		return "conditional create returns a valid opaque ETag", "verify PUT If-None-Match:* support, SigV4 signing, bucket policy, and that no proxy strips conditional headers"
	case StoreCompatibilityCheckHeadAfterCreate:
		return "HEAD immediately observes the completed create", "use the direct object API rather than a CDN and require strong read-after-write consistency"
	case StoreCompatibilityCheckReadAfterCreate:
		return "GET immediately observes the completed create", "check stale caches, replication/gateway consistency, ETag handling, and atomic object reads"
	case StoreCompatibilityCheckInputBufferOwnership:
		return "PutIfAbsent does not retain caller-owned byte buffers", "fix the Store adapter to copy or fully consume request bytes before returning"
	case StoreCompatibilityCheckCASInputBufferOwnership:
		return "CompareAndSwap does not retain caller-owned byte buffers", "fix the Store adapter to copy or fully consume request bytes before returning"
	case StoreCompatibilityCheckDuplicateCreate:
		return "a duplicate conditional create fails without changing data", "the endpoint or proxy may ignore If-None-Match:* or the adapter may not map 409/412 to ErrPrecondition"
	case StoreCompatibilityCheckBoundedGet:
		return "GET enforces the caller's positive MaxBytes limit", "fix the Store adapter to bound response buffering and return ErrResourceLimit"
	case StoreCompatibilityCheckOutputBufferOwnership:
		return "GET returns caller-owned object bytes", "fix the Store adapter to return an independent byte slice for every successful GET"
	case StoreCompatibilityCheckStaleCAS:
		return "a stale ETag cannot replace the object", "verify PUT If-Match support and that gateways, SDK middleware, and proxies preserve the header"
	case StoreCompatibilityCheckFailedCASPreservesObject:
		return "a rejected CAS leaves the object unchanged", "the backend must make the condition check and write one atomic single-key operation"
	case StoreCompatibilityCheckReplacementCAS:
		return "the current ETag performs one replacement CAS", "verify PUT If-Match support; VersionID is diagnostic and must not be added as a write condition"
	case StoreCompatibilityCheckReadAfterReplacement:
		return "GET immediately observes the completed replacement", "check strong overwrite visibility, atomic reads, opaque ETag propagation, and adapter input ownership"
	case StoreCompatibilityCheckHeadAfterReplacement:
		return "HEAD immediately observes the completed replacement", "bypass caches and require HEAD to expose the same current ETag as GET"
	case StoreCompatibilityCheckConditionalGetCurrent:
		return "conditional GET recognizes the current ETag", "verify GET If-None-Match forwarding and map not-modified responses to ErrNotModified"
	case StoreCompatibilityCheckConditionalGetStale:
		return "conditional GET with an old ETag returns the new object", "the endpoint or adapter may return not-modified unconditionally or serve a stale cached version"
	case StoreCompatibilityCheckNilCASCreate:
		return "nil-expected CAS creates only an absent object", "implement nil CompareAndSwap as atomic PUT If-None-Match:*"
	case StoreCompatibilityCheckNilCASDuplicate:
		return "a duplicate nil-expected CAS is rejected", "nil CompareAndSwap is being treated as an unconditional PUT or 409/412 is mapped incorrectly"
	case StoreCompatibilityCheckNilCASPreservesObject:
		return "a rejected nil-expected CAS leaves the object unchanged", "make the absence test and object creation atomic"
	case StoreCompatibilityCheckMissingKeyCAS:
		return "If-Match cannot create a missing object", "the provider or proxy may ignore If-Match; a provider-specific generation adapter may be required"
	case StoreCompatibilityCheckConcurrentPutIfAbsent:
		return "concurrent conditional creates have exactly one winner", "the gateway may emulate create-only with a non-atomic HEAD-then-PUT sequence"
	case StoreCompatibilityCheckReadAfterConcurrentPut:
		return "the concurrent conditional-create winner is the stored object", "a failed contender may have written data or the gateway may not linearize conditional creates"
	case StoreCompatibilityCheckConcurrentNilCAS:
		return "concurrent nil-expected CAS operations have exactly one winner", "the gateway may implement the absence check and write as separate operations"
	case StoreCompatibilityCheckReadAfterConcurrentNilCAS:
		return "GET observes the unique nil-CAS winner", "a contender that reported failure may still have modified the object"
	case StoreCompatibilityCheckHeadAfterConcurrentNilCAS:
		return "HEAD observes the unique nil-CAS winner", "HEAD may be stale or expose a different version-token representation"
	case StoreCompatibilityCheckConcurrentReplacementSeed:
		return "the concurrent replacement key can be initialized", "verify conditional-create permissions and immediate write visibility"
	case StoreCompatibilityCheckConcurrentReplacementCAS:
		return "concurrent replacement CAS operations have exactly one winner", "the gateway may emulate If-Match with a non-atomic read-before-write sequence"
	case StoreCompatibilityCheckReadAfterConcurrentReplacement:
		return "GET observes the unique replacement-CAS winner", "a losing writer may have modified data or the gateway may return stale content"
	case StoreCompatibilityCheckHeadAfterConcurrentReplacement:
		return "HEAD observes the unique replacement-CAS winner", "HEAD may be stale or expose an ETag inconsistent with the winning write"
	default:
		return "object-store compatibility assertion", "inspect the Store adapter and endpoint behavior for this operation"
	}
}
