package s3store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/internal/tlsroots"
	"github.com/vibe-agi/s3disk/presignedshare"
)

const (
	// PresignedGetCompatibilityDefaultTimeout bounds the semantic portion of
	// the finite probe. Best-effort cleanup has its own additional deadline.
	PresignedGetCompatibilityDefaultTimeout = 2 * time.Minute
	// PresignedGetCompatibilityMaximumTimeout prevents accidental unbounded
	// commissioning calls.
	PresignedGetCompatibilityMaximumTimeout = 30 * time.Minute
	// PresignedGetCompatibilityDefaultCapabilityLifetime leaves time for the
	// default probe while remaining short-lived.
	PresignedGetCompatibilityDefaultCapabilityLifetime = 5 * time.Minute
	// PresignedGetCompatibilityDefaultCleanupTimeout bounds best-effort removal
	// independently of cancellation of the main probe.
	PresignedGetCompatibilityDefaultCleanupTimeout = 15 * time.Second
	// PresignedGetCompatibilityRequiredChecks is the number of assertions in
	// the current credential-free reader commissioning contract.
	PresignedGetCompatibilityRequiredChecks = 14

	defaultPresignedGetProbePrefix              = ".s3disk/compatibility/presigned-get"
	maximumPresignedGetProbePrefixBytes         = 768
	maximumPresignedGetProbeResponseBytes       = 4 << 10
	maximumPresignedGetProbeHeaderBytes         = presignedshare.MaximumResponseHeaderBytes
	maximumPresignedGetProbeHeaderCount         = 256
	maximumPresignedGetProbeTLSRootCAPEMBytes   = 4 << 20
	maximumPresignedGetProbeTLSRootCertificates = 1024
	maximumPresignedGetProbeConnections         = 1024
	presignedGetCompatibilityExpiryMargin       = 2 * time.Second
)

// PresignedGetCompatibilityScope describes the deliberately limited evidence
// collected by this probe. A pass is not a mathematical proof about every
// gateway node, network failure schedule, cache, policy change, or future
// provider behavior.
type PresignedGetCompatibilityScope string

const (
	PresignedGetCompatibilitySingleEndpointFiniteProbe PresignedGetCompatibilityScope = "single_endpoint_finite_probe"
	// PresignedGetCompatibilityCrossConfigurationFiniteProbe samples writer
	// and bearer routes supplied by two separately constructed Store values.
	PresignedGetCompatibilityCrossConfigurationFiniteProbe PresignedGetCompatibilityScope = "cross_configuration_finite_probe"
)

// PresignedGetCompatibilityLimitation is an explicit boundary on what a pass
// establishes. These values remain present even on a successful report.
type PresignedGetCompatibilityLimitation string

const (
	PresignedGetCompatibilityLimitationFutureStatesNotProven                     PresignedGetCompatibilityLimitation = "future_provider_and_network_states_not_proven"
	PresignedGetCompatibilityLimitationExpiryNotSampled                          PresignedGetCompatibilityLimitation = "post_expiry_rejection_not_sampled"
	PresignedGetCompatibilityLimitationOtherMethodsNotSampled                    PresignedGetCompatibilityLimitation = "other_http_methods_and_transient_side_effects_not_sampled"
	PresignedGetCompatibilityLimitationSystemTrustNetworkIO                      PresignedGetCompatibilityLimitation = "dangerous_system_trust_may_perform_non_s3_network_io"
	PresignedGetCompatibilityLimitationArbitraryQueryBindingNotProven            PresignedGetCompatibilityLimitation = "arbitrary_query_and_historical_version_binding_not_proven"
	PresignedGetCompatibilityLimitationHEADAndBodylessStatusWireBodyNotVisible   PresignedGetCompatibilityLimitation = "head_and_bodyless_status_wire_body_not_observable_with_net_http"
	PresignedGetCompatibilityLimitationDiscardedWireMetadataAndExtraBytes        PresignedGetCompatibilityLimitation = "discarded_wire_metadata_and_extra_bytes_not_observable_with_net_http"
	PresignedGetCompatibilityLimitationBucketPublicAccessPolicyNotFullyProven    PresignedGetCompatibilityLimitation = "bucket_public_access_policy_not_fully_proven"
	PresignedGetCompatibilityLimitationPUTPayloadVariantsBeyondNamedSamples      PresignedGetCompatibilityLimitation = "put_payload_variants_beyond_named_samples_not_proven"
	PresignedGetCompatibilityLimitationArbitraryUnsignedHeaderOverrideBinding    PresignedGetCompatibilityLimitation = "arbitrary_unsigned_header_override_binding_not_proven"
	PresignedGetCompatibilityLimitationBucketAndOriginBindingNotSampled          PresignedGetCompatibilityLimitation = "bucket_and_origin_binding_not_sampled"
	PresignedGetCompatibilityLimitationCrossConfigurationBindingNotAuthenticated PresignedGetCompatibilityLimitation = "cross_configuration_bucket_origin_route_and_identity_not_authenticated"
	// Deprecated: use PresignedGetCompatibilityLimitationArbitraryQueryBindingNotProven.
	PresignedGetCompatibilityLimitationQueryBindingNotSampled = PresignedGetCompatibilityLimitationArbitraryQueryBindingNotProven
	// Deprecated: use PresignedGetCompatibilityLimitationHEADAndBodylessStatusWireBodyNotVisible.
	PresignedGetCompatibilityLimitationHEADWireBodyNotVisible = PresignedGetCompatibilityLimitationHEADAndBodylessStatusWireBodyNotVisible
)

// PresignedGetCompatibilityStatus is the result of one check or the whole
// probe.
type PresignedGetCompatibilityStatus string

const (
	PresignedGetCompatibilityPassed             PresignedGetCompatibilityStatus = "passed"
	PresignedGetCompatibilityIncompatible       PresignedGetCompatibilityStatus = "incompatible"
	PresignedGetCompatibilityIndeterminate      PresignedGetCompatibilityStatus = "indeterminate"
	PresignedGetCompatibilityConfigurationError PresignedGetCompatibilityStatus = "configuration_error"
	PresignedGetCompatibilityPermissionDenied   PresignedGetCompatibilityStatus = "permission_denied"
)

// PresignedGetCompatibilityCheckID is a stable machine-readable assertion.
type PresignedGetCompatibilityCheckID string

const (
	PresignedGetCompatibilityCheckConfiguration                PresignedGetCompatibilityCheckID = "configuration"
	PresignedGetCompatibilityCheckProbeObjectCreate            PresignedGetCompatibilityCheckID = "probe-object-create"
	PresignedGetCompatibilityCheckExactGetPresign              PresignedGetCompatibilityCheckID = "exact-get-presign"
	PresignedGetCompatibilityCheckAnonymousHeaders             PresignedGetCompatibilityCheckID = "anonymous-request-headers"
	PresignedGetCompatibilityCheckInitialGet                   PresignedGetCompatibilityCheckID = "anonymous-initial-get"
	PresignedGetCompatibilityCheckSameURLReplacement           PresignedGetCompatibilityCheckID = "same-url-replacement-visibility"
	PresignedGetCompatibilityCheckCurrentETagConditional       PresignedGetCompatibilityCheckID = "current-etag-not-modified"
	PresignedGetCompatibilityCheckStaleETagConditional         PresignedGetCompatibilityCheckID = "stale-etag-current-object"
	PresignedGetCompatibilityCheckAuthorizationQueryBinding    PresignedGetCompatibilityCheckID = "get-bearer-authorization-query-mutation-rejected"
	PresignedGetCompatibilityCheckAnonymousPolicyRejected      PresignedGetCompatibilityCheckID = "unsigned-anonymous-get-put-delete-rejected-unchanged"
	PresignedGetCompatibilityCheckNamedUnsignedHeaderOverrides PresignedGetCompatibilityCheckID = "named-unsigned-header-overrides-confined"
	PresignedGetCompatibilityCheckExactPathBinding             PresignedGetCompatibilityCheckID = "exact-key-path-binding"
	PresignedGetCompatibilityCheckHEADMutationRejected         PresignedGetCompatibilityCheckID = "get-bearer-head-mutation-rejected"
	PresignedGetCompatibilityCheckPUTRejectedUnchanged         PresignedGetCompatibilityCheckID = "get-bearer-put-rejected-unchanged"

	// Deprecated: use PresignedGetCompatibilityCheckHEADMutationRejected. The
	// finite probe samples HEAD specifically; it does not prove rejection of
	// every possible HTTP method.
	PresignedGetCompatibilityCheckGETMethodBinding = PresignedGetCompatibilityCheckHEADMutationRejected
	// Deprecated: use PresignedGetCompatibilityCheckPUTRejectedUnchanged.
	PresignedGetCompatibilityCheckZeroBytePUTRejectedUnchanged = PresignedGetCompatibilityCheckPUTRejectedUnchanged
	// Deprecated: use PresignedGetCompatibilityCheckPUTRejectedUnchanged.
	PresignedGetCompatibilityCheckNoWriteMethodBinding = PresignedGetCompatibilityCheckPUTRejectedUnchanged
)

// PresignedGetCompatibilityReason is a stable, redacted explanation.
type PresignedGetCompatibilityReason string

const (
	PresignedGetCompatibilityReasonSemanticViolation    PresignedGetCompatibilityReason = "semantic_violation"
	PresignedGetCompatibilityReasonOperationUnsupported PresignedGetCompatibilityReason = "operation_unsupported"
	PresignedGetCompatibilityReasonInvalidConfiguration PresignedGetCompatibilityReason = "invalid_configuration"
	PresignedGetCompatibilityReasonAccessDenied         PresignedGetCompatibilityReason = "access_denied"
	PresignedGetCompatibilityReasonRateLimited          PresignedGetCompatibilityReason = "rate_limited"
	PresignedGetCompatibilityReasonStoreUnavailable     PresignedGetCompatibilityReason = "store_unavailable"
	PresignedGetCompatibilityReasonCanceled             PresignedGetCompatibilityReason = "canceled"
	PresignedGetCompatibilityReasonDeadlineExceeded     PresignedGetCompatibilityReason = "deadline_exceeded"
	PresignedGetCompatibilityReasonNetworkError         PresignedGetCompatibilityReason = "network_error"
	PresignedGetCompatibilityReasonLocalProbeFailure    PresignedGetCompatibilityReason = "local_probe_failure"
	PresignedGetCompatibilityReasonUnknownOperational   PresignedGetCompatibilityReason = "unknown_operational_error"
)

// PresignedGetCompatibilityProbeOptions controls destructive commissioning.
// ObjectKeyPrefix identifies a private namespace where two random exact keys
// may briefly be created. Reports never include the prefix or generated keys.
// HTTPClient is used only as a source of bounded timeout, connection-pool, and
// TLS-version settings for anonymous B-side requests, including unsigned
// policy controls, named override-header controls, HEAD, and zero-byte plus
// non-empty PUT mutations. The probe constructs a new direct transport; the
// client's cookie jar and redirect policy are not used.
// Only nil or an unextended *http.Transport is accepted. Custom RoundTrippers,
// proxies, dialers, protocol selectors, TLS identities/callbacks/algorithms,
// cookies, and redirects are rejected or removed so they cannot forge
// commissioning evidence. TLSRootCAPEM is the strict trust-root input: it must
// contain only headerless CERTIFICATE PEM blocks with complete line boundaries
// and ASCII whitespace between blocks. It is bounded, parsed, and copied into a
// callback-free private pool. HTTPS probes require it by default because some
// operating-system trust implementations can fetch AIA or revocation data
// outside the locked S3 transport.
type PresignedGetCompatibilityProbeOptions struct {
	ObjectKeyPrefix    string
	TotalTimeout       time.Duration
	CapabilityLifetime time.Duration
	CleanupTimeout     time.Duration
	TLSRootCAPEM       []byte
	HTTPClient         *http.Client
	// DangerouslyAllowSystemTrustStore permits an HTTPS probe without
	// TLSRootCAPEM. On some platforms certificate evaluation may then perform
	// network I/O outside the probe's locked S3 dialer, invalidating strict
	// only-S3 evidence. The report retains an explicit limitation when enabled.
	DangerouslyAllowSystemTrustStore bool
}

// PresignedGetCompatibilityCheck records one completed assertion. Cause is a
// redacted classification, excluded from JSON and ordinary diagnostics.
type PresignedGetCompatibilityCheck struct {
	ID      PresignedGetCompatibilityCheckID `json:"id"`
	Status  PresignedGetCompatibilityStatus  `json:"status"`
	Reason  PresignedGetCompatibilityReason  `json:"reason,omitempty"`
	Summary string                           `json:"summary"`
	Detail  string                           `json:"detail,omitempty"`
	Cause   error                            `json:"-"`
}

func (check PresignedGetCompatibilityCheck) String() string {
	encoded, err := json.Marshal(check)
	if err != nil {
		return "s3store.PresignedGetCompatibilityCheck{redacted}"
	}
	return "s3store.PresignedGetCompatibilityCheck(" + string(encoded) + ")"
}

func (check PresignedGetCompatibilityCheck) GoString() string { return check.String() }

// PresignedGetCompatibilityCleanupStatus describes removal of probe objects.
type PresignedGetCompatibilityCleanupStatus string

const (
	PresignedGetCompatibilityCleanupNotAttempted PresignedGetCompatibilityCleanupStatus = "not_attempted"
	PresignedGetCompatibilityCleanupSucceeded    PresignedGetCompatibilityCleanupStatus = "succeeded"
	PresignedGetCompatibilityCleanupFailed       PresignedGetCompatibilityCleanupStatus = "failed"
)

// PresignedGetCompatibilityCleanupReport is separate from compatibility: a
// cleanup failure cannot turn a semantic pass into an incompatibility. Current
// absence cannot prove historical versions or delete markers were purged.
type PresignedGetCompatibilityCleanupReport struct {
	Status                      PresignedGetCompatibilityCleanupStatus `json:"status"`
	Reason                      PresignedGetCompatibilityReason        `json:"reason,omitempty"`
	Detail                      string                                 `json:"detail,omitempty"`
	Attempted                   int                                    `json:"attempted"`
	Succeeded                   int                                    `json:"succeeded"`
	Failed                      int                                    `json:"failed"`
	CurrentObjectsMayRemain     bool                                   `json:"current_objects_may_remain"`
	HistoricalVersionsMayRemain bool                                   `json:"historical_versions_may_remain"`
	Cause                       error                                  `json:"-"`
}

func (cleanup PresignedGetCompatibilityCleanupReport) String() string {
	encoded, err := json.Marshal(cleanup)
	if err != nil {
		return "s3store.PresignedGetCompatibilityCleanupReport{redacted}"
	}
	return "s3store.PresignedGetCompatibilityCleanupReport(" + string(encoded) + ")"
}

func (cleanup PresignedGetCompatibilityCleanupReport) GoString() string { return cleanup.String() }

// PresignedGetCompatibilityPresigningTopology records whether the writer and
// exact-GET presigner were configured through the same Store instance or two
// separate Store instances. Separate instances do not by themselves prove
// distinct IAM principals or least-privilege policies.
type PresignedGetCompatibilityPresigningTopology string

const (
	PresignedGetCompatibilitySameStore     PresignedGetCompatibilityPresigningTopology = "same_store"
	PresignedGetCompatibilitySeparateStore PresignedGetCompatibilityPresigningTopology = "separate_store"
)

// PresignedGetCompatibilityEvidence describes the Store inputs sampled by the
// finite probe. CrossConfigurationCanaryBindingObserved is true only when a
// split-store probe completes all checks: the writer then created, replaced,
// and read back the canaries while bearers issued by the separate presigning
// Store observed the exact bytes and versions. Cleanup remains separate
// operational evidence. This is still not an authenticated statement about
// credential identity or IAM policy.
type PresignedGetCompatibilityEvidence struct {
	PresigningTopology                      PresignedGetCompatibilityPresigningTopology `json:"presigning_topology,omitempty"`
	PresigningStoreInputDistinct            bool                                        `json:"presigning_store_input_distinct"`
	CrossConfigurationCanaryBindingObserved bool                                        `json:"cross_configuration_canary_binding_observed"`
}

// PresignedGetCompatibilityReport is a fail-fast commissioning result for the
// no-credential reader path. Compatible only means all finite checks passed at
// the sampled endpoint configuration or configuration pair during this
// invocation.
type PresignedGetCompatibilityReport struct {
	Scope          PresignedGetCompatibilityScope         `json:"scope"`
	Evidence       PresignedGetCompatibilityEvidence      `json:"evidence"`
	Status         PresignedGetCompatibilityStatus        `json:"status"`
	Compatible     bool                                   `json:"compatible"`
	Complete       bool                                   `json:"complete"`
	RequiredChecks int                                    `json:"required_checks"`
	Checks         []PresignedGetCompatibilityCheck       `json:"checks"`
	Limitations    []PresignedGetCompatibilityLimitation  `json:"limitations"`
	Cleanup        PresignedGetCompatibilityCleanupReport `json:"cleanup"`
}

func (report PresignedGetCompatibilityReport) String() string {
	encoded, err := json.Marshal(report)
	if err != nil {
		return "s3store.PresignedGetCompatibilityReport{redacted}"
	}
	return "s3store.PresignedGetCompatibilityReport(" + string(encoded) + ")"
}

func (report PresignedGetCompatibilityReport) GoString() string { return report.String() }

// PresignedGetCompatibilityError identifies the failed or inconclusive check.
// Error deliberately omits the underlying provider/transport error because it
// may contain the bearer URL. Cause retains only a safe classification.
type PresignedGetCompatibilityError struct {
	CheckID PresignedGetCompatibilityCheckID
	Status  PresignedGetCompatibilityStatus
	Reason  PresignedGetCompatibilityReason
	Detail  string
	Cause   error
}

func (probeErr *PresignedGetCompatibilityError) Error() string {
	if probeErr == nil {
		return "<nil>"
	}
	message := fmt.Sprintf("s3store: presigned GET compatibility check %q %s", probeErr.CheckID, probeErr.Status)
	if probeErr.Reason != "" {
		message += " (" + string(probeErr.Reason) + ")"
	}
	if probeErr.Detail != "" {
		message += ": " + probeErr.Detail
	}
	return message
}

func (probeErr *PresignedGetCompatibilityError) Unwrap() error {
	if probeErr == nil {
		return nil
	}
	return probeErr.Cause
}

func (probeErr *PresignedGetCompatibilityError) Is(target error) bool {
	return probeErr != nil && target == s3disk.ErrStoreIncompatible && probeErr.Status == PresignedGetCompatibilityIncompatible
}

func (probeErr *PresignedGetCompatibilityError) GoString() string { return probeErr.Error() }

// ProbePresignedGetCompatibility runs the probe with production-safe defaults.
func (store *Store) ProbePresignedGetCompatibility(ctx context.Context) (PresignedGetCompatibilityReport, error) {
	return store.ProbePresignedGetCompatibilityWithOptions(ctx, PresignedGetCompatibilityProbeOptions{})
}

// ProbePresignedGetCompatibilityWithPresigningStore runs the finite anonymous
// GET probe with separate writer and presigning Store instances. The receiver
// performs every credentialed canary operation and cleanup. presigningStore is
// used only to freeze credentials and create exact-key GET bearers; its
// credentialed data-plane client is never called.
//
// The two Stores must be independently constructed, use different SDK client
// instances, and name the same bucket. Their endpoints may differ so an A-side
// private route and the B-side public bearer route can be commissioned
// together. A successful report samples their current cross-route canary
// binding, but cannot prove distinct credential identities or least-privilege
// IAM policy.
func (store *Store) ProbePresignedGetCompatibilityWithPresigningStore(
	ctx context.Context,
	presigningStore *Store,
	options PresignedGetCompatibilityProbeOptions,
) (PresignedGetCompatibilityReport, error) {
	return store.probePresignedGetCompatibility(ctx, presigningStore, options, true)
}

// ProbePresignedGetCompatibilityWithOptions verifies the runtime assumptions
// required by a credential-free reader: anonymous exact-key presigned GET,
// replacement visibility through one fixed URL, dynamic If-None-Match, one
// same-context expiry-query mutation, unsigned GET/PUT/DELETE policy controls,
// eleven named method/path override headers, URI path, HEAD, and zero-byte plus
// non-empty PUT behavior. Negative samples are bracketed by independently
// valid exact GETs. Exact credentialed read-backs verify both sampled objects'
// bytes and complete versions around side-effect-capable controls. A-side
// writes, read-back, and cleanup use Store credentials; every B-side request goes directly to the
// presigned S3 URL and carries no Authorization, Proxy-Authorization, or Cookie
// header. The report explicitly states that post-expiry service rejection is
// not sampled: waiting out a share lifetime is unsuitable for a bounded
// commissioning call.
func (store *Store) ProbePresignedGetCompatibilityWithOptions(
	ctx context.Context,
	options PresignedGetCompatibilityProbeOptions,
) (report PresignedGetCompatibilityReport, resultErr error) {
	return store.probePresignedGetCompatibility(ctx, store, options, false)
}

func (store *Store) probePresignedGetCompatibility(
	ctx context.Context,
	presigningStore *Store,
	options PresignedGetCompatibilityProbeOptions,
	requireSeparateStore bool,
) (report PresignedGetCompatibilityReport, resultErr error) {
	evidence := newPresignedGetCompatibilityEvidence(store, presigningStore)
	report = newPresignedGetCompatibilityReport(evidence)
	recorder := presignedGetCompatibilityRecorder{report: &report}
	if ctx == nil || interfaceIsNil(ctx) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckConfiguration,
			PresignedGetCompatibilityConfigurationError,
			PresignedGetCompatibilityReasonInvalidConfiguration,
			"probe context is nil", nil,
		)
	}
	normalized, client, err := normalizePresignedGetProbeOptions(options)
	if err != nil {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckConfiguration,
			PresignedGetCompatibilityConfigurationError,
			PresignedGetCompatibilityReasonInvalidConfiguration,
			"probe options are invalid", err,
		)
	}
	if normalized.DangerouslyAllowSystemTrustStore {
		report.Limitations = append(report.Limitations, PresignedGetCompatibilityLimitationSystemTrustNetworkIO)
	}
	if err := validatePresignedGetStorePair(store, presigningStore, requireSeparateStore); err != nil {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckConfiguration,
			PresignedGetCompatibilityConfigurationError,
			PresignedGetCompatibilityReasonInvalidConfiguration,
			"writer and presigning S3 Store configuration is invalid", err,
		)
	}
	if presigningStore.presignedHTTPS && len(options.TLSRootCAPEM) == 0 && !normalized.DangerouslyAllowSystemTrustStore {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckConfiguration,
			PresignedGetCompatibilityConfigurationError,
			PresignedGetCompatibilityReasonInvalidConfiguration,
			"HTTPS B-side commissioning requires explicit TLSRootCAPEM for strict only-S3 verification", nil,
		)
	}
	probeCtx, cancel := context.WithTimeout(ctx, normalized.TotalTimeout)
	defer cancel()
	if err := probeCtx.Err(); err != nil {
		status, reason := presignedGetFailureClassification(err)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckConfiguration, status, reason,
			"probe context ended before I/O", err,
		)
	}
	recorder.pass(PresignedGetCompatibilityCheckConfiguration, "validated finite destructive probe configuration")

	sourceKey, targetKey, nonce, err := newPresignedGetProbeKeys(normalized.ObjectKeyPrefix)
	if err != nil {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckProbeObjectCreate,
			PresignedGetCompatibilityIndeterminate,
			PresignedGetCompatibilityReasonLocalProbeFailure,
			"could not generate private random probe keys", nil,
		)
	}
	v1 := []byte("s3disk-presigned-get-v1:" + nonce)
	v2 := []byte("s3disk-presigned-get-v2:" + nonce)
	target := []byte("s3disk-presigned-get-target:" + nonce)
	cleanupCandidates := make([]presignedGetProbeCleanupCandidate, 0, 2)
	defer func() {
		report.Cleanup = cleanupPresignedGetProbe(store, cleanupCandidates, normalized.CleanupTimeout)
	}()

	cleanupCandidates = append(cleanupCandidates, presignedGetProbeCleanupCandidate{key: sourceKey})
	sourceCandidate := len(cleanupCandidates) - 1
	version1, err := store.PutIfAbsent(probeCtx, sourceKey, v1)
	if err != nil {
		version1, err = reconcilePresignedGetProbeCreate(probeCtx, store, sourceKey, v1, err)
	}
	if err != nil {
		status, reason := presignedGetFailureClassification(err)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckProbeObjectCreate, status, reason,
			"credentialed A-side source object creation failed", err,
		)
	}
	cleanupCandidates[sourceCandidate].owned = true
	cleanupCandidates = append(cleanupCandidates, presignedGetProbeCleanupCandidate{key: targetKey})
	targetCandidate := len(cleanupCandidates) - 1
	targetVersion, err := store.PutIfAbsent(probeCtx, targetKey, target)
	if err != nil {
		targetVersion, err = reconcilePresignedGetProbeCreate(probeCtx, store, targetKey, target, err)
	}
	if err != nil {
		status, reason := presignedGetFailureClassification(err)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckProbeObjectCreate, status, reason,
			"credentialed A-side path-binding target creation failed", err,
		)
	}
	cleanupCandidates[targetCandidate].owned = true
	recorder.pass(PresignedGetCompatibilityCheckProbeObjectCreate, "created two isolated random exact-key probe objects")

	fullExpiry := time.Now().Add(normalized.CapabilityLifetime)
	session, err := presigningStore.NewPresignSession(probeCtx, fullExpiry)
	if err != nil {
		status, reason := presignedGetFailureClassification(err)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactGetPresign, status, reason,
			"could not issue one fixed-lifetime exact-key GET capability", err,
		)
	}
	capability, err := session.PresignGet(probeCtx, sourceKey)
	if err != nil {
		status, reason := presignedGetFailureClassification(err)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactGetPresign, status, reason,
			"exact-key GET presigning failed", err,
		)
	}
	bearer, err := exportPresignedGetProbeBearer(capability)
	if err != nil {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactGetPresign,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"presigner produced an unusable exact-key bearer", err,
		)
	}
	targetCapability, err := session.PresignGet(probeCtx, targetKey)
	if err != nil {
		status, reason := presignedGetFailureClassification(err)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactGetPresign, status, reason,
			"second exact-key GET presigning failed", err,
		)
	}
	targetBearer, err := exportPresignedGetProbeBearer(targetCapability)
	if err != nil {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactGetPresign,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"presigner produced an unusable second exact-key bearer", err,
		)
	}
	shortQuerySession, err := session.withExpiry(session.expiresAt.Add(-time.Second))
	if err != nil {
		status, reason := presignedGetFailureClassification(err)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactGetPresign, status, reason,
			"could not issue the shorter query-binding control capability", err,
		)
	}
	shortQueryCapability, err := shortQuerySession.PresignGet(probeCtx, sourceKey)
	if err != nil {
		status, reason := presignedGetFailureClassification(err)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactGetPresign, status, reason,
			"shorter query-binding control presigning failed", err,
		)
	}
	shortQueryBearer, err := exportPresignedGetProbeBearer(shortQueryCapability)
	if err != nil {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactGetPresign,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"presigner produced an unusable query-binding control bearer", err,
		)
	}
	recorder.pass(PresignedGetCompatibilityCheckExactGetPresign, "issued two exact-key bearers and one shorter query-binding control bearer")
	defer func() {
		for _, candidate := range []*presignedGetProbeBearer{&bearer, &targetBearer, &shortQueryBearer} {
			candidate.URL = ""
			for name := range candidate.Headers {
				candidate.Headers.Del(name)
			}
		}
	}()

	if err := validatePresignedGetProbeAnonymousHeaders(bearer.Headers); err != nil {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAnonymousHeaders,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"B-side request would carry a long-lived credential header", err,
		)
	}
	if err := validatePresignedGetProbeAnonymousHeaders(targetBearer.Headers); err != nil {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAnonymousHeaders,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"second B-side request would carry a long-lived credential header", err,
		)
	}
	if err := validatePresignedGetProbeAnonymousHeaders(shortQueryBearer.Headers); err != nil {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAnonymousHeaders,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"query-binding control request would carry a long-lived credential header", err,
		)
	}
	recorder.pass(PresignedGetCompatibilityCheckAnonymousHeaders, "all requests use query bearer authority and no credential or cookie header")
	sourceAuthority, err := newPresignedGetProbeAuthorityFingerprint(bearer, targetBearer, sourceKey)
	if err != nil {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckInitialGet,
			PresignedGetCompatibilityIndeterminate,
			PresignedGetCompatibilityReasonLocalProbeFailure,
			"could not derive the source bearer authority fingerprint", nil,
		)
	}
	targetAuthority, err := newPresignedGetProbeAuthorityFingerprint(targetBearer, bearer, targetKey)
	if err != nil {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckInitialGet,
			PresignedGetCompatibilityIndeterminate,
			PresignedGetCompatibilityReasonLocalProbeFailure,
			"could not derive the target bearer authority fingerprint", nil,
		)
	}
	defer func() {
		for index := range sourceAuthority.authorityValues {
			sourceAuthority.authorityValues[index] = ""
		}
		for index := range sourceAuthority.pathValues {
			sourceAuthority.pathValues[index] = ""
		}
		for index := range targetAuthority.authorityValues {
			targetAuthority.authorityValues[index] = ""
		}
		for index := range targetAuthority.pathValues {
			targetAuthority.pathValues[index] = ""
		}
	}()

	first, err := doPresignedGetProbeRequest(probeCtx, client, bearer.URL, bearer.Headers, "")
	if err != nil {
		status, reason := presignedGetFailureClassification(err)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckInitialGet, status, reason,
			"anonymous exact-key GET did not complete", err,
		)
	}
	if first.StatusCode != http.StatusOK {
		status, reason := presignedGetHTTPFailureClassification(first.StatusCode)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckInitialGet, status, reason,
			fmt.Sprintf("anonymous exact-key GET returned HTTP %d", first.StatusCode), nil,
		)
	}
	if probeSuccessfulResponseDisclosesOtherObject(first, version1, target, targetVersion) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckInitialGet,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"anonymous source GET disclosed the independently sampled target object", nil,
		)
	}
	if probeResponseDisclosesAuthority(first, targetAuthority, true) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckInitialGet,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"anonymous source GET disclosed the independently sampled target bearer authority", nil,
		)
	}
	if !equalProbeBytes(first.Body, v1) || first.ETag != version1.ETag || first.VersionID != version1.VersionID {
		detail := "anonymous GET did not return the current complete object and version"
		switch {
		case !equalProbeBytes(first.Body, v1):
			detail = fmt.Sprintf("anonymous GET returned %d bytes instead of the expected %d bytes", len(first.Body), len(v1))
		case first.ETag != version1.ETag:
			detail = "anonymous GET ETag did not match the credentialed create version"
		case first.VersionID != version1.VersionID:
			detail = "anonymous GET version ID did not match the credentialed create version"
		}
		return report, recorder.problem(
			PresignedGetCompatibilityCheckInitialGet,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			detail, nil,
		)
	}
	recorder.pass(PresignedGetCompatibilityCheckInitialGet, "anonymous GET returned v1 and a non-empty ETag")

	version2, err := store.CompareAndSwap(probeCtx, sourceKey, &version1, v2)
	if err != nil {
		status, reason := presignedGetFailureClassification(err)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckSameURLReplacement, status, reason,
			"credentialed A-side replacement failed", err,
		)
	}
	second, err := doPresignedGetProbeRequest(probeCtx, client, bearer.URL, bearer.Headers, "")
	if err != nil {
		status, reason := presignedGetFailureClassification(err)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckSameURLReplacement, status, reason,
			"same-URL anonymous GET after replacement did not complete", err,
		)
	}
	if probeSuccessfulResponseDisclosesOtherObject(second, version2, target, targetVersion) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckSameURLReplacement,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"same-URL source GET disclosed the independently sampled target object", nil,
		)
	}
	if probeResponseDisclosesAuthority(second, targetAuthority, true) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckSameURLReplacement,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"same-URL source GET disclosed the independently sampled target bearer authority", nil,
		)
	}
	if second.StatusCode != http.StatusOK || !equalProbeBytes(second.Body, v2) ||
		second.ETag != version2.ETag || second.VersionID != version2.VersionID || second.ETag == first.ETag {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckSameURLReplacement,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"the fixed presigned URL did not expose v2 with a changed ETag after A-side replacement", nil,
		)
	}
	recorder.pass(PresignedGetCompatibilityCheckSameURLReplacement, "the same fixed URL exposed v2 with a changed ETag")

	currentConditional, err := doPresignedGetProbeRequest(probeCtx, client, bearer.URL, bearer.Headers, second.ETag)
	if err != nil {
		status, reason := presignedGetFailureClassification(err)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckCurrentETagConditional, status, reason,
			"current-ETag conditional GET did not complete", err,
		)
	}
	if probeSuccessfulResponseDisclosesOtherObject(currentConditional, version2, target, targetVersion) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckCurrentETagConditional,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"current-ETag source response disclosed the independently sampled target object", nil,
		)
	}
	if probeResponseDisclosesAuthority(currentConditional, targetAuthority, true) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckCurrentETagConditional,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"current-ETag source response disclosed the independently sampled target bearer authority", nil,
		)
	}
	if currentConditional.StatusCode != http.StatusNotModified || len(currentConditional.Body) != 0 {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckCurrentETagConditional,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"If-None-Match with the current ETag did not return bodyless HTTP 304", nil,
		)
	}
	recorder.pass(PresignedGetCompatibilityCheckCurrentETagConditional, "current ETag returned bodyless HTTP 304")

	staleConditional, err := doPresignedGetProbeRequest(probeCtx, client, bearer.URL, bearer.Headers, first.ETag)
	if err != nil {
		status, reason := presignedGetFailureClassification(err)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckStaleETagConditional, status, reason,
			"stale-ETag conditional GET did not complete", err,
		)
	}
	if probeSuccessfulResponseDisclosesOtherObject(staleConditional, version2, target, targetVersion) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckStaleETagConditional,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"stale-ETag source response disclosed the independently sampled target object", nil,
		)
	}
	if probeResponseDisclosesAuthority(staleConditional, targetAuthority, true) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckStaleETagConditional,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"stale-ETag source response disclosed the independently sampled target bearer authority", nil,
		)
	}
	if staleConditional.StatusCode != http.StatusOK || !equalProbeBytes(staleConditional.Body, v2) ||
		staleConditional.ETag != second.ETag || staleConditional.VersionID != second.VersionID {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckStaleETagConditional,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"If-None-Match with the stale ETag did not return current v2", nil,
		)
	}
	recorder.pass(PresignedGetCompatibilityCheckStaleETagConditional, "stale ETag returned current v2 and its ETag")

	if !reflect.DeepEqual(shortQueryBearer.Headers, bearer.Headers) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAuthorizationQueryBinding,
			PresignedGetCompatibilityIndeterminate,
			PresignedGetCompatibilityReasonLocalProbeFailure,
			"query-binding control bearers did not share identical signed headers", nil,
		)
	}
	shortQueryObserved, err := doPresignedGetProbeRequest(probeCtx, client, shortQueryBearer.URL, shortQueryBearer.Headers, "")
	if err != nil {
		status, reason := presignedGetFailureClassification(err)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAuthorizationQueryBinding, status, reason,
			"shorter correctly signed query-binding control did not complete", err,
		)
	}
	if probeSuccessfulResponseDisclosesOtherObject(shortQueryObserved, version2, target, targetVersion) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAuthorizationQueryBinding,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"shorter source control GET disclosed the independently sampled target object", nil,
		)
	}
	if probeResponseDisclosesAuthority(shortQueryObserved, targetAuthority, true) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAuthorizationQueryBinding,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"shorter source control GET disclosed the independently sampled target bearer authority", nil,
		)
	}
	if shortQueryObserved.StatusCode != http.StatusOK || !equalProbeBytes(shortQueryObserved.Body, v2) ||
		shortQueryObserved.ETag != version2.ETag || shortQueryObserved.VersionID != version2.VersionID {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAuthorizationQueryBinding,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"shorter correctly signed query-binding control did not return the current sampled object", nil,
		)
	}
	queryMutatedURL, err := mutatePresignedGetProbeAuthorizationQuery(shortQueryBearer.URL, bearer.URL)
	if err != nil {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAuthorizationQueryBinding,
			PresignedGetCompatibilityIndeterminate,
			PresignedGetCompatibilityReasonLocalProbeFailure,
			"could not construct a bounded authorization-query mutation", nil,
		)
	}
	queryMutated, err := doPresignedGetProbeRequest(probeCtx, client, queryMutatedURL, shortQueryBearer.Headers, "")
	if err != nil {
		status, reason := presignedGetFailureClassification(err)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAuthorizationQueryBinding, status, reason,
			"authorization-query-mutated anonymous request did not complete", err,
		)
	}
	if queryMutated.StatusCode >= 200 && queryMutated.StatusCode < 300 {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAuthorizationQueryBinding,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"the exact GET bearer remained authorized after its signed expiry query was changed", nil,
		)
	}
	if !presignedGetAuthorizationQueryMutationRejectionStatus(queryMutated.StatusCode) {
		status, reason := presignedGetHTTPFailureClassification(queryMutated.StatusCode)
		if queryMutated.StatusCode >= 400 && queryMutated.StatusCode < 500 && status == PresignedGetCompatibilityIncompatible {
			status = PresignedGetCompatibilityIndeterminate
			reason = PresignedGetCompatibilityReasonUnknownOperational
		}
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAuthorizationQueryBinding, status, reason,
			fmt.Sprintf("authorization-query mutation returned inconclusive HTTP %d", queryMutated.StatusCode), nil,
		)
	}
	if presignedGetProbeResponseHasUnsupportedEncoding(queryMutated) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAuthorizationQueryBinding,
			PresignedGetCompatibilityIndeterminate,
			PresignedGetCompatibilityReasonUnknownOperational,
			"rejected authorization-query mutation used an encoded response that could not be inspected safely", nil,
		)
	}
	if probeResponseDisclosesObject(queryMutated, v2, version2) ||
		probeResponseDisclosesObject(queryMutated, target, targetVersion) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAuthorizationQueryBinding,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"rejected authorization-query mutation disclosed sampled object bytes or version", nil,
		)
	}
	if probeResponseDisclosesAuthority(queryMutated, targetAuthority, true) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAuthorizationQueryBinding,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"rejected authorization-query mutation disclosed the independently sampled target bearer authority", nil,
		)
	}
	targetAfterQuery, targetAfterQueryErr := store.Get(
		probeCtx, targetKey, s3disk.GetOptions{MaxBytes: maximumPresignedGetProbeResponseBytes},
	)
	if targetAfterQueryErr != nil {
		status, reason := presignedGetFailureClassification(targetAfterQueryErr)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAuthorizationQueryBinding, status, reason,
			"credentialed target read-back could not verify the second canary after the authorization-query sample", targetAfterQueryErr,
		)
	}
	if !equalProbeBytes(targetAfterQuery.Data, target) || targetAfterQuery.Version != targetVersion {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAuthorizationQueryBinding,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"the sampled target bytes or version changed during the authorization-query check", nil,
		)
	}
	if status, reason, disclosedOtherObject, cause := revalidatePresignedGetProbeExactGET(
		probeCtx, client, shortQueryBearer, v2, version2, target, targetVersion, targetAuthority,
	); status != PresignedGetCompatibilityPassed {
		detail := "the shorter exact GET bearer was not live immediately after the authorization-query sample"
		if disclosedOtherObject {
			detail = "the revalidated shorter source bearer disclosed the independently sampled target object or bearer authority"
		}
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAuthorizationQueryBinding, status, reason,
			detail, cause,
		)
	}
	if status, reason, disclosedOtherObject, cause := revalidatePresignedGetProbeExactGET(
		probeCtx, client, bearer, v2, version2, target, targetVersion, targetAuthority,
	); status != PresignedGetCompatibilityPassed {
		detail := "the longer exact GET control bearer was not live immediately after the authorization-query sample"
		if disclosedOtherObject {
			detail = "the revalidated longer source bearer disclosed the independently sampled target object or bearer authority"
		}
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAuthorizationQueryBinding, status, reason,
			detail, cause,
		)
	}
	recorder.pass(PresignedGetCompatibilityCheckAuthorizationQueryBinding, "a valid longer expiry value was rejected under the shorter bearer's signature while both controls stayed live")

	targetObserved, err := doPresignedGetProbeRequest(probeCtx, client, targetBearer.URL, targetBearer.Headers, "")
	if err != nil {
		status, reason := presignedGetFailureClassification(err)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactPathBinding, status, reason,
			"the correct target-key bearer did not complete before the path-mutation sample", err,
		)
	}
	if probeSuccessfulResponseDisclosesOtherObject(targetObserved, targetVersion, v2, version2) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactPathBinding,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"correct target-key GET disclosed the independently sampled source object", nil,
		)
	}
	if probeResponseDisclosesAuthority(targetObserved, sourceAuthority, true) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactPathBinding,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"correct target-key GET disclosed the independently sampled source bearer authority", nil,
		)
	}
	if targetObserved.StatusCode != http.StatusOK || !equalProbeBytes(targetObserved.Body, target) ||
		targetObserved.ETag != targetVersion.ETag || targetObserved.VersionID != targetVersion.VersionID {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactPathBinding,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"the correct target-key bearer did not return the sampled target bytes and version", nil,
		)
	}
	unsignedSource, err := stripPresignedGetProbeAuthority(bearer)
	if err != nil {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAnonymousPolicyRejected,
			PresignedGetCompatibilityIndeterminate,
			PresignedGetCompatibilityReasonLocalProbeFailure,
			"could not construct the unsigned source policy controls", nil,
		)
	}
	unsignedTarget, err := stripPresignedGetProbeAuthority(targetBearer)
	if err != nil {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAnonymousPolicyRejected,
			PresignedGetCompatibilityIndeterminate,
			PresignedGetCompatibilityReasonLocalProbeFailure,
			"could not construct the unsigned target policy control", nil,
		)
	}
	defer func() {
		unsignedSource.URL = ""
		unsignedTarget.URL = ""
		for name := range unsignedSource.Headers {
			unsignedSource.Headers.Del(name)
		}
		for name := range unsignedTarget.Headers {
			unsignedTarget.Headers.Del(name)
		}
	}()
	unsignedPUTBody := []byte("s3disk-presigned-unsigned-put:" + nonce)
	unsignedPolicySamples := []struct {
		label           string
		method          string
		bearer          presignedGetProbeBearer
		body            []byte
		targetPathKnown bool
	}{
		{label: "source GET", method: http.MethodGet, bearer: unsignedSource},
		{label: "target GET", method: http.MethodGet, bearer: unsignedTarget, targetPathKnown: true},
		{label: "zero-byte source PUT", method: http.MethodPut, bearer: unsignedSource, body: []byte{}},
		{label: "non-empty source PUT", method: http.MethodPut, bearer: unsignedSource, body: unsignedPUTBody},
		{label: "source DELETE", method: http.MethodDelete, bearer: unsignedSource},
	}
	for _, sample := range unsignedPolicySamples {
		observed, sampleErr := doPresignedGetProbeRequestWithMethodAndBody(
			probeCtx, client, sample.method, sample.bearer.URL, sample.bearer.Headers, "", sample.body,
		)
		if sampleErr != nil {
			status, reason := presignedGetFailureClassification(sampleErr)
			return report, recorder.problem(
				PresignedGetCompatibilityCheckAnonymousPolicyRejected, status, reason,
				"an unsigned anonymous policy control did not complete", sampleErr,
			)
		}
		switch observed.StatusCode {
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		default:
			return report, recorder.problem(
				PresignedGetCompatibilityCheckAnonymousPolicyRejected,
				PresignedGetCompatibilityIncompatible,
				PresignedGetCompatibilityReasonSemanticViolation,
				fmt.Sprintf("unsigned anonymous %s returned HTTP %d instead of 400, 401, or 403", sample.label, observed.StatusCode), nil,
			)
		}
		if presignedGetProbeResponseHasUnsupportedEncoding(observed) {
			return report, recorder.problem(
				PresignedGetCompatibilityCheckAnonymousPolicyRejected,
				PresignedGetCompatibilityIndeterminate,
				PresignedGetCompatibilityReasonUnknownOperational,
				"an unsigned anonymous policy rejection used an encoded response that could not be inspected safely", nil,
			)
		}
		if probeResponseDisclosesAuthority(observed, sourceAuthority, sample.targetPathKnown) ||
			probeResponseDisclosesAuthority(observed, targetAuthority, !sample.targetPathKnown) {
			return report, recorder.problem(
				PresignedGetCompatibilityCheckAnonymousPolicyRejected,
				PresignedGetCompatibilityIncompatible,
				PresignedGetCompatibilityReasonSemanticViolation,
				"an unsigned anonymous policy response disclosed bearer authority absent from that request", nil,
			)
		}
		if probeResponseDisclosesObject(observed, v2, version2) ||
			probeResponseDisclosesObject(observed, target, targetVersion) {
			return report, recorder.problem(
				PresignedGetCompatibilityCheckAnonymousPolicyRejected,
				PresignedGetCompatibilityIncompatible,
				PresignedGetCompatibilityReasonSemanticViolation,
				"an unsigned anonymous policy rejection disclosed sampled object bytes or version", nil,
			)
		}
		sourceAfterUnsigned, sourceAfterUnsignedErr := store.Get(
			probeCtx, sourceKey, s3disk.GetOptions{MaxBytes: maximumPresignedGetProbeResponseBytes},
		)
		if sourceAfterUnsignedErr != nil {
			status, reason := presignedGetFailureClassification(sourceAfterUnsignedErr)
			return report, recorder.problem(
				PresignedGetCompatibilityCheckAnonymousPolicyRejected, status, reason,
				"credentialed source read-back could not verify the first canary after an unsigned policy control", sourceAfterUnsignedErr,
			)
		}
		if !equalProbeBytes(sourceAfterUnsigned.Data, v2) || sourceAfterUnsigned.Version != version2 {
			return report, recorder.problem(
				PresignedGetCompatibilityCheckAnonymousPolicyRejected,
				PresignedGetCompatibilityIncompatible,
				PresignedGetCompatibilityReasonSemanticViolation,
				"the sampled source bytes or version changed during an unsigned anonymous policy control", nil,
			)
		}
		targetAfterUnsigned, targetAfterUnsignedErr := store.Get(
			probeCtx, targetKey, s3disk.GetOptions{MaxBytes: maximumPresignedGetProbeResponseBytes},
		)
		if targetAfterUnsignedErr != nil {
			status, reason := presignedGetFailureClassification(targetAfterUnsignedErr)
			return report, recorder.problem(
				PresignedGetCompatibilityCheckAnonymousPolicyRejected, status, reason,
				"credentialed target read-back could not verify the second canary after an unsigned policy control", targetAfterUnsignedErr,
			)
		}
		if !equalProbeBytes(targetAfterUnsigned.Data, target) || targetAfterUnsigned.Version != targetVersion {
			return report, recorder.problem(
				PresignedGetCompatibilityCheckAnonymousPolicyRejected,
				PresignedGetCompatibilityIncompatible,
				PresignedGetCompatibilityReasonSemanticViolation,
				"the sampled target bytes or version changed during an unsigned anonymous policy control", nil,
			)
		}
	}
	if status, reason, disclosedOtherObject, cause := revalidatePresignedGetProbeExactGET(
		probeCtx, client, bearer, v2, version2, target, targetVersion, targetAuthority,
	); status != PresignedGetCompatibilityPassed {
		detail := "the source bearer was not live after the unsigned anonymous policy controls"
		if disclosedOtherObject {
			detail = "the revalidated source bearer disclosed the independently sampled target object or bearer authority"
		}
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAnonymousPolicyRejected, status, reason, detail, cause,
		)
	}
	if status, reason, disclosedOtherObject, cause := revalidatePresignedGetProbeExactGET(
		probeCtx, client, targetBearer, target, targetVersion, v2, version2, sourceAuthority,
	); status != PresignedGetCompatibilityPassed {
		detail := "the target bearer was not live after the unsigned anonymous policy controls"
		if disclosedOtherObject {
			detail = "the revalidated target bearer disclosed the independently sampled source object or bearer authority"
		}
		return report, recorder.problem(
			PresignedGetCompatibilityCheckAnonymousPolicyRejected, status, reason, detail, cause,
		)
	}
	recorder.pass(
		PresignedGetCompatibilityCheckAnonymousPolicyRejected,
		"unsigned source and target GET plus source zero-byte PUT, non-empty PUT, and DELETE were rejected while both canaries stayed unchanged",
	)
	targetUnsignedURL, err := url.Parse(unsignedTarget.URL)
	if err != nil || targetUnsignedURL.Host == "" || targetUnsignedURL.Fragment != "" {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckNamedUnsignedHeaderOverrides,
			PresignedGetCompatibilityIndeterminate,
			PresignedGetCompatibilityReasonLocalProbeFailure,
			"could not construct the named path-override controls", nil,
		)
	}
	overrideSamples := []struct {
		name            string
		value           string
		targetPathKnown bool
	}{
		{name: "X-HTTP-Method", value: http.MethodPut},
		{name: "X-HTTP-Method-Override", value: http.MethodPut},
		{name: "X-Method-Override", value: http.MethodPut},
		{name: "X-Original-Method", value: http.MethodPut},
		{name: "X-Rewrite-Method", value: http.MethodPut},
		{name: "X-Forwarded-Uri", value: targetUnsignedURL.RequestURI(), targetPathKnown: true},
		{name: "X-Forwarded-Url", value: unsignedTarget.URL, targetPathKnown: true},
		{name: "X-Original-Uri", value: targetUnsignedURL.RequestURI(), targetPathKnown: true},
		{name: "X-Original-Url", value: unsignedTarget.URL, targetPathKnown: true},
		{name: "X-Rewrite-Uri", value: targetUnsignedURL.RequestURI(), targetPathKnown: true},
		{name: "X-Rewrite-Url", value: unsignedTarget.URL, targetPathKnown: true},
	}
	for _, sample := range overrideSamples {
		overrideHeaders := bearer.Headers.Clone()
		overrideHeaders.Set(sample.name, sample.value)
		observed, sampleErr := doPresignedGetProbeRequest(
			probeCtx, client, bearer.URL, overrideHeaders, "",
		)
		for name := range overrideHeaders {
			overrideHeaders.Del(name)
		}
		if sampleErr != nil {
			status, reason := presignedGetFailureClassification(sampleErr)
			return report, recorder.problem(
				PresignedGetCompatibilityCheckNamedUnsignedHeaderOverrides, status, reason,
				"a named unsigned override-header control did not complete", sampleErr,
			)
		}
		if presignedGetProbeResponseHasUnsupportedEncoding(observed) {
			return report, recorder.problem(
				PresignedGetCompatibilityCheckNamedUnsignedHeaderOverrides,
				PresignedGetCompatibilityIndeterminate,
				PresignedGetCompatibilityReasonUnknownOperational,
				"a named unsigned override-header response used an encoding that could not be inspected safely", nil,
			)
		}
		if probeResponseDisclosesAuthority(observed, targetAuthority, !sample.targetPathKnown) {
			return report, recorder.problem(
				PresignedGetCompatibilityCheckNamedUnsignedHeaderOverrides,
				PresignedGetCompatibilityIncompatible,
				PresignedGetCompatibilityReasonSemanticViolation,
				"a named unsigned override-header response disclosed target bearer authority absent from the request", nil,
			)
		}
		switch observed.StatusCode {
		case http.StatusOK:
			if probeSuccessfulResponseDisclosesOtherObject(observed, version2, target, targetVersion) ||
				!equalProbeBytes(observed.Body, v2) || observed.ETag != version2.ETag || observed.VersionID != version2.VersionID {
				return report, recorder.problem(
					PresignedGetCompatibilityCheckNamedUnsignedHeaderOverrides,
					PresignedGetCompatibilityIncompatible,
					PresignedGetCompatibilityReasonSemanticViolation,
					"a named unsigned override header escaped the signed source GET", nil,
				)
			}
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
			if probeResponseDisclosesObject(observed, v2, version2) ||
				probeResponseDisclosesObject(observed, target, targetVersion) {
				return report, recorder.problem(
					PresignedGetCompatibilityCheckNamedUnsignedHeaderOverrides,
					PresignedGetCompatibilityIncompatible,
					PresignedGetCompatibilityReasonSemanticViolation,
					"a rejected named unsigned override header disclosed sampled object bytes or version", nil,
				)
			}
		default:
			return report, recorder.problem(
				PresignedGetCompatibilityCheckNamedUnsignedHeaderOverrides,
				PresignedGetCompatibilityIncompatible,
				PresignedGetCompatibilityReasonSemanticViolation,
				fmt.Sprintf("a named unsigned override-header control returned unsupported HTTP %d", observed.StatusCode), nil,
			)
		}
		sourceUnchanged, sourceCheckErr := credentialedPresignedGetProbeObjectUnchanged(
			probeCtx, store, sourceKey, v2, version2,
		)
		if sourceCheckErr != nil {
			status, reason := presignedGetFailureClassification(sourceCheckErr)
			return report, recorder.problem(
				PresignedGetCompatibilityCheckNamedUnsignedHeaderOverrides, status, reason,
				"credentialed source read-back failed after a named unsigned override-header control", sourceCheckErr,
			)
		}
		if !sourceUnchanged {
			return report, recorder.problem(
				PresignedGetCompatibilityCheckNamedUnsignedHeaderOverrides,
				PresignedGetCompatibilityIncompatible,
				PresignedGetCompatibilityReasonSemanticViolation,
				"the sampled source changed during a named unsigned override-header control", nil,
			)
		}
		targetUnchanged, targetCheckErr := credentialedPresignedGetProbeObjectUnchanged(
			probeCtx, store, targetKey, target, targetVersion,
		)
		if targetCheckErr != nil {
			status, reason := presignedGetFailureClassification(targetCheckErr)
			return report, recorder.problem(
				PresignedGetCompatibilityCheckNamedUnsignedHeaderOverrides, status, reason,
				"credentialed target read-back failed after a named unsigned override-header control", targetCheckErr,
			)
		}
		if !targetUnchanged {
			return report, recorder.problem(
				PresignedGetCompatibilityCheckNamedUnsignedHeaderOverrides,
				PresignedGetCompatibilityIncompatible,
				PresignedGetCompatibilityReasonSemanticViolation,
				"the sampled target changed during a named unsigned override-header control", nil,
			)
		}
		if status, reason, disclosedOtherObject, cause := revalidatePresignedGetProbeExactGET(
			probeCtx, client, bearer, v2, version2, target, targetVersion, targetAuthority,
		); status != PresignedGetCompatibilityPassed {
			detail := "the source bearer was not live after a named unsigned override-header control"
			if disclosedOtherObject {
				detail = "the revalidated source bearer disclosed the independently sampled target object or bearer authority"
			}
			return report, recorder.problem(
				PresignedGetCompatibilityCheckNamedUnsignedHeaderOverrides, status, reason, detail, cause,
			)
		}
		if status, reason, disclosedOtherObject, cause := revalidatePresignedGetProbeExactGET(
			probeCtx, client, targetBearer, target, targetVersion, v2, version2, sourceAuthority,
		); status != PresignedGetCompatibilityPassed {
			detail := "the target bearer was not live after a named unsigned override-header control"
			if disclosedOtherObject {
				detail = "the revalidated target bearer disclosed the independently sampled source object or bearer authority"
			}
			return report, recorder.problem(
				PresignedGetCompatibilityCheckNamedUnsignedHeaderOverrides, status, reason, detail, cause,
			)
		}
	}
	recorder.pass(
		PresignedGetCompatibilityCheckNamedUnsignedHeaderOverrides,
		"eleven named unsigned method and path override headers were rejected or ignored without escaping the source GET or changing either canary",
	)
	tamperedURL, err := replacePresignedGetProbePath(bearer.URL, targetBearer.URL, sourceKey, targetKey)
	if err != nil {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactPathBinding,
			PresignedGetCompatibilityIndeterminate,
			PresignedGetCompatibilityReasonLocalProbeFailure,
			"could not construct the exact target-key path mutation", nil,
		)
	}
	tampered, err := doPresignedGetProbeRequest(probeCtx, client, tamperedURL, bearer.Headers, "")
	if err != nil {
		status, reason := presignedGetFailureClassification(err)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactPathBinding, status, reason,
			"path-mutated anonymous request did not complete", err,
		)
	}
	if tampered.StatusCode >= 200 && tampered.StatusCode < 300 {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactPathBinding,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"one exact-key bearer successfully read a different existing key after path mutation", nil,
		)
	}
	if !presignedGetPathMutationRejectionStatus(tampered.StatusCode) {
		status, reason := presignedGetHTTPFailureClassification(tampered.StatusCode)
		if tampered.StatusCode >= 400 && tampered.StatusCode < 500 && status == PresignedGetCompatibilityIncompatible {
			status = PresignedGetCompatibilityIndeterminate
			reason = PresignedGetCompatibilityReasonUnknownOperational
		}
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactPathBinding, status, reason,
			fmt.Sprintf("path-mutated request returned inconclusive HTTP %d", tampered.StatusCode), nil,
		)
	}
	if presignedGetProbeResponseHasUnsupportedEncoding(tampered) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactPathBinding,
			PresignedGetCompatibilityIndeterminate,
			PresignedGetCompatibilityReasonUnknownOperational,
			"rejected path mutation used an encoded response that could not be inspected safely", nil,
		)
	}
	if probeResponseDisclosesObject(tampered, target, targetVersion) ||
		probeResponseDisclosesObject(tampered, v2, s3disk.Version{ETag: second.ETag, VersionID: second.VersionID}) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactPathBinding,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"rejected path mutation disclosed sampled object bytes or version", nil,
		)
	}
	if probeResponseDisclosesAuthority(tampered, targetAuthority, false) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactPathBinding,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"rejected path mutation disclosed target bearer authority not present in the mutated request", nil,
		)
	}
	targetReadBack, targetReadBackErr := store.Get(probeCtx, targetKey, s3disk.GetOptions{MaxBytes: maximumPresignedGetProbeResponseBytes})
	if targetReadBackErr != nil {
		status, reason := presignedGetFailureClassification(targetReadBackErr)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactPathBinding, status, reason,
			"credentialed exact read-back could not prove the target still existed after the path-mutation sample", targetReadBackErr,
		)
	}
	if !equalProbeBytes(targetReadBack.Data, target) || targetReadBack.Version != targetVersion {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactPathBinding,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"the sampled target bytes or version changed during the path-mutation check", nil,
		)
	}
	if status, reason, disclosedOtherObject, cause := revalidatePresignedGetProbeExactGET(
		probeCtx, client, targetBearer, target, targetVersion, v2, version2, sourceAuthority,
	); status != PresignedGetCompatibilityPassed {
		detail := "the correct target GET bearer was not live immediately after the path-mutation sample"
		if disclosedOtherObject {
			detail = "the revalidated target bearer disclosed the independently sampled source object or bearer authority"
		}
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactPathBinding, status, reason,
			detail, cause,
		)
	}
	if status, reason, disclosedOtherObject, cause := revalidatePresignedGetProbeExactGET(
		probeCtx, client, bearer, v2, version2, target, targetVersion, targetAuthority,
	); status != PresignedGetCompatibilityPassed {
		detail := "the original exact GET bearer was not live immediately after the path-mutation sample"
		if disclosedOtherObject {
			detail = "the revalidated source bearer disclosed the independently sampled target object or bearer authority"
		}
		return report, recorder.problem(
			PresignedGetCompatibilityCheckExactPathBinding, status, reason,
			detail, cause,
		)
	}
	recorder.pass(PresignedGetCompatibilityCheckExactPathBinding, "a live source bearer was rejected for another independently readable existing exact key")

	methodMutated, err := doPresignedGetProbeRequestWithMethod(probeCtx, client, http.MethodHead, bearer.URL, bearer.Headers, "")
	if err != nil {
		status, reason := presignedGetFailureClassification(err)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckHEADMutationRejected, status, reason,
			"HEAD mutation of the GET bearer did not complete", err,
		)
	}
	if methodMutated.StatusCode >= 200 && methodMutated.StatusCode < 300 {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckHEADMutationRejected,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"the exact GET bearer also authorized HEAD after method mutation", nil,
		)
	}
	if !presignedGetMethodMutationRejectionStatus(methodMutated.StatusCode) {
		status, reason := presignedGetHTTPFailureClassification(methodMutated.StatusCode)
		if methodMutated.StatusCode >= 400 && methodMutated.StatusCode < 500 && status == PresignedGetCompatibilityIncompatible {
			status = PresignedGetCompatibilityIndeterminate
			reason = PresignedGetCompatibilityReasonUnknownOperational
		}
		return report, recorder.problem(
			PresignedGetCompatibilityCheckHEADMutationRejected, status, reason,
			fmt.Sprintf("HEAD mutation returned inconclusive HTTP %d", methodMutated.StatusCode), nil,
		)
	}
	if methodMutated.ContentLength > 0 || len(methodMutated.TransferEncoding) != 0 {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckHEADMutationRejected,
			PresignedGetCompatibilityIndeterminate,
			PresignedGetCompatibilityReasonUnknownOperational,
			"rejected HEAD mutation declared a response body that net/http cannot inspect", nil,
		)
	}
	if presignedGetProbeResponseHasUnsupportedEncoding(methodMutated) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckHEADMutationRejected,
			PresignedGetCompatibilityIndeterminate,
			PresignedGetCompatibilityReasonUnknownOperational,
			"rejected HEAD mutation used an encoded response that could not be inspected safely", nil,
		)
	}
	if probeResponseDisclosesObject(methodMutated, v2, s3disk.Version{ETag: second.ETag, VersionID: second.VersionID}) ||
		probeResponseDisclosesObject(methodMutated, target, targetVersion) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckHEADMutationRejected,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"rejected HEAD mutation disclosed sampled object bytes or version", nil,
		)
	}
	if probeResponseDisclosesAuthority(methodMutated, targetAuthority, true) {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckHEADMutationRejected,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"rejected HEAD mutation disclosed the independently sampled target bearer authority", nil,
		)
	}
	sourceAfterHEAD, sourceAfterHEADErr := store.Get(
		probeCtx, sourceKey, s3disk.GetOptions{MaxBytes: maximumPresignedGetProbeResponseBytes},
	)
	if sourceAfterHEADErr != nil {
		status, reason := presignedGetFailureClassification(sourceAfterHEADErr)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckHEADMutationRejected, status, reason,
			"credentialed source read-back could not verify the first canary after the rejected HEAD mutation", sourceAfterHEADErr,
		)
	}
	if !equalProbeBytes(sourceAfterHEAD.Data, v2) || sourceAfterHEAD.Version != version2 {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckHEADMutationRejected,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"the sampled source bytes or version changed during the rejected HEAD mutation", nil,
		)
	}
	targetAfterHEAD, targetAfterHEADErr := store.Get(
		probeCtx, targetKey, s3disk.GetOptions{MaxBytes: maximumPresignedGetProbeResponseBytes},
	)
	if targetAfterHEADErr != nil {
		status, reason := presignedGetFailureClassification(targetAfterHEADErr)
		return report, recorder.problem(
			PresignedGetCompatibilityCheckHEADMutationRejected, status, reason,
			"credentialed target read-back could not verify the second canary after the rejected HEAD mutation", targetAfterHEADErr,
		)
	}
	if !equalProbeBytes(targetAfterHEAD.Data, target) || targetAfterHEAD.Version != targetVersion {
		return report, recorder.problem(
			PresignedGetCompatibilityCheckHEADMutationRejected,
			PresignedGetCompatibilityIncompatible,
			PresignedGetCompatibilityReasonSemanticViolation,
			"the sampled target bytes or version changed during the rejected HEAD mutation", nil,
		)
	}
	if status, reason, disclosedOtherObject, cause := revalidatePresignedGetProbeExactGET(
		probeCtx, client, bearer, v2, version2, target, targetVersion, targetAuthority,
	); status != PresignedGetCompatibilityPassed {
		detail := "the original exact GET bearer was not live immediately after the HEAD-mutation sample"
		if disclosedOtherObject {
			detail = "the revalidated source bearer disclosed the independently sampled target object or bearer authority"
		}
		return report, recorder.problem(
			PresignedGetCompatibilityCheckHEADMutationRejected, status, reason,
			detail, cause,
		)
	}
	recorder.pass(PresignedGetCompatibilityCheckHEADMutationRejected, "HEAD mutation was rejected between successful exact GETs using the same bearer")

	putMutationSamples := []struct {
		label string
		body  []byte
	}{
		{label: "zero-byte", body: []byte{}},
		{label: "non-empty", body: []byte("s3disk-presigned-signed-put:" + nonce)},
	}
	for _, sample := range putMutationSamples {
		writeMutated, writeErr := doPresignedGetProbeRequestWithMethodAndBody(
			probeCtx, client, http.MethodPut, bearer.URL, bearer.Headers, "", sample.body,
		)
		if writeErr != nil {
			status, reason := presignedGetFailureClassification(writeErr)
			return report, recorder.problem(
				PresignedGetCompatibilityCheckPUTRejectedUnchanged, status, reason,
				fmt.Sprintf("%s PUT mutation of the GET bearer did not complete", sample.label), writeErr,
			)
		}
		// A rejection status alone is insufficient evidence: a broken gateway may
		// apply the write to either isolated key and only then return 4xx.
		sourceAfterPUT, sourceAfterPUTErr := store.Get(
			probeCtx, sourceKey, s3disk.GetOptions{MaxBytes: maximumPresignedGetProbeResponseBytes},
		)
		if sourceAfterPUTErr != nil {
			status, reason := presignedGetFailureClassification(sourceAfterPUTErr)
			return report, recorder.problem(
				PresignedGetCompatibilityCheckPUTRejectedUnchanged, status, reason,
				"credentialed source read-back could not verify the first canary after a sampled PUT", sourceAfterPUTErr,
			)
		}
		if !equalProbeBytes(sourceAfterPUT.Data, v2) || sourceAfterPUT.Version != version2 {
			return report, recorder.problem(
				PresignedGetCompatibilityCheckPUTRejectedUnchanged,
				PresignedGetCompatibilityIncompatible,
				PresignedGetCompatibilityReasonSemanticViolation,
				fmt.Sprintf("the sampled source bytes or version changed during the rejected %s PUT", sample.label), nil,
			)
		}
		targetAfterPUT, targetAfterPUTErr := store.Get(
			probeCtx, targetKey, s3disk.GetOptions{MaxBytes: maximumPresignedGetProbeResponseBytes},
		)
		if targetAfterPUTErr != nil {
			status, reason := presignedGetFailureClassification(targetAfterPUTErr)
			return report, recorder.problem(
				PresignedGetCompatibilityCheckPUTRejectedUnchanged, status, reason,
				"credentialed target read-back could not verify the second canary after a sampled PUT", targetAfterPUTErr,
			)
		}
		if !equalProbeBytes(targetAfterPUT.Data, target) || targetAfterPUT.Version != targetVersion {
			return report, recorder.problem(
				PresignedGetCompatibilityCheckPUTRejectedUnchanged,
				PresignedGetCompatibilityIncompatible,
				PresignedGetCompatibilityReasonSemanticViolation,
				fmt.Sprintf("the sampled target bytes or version changed during the rejected %s PUT", sample.label), nil,
			)
		}
		if writeMutated.StatusCode >= 200 && writeMutated.StatusCode < 300 {
			return report, recorder.problem(
				PresignedGetCompatibilityCheckPUTRejectedUnchanged,
				PresignedGetCompatibilityIncompatible,
				PresignedGetCompatibilityReasonSemanticViolation,
				fmt.Sprintf("the exact GET bearer also authorized a %s PUT to the isolated probe key", sample.label), nil,
			)
		}
		if !presignedGetMethodMutationRejectionStatus(writeMutated.StatusCode) {
			status, reason := presignedGetHTTPFailureClassification(writeMutated.StatusCode)
			if writeMutated.StatusCode >= 400 && writeMutated.StatusCode < 500 && status == PresignedGetCompatibilityIncompatible {
				status = PresignedGetCompatibilityIndeterminate
				reason = PresignedGetCompatibilityReasonUnknownOperational
			}
			return report, recorder.problem(
				PresignedGetCompatibilityCheckPUTRejectedUnchanged, status, reason,
				fmt.Sprintf("%s PUT mutation returned inconclusive HTTP %d", sample.label, writeMutated.StatusCode), nil,
			)
		}
		if presignedGetProbeResponseHasUnsupportedEncoding(writeMutated) {
			return report, recorder.problem(
				PresignedGetCompatibilityCheckPUTRejectedUnchanged,
				PresignedGetCompatibilityIndeterminate,
				PresignedGetCompatibilityReasonUnknownOperational,
				fmt.Sprintf("rejected %s PUT mutation used an encoded response that could not be inspected safely", sample.label), nil,
			)
		}
		if probeResponseDisclosesObject(writeMutated, v2, version2) ||
			probeResponseDisclosesObject(writeMutated, target, targetVersion) {
			return report, recorder.problem(
				PresignedGetCompatibilityCheckPUTRejectedUnchanged,
				PresignedGetCompatibilityIncompatible,
				PresignedGetCompatibilityReasonSemanticViolation,
				fmt.Sprintf("rejected %s PUT mutation disclosed sampled object bytes or version", sample.label), nil,
			)
		}
		if probeResponseDisclosesAuthority(writeMutated, targetAuthority, true) {
			return report, recorder.problem(
				PresignedGetCompatibilityCheckPUTRejectedUnchanged,
				PresignedGetCompatibilityIncompatible,
				PresignedGetCompatibilityReasonSemanticViolation,
				fmt.Sprintf("rejected %s PUT mutation disclosed the independently sampled target bearer authority", sample.label), nil,
			)
		}
		if status, reason, disclosedOtherObject, cause := revalidatePresignedGetProbeExactGET(
			probeCtx, client, bearer, v2, version2, target, targetVersion, targetAuthority,
		); status != PresignedGetCompatibilityPassed {
			detail := fmt.Sprintf("the source bearer was not live after the %s PUT sample", sample.label)
			if disclosedOtherObject {
				detail = "the revalidated source bearer disclosed the independently sampled target object or bearer authority"
			}
			return report, recorder.problem(
				PresignedGetCompatibilityCheckPUTRejectedUnchanged, status, reason, detail, cause,
			)
		}
		if status, reason, disclosedOtherObject, cause := revalidatePresignedGetProbeExactGET(
			probeCtx, client, targetBearer, target, targetVersion, v2, version2, sourceAuthority,
		); status != PresignedGetCompatibilityPassed {
			detail := fmt.Sprintf("the target bearer was not live after the %s PUT sample", sample.label)
			if disclosedOtherObject {
				detail = "the revalidated target bearer disclosed the independently sampled source object or bearer authority"
			}
			return report, recorder.problem(
				PresignedGetCompatibilityCheckPUTRejectedUnchanged, status, reason, detail, cause,
			)
		}
	}
	recorder.pass(
		PresignedGetCompatibilityCheckPUTRejectedUnchanged,
		"zero-byte and non-empty PUT mutations were rejected between successful source and target GETs with both canaries unchanged",
	)

	report.Status = PresignedGetCompatibilityPassed
	report.Compatible = true
	report.Complete = true
	if report.Evidence.PresigningTopology == PresignedGetCompatibilitySeparateStore {
		report.Evidence.CrossConfigurationCanaryBindingObserved = true
	}
	return report, nil
}

func validatePresignedGetStorePair(writer, presigningStore *Store, requireSeparateStore bool) error {
	if writer == nil || writer.client == nil || writer.sdkClient == nil || writer.bucket == "" {
		return fmt.Errorf("%w: writer S3 Store is not configured", s3disk.ErrStoreMisconfigured)
	}
	if presigningStore == nil || presigningStore.client == nil || presigningStore.sdkClient == nil || presigningStore.bucket == "" {
		return fmt.Errorf("%w: presigning S3 Store is not configured", s3disk.ErrStoreMisconfigured)
	}
	if writer.bucket != presigningStore.bucket {
		return fmt.Errorf("%w: writer and presigning S3 Stores name different buckets", s3disk.ErrStoreMisconfigured)
	}
	if requireSeparateStore && writer == presigningStore {
		return fmt.Errorf("%w: split commissioning requires separate Store instances", s3disk.ErrStoreMisconfigured)
	}
	if requireSeparateStore && writer.sdkClient == presigningStore.sdkClient {
		return fmt.Errorf("%w: split commissioning requires independent SDK clients", s3disk.ErrStoreMisconfigured)
	}
	return nil
}

type normalizedPresignedGetProbeOptions struct {
	ObjectKeyPrefix                  string
	TotalTimeout                     time.Duration
	CapabilityLifetime               time.Duration
	CleanupTimeout                   time.Duration
	DangerouslyAllowSystemTrustStore bool
}

func normalizePresignedGetProbeOptions(options PresignedGetCompatibilityProbeOptions) (normalizedPresignedGetProbeOptions, *http.Client, error) {
	if options.ObjectKeyPrefix == "" {
		options.ObjectKeyPrefix = defaultPresignedGetProbePrefix
	}
	if err := validatePresignedGetProbePrefix(options.ObjectKeyPrefix); err != nil {
		return normalizedPresignedGetProbeOptions{}, nil, err
	}
	if options.TotalTimeout == 0 {
		options.TotalTimeout = PresignedGetCompatibilityDefaultTimeout
	}
	if options.TotalTimeout < 0 || options.TotalTimeout > PresignedGetCompatibilityMaximumTimeout {
		return normalizedPresignedGetProbeOptions{}, nil, errors.New("total timeout is outside the permitted bound")
	}
	if options.CapabilityLifetime == 0 {
		options.CapabilityLifetime = PresignedGetCompatibilityDefaultCapabilityLifetime
	}
	if options.CapabilityLifetime < 2*time.Second || options.CapabilityLifetime > presignedshare.MaximumCapabilityLifetime {
		return normalizedPresignedGetProbeOptions{}, nil, errors.New("capability lifetime is outside the permitted bound")
	}
	if options.CapabilityLifetime < options.TotalTimeout+presignedGetCompatibilityExpiryMargin {
		return normalizedPresignedGetProbeOptions{}, nil, errors.New("capability lifetime does not cover the probe timeout and signing-time margin")
	}
	if options.CleanupTimeout == 0 {
		options.CleanupTimeout = PresignedGetCompatibilityDefaultCleanupTimeout
	}
	if options.CleanupTimeout < 0 || options.CleanupTimeout > PresignedGetCompatibilityMaximumTimeout {
		return normalizedPresignedGetProbeOptions{}, nil, errors.New("cleanup timeout is outside the permitted bound")
	}
	client, err := clonePresignedGetProbeHTTPClient(options.HTTPClient, options.TLSRootCAPEM)
	if err != nil {
		return normalizedPresignedGetProbeOptions{}, nil, err
	}
	return normalizedPresignedGetProbeOptions{
		ObjectKeyPrefix: options.ObjectKeyPrefix, TotalTimeout: options.TotalTimeout,
		CapabilityLifetime: options.CapabilityLifetime, CleanupTimeout: options.CleanupTimeout,
		DangerouslyAllowSystemTrustStore: options.DangerouslyAllowSystemTrustStore,
	}, client, nil
}

func validatePresignedGetProbePrefix(prefix string) error {
	if prefix == "" || len(prefix) > maximumPresignedGetProbePrefixBytes || !utf8.ValidString(prefix) ||
		strings.HasPrefix(prefix, "/") || strings.HasSuffix(prefix, "/") || strings.Contains(prefix, "//") {
		return errors.New("object-key prefix is not a bounded canonical relative prefix")
	}
	for _, character := range prefix {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._-/", character)) {
			return errors.New("object-key prefix contains an unsupported character")
		}
	}
	for _, segment := range strings.Split(prefix, "/") {
		if segment == "." || segment == ".." {
			return errors.New("object-key prefix contains a dot path segment")
		}
	}
	return nil
}

func clonePresignedGetProbeHTTPClient(input *http.Client, tlsRootCAPEM []byte) (*http.Client, error) {
	client := &http.Client{}
	var source *http.Transport
	if input != nil {
		if input.Timeout < 0 || input.Timeout > PresignedGetCompatibilityMaximumTimeout {
			return nil, errors.New("HTTP client timeout is outside the permitted bound")
		}
		client.Timeout = input.Timeout
		if input.Transport != nil {
			if interfaceIsNil(input.Transport) {
				return nil, errors.New("HTTP client contains a typed-nil transport")
			}
			configured, ok := input.Transport.(*http.Transport)
			if !ok || configured == nil {
				return nil, errors.New("HTTP client transport must be *http.Transport")
			}
			// Clone before inspecting exported fields. Clone coordinates the
			// standard library's lazy protocol initialization and leaves the
			// caller free to keep using or mutating its own transport.
			source = configured.Clone()
		}
	}
	transport, err := newPresignedGetProbeDirectTransport(source, tlsRootCAPEM)
	if err != nil {
		return nil, err
	}
	client.Transport = presignedGetAnonymousTransport{delegate: transport}
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client, nil
}

func newPresignedGetProbeDirectTransport(source *http.Transport, tlsRootCAPEM []byte) (*http.Transport, error) {
	dialer := newPresignedGetProbeNetworkDialer()
	transport := &http.Transport{
		// Proxy intentionally stays nil, including when the process has ambient
		// HTTP(S)_PROXY variables. A bearer request must go directly to its S3
		// origin through a private callback-free resolver.
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		Dial:                   nil,
		DialTLSContext:         nil,
		DialTLS:                nil,
		TLSHandshakeTimeout:    10 * time.Second,
		DisableCompression:     true,
		MaxIdleConns:           100,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        90 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: maximumPresignedGetProbeHeaderBytes,
		ForceAttemptHTTP2:      true,
	}
	var configuredTLS *tls.Config
	if source != nil {
		if source.Proxy != nil || source.OnProxyConnectResponse != nil ||
			source.DialContext != nil || source.Dial != nil ||
			source.DialTLSContext != nil || source.DialTLS != nil ||
			source.TLSNextProto != nil || source.ProxyConnectHeader != nil ||
			source.GetProxyConnectHeader != nil || source.Protocols != nil {
			return nil, errors.New("HTTP transport routing and protocol extensions are forbidden")
		}
		for _, duration := range []time.Duration{
			source.TLSHandshakeTimeout,
			source.IdleConnTimeout,
			source.ResponseHeaderTimeout,
			source.ExpectContinueTimeout,
		} {
			if duration < 0 || duration > PresignedGetCompatibilityMaximumTimeout {
				return nil, errors.New("HTTP transport timeout is outside the permitted bound")
			}
		}
		for _, count := range []int{source.MaxIdleConns, source.MaxIdleConnsPerHost, source.MaxConnsPerHost} {
			if count < 0 || count > maximumPresignedGetProbeConnections {
				return nil, errors.New("HTTP transport connection bound is outside the permitted range")
			}
		}
		if source.MaxResponseHeaderBytes < 0 {
			return nil, errors.New("HTTP response-header bound must not be negative")
		}
		transport.DisableKeepAlives = source.DisableKeepAlives
		if source.TLSHandshakeTimeout > 0 {
			transport.TLSHandshakeTimeout = source.TLSHandshakeTimeout
		}
		if source.MaxIdleConns > 0 {
			transport.MaxIdleConns = source.MaxIdleConns
		}
		if source.MaxIdleConnsPerHost > 0 {
			transport.MaxIdleConnsPerHost = source.MaxIdleConnsPerHost
		}
		if source.MaxConnsPerHost > 0 {
			transport.MaxConnsPerHost = source.MaxConnsPerHost
		}
		if source.IdleConnTimeout > 0 {
			transport.IdleConnTimeout = source.IdleConnTimeout
		}
		transport.ResponseHeaderTimeout = source.ResponseHeaderTimeout
		if source.ExpectContinueTimeout > 0 {
			transport.ExpectContinueTimeout = source.ExpectContinueTimeout
		}
		if source.MaxResponseHeaderBytes > 0 && source.MaxResponseHeaderBytes < maximumPresignedGetProbeHeaderBytes {
			transport.MaxResponseHeaderBytes = source.MaxResponseHeaderBytes
		}
		configuredTLS = source.TLSClientConfig
	}
	tlsConfig, err := lockedPresignedGetProbeTLSClientConfig(configuredTLS, tlsRootCAPEM)
	if err != nil {
		return nil, err
	}
	transport.TLSClientConfig = tlsConfig
	return transport, nil
}

func lockedPresignedGetProbeTLSClientConfig(source *tls.Config, tlsRootCAPEM []byte) (*tls.Config, error) {
	result := &tls.Config{MinVersion: tls.VersionTLS12}
	if source != nil && (source.InsecureSkipVerify || source.ServerName != "" ||
		source.Rand != nil || source.Time != nil ||
		len(source.Certificates) != 0 || source.NameToCertificate != nil ||
		source.GetCertificate != nil || source.GetClientCertificate != nil || source.GetConfigForClient != nil ||
		source.VerifyPeerCertificate != nil || source.VerifyConnection != nil ||
		!standardPresignedGetProbeNextProtos(source.NextProtos) || source.ClientAuth != tls.NoClientCert || source.ClientCAs != nil || source.RootCAs != nil ||
		source.ClientSessionCache != nil || source.UnwrapSession != nil || source.WrapSession != nil ||
		source.Renegotiation != tls.RenegotiateNever || source.KeyLogWriter != nil ||
		len(source.CipherSuites) != 0 || source.PreferServerCipherSuites || len(source.CurvePreferences) != 0 ||
		len(source.EncryptedClientHelloConfigList) != 0 || source.EncryptedClientHelloRejectionVerify != nil ||
		source.GetEncryptedClientHelloKeys != nil || len(source.EncryptedClientHelloKeys) != 0 ||
		source.SessionTicketKey != [32]byte{}) {
		return nil, errors.New("custom TLS identity, algorithms, callbacks, trust pools, or secret logging are forbidden")
	}
	if source != nil && source.MinVersion != 0 {
		if source.MinVersion < tls.VersionTLS12 || source.MinVersion > tls.VersionTLS13 {
			return nil, errors.New("TLS minimum version must be 1.2 or 1.3")
		}
		result.MinVersion = source.MinVersion
	}
	if source != nil && source.MaxVersion != 0 {
		if source.MaxVersion < result.MinVersion || source.MaxVersion > tls.VersionTLS13 {
			return nil, errors.New("TLS version range is invalid")
		}
		result.MaxVersion = source.MaxVersion
	}
	rootCAs, err := parsePresignedGetProbeTLSRootCAPEM(tlsRootCAPEM)
	if err != nil {
		return nil, err
	}
	result.RootCAs = rootCAs
	if source != nil {
		result.SessionTicketsDisabled = source.SessionTicketsDisabled
		result.DynamicRecordSizingDisabled = source.DynamicRecordSizingDisabled
	}
	return result, nil
}

func standardPresignedGetProbeNextProtos(protocols []string) bool {
	// http.Transport.Clone may lazily materialize this exact standard-library
	// default even when the caller supplied no ALPN override. The probe builds a
	// fresh transport, so accepting only this known pair does not retain caller
	// protocol authority. Any other non-empty list is a custom extension.
	return len(protocols) == 0 ||
		(len(protocols) == 2 && protocols[0] == "h2" && protocols[1] == "http/1.1")
}

func parsePresignedGetProbeTLSRootCAPEM(encoded []byte) (*x509.CertPool, error) {
	certificates, err := tlsroots.ParsePEMCertificates(
		encoded,
		maximumPresignedGetProbeTLSRootCAPEMBytes,
		maximumPresignedGetProbeTLSRootCertificates,
	)
	if err != nil {
		switch {
		case errors.Is(err, tlsroots.ErrPEMTooLarge):
			return nil, errors.New("TLS root CA PEM exceeds the byte limit")
		case errors.Is(err, tlsroots.ErrTooManyCertificates):
			return nil, errors.New("TLS root CA PEM contains too many certificates")
		case errors.Is(err, tlsroots.ErrInvalidCertificate):
			return nil, errors.New("TLS root CA PEM contains an invalid certificate")
		case errors.Is(err, tlsroots.ErrNoCertificates):
			return nil, errors.New("TLS root CA PEM contains no certificates")
		default:
			return nil, errors.New("TLS root CA PEM is malformed")
		}
	}
	if len(certificates) == 0 {
		return nil, nil
	}
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		pool.AddCert(certificate)
	}
	return pool, nil
}

func newPresignedGetProbeNetworkDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  &net.Resolver{PreferGo: true},
	}
}

func interfaceIsNil(value any) bool {
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

type presignedGetAnonymousTransport struct{ delegate http.RoundTripper }

var errPresignedGetProbeInformationalResponse = errors.New("anonymous S3 response used an unsupported informational response")

func (transport presignedGetAnonymousTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || transport.delegate == nil {
		return nil, errors.New("anonymous S3 transport is not configured")
	}
	if err := validatePresignedGetProbeAnonymousHeaders(request.Header); err != nil {
		return nil, errors.New("anonymous S3 request contained a forbidden credential header")
	}
	// Enforce the value-free boundary at the transport too, so a future caller
	// cannot bypass it by constructing a request outside the probe helper.
	valueFree := presignedGetProbeValueFreeContext{Context: request.Context()}
	request = request.WithContext(httptrace.WithClientTrace(valueFree, &httptrace.ClientTrace{
		Got1xxResponse: func(int, textproto.MIMEHeader) error {
			// S3 capability operations do not need informational responses. Abort
			// rather than discard a response field that could disclose sampled data
			// outside the final bounded response inspection.
			return errPresignedGetProbeInformationalResponse
		},
	}))
	return transport.delegate.RoundTrip(request)
}

type presignedGetProbeBearer struct {
	URL       string
	Headers   http.Header
	ExpiresAt time.Time
}

type presignedGetProbeBearerWire struct {
	Format  int    `json:"format"`
	URL     string `json:"url"`
	Headers []struct {
		Name   string   `json:"name"`
		Values []string `json:"values"`
	} `json:"headers"`
	ExpiresAt time.Time `json:"expires_at"`
}

func exportPresignedGetProbeBearer(capability presignedshare.Capability) (presignedGetProbeBearer, error) {
	encoded, err := capability.ExportBearer()
	if err != nil {
		return presignedGetProbeBearer{}, errors.New("capability export failed")
	}
	defer clear(encoded)
	var wire presignedGetProbeBearerWire
	if err := json.Unmarshal(encoded, &wire); err != nil || wire.Format != 1 || wire.URL == "" {
		return presignedGetProbeBearer{}, errors.New("capability export was malformed")
	}
	headers := make(http.Header, len(wire.Headers))
	for _, header := range wire.Headers {
		if header.Name == "" || len(header.Values) == 0 || headers[header.Name] != nil {
			return presignedGetProbeBearer{}, errors.New("capability export headers were malformed")
		}
		headers[header.Name] = append([]string(nil), header.Values...)
	}
	return presignedGetProbeBearer{URL: wire.URL, Headers: headers, ExpiresAt: wire.ExpiresAt}, nil
}

func validatePresignedGetProbeAnonymousHeaders(headers http.Header) error {
	for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie"} {
		if len(headers.Values(name)) != 0 {
			return errors.New("forbidden credential-bearing header")
		}
	}
	return nil
}

func stripPresignedGetProbeAuthority(bearer presignedGetProbeBearer) (presignedGetProbeBearer, error) {
	parsed, err := url.Parse(bearer.URL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Fragment != "" {
		return presignedGetProbeBearer{}, errors.New("presigned bearer URL was invalid")
	}
	queryIndex := strings.IndexByte(bearer.URL, '?')
	if queryIndex < 0 {
		return presignedGetProbeBearer{}, errors.New("presigned bearer URL had no authorization query")
	}
	base := bearer.URL[:queryIndex]
	parts := strings.Split(bearer.URL[queryIndex+1:], "&")
	kept := make([]string, 0, len(parts))
	removedSignature := false
	removedCredential := false
	for _, part := range parts {
		rawName, _, _ := strings.Cut(part, "=")
		name, err := url.QueryUnescape(rawName)
		if err != nil || name == "" {
			return presignedGetProbeBearer{}, errors.New("presigned bearer authorization query was malformed")
		}
		if strings.HasPrefix(strings.ToLower(name), "x-amz-") {
			removedSignature = removedSignature || strings.EqualFold(name, "X-Amz-Signature")
			removedCredential = removedCredential || strings.EqualFold(name, "X-Amz-Credential")
			continue
		}
		kept = append(kept, part)
	}
	if !removedSignature || !removedCredential {
		return presignedGetProbeBearer{}, errors.New("presigned bearer authorization query was incomplete")
	}
	unsignedURL := base
	if len(kept) != 0 {
		unsignedURL += "?" + strings.Join(kept, "&")
	}
	unsignedParsed, err := url.Parse(unsignedURL)
	if err != nil || unsignedParsed.Scheme != parsed.Scheme || unsignedParsed.Host != parsed.Host ||
		unsignedParsed.EscapedPath() != parsed.EscapedPath() || unsignedParsed.Fragment != "" {
		return presignedGetProbeBearer{}, errors.New("could not preserve exact origin and path while removing bearer authority")
	}
	headers := bearer.Headers.Clone()
	for name := range headers {
		if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Proxy-Authorization") ||
			strings.EqualFold(name, "Cookie") || strings.HasPrefix(strings.ToLower(name), "x-amz-") {
			headers.Del(name)
		}
	}
	if err := validatePresignedGetProbeAnonymousHeaders(headers); err != nil {
		return presignedGetProbeBearer{}, err
	}
	return presignedGetProbeBearer{URL: unsignedURL, Headers: headers}, nil
}

type presignedGetProbeHTTPResult struct {
	StatusCode       int
	Status           string
	ETag             string
	VersionID        string
	ContentLength    int64
	TransferEncoding []string
	Body             []byte
	Headers          http.Header
}

type presignedGetProbeAuthorityFingerprint struct {
	authorityValues []string
	pathValues      []string
}

func newPresignedGetProbeAuthorityFingerprint(
	foreign presignedGetProbeBearer,
	allowed presignedGetProbeBearer,
	foreignKey string,
) (presignedGetProbeAuthorityFingerprint, error) {
	foreignURL, err := url.Parse(foreign.URL)
	if err != nil || foreignURL.Host == "" || foreignURL.Fragment != "" {
		return presignedGetProbeAuthorityFingerprint{}, errors.New("foreign bearer URL was invalid")
	}
	allowedURL, err := url.Parse(allowed.URL)
	if err != nil || allowedURL.Host == "" || allowedURL.Fragment != "" {
		return presignedGetProbeAuthorityFingerprint{}, errors.New("allowed bearer URL was invalid")
	}
	fingerprint := presignedGetProbeAuthorityFingerprint{}
	appendUnique := func(destination *[]string, value string) {
		if value == "" {
			return
		}
		for _, existing := range *destination {
			if existing == value {
				return
			}
		}
		*destination = append(*destination, value)
	}
	appendUnique(&fingerprint.authorityValues, foreign.URL)
	foreignSignature := foreignURL.Query().Get("X-Amz-Signature")
	if foreignSignature == "" {
		return presignedGetProbeAuthorityFingerprint{}, errors.New("foreign bearer had no signature fingerprint")
	}
	if foreignSignature != allowedURL.Query().Get("X-Amz-Signature") {
		appendUnique(&fingerprint.authorityValues, foreignSignature)
	}
	for name, values := range foreign.Headers {
		allowedValues := allowed.Headers.Values(name)
		for _, value := range values {
			shared := false
			for _, allowedValue := range allowedValues {
				if value == allowedValue {
					shared = true
					break
				}
			}
			if shared || value == "" {
				continue
			}
			appendUnique(&fingerprint.authorityValues, value)
			appendUnique(&fingerprint.authorityValues, name+": "+value)
		}
	}
	appendUnique(&fingerprint.pathValues, foreignURL.EscapedPath())
	appendUnique(&fingerprint.pathValues, "/"+escapePresignedGetProbeKey(foreignKey))
	return fingerprint, nil
}

func probeResponseDisclosesAuthority(
	response presignedGetProbeHTTPResult,
	fingerprint presignedGetProbeAuthorityFingerprint,
	includePath bool,
) bool {
	values := fingerprint.authorityValues
	if includePath {
		values = append(values, fingerprint.pathValues...)
	}
	for _, value := range values {
		if value == "" {
			continue
		}
		if bytes.Contains(response.Body, []byte(value)) || strings.Contains(response.Status, value) {
			return true
		}
		for name, headerValues := range response.Headers {
			if strings.Contains(name, value) {
				return true
			}
			for _, headerValue := range headerValues {
				if strings.Contains(headerValue, value) {
					return true
				}
			}
		}
	}
	return false
}

func probeResponseDisclosesObject(response presignedGetProbeHTTPResult, body []byte, version s3disk.Version) bool {
	if len(body) != 0 && bytes.Contains(response.Body, body) ||
		version.ETag != "" && response.ETag == version.ETag ||
		version.VersionID != "" && response.VersionID == version.VersionID {
		return true
	}
	bodyText := string(body)
	if bodyText != "" && strings.Contains(response.Status, bodyText) ||
		version.ETag != "" && strings.Contains(response.Status, version.ETag) ||
		version.VersionID != "" && strings.Contains(response.Status, version.VersionID) {
		return true
	}
	for name, values := range response.Headers {
		if bodyText != "" && strings.Contains(name, bodyText) ||
			version.ETag != "" && strings.Contains(name, version.ETag) ||
			version.VersionID != "" && strings.Contains(name, version.VersionID) {
			return true
		}
		for _, value := range values {
			if bodyText != "" && strings.Contains(value, bodyText) ||
				version.ETag != "" && strings.Contains(value, version.ETag) ||
				version.VersionID != "" && strings.Contains(value, version.VersionID) {
				return true
			}
		}
	}
	return false
}

// probeSuccessfulResponseDisclosesOtherObject applies the same bounded
// body/status/header/trailer inspection to a successful observation while
// exempting only the response's own, expected ETag and version-ID fields. Some
// non-versioned S3 implementations legitimately return the same opaque value
// (for example "null") for several keys. Such a value in the canonical field
// is not evidence of a cross-key disclosure; the same value in any other
// metadata field remains evidence and fails closed.
func probeSuccessfulResponseDisclosesOtherObject(
	response presignedGetProbeHTTPResult,
	expectedVersion s3disk.Version,
	forbiddenBody []byte,
	forbiddenVersion s3disk.Version,
) bool {
	if len(forbiddenBody) != 0 && bytes.Contains(response.Body, forbiddenBody) ||
		forbiddenVersion.ETag != "" && forbiddenVersion.ETag != expectedVersion.ETag && response.ETag == forbiddenVersion.ETag ||
		forbiddenVersion.VersionID != "" && forbiddenVersion.VersionID != expectedVersion.VersionID && response.VersionID == forbiddenVersion.VersionID {
		return true
	}
	forbiddenBodyText := string(forbiddenBody)
	if forbiddenBodyText != "" && strings.Contains(response.Status, forbiddenBodyText) ||
		forbiddenVersion.ETag != "" && strings.Contains(response.Status, forbiddenVersion.ETag) ||
		forbiddenVersion.VersionID != "" && strings.Contains(response.Status, forbiddenVersion.VersionID) {
		return true
	}
	for name, values := range response.Headers {
		if forbiddenBodyText != "" && strings.Contains(name, forbiddenBodyText) ||
			forbiddenVersion.ETag != "" && strings.Contains(name, forbiddenVersion.ETag) ||
			forbiddenVersion.VersionID != "" && strings.Contains(name, forbiddenVersion.VersionID) {
			return true
		}
		for _, value := range values {
			if forbiddenBodyText != "" && strings.Contains(value, forbiddenBodyText) {
				return true
			}
			ownExpectedVersionField := strings.EqualFold(name, "ETag") && expectedVersion.ETag != "" && value == expectedVersion.ETag ||
				strings.EqualFold(name, "X-Amz-Version-Id") && expectedVersion.VersionID != "" && value == expectedVersion.VersionID
			if ownExpectedVersionField {
				continue
			}
			if forbiddenVersion.ETag != "" && strings.Contains(value, forbiddenVersion.ETag) ||
				forbiddenVersion.VersionID != "" && strings.Contains(value, forbiddenVersion.VersionID) {
				return true
			}
		}
	}
	return false
}

func presignedGetProbeResponseHasUnsupportedEncoding(response presignedGetProbeHTTPResult) bool {
	for _, value := range response.Headers.Values("Content-Encoding") {
		if value != "" && !strings.EqualFold(strings.TrimSpace(value), "identity") {
			return true
		}
	}
	return false
}

func revalidatePresignedGetProbeExactGET(
	ctx context.Context,
	client *http.Client,
	bearer presignedGetProbeBearer,
	expectedBody []byte,
	expectedVersion s3disk.Version,
	forbiddenBody []byte,
	forbiddenVersion s3disk.Version,
	forbiddenAuthority presignedGetProbeAuthorityFingerprint,
) (PresignedGetCompatibilityStatus, PresignedGetCompatibilityReason, bool, error) {
	observed, err := doPresignedGetProbeRequest(ctx, client, bearer.URL, bearer.Headers, "")
	if err != nil {
		status, reason := presignedGetFailureClassification(err)
		return status, reason, false, err
	}
	if observed.StatusCode != http.StatusOK {
		status, reason := presignedGetHTTPFailureClassification(observed.StatusCode)
		return status, reason, false, nil
	}
	if probeSuccessfulResponseDisclosesOtherObject(observed, expectedVersion, forbiddenBody, forbiddenVersion) ||
		probeResponseDisclosesAuthority(observed, forbiddenAuthority, true) {
		return PresignedGetCompatibilityIncompatible, PresignedGetCompatibilityReasonSemanticViolation, true, nil
	}
	if !equalProbeBytes(observed.Body, expectedBody) ||
		observed.ETag != expectedVersion.ETag || observed.VersionID != expectedVersion.VersionID {
		return PresignedGetCompatibilityIncompatible, PresignedGetCompatibilityReasonSemanticViolation, false, nil
	}
	return PresignedGetCompatibilityPassed, "", false, nil
}

func credentialedPresignedGetProbeObjectUnchanged(
	ctx context.Context,
	store *Store,
	key string,
	expectedBody []byte,
	expectedVersion s3disk.Version,
) (bool, error) {
	observed, err := store.Get(ctx, key, s3disk.GetOptions{MaxBytes: maximumPresignedGetProbeResponseBytes})
	if err != nil {
		return false, err
	}
	return equalProbeBytes(observed.Data, expectedBody) && observed.Version == expectedVersion, nil
}

func doPresignedGetProbeRequest(
	ctx context.Context,
	client *http.Client,
	rawURL string,
	baseHeaders http.Header,
	ifNoneMatch string,
) (presignedGetProbeHTTPResult, error) {
	return doPresignedGetProbeRequestWithMethod(ctx, client, http.MethodGet, rawURL, baseHeaders, ifNoneMatch)
}

func doPresignedGetProbeRequestWithMethod(
	ctx context.Context,
	client *http.Client,
	method string,
	rawURL string,
	baseHeaders http.Header,
	ifNoneMatch string,
) (presignedGetProbeHTTPResult, error) {
	return doPresignedGetProbeRequestWithMethodAndBody(ctx, client, method, rawURL, baseHeaders, ifNoneMatch, nil)
}

func doPresignedGetProbeRequestWithMethodAndBody(
	ctx context.Context,
	client *http.Client,
	method string,
	rawURL string,
	baseHeaders http.Header,
	ifNoneMatch string,
	requestPayload []byte,
) (presignedGetProbeHTTPResult, error) {
	if err := ctx.Err(); err != nil {
		return presignedGetProbeHTTPResult{}, err
	}
	// Context values can carry executable hooks such as net/http/httptrace.
	// Preserve cancellation and deadlines while denying every inherited value
	// to the anonymous commissioning request.
	var requestBody io.Reader
	if requestPayload != nil {
		requestBody = bytes.NewReader(requestPayload)
	}
	request, err := http.NewRequestWithContext(presignedGetProbeValueFreeContext{Context: ctx}, method, rawURL, requestBody)
	if err != nil {
		return presignedGetProbeHTTPResult{}, errors.New("could not construct anonymous S3 request")
	}
	request.Header = baseHeaders.Clone()
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-cache")
	request.Header.Set("Pragma", "no-cache")
	// Commissioning never reuses an anonymous connection. net/http suppresses
	// bodies for HEAD and bodyless statuses such as 304 and can discard bytes
	// beyond declared framing; closing bounds those parser ambiguities to this
	// request. This is probe isolation, not a claim about runtime Reader I/O.
	request.Close = true
	if ifNoneMatch != "" {
		request.Header.Set("If-None-Match", ifNoneMatch)
	}
	if err := validatePresignedGetProbeAnonymousHeaders(request.Header); err != nil {
		return presignedGetProbeHTTPResult{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return presignedGetProbeHTTPResult{}, ctx.Err()
		}
		return presignedGetProbeHTTPResult{}, classifyPresignedGetTransportError(err)
	}
	defer response.Body.Close()
	if err := validatePresignedGetProbeResponseHeaders(response.Header); err != nil {
		return presignedGetProbeHTTPResult{}, err
	}
	version, err := presignedGetProbeResponseVersion(response.Header, response.StatusCode == http.StatusOK)
	if err != nil {
		return presignedGetProbeHTTPResult{}, err
	}
	// Error bodies are provider-specific and occasionally large, but a broken
	// gateway can reject a path or method mutation while still disclosing object
	// bytes or an ETag. Buffer every response within the same small bound so the
	// negative checks can detect that finite sampled leak. The bytes remain
	// internal and are never copied into reports or errors.
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumPresignedGetProbeResponseBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return presignedGetProbeHTTPResult{}, ctx.Err()
		}
		return presignedGetProbeHTTPResult{}, errors.New("anonymous S3 response body could not be read")
	}
	if len(body) > maximumPresignedGetProbeResponseBytes {
		return presignedGetProbeHTTPResult{}, fmt.Errorf("%w: anonymous S3 response exceeded the probe body bound", s3disk.ErrResourceLimit)
	}
	metadata := response.Header.Clone()
	for name, values := range response.Trailer {
		metadata[name] = append(metadata[name], values...)
	}
	if err := validatePresignedGetProbeResponseHeaders(metadata); err != nil {
		return presignedGetProbeHTTPResult{}, err
	}
	if len(response.Status) > maximumPresignedGetProbeResponseBytes || strings.ContainsAny(response.Status, "\x00\r\n") {
		return presignedGetProbeHTTPResult{}, fmt.Errorf("%w: anonymous S3 response returned an invalid status", s3disk.ErrStoreIncompatible)
	}
	return presignedGetProbeHTTPResult{
		StatusCode:       response.StatusCode,
		Status:           response.Status,
		ETag:             version.ETag,
		VersionID:        version.VersionID,
		ContentLength:    response.ContentLength,
		TransferEncoding: append([]string(nil), response.TransferEncoding...),
		Body:             body,
		Headers:          metadata,
	}, nil
}

type presignedGetProbeValueFreeContext struct{ context.Context }

func (presignedGetProbeValueFreeContext) Value(any) any { return nil }

func validatePresignedGetProbeResponseHeaders(headers http.Header) error {
	if len(headers) > maximumPresignedGetProbeHeaderCount {
		return fmt.Errorf("%w: anonymous S3 response returned too many headers", s3disk.ErrResourceLimit)
	}
	var total int64
	for name, values := range headers {
		total += int64(len(name))
		for _, value := range values {
			total += int64(len(value))
			if total > maximumPresignedGetProbeHeaderBytes {
				return fmt.Errorf("%w: anonymous S3 response headers exceeded the probe bound", s3disk.ErrResourceLimit)
			}
		}
	}
	if total > maximumPresignedGetProbeHeaderBytes {
		return fmt.Errorf("%w: anonymous S3 response headers exceeded the probe bound", s3disk.ErrResourceLimit)
	}
	return nil
}

func presignedGetProbeResponseVersion(headers http.Header, requireETag bool) (s3disk.Version, error) {
	etags := headers.Values("ETag")
	if len(etags) > 1 || requireETag && len(etags) != 1 ||
		len(etags) == 1 && (etags[0] == "" || len(etags[0]) > s3disk.MaxStoreVersionTokenBytes || strings.ContainsAny(etags[0], "\x00\r\n")) {
		return s3disk.Version{}, fmt.Errorf("%w: anonymous S3 response returned an invalid ETag", s3disk.ErrStoreIncompatible)
	}
	versionIDs := headers.Values("X-Amz-Version-Id")
	if len(versionIDs) > 1 ||
		len(versionIDs) == 1 && (len(versionIDs[0]) > s3disk.MaxStoreVersionTokenBytes || strings.ContainsAny(versionIDs[0], "\x00\r\n")) {
		return s3disk.Version{}, fmt.Errorf("%w: anonymous S3 response returned an invalid version ID", s3disk.ErrStoreIncompatible)
	}
	version := s3disk.Version{}
	if len(etags) == 1 {
		version.ETag = etags[0]
	}
	if len(versionIDs) == 1 {
		version.VersionID = versionIDs[0]
	}
	return version, nil
}

func classifyPresignedGetTransportError(err error) error {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return presignedGetProbeNetworkError{timeout: netErr.Timeout()}
	}
	return errors.New("anonymous S3 transport failed")
}

type presignedGetProbeNetworkError struct{ timeout bool }

func (networkErr presignedGetProbeNetworkError) Error() string {
	return "anonymous S3 network operation failed"
}
func (networkErr presignedGetProbeNetworkError) Timeout() bool   { return networkErr.timeout }
func (networkErr presignedGetProbeNetworkError) Temporary() bool { return true }

func newPresignedGetProbeKeys(prefix string) (source, target, nonce string, err error) {
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		return "", "", "", err
	}
	nonce = hex.EncodeToString(random)
	base := prefix + "/" + nonce
	return base + "/source", base + "/target", nonce, nil
}

func mutatePresignedGetProbeAuthorizationQuery(shorterURL, longerURL string) (string, error) {
	shorter, err := url.Parse(shorterURL)
	if err != nil || shorter.Host == "" || shorter.Fragment != "" || shorter.RawQuery == "" {
		return "", errors.New("invalid presigned URL")
	}
	longer, err := url.Parse(longerURL)
	if err != nil || longer.Scheme != shorter.Scheme || longer.Host != shorter.Host ||
		longer.EscapedPath() != shorter.EscapedPath() || longer.Fragment != "" {
		return "", errors.New("invalid longer presigned URL")
	}
	parts, expiryIndex, shorterSeconds, err := presignedGetProbeExpiryQuery(shorter.RawQuery)
	if err != nil {
		return "", err
	}
	_, _, longerSeconds, err := presignedGetProbeExpiryQuery(longer.RawQuery)
	if err != nil || longerSeconds <= shorterSeconds {
		return "", errors.New("presigned control URL does not have a longer valid expiry")
	}
	shorterContext, err := presignedGetProbeComparableAuthorizationQuery(shorter.RawQuery)
	if err != nil {
		return "", err
	}
	longerContext, err := presignedGetProbeComparableAuthorizationQuery(longer.RawQuery)
	if err != nil || shorterContext != longerContext {
		return "", errors.New("presigned control URLs do not share one signing context")
	}
	parts[expiryIndex] = "X-Amz-Expires=" + strconv.FormatUint(longerSeconds, 10)
	queryIndex := strings.IndexByte(shorterURL, '?')
	if queryIndex < 0 {
		return "", errors.New("presigned URL has no raw query boundary")
	}
	mutated := shorterURL[:queryIndex+1] + strings.Join(parts, "&")
	mutatedURL, err := url.Parse(mutated)
	if err != nil || mutatedURL.Scheme != shorter.Scheme || mutatedURL.Host != shorter.Host ||
		mutatedURL.EscapedPath() != shorter.EscapedPath() || mutatedURL.RawQuery == shorter.RawQuery || mutatedURL.Fragment != "" {
		return "", errors.New("could not preserve the presigned URL while replacing its expiry query")
	}
	return mutated, nil
}

func presignedGetProbeExpiryQuery(rawQuery string) ([]string, int, uint64, error) {
	parts := strings.Split(rawQuery, "&")
	matched := -1
	var seconds uint64
	for index, part := range parts {
		const prefix = "X-Amz-Expires="
		if !strings.HasPrefix(part, prefix) {
			continue
		}
		if matched >= 0 {
			return nil, 0, 0, errors.New("presigned URL contains duplicate expiry parameters")
		}
		parsed, err := strconv.ParseUint(strings.TrimPrefix(part, prefix), 10, 64)
		if err != nil || parsed == 0 {
			return nil, 0, 0, errors.New("presigned URL expiry parameter is invalid")
		}
		matched = index
		seconds = parsed
	}
	if matched < 0 {
		return nil, 0, 0, errors.New("presigned URL has no signed expiry parameter")
	}
	return parts, matched, seconds, nil
}

func presignedGetProbeComparableAuthorizationQuery(rawQuery string) (string, error) {
	parts := strings.Split(rawQuery, "&")
	filtered := make([]string, 0, len(parts)-2)
	expires := 0
	signatures := 0
	for _, part := range parts {
		switch {
		case strings.HasPrefix(part, "X-Amz-Expires="):
			expires++
		case strings.HasPrefix(part, "X-Amz-Signature="):
			signatures++
		default:
			filtered = append(filtered, part)
		}
	}
	if expires != 1 || signatures != 1 {
		return "", errors.New("presigned URL does not have one expiry and signature parameter")
	}
	return strings.Join(filtered, "&"), nil
}

func replacePresignedGetProbePath(rawURL, exactTargetURL, sourceKey, targetKey string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || parsed.Fragment != "" {
		return "", errors.New("invalid presigned URL")
	}
	targetParsed, err := url.Parse(exactTargetURL)
	if err != nil || targetParsed.Host == "" || targetParsed.Fragment != "" ||
		targetParsed.Scheme != parsed.Scheme || targetParsed.Host != parsed.Host {
		return "", errors.New("invalid exact target presigned URL")
	}
	sourceSuffix := "/" + sourceKey
	targetSuffix := "/" + targetKey
	if !strings.HasSuffix(parsed.Path, sourceSuffix) || !strings.HasSuffix(targetParsed.Path, targetSuffix) {
		return "", errors.New("presigned path does not end with the source exact key")
	}
	// Change only the escaped key suffix in the original URL bytes. Rebuilding
	// URL.Path and clearing RawPath can silently decode an unrelated escaped
	// endpoint base path (for example /tenant%2Fgateway); a rejection of that
	// different route would be false evidence that the object key was bound.
	escapedPath := parsed.EscapedPath()
	escapedTargetPath := targetParsed.EscapedPath()
	escapedSourceSuffix := "/" + escapePresignedGetProbeKey(sourceKey)
	escapedTargetSuffix := "/" + escapePresignedGetProbeKey(targetKey)
	if !strings.HasSuffix(escapedPath, escapedSourceSuffix) ||
		!strings.HasSuffix(escapedTargetPath, escapedTargetSuffix) ||
		strings.TrimSuffix(escapedPath, escapedSourceSuffix) != strings.TrimSuffix(escapedTargetPath, escapedTargetSuffix) {
		return "", errors.New("presigned escaped path does not have the canonical source-key suffix")
	}
	// Use the path bytes independently proven usable by the correct target
	// bearer, while retaining the source bearer's signed query and headers.
	mutatedPath := escapedTargetPath
	pathAndAuthority := rawURL
	query := ""
	if queryIndex := strings.IndexByte(rawURL, '?'); queryIndex >= 0 {
		pathAndAuthority = rawURL[:queryIndex]
		query = rawURL[queryIndex:]
	}
	if !strings.HasSuffix(pathAndAuthority, escapedPath) {
		return "", errors.New("presigned URL path bytes are not canonical")
	}
	mutated := strings.TrimSuffix(pathAndAuthority, escapedPath) + mutatedPath + query
	mutatedURL, err := url.Parse(mutated)
	if err != nil || mutatedURL.Scheme != parsed.Scheme || mutatedURL.Host != parsed.Host ||
		mutatedURL.RawQuery != parsed.RawQuery || mutatedURL.Fragment != "" ||
		mutatedURL.Path != strings.TrimSuffix(parsed.Path, sourceSuffix)+"/"+targetKey {
		return "", errors.New("could not preserve the presigned URL while replacing its exact key")
	}
	return mutated, nil
}

func escapePresignedGetProbeKey(key string) string {
	segments := strings.Split(key, "/")
	for index := range segments {
		segments[index] = url.PathEscape(segments[index])
	}
	return strings.Join(segments, "/")
}

func equalProbeBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	difference := byte(0)
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

type presignedGetProbeCleanupCandidate struct {
	key   string
	owned bool
}

func reconcilePresignedGetProbeCreate(
	ctx context.Context,
	store *Store,
	key string,
	payload []byte,
	createErr error,
) (s3disk.Version, error) {
	// A conditional PUT may commit and lose its response; a retry then sees the
	// new object and returns 412. Both the key and payload contain the same fresh
	// cryptographic nonce, so an exact credentialed read-back of those bytes is
	// the ownership witness used to reconcile that ambiguous result.
	observed, err := store.Get(ctx, key, s3disk.GetOptions{MaxBytes: maximumPresignedGetProbeResponseBytes})
	if err == nil && equalProbeBytes(observed.Data, payload) {
		return observed.Version, nil
	}
	return s3disk.Version{}, createErr
}

func cleanupPresignedGetProbe(store *Store, candidates []presignedGetProbeCleanupCandidate, timeout time.Duration) PresignedGetCompatibilityCleanupReport {
	report := PresignedGetCompatibilityCleanupReport{Status: PresignedGetCompatibilityCleanupNotAttempted}
	if store == nil || len(candidates) == 0 {
		return report
	}
	report.Attempted = len(candidates)
	report.HistoricalVersionsMayRemain = true
	cleanupCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var classified error
	for _, candidate := range candidates {
		var deleteErr error
		if candidate.owned {
			deleteErr = store.Delete(cleanupCtx, candidate.key)
		}
		_, headErr := store.Head(cleanupCtx, candidate.key)
		if errors.Is(headErr, s3disk.ErrObjectNotFound) {
			report.Succeeded++
			continue
		}
		report.Failed++
		report.CurrentObjectsMayRemain = true
		if classified == nil {
			if !candidate.owned && headErr == nil {
				// An attempted create whose ownership could not be reconciled must
				// never cause deletion of a possibly pre-existing object.
				classified = s3disk.ErrStoreIncompatible
			} else if headErr != nil {
				classified = safePresignedGetCause(headErr)
			} else if deleteErr != nil {
				classified = safePresignedGetCause(deleteErr)
			} else {
				classified = s3disk.ErrStoreIncompatible
			}
		}
	}
	if report.Failed == 0 {
		report.Status = PresignedGetCompatibilityCleanupSucceeded
		report.Detail = "all current probe objects are absent"
		return report
	}
	report.Status = PresignedGetCompatibilityCleanupFailed
	report.Reason = presignedGetReasonForCause(classified)
	report.Detail = "one or more current probe objects could not be proven absent"
	report.Cause = classified
	return report
}

type presignedGetCompatibilityRecorder struct {
	report *PresignedGetCompatibilityReport
}

func newPresignedGetCompatibilityEvidence(writer, presigningStore *Store) PresignedGetCompatibilityEvidence {
	evidence := PresignedGetCompatibilityEvidence{}
	switch {
	case writer == nil || presigningStore == nil:
		return evidence
	case writer == presigningStore:
		evidence.PresigningTopology = PresignedGetCompatibilitySameStore
	default:
		evidence.PresigningTopology = PresignedGetCompatibilitySeparateStore
		evidence.PresigningStoreInputDistinct = true
	}
	return evidence
}

func newPresignedGetCompatibilityReport(evidence PresignedGetCompatibilityEvidence) PresignedGetCompatibilityReport {
	scope := PresignedGetCompatibilitySingleEndpointFiniteProbe
	bindingLimitation := PresignedGetCompatibilityLimitationBucketAndOriginBindingNotSampled
	if evidence.PresigningTopology == PresignedGetCompatibilitySeparateStore {
		scope = PresignedGetCompatibilityCrossConfigurationFiniteProbe
		bindingLimitation = PresignedGetCompatibilityLimitationCrossConfigurationBindingNotAuthenticated
	}
	return PresignedGetCompatibilityReport{
		Scope:          scope,
		Evidence:       evidence,
		Status:         PresignedGetCompatibilityIndeterminate,
		RequiredChecks: PresignedGetCompatibilityRequiredChecks,
		Checks:         make([]PresignedGetCompatibilityCheck, 0, PresignedGetCompatibilityRequiredChecks),
		Limitations: []PresignedGetCompatibilityLimitation{
			PresignedGetCompatibilityLimitationFutureStatesNotProven,
			PresignedGetCompatibilityLimitationExpiryNotSampled,
			PresignedGetCompatibilityLimitationOtherMethodsNotSampled,
			PresignedGetCompatibilityLimitationArbitraryQueryBindingNotProven,
			PresignedGetCompatibilityLimitationHEADAndBodylessStatusWireBodyNotVisible,
			PresignedGetCompatibilityLimitationDiscardedWireMetadataAndExtraBytes,
			PresignedGetCompatibilityLimitationBucketPublicAccessPolicyNotFullyProven,
			PresignedGetCompatibilityLimitationPUTPayloadVariantsBeyondNamedSamples,
			PresignedGetCompatibilityLimitationArbitraryUnsignedHeaderOverrideBinding,
			bindingLimitation,
		},
		Cleanup: PresignedGetCompatibilityCleanupReport{Status: PresignedGetCompatibilityCleanupNotAttempted},
	}
}

func (recorder presignedGetCompatibilityRecorder) pass(id PresignedGetCompatibilityCheckID, detail string) {
	recorder.report.Checks = append(recorder.report.Checks, PresignedGetCompatibilityCheck{
		ID: id, Status: PresignedGetCompatibilityPassed, Summary: presignedGetCheckSummary(id), Detail: detail,
	})
	recorder.report.Complete = len(recorder.report.Checks) == recorder.report.RequiredChecks
}

func (recorder presignedGetCompatibilityRecorder) problem(
	id PresignedGetCompatibilityCheckID,
	status PresignedGetCompatibilityStatus,
	reason PresignedGetCompatibilityReason,
	detail string,
	cause error,
) error {
	safeCause := safePresignedGetCause(cause)
	recorder.report.Checks = append(recorder.report.Checks, PresignedGetCompatibilityCheck{
		ID: id, Status: status, Reason: reason, Summary: presignedGetCheckSummary(id), Detail: detail, Cause: safeCause,
	})
	recorder.report.Status = status
	recorder.report.Compatible = false
	recorder.report.Complete = len(recorder.report.Checks) == recorder.report.RequiredChecks
	return &PresignedGetCompatibilityError{CheckID: id, Status: status, Reason: reason, Detail: detail, Cause: safeCause}
}

func presignedGetCheckSummary(id PresignedGetCompatibilityCheckID) string {
	switch id {
	case PresignedGetCompatibilityCheckConfiguration:
		return "validate bounded probe configuration"
	case PresignedGetCompatibilityCheckProbeObjectCreate:
		return "create isolated source and path-binding target objects"
	case PresignedGetCompatibilityCheckExactGetPresign:
		return "issue an exact-key GET bearer"
	case PresignedGetCompatibilityCheckAnonymousHeaders:
		return "exclude credential and cookie headers from B-side requests"
	case PresignedGetCompatibilityCheckInitialGet:
		return "read v1 anonymously with a non-empty ETag"
	case PresignedGetCompatibilityCheckSameURLReplacement:
		return "observe A-side replacement through the same fixed URL"
	case PresignedGetCompatibilityCheckCurrentETagConditional:
		return "return bodyless 304 for the current ETag"
	case PresignedGetCompatibilityCheckStaleETagConditional:
		return "return current bytes for a stale ETag"
	case PresignedGetCompatibilityCheckAuthorizationQueryBinding:
		return "reject reuse after changing the signed authorization expiry query"
	case PresignedGetCompatibilityCheckAnonymousPolicyRejected:
		return "reject unsigned anonymous GET, PUT, and DELETE while preserving both canaries"
	case PresignedGetCompatibilityCheckNamedUnsignedHeaderOverrides:
		return "confine named unsigned method and path override headers to the signed source GET"
	case PresignedGetCompatibilityCheckExactPathBinding:
		return "reject reuse of one bearer for another existing key"
	case PresignedGetCompatibilityCheckHEADMutationRejected:
		return "reject sampled HEAD reuse of an exact GET bearer"
	case PresignedGetCompatibilityCheckPUTRejectedUnchanged:
		return "reject sampled zero-byte and non-empty PUTs while preserving both canaries"
	default:
		return "unknown presigned GET compatibility assertion"
	}
}

func presignedGetFailureClassification(cause error) (PresignedGetCompatibilityStatus, PresignedGetCompatibilityReason) {
	status := PresignedGetCompatibilityIndeterminate
	switch {
	case errors.Is(cause, s3disk.ErrStoreIncompatible), errors.Is(cause, s3disk.ErrStoreOperationUnsupported):
		status = PresignedGetCompatibilityIncompatible
	case errors.Is(cause, s3disk.ErrStoreMisconfigured), errors.Is(cause, s3disk.ErrBucketNotFound):
		status = PresignedGetCompatibilityConfigurationError
	case errors.Is(cause, s3disk.ErrAccessDenied):
		status = PresignedGetCompatibilityPermissionDenied
	}
	return status, presignedGetReasonForCause(cause)
}

func presignedGetReasonForCause(cause error) PresignedGetCompatibilityReason {
	switch {
	case errors.Is(cause, context.Canceled):
		return PresignedGetCompatibilityReasonCanceled
	case errors.Is(cause, context.DeadlineExceeded):
		return PresignedGetCompatibilityReasonDeadlineExceeded
	case errors.Is(cause, s3disk.ErrStoreOperationUnsupported):
		return PresignedGetCompatibilityReasonOperationUnsupported
	case errors.Is(cause, s3disk.ErrStoreMisconfigured), errors.Is(cause, s3disk.ErrBucketNotFound):
		return PresignedGetCompatibilityReasonInvalidConfiguration
	case errors.Is(cause, s3disk.ErrAccessDenied):
		return PresignedGetCompatibilityReasonAccessDenied
	case errors.Is(cause, s3disk.ErrRateLimited):
		return PresignedGetCompatibilityReasonRateLimited
	case errors.Is(cause, s3disk.ErrStoreUnavailable):
		return PresignedGetCompatibilityReasonStoreUnavailable
	case errors.Is(cause, s3disk.ErrStoreIncompatible):
		return PresignedGetCompatibilityReasonSemanticViolation
	}
	var netErr net.Error
	if errors.As(cause, &netErr) {
		if netErr.Timeout() {
			return PresignedGetCompatibilityReasonDeadlineExceeded
		}
		return PresignedGetCompatibilityReasonNetworkError
	}
	return PresignedGetCompatibilityReasonUnknownOperational
}

func presignedGetHTTPFailureClassification(statusCode int) (PresignedGetCompatibilityStatus, PresignedGetCompatibilityReason) {
	switch {
	case statusCode == http.StatusRequestTimeout:
		return PresignedGetCompatibilityIndeterminate, PresignedGetCompatibilityReasonDeadlineExceeded
	case statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden:
		return PresignedGetCompatibilityPermissionDenied, PresignedGetCompatibilityReasonAccessDenied
	case statusCode == http.StatusMethodNotAllowed || statusCode == http.StatusNotImplemented:
		return PresignedGetCompatibilityIncompatible, PresignedGetCompatibilityReasonOperationUnsupported
	case statusCode == http.StatusTooManyRequests:
		return PresignedGetCompatibilityIndeterminate, PresignedGetCompatibilityReasonRateLimited
	case statusCode >= 500:
		return PresignedGetCompatibilityIndeterminate, PresignedGetCompatibilityReasonStoreUnavailable
	case statusCode >= 300 && statusCode < 400:
		return PresignedGetCompatibilityConfigurationError, PresignedGetCompatibilityReasonInvalidConfiguration
	default:
		return PresignedGetCompatibilityIncompatible, PresignedGetCompatibilityReasonSemanticViolation
	}
}

func presignedGetPathMutationRejectionStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return true
	default:
		return false
	}
}

func presignedGetAuthorizationQueryMutationRejectionStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return true
	default:
		return false
	}
}

func presignedGetMethodMutationRejectionStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusMethodNotAllowed:
		return true
	default:
		return false
	}
}

func safePresignedGetCause(cause error) error {
	if cause == nil {
		return nil
	}
	for _, sentinel := range []error{
		context.Canceled, context.DeadlineExceeded,
		s3disk.ErrStoreIncompatible, s3disk.ErrStoreOperationUnsupported,
		s3disk.ErrStoreMisconfigured, s3disk.ErrBucketNotFound,
		s3disk.ErrAccessDenied, s3disk.ErrRateLimited, s3disk.ErrStoreUnavailable,
		s3disk.ErrResourceLimit, s3disk.ErrPrecondition, s3disk.ErrObjectNotFound,
	} {
		if errors.Is(cause, sentinel) {
			return sentinel
		}
	}
	var netErr net.Error
	if errors.As(cause, &netErr) {
		return presignedGetProbeNetworkError{timeout: netErr.Timeout()}
	}
	return errors.New("redacted operational error")
}
