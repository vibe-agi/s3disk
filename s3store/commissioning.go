package s3store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vibe-agi/s3disk"
)

const (
	// S3CommissioningReportSchemaVersion identifies the JSON envelope and the
	// aggregation semantics implemented by ProbeCommissioning. The nested
	// writable-store report retains its own independent contract version.
	S3CommissioningReportSchemaVersion = 1

	// S3CommissioningDefaultTimeout bounds both active probe phases when the
	// caller supplies neither an explicit timeout nor a context deadline.
	S3CommissioningDefaultTimeout = s3disk.StoreCompatibilityDefaultTimeout + PresignedGetCompatibilityDefaultTimeout

	// S3CommissioningMaximumTimeout prevents an accidental unbounded combined
	// commissioning run. Independently bounded cleanup may extend wall time.
	S3CommissioningMaximumTimeout = 30 * time.Minute

	// S3CommissioningDefaultWritableStoreTimeout bounds the writable Store
	// phase independently of the combined parent deadline.
	S3CommissioningDefaultWritableStoreTimeout = s3disk.StoreCompatibilityDefaultTimeout

	s3CommissioningRepositoryPrefixFingerprintDomain = "s3disk:s3-commissioning:repository-prefix:v1\x00"
	s3CommissioningPresignedPrefixFingerprintDomain  = "s3disk:s3-commissioning:presigned-prefix:v1\x00"
	s3CommissioningDerivedPresignedSuffix            = ".s3disk/v1/probes/presigned-get"
	s3CommissioningWritableStoreContenders           = 8
)

// S3CommissioningScope describes the finite population sampled by a report.
// A successful run is evidence for one configured Store or Store pair and one
// invocation; it is not a proof about every gateway, network schedule, or
// future state.
type S3CommissioningScope string

const S3CommissioningSingleProcessDualFiniteProbe S3CommissioningScope = "single_process_dual_finite_probe"

// S3CommissioningStatus is the aggregate state of the two required probes.
type S3CommissioningStatus string

const (
	S3CommissioningPassed             S3CommissioningStatus = "passed"
	S3CommissioningIncompatible       S3CommissioningStatus = "incompatible"
	S3CommissioningIndeterminate      S3CommissioningStatus = "indeterminate"
	S3CommissioningConfigurationError S3CommissioningStatus = "configuration_error"
	S3CommissioningPermissionDenied   S3CommissioningStatus = "permission_denied"
)

// S3CommissioningProbeOptions configures one combined writable-store and
// credential-free presigned-GET commissioning run. RepositoryPrefix and the
// presigned object-key prefix are never copied into reports or ordinary
// diagnostics. TLSRootCAPEM is size-checked, then copied before validation and
// use.
//
// Because the anonymous probe must create exact HTTP routes inside the same
// namespace, RepositoryPrefix is currently restricted to the canonical ASCII
// prefix syntax accepted by PresignedGetCompatibilityProbeOptions. This is
// narrower than the full UTF-8 prefix syntax accepted by s3disk.NewRepository.
//
// DeploymentFingerprint, EvidenceID, and ImplementationVersion follow the
// same syntax as s3disk.StoreCompatibilityProbeOptions. They are unverified
// caller declarations and must contain no credentials or secrets. For split
// commissioning, the deployment inventory hashed into DeploymentFingerprint
// should cover both principal/policy configurations, the bucket, both routes,
// region/addressing/TLS settings, and the implementation build.
type S3CommissioningProbeOptions struct {
	RepositoryPrefix      string
	PresignedGet          PresignedGetCompatibilityProbeOptions
	DeploymentFingerprint string
	EvidenceID            string
	ImplementationVersion string
	// TotalTimeout bounds both active phases. Zero preserves an existing
	// caller deadline or selects S3CommissioningDefaultTimeout when none exists.
	// Each nested probe and both cleanup paths retain their own stricter bounds.
	TotalTimeout time.Duration
	// WritableStoreTimeout bounds only the writable Store phase. Zero selects
	// S3CommissioningDefaultWritableStoreTimeout. A shorter combined context
	// deadline still wins naturally.
	WritableStoreTimeout time.Duration
}

// MarshalJSON exposes only bounded, non-secret commissioning controls. Raw
// prefixes, trust roots, HTTP client state, and bearer-capable data are omitted.
func (options S3CommissioningProbeOptions) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		DeploymentFingerprint            string        `json:"deployment_fingerprint,omitempty"`
		EvidenceID                       string        `json:"evidence_id,omitempty"`
		ImplementationVersion            string        `json:"implementation_version,omitempty"`
		TotalTimeout                     time.Duration `json:"total_timeout_nanoseconds"`
		WritableStoreTimeout             time.Duration `json:"writable_store_timeout_nanoseconds"`
		PresignedTotalTimeout            time.Duration `json:"presigned_total_timeout_nanoseconds"`
		PresignedCapabilityLifetime      time.Duration `json:"presigned_capability_lifetime_nanoseconds"`
		PresignedCleanupTimeout          time.Duration `json:"presigned_cleanup_timeout_nanoseconds"`
		PresignedTLSRootsConfigured      bool          `json:"presigned_tls_roots_configured"`
		PresignedHTTPClientConfigured    bool          `json:"presigned_http_client_configured"`
		DangerouslyAllowSystemTrustStore bool          `json:"dangerously_allow_system_trust_store"`
	}{
		DeploymentFingerprint:            options.DeploymentFingerprint,
		EvidenceID:                       options.EvidenceID,
		ImplementationVersion:            options.ImplementationVersion,
		TotalTimeout:                     options.TotalTimeout,
		WritableStoreTimeout:             options.WritableStoreTimeout,
		PresignedTotalTimeout:            options.PresignedGet.TotalTimeout,
		PresignedCapabilityLifetime:      options.PresignedGet.CapabilityLifetime,
		PresignedCleanupTimeout:          options.PresignedGet.CleanupTimeout,
		PresignedTLSRootsConfigured:      len(options.PresignedGet.TLSRootCAPEM) != 0,
		PresignedHTTPClientConfigured:    options.PresignedGet.HTTPClient != nil,
		DangerouslyAllowSystemTrustStore: options.PresignedGet.DangerouslyAllowSystemTrustStore,
	})
}

func (options S3CommissioningProbeOptions) String() string {
	encoded, err := options.MarshalJSON()
	if err != nil {
		return "s3store.S3CommissioningProbeOptions{redacted}"
	}
	return "s3store.S3CommissioningProbeOptions(" + string(encoded) + ")"
}

func (options S3CommissioningProbeOptions) GoString() string { return options.String() }

// S3CommissioningEvidence binds the combined envelope to time, a random run
// identity, two domain-separated namespace fingerprints, and optional caller
// declarations. It is audit metadata, not an authenticated attestation.
// Predictable prefixes may still be susceptible to offline dictionary guesses.
type S3CommissioningEvidence struct {
	SchemaVersion                           int                                         `json:"schema_version"`
	StartedAt                               time.Time                                   `json:"started_at"`
	DurationNanoseconds                     int64                                       `json:"duration_nanoseconds"`
	RunID                                   string                                      `json:"run_id,omitempty"`
	RepositoryPrefixFingerprint             string                                      `json:"repository_prefix_fingerprint,omitempty"`
	PresignedPrefixFingerprint              string                                      `json:"presigned_prefix_fingerprint,omitempty"`
	PresignedPrefixDerived                  bool                                        `json:"presigned_prefix_derived"`
	PresignedPrefixRepositoryScoped         bool                                        `json:"presigned_prefix_repository_scoped"`
	DeploymentFingerprint                   string                                      `json:"deployment_fingerprint,omitempty"`
	EvidenceID                              string                                      `json:"evidence_id,omitempty"`
	ImplementationVersion                   string                                      `json:"implementation_version,omitempty"`
	PresigningTopology                      PresignedGetCompatibilityPresigningTopology `json:"presigning_topology,omitempty"`
	PresigningStoreInputDistinct            bool                                        `json:"presigning_store_input_distinct"`
	CrossConfigurationCanaryBindingObserved bool                                        `json:"cross_configuration_canary_binding_observed"`
	// FullyBound reports syntactic completeness only; it is not authentication.
	FullyBound bool `json:"fully_bound"`
}

func (evidence S3CommissioningEvidence) String() string {
	encoded, err := json.Marshal(evidence)
	if err != nil {
		return "s3store.S3CommissioningEvidence{redacted}"
	}
	return "s3store.S3CommissioningEvidence(" + string(encoded) + ")"
}

func (evidence S3CommissioningEvidence) GoString() string { return evidence.String() }

// S3CommissioningStageOutcome records whether a required phase was invoked
// and, if so, whether its semantic probe passed. Cleanup is outside this value.
type S3CommissioningStageOutcome string

const (
	S3CommissioningStageNotRun S3CommissioningStageOutcome = "not_run"
	S3CommissioningStagePassed S3CommissioningStageOutcome = "passed"
	S3CommissioningStageFailed S3CommissioningStageOutcome = "failed"
)

// S3CommissioningCleanupSummary provides one operational view over both
// nested cleanup reports. It never changes Compatible or stage outcomes.
type S3CommissioningCleanupSummary struct {
	WritableStoreStatus         s3disk.StoreCompatibilityCleanupStatus `json:"writable_store_status"`
	PresignedGetStatus          PresignedGetCompatibilityCleanupStatus `json:"presigned_get_status"`
	CurrentObjectsMayRemain     bool                                   `json:"current_objects_may_remain"`
	HistoricalVersionsMayRemain bool                                   `json:"historical_versions_may_remain"`
	AttentionRequired           bool                                   `json:"attention_required"`
}

// S3CommissioningReport preserves both nested reports even when one stage
// fails. Compatible is true only when both required probes pass. Complete
// reports whether both nested check sets completed, independently of pass or
// failure. Cleanup state is intentionally outside compatibility.
type S3CommissioningReport struct {
	SchemaVersion        int                             `json:"schema_version"`
	Scope                S3CommissioningScope            `json:"scope"`
	Evidence             S3CommissioningEvidence         `json:"evidence"`
	Status               S3CommissioningStatus           `json:"status"`
	Compatible           bool                            `json:"compatible"`
	Complete             bool                            `json:"complete"`
	WritableStoreOutcome S3CommissioningStageOutcome     `json:"writable_store_outcome"`
	PresignedGetOutcome  S3CommissioningStageOutcome     `json:"presigned_get_outcome"`
	WritableStore        s3disk.StoreCompatibilityReport `json:"writable_store"`
	PresignedGet         PresignedGetCompatibilityReport `json:"presigned_get"`
	Cleanup              S3CommissioningCleanupSummary   `json:"cleanup"`
}

func (report S3CommissioningReport) String() string {
	encoded, err := json.Marshal(report)
	if err != nil {
		return "s3store.S3CommissioningReport{redacted}"
	}
	return "s3store.S3CommissioningReport(" + string(encoded) + ")"
}

func (report S3CommissioningReport) GoString() string { return report.String() }

// S3CommissioningError safely aggregates one or both phase errors. Ordinary
// formatting and JSON expose no underlying SDK error because such errors can
// contain endpoint URLs or signed query parameters. Unwrap retains each error
// for errors.Is and errors.As without weakening diagnostic redaction.
type S3CommissioningError struct {
	Status               S3CommissioningStatus
	WritableStoreOutcome S3CommissioningStageOutcome
	PresignedGetOutcome  S3CommissioningStageOutcome

	overall       s3CommissioningSafeCause
	writableStore s3CommissioningSafeCause
	presignedGet  s3CommissioningSafeCause
}

func (probeErr S3CommissioningError) Error() string {
	return fmt.Sprintf(
		"s3store: S3 commissioning %s (overall=%s, writable_store=%s, presigned_get=%s)",
		probeErr.Status,
		s3CommissioningErrorState(probeErr.overall.configured()),
		normalizeS3CommissioningStageOutcome(probeErr.WritableStoreOutcome),
		normalizeS3CommissioningStageOutcome(probeErr.PresignedGetOutcome),
	)
}

func (probeErr S3CommissioningError) String() string   { return probeErr.Error() }
func (probeErr S3CommissioningError) GoString() string { return probeErr.Error() }

// Unwrap returns a fresh slice so callers cannot mutate the error's state.
func (probeErr S3CommissioningError) Unwrap() []error {
	errorsToUnwrap := make([]error, 0, 3)
	if probeErr.overall.configured() {
		errorsToUnwrap = append(errorsToUnwrap, probeErr.overall.original)
	}
	if probeErr.writableStore.configured() {
		errorsToUnwrap = append(errorsToUnwrap, probeErr.writableStore.original)
	}
	if probeErr.presignedGet.configured() {
		errorsToUnwrap = append(errorsToUnwrap, probeErr.presignedGet.original)
	}
	return errorsToUnwrap
}

// Is gives aggregate semantic incompatibility the same sentinel behavior as
// each nested probe while all other classifications continue through Unwrap.
func (probeErr S3CommissioningError) Is(target error) bool {
	return target == s3disk.ErrStoreIncompatible && probeErr.Status == S3CommissioningIncompatible
}

// OverallError returns a combined lifecycle or configuration error that is
// not attributable to either probe phase. Do not log arbitrary returned causes.
func (probeErr S3CommissioningError) OverallError() error {
	return probeErr.overall.original
}

// WritableStoreError returns the in-process writable probe error, if any.
// Callers must not log the returned value because SDK errors may contain URLs.
func (probeErr S3CommissioningError) WritableStoreError() error {
	return probeErr.writableStore.original
}

// PresignedGetError returns the safe presigned-GET error, if any.
func (probeErr S3CommissioningError) PresignedGetError() error {
	return probeErr.presignedGet.original
}

// MarshalJSON uses a value receiver so a copied error has the same safe schema
// as the constructor-returned pointer. Causes remain available only in process.
func (probeErr S3CommissioningError) MarshalJSON() ([]byte, error) {
	writableOutcome := normalizeS3CommissioningStageOutcome(probeErr.WritableStoreOutcome)
	presignedOutcome := normalizeS3CommissioningStageOutcome(probeErr.PresignedGetOutcome)
	return json.Marshal(struct {
		Status               S3CommissioningStatus       `json:"status"`
		OverallFailed        bool                        `json:"overall_failed"`
		WritableStoreOutcome S3CommissioningStageOutcome `json:"writable_store_outcome"`
		PresignedGetOutcome  S3CommissioningStageOutcome `json:"presigned_get_outcome"`
		WritableStoreFailed  bool                        `json:"writable_store_failed"`
		PresignedGetFailed   bool                        `json:"presigned_get_failed"`
	}{
		Status:               probeErr.Status,
		OverallFailed:        probeErr.overall.configured(),
		WritableStoreOutcome: writableOutcome,
		PresignedGetOutcome:  presignedOutcome,
		WritableStoreFailed:  writableOutcome == S3CommissioningStageFailed,
		PresignedGetFailed:   presignedOutcome == S3CommissioningStageFailed,
	})
}

// s3CommissioningSafeCause prevents raw SDK URLs from resurfacing if an
// aggregate error is copied and formatted reflectively. Unwrap and accessors
// deliberately return original instead of this diagnostic facade.
type s3CommissioningSafeCause struct {
	original error
}

func newS3CommissioningSafeCause(original error) s3CommissioningSafeCause {
	return s3CommissioningSafeCause{original: original}
}

func (cause s3CommissioningSafeCause) configured() bool { return cause.original != nil }

func (cause s3CommissioningSafeCause) Error() string {
	if !cause.configured() {
		return "none"
	}
	return "redacted"
}

func (cause s3CommissioningSafeCause) String() string   { return cause.Error() }
func (cause s3CommissioningSafeCause) GoString() string { return cause.Error() }

func (cause s3CommissioningSafeCause) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Present bool `json:"present"`
	}{Present: cause.configured()})
}

// ProbeCommissioning runs the writable 31-check Store contract probe followed
// by the credential-free 14-check presigned-GET probe. A phase error does not
// suppress the other phase while the shared overall context remains live.
// Invalid options are rejected before Store I/O.
func (store *Store) ProbeCommissioning(
	ctx context.Context,
	options S3CommissioningProbeOptions,
) (report S3CommissioningReport, resultErr error) {
	return store.probeCommissioning(ctx, store, options, false)
}

// ProbeCommissioningWithPresigningStore runs the writable Store contract with
// the receiver and the anonymous exact-GET contract with a separately
// constructed presigning Store. Credentialed canary operations and cleanup use
// only the receiver; the presigning Store is used only to create GET bearers.
// The method rejects the same Store, a shared SDK client, or different bucket
// names before S3 I/O.
func (store *Store) ProbeCommissioningWithPresigningStore(
	ctx context.Context,
	presigningStore *Store,
	options S3CommissioningProbeOptions,
) (S3CommissioningReport, error) {
	return store.probeCommissioning(ctx, presigningStore, options, true)
}

func (store *Store) probeCommissioning(
	ctx context.Context,
	presigningStore *Store,
	options S3CommissioningProbeOptions,
	requireSeparateStore bool,
) (report S3CommissioningReport, resultErr error) {
	started := time.Now()
	presigningEvidence := newPresignedGetCompatibilityEvidence(store, presigningStore)
	report = newS3CommissioningReport(started, presigningEvidence)
	defer func() {
		duration := time.Since(started)
		if duration < 0 {
			duration = 0
		}
		report.Evidence.DurationNanoseconds = duration.Nanoseconds()
		report.Evidence.CrossConfigurationCanaryBindingObserved =
			report.PresignedGet.Evidence.CrossConfigurationCanaryBindingObserved
		report.Cleanup = summarizeS3CommissioningCleanup(report.WritableStore.Cleanup, report.PresignedGet.Cleanup)
	}()
	runID, randomErr := newS3CommissioningRunID()
	if randomErr != nil {
		return report, newS3CommissioningReportError(report, randomErr, nil, nil)
	}
	report.Evidence.RunID = runID

	if ctx == nil || interfaceIsNil(ctx) {
		report.Status = S3CommissioningConfigurationError
		return report, newS3CommissioningReportError(
			report, fmt.Errorf("%w: commissioning context is nil", s3disk.ErrStoreMisconfigured), nil, nil,
		)
	}
	if err := validatePresignedGetStorePair(store, presigningStore, requireSeparateStore); err != nil {
		report.Status = S3CommissioningConfigurationError
		return report, newS3CommissioningReportError(
			report, err, nil, nil,
		)
	}
	if len(options.PresignedGet.TLSRootCAPEM) > maximumPresignedGetProbeTLSRootCAPEMBytes {
		report.Status = S3CommissioningConfigurationError
		return report, newS3CommissioningReportError(
			report,
			fmt.Errorf(
				"%w: commissioning TLS roots exceed %d bytes: %w",
				s3disk.ErrStoreMisconfigured,
				maximumPresignedGetProbeTLSRootCAPEMBytes,
				s3disk.ErrResourceLimit,
			),
			nil,
			nil,
		)
	}

	options = cloneS3CommissioningProbeOptions(options)
	repository, repositoryErr := s3disk.NewRepository(store, options.RepositoryPrefix)
	if repositoryErr != nil {
		report.Status = S3CommissioningConfigurationError
		return report, newS3CommissioningReportError(
			report,
			fmt.Errorf("%w: commissioning repository configuration is invalid: %w", s3disk.ErrStoreMisconfigured, repositoryErr),
			nil, nil,
		)
	}
	normalized, validationErr := normalizeS3CommissioningProbeOptions(presigningStore, &options, strings.Trim(options.RepositoryPrefix, "/"))
	if validationErr != nil {
		report.Status = S3CommissioningConfigurationError
		return report, newS3CommissioningReportError(
			report, fmt.Errorf("%w: commissioning options are invalid: %w", s3disk.ErrStoreMisconfigured, validationErr), nil, nil,
		)
	}
	report.Evidence = newS3CommissioningEvidence(options, normalized, presigningEvidence, runID, started)

	probeCtx, cancel := s3CommissioningProbeContext(ctx, options.TotalTimeout)
	defer cancel()
	if err := probeCtx.Err(); err != nil {
		report.Status = S3CommissioningIndeterminate
		return report, newS3CommissioningReportError(report, err, nil, nil)
	}

	var writableErr error
	report.WritableStore, writableErr = repository.ProbeStoreCompatibilityWithOptions(
		probeCtx,
		s3disk.StoreCompatibilityProbeOptions{
			DeploymentFingerprint: options.DeploymentFingerprint,
			EvidenceID:            options.EvidenceID,
			ImplementationVersion: options.ImplementationVersion,
			TotalTimeout:          normalized.WritableStoreTimeout,
		},
	)
	report.WritableStoreOutcome = writableS3CommissioningStageOutcome(report.WritableStore, writableErr)

	var overallErr, presignedErr error
	if err := probeCtx.Err(); err == nil {
		report.PresignedGet, presignedErr = store.probePresignedGetCompatibility(
			probeCtx, presigningStore, options.PresignedGet, requireSeparateStore,
		)
		report.PresignedGetOutcome = presignedS3CommissioningStageOutcome(report.PresignedGet, presignedErr)
	} else {
		overallErr = err
	}

	report.Status = aggregateS3CommissioningStatus(report.WritableStore.Status, report.PresignedGet.Status)
	report.Compatible = report.WritableStoreOutcome == S3CommissioningStagePassed &&
		report.PresignedGetOutcome == S3CommissioningStagePassed
	report.Complete = report.WritableStore.Complete && report.PresignedGet.Complete
	if report.Compatible {
		return report, nil
	}
	if report.Status == S3CommissioningPassed {
		report.Status = S3CommissioningIndeterminate
	}
	if overallErr == nil && writableErr == nil && presignedErr == nil {
		overallErr = errors.New("s3store: one or more commissioning phases did not produce a passing report")
	}
	return report, newS3CommissioningReportError(report, overallErr, writableErr, presignedErr)
}

func newS3CommissioningReport(
	started time.Time,
	presigningEvidence PresignedGetCompatibilityEvidence,
) S3CommissioningReport {
	report := S3CommissioningReport{
		SchemaVersion: S3CommissioningReportSchemaVersion,
		Scope:         S3CommissioningSingleProcessDualFiniteProbe,
		Evidence: S3CommissioningEvidence{
			SchemaVersion:                S3CommissioningReportSchemaVersion,
			StartedAt:                    started.UTC(),
			PresigningTopology:           presigningEvidence.PresigningTopology,
			PresigningStoreInputDistinct: presigningEvidence.PresigningStoreInputDistinct,
		},
		Status:               S3CommissioningIndeterminate,
		WritableStoreOutcome: S3CommissioningStageNotRun,
		PresignedGetOutcome:  S3CommissioningStageNotRun,
		WritableStore:        newS3CommissioningWritableStoreReport(started),
		PresignedGet:         newPresignedGetCompatibilityReport(presigningEvidence),
	}
	report.Cleanup = summarizeS3CommissioningCleanup(report.WritableStore.Cleanup, report.PresignedGet.Cleanup)
	return report
}

func newS3CommissioningWritableStoreReport(started time.Time) s3disk.StoreCompatibilityReport {
	return s3disk.StoreCompatibilityReport{
		ContractVersion: s3disk.StoreCompatibilityContractVersion,
		Scope:           s3disk.StoreCompatibilitySingleClientFiniteProbe,
		Evidence: s3disk.StoreCompatibilityEvidence{
			StartedAt: started.UTC(),
		},
		Status:         s3disk.StoreCompatibilityIndeterminate,
		RequiredChecks: s3disk.StoreCompatibilityRequiredChecks,
		Contenders:     s3CommissioningWritableStoreContenders,
		Checks:         make([]s3disk.StoreCompatibilityCheck, 0, s3disk.StoreCompatibilityRequiredChecks),
		Cleanup: s3disk.StoreCompatibilityCleanupReport{
			Status: s3disk.StoreCompatibilityCleanupNotAttempted,
		},
	}
}

func cloneS3CommissioningProbeOptions(options S3CommissioningProbeOptions) S3CommissioningProbeOptions {
	options.PresignedGet.TLSRootCAPEM = append([]byte(nil), options.PresignedGet.TLSRootCAPEM...)
	if options.PresignedGet.HTTPClient != nil {
		client := *options.PresignedGet.HTTPClient
		if transport, ok := client.Transport.(*http.Transport); ok && transport != nil {
			client.Transport = transport.Clone()
		}
		options.PresignedGet.HTTPClient = &client
	}
	return options
}

type normalizedS3CommissioningProbeOptions struct {
	RepositoryPrefix                string
	WritableStoreTimeout            time.Duration
	PresignedGet                    normalizedPresignedGetProbeOptions
	PresignedPrefixDerived          bool
	PresignedPrefixRepositoryScoped bool
}

func normalizeS3CommissioningProbeOptions(
	store *Store,
	options *S3CommissioningProbeOptions,
	repositoryPrefix string,
) (normalizedS3CommissioningProbeOptions, error) {
	if options == nil {
		return normalizedS3CommissioningProbeOptions{}, errors.New("options are nil")
	}
	if options.TotalTimeout < 0 || options.TotalTimeout > S3CommissioningMaximumTimeout {
		return normalizedS3CommissioningProbeOptions{}, errors.New("total timeout is outside the permitted bound")
	}
	writableStoreTimeout := options.WritableStoreTimeout
	if writableStoreTimeout == 0 {
		writableStoreTimeout = S3CommissioningDefaultWritableStoreTimeout
	}
	if writableStoreTimeout < 0 || writableStoreTimeout > s3disk.StoreCompatibilityMaximumTimeout {
		return normalizedS3CommissioningProbeOptions{}, errors.New("writable Store timeout is outside the permitted bound")
	}
	if options.DeploymentFingerprint != "" && !s3CommissioningCanonicalSHA256(options.DeploymentFingerprint) {
		return normalizedS3CommissioningProbeOptions{}, errors.New("deployment fingerprint must be 64 lowercase hexadecimal characters")
	}
	if options.EvidenceID != "" && !s3CommissioningEvidenceID(options.EvidenceID) {
		return normalizedS3CommissioningProbeOptions{}, errors.New("evidence ID has invalid syntax")
	}
	if options.ImplementationVersion != "" && !s3CommissioningImplementationVersion(options.ImplementationVersion) {
		return normalizedS3CommissioningProbeOptions{}, errors.New("implementation version has invalid syntax")
	}
	presignedPrefixDerived := options.PresignedGet.ObjectKeyPrefix == ""
	if presignedPrefixDerived {
		options.PresignedGet.ObjectKeyPrefix = s3CommissioningDerivedPresignedPrefix(repositoryPrefix)
	}
	presignedPrefixScoped := repositoryPrefix == "" ||
		options.PresignedGet.ObjectKeyPrefix == repositoryPrefix ||
		strings.HasPrefix(options.PresignedGet.ObjectKeyPrefix, repositoryPrefix+"/")
	if !presignedPrefixScoped {
		return normalizedS3CommissioningProbeOptions{}, errors.New("presigned object-key prefix is outside the repository namespace")
	}
	normalizedPresigned, client, err := normalizePresignedGetProbeOptions(options.PresignedGet)
	if client != nil {
		client.CloseIdleConnections()
	}
	if err != nil {
		return normalizedS3CommissioningProbeOptions{}, err
	}
	if store.presignedHTTPS && len(options.PresignedGet.TLSRootCAPEM) == 0 && !normalizedPresigned.DangerouslyAllowSystemTrustStore {
		return normalizedS3CommissioningProbeOptions{}, errors.New("HTTPS presigned commissioning requires explicit TLS roots")
	}
	return normalizedS3CommissioningProbeOptions{
		RepositoryPrefix:                repositoryPrefix,
		WritableStoreTimeout:            writableStoreTimeout,
		PresignedGet:                    normalizedPresigned,
		PresignedPrefixDerived:          presignedPrefixDerived,
		PresignedPrefixRepositoryScoped: presignedPrefixScoped,
	}, nil
}

func newS3CommissioningEvidence(
	options S3CommissioningProbeOptions,
	normalized normalizedS3CommissioningProbeOptions,
	presigningEvidence PresignedGetCompatibilityEvidence,
	runID string,
	started time.Time,
) S3CommissioningEvidence {
	evidence := S3CommissioningEvidence{
		SchemaVersion:                   S3CommissioningReportSchemaVersion,
		StartedAt:                       started.UTC(),
		RunID:                           runID,
		RepositoryPrefixFingerprint:     s3CommissioningPrefixFingerprint(s3CommissioningRepositoryPrefixFingerprintDomain, normalized.RepositoryPrefix),
		PresignedPrefixFingerprint:      s3CommissioningPrefixFingerprint(s3CommissioningPresignedPrefixFingerprintDomain, normalized.PresignedGet.ObjectKeyPrefix),
		PresignedPrefixDerived:          normalized.PresignedPrefixDerived,
		PresignedPrefixRepositoryScoped: normalized.PresignedPrefixRepositoryScoped,
		DeploymentFingerprint:           options.DeploymentFingerprint,
		EvidenceID:                      options.EvidenceID,
		ImplementationVersion:           options.ImplementationVersion,
		PresigningTopology:              presigningEvidence.PresigningTopology,
		PresigningStoreInputDistinct:    presigningEvidence.PresigningStoreInputDistinct,
	}
	evidence.FullyBound = evidence.RunID != "" &&
		evidence.RepositoryPrefixFingerprint != "" &&
		evidence.PresignedPrefixFingerprint != "" &&
		evidence.PresignedPrefixRepositoryScoped &&
		evidence.DeploymentFingerprint != "" &&
		evidence.EvidenceID != "" &&
		evidence.ImplementationVersion != ""
	return evidence
}

func s3CommissioningDerivedPresignedPrefix(repositoryPrefix string) string {
	if repositoryPrefix == "" {
		return s3CommissioningDerivedPresignedSuffix
	}
	return repositoryPrefix + "/" + s3CommissioningDerivedPresignedSuffix
}

func s3CommissioningPrefixFingerprint(domain, prefix string) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(domain))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(prefix)))
	_, _ = hasher.Write(size[:])
	_, _ = hasher.Write([]byte(prefix))
	return hex.EncodeToString(hasher.Sum(nil))
}

func newS3CommissioningRunID() (string, error) {
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		return "", errors.New("s3store: could not generate commissioning run identity")
	}
	return hex.EncodeToString(random), nil
}

func s3CommissioningProbeContext(ctx context.Context, totalTimeout time.Duration) (context.Context, context.CancelFunc) {
	if totalTimeout > 0 {
		return context.WithTimeout(ctx, totalTimeout)
	}
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, S3CommissioningDefaultTimeout)
}

func aggregateS3CommissioningStatus(
	writable s3disk.StoreCompatibilityStatus,
	presigned PresignedGetCompatibilityStatus,
) S3CommissioningStatus {
	if writable == s3disk.StoreCompatibilityPassed && presigned == PresignedGetCompatibilityPassed {
		return S3CommissioningPassed
	}
	if writable == s3disk.StoreCompatibilityIncompatible || presigned == PresignedGetCompatibilityIncompatible {
		return S3CommissioningIncompatible
	}
	if writable == s3disk.StoreCompatibilityPermissionDenied || presigned == PresignedGetCompatibilityPermissionDenied {
		return S3CommissioningPermissionDenied
	}
	if writable == s3disk.StoreCompatibilityConfigurationError || presigned == PresignedGetCompatibilityConfigurationError {
		return S3CommissioningConfigurationError
	}
	return S3CommissioningIndeterminate
}

func writableS3CommissioningStageOutcome(report s3disk.StoreCompatibilityReport, probeErr error) S3CommissioningStageOutcome {
	if probeErr == nil && report.Status == s3disk.StoreCompatibilityPassed && report.Compatible && report.Complete {
		return S3CommissioningStagePassed
	}
	return S3CommissioningStageFailed
}

func presignedS3CommissioningStageOutcome(report PresignedGetCompatibilityReport, probeErr error) S3CommissioningStageOutcome {
	if probeErr == nil && report.Status == PresignedGetCompatibilityPassed && report.Compatible && report.Complete {
		return S3CommissioningStagePassed
	}
	return S3CommissioningStageFailed
}

func normalizeS3CommissioningStageOutcome(outcome S3CommissioningStageOutcome) S3CommissioningStageOutcome {
	switch outcome {
	case S3CommissioningStageNotRun, S3CommissioningStagePassed, S3CommissioningStageFailed:
		return outcome
	default:
		return S3CommissioningStageNotRun
	}
}

func summarizeS3CommissioningCleanup(
	writable s3disk.StoreCompatibilityCleanupReport,
	presigned PresignedGetCompatibilityCleanupReport,
) S3CommissioningCleanupSummary {
	currentMayRemain := writable.CurrentObjectsMayRemain || presigned.CurrentObjectsMayRemain
	historicalMayRemain := writable.HistoricalVersionsMayRemain || presigned.HistoricalVersionsMayRemain
	attentionRequired := currentMayRemain || historicalMayRemain ||
		writable.Status == s3disk.StoreCompatibilityCleanupFailed ||
		writable.Status == s3disk.StoreCompatibilityCleanupNotSupported ||
		presigned.Status == PresignedGetCompatibilityCleanupFailed
	return S3CommissioningCleanupSummary{
		WritableStoreStatus:         writable.Status,
		PresignedGetStatus:          presigned.Status,
		CurrentObjectsMayRemain:     currentMayRemain,
		HistoricalVersionsMayRemain: historicalMayRemain,
		AttentionRequired:           attentionRequired,
	}
}

func newS3CommissioningReportError(
	report S3CommissioningReport,
	overall error,
	writableStore error,
	presignedGet error,
) error {
	if overall == nil && writableStore == nil && presignedGet == nil {
		return nil
	}
	return &S3CommissioningError{
		Status:               report.Status,
		WritableStoreOutcome: normalizeS3CommissioningStageOutcome(report.WritableStoreOutcome),
		PresignedGetOutcome:  normalizeS3CommissioningStageOutcome(report.PresignedGetOutcome),
		overall:              newS3CommissioningSafeCause(overall),
		writableStore:        newS3CommissioningSafeCause(writableStore),
		presignedGet:         newS3CommissioningSafeCause(presignedGet),
	}
}

func s3CommissioningErrorState(configured bool) string {
	if !configured {
		return "none"
	}
	return "failed"
}

func s3CommissioningCanonicalSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range []byte(value) {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func s3CommissioningEvidenceID(value string) bool {
	if len(value) == 0 || len(value) > s3disk.StoreCompatibilityEvidenceIDMaxBytes || !s3CommissioningASCIILetterOrDigit(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !s3CommissioningASCIILetterOrDigit(character) && character != '.' && character != '_' && character != ':' && character != '-' {
			return false
		}
	}
	return true
}

func s3CommissioningImplementationVersion(value string) bool {
	if len(value) == 0 || len(value) > s3disk.StoreCompatibilityImplementationVersionMaxBytes || !s3CommissioningASCIILetterOrDigit(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !s3CommissioningASCIILetterOrDigit(character) && character != '.' && character != '_' && character != '+' && character != '-' {
			return false
		}
	}
	return true
}

func s3CommissioningASCIILetterOrDigit(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9'
}
