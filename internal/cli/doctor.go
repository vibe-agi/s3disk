package cli

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/presignedshare"
	"github.com/vibe-agi/s3disk/s3store"
)

const (
	doctorDerivedPresignedPrefixSuffix        = ".s3disk/v1/probes/presigned-get"
	doctorCommissioningRepositoryPrefixDomain = "s3disk:s3-commissioning:repository-prefix:v1\x00"
	doctorCommissioningPresignedPrefixDomain  = "s3disk:s3-commissioning:presigned-prefix:v1\x00"
	doctorWritableRepositoryPrefixDomain      = "s3disk:store-compatibility:repository-prefix:v1\x00"
)

func runDoctor(ctx context.Context, options DoctorOptions, output io.Writer) error {
	if ctx == nil {
		return fmt.Errorf("s3disk s3 doctor: context is required")
	}
	if output == nil {
		return fmt.Errorf("s3disk s3 doctor: output is required")
	}
	tlsRootCAPEM, err := readBoundedFile(options.TLSCAFile, presignedshare.MaximumTLSRootCAPEMBytes)
	if err != nil {
		return fmt.Errorf("s3disk s3 doctor: read TLS CA: %w", err)
	}
	httpClient, err := s3HTTPClient(tlsRootCAPEM)
	if err != nil {
		return fmt.Errorf("s3disk s3 doctor: TLS CA: %w", err)
	}
	store, err := s3store.New(ctx, s3store.Config{
		Bucket:                options.Bucket,
		Region:                options.Region,
		Endpoint:              options.Endpoint,
		ExpectedBucketOwner:   options.ExpectedBucketOwner,
		UsePathStyle:          options.UsePathStyle,
		AllowInsecureEndpoint: options.AllowInsecureEndpoint,
		HTTPClient:            httpClient,
	})
	if err != nil {
		return fmt.Errorf("s3disk s3 doctor: configure store: %w", err)
	}
	return runDoctorCommissioning(ctx, store, options, tlsRootCAPEM, output)
}

type doctorCommissioningProber interface {
	ProbeCommissioning(context.Context, s3store.S3CommissioningProbeOptions) (s3store.S3CommissioningReport, error)
}

func runDoctorCommissioning(
	ctx context.Context,
	prober doctorCommissioningProber,
	options DoctorOptions,
	tlsRootCAPEM []byte,
	output io.Writer,
) error {
	if ctx == nil {
		return errors.New("s3disk s3 doctor: context is required")
	}
	if prober == nil {
		return errors.New("s3disk s3 doctor: commissioning probe is required")
	}
	if output == nil {
		return errors.New("s3disk s3 doctor: output is required")
	}
	report, probeErr := prober.ProbeCommissioning(ctx, s3store.S3CommissioningProbeOptions{
		RepositoryPrefix: options.Prefix,
		PresignedGet: s3store.PresignedGetCompatibilityProbeOptions{
			TotalTimeout:                     options.PresignedTimeout,
			CapabilityLifetime:               options.CapabilityLifetime,
			CleanupTimeout:                   options.CleanupTimeout,
			TLSRootCAPEM:                     append([]byte(nil), tlsRootCAPEM...),
			DangerouslyAllowSystemTrustStore: options.DangerouslyAllowSystemTrust,
		},
		DeploymentFingerprint: options.DeploymentFingerprint,
		EvidenceID:            options.EvidenceID,
		ImplementationVersion: options.ImplementationVersion,
		TotalTimeout:          options.TotalTimeout,
	})
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("s3disk s3 doctor: write report: %w", err)
	}
	if doctorCleanupAttentionRequired(report) && options.ErrorWriter != nil {
		_, _ = io.WriteString(options.ErrorWriter, "s3disk s3 doctor: warning: probe cleanup requires operator attention; inspect the report cleanup summary\n")
	}
	if probeErr != nil || !doctorCommissioningReportPassed(report, options) {
		// Probe errors can wrap SDK responses containing endpoints or signed URLs.
		// Return only the aggregate type whose formatting contract is redacted;
		// arbitrary probe errors are replaced by a fixed diagnostic.
		return safeDoctorCommissioningError(probeErr)
	}
	return nil
}

func doctorCommissioningReportPassed(report s3store.S3CommissioningReport, options DoctorOptions) bool {
	bindingsRequested := options.DeploymentFingerprint != "" || options.EvidenceID != "" ||
		options.ImplementationVersion != ""
	bindingsComplete := options.DeploymentFingerprint != "" && options.EvidenceID != "" &&
		options.ImplementationVersion != ""
	normalizedPrefix := strings.Trim(options.Prefix, "/")
	presignedPrefix := doctorDerivedPresignedPrefixSuffix
	if normalizedPrefix != "" {
		presignedPrefix = normalizedPrefix + "/" + doctorDerivedPresignedPrefixSuffix
	}
	evidence := report.Evidence
	writableEvidence := report.WritableStore.Evidence
	return report.SchemaVersion == s3store.S3CommissioningReportSchemaVersion &&
		report.Scope == s3store.S3CommissioningSingleProcessDualFiniteProbe &&
		evidence.SchemaVersion == s3store.S3CommissioningReportSchemaVersion &&
		!evidence.StartedAt.IsZero() && evidence.DurationNanoseconds >= 0 &&
		doctorCanonicalLowerHex(evidence.RunID, 24) &&
		evidence.RepositoryPrefixFingerprint == doctorCommissioningPrefixFingerprint(
			doctorCommissioningRepositoryPrefixDomain, normalizedPrefix,
		) &&
		evidence.PresignedPrefixFingerprint == doctorCommissioningPrefixFingerprint(
			doctorCommissioningPresignedPrefixDomain, presignedPrefix,
		) &&
		evidence.PresignedPrefixDerived && evidence.PresignedPrefixRepositoryScoped &&
		evidence.DeploymentFingerprint == options.DeploymentFingerprint &&
		evidence.EvidenceID == options.EvidenceID &&
		evidence.ImplementationVersion == options.ImplementationVersion &&
		bindingsRequested == bindingsComplete && evidence.FullyBound == bindingsComplete &&
		report.Status == s3store.S3CommissioningPassed && report.Compatible && report.Complete &&
		report.WritableStoreOutcome == s3store.S3CommissioningStagePassed &&
		report.PresignedGetOutcome == s3store.S3CommissioningStagePassed &&
		report.WritableStore.ContractVersion == s3disk.StoreCompatibilityContractVersion &&
		report.WritableStore.Scope == s3disk.StoreCompatibilitySingleClientFiniteProbe &&
		report.WritableStore.Status == s3disk.StoreCompatibilityPassed &&
		report.WritableStore.Compatible && report.WritableStore.Complete &&
		report.WritableStore.ProbeID != "" &&
		writableEvidence.RepositoryPrefixFingerprint == doctorCommissioningPrefixFingerprint(
			doctorWritableRepositoryPrefixDomain, normalizedPrefix,
		) &&
		!writableEvidence.StartedAt.IsZero() && writableEvidence.DurationNanoseconds >= 0 &&
		writableEvidence.DeploymentFingerprint == options.DeploymentFingerprint &&
		writableEvidence.EvidenceID == options.EvidenceID &&
		writableEvidence.ImplementationVersion == options.ImplementationVersion &&
		writableEvidence.FullyBound == bindingsComplete &&
		doctorWritableChecksPassed(report.WritableStore) &&
		report.PresignedGet.Scope == s3store.PresignedGetCompatibilitySingleEndpointFiniteProbe &&
		report.PresignedGet.Status == s3store.PresignedGetCompatibilityPassed &&
		report.PresignedGet.Compatible && report.PresignedGet.Complete &&
		doctorPresignedChecksPassed(report.PresignedGet) &&
		doctorCleanupSummaryConsistent(report)
}

func doctorWritableChecksPassed(report s3disk.StoreCompatibilityReport) bool {
	required := doctorWritableRequiredCheckIDs()
	if len(required) != s3disk.StoreCompatibilityRequiredChecks ||
		report.RequiredChecks != len(required) || len(report.Checks) != len(required) {
		return false
	}
	expected := make(map[s3disk.StoreCompatibilityCheckID]struct{}, len(required))
	for _, checkID := range required {
		expected[checkID] = struct{}{}
	}
	if len(expected) != len(required) {
		return false
	}
	for _, check := range report.Checks {
		if check.Status != s3disk.StoreCompatibilityPassed {
			return false
		}
		if _, exists := expected[check.ID]; !exists {
			return false
		}
		delete(expected, check.ID)
	}
	return len(expected) == 0
}

func doctorPresignedChecksPassed(report s3store.PresignedGetCompatibilityReport) bool {
	required := doctorPresignedRequiredCheckIDs()
	if len(required) != s3store.PresignedGetCompatibilityRequiredChecks ||
		report.RequiredChecks != len(required) || len(report.Checks) != len(required) {
		return false
	}
	expected := make(map[s3store.PresignedGetCompatibilityCheckID]struct{}, len(required))
	for _, checkID := range required {
		expected[checkID] = struct{}{}
	}
	if len(expected) != len(required) {
		return false
	}
	for _, check := range report.Checks {
		if check.Status != s3store.PresignedGetCompatibilityPassed {
			return false
		}
		if _, exists := expected[check.ID]; !exists {
			return false
		}
		delete(expected, check.ID)
	}
	return len(expected) == 0
}

func doctorWritableRequiredCheckIDs() []s3disk.StoreCompatibilityCheckID {
	return []s3disk.StoreCompatibilityCheckID{
		s3disk.StoreCompatibilityCheckConfiguration,
		s3disk.StoreCompatibilityCheckProbeKey,
		s3disk.StoreCompatibilityCheckMissingObjectMapping,
		s3disk.StoreCompatibilityCheckConditionalCreate,
		s3disk.StoreCompatibilityCheckHeadAfterCreate,
		s3disk.StoreCompatibilityCheckReadAfterCreate,
		s3disk.StoreCompatibilityCheckInputBufferOwnership,
		s3disk.StoreCompatibilityCheckCASInputBufferOwnership,
		s3disk.StoreCompatibilityCheckDuplicateCreate,
		s3disk.StoreCompatibilityCheckBoundedGet,
		s3disk.StoreCompatibilityCheckOutputBufferOwnership,
		s3disk.StoreCompatibilityCheckStaleCAS,
		s3disk.StoreCompatibilityCheckFailedCASPreservesObject,
		s3disk.StoreCompatibilityCheckReplacementCAS,
		s3disk.StoreCompatibilityCheckReadAfterReplacement,
		s3disk.StoreCompatibilityCheckHeadAfterReplacement,
		s3disk.StoreCompatibilityCheckConditionalGetCurrent,
		s3disk.StoreCompatibilityCheckConditionalGetStale,
		s3disk.StoreCompatibilityCheckNilCASCreate,
		s3disk.StoreCompatibilityCheckNilCASDuplicate,
		s3disk.StoreCompatibilityCheckNilCASPreservesObject,
		s3disk.StoreCompatibilityCheckMissingKeyCAS,
		s3disk.StoreCompatibilityCheckConcurrentPutIfAbsent,
		s3disk.StoreCompatibilityCheckReadAfterConcurrentPut,
		s3disk.StoreCompatibilityCheckConcurrentNilCAS,
		s3disk.StoreCompatibilityCheckReadAfterConcurrentNilCAS,
		s3disk.StoreCompatibilityCheckHeadAfterConcurrentNilCAS,
		s3disk.StoreCompatibilityCheckConcurrentReplacementSeed,
		s3disk.StoreCompatibilityCheckConcurrentReplacementCAS,
		s3disk.StoreCompatibilityCheckReadAfterConcurrentReplacement,
		s3disk.StoreCompatibilityCheckHeadAfterConcurrentReplacement,
	}
}

func doctorPresignedRequiredCheckIDs() []s3store.PresignedGetCompatibilityCheckID {
	return []s3store.PresignedGetCompatibilityCheckID{
		s3store.PresignedGetCompatibilityCheckConfiguration,
		s3store.PresignedGetCompatibilityCheckProbeObjectCreate,
		s3store.PresignedGetCompatibilityCheckExactGetPresign,
		s3store.PresignedGetCompatibilityCheckAnonymousHeaders,
		s3store.PresignedGetCompatibilityCheckInitialGet,
		s3store.PresignedGetCompatibilityCheckSameURLReplacement,
		s3store.PresignedGetCompatibilityCheckCurrentETagConditional,
		s3store.PresignedGetCompatibilityCheckStaleETagConditional,
		s3store.PresignedGetCompatibilityCheckAuthorizationQueryBinding,
		s3store.PresignedGetCompatibilityCheckAnonymousPolicyRejected,
		s3store.PresignedGetCompatibilityCheckNamedUnsignedHeaderOverrides,
		s3store.PresignedGetCompatibilityCheckExactPathBinding,
		s3store.PresignedGetCompatibilityCheckHEADMutationRejected,
		s3store.PresignedGetCompatibilityCheckPUTRejectedUnchanged,
	}
}

func doctorCleanupAttentionRequired(report s3store.S3CommissioningReport) bool {
	writable := report.WritableStore.Cleanup
	presigned := report.PresignedGet.Cleanup
	return writable.CurrentObjectsMayRemain || presigned.CurrentObjectsMayRemain ||
		writable.HistoricalVersionsMayRemain || presigned.HistoricalVersionsMayRemain ||
		writable.Status == s3disk.StoreCompatibilityCleanupFailed ||
		writable.Status == s3disk.StoreCompatibilityCleanupNotSupported ||
		presigned.Status == s3store.PresignedGetCompatibilityCleanupFailed
}

func doctorCleanupSummaryConsistent(report s3store.S3CommissioningReport) bool {
	writable := report.WritableStore.Cleanup
	presigned := report.PresignedGet.Cleanup
	writableTerminal := writable.Status == s3disk.StoreCompatibilityCleanupSucceeded ||
		writable.Status == s3disk.StoreCompatibilityCleanupFailed ||
		writable.Status == s3disk.StoreCompatibilityCleanupNotSupported
	presignedTerminal := presigned.Status == s3store.PresignedGetCompatibilityCleanupSucceeded ||
		presigned.Status == s3store.PresignedGetCompatibilityCleanupFailed
	return writableTerminal && presignedTerminal &&
		report.Cleanup.WritableStoreStatus == writable.Status &&
		report.Cleanup.PresignedGetStatus == presigned.Status &&
		report.Cleanup.CurrentObjectsMayRemain ==
			(writable.CurrentObjectsMayRemain || presigned.CurrentObjectsMayRemain) &&
		report.Cleanup.HistoricalVersionsMayRemain ==
			(writable.HistoricalVersionsMayRemain || presigned.HistoricalVersionsMayRemain) &&
		report.Cleanup.AttentionRequired == doctorCleanupAttentionRequired(report)
}

func doctorCommissioningPrefixFingerprint(domain, prefix string) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(domain))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(prefix)))
	_, _ = hasher.Write(size[:])
	_, _ = hasher.Write([]byte(prefix))
	return hex.EncodeToString(hasher.Sum(nil))
}

func doctorCanonicalLowerHex(value string, decodedBytes int) bool {
	if len(value) != decodedBytes*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == decodedBytes
}

func safeDoctorCommissioningError(probeErr error) error {
	var aggregate *s3store.S3CommissioningError
	if errors.As(probeErr, &aggregate) && aggregate != nil {
		return aggregate
	}
	var aggregateValue s3store.S3CommissioningError
	if errors.As(probeErr, &aggregateValue) {
		return aggregateValue
	}
	return errors.New("s3disk s3 doctor: provider did not produce complete compatible commissioning evidence")
}

func readBoundedFile(path string, maximum int64) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	if maximum < 1 {
		return nil, fmt.Errorf("invalid size bound")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("file is not regular")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	return data, nil
}
