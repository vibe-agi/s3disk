package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/s3store"
)

type doctorCommissioningProbeFunc func(
	context.Context,
	s3store.S3CommissioningProbeOptions,
) (s3store.S3CommissioningReport, error)

func (probe doctorCommissioningProbeFunc) ProbeCommissioning(
	ctx context.Context,
	options s3store.S3CommissioningProbeOptions,
) (s3store.S3CommissioningReport, error) {
	return probe(ctx, options)
}

func TestRunDoctorCommissioningMapsOptionsWritesOneReportAndWarnsAboutCleanup(t *testing.T) {
	tlsRoots := []byte("test TLS roots")
	options := DoctorOptions{
		Prefix:                      "repositories/customer-7",
		PresignedTimeout:            17 * time.Second,
		TotalTimeout:                41 * time.Second,
		CapabilityLifetime:          29 * time.Second,
		CleanupTimeout:              3 * time.Second,
		DeploymentFingerprint:       strings.Repeat("b", 64),
		EvidenceID:                  "commissioning-7",
		ImplementationVersion:       "build-7+linux",
		DangerouslyAllowSystemTrust: true,
	}
	var observed s3store.S3CommissioningProbeOptions
	probe := doctorCommissioningProbeFunc(func(
		_ context.Context,
		probeOptions s3store.S3CommissioningProbeOptions,
	) (s3store.S3CommissioningReport, error) {
		observed = probeOptions
		probeOptions.PresignedGet.TLSRootCAPEM[0] = 'X'
		return passingDoctorCommissioningReport(options, true), nil
	})
	var stdout, stderr bytes.Buffer
	options.ErrorWriter = &stderr
	if err := runDoctorCommissioning(context.Background(), probe, options, tlsRoots, &stdout); err != nil {
		t.Fatal(err)
	}
	if string(tlsRoots) != "test TLS roots" {
		t.Fatalf("caller's TLS roots were mutated: %q", tlsRoots)
	}
	if observed.RepositoryPrefix != options.Prefix || observed.PresignedGet.ObjectKeyPrefix != "" ||
		observed.PresignedGet.TotalTimeout != options.PresignedTimeout || observed.TotalTimeout != options.TotalTimeout ||
		observed.PresignedGet.CapabilityLifetime != options.CapabilityLifetime ||
		observed.PresignedGet.CleanupTimeout != options.CleanupTimeout ||
		observed.DeploymentFingerprint != options.DeploymentFingerprint || observed.EvidenceID != options.EvidenceID ||
		observed.ImplementationVersion != options.ImplementationVersion ||
		!observed.PresignedGet.DangerouslyAllowSystemTrustStore {
		t.Fatalf("unexpected commissioning options: %#v", observed)
	}
	if !strings.Contains(stderr.String(), "cleanup requires operator attention") {
		t.Fatalf("cleanup warning = %q", stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("\n  \"schema_version\"")) {
		t.Fatalf("report is not pretty-printed: %q", stdout.String())
	}
	assertOneDoctorJSONReport(t, stdout.Bytes(), s3store.S3CommissioningPassed)
}

func TestRunDoctorCommissioningWritesFailureReportWithoutRawCause(t *testing.T) {
	rawSecret := "https://storage.invalid/object?X-Amz-Signature=do-not-log"
	probe := doctorCommissioningProbeFunc(func(
		context.Context,
		s3store.S3CommissioningProbeOptions,
	) (s3store.S3CommissioningReport, error) {
		return s3store.S3CommissioningReport{
			SchemaVersion: s3store.S3CommissioningReportSchemaVersion,
			Status:        s3store.S3CommissioningIndeterminate,
		}, errors.New(rawSecret)
	})
	var stdout bytes.Buffer
	err := runDoctorCommissioning(context.Background(), probe, DoctorOptions{}, nil, &stdout)
	if err == nil {
		t.Fatal("failure probe unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), rawSecret) || strings.Contains(err.Error(), "X-Amz-Signature") {
		t.Fatalf("CLI error disclosed raw cause: %v", err)
	}
	if strings.Contains(stdout.String(), rawSecret) {
		t.Fatalf("report disclosed raw cause: %q", stdout.String())
	}
	assertOneDoctorJSONReport(t, stdout.Bytes(), s3store.S3CommissioningIndeterminate)
}

func TestRunDoctorCommissioningCleanupAttentionDoesNotFailPassingProbe(t *testing.T) {
	probe := doctorCommissioningProbeFunc(func(
		context.Context,
		s3store.S3CommissioningProbeOptions,
	) (s3store.S3CommissioningReport, error) {
		return passingDoctorCommissioningReport(DoctorOptions{}, true), nil
	})
	var stdout bytes.Buffer
	if err := runDoctorCommissioning(context.Background(), probe, DoctorOptions{}, nil, &stdout); err != nil {
		t.Fatal(err)
	}
}

func TestRunDoctorCommissioningFailsClosedOnIncompleteEvidenceBinding(t *testing.T) {
	options := DoctorOptions{
		DeploymentFingerprint: strings.Repeat("a", 64),
		EvidenceID:            "commissioning-8",
		ImplementationVersion: "build-8",
	}
	probe := doctorCommissioningProbeFunc(func(
		context.Context,
		s3store.S3CommissioningProbeOptions,
	) (s3store.S3CommissioningReport, error) {
		report := passingDoctorCommissioningReport(options, false)
		report.Evidence.FullyBound = false
		return report, nil
	})
	var stdout bytes.Buffer
	if err := runDoctorCommissioning(context.Background(), probe, options, nil, &stdout); err == nil {
		t.Fatal("fully-bound request accepted an unbound report")
	}
	assertOneDoctorJSONReport(t, stdout.Bytes(), s3store.S3CommissioningPassed)
}

func TestRunDoctorCommissioningPreservesSafeAggregateClassification(t *testing.T) {
	probe := doctorCommissioningProbeFunc(func(
		context.Context,
		s3store.S3CommissioningProbeOptions,
	) (s3store.S3CommissioningReport, error) {
		report := passingDoctorCommissioningReport(DoctorOptions{}, false)
		report.Status = s3store.S3CommissioningIncompatible
		report.Compatible = false
		report.WritableStoreOutcome = s3store.S3CommissioningStageFailed
		return report, &s3store.S3CommissioningError{
			Status:               s3store.S3CommissioningIncompatible,
			WritableStoreOutcome: s3store.S3CommissioningStageFailed,
			PresignedGetOutcome:  s3store.S3CommissioningStagePassed,
		}
	})
	var stdout bytes.Buffer
	err := runDoctorCommissioning(context.Background(), probe, DoctorOptions{}, nil, &stdout)
	if !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("aggregate classification = %v, want ErrStoreIncompatible", err)
	}
	var aggregate *s3store.S3CommissioningError
	if !errors.As(err, &aggregate) || aggregate.Status != s3store.S3CommissioningIncompatible {
		t.Fatalf("aggregate error = %#v", aggregate)
	}
}

func TestRunDoctorCommissioningRejectsTamperedPassingEnvelope(t *testing.T) {
	options := DoctorOptions{
		Prefix:                "repositories/customer-9",
		DeploymentFingerprint: strings.Repeat("c", 64),
		EvidenceID:            "commissioning-9",
		ImplementationVersion: "build-9",
	}
	tests := []struct {
		name   string
		mutate func(*s3store.S3CommissioningReport)
	}{
		{name: "combined declaration", mutate: func(report *s3store.S3CommissioningReport) { report.Evidence.EvidenceID = "other" }},
		{name: "run ID", mutate: func(report *s3store.S3CommissioningReport) { report.Evidence.RunID = "" }},
		{name: "repository fingerprint", mutate: func(report *s3store.S3CommissioningReport) {
			report.Evidence.RepositoryPrefixFingerprint = strings.Repeat("0", 64)
		}},
		{name: "combined scope", mutate: func(report *s3store.S3CommissioningReport) { report.Scope = "other" }},
		{name: "combined presigning topology", mutate: func(report *s3store.S3CommissioningReport) {
			report.Evidence.PresigningTopology = s3store.PresignedGetCompatibilitySeparateStore
			report.Evidence.PresigningStoreInputDistinct = true
			report.Evidence.CrossConfigurationCanaryBindingObserved = true
		}},
		{name: "writable contract", mutate: func(report *s3store.S3CommissioningReport) { report.WritableStore.ContractVersion++ }},
		{name: "writable required checks", mutate: func(report *s3store.S3CommissioningReport) { report.WritableStore.RequiredChecks-- }},
		{name: "writable check count", mutate: func(report *s3store.S3CommissioningReport) {
			report.WritableStore.Checks = report.WritableStore.Checks[:len(report.WritableStore.Checks)-1]
		}},
		{name: "unknown writable check", mutate: func(report *s3store.S3CommissioningReport) {
			report.WritableStore.Checks[0].ID = "unknown-writable-check"
		}},
		{name: "duplicate writable check", mutate: func(report *s3store.S3CommissioningReport) {
			report.WritableStore.Checks[0].ID = report.WritableStore.Checks[1].ID
		}},
		{name: "failed writable check", mutate: func(report *s3store.S3CommissioningReport) {
			report.WritableStore.Checks[0].Status = s3disk.StoreCompatibilityIndeterminate
		}},
		{name: "writable declaration", mutate: func(report *s3store.S3CommissioningReport) {
			report.WritableStore.Evidence.ImplementationVersion = "other"
		}},
		{name: "presigned scope", mutate: func(report *s3store.S3CommissioningReport) { report.PresignedGet.Scope = "other" }},
		{name: "presigned topology", mutate: func(report *s3store.S3CommissioningReport) {
			report.PresignedGet.Evidence.PresigningTopology = s3store.PresignedGetCompatibilitySeparateStore
			report.PresignedGet.Evidence.PresigningStoreInputDistinct = true
			report.PresignedGet.Evidence.CrossConfigurationCanaryBindingObserved = true
		}},
		{name: "presigned required checks", mutate: func(report *s3store.S3CommissioningReport) { report.PresignedGet.RequiredChecks-- }},
		{name: "presigned check count", mutate: func(report *s3store.S3CommissioningReport) {
			report.PresignedGet.Checks = report.PresignedGet.Checks[:len(report.PresignedGet.Checks)-1]
		}},
		{name: "unknown presigned check", mutate: func(report *s3store.S3CommissioningReport) {
			report.PresignedGet.Checks[0].ID = "unknown-presigned-check"
		}},
		{name: "duplicate presigned check", mutate: func(report *s3store.S3CommissioningReport) {
			report.PresignedGet.Checks[0].ID = report.PresignedGet.Checks[1].ID
		}},
		{name: "failed presigned check", mutate: func(report *s3store.S3CommissioningReport) {
			report.PresignedGet.Checks[0].Status = s3store.PresignedGetCompatibilityIndeterminate
		}},
		{name: "missing presigned limitation", mutate: func(report *s3store.S3CommissioningReport) {
			report.PresignedGet.Limitations = report.PresignedGet.Limitations[:len(report.PresignedGet.Limitations)-1]
		}},
		{name: "duplicate presigned limitation", mutate: func(report *s3store.S3CommissioningReport) {
			report.PresignedGet.Limitations[len(report.PresignedGet.Limitations)-1] =
				report.PresignedGet.Limitations[0]
		}},
		{name: "cross configuration limitation", mutate: func(report *s3store.S3CommissioningReport) {
			report.PresignedGet.Limitations[len(report.PresignedGet.Limitations)-1] =
				s3store.PresignedGetCompatibilityLimitationCrossConfigurationBindingNotAuthenticated
		}},
		{name: "cleanup status summary", mutate: func(report *s3store.S3CommissioningReport) {
			report.Cleanup.WritableStoreStatus = s3disk.StoreCompatibilityCleanupFailed
		}},
		{name: "cleanup object summary", mutate: func(report *s3store.S3CommissioningReport) {
			report.Cleanup.CurrentObjectsMayRemain = true
		}},
		{name: "cleanup attention summary", mutate: func(report *s3store.S3CommissioningReport) {
			report.Cleanup.AttentionRequired = true
		}},
		{name: "matching impossible writable cleanup state", mutate: func(report *s3store.S3CommissioningReport) {
			report.WritableStore.Cleanup.Status = s3disk.StoreCompatibilityCleanupNotAttempted
			report.Cleanup.WritableStoreStatus = s3disk.StoreCompatibilityCleanupNotAttempted
		}},
		{name: "matching impossible presigned cleanup state", mutate: func(report *s3store.S3CommissioningReport) {
			report.PresignedGet.Cleanup.Status = s3store.PresignedGetCompatibilityCleanupNotAttempted
			report.Cleanup.PresignedGetStatus = s3store.PresignedGetCompatibilityCleanupNotAttempted
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			probe := doctorCommissioningProbeFunc(func(
				context.Context,
				s3store.S3CommissioningProbeOptions,
			) (s3store.S3CommissioningReport, error) {
				report := passingDoctorCommissioningReport(options, false)
				test.mutate(&report)
				return report, nil
			})
			var stdout bytes.Buffer
			if err := runDoctorCommissioning(context.Background(), probe, options, nil, &stdout); err == nil {
				t.Fatal("tampered passing report was accepted")
			}
			assertOneDoctorJSONReport(t, stdout.Bytes(), s3store.S3CommissioningPassed)
		})
	}
}

func TestRunDoctorCommissioningRejectsTamperedSystemTrustLimitations(t *testing.T) {
	options := DoctorOptions{DangerouslyAllowSystemTrust: true}
	tests := []struct {
		name   string
		mutate func(*s3store.S3CommissioningReport)
	}{
		{name: "missing system trust limitation", mutate: func(report *s3store.S3CommissioningReport) {
			report.PresignedGet.Limitations = report.PresignedGet.Limitations[:len(report.PresignedGet.Limitations)-1]
		}},
		{name: "system trust limitation out of order", mutate: func(report *s3store.S3CommissioningReport) {
			last := len(report.PresignedGet.Limitations) - 1
			report.PresignedGet.Limitations[last-1], report.PresignedGet.Limitations[last] =
				report.PresignedGet.Limitations[last], report.PresignedGet.Limitations[last-1]
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			probe := doctorCommissioningProbeFunc(func(
				context.Context,
				s3store.S3CommissioningProbeOptions,
			) (s3store.S3CommissioningReport, error) {
				report := passingDoctorCommissioningReport(options, false)
				test.mutate(&report)
				return report, nil
			})
			var stdout bytes.Buffer
			if err := runDoctorCommissioning(context.Background(), probe, options, nil, &stdout); err == nil {
				t.Fatal("tampered system-trust limitations were accepted")
			}
			assertOneDoctorJSONReport(t, stdout.Bytes(), s3store.S3CommissioningPassed)
		})
	}
}

func TestRunDoctorCommissioningTamperedCleanupCannotSuppressWarning(t *testing.T) {
	probe := doctorCommissioningProbeFunc(func(
		context.Context,
		s3store.S3CommissioningProbeOptions,
	) (s3store.S3CommissioningReport, error) {
		report := passingDoctorCommissioningReport(DoctorOptions{}, true)
		report.Cleanup.AttentionRequired = false
		return report, nil
	})
	var stdout, stderr bytes.Buffer
	options := DoctorOptions{ErrorWriter: &stderr}
	if err := runDoctorCommissioning(context.Background(), probe, options, nil, &stdout); err == nil {
		t.Fatal("tampered cleanup summary was accepted")
	}
	if !strings.Contains(stderr.String(), "cleanup requires operator attention") {
		t.Fatalf("derived cleanup warning was suppressed: %q", stderr.String())
	}
}

func passingDoctorCommissioningReport(options DoctorOptions, attentionRequired bool) s3store.S3CommissioningReport {
	started := time.Unix(1_700_000_000, 0).UTC()
	fullyBound := options.DeploymentFingerprint != "" && options.EvidenceID != "" &&
		options.ImplementationVersion != ""
	normalizedPrefix := strings.Trim(options.Prefix, "/")
	presignedPrefix := doctorDerivedPresignedPrefixSuffix
	if normalizedPrefix != "" {
		presignedPrefix = normalizedPrefix + "/" + doctorDerivedPresignedPrefixSuffix
	}
	writableIDs := doctorWritableRequiredCheckIDs()
	writableChecks := make([]s3disk.StoreCompatibilityCheck, len(writableIDs))
	for index, checkID := range writableIDs {
		writableChecks[index] = s3disk.StoreCompatibilityCheck{
			ID:     checkID,
			Status: s3disk.StoreCompatibilityPassed,
		}
	}
	presignedIDs := doctorPresignedRequiredCheckIDs()
	presignedChecks := make([]s3store.PresignedGetCompatibilityCheck, len(presignedIDs))
	for index, checkID := range presignedIDs {
		presignedChecks[index] = s3store.PresignedGetCompatibilityCheck{
			ID:     checkID,
			Status: s3store.PresignedGetCompatibilityPassed,
		}
	}
	presignedLimitations := []s3store.PresignedGetCompatibilityLimitation{
		s3store.PresignedGetCompatibilityLimitationFutureStatesNotProven,
		s3store.PresignedGetCompatibilityLimitationExpiryNotSampled,
		s3store.PresignedGetCompatibilityLimitationOtherMethodsNotSampled,
		s3store.PresignedGetCompatibilityLimitationArbitraryQueryBindingNotProven,
		s3store.PresignedGetCompatibilityLimitationHEADAndBodylessStatusWireBodyNotVisible,
		s3store.PresignedGetCompatibilityLimitationDiscardedWireMetadataAndExtraBytes,
		s3store.PresignedGetCompatibilityLimitationBucketPublicAccessPolicyNotFullyProven,
		s3store.PresignedGetCompatibilityLimitationPUTPayloadVariantsBeyondNamedSamples,
		s3store.PresignedGetCompatibilityLimitationArbitraryUnsignedHeaderOverrideBinding,
		s3store.PresignedGetCompatibilityLimitationBucketAndOriginBindingNotSampled,
	}
	if options.DangerouslyAllowSystemTrust {
		presignedLimitations = append(
			presignedLimitations,
			s3store.PresignedGetCompatibilityLimitationSystemTrustNetworkIO,
		)
	}
	writableCleanup := s3disk.StoreCompatibilityCleanupReport{
		Status: s3disk.StoreCompatibilityCleanupSucceeded,
	}
	presignedCleanup := s3store.PresignedGetCompatibilityCleanupReport{
		Status: s3store.PresignedGetCompatibilityCleanupSucceeded,
	}
	cleanup := s3store.S3CommissioningCleanupSummary{
		WritableStoreStatus: writableCleanup.Status,
		PresignedGetStatus:  presignedCleanup.Status,
	}
	if attentionRequired {
		writableCleanup.HistoricalVersionsMayRemain = true
		cleanup.HistoricalVersionsMayRemain = true
		cleanup.AttentionRequired = true
	}
	return s3store.S3CommissioningReport{
		SchemaVersion: s3store.S3CommissioningReportSchemaVersion,
		Scope:         s3store.S3CommissioningSingleProcessDualFiniteProbe,
		Evidence: s3store.S3CommissioningEvidence{
			SchemaVersion: s3store.S3CommissioningReportSchemaVersion, StartedAt: started,
			DurationNanoseconds: 1, RunID: strings.Repeat("ab", 24),
			RepositoryPrefixFingerprint: doctorCommissioningPrefixFingerprint(
				doctorCommissioningRepositoryPrefixDomain, normalizedPrefix,
			),
			PresignedPrefixFingerprint: doctorCommissioningPrefixFingerprint(
				doctorCommissioningPresignedPrefixDomain, presignedPrefix,
			),
			PresignedPrefixDerived: true, PresignedPrefixRepositoryScoped: true,
			DeploymentFingerprint: options.DeploymentFingerprint, EvidenceID: options.EvidenceID,
			ImplementationVersion: options.ImplementationVersion, FullyBound: fullyBound,
			PresigningTopology: s3store.PresignedGetCompatibilitySameStore,
		},
		Status:               s3store.S3CommissioningPassed,
		Compatible:           true,
		Complete:             true,
		WritableStoreOutcome: s3store.S3CommissioningStagePassed,
		PresignedGetOutcome:  s3store.S3CommissioningStagePassed,
		WritableStore: s3disk.StoreCompatibilityReport{
			ContractVersion: s3disk.StoreCompatibilityContractVersion,
			Scope:           s3disk.StoreCompatibilitySingleClientFiniteProbe,
			Evidence: s3disk.StoreCompatibilityEvidence{
				StartedAt: started, DurationNanoseconds: 1,
				RepositoryPrefixFingerprint: doctorCommissioningPrefixFingerprint(
					doctorWritableRepositoryPrefixDomain, normalizedPrefix,
				),
				DeploymentFingerprint: options.DeploymentFingerprint, EvidenceID: options.EvidenceID,
				ImplementationVersion: options.ImplementationVersion, FullyBound: fullyBound,
			},
			ProbeID: "test-probe", Status: s3disk.StoreCompatibilityPassed,
			Compatible: true, Complete: true, RequiredChecks: s3disk.StoreCompatibilityRequiredChecks,
			Checks: writableChecks, Cleanup: writableCleanup,
		},
		PresignedGet: s3store.PresignedGetCompatibilityReport{
			Scope: s3store.PresignedGetCompatibilitySingleEndpointFiniteProbe,
			Evidence: s3store.PresignedGetCompatibilityEvidence{
				PresigningTopology: s3store.PresignedGetCompatibilitySameStore,
			},
			Status: s3store.PresignedGetCompatibilityPassed, Compatible: true, Complete: true,
			RequiredChecks: s3store.PresignedGetCompatibilityRequiredChecks,
			Checks:         presignedChecks,
			Limitations:    presignedLimitations,
			Cleanup:        presignedCleanup,
		},
		Cleanup: cleanup,
	}
}

func assertOneDoctorJSONReport(t *testing.T, encoded []byte, wantStatus s3store.S3CommissioningStatus) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	var report s3store.S3CommissioningReport
	if err := decoder.Decode(&report); err != nil {
		t.Fatalf("decode report: %v; output=%q", err, encoded)
	}
	if report.Status != wantStatus {
		t.Fatalf("status = %q, want %q", report.Status, wantStatus)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("stdout contains more than one JSON value: %v; output=%q", err, encoded)
	}
}
