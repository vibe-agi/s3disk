package s3disk_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestStoreCompatibilityEvidenceJSONGolden(t *testing.T) {
	t.Parallel()
	report := s3disk.StoreCompatibilityReport{
		ContractVersion: 1,
		Scope:           s3disk.StoreCompatibilitySingleClientFiniteProbe,
		Evidence: s3disk.StoreCompatibilityEvidence{
			StartedAt:                   time.Date(2026, time.July, 18, 12, 34, 56, 123456789, time.UTC),
			DurationNanoseconds:         987654321,
			RepositoryPrefixFingerprint: strings.Repeat("b", 64),
			DeploymentFingerprint:       strings.Repeat("a", 64),
			EvidenceID:                  "commissioning-20260718-001",
			ImplementationVersion:       "s3disk-v0.0.0+build.17",
			FullyBound:                  true,
		},
		ProbeID:        "0123456789abcdef",
		Status:         s3disk.StoreCompatibilityPassed,
		Compatible:     true,
		Complete:       true,
		RequiredChecks: 31,
		Contenders:     8,
		Checks:         []s3disk.StoreCompatibilityCheck{},
		Cleanup: s3disk.StoreCompatibilityCleanupReport{
			Status: s3disk.StoreCompatibilityCleanupSucceeded,
		},
	}

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	const want = `{
  "contract_version": 1,
  "scope": "single_client_finite_probe",
  "evidence": {
    "started_at": "2026-07-18T12:34:56.123456789Z",
    "duration_nanoseconds": 987654321,
    "repository_prefix_fingerprint": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "deployment_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "evidence_id": "commissioning-20260718-001",
    "implementation_version": "s3disk-v0.0.0+build.17",
    "fully_bound": true
  },
  "probe_id": "0123456789abcdef",
  "status": "passed",
  "compatible": true,
  "complete": true,
  "required_checks": 31,
  "contenders": 8,
  "checks": [],
  "cleanup": {
    "status": "succeeded",
    "attempted": 0,
    "succeeded": 0,
    "failed": 0,
    "delete_failures": 0,
    "current_objects_still_visible": 0,
    "verification_failures": 0,
    "current_objects_may_remain": false,
    "historical_versions_may_remain": false
  }
}`
	if string(encoded) != want {
		t.Fatalf("report JSON changed:\n%s\nwant:\n%s", encoded, want)
	}
}

func TestStoreCompatibilityEvidenceJSONReadsPreEvidenceReport(t *testing.T) {
	t.Parallel()
	const legacy = `{"contract_version":1,"scope":"single_client_finite_probe","status":"indeterminate","compatible":false,"complete":false,"required_checks":31,"contenders":8,"checks":[],"cleanup":{"status":"not_attempted","attempted":0,"succeeded":0,"failed":0,"current_objects_may_remain":false,"historical_versions_may_remain":false}}`
	var report s3disk.StoreCompatibilityReport
	if err := json.Unmarshal([]byte(legacy), &report); err != nil {
		t.Fatalf("Unmarshal pre-evidence report: %v", err)
	}
	if report.ContractVersion != 1 || report.Evidence != (s3disk.StoreCompatibilityEvidence{}) || report.Status != s3disk.StoreCompatibilityIndeterminate {
		t.Fatalf("pre-evidence report = %+v, want v1 with zero-value additive evidence", report)
	}
}

func TestProbeStoreCompatibilityWithOptionsBindsRedactedEvidence(t *testing.T) {
	t.Parallel()
	const repositoryPrefix = "customer-secret-looking-prefix/production"
	repository, err := s3disk.NewRepository(memstore.New(), repositoryPrefix)
	if err != nil {
		t.Fatalf("NewRepository: %v", err)
	}
	options := s3disk.StoreCompatibilityProbeOptions{
		DeploymentFingerprint: strings.Repeat("a", 64),
		EvidenceID:            "commissioning-20260718-001",
		ImplementationVersion: "commercial-build+17",
	}
	before := time.Now()
	report, err := repository.ProbeStoreCompatibilityWithOptions(context.Background(), options)
	after := time.Now()
	if err != nil {
		t.Fatalf("ProbeStoreCompatibilityWithOptions: %v", err)
	}
	if !report.Evidence.FullyBound {
		t.Fatalf("evidence = %+v, want fully bound", report.Evidence)
	}
	if report.Evidence.DeploymentFingerprint != options.DeploymentFingerprint ||
		report.Evidence.EvidenceID != options.EvidenceID ||
		report.Evidence.ImplementationVersion != options.ImplementationVersion {
		t.Fatalf("evidence identifiers = %+v, want validated options", report.Evidence)
	}
	if report.Evidence.RepositoryPrefixFingerprint == "" || len(report.Evidence.RepositoryPrefixFingerprint) != 64 {
		t.Fatalf("repository prefix fingerprint = %q, want SHA-256 hex", report.Evidence.RepositoryPrefixFingerprint)
	}
	if report.Evidence.StartedAt.Location() != time.UTC || report.Evidence.StartedAt.Before(before.Add(-time.Second).UTC()) || report.Evidence.StartedAt.After(after.Add(time.Second).UTC()) {
		t.Fatalf("started_at = %v, want UTC in call interval [%v, %v]", report.Evidence.StartedAt, before.UTC(), after.UTC())
	}
	if report.Evidence.DurationNanoseconds < 0 {
		t.Fatalf("duration_nanoseconds = %d, want non-negative", report.Evidence.DurationNanoseconds)
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(encoded), repositoryPrefix) {
		t.Fatalf("report JSON leaked raw repository prefix: %s", encoded)
	}
}

func TestProbeStoreCompatibilityWithOptionsRejectsInvalidOptionsBeforeStoreIO(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		options s3disk.StoreCompatibilityProbeOptions
		secret  string
	}{
		{
			name:    "non-canonical-deployment-fingerprint",
			options: s3disk.StoreCompatibilityProbeOptions{DeploymentFingerprint: strings.Repeat("A", 64)},
			secret:  strings.Repeat("A", 64),
		},
		{
			name:    "evidence-id-space",
			options: s3disk.StoreCompatibilityProbeOptions{EvidenceID: "do-not-log this"},
			secret:  "do-not-log this",
		},
		{
			name:    "evidence-id-too-long",
			options: s3disk.StoreCompatibilityProbeOptions{EvidenceID: strings.Repeat("x", s3disk.StoreCompatibilityEvidenceIDMaxBytes+1)},
			secret:  strings.Repeat("x", s3disk.StoreCompatibilityEvidenceIDMaxBytes+1),
		},
		{
			name:    "implementation-version-slash",
			options: s3disk.StoreCompatibilityProbeOptions{ImplementationVersion: "do-not-log/this"},
			secret:  "do-not-log/this",
		},
		{
			name:    "implementation-version-too-long",
			options: s3disk.StoreCompatibilityProbeOptions{ImplementationVersion: strings.Repeat("x", s3disk.StoreCompatibilityImplementationVersionMaxBytes+1)},
			secret:  strings.Repeat("x", s3disk.StoreCompatibilityImplementationVersionMaxBytes+1),
		},
		{
			name:    "negative-timeout",
			options: s3disk.StoreCompatibilityProbeOptions{TotalTimeout: -time.Nanosecond},
		},
		{
			name:    "excessive-timeout",
			options: s3disk.StoreCompatibilityProbeOptions{TotalTimeout: s3disk.StoreCompatibilityMaximumTimeout + time.Nanosecond},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &evidenceCountingStore{}
			repository, err := s3disk.NewRepository(store, "invalid-options")
			if err != nil {
				t.Fatalf("NewRepository: %v", err)
			}
			report, probeErr := repository.ProbeStoreCompatibilityWithOptions(context.Background(), test.options)
			if probeErr == nil || !errors.Is(probeErr, s3disk.ErrStoreMisconfigured) {
				t.Fatalf("error = %v, want ErrStoreMisconfigured", probeErr)
			}
			if store.calls.Load() != 0 {
				t.Fatalf("Store calls = %d, want zero before invalid-option rejection", store.calls.Load())
			}
			if report.Status != s3disk.StoreCompatibilityConfigurationError || len(report.Checks) != 1 || report.Checks[0].ID != s3disk.StoreCompatibilityCheckConfiguration {
				t.Fatalf("report = %+v, want one configuration error", report)
			}
			if report.Evidence.DeploymentFingerprint != "" || report.Evidence.EvidenceID != "" || report.Evidence.ImplementationVersion != "" || report.Evidence.FullyBound {
				t.Fatalf("invalid caller values were retained in evidence: %+v", report.Evidence)
			}
			if test.secret != "" && strings.Contains(probeErr.Error(), test.secret) {
				t.Fatalf("returned error leaked rejected option %q: %v", test.secret, probeErr)
			}
			encoded, err := json.Marshal(report)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if test.secret != "" && strings.Contains(string(encoded), test.secret) {
				t.Fatalf("report JSON leaked rejected option %q: %s", test.secret, encoded)
			}
		})
	}
}

func TestStoreCompatibilityRepositoryPrefixFingerprintIsStableAndDistinct(t *testing.T) {
	t.Parallel()
	invalidOptions := s3disk.StoreCompatibilityProbeOptions{EvidenceID: "invalid evidence ID"}
	probe := func(prefix string) s3disk.StoreCompatibilityReport {
		repository, err := s3disk.NewRepository(&evidenceCountingStore{}, prefix)
		if err != nil {
			t.Fatalf("NewRepository(%q): %v", prefix, err)
		}
		report, err := repository.ProbeStoreCompatibilityWithOptions(context.Background(), invalidOptions)
		if err == nil {
			t.Fatalf("ProbeStoreCompatibilityWithOptions(%q) unexpectedly succeeded", prefix)
		}
		return report
	}

	first := probe("tenant-a/repository")
	repeated := probe("/tenant-a/repository/")
	different := probe("tenant-b/repository")
	empty := probe("")
	const expectedFirst = "64903208df71f975e7bb2b3bdb9ab3630500e190021fd2f82526b69bee412c10"
	if first.Evidence.RepositoryPrefixFingerprint != expectedFirst {
		t.Fatalf("repository prefix fingerprint = %q, want pinned domain-separated digest %q", first.Evidence.RepositoryPrefixFingerprint, expectedFirst)
	}
	if first.Evidence.RepositoryPrefixFingerprint == "" || first.Evidence.RepositoryPrefixFingerprint != repeated.Evidence.RepositoryPrefixFingerprint {
		t.Fatalf("same normalized prefix fingerprints = %q and %q, want stable equality", first.Evidence.RepositoryPrefixFingerprint, repeated.Evidence.RepositoryPrefixFingerprint)
	}
	if first.Evidence.RepositoryPrefixFingerprint == different.Evidence.RepositoryPrefixFingerprint {
		t.Fatalf("different prefix fingerprints both = %q", first.Evidence.RepositoryPrefixFingerprint)
	}
	if len(empty.Evidence.RepositoryPrefixFingerprint) != 64 || empty.Evidence.RepositoryPrefixFingerprint == first.Evidence.RepositoryPrefixFingerprint {
		t.Fatalf("empty prefix fingerprint = %q, want a distinct nonempty digest", empty.Evidence.RepositoryPrefixFingerprint)
	}
}

func TestProbeStoreCompatibilityOldAPIAppliesDefaultDeadline(t *testing.T) {
	t.Parallel()
	store := &evidenceDeadlineStore{mode: evidenceDeadlineObserve}
	repository, err := s3disk.NewRepository(store, "old-api-default-deadline")
	if err != nil {
		t.Fatalf("NewRepository: %v", err)
	}
	before := time.Now()
	report, probeErr := repository.ProbeStoreCompatibility(context.Background())
	if probeErr == nil || !errors.Is(probeErr, s3disk.ErrStoreUnavailable) {
		t.Fatalf("error = %v, want observed Store unavailable error", probeErr)
	}
	deadline := store.deadline.Load()
	if deadline == nil {
		t.Fatal("Store did not observe a context deadline")
	}
	remaining := deadline.(time.Time).Sub(before)
	if remaining < s3disk.StoreCompatibilityDefaultTimeout-time.Second || remaining > s3disk.StoreCompatibilityDefaultTimeout+5*time.Second {
		t.Fatalf("default deadline remaining = %s, want approximately %s", remaining, s3disk.StoreCompatibilityDefaultTimeout)
	}
	if report.Evidence.RepositoryPrefixFingerprint == "" || report.Evidence.FullyBound {
		t.Fatalf("old API evidence = %+v, want prefix-bound but not fully caller-bound", report.Evidence)
	}
}

func TestProbeStoreCompatibilityExplicitTimeoutCancelsContextAwareStore(t *testing.T) {
	t.Parallel()
	store := &evidenceDeadlineStore{mode: evidenceDeadlineWait}
	repository, err := s3disk.NewRepository(store, "explicit-deadline")
	if err != nil {
		t.Fatalf("NewRepository: %v", err)
	}
	started := time.Now()
	report, probeErr := repository.ProbeStoreCompatibilityWithOptions(context.Background(), s3disk.StoreCompatibilityProbeOptions{
		TotalTimeout: 20 * time.Millisecond,
	})
	if probeErr == nil || !errors.Is(probeErr, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context deadline exceeded", probeErr)
	}
	if elapsed := time.Since(started); elapsed < 10*time.Millisecond || elapsed > 5*time.Second {
		t.Fatalf("elapsed = %s, want prompt context-bound return", elapsed)
	}
	if report.Status != s3disk.StoreCompatibilityIndeterminate || report.Checks[len(report.Checks)-1].Reason != s3disk.StoreCompatibilityReasonDeadlineExceeded {
		t.Fatalf("report = %+v, want indeterminate deadline reason", report)
	}
}

func TestProbeStoreCompatibilityEarlierCallerDeadlineWins(t *testing.T) {
	t.Parallel()
	store := &evidenceDeadlineStore{mode: evidenceDeadlineObserve}
	repository, err := s3disk.NewRepository(store, "caller-deadline")
	if err != nil {
		t.Fatalf("NewRepository: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	wantDeadline, _ := ctx.Deadline()
	_, probeErr := repository.ProbeStoreCompatibilityWithOptions(ctx, s3disk.StoreCompatibilityProbeOptions{
		TotalTimeout: time.Minute,
	})
	if probeErr == nil || !errors.Is(probeErr, s3disk.ErrStoreUnavailable) {
		t.Fatalf("error = %v, want observed Store unavailable error", probeErr)
	}
	observed := store.deadline.Load()
	if observed == nil || !observed.(time.Time).Equal(wantDeadline) {
		t.Fatalf("Store deadline = %v, want earlier caller deadline %v", observed, wantDeadline)
	}
}

func TestStoreCompatibilityDurationIncludesCleanup(t *testing.T) {
	t.Parallel()
	const delay = 10 * time.Millisecond
	store := &evidenceDelayedDeleteStore{Store: memstore.New(), delay: delay}
	repository, err := s3disk.NewRepository(store, "cleanup-duration")
	if err != nil {
		t.Fatalf("NewRepository: %v", err)
	}
	report, err := repository.ProbeStoreCompatibility(context.Background())
	if err != nil {
		t.Fatalf("ProbeStoreCompatibility: %v", err)
	}
	if report.Cleanup.Attempted == 0 || report.Cleanup.Status != s3disk.StoreCompatibilityCleanupSucceeded {
		t.Fatalf("cleanup = %+v, want attempted success", report.Cleanup)
	}
	minimum := time.Duration(report.Cleanup.Attempted) * delay
	if time.Duration(report.Evidence.DurationNanoseconds) < minimum {
		t.Fatalf("reported duration = %s, want at least cleanup delay %s", time.Duration(report.Evidence.DurationNanoseconds), minimum)
	}
}

type evidenceCountingStore struct {
	calls atomic.Int64
}

func (store *evidenceCountingStore) Get(context.Context, string, s3disk.GetOptions) (s3disk.Object, error) {
	store.calls.Add(1)
	return s3disk.Object{}, s3disk.ErrStoreUnavailable
}

func (store *evidenceCountingStore) Head(context.Context, string) (s3disk.Version, error) {
	store.calls.Add(1)
	return s3disk.Version{}, s3disk.ErrStoreUnavailable
}

func (store *evidenceCountingStore) PutIfAbsent(context.Context, string, []byte) (s3disk.Version, error) {
	store.calls.Add(1)
	return s3disk.Version{}, s3disk.ErrStoreUnavailable
}

func (store *evidenceCountingStore) CompareAndSwap(context.Context, string, *s3disk.Version, []byte) (s3disk.Version, error) {
	store.calls.Add(1)
	return s3disk.Version{}, s3disk.ErrStoreUnavailable
}

func (store *evidenceCountingStore) Delete(context.Context, string) error {
	store.calls.Add(1)
	return nil
}

type evidenceDeadlineMode uint8

const (
	evidenceDeadlineObserve evidenceDeadlineMode = iota
	evidenceDeadlineWait
)

type evidenceDeadlineStore struct {
	mode     evidenceDeadlineMode
	deadline atomic.Value
}

func (store *evidenceDeadlineStore) Get(context.Context, string, s3disk.GetOptions) (s3disk.Object, error) {
	return s3disk.Object{}, errors.New("unexpected Get")
}

func (store *evidenceDeadlineStore) Head(ctx context.Context, _ string) (s3disk.Version, error) {
	if deadline, ok := ctx.Deadline(); ok {
		store.deadline.Store(deadline)
	}
	if store.mode == evidenceDeadlineWait {
		<-ctx.Done()
		return s3disk.Version{}, ctx.Err()
	}
	return s3disk.Version{}, s3disk.ErrStoreUnavailable
}

func (store *evidenceDeadlineStore) PutIfAbsent(context.Context, string, []byte) (s3disk.Version, error) {
	return s3disk.Version{}, errors.New("unexpected PutIfAbsent")
}

func (store *evidenceDeadlineStore) CompareAndSwap(context.Context, string, *s3disk.Version, []byte) (s3disk.Version, error) {
	return s3disk.Version{}, errors.New("unexpected CompareAndSwap")
}

type evidenceDelayedDeleteStore struct {
	*memstore.Store
	delay time.Duration
}

func (store *evidenceDelayedDeleteStore) Delete(ctx context.Context, key string) error {
	timer := time.NewTimer(store.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return store.Store.Delete(ctx, key)
	}
}
