package s3disk

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestConcurrentCompatibilitySemanticEvidenceOutranksTimeout(t *testing.T) {
	t.Parallel()
	for _, results := range [][]compatibilityWriteResult{
		{
			{contender: 0, version: Version{ETag: "winner-0"}},
			{contender: 1, version: Version{ETag: "winner-1"}},
			{contender: 2, err: context.DeadlineExceeded},
			{contender: 3, err: ErrPrecondition},
		},
		{
			{contender: 3, err: ErrPrecondition},
			{contender: 2, err: context.DeadlineExceeded},
			{contender: 1, version: Version{ETag: "winner-1"}},
			{contender: 0, version: Version{ETag: "winner-0"}},
		},
	} {
		report := StoreCompatibilityReport{RequiredChecks: 1}
		recorder := compatibilityRecorder{report: &report}
		_, err := requireSingleCompatibilityWinner(recorder, StoreCompatibilityCheckConcurrentPutIfAbsent, results)
		if !errors.Is(err, ErrStoreIncompatible) {
			t.Fatalf("error = %v, want definitive ErrStoreIncompatible", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v, want retained timeout cause", err)
		}
		if report.Status != StoreCompatibilityIncompatible || len(report.Checks) != 1 ||
			report.Checks[0].Reason != StoreCompatibilityReasonSemanticViolation {
			t.Fatalf("report = %+v, want semantic incompatibility", report)
		}
	}
}

func TestCompatibilityWriteReconciliationIsFailClosed(t *testing.T) {
	t.Parallel()
	payload := []byte("new payload")
	previous := Object{Data: []byte("old payload"), Version: Version{ETag: "old-etag"}}
	for _, test := range []struct {
		name       string
		store      Store
		previous   *Object
		operation  error
		applied    bool
		status     StoreCompatibilityStatus
		wantCauses []error
	}{
		{
			name:      "applied-after-precondition-retry",
			store:     &compatibilityReconciliationGetStore{object: Object{Data: payload, Version: Version{ETag: "new-etag"}}},
			operation: ErrPrecondition, applied: true,
		},
		{
			name:  "operational-old-state",
			store: &compatibilityReconciliationGetStore{object: previous}, previous: &previous,
			operation: ErrStoreUnavailable, status: StoreCompatibilityIndeterminate,
		},
		{
			name:  "precondition-old-state",
			store: &compatibilityReconciliationGetStore{object: previous}, previous: &previous,
			operation: ErrPrecondition, status: StoreCompatibilityIncompatible,
		},
		{
			name:      "reconciliation-read-failure-does-not-promote-precondition",
			store:     &compatibilityReconciliationGetStore{err: ErrStoreUnavailable},
			operation: ErrPrecondition, status: StoreCompatibilityIndeterminate,
			wantCauses: []error{ErrPrecondition, ErrStoreUnavailable},
		},
		{
			name:  "replacement-etag-reuse",
			store: &compatibilityReconciliationGetStore{object: Object{Data: payload, Version: Version{ETag: "old-etag"}}}, previous: &previous,
			operation: ErrPrecondition, status: StoreCompatibilityIncompatible,
		},
		{
			name:      "foreign-bytes-outrank-operational",
			store:     &compatibilityReconciliationGetStore{object: Object{Data: []byte("foreign"), Version: Version{ETag: "foreign-etag"}}},
			operation: ErrStoreUnavailable, status: StoreCompatibilityIncompatible,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := reconcileCompatibilityWrite(context.Background(), test.store, "isolated", payload, test.previous, test.operation)
			if result.applied != test.applied || result.status != test.status {
				t.Fatalf("reconciliation = %+v, want applied=%v status=%q", result, test.applied, test.status)
			}
			for _, cause := range test.wantCauses {
				if !errors.Is(result.cause, cause) {
					t.Fatalf("cause = %v, want errors.Is(..., %v)", result.cause, cause)
				}
			}
		})
	}
}

func TestConcurrentZeroWinnerReconciliationRetainsOtherOperationalAmbiguity(t *testing.T) {
	t.Parallel()
	base := []byte("payload")
	store := &compatibilityReconciliationGetStore{object: Object{
		Data: compatibilityContenderPayload(base, 0), Version: Version{ETag: "winner-etag"},
	}}
	results := make([]compatibilityWriteResult, compatibilityContenders)
	for contender := range compatibilityContenders {
		results[contender] = compatibilityWriteResult{contender: contender, err: ErrPrecondition}
	}
	results[1].err = errors.Join(ErrPrecondition, ErrStoreUnavailable)
	report := StoreCompatibilityReport{RequiredChecks: 1}
	recorder := compatibilityRecorder{report: &report}

	reconciled, _, _, err := reconcileCompatibilityZeroWinner(
		context.Background(), recorder, StoreCompatibilityCheckConcurrentPutIfAbsent,
		store, "zero-winner-operational", base, nil, results,
	)
	if err != nil {
		t.Fatalf("zero-winner reconciliation: %v", err)
	}
	_, err = requireSingleCompatibilityWinner(recorder, StoreCompatibilityCheckConcurrentPutIfAbsent, reconciled)
	if err == nil || errors.Is(err, ErrStoreIncompatible) || !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("remaining operational contender error = %v, want indeterminate ErrStoreUnavailable", err)
	}
	if report.Status != StoreCompatibilityIndeterminate {
		t.Fatalf("report status = %q, want indeterminate", report.Status)
	}
}

func TestConcurrentZeroWinnerMissingStateDistinguishesSemanticFromOperational(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		operational  bool
		wantStatus   StoreCompatibilityStatus
		incompatible bool
	}{
		{name: "all-preconditions", wantStatus: StoreCompatibilityIncompatible, incompatible: true},
		{name: "one-operational", operational: true, wantStatus: StoreCompatibilityIndeterminate},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			results := make([]compatibilityWriteResult, compatibilityContenders)
			for contender := range compatibilityContenders {
				results[contender] = compatibilityWriteResult{contender: contender, err: ErrPrecondition}
			}
			if test.operational {
				results[0].err = ErrStoreUnavailable
			}
			report := StoreCompatibilityReport{RequiredChecks: 1}
			recorder := compatibilityRecorder{report: &report}
			_, _, _, err := reconcileCompatibilityZeroWinner(
				context.Background(), recorder, StoreCompatibilityCheckConcurrentPutIfAbsent,
				&compatibilityReconciliationGetStore{err: ErrObjectNotFound}, "missing", []byte("payload"), nil, results,
			)
			if err == nil || report.Status != test.wantStatus || errors.Is(err, ErrStoreIncompatible) != test.incompatible {
				t.Fatalf("error = %v, report = %+v, want status=%q incompatible=%v", err, report, test.wantStatus, test.incompatible)
			}
		})
	}
}

func TestCompatibilityCleanupUsesOneOverallDeadline(t *testing.T) {
	t.Parallel()
	store := &compatibilityCleanupDeadlineStore{}
	report := StoreCompatibilityReport{Cleanup: StoreCompatibilityCleanupReport{
		Status:                      StoreCompatibilityCleanupNotAttempted,
		CurrentObjectsMayRemain:     true,
		HistoricalVersionsMayRemain: true,
	}}
	keys := []string{"first", "second", "third"}

	started := time.Now()
	cleanupCompatibilityProbeWithTimeout(&report, store, store, keys, 25*time.Millisecond)
	elapsed := time.Since(started)

	if elapsed > time.Second {
		t.Fatalf("cleanup elapsed %v, want one bounded overall deadline", elapsed)
	}
	if store.deleteCalls != 1 || store.headCalls != 0 {
		t.Fatalf("calls = (delete=%d head=%d), want one blocked call and no calls after the shared deadline", store.deleteCalls, store.headCalls)
	}
	if report.Cleanup.Status != StoreCompatibilityCleanupFailed ||
		report.Cleanup.Reason != StoreCompatibilityCleanupReasonDeadlineExceeded ||
		report.Cleanup.Attempted != len(keys) || report.Cleanup.Failed != len(keys) ||
		report.Cleanup.DeleteFailures != len(keys) || report.Cleanup.VerificationFailures != len(keys) ||
		!report.Cleanup.CurrentObjectsMayRemain || !errors.Is(report.Cleanup.Cause, context.DeadlineExceeded) {
		t.Fatalf("cleanup = %+v, want all remaining keys failed under one shared deadline", report.Cleanup)
	}
}

func TestCompatibilityCleanupDefinitiveNotFoundRequiresPureTree(t *testing.T) {
	t.Parallel()
	opaque := &compatibilityCleanupOpaqueError{detail: "provider diagnostic"}
	classified := ClassifyObjectNotFound(opaque)
	var preserved *compatibilityCleanupOpaqueError
	if !errors.Is(classified, ErrObjectNotFound) || !errors.Is(classified, opaque) ||
		!errors.As(classified, &preserved) || preserved != opaque {
		t.Fatalf("classified error = %v, want missing-object marker with preserved provider cause", classified)
	}

	tests := []struct {
		name  string
		cause error
		want  bool
	}{
		{name: "sentinel", cause: ErrObjectNotFound, want: true},
		{name: "pure wrapper", cause: fmt.Errorf("missing: %w", ErrObjectNotFound), want: true},
		{name: "multiple pure wrappers", cause: fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", ErrObjectNotFound)), want: true},
		{name: "classified provider cause", cause: classified, want: true},
		{name: "wrapped classified provider cause", cause: fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", classified)), want: true},
		{name: "opaque sibling", cause: errors.Join(ErrObjectNotFound, opaque), want: false},
		{name: "wrapped opaque sibling", cause: fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", errors.Join(ErrObjectNotFound, opaque))), want: false},
		{name: "classified plus opaque sibling", cause: errors.Join(classified, errors.New("unclassified sibling")), want: false},
		{name: "all siblings definitive", cause: errors.Join(ErrObjectNotFound, fmt.Errorf("wrapped: %w", classified)), want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := compatibilityCleanupDefinitiveNotFound(test.cause); got != test.want {
				t.Fatalf("compatibilityCleanupDefinitiveNotFound(%v) = %v, want %v", test.cause, got, test.want)
			}
		})
	}
}

func TestCompatibilityCleanupMixedMissingAndOperationalCauseIsUnverified(t *testing.T) {
	t.Parallel()
	opaque := &compatibilityCleanupOpaqueError{detail: "opaque SDK failure"}
	for _, test := range []struct {
		name       string
		headErr    error
		wantReason StoreCompatibilityCleanupReason
		wantCause  error
	}{
		{
			name:       "known operational sibling",
			headErr:    errors.Join(ErrObjectNotFound, ErrStoreUnavailable),
			wantReason: StoreCompatibilityCleanupReasonStoreUnavailable,
			wantCause:  ErrStoreUnavailable,
		},
		{
			name:       "opaque sibling",
			headErr:    errors.Join(ErrObjectNotFound, opaque),
			wantReason: StoreCompatibilityCleanupReasonVerificationFailed,
			wantCause:  opaque,
		},
		{
			name:       "multiply wrapped opaque sibling",
			headErr:    fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", errors.Join(ErrObjectNotFound, opaque))),
			wantReason: StoreCompatibilityCleanupReasonVerificationFailed,
			wantCause:  opaque,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &compatibilityCleanupFixedStore{headErr: test.headErr}
			report := StoreCompatibilityReport{Cleanup: StoreCompatibilityCleanupReport{CurrentObjectsMayRemain: true}}

			cleanupCompatibilityProbeWithTimeout(&report, store, store, []string{"isolated"}, time.Second)

			if report.Cleanup.Status != StoreCompatibilityCleanupFailed ||
				report.Cleanup.Reason != test.wantReason ||
				report.Cleanup.VerificationFailures != 1 || report.Cleanup.Succeeded != 0 ||
				!report.Cleanup.CurrentObjectsMayRemain || !errors.Is(report.Cleanup.Cause, test.wantCause) {
				t.Fatalf("cleanup = %+v, want mixed missing/operational HEAD to remain unverified with reason %q", report.Cleanup, test.wantReason)
			}
		})
	}
}

func TestCompatibilityReportCompleteWhenFinalCheckFails(t *testing.T) {
	t.Parallel()
	report := StoreCompatibilityReport{RequiredChecks: 2}
	recorder := compatibilityRecorder{report: &report}
	recorder.pass(StoreCompatibilityCheckConfiguration)
	err := recorder.incompatible(StoreCompatibilityCheckHeadAfterConcurrentReplacement, "final check failed", nil)

	if !errors.Is(err, ErrStoreIncompatible) || !report.Complete || report.Compatible {
		t.Fatalf("report = %+v, error = %v; want complete incompatible report", report, err)
	}
}

type compatibilityReconciliationGetStore struct {
	Store
	object Object
	err    error
}

func (store *compatibilityReconciliationGetStore) Get(context.Context, string, GetOptions) (Object, error) {
	return store.object, store.err
}

type compatibilityCleanupDeadlineStore struct {
	Store
	deleteCalls int
	headCalls   int
}

func (store *compatibilityCleanupDeadlineStore) Delete(ctx context.Context, _ string) error {
	store.deleteCalls++
	<-ctx.Done()
	return ctx.Err()
}

func (store *compatibilityCleanupDeadlineStore) Head(ctx context.Context, _ string) (Version, error) {
	store.headCalls++
	<-ctx.Done()
	return Version{}, ctx.Err()
}

type compatibilityCleanupFixedStore struct {
	Store
	headErr error
}

type compatibilityCleanupOpaqueError struct {
	detail string
}

func (err *compatibilityCleanupOpaqueError) Error() string { return err.detail }

func (store *compatibilityCleanupFixedStore) Delete(context.Context, string) error {
	return nil
}

func (store *compatibilityCleanupFixedStore) Head(context.Context, string) (Version, error) {
	return Version{}, store.headErr
}
