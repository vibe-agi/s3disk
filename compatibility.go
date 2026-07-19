package s3disk

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const compatibilityContenders = 8

const compatibilityCleanupTimeout = 5 * time.Second

// compatibilityProbePayloadDomain separates probe objects from application
// data. The project has not published its first compatibility contract, so the
// internal payload domain remains v1 along with that pre-release contract.
const compatibilityProbePayloadDomain = "s3disk-store-probe-v1"

const compatibilityReconciledWriteDetail = "write response was ambiguous; an exact GET of this probe's isolated key matched the unique payload and supplied the observed version; this reconciles only this operation and does not establish network stability"

var errCompatibilityCleanupCurrentObjectStillVisible = errors.New("s3disk: compatibility cleanup current object remains visible")

// CheckStoreCompatibility performs the default commissioning probe and
// preserves the original error-only API. Use ProbeStoreCompatibility when a
// structured report is needed for certification or support diagnostics.
func (repository *Repository) CheckStoreCompatibility(ctx context.Context) error {
	_, err := repository.ProbeStoreCompatibility(ctx)
	return err
}

// ProbeStoreCompatibility performs a small destructive-to-random-keys probe
// below the repository namespace. It verifies the conditional, atomic, strong
// single-key read semantics required by the protocol and explains the first
// failed or inconclusive capability.
//
// Run this commissioning probe for every vendor, server version, gateway,
// proxy, bucket policy, encryption mode, and endpoint mode before enabling
// publication. A successful finite probe is evidence for that configuration,
// not a mathematical proof of all future behavior under every failure.
func (repository *Repository) ProbeStoreCompatibility(ctx context.Context) (report StoreCompatibilityReport, probeErr error) {
	return repository.ProbeStoreCompatibilityWithOptions(ctx, StoreCompatibilityProbeOptions{})
}

// ProbeStoreCompatibilityWithOptions performs the commissioning probe and
// optionally binds its redacted JSON evidence to caller-controlled deployment
// and implementation identifiers. Option validation happens before Store I/O.
// When ctx has no deadline and TotalTimeout is zero, the active probe receives
// StoreCompatibilityDefaultTimeout. Cleanup remains independently bounded and
// may run after that context ends; DurationNanoseconds includes cleanup.
func (repository *Repository) ProbeStoreCompatibilityWithOptions(
	ctx context.Context,
	options StoreCompatibilityProbeOptions,
) (report StoreCompatibilityReport, probeErr error) {
	started := time.Now()
	report = StoreCompatibilityReport{
		ContractVersion: StoreCompatibilityContractVersion,
		Scope:           StoreCompatibilitySingleClientFiniteProbe,
		Evidence:        newStoreCompatibilityEvidence(repository, StoreCompatibilityProbeOptions{}, started),
		Status:          StoreCompatibilityIndeterminate,
		RequiredChecks:  compatibilityRequiredChecks,
		Contenders:      compatibilityContenders,
		Checks:          make([]StoreCompatibilityCheck, 0, compatibilityRequiredChecks),
		Cleanup: StoreCompatibilityCleanupReport{
			Status: StoreCompatibilityCleanupNotAttempted,
		},
	}
	recorder := compatibilityRecorder{report: &report}
	defer func() {
		duration := time.Since(started)
		if duration < 0 {
			duration = 0
		}
		report.Evidence.DurationNanoseconds = duration.Nanoseconds()
	}()
	if err := validateStoreCompatibilityProbeOptions(options); err != nil {
		return compatibilityProbeResult(&report, recorder.problem(
			StoreCompatibilityCheckConfiguration,
			StoreCompatibilityConfigurationError,
			"invalid compatibility probe options",
			err,
		))
	}
	report.Evidence = newStoreCompatibilityEvidence(repository, options, started)
	probeCtx, cancel := compatibilityProbeContext(ctx, options)
	defer cancel()
	return repository.probeStoreCompatibility(probeCtx, report)
}

func (repository *Repository) probeStoreCompatibility(
	ctx context.Context,
	initialReport StoreCompatibilityReport,
) (report StoreCompatibilityReport, probeErr error) {
	report = initialReport
	recorder := compatibilityRecorder{report: &report}
	if repository == nil || repository.reader == nil {
		return compatibilityProbeResult(&report, recorder.problem(StoreCompatibilityCheckConfiguration, StoreCompatibilityConfigurationError, "repository or ObjectReader is nil", ErrStoreMisconfigured))
	}
	if repository.store == nil {
		return compatibilityProbeResult(&report, recorder.problem(StoreCompatibilityCheckConfiguration, StoreCompatibilityConfigurationError, "the full compatibility probe requires Head and conditional write authority", ErrRepositoryReadOnly))
	}
	if err := ctx.Err(); err != nil {
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckConfiguration, "probe context ended before store I/O", err))
	}
	recorder.pass(StoreCompatibilityCheckConfiguration)

	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return compatibilityProbeResult(&report, recorder.problem(StoreCompatibilityCheckProbeKey, StoreCompatibilityIndeterminate, "could not generate an isolated probe namespace", err))
	}
	report.ProbeID = hex.EncodeToString(nonce)
	recorder.pass(StoreCompatibilityCheckProbeKey)
	probePrefix := repository.key("probes/" + report.ProbeID)
	key := probePrefix + "/conditional"
	nilCASKey := probePrefix + "/nil-cas"
	missingCASKey := probePrefix + "/missing-if-match"
	concurrentPutKey := probePrefix + "/concurrent-put-if-absent"
	concurrentCASKey := probePrefix + "/concurrent-nil-cas"
	concurrentReplaceKey := probePrefix + "/concurrent-replace-cas"
	probeKeys := make([]string, 0, 6)
	trackProbeKey := func(key string) {
		probeKeys = append(probeKeys, key)
		report.Cleanup.CurrentObjectsMayRemain = true
		report.Cleanup.HistoricalVersionsMayRemain = true
	}
	if deleter, ok := repository.store.(ObjectDeleter); ok {
		defer func() { cleanupCompatibilityProbe(&report, repository.store, deleter, probeKeys) }()
	} else {
		report.Cleanup.Status = StoreCompatibilityCleanupNotSupported
		report.Cleanup.Reason = StoreCompatibilityCleanupReasonDeleteNotSupported
		report.Cleanup.Detail = "the Store does not implement ObjectDeleter; any tracked current probe objects may remain"
	}

	first := append([]byte(compatibilityProbePayloadDomain+":first:"), nonce...)
	second := append([]byte(compatibilityProbePayloadDomain+":second:"), nonce...)
	firstOriginal := append([]byte(nil), first...)
	secondOriginal := append([]byte(nil), second...)

	if _, err := repository.store.Head(ctx, key); !errors.Is(err, ErrObjectNotFound) {
		if err == nil {
			return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckMissingObjectMapping, "HEAD unexpectedly found a fresh random probe key", nil))
		}
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckMissingObjectMapping, "HEAD of a missing key did not return ErrObjectNotFound", err))
	}
	if _, err := repository.reader.Get(ctx, key, GetOptions{}); !errors.Is(err, ErrObjectNotFound) {
		if err == nil {
			return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckMissingObjectMapping, "GET unexpectedly found a fresh random probe key", nil))
		}
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckMissingObjectMapping, "GET of a missing key did not return ErrObjectNotFound", err))
	}
	recorder.pass(StoreCompatibilityCheckMissingObjectMapping)

	trackProbeKey(key)
	created, err := repository.store.PutIfAbsent(ctx, key, first)
	createdReconciled := false
	if err != nil {
		reconciliation := reconcileCompatibilityWrite(ctx, repository.reader, key, firstOriginal, nil, err)
		if !reconciliation.applied {
			return compatibilityProbeResult(&report, recorder.problem(
				StoreCompatibilityCheckConditionalCreate,
				reconciliation.status,
				"conditional create response was ambiguous; "+reconciliation.detail,
				reconciliation.cause,
			))
		}
		created = reconciliation.version
		createdReconciled = true
	}
	if err := validateStoreVersion("compatibility conditional create", created); err != nil {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckConditionalCreate, "conditional create returned an invalid version token", err))
	}
	if createdReconciled {
		recorder.passDetail(StoreCompatibilityCheckConditionalCreate, compatibilityReconciledWriteDetail)
	} else {
		recorder.pass(StoreCompatibilityCheckConditionalCreate)
	}

	// A Store must finish consuming or copy request data before a write returns.
	// Publisher buffers are deliberately reused.
	first[0] ^= 0xff
	headed, err := repository.store.Head(ctx, key)
	if err != nil {
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckHeadAfterCreate, "HEAD failed after a completed create", err))
	}
	if err := validateStoreVersion("compatibility HEAD after create", headed); err != nil {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckHeadAfterCreate, "HEAD returned an invalid version token", err))
	}
	if headed.ETag != created.ETag {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckHeadAfterCreate, "HEAD returned a different ETag from the completed create", nil))
	}
	recorder.pass(StoreCompatibilityCheckHeadAfterCreate)

	observed, err := repository.reader.Get(ctx, key, GetOptions{})
	if err != nil {
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckReadAfterCreate, "GET failed after a completed create", err))
	}
	if err := validateStoreVersion("compatibility GET after create", observed.Version); err != nil {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckReadAfterCreate, "GET returned an invalid version token", err))
	}
	if !bytes.Equal(observed.Data, firstOriginal) {
		if bytes.Equal(observed.Data, first) {
			return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckInputBufferOwnership, "stored data changed when the caller reused its input buffer", nil))
		}
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckReadAfterCreate, "GET returned bytes different from the completed create", nil))
	}
	if observed.Version.ETag != created.ETag {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckReadAfterCreate, "GET returned a different ETag from the completed create", nil))
	}
	recorder.pass(StoreCompatibilityCheckReadAfterCreate)
	recorder.pass(StoreCompatibilityCheckInputBufferOwnership)

	if _, err := repository.store.PutIfAbsent(ctx, key, second); !errors.Is(err, ErrPrecondition) {
		if err == nil {
			return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckDuplicateCreate, "duplicate conditional create succeeded", nil))
		}
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckDuplicateCreate, "duplicate conditional create did not return ErrPrecondition", err))
	}
	duplicateObserved, err := repository.reader.Get(ctx, key, GetOptions{})
	if err != nil {
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckDuplicateCreate, "could not verify data after a rejected duplicate create", err))
	}
	if err := validateStoreVersion("compatibility GET after duplicate create", duplicateObserved.Version); err != nil {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckDuplicateCreate, "GET after duplicate create returned an invalid version token", err))
	}
	if !bytes.Equal(duplicateObserved.Data, firstOriginal) || duplicateObserved.Version.ETag != created.ETag {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckDuplicateCreate, "rejected duplicate create modified data or version", nil))
	}
	observed = duplicateObserved
	recorder.pass(StoreCompatibilityCheckDuplicateCreate)

	exact, err := repository.reader.Get(ctx, key, GetOptions{MaxBytes: int64(len(firstOriginal))})
	if err != nil {
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckBoundedGet, "GET rejected a body exactly equal to MaxBytes", err))
	}
	if err := validateStoreVersion("compatibility bounded GET", exact.Version); err != nil {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckBoundedGet, "bounded GET returned an invalid version token", err))
	}
	if !bytes.Equal(exact.Data, firstOriginal) || exact.Version.ETag != created.ETag {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckBoundedGet, "bounded GET returned different data or version", nil))
	}
	if _, err := repository.reader.Get(ctx, key, GetOptions{MaxBytes: int64(len(firstOriginal) - 1)}); !errors.Is(err, ErrResourceLimit) {
		if err == nil {
			return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckBoundedGet, "GET ignored a positive MaxBytes smaller than the body", nil))
		}
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckBoundedGet, "oversized bounded GET did not return ErrResourceLimit", err))
	}
	recorder.pass(StoreCompatibilityCheckBoundedGet)

	// Successful GET calls must return independent caller-owned buffers.
	observed.Data[0] ^= 0xff
	observedAgain, err := repository.reader.Get(ctx, key, GetOptions{})
	if err != nil {
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckOutputBufferOwnership, "second GET failed while checking buffer ownership", err))
	}
	if err := validateStoreVersion("compatibility second GET", observedAgain.Version); err != nil {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckOutputBufferOwnership, "second GET returned an invalid version token", err))
	}
	if !bytes.Equal(observedAgain.Data, firstOriginal) || observedAgain.Version.ETag != created.ETag {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckOutputBufferOwnership, "mutating one GET result changed a later GET result", nil))
	}
	observed = observedAgain
	recorder.pass(StoreCompatibilityCheckOutputBufferOwnership)

	// VersionID is diagnostic only. Deliberately change it to catch adapters
	// that incorrectly strengthen the ETag condition with a provider version ID.
	currentExpected := observed.Version
	currentExpected.VersionID = "s3disk-probe-version-id-must-be-ignored"
	replaced, err := repository.store.CompareAndSwap(ctx, key, &currentExpected, second)
	replacedReconciled := false
	if err != nil {
		beforeReplacement := observed
		reconciliation := reconcileCompatibilityWrite(ctx, repository.reader, key, secondOriginal, &beforeReplacement, err)
		if !reconciliation.applied {
			return compatibilityProbeResult(&report, recorder.problem(
				StoreCompatibilityCheckReplacementCAS,
				reconciliation.status,
				"CAS response was ambiguous; "+reconciliation.detail,
				reconciliation.cause,
			))
		}
		replaced = reconciliation.version
		replacedReconciled = true
	}
	if err := validateStoreVersion("compatibility replacement CAS", replaced); err != nil {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckReplacementCAS, "replacement CAS returned an invalid version token", err))
	}
	if replaced.ETag == created.ETag {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckReplacementCAS, "different object bytes reused the previous ETag, so stale CAS cannot be detected", nil))
	}
	if replacedReconciled {
		recorder.passDetail(StoreCompatibilityCheckReplacementCAS, compatibilityReconciledWriteDetail)
	} else {
		recorder.pass(StoreCompatibilityCheckReplacementCAS)
	}

	second[0] ^= 0xff
	current, err := repository.reader.Get(ctx, key, GetOptions{})
	if err != nil {
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckReadAfterReplacement, "GET failed after a completed replacement", err))
	}
	if err := validateStoreVersion("compatibility GET after replacement", current.Version); err != nil {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckReadAfterReplacement, "GET returned an invalid replacement version token", err))
	}
	if !bytes.Equal(current.Data, secondOriginal) {
		if bytes.Equal(current.Data, second) {
			return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckCASInputBufferOwnership, "stored data changed when the caller reused its CAS input buffer", nil))
		}
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckReadAfterReplacement, "GET did not return the completed replacement bytes", nil))
	}
	if current.Version.ETag != replaced.ETag {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckReadAfterReplacement, "GET returned a different ETag from the completed replacement", nil))
	}
	recorder.pass(StoreCompatibilityCheckReadAfterReplacement)
	recorder.pass(StoreCompatibilityCheckCASInputBufferOwnership)
	headed, err = repository.store.Head(ctx, key)
	if err != nil {
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckHeadAfterReplacement, "HEAD failed after a completed replacement", err))
	}
	if err := validateStoreVersion("compatibility HEAD after replacement", headed); err != nil {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckHeadAfterReplacement, "HEAD returned an invalid replacement version token", err))
	}
	if headed.ETag != current.Version.ETag {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckHeadAfterReplacement, "HEAD and GET returned different replacement ETags", nil))
	}
	recorder.pass(StoreCompatibilityCheckHeadAfterReplacement)

	// Reuse the provider-issued ETag from the first version as a syntactically
	// valid stale token. ETags are opaque and must never be modified or parsed by
	// the probe to manufacture a condition.
	staleExpected := created
	if _, err := repository.store.CompareAndSwap(ctx, key, &staleExpected, firstOriginal); !errors.Is(err, ErrPrecondition) {
		if err == nil {
			return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckStaleCAS, "CAS with a stale ETag succeeded", nil))
		}
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckStaleCAS, "CAS with a stale ETag did not return ErrPrecondition", err))
	}
	recorder.pass(StoreCompatibilityCheckStaleCAS)
	unchanged, err := repository.reader.Get(ctx, key, GetOptions{})
	if err != nil {
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckFailedCASPreservesObject, "could not verify data after a rejected stale CAS", err))
	}
	if err := validateStoreVersion("compatibility GET after stale CAS", unchanged.Version); err != nil {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckFailedCASPreservesObject, "GET after stale CAS returned an invalid version token", err))
	}
	if !bytes.Equal(unchanged.Data, secondOriginal) || unchanged.Version.ETag != replaced.ETag {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckFailedCASPreservesObject, "rejected stale CAS modified data or version", nil))
	}
	recorder.pass(StoreCompatibilityCheckFailedCASPreservesObject)

	if _, err := repository.reader.Get(ctx, key, GetOptions{IfNoneMatch: current.Version.ETag}); !errors.Is(err, ErrNotModified) {
		if err == nil {
			return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckConditionalGetCurrent, "GET with the current ETag returned the object instead of ErrNotModified", nil))
		}
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckConditionalGetCurrent, "GET with the current ETag did not return ErrNotModified", err))
	}
	recorder.pass(StoreCompatibilityCheckConditionalGetCurrent)
	staleConditional, err := repository.reader.Get(ctx, key, GetOptions{IfNoneMatch: created.ETag})
	if err != nil {
		if errors.Is(err, ErrNotModified) {
			return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckConditionalGetStale, "GET with an old ETag incorrectly returned ErrNotModified", err))
		}
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckConditionalGetStale, "GET with an old ETag failed", err))
	}
	if err := validateStoreVersion("compatibility GET with stale If-None-Match", staleConditional.Version); err != nil {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckConditionalGetStale, "conditional GET returned an invalid version token", err))
	}
	if !bytes.Equal(staleConditional.Data, secondOriginal) || staleConditional.Version.ETag != replaced.ETag {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckConditionalGetStale, "GET with an old ETag did not return the current object", nil))
	}
	recorder.pass(StoreCompatibilityCheckConditionalGetStale)

	// Publisher.Commit uses nil expected for a channel's first publication.
	trackProbeKey(nilCASKey)
	nilCreated, err := repository.store.CompareAndSwap(ctx, nilCASKey, nil, firstOriginal)
	nilCreatedReconciled := false
	if err != nil {
		reconciliation := reconcileCompatibilityWrite(ctx, repository.reader, nilCASKey, firstOriginal, nil, err)
		if !reconciliation.applied {
			return compatibilityProbeResult(&report, recorder.problem(
				StoreCompatibilityCheckNilCASCreate,
				reconciliation.status,
				"nil-expected CAS response was ambiguous; "+reconciliation.detail,
				reconciliation.cause,
			))
		}
		nilCreated = reconciliation.version
		nilCreatedReconciled = true
	}
	if err := validateStoreVersion("compatibility nil-expected CAS", nilCreated); err != nil {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckNilCASCreate, "nil-expected CAS returned an invalid version token", err))
	}
	if nilCreatedReconciled {
		recorder.passDetail(StoreCompatibilityCheckNilCASCreate, compatibilityReconciledWriteDetail)
	} else {
		recorder.pass(StoreCompatibilityCheckNilCASCreate)
	}
	if _, err := repository.store.CompareAndSwap(ctx, nilCASKey, nil, secondOriginal); !errors.Is(err, ErrPrecondition) {
		if err == nil {
			return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckNilCASDuplicate, "duplicate nil-expected CAS succeeded", nil))
		}
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckNilCASDuplicate, "duplicate nil-expected CAS did not return ErrPrecondition", err))
	}
	recorder.pass(StoreCompatibilityCheckNilCASDuplicate)
	nilObserved, err := repository.reader.Get(ctx, nilCASKey, GetOptions{})
	if err != nil {
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckNilCASPreservesObject, "could not verify data after a rejected nil-expected CAS", err))
	}
	if err := validateStoreVersion("compatibility GET after duplicate nil CAS", nilObserved.Version); err != nil {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckNilCASPreservesObject, "GET after duplicate nil CAS returned an invalid version token", err))
	}
	if !bytes.Equal(nilObserved.Data, firstOriginal) || nilObserved.Version.ETag != nilCreated.ETag {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckNilCASPreservesObject, "rejected nil-expected CAS modified data or version", nil))
	}
	recorder.pass(StoreCompatibilityCheckNilCASPreservesObject)

	trackProbeKey(missingCASKey)
	missingExpected := current.Version
	if _, err := repository.store.CompareAndSwap(ctx, missingCASKey, &missingExpected, firstOriginal); !errors.Is(err, ErrPrecondition) {
		if err == nil {
			return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckMissingKeyCAS, "CAS with If-Match created a missing object", nil))
		}
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckMissingKeyCAS, "CAS against a missing key did not return ErrPrecondition", err))
	}
	if _, err := repository.store.Head(ctx, missingCASKey); !errors.Is(err, ErrObjectNotFound) {
		if err == nil {
			return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckMissingKeyCAS, "CAS reported ErrPrecondition but still created the missing object", nil))
		}
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckMissingKeyCAS, "could not verify the missing key after rejected CAS", err))
	}
	recorder.pass(StoreCompatibilityCheckMissingKeyCAS)

	trackProbeKey(concurrentPutKey)
	putResults := runCompatibilityContenders(func(contender int, data []byte) (Version, error) {
		return repository.store.PutIfAbsent(ctx, concurrentPutKey, data)
	}, firstOriginal)
	var putObserved Object
	putReconciledDetail := ""
	if compatibilitySuccessCount(putResults) == 0 {
		putResults, putObserved, putReconciledDetail, err = reconcileCompatibilityZeroWinner(
			ctx, recorder, StoreCompatibilityCheckConcurrentPutIfAbsent,
			repository.reader, concurrentPutKey, firstOriginal, nil, putResults,
		)
		if err != nil {
			return report, err
		}
	}
	putWinner, err := requireSingleCompatibilityWinner(recorder, StoreCompatibilityCheckConcurrentPutIfAbsent, putResults)
	if err != nil {
		return report, err
	}
	if putReconciledDetail != "" {
		recorder.passDetail(StoreCompatibilityCheckConcurrentPutIfAbsent, putReconciledDetail)
	} else {
		recorder.pass(StoreCompatibilityCheckConcurrentPutIfAbsent)
		putObserved, err = repository.reader.Get(ctx, concurrentPutKey, GetOptions{})
		if err != nil {
			return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckReadAfterConcurrentPut, "GET failed after concurrent conditional create", err))
		}
	}
	if err := validateStoreVersion("compatibility GET after concurrent PutIfAbsent", putObserved.Version); err != nil {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckReadAfterConcurrentPut, "GET returned an invalid winner version token", err))
	}
	if !compatibilityObjectMatchesWinner(putObserved, firstOriginal, putWinner) {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckReadAfterConcurrentPut, "stored object or ETag does not match the sole successful contender", nil))
	}
	putHead, err := repository.store.Head(ctx, concurrentPutKey)
	if err != nil {
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckReadAfterConcurrentPut, "HEAD failed after concurrent conditional create", err))
	}
	if err := validateStoreVersion("compatibility HEAD after concurrent PutIfAbsent", putHead); err != nil {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckReadAfterConcurrentPut, "HEAD returned an invalid winner version token", err))
	}
	if putHead.ETag != putWinner.version.ETag {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckReadAfterConcurrentPut, "HEAD does not identify the sole successful contender", nil))
	}
	recorder.pass(StoreCompatibilityCheckReadAfterConcurrentPut)

	trackProbeKey(concurrentCASKey)
	nilResults := runCompatibilityContenders(func(contender int, data []byte) (Version, error) {
		return repository.store.CompareAndSwap(ctx, concurrentCASKey, nil, data)
	}, firstOriginal)
	var concurrentObserved Object
	nilReconciledDetail := ""
	if compatibilitySuccessCount(nilResults) == 0 {
		nilResults, concurrentObserved, nilReconciledDetail, err = reconcileCompatibilityZeroWinner(
			ctx, recorder, StoreCompatibilityCheckConcurrentNilCAS,
			repository.reader, concurrentCASKey, firstOriginal, nil, nilResults,
		)
		if err != nil {
			return report, err
		}
	}
	nilWinner, err := requireSingleCompatibilityWinner(recorder, StoreCompatibilityCheckConcurrentNilCAS, nilResults)
	if err != nil {
		return report, err
	}
	if nilReconciledDetail != "" {
		recorder.passDetail(StoreCompatibilityCheckConcurrentNilCAS, nilReconciledDetail)
	} else {
		recorder.pass(StoreCompatibilityCheckConcurrentNilCAS)
		concurrentObserved, err = repository.reader.Get(ctx, concurrentCASKey, GetOptions{})
		if err != nil {
			return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckReadAfterConcurrentNilCAS, "GET failed after concurrent nil-expected CAS", err))
		}
	}
	if err := validateStoreVersion("compatibility GET after concurrent nil CAS", concurrentObserved.Version); err != nil {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckReadAfterConcurrentNilCAS, "GET returned an invalid winner version token", err))
	}
	if !compatibilityObjectMatchesWinner(concurrentObserved, firstOriginal, nilWinner) {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckReadAfterConcurrentNilCAS, "stored object or ETag does not match the sole successful contender", nil))
	}
	recorder.pass(StoreCompatibilityCheckReadAfterConcurrentNilCAS)
	concurrentHead, err := repository.store.Head(ctx, concurrentCASKey)
	if err != nil {
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckHeadAfterConcurrentNilCAS, "HEAD failed after concurrent nil-expected CAS", err))
	}
	if err := validateStoreVersion("compatibility HEAD after concurrent nil CAS", concurrentHead); err != nil {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckHeadAfterConcurrentNilCAS, "HEAD returned an invalid winner version token", err))
	}
	if concurrentHead.ETag != nilWinner.version.ETag {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckHeadAfterConcurrentNilCAS, "HEAD does not identify the sole successful contender", nil))
	}
	recorder.pass(StoreCompatibilityCheckHeadAfterConcurrentNilCAS)

	trackProbeKey(concurrentReplaceKey)
	replaceBase, err := repository.store.CompareAndSwap(ctx, concurrentReplaceKey, nil, firstOriginal)
	replaceBaseReconciled := false
	if err != nil {
		reconciliation := reconcileCompatibilityWrite(ctx, repository.reader, concurrentReplaceKey, firstOriginal, nil, err)
		if !reconciliation.applied {
			return compatibilityProbeResult(&report, recorder.problem(
				StoreCompatibilityCheckConcurrentReplacementSeed,
				reconciliation.status,
				"concurrent replacement seed response was ambiguous; "+reconciliation.detail,
				reconciliation.cause,
			))
		}
		replaceBase = reconciliation.version
		replaceBaseReconciled = true
	}
	if err := validateStoreVersion("compatibility concurrent replacement seed", replaceBase); err != nil {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckConcurrentReplacementSeed, "replacement seed returned an invalid version token", err))
	}
	if replaceBaseReconciled {
		recorder.passDetail(StoreCompatibilityCheckConcurrentReplacementSeed, compatibilityReconciledWriteDetail)
	} else {
		recorder.pass(StoreCompatibilityCheckConcurrentReplacementSeed)
	}
	replaceResults := runCompatibilityContenders(func(contender int, data []byte) (Version, error) {
		expected := replaceBase
		return repository.store.CompareAndSwap(ctx, concurrentReplaceKey, &expected, data)
	}, secondOriginal)
	var replacedConcurrent Object
	replaceReconciledDetail := ""
	if compatibilitySuccessCount(replaceResults) == 0 {
		prior := &Object{Data: firstOriginal, Version: replaceBase}
		replaceResults, replacedConcurrent, replaceReconciledDetail, err = reconcileCompatibilityZeroWinner(
			ctx, recorder, StoreCompatibilityCheckConcurrentReplacementCAS,
			repository.reader, concurrentReplaceKey, secondOriginal, prior, replaceResults,
		)
		if err != nil {
			return report, err
		}
	}
	replaceWinner, err := requireSingleCompatibilityWinner(recorder, StoreCompatibilityCheckConcurrentReplacementCAS, replaceResults)
	if err != nil {
		return report, err
	}
	if replaceWinner.version.ETag == replaceBase.ETag {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckConcurrentReplacementCAS, "winning replacement reused the seed ETag for different bytes", nil))
	}
	if replaceReconciledDetail != "" {
		recorder.passDetail(StoreCompatibilityCheckConcurrentReplacementCAS, replaceReconciledDetail)
	} else {
		recorder.pass(StoreCompatibilityCheckConcurrentReplacementCAS)
		replacedConcurrent, err = repository.reader.Get(ctx, concurrentReplaceKey, GetOptions{})
		if err != nil {
			return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckReadAfterConcurrentReplacement, "GET failed after concurrent replacement CAS", err))
		}
	}
	if err := validateStoreVersion("compatibility GET after concurrent replacement", replacedConcurrent.Version); err != nil {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckReadAfterConcurrentReplacement, "GET returned an invalid replacement-winner version", err))
	}
	if !compatibilityObjectMatchesWinner(replacedConcurrent, secondOriginal, replaceWinner) {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckReadAfterConcurrentReplacement, "stored object or ETag does not match the sole successful replacement", nil))
	}
	recorder.pass(StoreCompatibilityCheckReadAfterConcurrentReplacement)
	replacedHead, err := repository.store.Head(ctx, concurrentReplaceKey)
	if err != nil {
		return compatibilityProbeResult(&report, recorder.operationFailure(StoreCompatibilityCheckHeadAfterConcurrentReplacement, "HEAD failed after concurrent replacement CAS", err))
	}
	if err := validateStoreVersion("compatibility HEAD after concurrent replacement", replacedHead); err != nil {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckHeadAfterConcurrentReplacement, "HEAD returned an invalid replacement-winner version", err))
	}
	if replacedHead.ETag != replaceWinner.version.ETag {
		return compatibilityProbeResult(&report, recorder.incompatible(StoreCompatibilityCheckHeadAfterConcurrentReplacement, "HEAD does not identify the sole successful replacement", nil))
	}
	recorder.pass(StoreCompatibilityCheckHeadAfterConcurrentReplacement)

	report.Status = StoreCompatibilityPassed
	report.Compatible = true
	return report, nil
}

type compatibilityWriteReconciliation struct {
	applied bool
	version Version
	status  StoreCompatibilityStatus
	detail  string
	cause   error
}

func reconcileCompatibilityWrite(
	ctx context.Context,
	reader ObjectReader,
	key string,
	payload []byte,
	previous *Object,
	operationErr error,
) compatibilityWriteReconciliation {
	maximum := int64(len(payload))
	if previous != nil && int64(len(previous.Data)) > maximum {
		maximum = int64(len(previous.Data))
	}
	observed, getErr := reader.Get(ctx, key, GetOptions{MaxBytes: maximum})
	if getErr != nil {
		cause := errors.Join(operationErr, getErr)
		switch {
		case errors.Is(getErr, ErrResourceLimit):
			return compatibilityWriteReconciliation{
				status: StoreCompatibilityIncompatible,
				detail: "the isolated key contains an object larger than either the attempted payload or its expected prior state",
				cause:  cause,
			}
		case errors.Is(getErr, ErrObjectNotFound):
			if previous != nil {
				return compatibilityWriteReconciliation{
					status: StoreCompatibilityIncompatible,
					detail: "the isolated replacement key disappeared while reconciling the write",
					cause:  cause,
				}
			}
			status := compatibilityReconciliationStatus(operationErr)
			detail := "the isolated key remains absent, so the write outcome was not applied and is inconclusive"
			if status == StoreCompatibilityIncompatible {
				detail = "the isolated key remains absent even though the satisfied create condition was reported as failed"
			}
			return compatibilityWriteReconciliation{status: status, detail: detail, cause: cause}
		default:
			return compatibilityWriteReconciliation{
				status: compatibilityReconciliationFailureStatus(operationErr, getErr),
				detail: "the isolated key could not be read to reconcile the ambiguous write response",
				cause:  cause,
			}
		}
	}
	if err := validateStoreVersion("compatibility reconciliation GET", observed.Version); err != nil {
		return compatibilityWriteReconciliation{
			status: StoreCompatibilityIncompatible,
			detail: "the reconciliation GET returned an invalid version token",
			cause:  errors.Join(operationErr, err),
		}
	}
	if bytes.Equal(observed.Data, payload) {
		if previous != nil && observed.Version.ETag == previous.Version.ETag {
			return compatibilityWriteReconciliation{
				status: StoreCompatibilityIncompatible,
				detail: "the replacement bytes were stored but reused the prior ETag",
				cause:  operationErr,
			}
		}
		if !compatibilityWriteCanReconcile(operationErr) {
			return compatibilityWriteReconciliation{
				status: compatibilityReconciliationStatus(operationErr),
				detail: "the payload is present, but the returned error is not an ambiguous retry or operational outcome that the probe can reconcile",
				cause:  operationErr,
			}
		}
		return compatibilityWriteReconciliation{applied: true, version: observed.Version}
	}
	if previous != nil && bytes.Equal(observed.Data, previous.Data) && observed.Version.ETag == previous.Version.ETag {
		status := compatibilityReconciliationStatus(operationErr)
		detail := "the expected prior state is unchanged, so the replacement outcome is inconclusive"
		if status == StoreCompatibilityIncompatible {
			detail = "the expected prior state is unchanged even though its matching ETag was reported as a failed precondition"
		}
		return compatibilityWriteReconciliation{status: status, detail: detail, cause: operationErr}
	}
	return compatibilityWriteReconciliation{
		status: StoreCompatibilityIncompatible,
		detail: "the isolated key contains neither the attempted payload nor its exact expected prior state",
		cause:  operationErr,
	}
}

func compatibilityWriteCanReconcile(cause error) bool {
	if compatibilityDefinitiveIncompatibility(cause) {
		return false
	}
	status := compatibilityReconciliationStatus(cause)
	return errors.Is(cause, ErrPrecondition) || status == StoreCompatibilityIndeterminate
}

func compatibilityDefinitivePrecondition(cause error) bool {
	if !errors.Is(cause, ErrPrecondition) || compatibilityDefinitiveIncompatibility(cause) {
		return false
	}
	if errors.Is(cause, ErrAccessDenied) || errors.Is(cause, ErrBucketNotFound) ||
		errors.Is(cause, ErrStoreMisconfigured) || errors.Is(cause, context.Canceled) ||
		errors.Is(cause, context.DeadlineExceeded) || errors.Is(cause, ErrRateLimited) ||
		errors.Is(cause, ErrStoreUnavailable) {
		return false
	}
	var networkError net.Error
	return !errors.As(cause, &networkError)
}

func compatibilityDefinitiveIncompatibility(cause error) bool {
	return errors.Is(cause, ErrStoreIncompatible) ||
		errors.Is(cause, ErrStoreOperationUnsupported) ||
		errors.Is(cause, ErrObjectNotFound) ||
		errors.Is(cause, ErrNotModified) ||
		errors.Is(cause, ErrResourceLimit)
}

// compatibilityReconciliationStatus deliberately considers operational causes
// before ErrPrecondition. A retried conditional write can return a final 412
// after its first request was applied and its response was lost.
func compatibilityReconciliationStatus(cause error) StoreCompatibilityStatus {
	switch {
	case compatibilityDefinitiveIncompatibility(cause):
		return StoreCompatibilityIncompatible
	case errors.Is(cause, ErrAccessDenied):
		return StoreCompatibilityPermissionDenied
	case errors.Is(cause, ErrBucketNotFound), errors.Is(cause, ErrStoreMisconfigured):
		return StoreCompatibilityConfigurationError
	case errors.Is(cause, context.Canceled), errors.Is(cause, context.DeadlineExceeded),
		errors.Is(cause, ErrRateLimited), errors.Is(cause, ErrStoreUnavailable):
		return StoreCompatibilityIndeterminate
	}
	var networkError net.Error
	if errors.As(cause, &networkError) {
		return StoreCompatibilityIndeterminate
	}
	if errors.Is(cause, ErrPrecondition) {
		return StoreCompatibilityIncompatible
	}
	return StoreCompatibilityIndeterminate
}

func compatibilityReconciliationFailureStatus(causes ...error) StoreCompatibilityStatus {
	result := StoreCompatibilityIndeterminate
	for _, cause := range causes {
		if compatibilityDefinitiveIncompatibility(cause) {
			return StoreCompatibilityIncompatible
		}
		switch compatibilityReconciliationStatus(cause) {
		case StoreCompatibilityPermissionDenied:
			result = StoreCompatibilityPermissionDenied
		case StoreCompatibilityConfigurationError:
			if result != StoreCompatibilityPermissionDenied {
				result = StoreCompatibilityConfigurationError
			}
		}
	}
	return result
}

func compatibilitySuccessCount(results []compatibilityWriteResult) int {
	successes := 0
	for _, result := range results {
		if result.err == nil {
			successes++
		}
	}
	return successes
}

func reconcileCompatibilityZeroWinner(
	ctx context.Context,
	recorder compatibilityRecorder,
	id StoreCompatibilityCheckID,
	reader ObjectReader,
	key string,
	base []byte,
	previous *Object,
	results []compatibilityWriteResult,
) ([]compatibilityWriteResult, Object, string, error) {
	maximum := int64(len(base) + 1)
	if previous != nil && int64(len(previous.Data)) > maximum {
		maximum = int64(len(previous.Data))
	}
	observed, getErr := reader.Get(ctx, key, GetOptions{MaxBytes: maximum})
	operationalErrors := make([]error, 0, len(results))
	allErrors := make([]error, 0, len(results)+1)
	for _, result := range results {
		allErrors = append(allErrors, result.err)
		if result.err != nil && !compatibilityDefinitivePrecondition(result.err) {
			operationalErrors = append(operationalErrors, result.err)
		}
	}
	if getErr != nil {
		allErrors = append(allErrors, getErr)
		cause := errors.Join(allErrors...)
		switch {
		case errors.Is(getErr, ErrResourceLimit):
			return nil, Object{}, "", recorder.incompatible(id, "the isolated concurrent key contains an object larger than every contender payload", cause)
		case errors.Is(getErr, ErrObjectNotFound):
			if previous == nil && len(operationalErrors) != 0 {
				return nil, Object{}, "", recorder.problem(
					id, compatibilityReconciliationFailureStatus(operationalErrors...),
					"no contender returned success and the isolated key remains absent after operationally ambiguous responses",
					cause,
				)
			}
			if previous == nil {
				return nil, Object{}, "", recorder.incompatible(id, "all contenders reported failed preconditions but the isolated create key remains absent", cause)
			}
			return nil, Object{}, "", recorder.incompatible(id, "the isolated replacement key disappeared while reconciling zero successful contenders", cause)
		default:
			causes := append(operationalErrors, getErr)
			return nil, Object{}, "", recorder.problem(
				id, compatibilityReconciliationFailureStatus(causes...),
				"no contender returned success and the isolated key could not be read for reconciliation",
				cause,
			)
		}
	}
	if err := validateStoreVersion("compatibility concurrent reconciliation GET", observed.Version); err != nil {
		allErrors = append(allErrors, err)
		return nil, Object{}, "", recorder.incompatible(id, "the concurrent reconciliation GET returned an invalid version token", errors.Join(allErrors...))
	}
	if previous != nil && observed.Version.ETag == previous.Version.ETag && !bytes.Equal(observed.Data, previous.Data) {
		return nil, Object{}, "", recorder.incompatible(id, "a concurrent replacement changed bytes but reused the seed ETag", errors.Join(allErrors...))
	}
	matched := -1
	for index, result := range results {
		if bytes.Equal(observed.Data, compatibilityContenderPayload(base, result.contender)) {
			if matched != -1 {
				return nil, Object{}, "", recorder.incompatible(id, "multiple contender identities matched one stored payload", errors.Join(allErrors...))
			}
			matched = index
		}
	}
	if matched == -1 {
		if previous != nil && bytes.Equal(observed.Data, previous.Data) && observed.Version.ETag == previous.Version.ETag && len(operationalErrors) != 0 {
			return nil, Object{}, "", recorder.problem(
				id, compatibilityReconciliationFailureStatus(operationalErrors...),
				"no contender returned success and the exact seed state remains after operationally ambiguous responses",
				errors.Join(allErrors...),
			)
		}
		return nil, Object{}, "", recorder.incompatible(id, "the isolated key matches neither a unique contender payload nor its exact expected prior state", errors.Join(allErrors...))
	}
	if !compatibilityWriteCanReconcile(results[matched].err) {
		return nil, Object{}, "", recorder.problem(
			id, compatibilityReconciliationStatus(results[matched].err),
			fmt.Sprintf("contender %d's payload is present, but its error is not an ambiguous retry or operational outcome", results[matched].contender),
			results[matched].err,
		)
	}
	reconciled := append([]compatibilityWriteResult(nil), results...)
	reconciled[matched].version = observed.Version
	reconciled[matched].err = nil
	detail := fmt.Sprintf("all responses were ambiguous; an exact GET of this probe's isolated key matched contender %d's unique payload and supplied the observed version; this reconciles only this batch and does not establish network stability", reconciled[matched].contender)
	return reconciled, observed, detail, nil
}

type compatibilityWriteResult struct {
	contender int
	version   Version
	err       error
}

func runCompatibilityContenders(write func(contender int, data []byte) (Version, error), base []byte) []compatibilityWriteResult {
	start := make(chan struct{})
	results := make(chan compatibilityWriteResult, compatibilityContenders)
	var ready sync.WaitGroup
	ready.Add(compatibilityContenders)
	for contender := range compatibilityContenders {
		go func() {
			data := compatibilityContenderPayload(base, contender)
			ready.Done()
			<-start
			version, err := write(contender, data)
			results <- compatibilityWriteResult{contender: contender, version: version, err: err}
		}()
	}
	ready.Wait()
	close(start)
	collected := make([]compatibilityWriteResult, 0, compatibilityContenders)
	for range compatibilityContenders {
		collected = append(collected, <-results)
	}
	return collected
}

func requireSingleCompatibilityWinner(recorder compatibilityRecorder, id StoreCompatibilityCheckID, results []compatibilityWriteResult) (compatibilityWriteResult, error) {
	var winner compatibilityWriteResult
	winners := 0
	var invalidWinner error
	invalidContender := -1
	var unexpectedErrors []error
	var unexpectedContenders []int
	for _, result := range results {
		if result.err == nil {
			if err := validateStoreVersion("compatibility concurrent winner", result.version); err != nil {
				if invalidWinner == nil {
					invalidWinner = err
					invalidContender = result.contender
				}
			}
			winner = result
			winners++
			continue
		}
		if !compatibilityDefinitivePrecondition(result.err) {
			unexpectedErrors = append(unexpectedErrors, result.err)
			unexpectedContenders = append(unexpectedContenders, result.contender)
		}
	}
	// Semantic contradictions outrank transient/configuration failures from the
	// same batch. The verdict must not depend on goroutine completion order.
	if invalidWinner != nil {
		causes := append([]error{invalidWinner}, unexpectedErrors...)
		return compatibilityWriteResult{}, recorder.incompatible(id, fmt.Sprintf("contender %d returned an invalid successful version", invalidContender), errors.Join(causes...))
	}
	if winners > 1 {
		return compatibilityWriteResult{}, recorder.incompatible(id, fmt.Sprintf("concurrent operation had %d successful contenders; want exactly 1", winners), errors.Join(unexpectedErrors...))
	}
	if len(unexpectedErrors) > 0 {
		return compatibilityWriteResult{}, recorder.problem(
			id,
			compatibilityReconciliationFailureStatus(unexpectedErrors...),
			fmt.Sprintf("contenders %v returned neither success nor ErrPrecondition", unexpectedContenders),
			errors.Join(unexpectedErrors...),
		)
	}
	if winners != 1 {
		return compatibilityWriteResult{}, recorder.incompatible(id, fmt.Sprintf("concurrent operation had %d successful contenders; want exactly 1", winners), nil)
	}
	return winner, nil
}

func compatibilityContenderPayload(base []byte, contender int) []byte {
	data := make([]byte, len(base)+1)
	copy(data, base)
	data[len(base)] = byte(contender)
	return data
}

func compatibilityObjectMatchesWinner(object Object, base []byte, winner compatibilityWriteResult) bool {
	return bytes.Equal(object.Data, compatibilityContenderPayload(base, winner.contender)) &&
		object.Version.ETag == winner.version.ETag
}

// compatibilityProbeResult copies the report only after the recorder has
// appended its failure. This avoids depending on return-expression evaluation
// order when the recorder mutates the named report through a pointer.
func compatibilityProbeResult(report *StoreCompatibilityReport, probeErr error) (StoreCompatibilityReport, error) {
	return *report, probeErr
}

func cleanupCompatibilityProbe(report *StoreCompatibilityReport, store Store, deleter ObjectDeleter, keys []string) {
	cleanupCompatibilityProbeWithTimeout(report, store, deleter, keys, compatibilityCleanupTimeout)
}

func cleanupCompatibilityProbeWithTimeout(
	report *StoreCompatibilityReport,
	store Store,
	deleter ObjectDeleter,
	keys []string,
	timeout time.Duration,
) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var failures []error
	reasons := make(map[StoreCompatibilityCleanupReason]struct{})
	for _, key := range keys {
		report.Cleanup.Attempted++

		deleteErr := cleanupCtx.Err()
		if deleteErr == nil {
			deleteErr = deleter.Delete(cleanupCtx, key)
		}
		deleteAccepted := deleteErr == nil || compatibilityCleanupDefinitiveNotFound(deleteErr)
		if !deleteAccepted {
			report.Cleanup.DeleteFailures++
			failures = append(failures, deleteErr)
			compatibilityCleanupAddReason(reasons, deleteErr, StoreCompatibilityCleanupReasonDeleteFailed)
		}

		headErr := cleanupCtx.Err()
		if headErr == nil {
			_, headErr = store.Head(cleanupCtx, key)
		}
		verifiedAbsent := compatibilityCleanupDefinitiveNotFound(headErr)
		switch {
		case headErr == nil:
			report.Cleanup.CurrentObjectsStillVisible++
			failures = append(failures, errCompatibilityCleanupCurrentObjectStillVisible)
			reasons[StoreCompatibilityCleanupReasonCurrentObjectStillVisible] = struct{}{}
		case !verifiedAbsent:
			report.Cleanup.VerificationFailures++
			failures = append(failures, headErr)
			compatibilityCleanupAddReason(reasons, headErr, StoreCompatibilityCleanupReasonVerificationFailed)
		}

		if deleteAccepted && verifiedAbsent {
			report.Cleanup.Succeeded++
		} else {
			report.Cleanup.Failed++
		}
	}

	if report.Cleanup.Failed == 0 {
		report.Cleanup.Status = StoreCompatibilityCleanupSucceeded
		report.Cleanup.CurrentObjectsMayRemain = false
		if report.Cleanup.Attempted == 0 {
			report.Cleanup.Detail = "no probe objects required cleanup"
		} else {
			report.Cleanup.Detail = "HEAD verified every attempted current probe object absent; historical versions or delete markers may remain"
		}
		return
	}

	report.Cleanup.Status = StoreCompatibilityCleanupFailed
	report.Cleanup.Reason = compatibilityCleanupAggregateReason(reasons)
	report.Cleanup.Detail = fmt.Sprintf(
		"cleanup failed for %d of %d tracked objects (delete failures: %d, current objects still visible: %d, HEAD verification failures: %d); object keys and provider errors are omitted",
		report.Cleanup.Failed,
		report.Cleanup.Attempted,
		report.Cleanup.DeleteFailures,
		report.Cleanup.CurrentObjectsStillVisible,
		report.Cleanup.VerificationFailures,
	)
	report.Cleanup.CurrentObjectsMayRemain = report.Cleanup.CurrentObjectsStillVisible != 0 || report.Cleanup.VerificationFailures != 0
	report.Cleanup.Cause = errors.Join(failures...)
}

func compatibilityCleanupDefinitiveNotFound(cause error) bool {
	if cause == nil {
		return false
	}
	if cause == ErrObjectNotFound {
		return true
	}
	if _, classified := cause.(interface{ definitiveObjectNotFound() }); classified {
		return true
	}
	if joined, ok := cause.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !compatibilityCleanupDefinitiveNotFound(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := cause.(interface{ Unwrap() error }); ok {
		return compatibilityCleanupDefinitiveNotFound(wrapped.Unwrap())
	}
	return false
}

func compatibilityCleanupAddReason(
	reasons map[StoreCompatibilityCleanupReason]struct{},
	cause error,
	fallback StoreCompatibilityCleanupReason,
) {
	reason := fallback
	switch {
	case errors.Is(cause, ErrAccessDenied):
		reason = StoreCompatibilityCleanupReasonAccessDenied
	case errors.Is(cause, ErrBucketNotFound), errors.Is(cause, ErrStoreMisconfigured):
		reason = StoreCompatibilityCleanupReasonConfigurationError
	case errors.Is(cause, context.Canceled), errors.Is(cause, context.DeadlineExceeded):
		reason = StoreCompatibilityCleanupReasonDeadlineExceeded
	case errors.Is(cause, ErrRateLimited), errors.Is(cause, ErrStoreUnavailable):
		reason = StoreCompatibilityCleanupReasonStoreUnavailable
	default:
		var networkError net.Error
		if errors.As(cause, &networkError) {
			reason = StoreCompatibilityCleanupReasonNetworkError
		}
	}
	reasons[reason] = struct{}{}
}

func compatibilityCleanupAggregateReason(reasons map[StoreCompatibilityCleanupReason]struct{}) StoreCompatibilityCleanupReason {
	if len(reasons) != 1 {
		return StoreCompatibilityCleanupReasonMultipleFailures
	}
	for reason := range reasons {
		return reason
	}
	return StoreCompatibilityCleanupReasonMultipleFailures
}
