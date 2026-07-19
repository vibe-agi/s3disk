package s3disk

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	// StoreCompatibilityDefaultTimeout bounds the active probe when neither the
	// caller context nor StoreCompatibilityProbeOptions supplies a deadline.
	// Cleanup has its own additional, bounded timeout.
	StoreCompatibilityDefaultTimeout = 5 * time.Minute

	// StoreCompatibilityMaximumTimeout is the largest explicit probe timeout.
	// A caller context may still carry a later deadline; zero selects the caller
	// deadline or StoreCompatibilityDefaultTimeout when it has none.
	StoreCompatibilityMaximumTimeout = 30 * time.Minute

	// StoreCompatibilityEvidenceIDMaxBytes is the maximum encoded evidence ID.
	StoreCompatibilityEvidenceIDMaxBytes = 128

	// StoreCompatibilityImplementationVersionMaxBytes is the maximum encoded
	// caller-supplied implementation version.
	StoreCompatibilityImplementationVersionMaxBytes = 128

	compatibilityPrefixFingerprintDomain = "s3disk:store-compatibility:repository-prefix:v1\x00"
)

// StoreCompatibilityProbeOptions binds a commissioning result to identifiers
// supplied by the deployment controller. These values are copied into JSON;
// callers must never put credentials, tokens, endpoint secrets, or other
// confidential values in them.
//
// DeploymentFingerprint, when set, must be a canonical lowercase 64-character
// SHA-256 hex string computed by the caller over its non-secret deployment
// configuration. s3disk deliberately does not guess which endpoint, bucket,
// credential identity, proxy, encryption, or SDK settings define a deployment.
type StoreCompatibilityProbeOptions struct {
	// DeploymentFingerprint is an optional caller-computed SHA-256 digest of a
	// canonical, non-secret description of the exact commissioned deployment.
	DeploymentFingerprint string
	// EvidenceID is an optional run identifier. It must start with an ASCII
	// letter or digit and otherwise contain only letters, digits, '.', '_',
	// ':', or '-'.
	EvidenceID string
	// ImplementationVersion is an optional caller-controlled artifact or build
	// identifier. It uses the EvidenceID alphabet plus '+', but not ':'.
	ImplementationVersion string
	// TotalTimeout bounds active probe Store operations. Zero preserves an
	// existing caller deadline or selects StoreCompatibilityDefaultTimeout.
	// Independently bounded cleanup may add up to the cleanup timeout.
	TotalTimeout time.Duration
}

// StoreCompatibilityEvidence records when and for which repository namespace
// a finite probe ran. It is audit material, not an authenticated statement.
// RepositoryPrefixFingerprint is domain-separated and never contains the raw
// prefix, but predictable prefixes can still be vulnerable to dictionary
// guessing.
type StoreCompatibilityEvidence struct {
	// StartedAt is the probing process's UTC wall-clock time, not an attested
	// timestamp.
	StartedAt time.Time `json:"started_at"`
	// DurationNanoseconds includes option handling and independently bounded
	// cleanup.
	DurationNanoseconds int64 `json:"duration_nanoseconds"`
	// RepositoryPrefixFingerprint binds the normalized, unrecorded prefix using
	// the documented domain-separated construction.
	RepositoryPrefixFingerprint string `json:"repository_prefix_fingerprint,omitempty"`
	// DeploymentFingerprint, EvidenceID, and ImplementationVersion are the
	// validated but otherwise unverified caller declarations.
	DeploymentFingerprint string `json:"deployment_fingerprint,omitempty"`
	EvidenceID            string `json:"evidence_id,omitempty"`
	ImplementationVersion string `json:"implementation_version,omitempty"`
	// FullyBound reports syntactic completeness only. It is not authentication.
	FullyBound bool `json:"fully_bound"`
}

func newStoreCompatibilityEvidence(repository *Repository, options StoreCompatibilityProbeOptions, started time.Time) StoreCompatibilityEvidence {
	evidence := StoreCompatibilityEvidence{
		StartedAt:             started.UTC(),
		DeploymentFingerprint: options.DeploymentFingerprint,
		EvidenceID:            options.EvidenceID,
		ImplementationVersion: options.ImplementationVersion,
	}
	if repository != nil {
		evidence.RepositoryPrefixFingerprint = compatibilityRepositoryPrefixFingerprint(repository.prefix)
	}
	evidence.FullyBound = evidence.RepositoryPrefixFingerprint != "" &&
		evidence.DeploymentFingerprint != "" &&
		evidence.EvidenceID != "" &&
		evidence.ImplementationVersion != ""
	return evidence
}

func compatibilityRepositoryPrefixFingerprint(prefix string) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(compatibilityPrefixFingerprintDomain))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(prefix)))
	_, _ = hasher.Write(size[:])
	_, _ = hasher.Write([]byte(prefix))
	return hex.EncodeToString(hasher.Sum(nil))
}

func validateStoreCompatibilityProbeOptions(options StoreCompatibilityProbeOptions) error {
	if options.DeploymentFingerprint != "" && !isCanonicalSHA256(options.DeploymentFingerprint) {
		return fmt.Errorf("%w: compatibility deployment fingerprint must be 64 lowercase hexadecimal characters", ErrStoreMisconfigured)
	}
	if options.EvidenceID != "" && !isCompatibilityEvidenceID(options.EvidenceID) {
		return fmt.Errorf("%w: compatibility evidence ID has invalid syntax", ErrStoreMisconfigured)
	}
	if options.ImplementationVersion != "" && !isCompatibilityImplementationVersion(options.ImplementationVersion) {
		return fmt.Errorf("%w: compatibility implementation version has invalid syntax", ErrStoreMisconfigured)
	}
	if options.TotalTimeout < 0 || options.TotalTimeout > StoreCompatibilityMaximumTimeout {
		return fmt.Errorf("%w: compatibility total timeout must be between zero and %s", ErrStoreMisconfigured, StoreCompatibilityMaximumTimeout)
	}
	return nil
}

func isCanonicalSHA256(value string) bool {
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

func isCompatibilityEvidenceID(value string) bool {
	if len(value) == 0 || len(value) > StoreCompatibilityEvidenceIDMaxBytes || !isASCIILetterOrDigit(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !isASCIILetterOrDigit(character) && character != '.' && character != '_' && character != ':' && character != '-' {
			return false
		}
	}
	return true
}

func isCompatibilityImplementationVersion(value string) bool {
	if len(value) == 0 || len(value) > StoreCompatibilityImplementationVersionMaxBytes || !isASCIILetterOrDigit(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !isASCIILetterOrDigit(character) && character != '.' && character != '_' && character != '+' && character != '-' {
			return false
		}
	}
	return true
}

func isASCIILetterOrDigit(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9'
}

func compatibilityProbeContext(ctx context.Context, options StoreCompatibilityProbeOptions) (context.Context, context.CancelFunc) {
	if options.TotalTimeout > 0 {
		return context.WithTimeout(ctx, options.TotalTimeout)
	}
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, StoreCompatibilityDefaultTimeout)
}
