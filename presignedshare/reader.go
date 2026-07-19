package presignedshare

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vibe-agi/s3disk"
)

const (
	// DefaultOperationTimeout bounds one complete root or object GET, including
	// consuming and closing the response body.
	DefaultOperationTimeout = 2 * time.Minute
	// MaximumOperationTimeout prevents configuration from removing practical
	// liveness bounds. A caller's earlier context deadline always wins.
	MaximumOperationTimeout = 30 * time.Minute
	// MaximumObjectBytes is the finite fallback when GetOptions.MaxBytes is zero.
	MaximumObjectBytes int64 = 64 << 20
	// MaximumResponseHeaderBytes is enforced by the locked built-in transport
	// before allocation and checked again after every response.
	MaximumResponseHeaderBytes int64 = 64 << 10
	// MaximumTLSRootCAPEMBytes bounds caller-provisioned trust roots before
	// parsing and copying them into Reader-owned certificate objects.
	MaximumTLSRootCAPEMBytes = 4 << 20
	// MaximumTLSRootCertificates bounds certificate parsing work and the
	// Reader-owned trust pool. Producers should enforce the same limit before
	// distributing a handoff so an accepted share cannot fail only at mount.
	MaximumTLSRootCertificates = 1024
	// DefaultMaxConnectionsPerHost bounds direct Reader use even when callers
	// bypass Consumer's download semaphore.
	DefaultMaxConnectionsPerHost = 64

	DefaultMaxRetainedCapabilities    = 4 * MaximumBundleCapabilities
	MaximumRetainedCapabilities       = 4 * MaximumBundleCapabilities
	DefaultMaxRetainedCapabilityBytes = 128 << 20
	MaximumRetainedCapabilityBytes    = 512 << 20
)

var errRedirectForbidden = errors.New("presignedshare: redirect forbidden")

// ReaderConfig binds a Reader to one out-of-band root bearer capability and
// one signed share identity. HTTPS requires TLSRootCAPEM by default; Reader
// parses it into private, callback-free certificate objects.
// HTTPClient may supply TLS version bounds, finite timeouts, and connection-pool
// bounds through an otherwise unextended *http.Transport. Reader constructs its own direct transport and
// rejects proxies, custom dialers, alternate-protocol RoundTrippers, custom TLS
// callbacks, redirects, CookieJar injection, and disabled certificate
// verification. It never adds S3 credentials or an Authorization header.
type ReaderConfig struct {
	RootCapability   Capability
	RepositoryPrefix string
	ReferenceKey     string
	ShareID          ShareID
	Verifier         s3disk.ReferenceVerifier
	// ClientEncryption authenticates and decrypts the signed root bundle and
	// each immutable object only when its exact capability is read. Construct
	// the recipient repository with NewReadOnlyRepositoryWithOptions and this
	// same profile so it derives the matching opaque physical object keys; the
	// repository recognizes Reader's decryption boundary and does not re-open
	// the plaintext a second time.
	ClientEncryption *s3disk.ClientEncryptionProfile
	// DangerouslyAllowCustomReferenceVerifier permits a verifier that is not
	// the built-in offline Ed25519 verifier. A custom implementation can perform
	// arbitrary network I/O and therefore breaks Reader's S3-only guarantee.
	DangerouslyAllowCustomReferenceVerifier bool
	// TLSRootCAPEM replaces the host system trust roots when non-empty. Passing
	// a caller-created *x509.CertPool through HTTPClient is forbidden because a
	// CertPool can contain executable verification constraints and mutable
	// certificate pointers. HTTPS requires a non-empty TLSRootCAPEM unless
	// DangerouslyAllowSystemTrustStore is set.
	TLSRootCAPEM []byte
	// DangerouslyAllowSystemTrustStore permits HTTPS to use the host system
	// trust verifier. Some platforms can perform auxiliary AIA or revocation
	// network requests outside Reader's locked dialer, so this opt-out breaks
	// the strict S3-only guarantee.
	DangerouslyAllowSystemTrustStore bool
	HTTPClient                       *http.Client
	OperationTimeout                 time.Duration
	AllowInsecureLoopback            bool

	MaxRetainedCapabilities    int
	MaxRetainedCapabilityBytes int64
}

// Reader implements s3disk.ObjectReader using only a fixed root bundle URL and
// exact-key capabilities authenticated by that bundle. It never contacts the
// publisher and never performs LIST, HEAD, or write operations.
type Reader struct {
	rootCapability                          Capability
	repositoryPrefix                        string
	referenceKey                            string
	shareID                                 ShareID
	verifier                                s3disk.ReferenceVerifier
	clientEncryption                        *s3disk.ClientEncryptionProfile
	client                                  *http.Client
	operationTimeout                        time.Duration
	allowInsecureLoopback                   bool
	dangerouslyAllowCustomReferenceVerifier bool

	maxRetainedCapabilities    int
	maxRetainedCapabilityBytes int64

	refreshGate chan struct{}
	state       *readerState
}

type readerState struct {
	mu                      sync.RWMutex
	current                 *readerRevision
	retainedCapabilities    map[string]Capability
	retainedCapabilityBytes int64
}

type readerRevision struct {
	revision        uint64
	generation      uint64
	commit          s3disk.Digest
	bundleDigest    [sha256.Size]byte
	bundleETag      string
	bundleVersionID string
	referenceData   []byte
	capabilities    map[string]Capability
	capabilityBytes int64
}

// NewReader constructs a fail-closed reader without performing network I/O.
func NewReader(config ReaderConfig) (*Reader, error) {
	if !config.RootCapability.Configured() {
		return nil, fmt.Errorf("presignedshare: root capability is required")
	}
	rootURL, rootOrigin, err := validateCapabilityURL(config.RootCapability.rawURL, config.AllowInsecureLoopback)
	if err != nil || rootOrigin != config.RootCapability.origin {
		return nil, fmt.Errorf("presignedshare: root capability transport is not permitted")
	}
	if rootURL.Scheme == "https" && len(config.TLSRootCAPEM) == 0 && !config.DangerouslyAllowSystemTrustStore {
		return nil, fmt.Errorf("presignedshare: TLSRootCAPEM is required for HTTPS unless DangerouslyAllowSystemTrustStore is set")
	}
	if !configuredInterface(config.Verifier) {
		return nil, fmt.Errorf("presignedshare: verifier is required")
	}
	if !s3disk.IsOfflineReferenceVerifier(config.Verifier) && !config.DangerouslyAllowCustomReferenceVerifier {
		return nil, fmt.Errorf("presignedshare: custom verifier requires DangerouslyAllowCustomReferenceVerifier and breaks the S3-only boundary")
	}
	if config.Verifier.RepositoryID().IsZero() {
		return nil, fmt.Errorf("presignedshare: verifier is required")
	}
	if config.ClientEncryption != nil && config.ClientEncryption.RepositoryID() != config.Verifier.RepositoryID() {
		return nil, fmt.Errorf("presignedshare: client encryption and verifier repository identities do not match")
	}
	if config.ShareID.IsZero() {
		return nil, fmt.Errorf("presignedshare: share ID is required")
	}
	prefix, err := validateBundleBindings(config.RepositoryPrefix, config.ReferenceKey, config.ShareID, 1, 1)
	if err != nil {
		return nil, err
	}
	if hasHeader(config.RootCapability.headers, "If-None-Match") ||
		hasHeader(config.RootCapability.headers, "Cache-Control") || hasHeader(config.RootCapability.headers, "Pragma") {
		return nil, fmt.Errorf("presignedshare: root capability must not fix runtime polling headers")
	}
	if config.RootCapability.expiresAt.IsZero() || !config.RootCapability.expiresAt.After(time.Now()) {
		return nil, fmt.Errorf("presignedshare: root capability is expired")
	}
	if config.OperationTimeout == 0 {
		config.OperationTimeout = DefaultOperationTimeout
	}
	if config.OperationTimeout < 0 || config.OperationTimeout > MaximumOperationTimeout {
		return nil, fmt.Errorf("presignedshare: operation timeout must be positive and at most %s", MaximumOperationTimeout)
	}
	if config.MaxRetainedCapabilities == 0 {
		config.MaxRetainedCapabilities = DefaultMaxRetainedCapabilities
	}
	if config.MaxRetainedCapabilities < 1 || config.MaxRetainedCapabilities > MaximumRetainedCapabilities {
		return nil, fmt.Errorf("presignedshare: retained capabilities must be between 1 and %d", MaximumRetainedCapabilities)
	}
	if config.MaxRetainedCapabilityBytes == 0 {
		config.MaxRetainedCapabilityBytes = DefaultMaxRetainedCapabilityBytes
	}
	if config.MaxRetainedCapabilityBytes < 1 || config.MaxRetainedCapabilityBytes > MaximumRetainedCapabilityBytes {
		return nil, fmt.Errorf("presignedshare: retained capability bytes must be between 1 and %d", MaximumRetainedCapabilityBytes)
	}

	client, err := lockedHTTPClient(config.HTTPClient, config.TLSRootCAPEM)
	if err != nil {
		return nil, err
	}
	return &Reader{
		rootCapability: config.RootCapability, repositoryPrefix: prefix,
		referenceKey: config.ReferenceKey, shareID: config.ShareID, verifier: config.Verifier,
		clientEncryption: config.ClientEncryption,
		client:           client, operationTimeout: config.OperationTimeout,
		allowInsecureLoopback:                   config.AllowInsecureLoopback,
		dangerouslyAllowCustomReferenceVerifier: config.DangerouslyAllowCustomReferenceVerifier,
		maxRetainedCapabilities:                 config.MaxRetainedCapabilities,
		maxRetainedCapabilityBytes:              config.MaxRetainedCapabilityBytes,
		refreshGate:                             make(chan struct{}, 1),
		state: &readerState{
			retainedCapabilities: make(map[string]Capability),
		},
	}, nil
}

// AuthorizationExpiry implements s3disk.AuthorizationExpirySource. The root
// bearer and every accepted bundle are required to use this same fixed expiry.
func (reader *Reader) AuthorizationExpiry() (time.Time, bool) {
	if reader == nil || reader.rootCapability.expiresAt.IsZero() {
		return time.Time{}, false
	}
	return reader.rootCapability.expiresAt, true
}

func (reader Reader) String() string {
	return fmt.Sprintf(
		"presignedshare.Reader{configured:%t,authorization_expires_at:%s,secrets:redacted}",
		reader.rootCapability.Configured() && reader.client != nil && reader.refreshGate != nil && reader.state != nil,
		reader.rootCapability.expiresAt.Format(time.RFC3339Nano),
	)
}

func (reader Reader) GoString() string { return reader.String() }

func (reader Reader) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Configured             bool      `json:"configured"`
		AuthorizationExpiresAt time.Time `json:"authorization_expires_at,omitempty"`
		Secrets                string    `json:"secrets"`
	}{
		Configured:             reader.rootCapability.Configured() && reader.client != nil && reader.refreshGate != nil && reader.state != nil,
		AuthorizationExpiresAt: reader.rootCapability.expiresAt,
		Secrets:                "redacted",
	})
}

// Get implements s3disk.ObjectReader. Reading the exact reference key polls the
// fixed root bundle; immutable keys are fetched lazily only through a verified
// exact-key capability retained from an accepted revision. With client
// encryption configured, both root and immutable responses are authenticated
// and opened before they cross the ObjectReader boundary.
func (reader *Reader) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	if reader == nil {
		return s3disk.Object{}, fmt.Errorf("presignedshare: nil reader")
	}
	if ctx == nil {
		return s3disk.Object{}, fmt.Errorf("presignedshare: context is required")
	}
	if !reader.rootCapability.expiresAt.After(time.Now()) {
		return s3disk.Object{}, fmt.Errorf("presignedshare: share authorization expired: %w", s3disk.ErrAccessDenied)
	}
	if err := validateGetOptions(options); err != nil {
		return s3disk.Object{}, err
	}
	if key == reader.referenceKey {
		return reader.getReference(ctx, options)
	}
	if err := validateImmutableKey(reader.repositoryPrefix, key); err != nil {
		return s3disk.Object{}, fmt.Errorf("presignedshare: %w", s3disk.ErrAccessDenied)
	}
	return reader.getImmutable(ctx, key, options)
}

// ClientEncryptionApplied allows s3disk.NewReadOnlyRepositoryWithOptions to
// recognize that this Reader already opens immutable ciphertext and avoid a
// second decryption layer. It does not expose key material.
func (reader *Reader) ClientEncryptionApplied(profile *s3disk.ClientEncryptionProfile) bool {
	return reader != nil && reader.clientEncryption.Equivalent(profile)
}

func (reader *Reader) getReference(ctx context.Context, options s3disk.GetOptions) (s3disk.Object, error) {
	operationCtx, cancel := reader.operationContext(ctx)
	defer cancel()
	if err := reader.acquireRefresh(operationCtx); err != nil {
		return s3disk.Object{}, err
	}
	defer reader.releaseRefresh()
	return reader.getReferenceLocked(operationCtx, options)
}

// getReferenceLocked polls and installs the root while refreshGate is held.
func (reader *Reader) getReferenceLocked(operationCtx context.Context, options s3disk.GetOptions) (s3disk.Object, error) {
	reader.state.mu.RLock()
	ifNoneMatch := ""
	if reader.state.current != nil {
		ifNoneMatch = reader.state.current.bundleETag
	}
	reader.state.mu.RUnlock()

	headers := reader.rootCapability.headers.Clone()
	headers.Set("Cache-Control", "no-cache")
	headers.Set("Pragma", "no-cache")
	if ifNoneMatch != "" {
		headers.Set("If-None-Match", ifNoneMatch)
	}
	response, err := reader.doGET(operationCtx, reader.rootCapability.rawURL, headers)
	if err != nil {
		return s3disk.Object{}, err
	}
	defer response.Body.Close()
	if err := validateResponseHeaders(response.Header); err != nil {
		return s3disk.Object{}, err
	}
	if response.StatusCode == http.StatusNotModified {
		return reader.referenceFromCurrent(options)
	}
	if response.StatusCode != http.StatusOK {
		return s3disk.Object{}, classifyHTTPStatus(response.StatusCode)
	}
	version, err := responseVersion(response.Header)
	if err != nil {
		return s3disk.Object{}, err
	}
	rootLimit := int64(MaximumBundleBytes)
	if reader.clientEncryption != nil {
		rootLimit += s3disk.ClientEncryptionCiphertextOverhead
	}
	data, err := readBoundedBody(operationCtx, response, rootLimit)
	if err != nil {
		return s3disk.Object{}, err
	}
	if reader.clientEncryption != nil {
		data, err = reader.clientEncryption.OpenObject(reader.rootCapability.exactKey, data)
		if err != nil {
			return s3disk.Object{}, fmt.Errorf("presignedshare: open encrypted root: %w", err)
		}
	}
	bundle, err := Decode(operationCtx, data, reader.verifier, DecodeOptions{
		RootCapability: reader.rootCapability, RepositoryPrefix: reader.repositoryPrefix,
		ReferenceKey: reader.referenceKey, ShareID: reader.shareID,
		AllowInsecureLoopback:                   reader.allowInsecureLoopback,
		DangerouslyAllowCustomReferenceVerifier: reader.dangerouslyAllowCustomReferenceVerifier,
	})
	if err != nil {
		if errors.Is(err, ErrUntrustedBundle) {
			return s3disk.Object{}, fmt.Errorf("presignedshare: %w: %w", s3disk.ErrUntrustedReference, err)
		}
		return s3disk.Object{}, fmt.Errorf("presignedshare: %w: %w", s3disk.ErrCorruptObject, err)
	}
	if err := reader.installBundle(operationCtx, bundle, sha256.Sum256(data), version); err != nil {
		return s3disk.Object{}, err
	}
	return reader.referenceFromCurrent(options)
}

func (reader *Reader) referenceFromCurrent(options s3disk.GetOptions) (s3disk.Object, error) {
	reader.state.mu.RLock()
	defer reader.state.mu.RUnlock()
	if reader.state.current == nil {
		return s3disk.Object{}, fmt.Errorf("presignedshare: 304 without an installed bundle: %w", s3disk.ErrStoreIncompatible)
	}
	if options.IfNoneMatch != "" && options.IfNoneMatch == reader.state.current.bundleETag {
		return s3disk.Object{}, s3disk.ErrNotModified
	}
	if options.MaxBytes > 0 && int64(len(reader.state.current.referenceData)) > options.MaxBytes {
		return s3disk.Object{}, fmt.Errorf("presignedshare: reference exceeds read limit: %w", s3disk.ErrResourceLimit)
	}
	return s3disk.Object{
		Data:    append([]byte(nil), reader.state.current.referenceData...),
		Version: s3disk.Version{ETag: reader.state.current.bundleETag, VersionID: reader.state.current.bundleVersionID},
	}, nil
}

func (reader *Reader) getImmutable(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	operationCtx, cancel := reader.operationContext(ctx)
	defer cancel()
	capability, ok := reader.findCapability(key)
	if !ok && !reader.hasCurrentBundle() {
		// Consumer restart recovery validates the durable watermark's commit
		// ancestry before it asks ObjectReader for the mutable reference. A fresh
		// Reader therefore has to install its fixed S3 root bundle before it can
		// authorize that first immutable commit GET. This bootstrap performs only
		// the same root GET used by ordinary polling; it never contacts A, lists a
		// prefix, derives a URL, or broadens the authenticated exact-key set.
		if err := reader.ensureInitialBundle(operationCtx); err != nil {
			return s3disk.Object{}, err
		}
		capability, ok = reader.findCapability(key)
	}
	if !ok {
		// A concurrent refresh may have installed the exact capability after the
		// initial lookup. Synchronize with the refresh gate and recheck before
		// returning a false denial; this does not poll S3 when a bundle is already
		// installed.
		if err := reader.acquireRefresh(operationCtx); err != nil {
			return s3disk.Object{}, err
		}
		capability, ok = reader.findCapability(key)
		reader.releaseRefresh()
	}
	if !ok {
		return s3disk.Object{}, fmt.Errorf("presignedshare: exact object capability unavailable: %w", s3disk.ErrAccessDenied)
	}
	if !capability.expiresAt.After(time.Now()) {
		return s3disk.Object{}, fmt.Errorf("presignedshare: capability expired: %w", s3disk.ErrAccessDenied)
	}
	headers := capability.headers.Clone()
	if options.IfNoneMatch != "" {
		headers.Set("If-None-Match", options.IfNoneMatch)
	}
	response, err := reader.doGET(operationCtx, capability.rawURL, headers)
	if err != nil {
		return s3disk.Object{}, err
	}
	defer response.Body.Close()
	if err := validateResponseHeaders(response.Header); err != nil {
		return s3disk.Object{}, err
	}
	if response.StatusCode == http.StatusNotModified {
		return s3disk.Object{}, s3disk.ErrNotModified
	}
	if response.StatusCode != http.StatusOK {
		return s3disk.Object{}, classifyHTTPStatus(response.StatusCode)
	}
	version, err := responseVersion(response.Header)
	if err != nil {
		return s3disk.Object{}, err
	}
	if options.IfNoneMatch != "" && options.IfNoneMatch == version.ETag {
		return s3disk.Object{}, s3disk.ErrNotModified
	}
	limit := MaximumObjectBytes
	if reader.clientEncryption != nil {
		limit += s3disk.ClientEncryptionCiphertextOverhead
	}
	if options.MaxBytes > 0 {
		requestedLimit := options.MaxBytes
		if reader.clientEncryption != nil {
			if requestedLimit > s3disk.ClientEncryptionMaxPlaintextBytes {
				requestedLimit = s3disk.ClientEncryptionMaxPlaintextBytes
			}
			requestedLimit += s3disk.ClientEncryptionCiphertextOverhead
		}
		if requestedLimit < limit {
			limit = requestedLimit
		}
	}
	data, err := readBoundedBody(operationCtx, response, limit)
	if err != nil {
		return s3disk.Object{}, err
	}
	if reader.clientEncryption != nil {
		data, err = reader.clientEncryption.OpenObject(key, data)
		if err != nil {
			return s3disk.Object{}, fmt.Errorf("presignedshare: open encrypted immutable object: %w", err)
		}
		if options.MaxBytes > 0 && int64(len(data)) > options.MaxBytes {
			return s3disk.Object{}, fmt.Errorf("presignedshare: decrypted object exceeds read limit: %w", s3disk.ErrResourceLimit)
		}
	}
	return s3disk.Object{Data: data, Version: version}, nil
}

func (reader *Reader) hasCurrentBundle() bool {
	reader.state.mu.RLock()
	defer reader.state.mu.RUnlock()
	return reader.state.current != nil
}

func (reader *Reader) ensureInitialBundle(ctx context.Context) error {
	if reader.hasCurrentBundle() {
		return nil
	}
	if err := reader.acquireRefresh(ctx); err != nil {
		return err
	}
	defer reader.releaseRefresh()
	// Collapse a restart stampede: a waiter which observed nil before another
	// goroutine installed the bundle must not issue a redundant root GET.
	if reader.hasCurrentBundle() {
		return nil
	}
	_, err := reader.getReferenceLocked(ctx, s3disk.GetOptions{MaxBytes: maximumReferenceBytes})
	return err
}

func (reader *Reader) installBundle(ctx context.Context, bundle *Bundle, digest [sha256.Size]byte, rootVersion s3disk.Version) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if bundle == nil {
		return fmt.Errorf("presignedshare: nil decoded bundle: %w", s3disk.ErrCorruptObject)
	}
	capabilityBytes, err := validateReaderCapabilities(ctx, bundle.capabilities)
	if err != nil {
		return err
	}
	if len(bundle.capabilities) > reader.maxRetainedCapabilities || capabilityBytes > reader.maxRetainedCapabilityBytes {
		return fmt.Errorf("presignedshare: current revision exceeds retention budget: %w", s3disk.ErrResourceLimit)
	}
	next := &readerRevision{
		revision: bundle.revision, generation: bundle.referenceGeneration, commit: bundle.referenceCommit, bundleDigest: digest,
		bundleETag: rootVersion.ETag, bundleVersionID: rootVersion.VersionID,
		referenceData: append([]byte(nil), bundle.reference.Data...), capabilities: bundle.capabilities,
		capabilityBytes: capabilityBytes,
	}

	reader.state.mu.Lock()
	defer reader.state.mu.Unlock()
	if reader.state.current == nil {
		reader.state.current = next
		return nil
	}
	current := reader.state.current
	if next.revision < current.revision {
		return fmt.Errorf("presignedshare: bundle revision regressed: %w", s3disk.ErrRollbackDetected)
	}
	if next.revision == current.revision {
		if next.bundleDigest != current.bundleDigest {
			return fmt.Errorf("presignedshare: one revision has different signed bytes: %w", s3disk.ErrSplitBrain)
		}
		// An identical signed revision may be rewritten at the bundle key. Use
		// the latest observed root ETag while retaining the identical contents.
		reader.state.current = next
		return nil
	}
	if next.generation < current.generation {
		return fmt.Errorf("presignedshare: snapshot generation regressed: %w", s3disk.ErrRollbackDetected)
	}
	if next.generation == current.generation && next.commit != current.commit {
		return fmt.Errorf("presignedshare: one generation names different commits: %w", s3disk.ErrSplitBrain)
	}
	if next.bundleETag == current.bundleETag && next.bundleDigest != current.bundleDigest {
		return fmt.Errorf("presignedshare: bundle bytes changed without an ETag change: %w", s3disk.ErrStoreIncompatible)
	}

	// There is no open-handle lease callback from Consumer to ObjectReader. To
	// preserve snapshot-pinned reads, every exact key from every revision this
	// Reader has accepted must therefore remain usable until the Reader is
	// discarded or its fixed authorization expires. Deduplicate immutable keys
	// across revisions. If the finite union budget is exhausted, reject the new
	// revision atomically and keep the current view and all older handles
	// readable; silently evicting an older capability would violate that
	// contract under an otherwise healthy network and store.
	retained := make(map[string]Capability, len(reader.state.retainedCapabilities)+len(current.capabilities))
	retainedBytes := reader.state.retainedCapabilityBytes
	index := 0
	for key, capability := range reader.state.retainedCapabilities {
		if index&255 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		index++
		retained[key] = capability
	}
	for key, capability := range current.capabilities {
		if index&255 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		index++
		if _, exists := retained[key]; exists {
			continue
		}
		charge, err := readerCapabilityCharge(key, capability)
		if err != nil || retainedBytes > math.MaxInt64-charge {
			return fmt.Errorf("presignedshare: retained capability accounting overflow: %w", s3disk.ErrResourceLimit)
		}
		retained[key] = capability
		retainedBytes += charge
	}
	for key := range next.capabilities {
		if index&255 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		index++
		if capability, exists := retained[key]; exists {
			charge, err := readerCapabilityCharge(key, capability)
			if err != nil || charge > retainedBytes {
				return fmt.Errorf("presignedshare: retained capability accounting underflow: %w", s3disk.ErrResourceLimit)
			}
			delete(retained, key)
			retainedBytes -= charge
		}
	}
	if len(retained) > reader.maxRetainedCapabilities ||
		retainedBytes > reader.maxRetainedCapabilityBytes ||
		len(next.capabilities) > reader.maxRetainedCapabilities-len(retained) ||
		next.capabilityBytes > reader.maxRetainedCapabilityBytes-retainedBytes {
		return fmt.Errorf("presignedshare: accepting the new revision would evict an older exact capability: %w", s3disk.ErrResourceLimit)
	}
	reader.state.current = next
	reader.state.retainedCapabilities = retained
	reader.state.retainedCapabilityBytes = retainedBytes
	return nil
}

func validateReaderCapabilities(ctx context.Context, capabilities map[string]Capability) (int64, error) {
	total := int64(0)
	index := 0
	for key, capability := range capabilities {
		if index&255 == 0 {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
		}
		index++
		if hasHeader(capability.headers, "If-None-Match") {
			return 0, fmt.Errorf("presignedshare: object capability must not fix If-None-Match: %w", s3disk.ErrStoreMisconfigured)
		}
		charge, err := readerCapabilityCharge(key, capability)
		if err != nil || total > math.MaxInt64-charge {
			return 0, fmt.Errorf("presignedshare: capability accounting overflow: %w", s3disk.ErrResourceLimit)
		}
		total += charge
	}
	return total, nil
}

func readerCapabilityCharge(key string, capability Capability) (int64, error) {
	charge := int64(256 + len(key) + len(capability.rawURL))
	for name, values := range capability.headers {
		if charge > math.MaxInt64-int64(len(name)+32) {
			return 0, s3disk.ErrResourceLimit
		}
		charge += int64(len(name) + 32)
		for _, value := range values {
			if charge > math.MaxInt64-int64(len(value)+16) {
				return 0, s3disk.ErrResourceLimit
			}
			charge += int64(len(value) + 16)
		}
	}
	if charge < 0 {
		return 0, s3disk.ErrResourceLimit
	}
	return charge, nil
}

func (reader *Reader) findCapability(key string) (Capability, bool) {
	reader.state.mu.RLock()
	defer reader.state.mu.RUnlock()
	if reader.state.current != nil {
		if capability, ok := reader.state.current.capabilities[key]; ok {
			return capability, true
		}
	}
	if capability, ok := reader.state.retainedCapabilities[key]; ok {
		return capability, true
	}
	return Capability{}, false
}

func (reader *Reader) acquireRefresh(ctx context.Context) error {
	select {
	case reader.refreshGate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (reader *Reader) releaseRefresh() { <-reader.refreshGate }

func (reader *Reader) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	operationCtx, cancelOperation := context.WithTimeout(ctx, reader.operationTimeout)
	if !reader.rootCapability.expiresAt.Before(time.Now().Add(reader.operationTimeout)) {
		return operationCtx, cancelOperation
	}
	expiryCtx, cancelExpiry := context.WithDeadline(operationCtx, reader.rootCapability.expiresAt)
	return expiryCtx, func() {
		cancelExpiry()
		cancelOperation()
	}
}

func (reader *Reader) doGET(ctx context.Context, rawURL string, headers http.Header) (*http.Response, error) {
	if !reader.rootCapability.expiresAt.After(time.Now()) {
		return nil, fmt.Errorf("presignedshare: share authorization expired: %w", s3disk.ErrAccessDenied)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// net/http interprets context values such as httptrace.ClientTrace as
	// executable callbacks. Capability requests must not invoke arbitrary
	// caller callbacks (which could contact a non-S3 control plane or observe
	// signed headers), so expose only cancellation and deadline semantics to the
	// transport.
	request, err := http.NewRequestWithContext(contextWithoutValues{Context: ctx}, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("presignedshare: construct GET: %w", s3disk.ErrStoreMisconfigured)
	}
	request.Header = headers.Clone()
	if !hasHeader(request.Header, "Accept-Encoding") {
		request.Header.Set("Accept-Encoding", "identity")
	}
	response, err := reader.client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if errors.Is(err, errRedirectForbidden) {
			return nil, fmt.Errorf("presignedshare: redirect rejected: %w", s3disk.ErrStoreMisconfigured)
		}
		return nil, fmt.Errorf("presignedshare: transport failed: %w", s3disk.ErrStoreUnavailable)
	}
	return response, nil
}

type contextWithoutValues struct{ context.Context }

func (contextWithoutValues) Value(any) any { return nil }

func lockedHTTPClient(configured *http.Client, tlsRootCAPEM []byte) (*http.Client, error) {
	client := &http.Client{}
	var source *http.Transport
	if configured != nil {
		if configured.Timeout < 0 || configured.Timeout > MaximumOperationTimeout {
			return nil, fmt.Errorf("presignedshare: HTTP client timeout is outside the permitted bound")
		}
		client.Timeout = configured.Timeout
		if configured.Transport != nil {
			var ok bool
			source, ok = configured.Transport.(*http.Transport)
			if !ok || source == nil {
				return nil, fmt.Errorf("presignedshare: HTTP client transport must be *http.Transport")
			}
			// Clone before inspecting exported fields. Transport.Clone coordinates
			// the standard library's lazy protocol initialization and prevents later
			// caller mutation from changing the Reader-owned transport.
			source = source.Clone()
		}
	}
	// Authentication is carried only by the explicitly validated capability.
	// A caller's CookieJar would otherwise inject unreviewed credentials after
	// header validation based solely on the capability URL's origin.
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errRedirectForbidden }
	direct, err := lockedDirectTransport(source, tlsRootCAPEM)
	if err != nil {
		return nil, err
	}
	client.Transport = direct
	return client, nil
}

func lockedDirectTransport(source *http.Transport, tlsRootCAPEM []byte) (*http.Transport, error) {
	dialer := newLockedNetworkDialer()
	transport := &http.Transport{
		// Proxy must remain nil. In particular, do not inherit
		// http.ProxyFromEnvironment from http.DefaultTransport: a bearer request
		// must go directly to the authenticated S3 origin.
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		Dial:                   nil,
		DialTLSContext:         nil,
		DialTLS:                nil,
		TLSHandshakeTimeout:    10 * time.Second,
		DisableCompression:     true,
		MaxIdleConns:           100,
		MaxIdleConnsPerHost:    2,
		MaxConnsPerHost:        DefaultMaxConnectionsPerHost,
		IdleConnTimeout:        90 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: MaximumResponseHeaderBytes,
		ForceAttemptHTTP2:      true,
	}
	var configuredTLS *tls.Config
	if source != nil {
		if source.Proxy != nil || source.OnProxyConnectResponse != nil ||
			source.DialContext != nil || source.Dial != nil ||
			source.DialTLSContext != nil || source.DialTLS != nil ||
			source.TLSNextProto != nil || source.ProxyConnectHeader != nil ||
			source.GetProxyConnectHeader != nil || source.Protocols != nil {
			return nil, fmt.Errorf("presignedshare: HTTP transport routing and protocol extensions are forbidden")
		}
		for _, duration := range []time.Duration{
			source.TLSHandshakeTimeout,
			source.IdleConnTimeout,
			source.ResponseHeaderTimeout,
			source.ExpectContinueTimeout,
		} {
			if duration < 0 || duration > MaximumOperationTimeout {
				return nil, fmt.Errorf("presignedshare: HTTP transport timeout is outside the permitted bound")
			}
		}
		for _, count := range []int{source.MaxIdleConns, source.MaxIdleConnsPerHost, source.MaxConnsPerHost} {
			if count < 0 || count > 1024 {
				return nil, fmt.Errorf("presignedshare: HTTP transport connection bound is outside the permitted range")
			}
		}
		if source.MaxResponseHeaderBytes < 0 {
			return nil, fmt.Errorf("presignedshare: HTTP response-header bound must not be negative")
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
		if source.MaxResponseHeaderBytes > 0 && source.MaxResponseHeaderBytes < MaximumResponseHeaderBytes {
			transport.MaxResponseHeaderBytes = source.MaxResponseHeaderBytes
		}
		configuredTLS = source.TLSClientConfig
	}
	tlsConfig, err := lockedTLSClientConfig(configuredTLS, tlsRootCAPEM)
	if err != nil {
		return nil, err
	}
	transport.TLSClientConfig = tlsConfig
	return transport, nil
}

func lockedTLSClientConfig(source *tls.Config, tlsRootCAPEM []byte) (*tls.Config, error) {
	result := &tls.Config{MinVersion: tls.VersionTLS12}
	if source != nil && (source.InsecureSkipVerify || source.ServerName != "" ||
		source.Rand != nil || source.Time != nil ||
		len(source.Certificates) != 0 || source.NameToCertificate != nil ||
		source.GetCertificate != nil || source.GetClientCertificate != nil || source.GetConfigForClient != nil ||
		source.VerifyPeerCertificate != nil || source.VerifyConnection != nil ||
		!standardLibraryALPN(source.NextProtos) || source.ClientAuth != tls.NoClientCert || source.ClientCAs != nil || source.RootCAs != nil ||
		source.ClientSessionCache != nil || source.UnwrapSession != nil || source.WrapSession != nil ||
		source.Renegotiation != tls.RenegotiateNever || source.KeyLogWriter != nil ||
		len(source.CipherSuites) != 0 || source.PreferServerCipherSuites || len(source.CurvePreferences) != 0 ||
		len(source.EncryptedClientHelloConfigList) != 0 || source.EncryptedClientHelloRejectionVerify != nil ||
		source.GetEncryptedClientHelloKeys != nil || len(source.EncryptedClientHelloKeys) != 0 ||
		source.SessionTicketKey != [32]byte{}) {
		return nil, fmt.Errorf("presignedshare: custom TLS identity, algorithms, callbacks, or secret logging are forbidden")
	}
	if source != nil && source.MinVersion != 0 {
		if source.MinVersion < tls.VersionTLS12 || source.MinVersion > tls.VersionTLS13 {
			return nil, fmt.Errorf("presignedshare: TLS minimum version must be 1.2 or 1.3")
		}
		result.MinVersion = source.MinVersion
	}
	if source != nil && source.MaxVersion != 0 {
		if source.MaxVersion < result.MinVersion || source.MaxVersion > tls.VersionTLS13 {
			return nil, fmt.Errorf("presignedshare: TLS version range is invalid")
		}
		result.MaxVersion = source.MaxVersion
	}
	rootCAs, err := parseLockedTLSRootCAPEM(tlsRootCAPEM)
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

func standardLibraryALPN(nextProtos []string) bool {
	// Transport.Clone may initialize the standard HTTP/2 ALPN pair before we
	// inspect its TLS config. Accept that one exact standard-library value, but
	// do not copy it into the Reader-owned config. ForceAttemptHTTP2 on the new
	// transport will negotiate its own protocol set.
	return len(nextProtos) == 0 ||
		(len(nextProtos) == 2 && nextProtos[0] == "h2" && nextProtos[1] == "http/1.1")
}

func newLockedNetworkDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  &net.Resolver{PreferGo: true},
	}
}

func parseLockedTLSRootCAPEM(encoded []byte) (*x509.CertPool, error) {
	if len(encoded) == 0 {
		return nil, nil
	}
	if len(encoded) > MaximumTLSRootCAPEMBytes {
		return nil, fmt.Errorf("presignedshare: TLS root CA PEM exceeds the byte limit")
	}
	remaining := append([]byte(nil), encoded...)
	pool := x509.NewCertPool()
	count := 0
	for {
		remaining = bytes.TrimLeft(remaining, " \t\r\n")
		if len(remaining) == 0 {
			break
		}
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, fmt.Errorf("presignedshare: TLS root CA PEM is malformed")
		}
		const endMarker = "-----END CERTIFICATE-----"
		endOffset := bytes.Index(remaining, []byte(endMarker))
		if endOffset < 0 || bytes.Contains(
			remaining[len("-----BEGIN CERTIFICATE-----"):endOffset],
			[]byte("-----BEGIN "),
		) {
			return nil, fmt.Errorf("presignedshare: TLS root CA PEM is malformed")
		}
		candidateEnd := endOffset + len(endMarker)
		if candidateEnd < len(remaining) && remaining[candidateEnd] == '\r' {
			candidateEnd++
		}
		if candidateEnd < len(remaining) && remaining[candidateEnd] == '\n' {
			candidateEnd++
		}
		block, rest := pem.Decode(remaining[:candidateEnd])
		if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("presignedshare: TLS root CA PEM is malformed")
		}
		count++
		if count > MaximumTLSRootCertificates {
			return nil, fmt.Errorf("presignedshare: TLS root CA PEM contains too many certificates")
		}
		certificate, err := x509.ParseCertificate(append([]byte(nil), block.Bytes...))
		if err != nil {
			return nil, fmt.Errorf("presignedshare: TLS root CA PEM contains an invalid certificate")
		}
		pool.AddCert(certificate)
		remaining = remaining[candidateEnd:]
	}
	if count == 0 {
		return nil, fmt.Errorf("presignedshare: TLS root CA PEM contains no certificates")
	}
	return pool, nil
}

func validateGetOptions(options s3disk.GetOptions) error {
	if options.MaxBytes < 0 {
		return fmt.Errorf("presignedshare: max bytes must not be negative: %w", s3disk.ErrResourceLimit)
	}
	if len(options.IfNoneMatch) > s3disk.MaxStoreVersionTokenBytes {
		return fmt.Errorf("presignedshare: If-None-Match exceeds the token bound: %w", s3disk.ErrResourceLimit)
	}
	if strings.ContainsAny(options.IfNoneMatch, "\x00\r\n") {
		return fmt.Errorf("presignedshare: If-None-Match is invalid: %w", s3disk.ErrStoreMisconfigured)
	}
	return nil
}

func validateResponseHeaders(headers http.Header) error {
	if len(headers) > 256 {
		return fmt.Errorf("presignedshare: response has too many headers: %w", s3disk.ErrResourceLimit)
	}
	total := int64(0)
	for name, values := range headers {
		total += int64(len(name))
		for _, value := range values {
			total += int64(len(value))
			if total > MaximumResponseHeaderBytes {
				return fmt.Errorf("presignedshare: response headers exceed the byte limit: %w", s3disk.ErrResourceLimit)
			}
		}
	}
	return nil
}

func responseVersion(headers http.Header) (s3disk.Version, error) {
	etags := headers.Values("ETag")
	if len(etags) != 1 || etags[0] == "" || len(etags[0]) > s3disk.MaxStoreVersionTokenBytes || strings.ContainsAny(etags[0], "\x00\r\n") {
		return s3disk.Version{}, fmt.Errorf("presignedshare: response ETag is invalid: %w", s3disk.ErrStoreIncompatible)
	}
	versionIDs := headers.Values("X-Amz-Version-Id")
	if len(versionIDs) > 1 || (len(versionIDs) == 1 && (len(versionIDs[0]) > s3disk.MaxStoreVersionTokenBytes || strings.ContainsAny(versionIDs[0], "\x00\r\n"))) {
		return s3disk.Version{}, fmt.Errorf("presignedshare: response version ID is invalid: %w", s3disk.ErrStoreIncompatible)
	}
	version := s3disk.Version{ETag: etags[0]}
	if len(versionIDs) == 1 {
		version.VersionID = versionIDs[0]
	}
	return version, nil
}

func readBoundedBody(ctx context.Context, response *http.Response, limit int64) ([]byte, error) {
	if response.ContentLength < -1 {
		return nil, fmt.Errorf("presignedshare: response Content-Length is invalid: %w", s3disk.ErrStoreIncompatible)
	}
	if response.ContentLength > limit {
		return nil, fmt.Errorf("presignedshare: response body exceeds %d bytes: %w", limit, s3disk.ErrResourceLimit)
	}
	readLimit := limit
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, readLimit))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("presignedshare: response body read failed: %w", s3disk.ErrStoreUnavailable)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("presignedshare: response body exceeds %d bytes: %w", limit, s3disk.ErrResourceLimit)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

func classifyHTTPStatus(status int) error {
	var sentinel error
	switch {
	case status == http.StatusNotModified:
		sentinel = s3disk.ErrNotModified
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		sentinel = s3disk.ErrAccessDenied
	case status == http.StatusNotFound:
		sentinel = s3disk.ErrObjectNotFound
	case status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented:
		sentinel = s3disk.ErrStoreOperationUnsupported
	case status == http.StatusTooManyRequests:
		sentinel = s3disk.ErrRateLimited
	case status == http.StatusRequestTimeout || status == http.StatusConflict || status >= http.StatusInternalServerError:
		sentinel = s3disk.ErrStoreUnavailable
	case status == http.StatusPreconditionFailed:
		sentinel = s3disk.ErrPrecondition
	case status >= 300 && status < 400:
		sentinel = s3disk.ErrStoreMisconfigured
	case status >= 400 && status < 500:
		sentinel = s3disk.ErrStoreMisconfigured
	default:
		sentinel = s3disk.ErrStoreIncompatible
	}
	return fmt.Errorf("presignedshare: HTTP status %d: %w", status, sentinel)
}

func hasHeader(headers http.Header, name string) bool {
	for existing := range headers {
		if strings.EqualFold(existing, name) {
			return true
		}
	}
	return false
}

var (
	_ s3disk.ObjectReader              = (*Reader)(nil)
	_ s3disk.AuthorizationExpirySource = (*Reader)(nil)
)
