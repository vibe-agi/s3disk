package presignedshare

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
)

const (
	readerRootKey      = "shares/reader-root-bundle"
	readerReferenceKey = "repo/.s3disk/v1/refs/bWFpbg"
	readerObjectKeyA   = "repo/.s3disk/v1/objects/chunk/sha256/aa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	readerObjectKeyB   = "repo/.s3disk/v1/objects/file/sha256/bb/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	readerObjectKeyC   = "repo/.s3disk/v1/objects/dir/sha256/cc/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func TestReaderPollsBundleConditionallyAndFetchesObjectsLazily(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
	defer fixture.close()
	fixture.publish(t, 1, 1, readerTestReference(1, "initial"), map[string]string{
		readerObjectKeyA: "/object/a",
		readerObjectKeyB: "/object/b",
	}, `"bundle-v1"`)
	fixture.store.setObject("/object/a", objectResponse{data: []byte("alpha"), etag: `"object-a"`})
	fixture.store.setObject("/object/b", objectResponse{data: []byte("bravo"), etag: `"object-b"`})

	reader := fixture.reader(t)
	reference, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{MaxBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if reference.Version.ETag != `"bundle-v1"` || reference.Version.VersionID != "bundle-version" {
		t.Fatalf("reference version = %+v, want root bundle HTTP version", reference.Version)
	}
	if fixture.store.objectRequestCount() != 0 {
		t.Fatal("reference refresh eagerly fetched an immutable object")
	}
	if fixture.store.sawAuthorization() {
		t.Fatal("Reader added an Authorization header or S3 credential")
	}

	alpha, err := reader.Get(context.Background(), readerObjectKeyA, s3disk.GetOptions{MaxBytes: 5})
	if err != nil {
		t.Fatal(err)
	}
	if string(alpha.Data) != "alpha" || alpha.Version.ETag != `"object-a"` {
		t.Fatalf("object = %q %+v", alpha.Data, alpha.Version)
	}
	if fixture.store.pathRequests("/object/a") != 1 || fixture.store.pathRequests("/object/b") != 0 {
		t.Fatalf("lazy request counts a/b = %d/%d", fixture.store.pathRequests("/object/a"), fixture.store.pathRequests("/object/b"))
	}

	_, err = reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{IfNoneMatch: reference.Version.ETag, MaxBytes: 4096})
	if !errors.Is(err, s3disk.ErrNotModified) {
		t.Fatalf("conditional refresh error = %v, want ErrNotModified", err)
	}
	if got := fixture.store.lastRootIfNoneMatch(); got != `"bundle-v1"` {
		t.Fatalf("root If-None-Match = %q", got)
	}
	if cacheControl, pragma := fixture.store.lastRootCacheHeaders(); cacheControl != "no-cache" || pragma != "no-cache" {
		t.Fatalf("root cache headers = %q/%q, want no-cache/no-cache", cacheControl, pragma)
	}
	// Reader-internal bundle polling may get 304 even when a new caller does
	// not supply a reference condition; it must return the cached reference.
	if _, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{MaxBytes: 4096}); err != nil {
		t.Fatalf("unconditional caller after root 304: %v", err)
	}
}

func TestReaderBootstrapsFixedRootBeforeFirstImmutableRead(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
	defer fixture.close()
	fixture.publish(t, 1, 1, readerTestReference(1, "restart-bootstrap"), map[string]string{
		readerObjectKeyA: "/object/a",
	}, `"bundle-bootstrap"`)
	fixture.store.setObject("/object/a", objectResponse{data: []byte("restart commit"), etag: `"object-a"`})

	reader := fixture.reader(t)
	object, err := reader.Get(context.Background(), readerObjectKeyA, s3disk.GetOptions{MaxBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	if string(object.Data) != "restart commit" {
		t.Fatalf("first immutable read = %q", object.Data)
	}
	if fixture.store.pathRequests("/bundle") != 1 || fixture.store.pathRequests("/object/a") != 1 {
		t.Fatalf("bootstrap requests root/object = %d/%d, want 1/1",
			fixture.store.pathRequests("/bundle"), fixture.store.pathRequests("/object/a"))
	}
	if fixture.store.sawAuthorization() {
		t.Fatal("bootstrap added an Authorization header or reusable S3 credential")
	}

	// An arbitrary key still cannot be derived or fetched after bootstrap.
	if _, err := reader.Get(context.Background(), readerObjectKeyB, s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrAccessDenied) {
		t.Fatalf("ungranted key error = %v, want ErrAccessDenied", err)
	}
	if fixture.store.pathRequests("/object/b") != 0 {
		t.Fatal("bootstrap attempted a network request for an ungranted key")
	}
}

func TestReaderCollapsesConcurrentImmutableRootBootstrap(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
	defer fixture.close()
	fixture.publish(t, 1, 1, readerTestReference(1, "concurrent-restart-bootstrap"), map[string]string{
		readerObjectKeyA: "/object/a",
	}, `"bundle-bootstrap"`)
	fixture.store.setObject("/object/a", objectResponse{data: []byte("restart commit"), etag: `"object-a"`})
	fixture.store.mu.Lock()
	fixture.store.rootDelay = 5 * time.Millisecond
	fixture.store.mu.Unlock()

	reader := fixture.reader(t)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 0; index < 20; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			if _, err := reader.Get(context.Background(), readerObjectKeyA, s3disk.GetOptions{MaxBytes: 64}); err != nil {
				t.Errorf("concurrent bootstrap: %v", err)
			}
		}()
	}
	close(start)
	wait.Wait()
	if roots := fixture.store.pathRequests("/bundle"); roots != 1 {
		t.Fatalf("concurrent immutable bootstrap root requests = %d, want 1", roots)
	}
}

func TestReaderDropsCallerCookieJarCredentials(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
	defer fixture.close()
	fixture.publish(t, 1, 1, readerTestReference(1, "cookie-jar"), map[string]string{readerObjectKeyA: "/object/a"}, `"root"`)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	serverURL, err := url.Parse(fixture.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(serverURL, []*http.Cookie{{Name: "ambient-session", Value: "must-not-leak"}})
	client := *fixture.readerConfig.HTTPClient
	client.Jar = jar
	fixture.readerConfig.HTTPClient = &client
	reader := fixture.reader(t)
	if _, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	if fixture.store.sawCookie() {
		t.Fatal("Reader allowed caller CookieJar credentials onto a capability request")
	}
}

func TestNewReaderRejectsCustomVerifierBeforeCallingIt(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
	defer fixture.close()
	verifier := &readerCountingVerifier{repositoryID: fixture.verifier.RepositoryID()}
	config := fixture.readerConfig
	config.Verifier = verifier

	if _, err := NewReader(config); err == nil {
		t.Fatal("NewReader accepted a custom verifier without the dangerous opt-out")
	}
	if verifier.calls != 0 {
		t.Fatalf("custom verifier calls = %d, want 0", verifier.calls)
	}

	config.DangerouslyAllowCustomReferenceVerifier = true
	if _, err := NewReader(config); err != nil {
		t.Fatalf("NewReader with dangerous custom-verifier opt-out: %v", err)
	}
	if verifier.calls != 1 {
		t.Fatalf("custom verifier calls = %d, want 1 after opt-out", verifier.calls)
	}

	embedded := &readerEmbeddedVerifier{Ed25519ReferenceVerifier: fixture.verifier}
	config.Verifier = embedded
	config.DangerouslyAllowCustomReferenceVerifier = false
	if _, err := NewReader(config); err == nil {
		t.Fatal("NewReader accepted a wrapper which overrides an embedded offline verifier")
	}
	if embedded.calls != 0 {
		t.Fatalf("embedded verifier calls = %d, want 0", embedded.calls)
	}
}

func TestReaderStripsHTTPTraceCallbacksFromCapabilityRequests(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
	defer fixture.close()
	fixture.publish(t, 1, 1, readerTestReference(1, "context-trace"), map[string]string{
		readerObjectKeyA: "/object/a",
	}, `"root"`)
	reader := fixture.reader(t)

	callbacks := 0
	trace := &httptrace.ClientTrace{
		GetConn: func(string) { callbacks++ },
		WroteHeaderField: func(string, []string) {
			callbacks++
		},
	}
	ctx := httptrace.WithClientTrace(context.Background(), trace)
	if _, err := reader.Get(ctx, readerReferenceKey, s3disk.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	if callbacks != 0 {
		t.Fatalf("caller HTTP trace callbacks = %d, want 0", callbacks)
	}
}

func TestReaderRejectsUnconstrainedHTTPClientExtensions(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
	defer fixture.close()
	config := fixture.readerConfig
	config.HTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("must not run")
	})}
	if _, err := NewReader(config); err == nil {
		t.Fatal("NewReader accepted a custom RoundTripper")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec -- rejection fixture
	config.HTTPClient = &http.Client{Transport: transport}
	if _, err := NewReader(config); err == nil {
		t.Fatal("NewReader accepted InsecureSkipVerify")
	}
	transport = &http.Transport{TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{
		"h2": func(string, *tls.Conn) http.RoundTripper {
			return roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("alternate protocol must not run")
			})
		},
	}}
	config.HTTPClient = &http.Client{Transport: transport}
	if _, err := NewReader(config); err == nil {
		t.Fatal("NewReader accepted a TLSNextProto RoundTripper extension")
	}
	transport = &http.Transport{Proxy: http.ProxyFromEnvironment}
	config.HTTPClient = &http.Client{Transport: transport}
	if _, err := NewReader(config); err == nil {
		t.Fatal("NewReader accepted environment proxy routing")
	}
	transport = &http.Transport{TLSClientConfig: &tls.Config{
		CipherSuites: []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
	}}
	config.HTTPClient = &http.Client{Transport: transport}
	if _, err := NewReader(config); err == nil {
		t.Fatal("NewReader accepted an explicitly configured insecure cipher suite")
	}

	constraintCalls := 0
	rootCAs := x509.NewCertPool()
	rootCAs.AddCertWithConstraint(fixture.server.Certificate(), func([]*x509.Certificate) error {
		constraintCalls++
		return nil
	})
	transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootCAs}}
	config.HTTPClient = &http.Client{Transport: transport}
	if _, err := NewReader(config); err == nil {
		t.Fatal("NewReader accepted a caller-created certificate pool")
	}
	if constraintCalls != 0 {
		t.Fatalf("certificate-pool constraint calls = %d, want 0", constraintCalls)
	}
}

func TestReaderAcceptsStandardLibraryHTTP2ALPNButNotCustomALPN(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
	defer fixture.close()
	config := fixture.readerConfig
	config.HTTPClient = &http.Client{Transport: &http.Transport{ForceAttemptHTTP2: true}}

	reader, err := NewReader(config)
	if err != nil {
		t.Fatalf("NewReader with ForceAttemptHTTP2: %v", err)
	}
	transport, ok := reader.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Reader transport = %T, want *http.Transport", reader.client.Transport)
	}
	if got := transport.TLSClientConfig.NextProtos; len(got) != 0 {
		t.Fatalf("Reader inherited caller ALPN protocols = %q, want none", got)
	}

	config.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		NextProtos: []string{"custom-protocol"},
	}}}
	if _, err := NewReader(config); err == nil {
		t.Fatal("NewReader accepted custom ALPN protocols")
	}
}

func TestReaderHTTPSRequiresExplicitTrustSource(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
	defer fixture.close()

	config := fixture.readerConfig
	config.TLSRootCAPEM = nil
	if _, err := NewReader(config); err == nil {
		t.Fatal("NewReader accepted HTTPS with neither pinned roots nor the dangerous system-trust opt-out")
	}

	config.DangerouslyAllowSystemTrustStore = true
	if _, err := NewReader(config); err != nil {
		t.Fatalf("NewReader with explicit system-trust opt-out: %v", err)
	}

	config.DangerouslyAllowSystemTrustStore = false
	config.TLSRootCAPEM = fixture.readerConfig.TLSRootCAPEM
	if _, err := NewReader(config); err != nil {
		t.Fatalf("NewReader with explicit PEM trust roots: %v", err)
	}

	config.TLSRootCAPEM = append([]byte("AWS_SECRET_ACCESS_KEY=must-not-be-ignored\n"), fixture.readerConfig.TLSRootCAPEM...)
	if _, err := NewReader(config); err == nil {
		t.Fatal("NewReader accepted non-PEM material before an otherwise valid trust root")
	}
	config.TLSRootCAPEM = append([]byte("-----BEGIN CERTIFICATE-----\ninvalid and unclosed\n"), fixture.readerConfig.TLSRootCAPEM...)
	if _, err := NewReader(config); err == nil {
		t.Fatal("NewReader skipped an unclosed certificate block before a valid trust root")
	}
	firstWithoutLineEnd := bytes.TrimSuffix(fixture.readerConfig.TLSRootCAPEM, []byte{'\n'})
	config.TLSRootCAPEM = append(append([]byte(nil), firstWithoutLineEnd...), fixture.readerConfig.TLSRootCAPEM...)
	if _, err := NewReader(config); err == nil {
		t.Fatal("NewReader accepted two certificate boundaries on the same line")
	}
}

func TestReaderBuildsDirectLockedTransport(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
	defer fixture.close()
	reader := fixture.reader(t)
	transport, ok := reader.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Reader transport = %T, want *http.Transport", reader.client.Transport)
	}
	//lint:ignore SA1019 Deprecated dialer fields must remain empty on the constructed transport.
	legacyDialerConfigured := transport.Dial != nil || transport.DialTLS != nil
	if transport.Proxy != nil || transport.OnProxyConnectResponse != nil ||
		transport.DialContext == nil || transport.DialTLSContext != nil ||
		legacyDialerConfigured ||
		transport.TLSNextProto != nil || transport.ProxyConnectHeader != nil ||
		transport.GetProxyConnectHeader != nil || transport.Protocols != nil {
		t.Fatal("Reader retained a caller-controlled routing or alternate-protocol extension")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify ||
		transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("Reader did not retain only the trusted TLS roots with verification enabled")
	}
	dialer := newLockedNetworkDialer()
	if dialer.Resolver == nil || dialer.Resolver == net.DefaultResolver || !dialer.Resolver.PreferGo || dialer.Resolver.Dial != nil {
		t.Fatal("Reader dialer does not use a private callback-free DNS resolver")
	}
}

func TestReaderUpdateRollbackSplitBrainAndTamper(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
	defer fixture.close()
	fixture.store.setObject("/object/a", objectResponse{data: []byte("alpha"), etag: `"a"`})
	fixture.store.setObject("/object/b", objectResponse{data: []byte("bravo"), etag: `"b"`})
	referenceOne := readerTestReference(1, "reference-one")
	fixture.publish(t, 1, 1, referenceOne, map[string]string{readerObjectKeyA: "/object/a"}, `"root-1"`)
	reader := fixture.reader(t)
	first, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	referenceTwo := readerTestReference(2, "reference-two")
	fixture.publish(t, 2, 2, referenceTwo, map[string]string{readerObjectKeyB: "/object/b"}, `"root-2"`)
	second, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{IfNoneMatch: first.Version.ETag})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second.Data, referenceTwo) || second.Version.ETag != `"root-2"` {
		t.Fatalf("updated reference = %q %+v", second.Data, second.Version)
	}
	// The previous revision remains usable for an already-open snapshot.
	if object, err := reader.Get(context.Background(), readerObjectKeyA, s3disk.GetOptions{}); err != nil || string(object.Data) != "alpha" {
		t.Fatalf("retained old capability object=%q err=%v", object.Data, err)
	}

	fixture.publish(t, 1, 1, referenceOne, map[string]string{readerObjectKeyA: "/object/a"}, `"root-rollback"`)
	if _, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrRollbackDetected) {
		t.Fatalf("revision rollback error = %v", err)
	}

	fixture.publish(t, 2, 2, readerTestReference(2, "different-same-revision"), map[string]string{readerObjectKeyB: "/object/b"}, `"root-split"`)
	if _, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrSplitBrain) {
		t.Fatalf("same revision split-brain error = %v", err)
	}

	fixture.publish(t, 3, 3, readerTestReference(3, "reference-three"), map[string]string{readerObjectKeyB: "/object/b"}, `"root-tamper"`)
	fixture.store.mu.Lock()
	fixture.store.bundle = bytes.Replace(fixture.store.bundle, []byte("signature=object"), []byte("signature=tamper"), 1)
	fixture.store.mu.Unlock()
	_, err = reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{})
	if !errors.Is(err, s3disk.ErrUntrustedReference) {
		t.Fatalf("tamper error = %v, want ErrUntrustedReference", err)
	}
	if strings.Contains(err.Error(), "signature=") || strings.Contains(err.Error(), fixture.server.URL) {
		t.Fatalf("tamper error leaked bearer material: %v", err)
	}
}

func TestReaderRejectsGenerationRegressionAndSameGenerationFork(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
	defer fixture.close()
	fixture.publish(t, 1, 3, readerTestReference(3, "generation-three"), map[string]string{readerObjectKeyA: "/object/a"}, `"root-1"`)
	reader := fixture.reader(t)
	if _, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	fixture.publish(t, 2, 2, readerTestReference(2, "generation-two"), map[string]string{readerObjectKeyA: "/object/a"}, `"root-2"`)
	if _, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrRollbackDetected) {
		t.Fatalf("generation rollback error = %v", err)
	}
	fixture.publish(t, 2, 3, readerTestReference(3, "forked-generation-three"), map[string]string{readerObjectKeyA: "/object/a"}, `"root-3"`)
	if _, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrSplitBrain) {
		t.Fatalf("generation fork error = %v", err)
	}
}

func TestReaderAllowsHigherRevisionResignOfSameGenerationAndCommit(t *testing.T) {
	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	capability, err := newTestCapability(readerObjectKeyA, "https://objects.example.test/object?signature=secret", nil, expiry, CapabilityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	commit, err := s3disk.ParseDigest(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	reader := &Reader{
		maxRetainedCapabilities:    2,
		maxRetainedCapabilityBytes: 1 << 20,
		state: &readerState{
			retainedCapabilities: make(map[string]Capability),
		},
	}
	first := &Bundle{
		revision: 1, referenceGeneration: 7, referenceCommit: commit,
		reference:    s3disk.Object{Data: []byte("signed-reference-key-one")},
		capabilities: map[string]Capability{readerObjectKeyA: capability},
	}
	if err := reader.installBundle(context.Background(), first, sha256.Sum256([]byte("bundle-one")), s3disk.Version{ETag: `"one"`}); err != nil {
		t.Fatal(err)
	}
	second := &Bundle{
		revision: 2, referenceGeneration: 7, referenceCommit: commit,
		reference:    s3disk.Object{Data: []byte("same-reference-resigned-by-key-two")},
		capabilities: map[string]Capability{readerObjectKeyA: capability},
	}
	if err := reader.installBundle(context.Background(), second, sha256.Sum256([]byte("bundle-two")), s3disk.Version{ETag: `"two"`}); err != nil {
		t.Fatalf("legitimate resign was rejected: %v", err)
	}
	reader.state.mu.RLock()
	got := append([]byte(nil), reader.state.current.referenceData...)
	reader.state.mu.RUnlock()
	if !bytes.Equal(got, second.reference.Data) {
		t.Fatalf("current reference = %q, want resigned bytes", got)
	}
}

func TestReaderRejectsRedirectsAndCrossOriginBundleWithoutFollowing(t *testing.T) {
	t.Run("root redirect", func(t *testing.T) {
		fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
		defer fixture.close()
		fixture.publish(t, 1, 1, readerTestReference(1, "redirect-root"), map[string]string{readerObjectKeyA: "/object/a"}, `"root"`)
		fixture.store.mu.Lock()
		fixture.store.rootRedirect = "/redirect-target?secret=redirected"
		fixture.store.mu.Unlock()
		_, err := fixture.reader(t).Get(context.Background(), readerReferenceKey, s3disk.GetOptions{})
		if !errors.Is(err, s3disk.ErrStoreMisconfigured) {
			t.Fatalf("redirect error = %v", err)
		}
		if fixture.store.pathRequests("/redirect-target") != 0 || strings.Contains(err.Error(), "secret=") {
			t.Fatalf("redirect followed or leaked: hits=%d err=%v", fixture.store.pathRequests("/redirect-target"), err)
		}
	})

	t.Run("object redirect", func(t *testing.T) {
		fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
		defer fixture.close()
		fixture.publish(t, 1, 1, readerTestReference(1, "redirect-object"), map[string]string{readerObjectKeyA: "/object/a"}, `"root"`)
		fixture.store.setObject("/object/a", objectResponse{status: http.StatusFound, redirect: "/redirect-target?secret=object"})
		reader := fixture.reader(t)
		if _, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{}); err != nil {
			t.Fatal(err)
		}
		_, err := reader.Get(context.Background(), readerObjectKeyA, s3disk.GetOptions{})
		if !errors.Is(err, s3disk.ErrStoreMisconfigured) || fixture.store.pathRequests("/redirect-target") != 0 {
			t.Fatalf("object redirect result hits=%d err=%v", fixture.store.pathRequests("/redirect-target"), err)
		}
	})

	t.Run("signed cross origin", func(t *testing.T) {
		fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
		defer fixture.close()
		fixture.publish(t, 1, 1, readerTestReference(1, "cross-origin"), map[string]string{readerObjectKeyA: "/object/a"}, `"root"`)
		fixture.store.mu.Lock()
		var envelope signedBundle
		if err := json.Unmarshal(fixture.store.bundle, &envelope); err != nil {
			fixture.store.mu.Unlock()
			t.Fatal(err)
		}
		envelope.Payload.Capabilities[0].URL = "https://other.example.test/object?signature=cross-origin-secret"
		resignEnvelope(t, &envelope, fixture.signer)
		fixture.store.bundle, _ = json.Marshal(envelope)
		fixture.store.mu.Unlock()
		_, err := fixture.reader(t).Get(context.Background(), readerReferenceKey, s3disk.GetOptions{})
		if !errors.Is(err, s3disk.ErrCorruptObject) || strings.Contains(err.Error(), "cross-origin-secret") {
			t.Fatalf("cross-origin error = %v", err)
		}
	})
}

func TestReaderObjectStatusLimitsAndVersions(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
	defer fixture.close()
	fixture.publish(t, 1, 1, readerTestReference(1, "status"), map[string]string{readerObjectKeyA: "/object/a"}, `"root"`)
	reader := fixture.reader(t)
	if _, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{}); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		status int
		want   error
	}{
		{"denied", http.StatusForbidden, s3disk.ErrAccessDenied},
		{"missing", http.StatusNotFound, s3disk.ErrObjectNotFound},
		{"rate", http.StatusTooManyRequests, s3disk.ErrRateLimited},
		{"unavailable", http.StatusServiceUnavailable, s3disk.ErrStoreUnavailable},
		{"unsupported", http.StatusMethodNotAllowed, s3disk.ErrStoreOperationUnsupported},
		{"precondition", http.StatusPreconditionFailed, s3disk.ErrPrecondition},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture.store.setObject("/object/a", objectResponse{status: test.status})
			_, err := reader.Get(context.Background(), readerObjectKeyA, s3disk.GetOptions{})
			if !errors.Is(err, test.want) {
				t.Fatalf("status %d error = %v, want %v", test.status, err, test.want)
			}
			if strings.Contains(err.Error(), fixture.server.URL) || strings.Contains(err.Error(), "signature=") {
				t.Fatalf("status error leaked bearer: %v", err)
			}
		})
	}

	fixture.store.setObject("/object/a", objectResponse{data: []byte("missing-etag")})
	if _, err := reader.Get(context.Background(), readerObjectKeyA, s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("missing ETag error = %v", err)
	}
	fixture.store.setObject("/object/a", objectResponse{data: []byte("oversized-etag"), etag: strings.Repeat("e", s3disk.MaxStoreVersionTokenBytes+1)})
	if _, err := reader.Get(context.Background(), readerObjectKeyA, s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("oversized ETag error = %v", err)
	}

	fixture.store.setObject("/object/a", objectResponse{data: bytes.Repeat([]byte{'x'}, 1025), etag: `"large"`, chunked: true})
	if _, err := reader.Get(context.Background(), readerObjectKeyA, s3disk.GetOptions{MaxBytes: 1024}); !errors.Is(err, s3disk.ErrResourceLimit) {
		t.Fatalf("streaming limit error = %v", err)
	}
	fixture.store.setObject("/object/a", objectResponse{data: []byte("short"), etag: `"declared"`, declaredLength: 2048})
	if _, err := reader.Get(context.Background(), readerObjectKeyA, s3disk.GetOptions{MaxBytes: 1024}); !errors.Is(err, s3disk.ErrResourceLimit) {
		t.Fatalf("Content-Length limit error = %v", err)
	}

	fixture.store.setObject("/object/a", objectResponse{data: []byte("conditional"), etag: `"condition"`})
	if _, err := reader.Get(context.Background(), readerObjectKeyA, s3disk.GetOptions{IfNoneMatch: `"condition"`}); !errors.Is(err, s3disk.ErrNotModified) {
		t.Fatalf("conditional object error = %v", err)
	}
}

func TestReaderRootRequiresHTTPVersionAndRetentionBytes(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
	defer fixture.close()
	fixture.publish(t, 1, 1, readerTestReference(1, "root-etag"), map[string]string{readerObjectKeyA: "/object/a"}, `"root"`)
	fixture.store.mu.Lock()
	fixture.store.bundleETag = ""
	fixture.store.mu.Unlock()
	if _, err := fixture.reader(t).Get(context.Background(), readerReferenceKey, s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("missing root ETag error = %v", err)
	}

	fixture.publish(t, 1, 1, readerTestReference(1, "retention-bytes"), map[string]string{readerObjectKeyA: "/object/a"}, `"root-with-etag"`)
	config := fixture.readerConfig
	config.MaxRetainedCapabilityBytes = 1
	reader, err := NewReader(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrResourceLimit) {
		t.Fatalf("retention byte limit error = %v", err)
	}
	if _, err := reader.Get(context.Background(), readerObjectKeyA, s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrResourceLimit) {
		t.Fatalf("object after rejected install error = %v, want repeated bounded root rejection", err)
	}
	if fixture.store.pathRequests("/object/a") != 0 {
		t.Fatal("rejected root install allowed an immutable-object request")
	}
}

func TestReaderRequiresExplicitLoopbackHTTPAtConsumption(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
	defer fixture.close()
	root, err := newTestCapability(readerRootKey, "http://127.0.0.1:9000/bundle?signature=test", nil, fixture.expiry, CapabilityOptions{AllowInsecureLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	config := fixture.readerConfig
	config.RootCapability = root
	config.TLSRootCAPEM = nil
	config.AllowInsecureLoopback = false
	if _, err := NewReader(config); err == nil {
		t.Fatal("NewReader accepted loopback HTTP without ReaderConfig opt-in")
	}
	config.AllowInsecureLoopback = true
	if _, err := NewReader(config); err != nil {
		t.Fatalf("explicit Reader loopback HTTP opt-in rejected: %v", err)
	}
}

func TestReaderResponseHeaderBoundWithCustomTransport(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
	defer fixture.close()
	fixture.publish(t, 1, 1, readerTestReference(1, "headers"), map[string]string{readerObjectKeyA: "/object/a"}, `"root"`)
	reader := fixture.reader(t)
	if _, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	reader.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"ETag": {`"etag"`}, "X-Oversized": {strings.Repeat("h", int(MaximumResponseHeaderBytes))}},
			Body:       io.NopCloser(strings.NewReader("data")), ContentLength: 4,
		}, nil
	})
	if _, err := reader.Get(context.Background(), readerObjectKeyA, s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrResourceLimit) {
		t.Fatalf("header bound error = %v", err)
	}
}

func TestReaderAuthorizationExpiryBoundsCompleteBody(t *testing.T) {
	expiry := time.Now().Add(350 * time.Millisecond).UTC()
	fixture := newReaderFixture(t, expiry, ReaderConfig{OperationTimeout: 5 * time.Second})
	defer fixture.close()
	fixture.publish(t, 1, 1, readerTestReference(1, "expiry"), map[string]string{readerObjectKeyA: "/object/a"}, `"root"`)
	fixture.store.setObject("/object/a", objectResponse{data: []byte("prefix"), etag: `"blocked"`, blockUntilContext: true})
	reader := fixture.reader(t)
	if got, known := reader.AuthorizationExpiry(); !known || !got.Equal(expiry) {
		t.Fatalf("AuthorizationExpiry = %v/%t, want %v", got, known, expiry)
	}
	if _, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	_, err := reader.Get(context.Background(), readerObjectKeyA, s3disk.GetOptions{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("body expiry error = %v, want DeadlineExceeded", err)
	}
	requestsBefore := fixture.store.totalRequests()
	for _, key := range []string{readerReferenceKey, readerObjectKeyA} {
		if _, err := reader.Get(context.Background(), key, s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrAccessDenied) {
			t.Fatalf("expired Get(%q) error = %v, want ErrAccessDenied", key, err)
		}
	}
	if requestsAfter := fixture.store.totalRequests(); requestsAfter != requestsBefore {
		t.Fatalf("expired Gets performed network I/O: before=%d after=%d", requestsBefore, requestsAfter)
	}
}

func TestReaderRetentionRejectsUpdateBeforeEvictingOlderExactCapability(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{
		MaxRetainedCapabilities: 2,
	})
	defer fixture.close()
	fixture.store.setObject("/object/a", objectResponse{data: []byte("alpha"), etag: `"a"`})
	fixture.store.setObject("/object/b", objectResponse{data: []byte("bravo"), etag: `"b"`})
	fixture.store.setObject("/object/c", objectResponse{data: []byte("charlie"), etag: `"c"`})
	fixture.publish(t, 1, 1, readerTestReference(1, "retention-one"), map[string]string{readerObjectKeyA: "/object/a"}, `"root-1"`)
	reader := fixture.reader(t)
	if _, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	fixture.publish(t, 2, 2, readerTestReference(2, "retention-two"), map[string]string{readerObjectKeyB: "/object/b"}, `"root-2"`)
	if _, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	fixture.publish(t, 3, 3, readerTestReference(3, "retention-three"), map[string]string{readerObjectKeyC: "/object/c"}, `"root-3"`)
	if _, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrResourceLimit) {
		t.Fatalf("third revision error = %v, want ErrResourceLimit before eviction", err)
	}
	for key, want := range map[string]string{readerObjectKeyA: "alpha", readerObjectKeyB: "bravo"} {
		object, err := reader.Get(context.Background(), key, s3disk.GetOptions{})
		if err != nil || string(object.Data) != want {
			t.Fatalf("retained %s object=%q err=%v", key, object.Data, err)
		}
	}
	if _, err := reader.Get(context.Background(), readerObjectKeyC, s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrAccessDenied) {
		t.Fatalf("rejected revision key error = %v, want ErrAccessDenied", err)
	}
}

func TestReaderRetentionDeduplicatesImmutableKeysAcrossRevisions(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{
		MaxRetainedCapabilities: 1,
	})
	defer fixture.close()
	fixture.store.setObject("/object/a", objectResponse{data: []byte("alpha"), etag: `"a"`})
	reader := fixture.reader(t)
	for revision := uint64(1); revision <= 10; revision++ {
		fixture.publish(t, revision, revision, readerTestReference(revision, fmt.Sprintf("deduplicated-%d", revision)), map[string]string{
			readerObjectKeyA: "/object/a",
		}, fmt.Sprintf(`"root-%d"`, revision))
		if _, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{}); err != nil {
			t.Fatalf("revision %d: %v", revision, err)
		}
	}
	if object, err := reader.Get(context.Background(), readerObjectKeyA, s3disk.GetOptions{}); err != nil || string(object.Data) != "alpha" {
		t.Fatalf("deduplicated object=%q err=%v", object.Data, err)
	}
}

func TestReaderRefreshSerializationIsCancelableAndRaceSafe(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
	defer fixture.close()
	fixture.publish(t, 1, 1, readerTestReference(1, "concurrency"), map[string]string{readerObjectKeyA: "/object/a"}, `"root"`)
	reader := fixture.reader(t)
	reference, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	hold := make(chan struct{})
	started := make(chan struct{})
	fixture.store.mu.Lock()
	fixture.store.rootHold = hold
	fixture.store.rootStarted = started
	fixture.store.rootStartOnce = sync.Once{}
	fixture.store.mu.Unlock()
	firstDone := make(chan error, 1)
	go func() {
		_, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{IfNoneMatch: reference.Version.ETag})
		firstDone <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first refresh did not reach root")
	}
	ctx, cancel := context.WithCancel(context.Background())
	secondDone := make(chan error, 1)
	go func() {
		_, err := reader.Get(ctx, readerReferenceKey, s3disk.GetOptions{IfNoneMatch: reference.Version.ETag})
		secondDone <- err
	}()
	cancel()
	if err := <-secondDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting refresh error = %v, want context.Canceled", err)
	}
	close(hold)
	if err := <-firstDone; !errors.Is(err, s3disk.ErrNotModified) {
		t.Fatalf("first refresh error = %v", err)
	}
	if maximum := fixture.store.maximumConcurrentRoots(); maximum != 1 {
		t.Fatalf("maximum concurrent root requests = %d, want 1", maximum)
	}

	fixture.store.mu.Lock()
	fixture.store.rootHold = nil
	fixture.store.rootStarted = nil
	fixture.store.rootDelay = 2 * time.Millisecond
	fixture.store.mu.Unlock()
	var wait sync.WaitGroup
	for index := 0; index < 20; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, gotErr := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{IfNoneMatch: reference.Version.ETag})
			if !errors.Is(gotErr, s3disk.ErrNotModified) {
				t.Errorf("concurrent refresh error = %v", gotErr)
			}
		}()
	}
	wait.Wait()
	if maximum := fixture.store.maximumConcurrentRoots(); maximum != 1 {
		t.Fatalf("maximum concurrent root requests after fanout = %d", maximum)
	}
}

func TestReaderDiagnosticsRedactRootAndObjectBearers(t *testing.T) {
	fixture := newReaderFixture(t, time.Now().Add(10*time.Minute).UTC().Truncate(time.Second), ReaderConfig{})
	defer fixture.close()
	fixture.publish(t, 1, 1, readerTestReference(1, "diagnostics"), map[string]string{readerObjectKeyA: "/object/a"}, `"root"`)
	reader := fixture.reader(t)
	if _, err := reader.Get(context.Background(), readerReferenceKey, s3disk.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(reader)
	if err != nil {
		t.Fatal(err)
	}
	readerValue := *reader
	encodedValue, err := json.Marshal(readerValue)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		fmt.Sprint(reader), fmt.Sprintf("%+v", reader), fmt.Sprintf("%#v", reader), string(encoded),
		fmt.Sprint(readerValue), fmt.Sprintf("%+v", readerValue), fmt.Sprintf("%#v", readerValue), string(encodedValue),
	} {
		if strings.Contains(value, fixture.server.URL) || strings.Contains(value, "signature=") || !strings.Contains(value, "redacted") {
			t.Fatalf("Reader diagnostic leaked bearer or omitted redaction: %s", value)
		}
	}
}

type readerFixture struct {
	t            *testing.T
	store        *readerHTTPStore
	server       *httptest.Server
	expiry       time.Time
	shareID      ShareID
	signer       *s3disk.Ed25519ReferenceSigner
	verifier     *s3disk.Ed25519ReferenceVerifier
	root         Capability
	readerConfig ReaderConfig
}

type readerCountingVerifier struct {
	repositoryID s3disk.RepositoryID
	calls        int
}

type readerEmbeddedVerifier struct {
	*s3disk.Ed25519ReferenceVerifier
	calls int
}

func (verifier *readerEmbeddedVerifier) RepositoryID() s3disk.RepositoryID {
	verifier.calls++
	return verifier.Ed25519ReferenceVerifier.RepositoryID()
}

func (verifier *readerEmbeddedVerifier) Verify(context.Context, string, []byte, []byte) error {
	verifier.calls++
	return nil
}

func (verifier *readerCountingVerifier) RepositoryID() s3disk.RepositoryID {
	verifier.calls++
	return verifier.repositoryID
}

func (*readerCountingVerifier) Verify(context.Context, string, []byte, []byte) error {
	return nil
}

func newReaderFixture(t *testing.T, expiry time.Time, overrides ReaderConfig) *readerFixture {
	t.Helper()
	store := &readerHTTPStore{objects: make(map[string]objectResponse), requests: make(map[string]int)}
	server := httptest.NewTLSServer(store)
	repositoryID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	signer, err := s3disk.NewEd25519ReferenceSigner(repositoryID, "reader-share", privateKey)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	verifier, err := s3disk.NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{"reader-share": publicKey})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	shareID, err := GenerateShareID()
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	root, err := newTestCapability(readerRootKey, server.URL+"/bundle?signature=root-secret", nil, expiry, CapabilityOptions{})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	tlsRootCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	config := ReaderConfig{
		RootCapability: root, RepositoryPrefix: "repo", ReferenceKey: readerReferenceKey,
		ShareID: shareID, Verifier: verifier, TLSRootCAPEM: tlsRootCAPEM, HTTPClient: &http.Client{Transport: transport},
		OperationTimeout:           overrides.OperationTimeout,
		MaxRetainedCapabilities:    overrides.MaxRetainedCapabilities,
		MaxRetainedCapabilityBytes: overrides.MaxRetainedCapabilityBytes,
	}
	return &readerFixture{
		t: t, store: store, server: server, expiry: expiry, shareID: shareID,
		signer: signer, verifier: verifier, root: root, readerConfig: config,
	}
}

func (fixture *readerFixture) close() { fixture.server.Close() }

func (fixture *readerFixture) reader(t *testing.T) *Reader {
	t.Helper()
	reader, err := NewReader(fixture.readerConfig)
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

func (fixture *readerFixture) publish(t *testing.T, revision, generation uint64, reference []byte, objectPaths map[string]string, etag string) []byte {
	t.Helper()
	identity, err := s3disk.VerifySnapshotReference(context.Background(), reference, "main", nil)
	if err != nil {
		t.Fatalf("test reference: %v", err)
	}
	if identity.Generation != generation {
		t.Fatalf("test reference generation = %d, want %d", identity.Generation, generation)
	}
	keys := make([]string, 0, len(objectPaths))
	for key := range objectPaths {
		keys = append(keys, key)
	}
	// Deliberately do not sort: Build owns canonical ordering.
	capabilities := make([]ExactCapability, 0, len(keys))
	for _, key := range keys {
		path := objectPaths[key]
		capability, err := newTestCapability(key, fixture.server.URL+path+"?signature=object-secret-"+strconv.FormatUint(revision, 10), nil, fixture.expiry, CapabilityOptions{})
		if err != nil {
			t.Fatal(err)
		}
		capabilities = append(capabilities, ExactCapability{Key: key, Capability: capability})
	}
	encoded, err := Build(context.Background(), BuildInput{
		RootCapability: fixture.root, RootKey: readerRootKey, RepositoryPrefix: "repo", ReferenceKey: readerReferenceKey,
		ShareID: fixture.shareID, Revision: revision, ReferenceGeneration: generation, ReferenceCommit: identity.Commit,
		Reference:              s3disk.Object{Data: append([]byte(nil), reference...), Version: s3disk.Version{ETag: `"embedded-reference-etag"`}},
		AuthorizationExpiresAt: fixture.expiry, Capabilities: capabilities,
	}, fixture.signer, fixture.verifier)
	if err != nil {
		t.Fatal(err)
	}
	fixture.store.mu.Lock()
	fixture.store.bundle = encoded
	fixture.store.bundleETag = etag
	fixture.store.bundleVersionID = "bundle-version"
	fixture.store.mu.Unlock()
	return encoded
}

func readerTestReference(generation uint64, tag string) []byte {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d:%s", generation, tag)))
	commit := s3disk.Digest(hash)
	return []byte(fmt.Sprintf(`{"format":1,"generation":%d,"commit":"%s"}`, generation, commit))
}

type objectResponse struct {
	status            int
	data              []byte
	etag              string
	versionID         string
	redirect          string
	declaredLength    int64
	chunked           bool
	blockUntilContext bool
	headers           http.Header
}

type readerHTTPStore struct {
	mu                   sync.Mutex
	bundle               []byte
	bundleETag           string
	bundleVersionID      string
	objects              map[string]objectResponse
	requests             map[string]int
	lastRootIfNone       string
	lastRootCacheControl string
	lastRootPragma       string
	authorization        bool
	cookie               bool
	rootRedirect         string
	rootHold             chan struct{}
	rootStarted          chan struct{}
	rootStartOnce        sync.Once
	rootDelay            time.Duration
	activeRoots          int
	maxActiveRoots       int
}

func (store *readerHTTPStore) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	store.mu.Lock()
	store.requests[request.URL.Path]++
	if request.Header.Get("Authorization") != "" {
		store.authorization = true
	}
	if request.Header.Get("Cookie") != "" {
		store.cookie = true
	}
	if request.URL.Path == "/bundle" {
		store.activeRoots++
		if store.activeRoots > store.maxActiveRoots {
			store.maxActiveRoots = store.activeRoots
		}
		store.lastRootIfNone = request.Header.Get("If-None-Match")
		store.lastRootCacheControl = request.Header.Get("Cache-Control")
		store.lastRootPragma = request.Header.Get("Pragma")
		hold, started, delay := store.rootHold, store.rootStarted, store.rootDelay
		redirect := store.rootRedirect
		bundle := append([]byte(nil), store.bundle...)
		etag, versionID := store.bundleETag, store.bundleVersionID
		ifNoneMatch := store.lastRootIfNone
		if started != nil {
			store.rootStartOnce.Do(func() { close(started) })
		}
		store.mu.Unlock()
		defer func() {
			store.mu.Lock()
			store.activeRoots--
			store.mu.Unlock()
		}()
		if hold != nil {
			select {
			case <-hold:
			case <-request.Context().Done():
				return
			}
		}
		if delay > 0 {
			time.Sleep(delay)
		}
		if redirect != "" {
			http.Redirect(writer, request, redirect, http.StatusFound)
			return
		}
		if ifNoneMatch != "" && ifNoneMatch == etag {
			writer.WriteHeader(http.StatusNotModified)
			return
		}
		writer.Header().Set("ETag", etag)
		writer.Header().Set("X-Amz-Version-Id", versionID)
		_, _ = writer.Write(bundle)
		return
	}
	response, ok := store.objects[request.URL.Path]
	store.mu.Unlock()
	if !ok {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	for name, values := range response.headers {
		for _, value := range values {
			writer.Header().Add(name, value)
		}
	}
	if response.redirect != "" {
		http.Redirect(writer, request, response.redirect, response.status)
		return
	}
	if request.Header.Get("If-None-Match") != "" && request.Header.Get("If-None-Match") == response.etag {
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	if response.etag != "" {
		writer.Header().Set("ETag", response.etag)
	}
	if response.versionID != "" {
		writer.Header().Set("X-Amz-Version-Id", response.versionID)
	}
	if response.declaredLength > 0 {
		writer.Header().Set("Content-Length", strconv.FormatInt(response.declaredLength, 10))
	}
	status := response.status
	if status == 0 {
		status = http.StatusOK
	}
	writer.WriteHeader(status)
	if response.chunked {
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
	}
	_, _ = writer.Write(response.data)
	if response.blockUntilContext {
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		<-request.Context().Done()
	}
}

func (store *readerHTTPStore) setObject(path string, response objectResponse) {
	store.mu.Lock()
	store.objects[path] = response
	store.mu.Unlock()
}

func (store *readerHTTPStore) objectRequestCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	total := 0
	for path, count := range store.requests {
		if strings.HasPrefix(path, "/object/") {
			total += count
		}
	}
	return total
}

func (store *readerHTTPStore) pathRequests(path string) int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.requests[path]
}

func (store *readerHTTPStore) sawAuthorization() bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.authorization
}

func (store *readerHTTPStore) sawCookie() bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.cookie
}

func (store *readerHTTPStore) totalRequests() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	total := 0
	for _, count := range store.requests {
		total += count
	}
	return total
}

func (store *readerHTTPStore) lastRootIfNoneMatch() string {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.lastRootIfNone
}

func (store *readerHTTPStore) lastRootCacheHeaders() (string, string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.lastRootCacheControl, store.lastRootPragma
}

func (store *readerHTTPStore) maximumConcurrentRoots() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.maxActiveRoots
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

var _ http.RoundTripper = roundTripFunc(nil)
