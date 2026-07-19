package presignedshare

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vibe-agi/s3disk/internal/presignedcap"
)

const (
	// MaximumCapabilityURLBytes bounds a presigned URL retained in memory or
	// accepted from an authenticated bundle.
	MaximumCapabilityURLBytes = 16 << 10
	// MaximumCapabilityHeaders bounds distinct signed/request header names.
	MaximumCapabilityHeaders = 32
	// MaximumCapabilityHeaderValues bounds all values across all headers.
	MaximumCapabilityHeaderValues = 64
	// MaximumCapabilityHeaderBytes bounds header names and values together.
	MaximumCapabilityHeaderBytes = 16 << 10
	// MaximumCapabilityLifetime is also compatible with the SigV4 query
	// authentication upper bound used by AWS S3. A provider may impose less.
	MaximumCapabilityLifetime = 7 * 24 * time.Hour
	// MaximumBearerExportBytes bounds the explicit cross-machine secret
	// envelope produced by ExportBearer and accepted by ParseBearer.
	MaximumBearerExportBytes = 128 << 10
)

var ErrInvalidCapability = errors.New("presignedshare: invalid capability")

// CapabilityOptions controls validation at the point secret material enters
// this package. HTTP is never accepted except for an explicitly enabled
// literal loopback endpoint used by local integration tests.
type CapabilityOptions struct {
	AllowInsecureLoopback bool
}

// Capability is one exact-key, time-limited GET authority. Its raw URL and
// headers deliberately have no public accessor: future network code in this
// package consumes them without making accidental application logging easy.
type Capability struct {
	rawURL     string
	headers    http.Header
	expiresAt  time.Time
	origin     string
	exactKey   string
	provenance capabilityProvenance
}

type capabilityProvenance uint8

const (
	capabilityProvenanceUnchecked capabilityProvenance = iota
	capabilityProvenanceExactGET
	capabilityProvenanceImportedBearer
	capabilityProvenanceAuthenticatedBundle
)

// NewCapabilityFromExactGET imports material minted by an in-module,
// provider-specific exact GetObject implementation. The internal parameter is
// deliberately unavailable to external modules; production callers normally
// receive Capability values from s3store.PresignSession instead.
func NewCapabilityFromExactGET(material presignedcap.ExactGET, options CapabilityOptions) (Capability, error) {
	return newCapability(
		material.Key(), material.URL(), material.Headers(), material.ExpiresAt(),
		options, time.Now(), capabilityProvenanceExactGET,
	)
}

// DangerouslyNewUncheckedCapability is an explicit interoperability escape
// hatch for a custom presigner outside this module. It validates transport
// syntax and finite bounds, but cannot prove that rawURL is a GetObject
// request, that claimedExactKey is its target, or that the provider enforces
// expiresAt. Build rejects this value unless its dangerous opt-in is set.
func DangerouslyNewUncheckedCapability(
	claimedExactKey, rawURL string,
	headers http.Header,
	expiresAt time.Time,
	options CapabilityOptions,
) (Capability, error) {
	return newCapability(
		claimedExactKey, rawURL, headers, expiresAt, options, time.Now(),
		capabilityProvenanceUnchecked,
	)
}

func newCapability(
	exactKey, rawURL string,
	headers http.Header,
	expiresAt time.Time,
	options CapabilityOptions,
	now time.Time,
	provenance capabilityProvenance,
) (Capability, error) {
	if !validObjectKey(exactKey) {
		return Capability{}, invalidCapability("claimed exact object key is invalid")
	}
	if expiresAt.IsZero() || !expiresAt.After(now) || expiresAt.Sub(now) > MaximumCapabilityLifetime {
		return Capability{}, invalidCapability("expiry is outside the permitted lifetime")
	}
	parsed, origin, err := validateCapabilityURL(rawURL, options.AllowInsecureLoopback)
	if err != nil {
		return Capability{}, err
	}
	canonicalHeaders, err := validateCapabilityHeaders(headers)
	if err != nil {
		return Capability{}, err
	}
	return Capability{
		rawURL:     parsed.String(),
		headers:    canonicalHeaders,
		expiresAt:  expiresAt.UTC().Round(0),
		origin:     origin,
		exactKey:   exactKey,
		provenance: provenance,
	}, nil
}

// ExpiresAt returns the advertised bearer expiry. Enforcement by the object
// store, rather than this metadata alone, is the access-control boundary.
func (capability Capability) ExpiresAt() time.Time { return capability.expiresAt }

// Configured reports whether the value contains a validated secret URL.
func (capability Capability) Configured() bool { return capability.rawURL != "" }

func (capability Capability) String() string {
	return fmt.Sprintf("presignedshare.Capability{configured:%t,headers:%d,expires_at:%s,secret:redacted}",
		capability.Configured(), len(capability.headers), capability.expiresAt.Format(time.RFC3339Nano))
}

func (capability Capability) GoString() string { return capability.String() }

// MarshalJSON deliberately does not serialize usable bearer material. Bundle
// encoding uses a private wire representation after signing is requested.
func (capability Capability) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Configured bool      `json:"configured"`
		ExpiresAt  time.Time `json:"expires_at,omitempty"`
		Secret     string    `json:"secret"`
	}{
		Configured: capability.Configured(),
		ExpiresAt:  capability.expiresAt,
		Secret:     "redacted",
	})
}

type bearerExport struct {
	Format    int          `json:"format"`
	ExactKey  string       `json:"exact_key"`
	URL       string       `json:"url"`
	Headers   []wireHeader `json:"headers"`
	ExpiresAt time.Time    `json:"expires_at"`
}

// ExportBearer deliberately exports usable bearer authority for out-of-band
// transfer from A to B/C/D. The returned bytes are a secret, may be replayed
// until expiry, and must never be logged or placed in command-line arguments.
// Unlike ordinary Capability JSON, this explicit method includes the URL and
// required signed headers.
func (capability Capability) ExportBearer() ([]byte, error) {
	if !capability.Configured() {
		return nil, invalidCapability("cannot export an unconfigured value")
	}
	if capability.provenance != capabilityProvenanceExactGET && capability.provenance != capabilityProvenanceImportedBearer {
		return nil, invalidCapability("capability lacks verified exact-GET mint provenance")
	}
	return capability.exportBearer()
}

// DangerouslyExportUncheckedBearer exports a capability produced through the
// unchecked constructor. It exists only for explicitly commissioned custom
// presigners; the caller owns proof of exact GetObject scope and real expiry.
func (capability Capability) DangerouslyExportUncheckedBearer() ([]byte, error) {
	if !capability.Configured() || capability.provenance != capabilityProvenanceUnchecked {
		return nil, invalidCapability("capability is not an unchecked configured value")
	}
	return capability.exportBearer()
}

func (capability Capability) exportBearer() ([]byte, error) {
	encoded, err := json.Marshal(bearerExport{
		Format: 1, ExactKey: capability.exactKey, URL: capability.rawURL,
		Headers: headersToWire(capability.headers), ExpiresAt: capability.expiresAt,
	})
	if err != nil || len(encoded) > MaximumBearerExportBytes {
		return nil, invalidCapability("bearer export exceeds its encoding bound")
	}
	return encoded, nil
}

// ParseBearer imports the canonical secret envelope produced by ExportBearer
// and runs the same URL, header, transport, and expiry validation as
// NewCapability. Parse errors never contain the secret input.
func ParseBearer(data []byte, options CapabilityOptions) (Capability, error) {
	if len(data) == 0 || len(data) > MaximumBearerExportBytes {
		return Capability{}, invalidCapability("bearer encoding length is outside the permitted bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire bearerExport
	if err := decoder.Decode(&wire); err != nil {
		return Capability{}, invalidCapability("bearer encoding is malformed")
	}
	if decoder.Decode(&struct{}{}) == nil {
		return Capability{}, invalidCapability("bearer encoding has a trailing JSON value")
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, data) || wire.Format != 1 {
		return Capability{}, invalidCapability("bearer encoding is not canonical")
	}
	headers, err := headersFromWire(wire.Headers)
	if err != nil {
		return Capability{}, invalidCapability("bearer headers are invalid")
	}
	capability, err := newCapability(
		wire.ExactKey, wire.URL, headers, wire.ExpiresAt, options, time.Now(),
		capabilityProvenanceImportedBearer,
	)
	if err != nil {
		return Capability{}, invalidCapability("bearer capability is invalid")
	}
	return capability, nil
}

func invalidCapability(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidCapability, reason)
}

func validateCapabilityURL(rawURL string, allowInsecureLoopback bool) (*url.URL, string, error) {
	if rawURL == "" || len(rawURL) > MaximumCapabilityURLBytes || !utf8.ValidString(rawURL) {
		return nil, "", invalidCapability("URL length is outside the permitted bound")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.Opaque != "" {
		return nil, "", invalidCapability("URL must be absolute")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return nil, "", invalidCapability("URL userinfo and fragments are forbidden")
	}
	if parsed.Scheme != "https" {
		if parsed.Scheme != "http" || !allowInsecureLoopback || !isLiteralLoopback(parsed.Hostname()) {
			return nil, "", invalidCapability("URL must use HTTPS")
		}
	}
	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" || strings.ContainsAny(hostname, "\x00\r\n") {
		return nil, "", invalidCapability("URL host is invalid")
	}
	for _, character := range hostname {
		if character > 0x7f || character == '%' {
			return nil, "", invalidCapability("URL host is invalid")
		}
	}
	port := parsed.Port()
	if strings.HasSuffix(parsed.Host, ":") {
		return nil, "", invalidCapability("URL port is invalid")
	}
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 || strconv.Itoa(portNumber) != port {
		return nil, "", invalidCapability("URL port is invalid")
	}
	if address := net.ParseIP(hostname); address != nil {
		hostname = address.String()
	}
	origin := parsed.Scheme + "://" + net.JoinHostPort(hostname, port)
	return parsed, origin, nil
}

func isLiteralLoopback(host string) bool {
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

type wireHeader struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

func validateCapabilityHeaders(headers http.Header) (http.Header, error) {
	if len(headers) > MaximumCapabilityHeaders {
		return nil, invalidCapability("too many headers")
	}
	canonical := make(http.Header, len(headers))
	totalBytes := 0
	totalValues := 0
	for name, values := range headers {
		if !validHeaderName(name) {
			return nil, invalidCapability("header name is invalid")
		}
		name = http.CanonicalHeaderKey(name)
		if forbiddenCapabilityHeader(name) {
			return nil, invalidCapability("hop-by-hop or framing header is forbidden")
		}
		if _, duplicate := canonical[name]; duplicate {
			return nil, invalidCapability("duplicate canonical header name")
		}
		if len(values) == 0 {
			return nil, invalidCapability("header has no value")
		}
		totalValues += len(values)
		if totalValues > MaximumCapabilityHeaderValues {
			return nil, invalidCapability("too many header values")
		}
		cloned := make([]string, len(values))
		for index, value := range values {
			if !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
				return nil, invalidCapability("header value is invalid")
			}
			totalBytes += len(name) + len(value)
			if totalBytes > MaximumCapabilityHeaderBytes {
				return nil, invalidCapability("headers exceed the byte bound")
			}
			cloned[index] = value
		}
		canonical[name] = cloned
	}
	return canonical, nil
}

func validHeaderName(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character))) {
			return false
		}
	}
	return true
}

func forbiddenCapabilityHeader(name string) bool {
	switch strings.ToLower(name) {
	case "authorization", "connection", "content-length", "cookie", "host", "if-none-match", "keep-alive",
		"if-match", "if-modified-since", "if-range", "if-unmodified-since", "proxy-authorization", "proxy-connection",
		"range", "set-cookie", "te", "trailer", "transfer-encoding", "upgrade",
		"forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-port", "x-forwarded-prefix",
		"x-forwarded-proto", "x-forwarded-server", "x-forwarded-uri", "x-forwarded-url",
		"x-http-method", "x-http-method-override", "x-method-override", "x-original-method", "x-rewrite-method",
		"x-original-host", "x-original-uri", "x-original-url", "x-rewrite-uri", "x-rewrite-url",
		"x-amz-server-side-encryption-customer-key", "x-amz-server-side-encryption-customer-key-md5":
		return true
	default:
		return false
	}
}

func headersToWire(headers http.Header) []wireHeader {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]wireHeader, 0, len(names))
	for _, name := range names {
		result = append(result, wireHeader{Name: name, Values: append([]string(nil), headers[name]...)})
	}
	return result
}

func headersFromWire(values []wireHeader) (http.Header, error) {
	if len(values) > MaximumCapabilityHeaders {
		return nil, invalidCapability("too many headers")
	}
	headers := make(http.Header, len(values))
	previous := ""
	for _, value := range values {
		if previous != "" && value.Name <= previous {
			return nil, invalidCapability("wire headers are not uniquely sorted")
		}
		previous = value.Name
		headers[value.Name] = append([]string(nil), value.Values...)
	}
	return validateCapabilityHeaders(headers)
}
