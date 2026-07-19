package presignedshare

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCapabilityRedactsEveryOrdinaryDiagnosticEncoding(t *testing.T) {
	secretURL := "https://objects.example.test/bucket/key?X-Amz-Signature=top-secret-signature"
	secretHeader := "secret-session-token"
	capability, err := newTestCapability("test-object", secretURL, http.Header{"X-Capability-Signature": {secretHeader}}, time.Now().Add(time.Hour), CapabilityOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for name, encoded := range map[string]string{
		"String":   fmt.Sprint(capability),
		"verbose":  fmt.Sprintf("%+v", capability),
		"GoString": fmt.Sprintf("%#v", capability),
	} {
		if strings.Contains(encoded, secretURL) || strings.Contains(encoded, "top-secret-signature") || strings.Contains(encoded, secretHeader) {
			t.Fatalf("%s leaked bearer material: %s", name, encoded)
		}
		if !strings.Contains(encoded, "redacted") {
			t.Fatalf("%s = %q, want an explicit redaction marker", name, encoded)
		}
	}
	encoded, err := json.Marshal(capability)
	if err != nil {
		t.Fatal(err)
	}
	if bytesContainAny(encoded, secretURL, "top-secret-signature", secretHeader) || !strings.Contains(string(encoded), "redacted") {
		t.Fatalf("JSON did not redact capability: %s", encoded)
	}
}

func TestNewCapabilityValidatesTransportBounds(t *testing.T) {
	future := time.Now().Add(time.Hour)
	tests := []struct {
		name    string
		rawURL  string
		headers http.Header
		expires time.Time
		options CapabilityOptions
	}{
		{name: "plain HTTP", rawURL: "http://objects.example.test/key", expires: future},
		{name: "loopback HTTP needs opt in", rawURL: "http://127.0.0.1:9000/key", expires: future},
		{name: "userinfo", rawURL: "https://user:pass@objects.example.test/key", expires: future},
		{name: "fragment", rawURL: "https://objects.example.test/key#secret", expires: future},
		{name: "invalid port", rawURL: "https://objects.example.test:70000/key", expires: future},
		{name: "ambiguous unicode host", rawURL: "https://café.example.test/key", expires: future},
		{name: "oversized URL", rawURL: "https://objects.example.test/" + strings.Repeat("x", MaximumCapabilityURLBytes), expires: future},
		{name: "expired", rawURL: "https://objects.example.test/key", expires: time.Now().Add(-time.Second)},
		{name: "lifetime too long", rawURL: "https://objects.example.test/key", expires: time.Now().Add(MaximumCapabilityLifetime + time.Hour)},
		{name: "header newline", rawURL: "https://objects.example.test/key", headers: http.Header{"X-Test": {"safe\r\nInjected: yes"}}, expires: future},
		{name: "framing header", rawURL: "https://objects.example.test/key", headers: http.Header{"Host": {"other.example.test"}}, expires: future},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := newTestCapability("test-object", test.rawURL, test.headers, test.expires, test.options)
			if !errors.Is(err, ErrInvalidCapability) {
				t.Fatalf("error = %v, want ErrInvalidCapability", err)
			}
			if err != nil && strings.Contains(err.Error(), test.rawURL) {
				t.Fatalf("error leaked URL: %v", err)
			}
		})
	}

	if _, err := newTestCapability("test-object", "http://127.0.0.1:9000/key?secret=yes", nil, future, CapabilityOptions{AllowInsecureLoopback: true}); err != nil {
		t.Fatalf("explicit loopback HTTP capability rejected: %v", err)
	}
	if _, err := newTestCapability("test-object", "http://localhost:9000/key", nil, future, CapabilityOptions{AllowInsecureLoopback: true}); !errors.Is(err, ErrInvalidCapability) {
		t.Fatalf("DNS-name loopback error = %v, want ErrInvalidCapability", err)
	}
	if _, err := newTestCapability("test-object", "http://192.0.2.10:9000/key", nil, future, CapabilityOptions{AllowInsecureLoopback: true}); !errors.Is(err, ErrInvalidCapability) {
		t.Fatalf("non-loopback HTTP error = %v, want ErrInvalidCapability", err)
	}
	manyHeaders := make(http.Header, MaximumCapabilityHeaders+1)
	for index := 0; index <= MaximumCapabilityHeaders; index++ {
		manyHeaders[fmt.Sprintf("X-Test-%d", index)] = []string{"value"}
	}
	if _, err := newTestCapability("test-object", "https://objects.example.test/key", manyHeaders, future, CapabilityOptions{}); !errors.Is(err, ErrInvalidCapability) {
		t.Fatalf("header count error = %v, want ErrInvalidCapability", err)
	}
	for _, name := range []string{
		"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "If-None-Match", "If-Match",
		"If-Modified-Since", "If-Unmodified-Since", "If-Range", "Range",
		"X-HTTP-Method", "X-HTTP-Method-Override", "X-Method-Override", "X-Original-Method", "X-Rewrite-Method",
		"Forwarded", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Uri", "X-Forwarded-Url",
		"X-Original-Host", "X-Original-Uri", "X-Original-Url", "X-Rewrite-Uri", "X-Rewrite-Url",
		"X-Amz-Server-Side-Encryption-Customer-Key",
	} {
		if _, err := newTestCapability("test-object", "https://objects.example.test/key", http.Header{name: {"secret"}}, future, CapabilityOptions{}); !errors.Is(err, ErrInvalidCapability) {
			t.Fatalf("forbidden header %q error = %v, want ErrInvalidCapability", name, err)
		}
	}
	if _, err := newTestCapability("test-object", "https://objects.example.test/key", http.Header{
		"X-Amz-Security-Token": {"temporary-bearer-component"},
	}, future, CapabilityOptions{}); err != nil {
		t.Fatalf("signed temporary-token header rejected: %v", err)
	}
}

func TestCapabilityDefensivelyCopiesHeaders(t *testing.T) {
	headers := http.Header{"X-Test": {"original"}}
	capability, err := newTestCapability("test-object", "https://objects.example.test/key?signature=secret", headers, time.Now().Add(time.Hour), CapabilityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	headers["X-Test"][0] = "mutated"
	headers.Set("X-Added", "mutated")
	if got := capability.headers.Get("X-Test"); got != "original" {
		t.Fatalf("retained header = %q, want defensive copy", got)
	}
	if got := capability.headers.Get("X-Added"); got != "" {
		t.Fatalf("retained added header = %q", got)
	}
}

func TestCapabilityBearerExportRoundTripIsExplicitAndCanonical(t *testing.T) {
	secretURL := "https://objects.example.test/bucket/root?X-Amz-Signature=export-secret"
	capability, err := newTestCapability("shares/root", secretURL, http.Header{
		"X-Capability-Signature": {"signed-header-secret"},
		"X-Test":                 {"one", "two"},
	}, time.Now().Add(time.Hour).UTC().Truncate(time.Second), CapabilityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	exported, err := capability.ExportBearer()
	if err != nil {
		t.Fatal(err)
	}
	if !bytesContainAny(exported, "export-secret", "signed-header-secret") {
		t.Fatalf("explicit bearer export omitted usable authority: %s", exported)
	}
	parsed, err := ParseBearer(exported, CapabilityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.rawURL != capability.rawURL || parsed.expiresAt != capability.expiresAt ||
		parsed.exactKey != capability.exactKey || fmt.Sprint(parsed.headers) != fmt.Sprint(capability.headers) {
		t.Fatalf("parsed capability differs: got secret metadata lengths %d/%d", len(parsed.rawURL), len(parsed.headers))
	}

	ordinaryJSON, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	for _, diagnostic := range [][]byte{ordinaryJSON, []byte(fmt.Sprint(parsed)), []byte(fmt.Sprintf("%#v", parsed))} {
		if bytesContainAny(diagnostic, "export-secret", "signed-header-secret") {
			t.Fatalf("ordinary diagnostic leaked imported bearer: %s", diagnostic)
		}
	}
	if _, err := ParseBearer(append([]byte(" "), exported...), CapabilityOptions{}); !errors.Is(err, ErrInvalidCapability) {
		t.Fatalf("noncanonical bearer error = %v, want ErrInvalidCapability", err)
	}
	tampered := bytes.Replace(exported, []byte("https://"), []byte("http://"), 1)
	if _, err := ParseBearer(tampered, CapabilityOptions{}); !errors.Is(err, ErrInvalidCapability) || strings.Contains(err.Error(), "export-secret") {
		t.Fatalf("tampered bearer error = %v", err)
	}
}

func TestUncheckedCapabilityRequiresExplicitDangerousExport(t *testing.T) {
	capability, err := DangerouslyNewUncheckedCapability(
		"shares/custom-root",
		"https://custom.example.test/root?opaque-bearer=secret",
		nil,
		time.Now().Add(time.Hour),
		CapabilityOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := capability.ExportBearer(); !errors.Is(err, ErrInvalidCapability) {
		t.Fatalf("ordinary export error = %v, want ErrInvalidCapability", err)
	}
	exported, err := capability.DangerouslyExportUncheckedBearer()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseBearer(exported, CapabilityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.exactKey != "shares/custom-root" || parsed.provenance != capabilityProvenanceImportedBearer {
		t.Fatalf("parsed unchecked bearer binding = %q/%d", parsed.exactKey, parsed.provenance)
	}
}

func bytesContainAny(data []byte, values ...string) bool {
	for _, value := range values {
		if strings.Contains(string(data), value) {
			return true
		}
	}
	return false
}

func newTestCapability(
	exactKey, rawURL string,
	headers http.Header,
	expiresAt time.Time,
	options CapabilityOptions,
) (Capability, error) {
	return newCapability(
		exactKey, rawURL, headers, expiresAt, options, time.Now(),
		capabilityProvenanceExactGET,
	)
}
