package tlsroots

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParsePEMCertificatesStrictSequence(t *testing.T) {
	t.Parallel()
	certificate := testCertificatePEM(t)
	withoutFinalLF := bytes.TrimSuffix(certificate, []byte{'\n'})
	withEndLineWhitespace := bytes.Replace(
		certificate,
		[]byte("-----END CERTIFICATE-----\n"),
		[]byte("-----END CERTIFICATE----- \t\r\n"),
		1,
	)
	for _, test := range []struct {
		name  string
		input []byte
		count int
	}{
		{name: "single canonical", input: certificate, count: 1},
		{name: "single EOF boundary", input: withoutFinalLF, count: 1},
		{name: "outer ASCII whitespace", input: append(append([]byte(" \t\r\n"), certificate...), []byte(" \t\r\n")...), count: 1},
		{name: "END line whitespace", input: withEndLineWhitespace, count: 1},
		{name: "two certificates", input: append(append([]byte(nil), certificate...), certificate...), count: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := bytes.Clone(test.input)
			original := bytes.Clone(input)
			certificates, err := ParsePEMCertificates(input, 1<<20, 4)
			if err != nil {
				t.Fatal(err)
			}
			if len(certificates) != test.count {
				t.Fatalf("certificate count = %d, want %d", len(certificates), test.count)
			}
			if !bytes.Equal(input, original) {
				t.Fatal("parser mutated caller input")
			}
			firstRaw := bytes.Clone(certificates[0].Raw)
			clear(input)
			if !bytes.Equal(certificates[0].Raw, firstRaw) {
				t.Fatal("returned certificate aliases caller input")
			}
		})
	}
}

func TestParsePEMCertificatesRejectsNonCertificateMaterial(t *testing.T) {
	t.Parallel()
	certificate := testCertificatePEM(t)
	withoutFinalLF := bytes.TrimSuffix(certificate, []byte{'\n'})
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("must-not-be-accepted")})
	headerCertificate := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Headers: map[string]string{"Secret": "must-not-be-accepted"},
		Bytes: testCertificate(t).Raw,
	})
	invalidDER := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")})
	concatenatedDER := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: append(append([]byte(nil), testCertificate(t).Raw...), testCertificate(t).Raw...),
	})
	tests := []struct {
		name  string
		input []byte
		want  error
	}{
		{name: "whitespace only", input: []byte(" \t\r\n"), want: ErrNoCertificates},
		{name: "arbitrary prefix", input: append([]byte("secret\n"), certificate...), want: ErrMalformedPEM},
		{name: "UTF-8 BOM", input: append([]byte{0xef, 0xbb, 0xbf}, certificate...), want: ErrMalformedPEM},
		{name: "NUL prefix", input: append([]byte{0}, certificate...), want: ErrMalformedPEM},
		{name: "arbitrary suffix", input: append(append([]byte(nil), certificate...), []byte("secret")...), want: ErrMalformedPEM},
		{name: "NUL suffix", input: append(append([]byte(nil), certificate...), 0), want: ErrMalformedPEM},
		{name: "arbitrary between blocks", input: append(append(append([]byte(nil), certificate...), []byte("secret\n")...), certificate...), want: ErrMalformedPEM},
		{name: "unclosed leading block", input: append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n"), certificate...), want: ErrMalformedPEM},
		{name: "unclosed trailing block", input: append(append([]byte(nil), certificate...), []byte("-----BEGIN CERTIFICATE-----\ninvalid\n")...), want: ErrMalformedPEM},
		{name: "adjacent same-line blocks", input: append(append([]byte(nil), withoutFinalLF...), certificate...), want: ErrMalformedPEM},
		{name: "spaced same-line blocks", input: append(append(append([]byte(nil), withoutFinalLF...), []byte(" \t")...), certificate...), want: ErrMalformedPEM},
		{name: "bare CR boundary", input: append(append(append([]byte(nil), withoutFinalLF...), '\r'), certificate...), want: ErrMalformedPEM},
		{name: "private key before", input: append(append([]byte(nil), privateKey...), certificate...), want: ErrMalformedPEM},
		{name: "private key after", input: append(append([]byte(nil), certificate...), privateKey...), want: ErrMalformedPEM},
		{name: "TRUSTED CERTIFICATE", input: bytes.Replace(certificate, []byte("CERTIFICATE"), []byte("TRUSTED CERTIFICATE"), 2), want: ErrMalformedPEM},
		{name: "PEM headers", input: headerCertificate, want: ErrMalformedPEM},
		{name: "bad base64", input: []byte("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n"), want: ErrMalformedPEM},
		{name: "invalid DER", input: invalidDER, want: ErrInvalidCertificate},
		{name: "multiple DER certificates in one block", input: concatenatedDER, want: ErrInvalidCertificate},
		{name: "mismatched END", input: []byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END PRIVATE KEY-----\n"), want: ErrMalformedPEM},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParsePEMCertificates(test.input, 1<<20, 4)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if bytes.Contains([]byte(err.Error()), []byte("secret")) {
				t.Fatalf("error disclosed rejected input: %q", err)
			}
		})
	}
}

func TestParsePEMCertificatesLimits(t *testing.T) {
	t.Parallel()
	certificate := testCertificatePEM(t)
	if _, err := ParsePEMCertificates(certificate, len(certificate), 1); err != nil {
		t.Fatalf("exact limits rejected: %v", err)
	}
	if _, err := ParsePEMCertificates(certificate, len(certificate)-1, 1); !errors.Is(err, ErrPEMTooLarge) {
		t.Fatalf("byte-limit error = %v, want ErrPEMTooLarge", err)
	}
	two := append(append([]byte(nil), certificate...), certificate...)
	if _, err := ParsePEMCertificates(two, len(two), 1); !errors.Is(err, ErrTooManyCertificates) {
		t.Fatalf("certificate-limit error = %v, want ErrTooManyCertificates", err)
	}
	if _, err := ParsePEMCertificates(nil, -1, 1); !errors.Is(err, ErrInvalidLimits) {
		t.Fatalf("negative byte-limit error = %v, want ErrInvalidLimits", err)
	}
	if _, err := ParsePEMCertificates(nil, 1, 0); !errors.Is(err, ErrInvalidLimits) {
		t.Fatalf("zero certificate-limit error = %v, want ErrInvalidLimits", err)
	}
}

func FuzzParsePEMCertificatesNeverPanics(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n"))
	f.Add([]byte("secret\n-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"))
	f.Add(testCertificatePEM(f))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		const maximumFuzzBytes = 64 << 10
		if len(encoded) > maximumFuzzBytes+1 {
			encoded = encoded[:maximumFuzzBytes+1]
		}
		_, _ = ParsePEMCertificates(encoded, maximumFuzzBytes, 32)
	})
}

func testCertificatePEM(t testing.TB) []byte {
	t.Helper()
	certificate := testCertificate(t)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if len(encoded) == 0 {
		t.Fatal("test certificate PEM is empty")
	}
	return encoded
}

func testCertificate(t testing.TB) *x509.Certificate {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	return server.Certificate()
}
