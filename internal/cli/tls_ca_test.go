package cli

import (
	"bytes"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vibe-agi/s3disk/presignedshare"
)

func TestCanonicalTLSRootCAPEMRejectsHiddenNonCertificateMaterial(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if len(certificate) == 0 {
		t.Fatal("test certificate PEM is empty")
	}

	t.Run("canonical certificate", func(t *testing.T) {
		input := append([]byte(" \n\t"), certificate...)
		input = append(input, '\n')
		canonical, err := canonicalTLSRootCAPEM(input)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(canonical, certificate) {
			t.Fatalf("canonical PEM differs: %q", canonical)
		}
	})

	for _, test := range []struct {
		name           string
		prefix, suffix []byte
	}{
		{name: "private key", suffix: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("AWS_SECRET_ACCESS_KEY=must-not-persist")})},
		{name: "arbitrary leading secret", prefix: []byte("AWS_SECRET_ACCESS_KEY=must-not-persist\n")},
		{name: "unclosed leading certificate", prefix: []byte("-----BEGIN CERTIFICATE-----\ninvalid\n")},
		{name: "arbitrary trailing secret", suffix: []byte("AWS_SECRET_ACCESS_KEY=must-not-persist\n")},
		{name: "certificate headers", suffix: pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Headers: map[string]string{"Secret": "must-not-persist"}, Bytes: server.Certificate().Raw,
		})},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := append(append([]byte(nil), test.prefix...), certificate...)
			input = append(input, test.suffix...)
			canonical, err := canonicalTLSRootCAPEM(input)
			clear(canonical)
			if err == nil {
				t.Fatal("certificate bundle accepted hidden non-certificate material")
			}
		})
	}

	t.Run("certificate count", func(t *testing.T) {
		input := bytes.Repeat(certificate, presignedshare.MaximumTLSRootCertificates+1)
		canonical, err := canonicalTLSRootCAPEM(input)
		clear(canonical)
		if err == nil {
			t.Fatal("certificate bundle exceeded the Reader certificate-count limit")
		}
	})
}
