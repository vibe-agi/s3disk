// Package tlsroots implements the shared, strict TLS trust-root parser used by
// the CLI, the credential-free Reader, and S3 commissioning probes.
package tlsroots

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

var (
	// ErrInvalidLimits reports an invalid internal resource-bound configuration.
	ErrInvalidLimits = errors.New("tlsroots: invalid parser limits")
	// ErrPEMTooLarge reports input beyond the configured byte limit.
	ErrPEMTooLarge = errors.New("tlsroots: PEM exceeds the byte limit")
	// ErrMalformedPEM reports syntax or non-certificate material.
	ErrMalformedPEM = errors.New("tlsroots: PEM is malformed")
	// ErrTooManyCertificates reports input beyond the certificate-count limit.
	ErrTooManyCertificates = errors.New("tlsroots: PEM contains too many certificates")
	// ErrInvalidCertificate reports a syntactically valid block with invalid DER.
	ErrInvalidCertificate = errors.New("tlsroots: PEM contains an invalid certificate")
	// ErrNoCertificates reports non-empty input containing only permitted whitespace.
	ErrNoCertificates = errors.New("tlsroots: PEM contains no certificates")
)

const (
	certificateBeginMarker = "-----BEGIN CERTIFICATE-----"
	certificateEndMarker   = "-----END CERTIFICATE-----"
)

// ParsePEMCertificates parses a complete sequence of headerless CERTIFICATE
// PEM blocks. Leading whitespace may contain only space, horizontal tab, CR,
// or LF. Every END boundary must reach EOF after optional space/horizontal tab,
// or terminate with LF/CRLF on a line containing no other bytes; further ASCII
// whitespace and blocks may then follow. An empty input means that no explicit
// roots were configured; a non-empty whitespace-only input is an error. The
// returned certificates never alias encoded.
func ParsePEMCertificates(encoded []byte, maximumBytes, maximumCertificates int) ([]*x509.Certificate, error) {
	if maximumBytes < 0 || maximumCertificates < 1 {
		return nil, ErrInvalidLimits
	}
	if len(encoded) == 0 {
		return nil, nil
	}
	if len(encoded) > maximumBytes {
		return nil, ErrPEMTooLarge
	}

	working := bytes.Clone(encoded)
	defer clear(working)
	remaining := working
	certificates := make([]*x509.Certificate, 0, min(maximumCertificates, 16))
	for {
		remaining = trimLeftASCIIWhitespace(remaining)
		if len(remaining) == 0 {
			break
		}
		if !bytes.HasPrefix(remaining, []byte(certificateBeginMarker)) {
			return nil, ErrMalformedPEM
		}

		endOffset := bytes.Index(remaining, []byte(certificateEndMarker))
		if endOffset < len(certificateBeginMarker) || bytes.Contains(
			remaining[len(certificateBeginMarker):endOffset],
			[]byte("-----BEGIN "),
		) {
			return nil, ErrMalformedPEM
		}
		candidateEnd := endOffset + len(certificateEndMarker)
		block, rest := pem.Decode(remaining[:candidateEnd])
		if block == nil || len(rest) != 0 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			if block != nil {
				clear(block.Bytes)
			}
			return nil, ErrMalformedPEM
		}
		if len(certificates) == maximumCertificates {
			clear(block.Bytes)
			return nil, ErrTooManyCertificates
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			clear(block.Bytes)
			return nil, ErrInvalidCertificate
		}
		certificates = append(certificates, certificate)

		consumed, ok := consumeCertificateEndLine(remaining[candidateEnd:])
		if !ok {
			return nil, ErrMalformedPEM
		}
		remaining = remaining[candidateEnd+consumed:]
	}
	if len(certificates) == 0 {
		return nil, ErrNoCertificates
	}
	return certificates, nil
}

func trimLeftASCIIWhitespace(value []byte) []byte {
	for len(value) > 0 {
		switch value[0] {
		case ' ', '\t', '\r', '\n':
			value = value[1:]
		default:
			return value
		}
	}
	return value
}

// consumeCertificateEndLine returns bytes through the optional line ending.
// Spaces and horizontal tabs are permitted after the END marker, but another
// PEM boundary on that same line is not.
func consumeCertificateEndLine(value []byte) (int, bool) {
	offset := 0
	for offset < len(value) && (value[offset] == ' ' || value[offset] == '\t') {
		offset++
	}
	if offset == len(value) {
		return offset, true
	}
	switch value[offset] {
	case '\n':
		return offset + 1, true
	case '\r':
		if offset+1 < len(value) && value[offset+1] == '\n' {
			return offset + 2, true
		}
	}
	return 0, false
}
