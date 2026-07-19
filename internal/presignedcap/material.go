// Package presignedcap carries in-module provenance from a reviewed S3
// GetObject presigner into presignedshare. The Go internal-package boundary
// prevents external callers from manufacturing this marker through the public
// wire-format API.
package presignedcap

import (
	"net/http"
	"time"
)

// ExactGET is material produced after an in-module adapter has invoked its
// SDK's exact-key GetObject presigner and verified the effective expiry. Its
// fields are private so only constructors in this internal package can create
// a nonzero value.
type ExactGET struct {
	key       string
	rawURL    string
	headers   http.Header
	expiresAt time.Time
}

// NewExactGET records the result of a reviewed exact GetObject presign path.
// It does not replace wire validation; presignedshare validates and copies the
// material again at its trust boundary.
func NewExactGET(key, rawURL string, headers http.Header, expiresAt time.Time) ExactGET {
	return ExactGET{
		key:       key,
		rawURL:    rawURL,
		headers:   headers.Clone(),
		expiresAt: expiresAt,
	}
}

func (material ExactGET) Key() string          { return material.key }
func (material ExactGET) URL() string          { return material.rawURL }
func (material ExactGET) Headers() http.Header { return material.headers.Clone() }
func (material ExactGET) ExpiresAt() time.Time { return material.expiresAt }
