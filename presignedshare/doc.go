// Package presignedshare defines the authenticated, strictly bounded wire
// format used to distribute exact S3 GET capabilities through S3 itself.
//
// A capability is a replayable bearer secret until its expiry. The package
// therefore keeps its URL and request headers private and redacts ordinary
// formatting and JSON diagnostics. Bundle bytes intentionally contain those
// secrets and must be transported and stored as secret material.
//
// Client encryption is an opt-in composition, not an implicit property of
// Build or Decode: their signed bundle bytes remain plaintext secret material
// before sealing. When A's Repository and RootPublisher and B's Reader and
// read-only Repository all use the same s3disk strict-share-isolation-v1
// profile, the signed root bundle and every exact object body are ciphertext in
// S3. The profile starts from a random per-share 256-bit key, uses
// domain-separated HKDF-SHA256 with a fresh per-envelope salt, and seals with
// AES-256-GCM and a fresh random nonce. Associated data binds the RepositoryID
// and exact logical/store key. Immutable repository objects use share-keyed
// HMAC-SHA256 physical IDs, preserving lazy reads and S3 deduplication only
// within that share. The private initial handoff gives B this share key but no
// SecretAccessKey, credential provider, or reusable signer; its bearer can
// still expose an access-key ID and temporary session token.
//
// The key is symmetric and per-share, not per-recipient. Any B/C/D holding the
// same handoff can decrypt and create valid AEAD envelopes, so AES-GCM does not
// identify publisher A or support individual recipient revocation. Publisher
// state authenticity comes from signed references/root bundles and logical
// hashes. Products needing recipient-level isolation create separate shares,
// prefixes, keys, roots, and handoffs.
//
// After the initial root-bearer handoff, S3 is the only runtime medium. This
// package does not contact a publisher, provide an HTTP broker, renew a share,
// or grant prefix/list authority. Every bundle entry names one exact object key.
// Production builders use an internally proven exact-GET mint such as
// s3store.PresignSession. An opaque custom provider URL cannot prove its HTTP
// method, exact key, or real service-side expiry and therefore requires the
// explicitly named dangerous interoperability path.
//
// Exact GET signing does not by itself prove that the bucket is private or
// that a gateway rejects unsigned writes and deletes. Commercial deployments
// must separately enforce and review bucket public-access controls and use a
// GetObject-only signing principal scoped to the one commissioned bucket and
// origin. The finite compatibility probe samples those boundaries; it cannot
// infer the complete BPA/IAM policy graph or certify alternate origins.
//
// The default Reader accepts exactly s3disk.Ed25519ReferenceVerifier for local
// signature verification. Custom verifier callbacks require an explicit
// dangerous opt-out and invalidate the S3-only property. Its HTTP transport is
// likewise constructed internally. Every HTTPS reader imports its commissioned
// trust roots from bounded PEM bytes, not from an executable x509.CertPool or a
// platform verifier that may perform auxiliary network fetches. The explicitly
// dangerous system-trust opt-out invalidates the strict S3-only property.
// Provider certification must also inspect raw HTTP/1.1 and HTTP/2 traffic:
// net/http cannot expose every illegal bodyless-response byte, chunk extension,
// or byte beyond declared framing to this package.
//
// Share-key compromise and plaintext already read by B are not revocable.
// DiskCache is downstream of decryption, remains plaintext, and is keyed by
// logical chunk digest rather than share/profile identity; use a separate
// private cache directory for every share. Keep each prefix/profile/key domain
// separate, prohibit convergent encryption, deliver the handoff privately, and
// retain SSE as defense in depth rather than a replacement for client-side
// encryption.
package presignedshare
