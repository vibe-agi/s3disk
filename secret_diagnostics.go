package s3disk

import (
	"encoding/json"
	"fmt"
)

// String deliberately excludes the in-process Ed25519 private key. The key ID
// and repository ID are also omitted so ordinary diagnostics remain suitable
// for a customer-data-minimizing default telemetry path.
func (signer Ed25519ReferenceSigner) String() string {
	return fmt.Sprintf(
		"s3disk.Ed25519ReferenceSigner{configured:%t,secrets:redacted}",
		!signer.repositoryID.IsZero() && signer.keyID != "" && len(signer.privateKey) > 0,
	)
}

func (signer Ed25519ReferenceSigner) GoString() string { return signer.String() }

func (signer Ed25519ReferenceSigner) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Configured bool   `json:"configured"`
		Secrets    string `json:"secrets"`
	}{
		Configured: !signer.repositoryID.IsZero() && signer.keyID != "" && len(signer.privateKey) > 0,
		Secrets:    "redacted",
	})
}

// String bounds and redacts the verifier keyring. Public verification keys are
// not signing secrets, but dumping a complete tenant trust configuration is
// still inappropriate in ordinary diagnostics.
func (verifier Ed25519ReferenceVerifier) String() string {
	return fmt.Sprintf(
		"s3disk.Ed25519ReferenceVerifier{configured:%t,keys:%d,secrets:redacted}",
		!verifier.repositoryID.IsZero() && len(verifier.publicKeys) > 0,
		len(verifier.publicKeys),
	)
}

func (verifier Ed25519ReferenceVerifier) GoString() string { return verifier.String() }

func (verifier Ed25519ReferenceVerifier) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Configured bool   `json:"configured"`
		Keys       int    `json:"keys"`
		Secrets    string `json:"secrets"`
	}{
		Configured: !verifier.repositoryID.IsZero() && len(verifier.publicKeys) > 0,
		Keys:       len(verifier.publicKeys),
		Secrets:    "redacted",
	})
}

// String prevents Publisher's duplicated signer/options fields from being
// recursively formatted. It intentionally omits repository prefix, trust
// identities, journal state, checkpoint values, and source metadata.
func (publisher Publisher) String() string {
	return fmt.Sprintf(
		"s3disk.Publisher{configured:%t,signed_references:%t,publication_journal:%t,trusted_checkpoint:%t,secrets:redacted}",
		publisher.repository != nil,
		interfaceDependencyConfigured(publisher.referenceSigner) && interfaceDependencyConfigured(publisher.referenceVerifier),
		interfaceDependencyConfigured(publisher.publicationJournal),
		publisher.trustedCheckpoint != nil,
	)
}

func (publisher Publisher) GoString() string { return publisher.String() }

func (publisher Publisher) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Configured         bool   `json:"configured"`
		SignedReferences   bool   `json:"signed_references"`
		PublicationJournal bool   `json:"publication_journal"`
		TrustedCheckpoint  bool   `json:"trusted_checkpoint"`
		Secrets            string `json:"secrets"`
	}{
		Configured:         publisher.repository != nil,
		SignedReferences:   interfaceDependencyConfigured(publisher.referenceSigner) && interfaceDependencyConfigured(publisher.referenceVerifier),
		PublicationJournal: interfaceDependencyConfigured(publisher.publicationJournal),
		TrustedCheckpoint:  publisher.trustedCheckpoint != nil,
		Secrets:            "redacted",
	})
}
