package presignedshare

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
)

func TestBuildDecodeCanonicalSignedBundle(t *testing.T) {
	fixture := newBundleFixture(t)
	encoded, err := Build(context.Background(), fixture.input, fixture.signer, fixture.verifier)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) == 0 || encoded[0] != '{' || encoded[len(encoded)-1] != '}' {
		t.Fatalf("Build returned non-canonical envelope framing: %q", encoded)
	}

	bundle, err := Decode(context.Background(), encoded, fixture.verifier, fixture.decodeOptions)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Revision() != fixture.input.Revision || bundle.ReferenceGeneration() != fixture.input.ReferenceGeneration {
		t.Fatalf("decoded revision/generation = %d/%d", bundle.Revision(), bundle.ReferenceGeneration())
	}
	if bundle.ReferenceCommit() != fixture.input.ReferenceCommit {
		t.Fatalf("decoded reference commit = %s, want %s", bundle.ReferenceCommit(), fixture.input.ReferenceCommit)
	}
	if bundle.ShareID() != fixture.input.ShareID || bundle.ReferenceKey() != fixture.input.ReferenceKey || bundle.RepositoryPrefix() != fixture.input.RepositoryPrefix {
		t.Fatal("decoded out-of-band bindings changed")
	}
	if bundle.AuthorizationExpiresAt() != fixture.input.AuthorizationExpiresAt || bundle.CapabilityCount() != 2 {
		t.Fatalf("decoded expiry/count = %v/%d", bundle.AuthorizationExpiresAt(), bundle.CapabilityCount())
	}
	reference := bundle.Reference()
	if !bytes.Equal(reference.Data, fixture.input.Reference.Data) || reference.Version != fixture.input.Reference.Version {
		t.Fatalf("decoded reference = %+v", reference)
	}
	reference.Data[0] ^= 0xff
	if bytes.Equal(reference.Data, bundle.Reference().Data) {
		t.Fatal("Reference accessor aliases retained bundle bytes")
	}

	secretURL := fixture.input.Capabilities[0].Capability.rawURL
	secretHeader := "first-header-secret"
	for _, diagnostic := range []string{
		fmt.Sprint(bundle), fmt.Sprintf("%+v", bundle), fmt.Sprintf("%#v", bundle),
		fmt.Sprint(*bundle), fmt.Sprintf("%+v", *bundle), fmt.Sprintf("%#v", *bundle),
	} {
		if strings.Contains(diagnostic, secretURL) || strings.Contains(diagnostic, secretHeader) || !strings.Contains(diagnostic, "redacted") {
			t.Fatalf("bundle diagnostic leaked or omitted redaction: %s", diagnostic)
		}
	}
	diagnosticJSON, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if bytesContainAny(diagnosticJSON, secretURL, secretHeader) || !strings.Contains(string(diagnosticJSON), "redacted") {
		t.Fatalf("bundle JSON leaked: %s", diagnosticJSON)
	}
}

func TestDecodeRejectsCustomVerifierBeforeCallingIt(t *testing.T) {
	fixture := newBundleFixture(t)
	encoded, err := Build(context.Background(), fixture.input, fixture.signer, fixture.verifier)
	if err != nil {
		t.Fatal(err)
	}
	verifier := &bundleCountingVerifier{Ed25519ReferenceVerifier: fixture.verifier}
	if _, err := Decode(context.Background(), encoded, verifier, fixture.decodeOptions); !errors.Is(err, ErrUntrustedBundle) {
		t.Fatalf("custom verifier error = %v, want ErrUntrustedBundle", err)
	}
	if verifier.calls != 0 {
		t.Fatalf("custom verifier calls = %d, want 0", verifier.calls)
	}

	options := fixture.decodeOptions
	options.DangerouslyAllowCustomReferenceVerifier = true
	if _, err := Decode(context.Background(), encoded, verifier, options); err != nil {
		t.Fatalf("Decode with dangerous custom-verifier opt-out: %v", err)
	}
	if verifier.calls == 0 {
		t.Fatal("dangerous custom-verifier opt-out did not invoke the custom verifier")
	}
}

func TestDecodeRejectsTamperingAndNonCanonicalEncoding(t *testing.T) {
	fixture := newBundleFixture(t)
	encoded, err := Build(context.Background(), fixture.input, fixture.signer, fixture.verifier)
	if err != nil {
		t.Fatal(err)
	}

	tampered := bytes.Replace(encoded, []byte("signature=first-secret"), []byte("signature=other-secret"), 1)
	if bytes.Equal(tampered, encoded) {
		t.Fatal("test did not find bearer URL to tamper")
	}
	_, err = Decode(context.Background(), tampered, fixture.verifier, fixture.decodeOptions)
	if !errors.Is(err, ErrUntrustedBundle) {
		t.Fatalf("tamper error = %v, want ErrUntrustedBundle", err)
	}
	if strings.Contains(err.Error(), "other-secret") || strings.Contains(err.Error(), "first-secret") {
		t.Fatalf("tamper error leaked bearer data: %v", err)
	}

	noncanonical := append([]byte(" \n"), encoded...)
	if _, err := Decode(context.Background(), noncanonical, fixture.verifier, fixture.decodeOptions); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("noncanonical error = %v, want ErrInvalidBundle", err)
	}

	withUnknown := bytes.Replace(encoded, []byte(`{"format":1,`), []byte(`{"format":1,"unknown":true,`), 1)
	if _, err := Decode(context.Background(), withUnknown, fixture.verifier, fixture.decodeOptions); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("unknown field error = %v, want ErrInvalidBundle", err)
	}
}

func TestBuildRejectsDuplicateExactKeysAndDifferentOrigin(t *testing.T) {
	fixture := newBundleFixture(t)
	fixture.input.Capabilities = append(fixture.input.Capabilities, fixture.input.Capabilities[0])
	if _, err := Build(context.Background(), fixture.input, fixture.signer, fixture.verifier); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("duplicate error = %v, want ErrInvalidBundle", err)
	}

	fixture = newBundleFixture(t)
	other, err := newTestCapability(fixture.input.Capabilities[0].Key, "https://other.example.test/bucket/object?signature=secret", nil, fixture.input.AuthorizationExpiresAt, CapabilityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fixture.input.Capabilities[0].Capability = other
	if _, err := Build(context.Background(), fixture.input, fixture.signer, fixture.verifier); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("origin error = %v, want ErrInvalidBundle", err)
	}
}

func TestBuildRequiresMintedExactKeyProvenanceByDefault(t *testing.T) {
	fixture := newBundleFixture(t)
	wrongKey, err := newTestCapability(
		fixture.input.Capabilities[0].Key+"-different",
		fixture.input.Capabilities[0].Capability.rawURL,
		fixture.input.Capabilities[0].Capability.headers,
		fixture.input.AuthorizationExpiresAt,
		CapabilityOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.input.Capabilities[0].Capability = wrongKey
	if _, err := Build(context.Background(), fixture.input, fixture.signer, fixture.verifier); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("mislabeled exact key error = %v, want ErrInvalidBundle", err)
	}

	fixture = newBundleFixture(t)
	uncheckedRoot, err := DangerouslyNewUncheckedCapability(
		fixture.input.RootKey,
		fixture.input.RootCapability.rawURL,
		fixture.input.RootCapability.headers,
		fixture.input.AuthorizationExpiresAt,
		CapabilityOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	uncheckedObject, err := DangerouslyNewUncheckedCapability(
		fixture.input.Capabilities[0].Key,
		fixture.input.Capabilities[0].Capability.rawURL,
		fixture.input.Capabilities[0].Capability.headers,
		fixture.input.AuthorizationExpiresAt,
		CapabilityOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.input.RootCapability = uncheckedRoot
	fixture.input.Capabilities[0].Capability = uncheckedObject
	if _, err := Build(context.Background(), fixture.input, fixture.signer, fixture.verifier); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("unchecked default error = %v, want ErrInvalidBundle", err)
	}
	fixture.input.DangerouslyAllowUncheckedCapabilities = true
	if _, err := Build(context.Background(), fixture.input, fixture.signer, fixture.verifier); err != nil {
		t.Fatalf("explicit unchecked opt-in rejected: %v", err)
	}

	fixture = newBundleFixture(t)
	fixture.input.RootKey += "-different"
	if _, err := Build(context.Background(), fixture.input, fixture.signer, fixture.verifier); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("root exact key mismatch error = %v, want ErrInvalidBundle", err)
	}
}

func TestDecodeRejectsSignedDuplicateAndDifferentOrigin(t *testing.T) {
	fixture := newBundleFixture(t)
	encoded, err := Build(context.Background(), fixture.input, fixture.signer, fixture.verifier)
	if err != nil {
		t.Fatal(err)
	}
	var envelope signedBundle
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal(err)
	}

	t.Run("duplicate", func(t *testing.T) {
		modified := envelope
		modified.Payload.Capabilities = append([]wireExactCapability(nil), envelope.Payload.Capabilities...)
		modified.Payload.Capabilities = append(modified.Payload.Capabilities, modified.Payload.Capabilities[len(modified.Payload.Capabilities)-1])
		resignEnvelope(t, &modified, fixture.signer)
		data, _ := json.Marshal(modified)
		if _, err := Decode(context.Background(), data, fixture.verifier, fixture.decodeOptions); !errors.Is(err, ErrInvalidBundle) {
			t.Fatalf("duplicate decode error = %v, want ErrInvalidBundle", err)
		}
	})

	t.Run("origin", func(t *testing.T) {
		modified := envelope
		modified.Payload.Capabilities = append([]wireExactCapability(nil), envelope.Payload.Capabilities...)
		modified.Payload.Capabilities[0].URL = strings.Replace(modified.Payload.Capabilities[0].URL, "objects.example.test", "other.example.test", 1)
		resignEnvelope(t, &modified, fixture.signer)
		data, _ := json.Marshal(modified)
		if _, err := Decode(context.Background(), data, fixture.verifier, fixture.decodeOptions); !errors.Is(err, ErrInvalidBundle) {
			t.Fatalf("origin decode error = %v, want ErrInvalidBundle", err)
		}
	})
}

func TestBundleTrustAndBindingAreMandatory(t *testing.T) {
	fixture := newBundleFixture(t)
	encoded, err := Build(context.Background(), fixture.input, fixture.signer, fixture.verifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(context.Background(), encoded, nil, fixture.decodeOptions); !errors.Is(err, ErrUntrustedBundle) {
		t.Fatalf("nil verifier error = %v, want ErrUntrustedBundle", err)
	}

	wrongOptions := fixture.decodeOptions
	wrongOptions.ReferenceKey = "repo/.s3disk/v1/refs/another"
	if _, err := Decode(context.Background(), encoded, fixture.verifier, wrongOptions); !errors.Is(err, ErrUntrustedBundle) {
		t.Fatalf("wrong reference error = %v, want ErrUntrustedBundle", err)
	}
	wrongOptions = fixture.decodeOptions
	wrongOptions.ShareID[0] ^= 0xff
	if _, err := Decode(context.Background(), encoded, fixture.verifier, wrongOptions); !errors.Is(err, ErrUntrustedBundle) {
		t.Fatalf("wrong share error = %v, want ErrUntrustedBundle", err)
	}

	otherID, _ := s3disk.GenerateRepositoryID()
	_, otherPrivate, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := s3disk.NewEd25519ReferenceSigner(otherID, "other", otherPrivate)
	otherVerifier, _ := s3disk.NewEd25519ReferenceVerifier(otherID, map[string]ed25519.PublicKey{"other": otherPrivate.Public().(ed25519.PublicKey)})
	if _, err := Build(context.Background(), fixture.input, otherSigner, fixture.verifier); !errors.Is(err, ErrUntrustedBundle) {
		t.Fatalf("mismatched build trust roots error = %v, want ErrUntrustedBundle", err)
	}
	if _, err := Decode(context.Background(), encoded, otherVerifier, fixture.decodeOptions); !errors.Is(err, ErrUntrustedBundle) {
		t.Fatalf("wrong verifier error = %v, want ErrUntrustedBundle", err)
	}
}

func TestBundleSignatureUsesDedicatedDomain(t *testing.T) {
	fixture := newBundleFixture(t)
	encoded, err := Build(context.Background(), fixture.input, fixture.signer, fixture.verifier)
	if err != nil {
		t.Fatal(err)
	}
	var envelope signedBundle
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	// A signature over the canonical payload alone must not verify as a share
	// bundle signature; the dedicated domain and length prefix are mandatory.
	envelope.Signature, err = fixture.signer.Sign(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	wrongDomain, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(context.Background(), wrongDomain, fixture.verifier, fixture.decodeOptions); !errors.Is(err, ErrUntrustedBundle) {
		t.Fatalf("wrong-domain signature error = %v, want ErrUntrustedBundle", err)
	}
}

func TestBundleBoundsAndExpiryCoverage(t *testing.T) {
	fixture := newBundleFixture(t)
	fixture.input.Reference.Data = bytes.Repeat([]byte{'r'}, maximumReferenceBytes+1)
	if _, err := Build(context.Background(), fixture.input, fixture.signer, fixture.verifier); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("reference bound error = %v, want ErrInvalidBundle", err)
	}

	fixture = newBundleFixture(t)
	fixture.input.Capabilities = make([]ExactCapability, MaximumBundleCapabilities+1)
	if _, err := Build(context.Background(), fixture.input, fixture.signer, fixture.verifier); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("capability count error = %v, want ErrInvalidBundle", err)
	}

	fixture = newBundleFixture(t)
	early, err := newTestCapability(fixture.input.Capabilities[0].Key, "https://objects.example.test/bucket/early?signature=secret", nil, fixture.input.AuthorizationExpiresAt.Add(-time.Second), CapabilityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fixture.input.Capabilities[0].Capability = early
	if _, err := Build(context.Background(), fixture.input, fixture.signer, fixture.verifier); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("early capability error = %v, want ErrInvalidBundle", err)
	}

	fixture = newBundleFixture(t)
	fixture.input.Capabilities = nil
	if _, err := Build(context.Background(), fixture.input, fixture.signer, fixture.verifier); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("empty capability set error = %v, want ErrInvalidBundle", err)
	}

	fixture = newBundleFixture(t)
	laterRoot, err := newTestCapability(fixture.input.RootKey, "https://objects.example.test/bucket/random-bundle?signature=later-root", nil, fixture.input.AuthorizationExpiresAt.Add(time.Minute), CapabilityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fixture.input.RootCapability = laterRoot
	if _, err := Build(context.Background(), fixture.input, fixture.signer, fixture.verifier); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("root/share expiry mismatch error = %v, want ErrInvalidBundle", err)
	}
}

func TestBundleReferenceIdentityMustMatchEmbeddedBytes(t *testing.T) {
	fixture := newBundleFixture(t)
	fixture.input.ReferenceGeneration++
	if _, err := Build(context.Background(), fixture.input, fixture.signer, fixture.verifier); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("generation mismatch error = %v, want ErrInvalidBundle", err)
	}
	fixture = newBundleFixture(t)
	fixture.input.ReferenceCommit[0] ^= 0xff
	if _, err := Build(context.Background(), fixture.input, fixture.signer, fixture.verifier); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("commit mismatch error = %v, want ErrInvalidBundle", err)
	}

	fixture = newBundleFixture(t)
	encoded, err := Build(context.Background(), fixture.input, fixture.signer, fixture.verifier)
	if err != nil {
		t.Fatal(err)
	}
	var envelope signedBundle
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Payload.ReferenceCommit[0] ^= 0xff
	resignEnvelope(t, &envelope, fixture.signer)
	tamperedIdentity, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(context.Background(), tamperedIdentity, fixture.verifier, fixture.decodeOptions); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("signed identity mismatch error = %v, want ErrInvalidBundle", err)
	}
}

func TestBundleRequiresCanonicalExactProtocolKeys(t *testing.T) {
	fixture := newBundleFixture(t)
	valid := fixture.input.Capabilities[0].Key
	tests := map[string]string{
		"wrong kind":       strings.Replace(valid, "/objects/file/", "/objects/executable/", 1),
		"wrong algorithm":  strings.Replace(valid, "/sha256/", "/sha1/", 1),
		"uppercase digest": strings.ToUpper(valid),
		"wrong shard":      strings.Replace(valid, "/bb/", "/aa/", 1),
		"extra segment":    valid + "/suffix",
	}
	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			copyFixture := newBundleFixture(t)
			copyFixture.input.Capabilities[0].Key = key
			if _, err := Build(context.Background(), copyFixture.input, copyFixture.signer, copyFixture.verifier); !errors.Is(err, ErrInvalidBundle) {
				t.Fatalf("key error = %v, want ErrInvalidBundle", err)
			}
		})
	}

	for name, key := range map[string]string{
		"empty channel":     "repo/.s3disk/v1/refs/",
		"nested channel":    "repo/.s3disk/v1/refs/bWFpbg/extra",
		"padded base64":     "repo/.s3disk/v1/refs/bWFpbg==",
		"extra signed part": "repo/.s3disk/v1/signed-refs/v1/bWFpbg/extra",
	} {
		t.Run(name, func(t *testing.T) {
			copyFixture := newBundleFixture(t)
			copyFixture.input.ReferenceKey = key
			if _, err := Build(context.Background(), copyFixture.input, copyFixture.signer, copyFixture.verifier); !errors.Is(err, ErrInvalidBundle) {
				t.Fatalf("reference key error = %v, want ErrInvalidBundle", err)
			}
		})
	}
}

func TestBuildAndDecodeHonorCanceledContextBeforeWork(t *testing.T) {
	fixture := newBundleFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Build(ctx, fixture.input, fixture.signer, fixture.verifier); !errors.Is(err, context.Canceled) {
		t.Fatalf("Build error = %v, want context.Canceled", err)
	}
	if _, err := Decode(ctx, []byte("not JSON and must not be parsed"), fixture.verifier, fixture.decodeOptions); !errors.Is(err, context.Canceled) {
		t.Fatalf("Decode error = %v, want context.Canceled", err)
	}
}

func TestShareKeyIDUsesCoreSafeCharacterSet(t *testing.T) {
	for _, keyID := range []string{"with space", "slash/key", "unicode-键", "line\nbreak"} {
		if err := validateKeyID(keyID); !errors.Is(err, ErrUntrustedBundle) {
			t.Fatalf("validateKeyID(%q) = %v, want ErrUntrustedBundle", keyID, err)
		}
	}
	if err := validateKeyID("rotation-2026.07:key_1"); err != nil {
		t.Fatalf("safe key ID rejected: %v", err)
	}
}

func TestCanonicalOriginNormalizesDefaultPort(t *testing.T) {
	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	withoutPort, err := newTestCapability("shares/root", "https://objects.example.test/bucket/root?signature=root", nil, expiry, CapabilityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	withPort, err := newTestCapability("objects/object", "https://objects.example.test:443/bucket/object?signature=object", nil, expiry, CapabilityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if withoutPort.origin != withPort.origin {
		t.Fatalf("origins = %q and %q, want canonical equality", withoutPort.origin, withPort.origin)
	}
}

type bundleFixture struct {
	input         BuildInput
	decodeOptions DecodeOptions
	signer        *s3disk.Ed25519ReferenceSigner
	verifier      *s3disk.Ed25519ReferenceVerifier
}

type bundleCountingVerifier struct {
	*s3disk.Ed25519ReferenceVerifier
	calls int
}

func (verifier *bundleCountingVerifier) RepositoryID() s3disk.RepositoryID {
	verifier.calls++
	return verifier.Ed25519ReferenceVerifier.RepositoryID()
}

func (verifier *bundleCountingVerifier) Verify(ctx context.Context, keyID string, message, signature []byte) error {
	verifier.calls++
	return verifier.Ed25519ReferenceVerifier.Verify(ctx, keyID, message, signature)
}

func newBundleFixture(t *testing.T) bundleFixture {
	t.Helper()
	repositoryID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := s3disk.NewEd25519ReferenceSigner(repositoryID, "share-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := s3disk.NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{"share-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	shareID, err := GenerateShareID()
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)
	const rootKey = "shares/random-bundle"
	const firstKey = "repo/.s3disk/v1/objects/chunk/sha256/aa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const secondKey = "repo/.s3disk/v1/objects/file/sha256/bb/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	root, err := newTestCapability(rootKey, "https://objects.example.test/bucket/random-bundle?X-Amz-Signature=root-secret", nil, expiry, CapabilityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := newTestCapability(firstKey, "https://objects.example.test/bucket/one?signature=first-secret", http.Header{"X-Capability-Signature": {"first-header-secret"}}, expiry, CapabilityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := newTestCapability(secondKey, "https://objects.example.test/bucket/two?signature=second-secret", nil, expiry, CapabilityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	commit, err := s3disk.ParseDigest(strings.Repeat("7a", 32))
	if err != nil {
		t.Fatal(err)
	}
	input := BuildInput{
		RootCapability: root, RootKey: rootKey, RepositoryPrefix: "repo", ReferenceKey: "repo/.s3disk/v1/refs/bWFpbg",
		ShareID: shareID, Revision: 9, ReferenceGeneration: 7, ReferenceCommit: commit,
		Reference:              s3disk.Object{Data: []byte(fmt.Sprintf(`{"format":1,"generation":7,"commit":"%s"}`, commit)), Version: s3disk.Version{ETag: `"reference-etag"`, VersionID: "version-7"}},
		AuthorizationExpiresAt: expiry,
		Capabilities: []ExactCapability{
			{Key: secondKey, Capability: second},
			{Key: firstKey, Capability: first},
		},
	}
	return bundleFixture{
		input: input, signer: signer, verifier: verifier,
		decodeOptions: DecodeOptions{RootCapability: root, RepositoryPrefix: input.RepositoryPrefix, ReferenceKey: input.ReferenceKey, ShareID: shareID},
	}
}

func resignEnvelope(t *testing.T, envelope *signedBundle, signer s3disk.ReferenceSigner) {
	t.Helper()
	payload, err := json.Marshal(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(context.Background(), bundleSigningMessage(payload))
	if err != nil {
		t.Fatal(err)
	}
	envelope.Signature = signature
}
