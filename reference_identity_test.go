package s3disk

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestVerifySnapshotReferenceUnsigned(t *testing.T) {
	commit := digestObject("commit", []byte("reference-identity-unsigned"))
	data, err := canonicalJSON(snapshotReference{
		Format: objectFormatVersion, Generation: 7, Commit: commit,
	})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := VerifySnapshotReference(context.Background(), data, "main", nil)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Generation != 7 || identity.Commit != commit || identity.Authenticated || !identity.RepositoryID.IsZero() {
		t.Fatalf("identity = %+v", identity)
	}
}

func TestVerifySnapshotReferenceSigned(t *testing.T) {
	repositoryID, signer, verifier := newReferenceIdentityTrust(t)
	commit := digestObject("commit", []byte("reference-identity-signed"))
	data, err := signSnapshotReference(context.Background(), "main", snapshotReference{
		Format: objectFormatVersion, Generation: 9, Commit: commit,
	}, signer, verifier)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := VerifySnapshotReference(context.Background(), data, "main", verifier)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Generation != 9 || identity.Commit != commit || !identity.Authenticated || identity.RepositoryID != repositoryID {
		t.Fatalf("identity = %+v", identity)
	}

	if _, err := VerifySnapshotReference(context.Background(), data, "other", verifier); !errors.Is(err, ErrUntrustedReference) {
		t.Fatalf("channel mismatch error = %v, want ErrUntrustedReference", err)
	}
	tampered := append([]byte(nil), data...)
	tampered[len(tampered)-2] ^= 1
	if _, err := VerifySnapshotReference(context.Background(), tampered, "main", verifier); !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("tampered error = %v, want ErrInvalidReference", err)
	}
	if _, err := VerifySnapshotReference(context.Background(), data, "main", nil); !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("signed without verifier error = %v, want ErrInvalidReference", err)
	}
}

func TestVerifySnapshotReferenceRejectsInvalidInputsBeforeVerification(t *testing.T) {
	_, _, verifier := newReferenceIdentityTrust(t)
	var typedNil *Ed25519ReferenceVerifier
	var typedNilVerifier ReferenceVerifier = typedNil
	tests := []struct {
		name     string
		ctx      context.Context
		data     []byte
		channel  string
		verifier ReferenceVerifier
	}{
		{name: "nil context", data: []byte("{}"), channel: "main"},
		{name: "empty", ctx: context.Background(), channel: "main"},
		{name: "bad channel", ctx: context.Background(), data: []byte("{}"), channel: "../main"},
		{name: "typed nil", ctx: context.Background(), data: []byte("{}"), channel: "main", verifier: typedNilVerifier},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := VerifySnapshotReference(test.ctx, test.data, test.channel, test.verifier); err == nil {
				t.Fatal("VerifySnapshotReference unexpectedly succeeded")
			}
		})
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifySnapshotReference(canceled, []byte("{}"), "main", verifier); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled error = %v", err)
	}
}

func newReferenceIdentityTrust(t *testing.T) (RepositoryID, ReferenceSigner, ReferenceVerifier) {
	t.Helper()
	repositoryID, err := GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewEd25519ReferenceSigner(repositoryID, "reference-identity", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{
		"reference-identity": publicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	return repositoryID, signer, verifier
}
