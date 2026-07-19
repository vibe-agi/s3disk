package s3disk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestSignedReferenceGoldenVector(t *testing.T) {
	var repositoryID RepositoryID
	for index := range repositoryID {
		repositoryID[index] = byte(index)
	}
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signer, err := NewEd25519ReferenceSigner(repositoryID, "key-2026", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{"key-2026": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	var commit Digest
	for index := range commit {
		commit[index] = byte(0xa0 + index)
	}
	reference := snapshotReference{Format: objectFormatVersion, Generation: 42, Commit: commit}
	data, err := signSnapshotReference(context.Background(), "release/main", reference, signer, verifier)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"format":1,"reference":{"format":1,"repository_id":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","channel":"release/main","generation":42,"commit":"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf","key_id":"key-2026"},"signature":"1FHEqLFCAyEhItXmxOBeOMVP2CGwaFe4YDCDNwImH6cemsDHqUH2LrLuacTJsSveeI9HXCA+XKO67E8i5RtyBA=="}`
	if string(data) != want {
		t.Fatalf("signed reference golden mismatch\ngot:  %s\nwant: %s", data, want)
	}
	decoded, err := verifySignedSnapshotReference(context.Background(), data, "release/main", verifier)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != reference {
		t.Fatalf("decoded = %+v, want %+v", decoded, reference)
	}
	if _, err := verifySignedSnapshotReference(context.Background(), data, "release/other", verifier); !errors.Is(err, ErrUntrustedReference) {
		t.Fatalf("cross-channel verification error = %v", err)
	}
}

func FuzzVerifySignedReferenceNeverPanics(f *testing.F) {
	var repositoryID RepositoryID
	repositoryID[0] = 1
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	verifier, err := NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{"key": publicKey})
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(`{"format":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxReferenceBytes+1 {
			t.Skip()
		}
		_, _ = verifySignedSnapshotReference(t.Context(), data, "main", verifier)
	})
}
