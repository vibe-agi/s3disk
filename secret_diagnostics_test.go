package s3disk_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestSigningAndPublisherDiagnosticsRedactSecretState(t *testing.T) {
	seed := bytes.Repeat([]byte{0xa7}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	var repositoryID s3disk.RepositoryID
	for index := range repositoryID {
		repositoryID[index] = byte(index + 1)
	}
	const keyID = "tenant-private-key-id-must-not-be-in-default-diagnostics"
	signer, err := s3disk.NewEd25519ReferenceSigner(repositoryID, keyID, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := s3disk.NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{keyID: publicKey})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := s3disk.NewRepository(memstore.New(), "secret-diagnostics-prefix")
	if err != nil {
		t.Fatal(err)
	}
	journal, err := s3disk.NewFilePublicationJournal(filepath.Join(t.TempDir(), "publisher.journal"))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: signer, ReferenceVerifier: verifier,
		PublicationJournal: journal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	privateSliceDiagnostic := fmt.Sprint([]byte(privateKey))
	privateBase64 := base64.StdEncoding.EncodeToString(privateKey)
	publicSliceDiagnostic := fmt.Sprint([]byte(publicKey))
	values := []any{signer, *signer, verifier, *verifier, publisher, *publisher}
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal %T: %v", value, err)
		}
		for _, diagnostic := range []string{
			fmt.Sprint(value),
			fmt.Sprintf("%+v", value),
			fmt.Sprintf("%#v", value),
			string(encoded),
		} {
			if !strings.Contains(diagnostic, "redacted") {
				t.Fatalf("%T diagnostic omitted redaction marker: %s", value, diagnostic)
			}
			for _, secret := range []string{privateSliceDiagnostic, privateBase64, publicSliceDiagnostic, keyID} {
				if strings.Contains(diagnostic, secret) {
					t.Fatalf("%T diagnostic leaked protected signing state: %s", value, diagnostic)
				}
			}
		}
	}
}
