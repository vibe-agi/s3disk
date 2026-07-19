package s3store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/presignedshare"
)

func TestPresignSessionProducesOneFixedExpiryCapabilitySet(t *testing.T) {
	t.Parallel()
	const (
		accessKey = "PRESIGN-ACCESS-DO-NOT-LOG"
		secretKey = "presign-secret-do-not-log"
		token     = "presign-token-do-not-log"
	)
	credentialsExpireAt := time.Now().Add(2 * time.Hour)
	store, err := New(context.Background(), Config{
		Bucket: "share-bucket", Region: "us-east-1",
		Endpoint: "http://127.0.0.1:9000", UsePathStyle: true,
		CredentialsProvider: CredentialsProviderFunc(func(context.Context) (Credentials, error) {
			return Credentials{
				AccessKeyID: accessKey, SecretAccessKey: secretKey, SessionToken: token,
				Expires: credentialsExpireAt,
			}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	requestedExpiry := time.Now().UTC().Add(30*time.Minute + 537*time.Millisecond)
	session, err := store.NewPresignSession(context.Background(), requestedExpiry)
	if err != nil {
		t.Fatal(err)
	}
	effectiveExpiry, known := session.AuthorizationExpiry()
	if !known || !effectiveExpiry.Equal(requestedExpiry.UTC().Truncate(time.Second)) {
		t.Fatalf("effective expiry = (%v, %t), want %v", effectiveExpiry, known, requestedExpiry.UTC().Truncate(time.Second))
	}
	rootCapability, err := session.PresignGet(context.Background(), "shares/random-root-bundle")
	if err != nil {
		t.Fatal(err)
	}
	objectKey := "repo/.s3disk/v1/objects/chunk/sha256/aa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	objectCapability, err := session.PresignGet(context.Background(), objectKey)
	if err != nil {
		t.Fatal(err)
	}
	if !rootCapability.ExpiresAt().Equal(effectiveExpiry) || !objectCapability.ExpiresAt().Equal(effectiveExpiry) {
		t.Fatalf("capability expiries = %v and %v, want %v", rootCapability.ExpiresAt(), objectCapability.ExpiresAt(), effectiveExpiry)
	}

	// Building a bundle proves root and object requests use one canonical
	// origin and exactly the same advertised service-side deadline.
	repositoryID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := s3disk.NewEd25519ReferenceSigner(repositoryID, "share", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := s3disk.NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{"share": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	shareID, err := presignedshare.GenerateShareID()
	if err != nil {
		t.Fatal(err)
	}
	commit, err := s3disk.ParseDigest(strings.Repeat("aa", 32))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := presignedshare.Build(context.Background(), presignedshare.BuildInput{
		RootCapability: rootCapability, RootKey: "shares/random-root-bundle", RepositoryPrefix: "repo",
		ReferenceKey: "repo/.s3disk/v1/refs/bWFpbg", ShareID: shareID,
		Revision: 1, ReferenceGeneration: 1, ReferenceCommit: commit,
		Reference: s3disk.Object{
			Data:    []byte(fmt.Sprintf(`{"format":1,"generation":1,"commit":"%s"}`, commit)),
			Version: s3disk.Version{ETag: `"reference"`},
		},
		AuthorizationExpiresAt: effectiveExpiry,
		Capabilities:           []presignedshare.ExactCapability{{Key: objectKey, Capability: objectCapability}},
	}, signer, verifier)
	if err != nil {
		t.Fatalf("Build with one fixed presign session: %v", err)
	}
	if len(encoded) == 0 {
		t.Fatal("Build returned an empty bundle")
	}

	encodedSession, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	valueSession := *session
	encodedValueSession, err := json.Marshal(valueSession)
	if err != nil {
		t.Fatal(err)
	}
	for _, diagnostic := range []string{
		fmt.Sprint(session), fmt.Sprintf("%+v", session), fmt.Sprintf("%#v", session),
		fmt.Sprint(valueSession), fmt.Sprintf("%+v", valueSession), fmt.Sprintf("%#v", valueSession),
		string(encodedSession), string(encodedValueSession),
	} {
		for _, secret := range []string{accessKey, secretKey, token} {
			if strings.Contains(diagnostic, secret) {
				t.Fatalf("presign session diagnostic leaked %q: %s", secret, diagnostic)
			}
		}
		if !strings.Contains(diagnostic, "redacted") {
			t.Fatalf("presign session diagnostic omitted redaction marker: %s", diagnostic)
		}
	}
}

func TestNewPresignSessionRejectsCredentialAndLifetimeMismatch(t *testing.T) {
	t.Parallel()
	var retrievals atomic.Int32
	store, err := New(context.Background(), Config{
		Bucket: "share-bucket", Region: "us-east-1",
		Endpoint: "http://127.0.0.1:9000", UsePathStyle: true,
		CredentialsProvider: CredentialsProviderFunc(func(context.Context) (Credentials, error) {
			retrievals.Add(1)
			return Credentials{
				AccessKeyID: "temporary", SecretAccessKey: "temporary-secret",
				Expires: time.Now().Add(5 * time.Minute),
			}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewPresignSession(context.Background(), time.Now().Add(30*time.Minute)); !errors.Is(err, s3disk.ErrAccessDenied) {
		t.Fatalf("credential lifetime error = %v, want ErrAccessDenied", err)
	}
	if retrievals.Load() == 0 {
		t.Fatal("presign session did not inspect temporary credential expiry")
	}

	retrievals.Store(0)
	if _, err := store.NewPresignSession(context.Background(), time.Now().Add(presignedshare.MaximumCapabilityLifetime+time.Hour)); !errors.Is(err, s3disk.ErrResourceLimit) {
		t.Fatalf("oversized lifetime error = %v, want ErrResourceLimit", err)
	}
	if retrievals.Load() != 0 {
		t.Fatal("invalid lifetime retrieved credentials before failing")
	}

	if _, err := (&Store{}).NewPresignSession(context.Background(), time.Now().Add(time.Hour)); !errors.Is(err, s3disk.ErrStoreMisconfigured) {
		t.Fatalf("unconfigured Store error = %v, want ErrStoreMisconfigured", err)
	}
}

func TestPresignSessionRejectsInvalidExactKey(t *testing.T) {
	t.Parallel()
	store, err := New(context.Background(), Config{
		Bucket: "share-bucket", Region: "us-east-1",
		Endpoint: "http://127.0.0.1:9000", UsePathStyle: true,
		CredentialsProvider: CredentialsProviderFunc(func(context.Context) (Credentials, error) {
			return Credentials{AccessKeyID: "access", SecretAccessKey: "secret"}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.NewPresignSession(context.Background(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"", "bad\x00key", strings.Repeat("x", maxPresignedObjectKeyBytes+1)} {
		if _, err := session.PresignGet(context.Background(), key); !errors.Is(err, s3disk.ErrInvalidPath) {
			t.Errorf("key length %d error = %v, want ErrInvalidPath", len(key), err)
		}
	}
}
