package s3disk_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestClientEncryptionProfileRoundTripBindingAndRedaction(t *testing.T) {
	repositoryID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	key, err := s3disk.GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	secret := key.ExportSecret()
	if secret == "" {
		t.Fatal("generated key exported an empty secret")
	}
	parsed, err := s3disk.ParseClientEncryptionKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ExportSecret() != secret {
		t.Fatal("parsed key did not preserve its canonical secret")
	}
	profile, err := s3disk.NewClientEncryptionProfile(repositoryID, parsed)
	if err != nil {
		t.Fatal(err)
	}

	const objectKey = "private/share/.s3disk/v1/objects/chunk/hmac-sha256/aa/example"
	plaintext := []byte("customer plaintext must not appear in S3")
	first, err := profile.SealObject(objectKey, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	second, err := profile.SealObject(objectKey, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two encryptions reused the complete ciphertext envelope")
	}
	if got, want := int64(len(first)), int64(len(plaintext))+s3disk.ClientEncryptionCiphertextOverhead; got != want {
		t.Fatalf("ciphertext bytes = %d, want fixed envelope size %d", got, want)
	}
	if bytes.Contains(first, plaintext) || bytes.Contains(second, plaintext) {
		t.Fatal("ciphertext envelope contains plaintext")
	}
	opened, err := profile.OpenObject(objectKey, first)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened plaintext = %q", opened)
	}
	opened[0] ^= 0xff
	again, err := profile.OpenObject(objectKey, first)
	if err != nil || !bytes.Equal(again, plaintext) {
		t.Fatal("OpenObject returned aliased or unstable plaintext")
	}
	if _, err := profile.OpenObject(objectKey+"-other", first); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("wrong logical key error = %v, want ErrCorruptObject", err)
	}
	tampered := append([]byte(nil), first...)
	tampered[len(tampered)-1] ^= 1
	if _, err := profile.OpenObject(objectKey, tampered); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("tamper error = %v, want ErrCorruptObject", err)
	}
	for name, invalid := range map[string][]byte{
		"header":    append([]byte(nil), first...),
		"kdf-salt":  append([]byte(nil), first...),
		"truncated": append([]byte(nil), first[:len(first)-1]...),
	} {
		switch name {
		case "header":
			invalid[0] ^= 1
		case "kdf-salt":
			invalid[8] ^= 1
		}
		if _, err := profile.OpenObject(objectKey, invalid); !errors.Is(err, s3disk.ErrCorruptObject) {
			t.Fatalf("%s envelope error = %v, want ErrCorruptObject", name, err)
		}
	}
	otherKey, err := s3disk.GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	otherProfile, err := s3disk.NewClientEncryptionProfile(repositoryID, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherProfile.OpenObject(objectKey, first); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("wrong share key error = %v, want ErrCorruptObject", err)
	}

	encodedProfile, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, diagnostic := range []string{
		fmt.Sprint(key), fmt.Sprintf("%#v", key), string(mustJSON(t, key)),
		fmt.Sprint(profile), fmt.Sprintf("%#v", profile), string(encodedProfile),
	} {
		if strings.Contains(diagnostic, secret) || strings.Contains(diagnostic, string(plaintext)) {
			t.Fatalf("encryption diagnostic leaked secret material: %s", diagnostic)
		}
	}
}

func TestClientEncryptionZeroValueDiagnosticsRemainRedacted(t *testing.T) {
	var key s3disk.ClientEncryptionKey
	var profile s3disk.ClientEncryptionProfile
	var store s3disk.ClientEncryptedStore
	for _, value := range []any{key, profile, store} {
		for _, diagnostic := range []string{fmt.Sprint(value), fmt.Sprintf("%#v", value), string(mustJSON(t, value))} {
			if !strings.Contains(diagnostic, "redacted") {
				t.Fatalf("zero-value diagnostic is not redacted: %s", diagnostic)
			}
		}
	}
}

func TestClientEncryptedStorePreservesCASAndPlaintextBounds(t *testing.T) {
	ctx := context.Background()
	base := memstore.New()
	repositoryID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	key, err := s3disk.GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := s3disk.NewClientEncryptionProfile(repositoryID, key)
	if err != nil {
		t.Fatal(err)
	}
	store, err := s3disk.NewClientEncryptedStore(base, profile)
	if err != nil {
		t.Fatal(err)
	}

	const objectKey = "isolated-share/root"
	v1 := []byte("encrypted generation one")
	version1, err := store.PutIfAbsent(ctx, objectKey, v1)
	if err != nil {
		t.Fatal(err)
	}
	raw1, err := base.Get(ctx, objectKey, s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if raw1.Version != version1 || bytes.Equal(raw1.Data, v1) || bytes.Contains(raw1.Data, v1) {
		t.Fatalf("raw stored object was not an opaque envelope: version=%+v bytes=%q", raw1.Version, raw1.Data)
	}
	observed1, err := store.Get(ctx, objectKey, s3disk.GetOptions{MaxBytes: int64(len(v1))})
	if err != nil {
		t.Fatal(err)
	}
	if observed1.Version != version1 || !bytes.Equal(observed1.Data, v1) {
		t.Fatalf("decrypted v1 = %+v %q", observed1.Version, observed1.Data)
	}
	if _, err := store.Get(ctx, objectKey, s3disk.GetOptions{MaxBytes: int64(len(v1) - 1)}); !errors.Is(err, s3disk.ErrResourceLimit) {
		t.Fatalf("small plaintext limit error = %v, want ErrResourceLimit", err)
	}
	if _, err := store.Get(ctx, objectKey, s3disk.GetOptions{IfNoneMatch: version1.ETag}); !errors.Is(err, s3disk.ErrNotModified) {
		t.Fatalf("conditional encrypted GET error = %v, want ErrNotModified", err)
	}

	v2 := []byte("encrypted generation two")
	version2, err := store.CompareAndSwap(ctx, objectKey, &version1, v2)
	if err != nil {
		t.Fatal(err)
	}
	if version2.ETag == version1.ETag {
		t.Fatal("encrypted replacement did not change the backing ETag")
	}
	if _, err := store.CompareAndSwap(ctx, objectKey, &version1, []byte("stale")); !errors.Is(err, s3disk.ErrPrecondition) {
		t.Fatalf("stale encrypted CAS error = %v, want ErrPrecondition", err)
	}
	observed2, err := store.Get(ctx, objectKey, s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if observed2.Version != version2 || !bytes.Equal(observed2.Data, v2) {
		t.Fatalf("decrypted v2 = %+v %q", observed2.Version, observed2.Data)
	}
	if head, err := store.Head(ctx, objectKey); err != nil || head != version2 {
		t.Fatalf("encrypted HEAD = %+v, %v", head, err)
	}

	wrongKey, err := s3disk.GenerateClientEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	wrongProfile, err := s3disk.NewClientEncryptionProfile(repositoryID, wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s3disk.NewClientEncryptedStore(store, wrongProfile); !errors.Is(err, s3disk.ErrStoreMisconfigured) {
		t.Fatalf("different-profile nested encrypted Store error = %v, want ErrStoreMisconfigured", err)
	}
	wrongStore, err := s3disk.NewClientEncryptedStore(base, wrongProfile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongStore.Get(ctx, objectKey, s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("wrong-key encrypted Store error = %v, want ErrCorruptObject", err)
	}
	if strings.Contains(fmt.Sprint(store), key.ExportSecret()) || strings.Contains(fmt.Sprintf("%#v", store), key.ExportSecret()) {
		t.Fatal("encrypted Store diagnostic leaked its share key")
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
