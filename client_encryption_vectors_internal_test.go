package s3disk

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

const (
	strictShareIsolationVectorKeyHex          = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	strictShareIsolationVectorRepositoryIDHex = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
	strictShareIsolationVectorSaltHex         = "404142434445464748494a4b4c4d4e4f"
	strictShareIsolationVectorNonceHex        = "505152535455565758595a5b"
	strictShareIsolationVectorDigestHex       = "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
	strictShareIsolationVectorPlaintextHex    = "73336469736b207374726963742d73686172652d69736f6c6174696f6e2d763100ff"
	strictShareIsolationVectorObjectKey       = "private/vector/.s3disk/v1/objects/chunk/hmac-sha256/0123456789abcdef"

	// These values are generated once from the independently specified framing
	// below and then frozen. They must never be regenerated through production
	// objectAEAD, objectAssociatedData, or opaqueObjectID helpers.
	strictShareIsolationVectorEnvelopeHex = "7333646365000100404142434445464748494a4b4c4d4e4f505152535455565758595a5be16e697036499dfccd346137a2bb5af482dc1d26e4abc45768846d46a1aa8e7954043a107dea472c2f1cb4bbf901f5eedd0e"
	strictShareIsolationVectorOpaqueID    = "1c03dc885ba8fdb896e9452c7967a14a4b797dc978e99b67a2a90c903e923921"
)

var (
	strictShareIsolationVectorHeader       = []byte{'s', '3', 'd', 'c', 'e', 0, 1, 0}
	strictShareIsolationVectorMasterDomain = []byte("s3disk\x00client-encryption\x00master\x00v1\x00")
	strictShareIsolationVectorIndexDomain  = []byte("s3disk\x00client-encryption\x00index\x00v1\x00")
	strictShareIsolationVectorObjectDomain = []byte("s3disk\x00client-encryption\x00object\x00v1\x00")
)

func TestStrictShareIsolationV1KnownAnswer(t *testing.T) {
	rawKey := decodeVectorHex(t, strictShareIsolationVectorKeyHex)
	repositoryIDBytes := decodeVectorHex(t, strictShareIsolationVectorRepositoryIDHex)
	messageSalt := decodeVectorHex(t, strictShareIsolationVectorSaltHex)
	nonce := decodeVectorHex(t, strictShareIsolationVectorNonceHex)
	plaintext := decodeVectorHex(t, strictShareIsolationVectorPlaintextHex)
	digestBytes := decodeVectorHex(t, strictShareIsolationVectorDigestHex)

	independentEnvelope, independentOpaqueID := constructStrictShareIsolationVector(
		t,
		rawKey,
		repositoryIDBytes,
		messageSalt,
		nonce,
		strictShareIsolationVectorObjectKey,
		plaintext,
		"chunk",
		digestBytes,
	)
	if strictShareIsolationVectorEnvelopeHex == "" || strictShareIsolationVectorOpaqueID == "" {
		t.Fatalf("freeze strict-share-isolation-v1 vectors: envelope=%x opaque=%s", independentEnvelope, independentOpaqueID)
	}
	expectedEnvelope := decodeVectorHex(t, strictShareIsolationVectorEnvelopeHex)
	if !bytes.Equal(independentEnvelope, expectedEnvelope) {
		t.Fatalf("independent AES-GCM envelope = %x, want frozen vector %x", independentEnvelope, expectedEnvelope)
	}
	if independentOpaqueID != strictShareIsolationVectorOpaqueID {
		t.Fatalf("independent opaque ID = %s, want frozen vector %s", independentOpaqueID, strictShareIsolationVectorOpaqueID)
	}
	if got, want := int64(len(expectedEnvelope)), int64(len(plaintext))+ClientEncryptionCiphertextOverhead; got != want {
		t.Fatalf("known-answer envelope bytes = %d, want plaintext plus overhead = %d", got, want)
	}

	profile := strictShareIsolationVectorProfile(t, rawKey)
	opened, err := profile.OpenObject(strictShareIsolationVectorObjectKey, expectedEnvelope)
	if err != nil {
		t.Fatalf("OpenObject(frozen independently constructed envelope): %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("OpenObject plaintext = %x, want %x", opened, plaintext)
	}

	digest, err := ParseDigest(strictShareIsolationVectorDigestHex)
	if err != nil {
		t.Fatal(err)
	}
	if got := profile.opaqueObjectID("chunk", digest); got != strictShareIsolationVectorOpaqueID {
		t.Fatalf("production opaque object ID = %s, want frozen independent vector %s", got, strictShareIsolationVectorOpaqueID)
	}
}

// constructStrictShareIsolationVector deliberately duplicates the documented
// wire framing using only standard cryptographic primitives. Keeping it
// independent of production encryption helpers makes this a true regression
// vector instead of a round-trip test of one implementation.
func constructStrictShareIsolationVector(
	t testing.TB,
	rawKey, repositoryID, messageSalt, nonce []byte,
	objectKey string,
	plaintext []byte,
	kind string,
	digest []byte,
) ([]byte, string) {
	t.Helper()
	if len(rawKey) != 32 || len(repositoryID) != 32 || len(messageSalt) != 16 || len(nonce) != 12 || len(digest) != sha256.Size {
		t.Fatal("invalid strict-share-isolation-v1 vector fixture length")
	}

	encryptionMaster := vectorHKDF(t, rawKey, repositoryID, strictShareIsolationVectorMasterDomain)
	indexKey := vectorHKDF(t, rawKey, repositoryID, strictShareIsolationVectorIndexDomain)

	associatedData := make([]byte, 0, len(strictShareIsolationVectorObjectDomain)+len(repositoryID)+len(messageSalt)+4+len(objectKey))
	associatedData = append(associatedData, strictShareIsolationVectorObjectDomain...)
	associatedData = append(associatedData, repositoryID...)
	associatedData = append(associatedData, messageSalt...)
	var objectKeyLength [4]byte
	binary.BigEndian.PutUint32(objectKeyLength[:], uint32(len(objectKey)))
	associatedData = append(associatedData, objectKeyLength[:]...)
	associatedData = append(associatedData, objectKey...)

	messageKey := vectorHKDF(t, encryptionMaster, messageSalt, associatedData)
	block, err := aes.NewCipher(messageKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	ciphertextAndTag := aead.Seal(nil, nonce, plaintext, associatedData)
	envelope := make([]byte, 0, len(strictShareIsolationVectorHeader)+len(messageSalt)+len(nonce)+len(ciphertextAndTag))
	envelope = append(envelope, strictShareIsolationVectorHeader...)
	envelope = append(envelope, messageSalt...)
	envelope = append(envelope, nonce...)
	envelope = append(envelope, ciphertextAndTag...)

	mac := hmac.New(sha256.New, indexKey)
	_, _ = mac.Write(strictShareIsolationVectorIndexDomain)
	_, _ = mac.Write([]byte(kind))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(digest)
	return envelope, hex.EncodeToString(mac.Sum(nil))
}

func vectorHKDF(t testing.TB, inputKey, salt, info []byte) []byte {
	t.Helper()
	derived, err := hkdf.Key(sha256.New, inputKey, salt, string(info), 32)
	if err != nil {
		t.Fatal(err)
	}
	return derived
}

func strictShareIsolationVectorProfile(t testing.TB, rawKey []byte) *ClientEncryptionProfile {
	t.Helper()
	secret := clientEncryptionSecretPrefix + base64.RawURLEncoding.EncodeToString(rawKey)
	key, err := ParseClientEncryptionKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	repositoryID, err := ParseRepositoryID(strictShareIsolationVectorRepositoryIDHex)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := NewClientEncryptionProfile(repositoryID, key)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func decodeVectorHex(t testing.TB, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode fixed test vector: %v", err)
	}
	return decoded
}

func TestClientEncryptionExactMaximumBoundaries(t *testing.T) {
	if ClientEncryptionMaxPlaintextBytes != 64<<20 {
		t.Fatalf("maximum plaintext bytes = %d, want 64 MiB", ClientEncryptionMaxPlaintextBytes)
	}
	if ClientEncryptionCiphertextOverhead != 52 {
		t.Fatalf("ciphertext overhead = %d, want 52", ClientEncryptionCiphertextOverhead)
	}

	profile := strictShareIsolationVectorProfile(t, decodeVectorHex(t, strictShareIsolationVectorKeyHex))
	plaintext := make([]byte, int(ClientEncryptionMaxPlaintextBytes))
	plaintext[0] = 0x11
	plaintext[len(plaintext)/2] = 0x22
	plaintext[len(plaintext)-1] = 0x33
	envelope, err := profile.SealObject(strictShareIsolationVectorObjectKey, plaintext)
	if err != nil {
		t.Fatalf("SealObject(exact 64 MiB): %v", err)
	}
	if got, want := int64(len(envelope)), ClientEncryptionMaxPlaintextBytes+ClientEncryptionCiphertextOverhead; got != want {
		t.Fatalf("maximum envelope bytes = %d, want %d", got, want)
	}

	// Release the source before allocating the decrypted result. This test is
	// intentionally not parallel: its peak live payload stays close to 128 MiB.
	plaintext = nil
	runtime.GC()
	opened, err := profile.OpenObject(strictShareIsolationVectorObjectKey, envelope)
	if err != nil {
		t.Fatalf("OpenObject(exact 64 MiB plus 52 bytes): %v", err)
	}
	if int64(len(opened)) != ClientEncryptionMaxPlaintextBytes || opened[0] != 0x11 || opened[len(opened)/2] != 0x22 || opened[len(opened)-1] != 0x33 {
		t.Fatal("maximum-size decrypted plaintext did not preserve length and sentinels")
	}

	envelope = nil
	opened = nil
	runtime.GC()
	tooLarge := make([]byte, int(ClientEncryptionMaxPlaintextBytes+ClientEncryptionCiphertextOverhead+1))
	if _, err := profile.SealObject(strictShareIsolationVectorObjectKey, tooLarge[:ClientEncryptionMaxPlaintextBytes+1]); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("SealObject(64 MiB plus one) error = %v, want ErrResourceLimit", err)
	}
	if _, err := profile.OpenObject(strictShareIsolationVectorObjectKey, tooLarge); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("OpenObject(maximum envelope plus one) error = %v, want ErrResourceLimit", err)
	}
}

func TestClientEncryptedReaderAddsExactEnvelopeOverhead(t *testing.T) {
	profile := strictShareIsolationVectorProfile(t, decodeVectorHex(t, strictShareIsolationVectorKeyHex))
	const objectKey = strictShareIsolationVectorObjectKey
	envelope, err := profile.SealObject(objectKey, []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	backing := &clientEncryptionLimitRecorder{object: Object{
		Data:    envelope,
		Version: Version{ETag: "vector"},
	}}
	reader, err := newClientEncryptedObjectReader(backing, profile)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name          string
		plaintextMax  int64
		ciphertextMax int64
	}{
		{name: "small exact", plaintextMax: 3, ciphertextMax: 3 + ClientEncryptionCiphertextOverhead},
		{name: "adapter default becomes protocol maximum", plaintextMax: 0, ciphertextMax: ClientEncryptionMaxPlaintextBytes + ClientEncryptionCiphertextOverhead},
		{name: "protocol maximum", plaintextMax: ClientEncryptionMaxPlaintextBytes, ciphertextMax: ClientEncryptionMaxPlaintextBytes + ClientEncryptionCiphertextOverhead},
		{name: "above protocol maximum is clamped", plaintextMax: ClientEncryptionMaxPlaintextBytes + 1, ciphertextMax: ClientEncryptionMaxPlaintextBytes + ClientEncryptionCiphertextOverhead},
	} {
		t.Run(test.name, func(t *testing.T) {
			backing.calls = nil
			object, err := reader.Get(context.Background(), objectKey, GetOptions{IfNoneMatch: "previous", MaxBytes: test.plaintextMax})
			if err != nil {
				t.Fatal(err)
			}
			if string(object.Data) != "abc" {
				t.Fatalf("decrypted data = %q, want abc", object.Data)
			}
			if len(backing.calls) != 1 {
				t.Fatalf("backing GET calls = %d, want 1", len(backing.calls))
			}
			if got := backing.calls[0].MaxBytes; got != test.ciphertextMax {
				t.Fatalf("backing MaxBytes = %d, want plaintext limit plus 52 = %d", got, test.ciphertextMax)
			}
			if got := backing.calls[0].IfNoneMatch; got != "previous" {
				t.Fatalf("backing IfNoneMatch = %q, want previous", got)
			}
		})
	}

	backing.calls = nil
	if _, err := reader.Get(context.Background(), objectKey, GetOptions{MaxBytes: -1}); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("negative plaintext MaxBytes error = %v, want ErrResourceLimit", err)
	}
	if len(backing.calls) != 0 {
		t.Fatalf("negative plaintext MaxBytes reached backing reader %d times", len(backing.calls))
	}
}

type clientEncryptionLimitRecorder struct {
	object Object
	calls  []GetOptions
}

func (reader *clientEncryptionLimitRecorder) Get(_ context.Context, _ string, options GetOptions) (Object, error) {
	reader.calls = append(reader.calls, options)
	if options.MaxBytes > 0 && int64(len(reader.object.Data)) > options.MaxBytes {
		return Object{}, fmt.Errorf("%w: recording reader ciphertext exceeds limit", ErrResourceLimit)
	}
	return Object{Data: append([]byte(nil), reader.object.Data...), Version: reader.object.Version}, nil
}

func FuzzClientEncryptionOpenObjectMalformed(f *testing.F) {
	rawKey := decodeVectorHex(f, strictShareIsolationVectorKeyHex)
	profile := strictShareIsolationVectorProfile(f, rawKey)
	validEnvelope := decodeVectorHex(f, strictShareIsolationVectorEnvelopeHex)
	malformed := [][]byte{
		{},
		append([]byte(nil), strictShareIsolationVectorHeader...),
		append(append([]byte(nil), strictShareIsolationVectorHeader...), make([]byte, 15)...),
		append(append([]byte(nil), strictShareIsolationVectorHeader...), make([]byte, int(ClientEncryptionCiphertextOverhead)-len(strictShareIsolationVectorHeader))...),
		append([]byte(nil), validEnvelope[:len(validEnvelope)-1]...),
		flipVectorByte(validEnvelope, 0),
		flipVectorByte(validEnvelope, len(strictShareIsolationVectorHeader)),
		flipVectorByte(validEnvelope, len(strictShareIsolationVectorHeader)+clientEncryptionSaltBytes),
		flipVectorByte(validEnvelope, len(validEnvelope)-1),
	}
	for index, seed := range malformed {
		if plaintext, err := profile.OpenObject(strictShareIsolationVectorObjectKey, seed); err == nil || plaintext != nil {
			f.Fatalf("malformed seed %d unexpectedly opened: plaintext=%x err=%v", index, plaintext, err)
		}
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, envelope []byte) {
		plaintext, err := profile.OpenObject(strictShareIsolationVectorObjectKey, envelope)
		if err == nil {
			if int64(len(plaintext)) > ClientEncryptionMaxPlaintextBytes {
				t.Fatalf("OpenObject returned %d plaintext bytes above the protocol maximum", len(plaintext))
			}
			return
		}
		if plaintext != nil {
			t.Fatalf("OpenObject returned plaintext %x with error %v", plaintext, err)
		}
		if !errors.Is(err, ErrCorruptObject) && !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("OpenObject malformed envelope error = %v, want ErrCorruptObject or ErrResourceLimit", err)
		}
	})
}

func flipVectorByte(input []byte, index int) []byte {
	copyOfInput := append([]byte(nil), input...)
	copyOfInput[index] ^= 0x01
	return copyOfInput
}

func TestClientEncryptionDiagnosticsRedactRawKeyRepresentations(t *testing.T) {
	rawKey := decodeVectorHex(t, strictShareIsolationVectorKeyHex)
	secret := clientEncryptionSecretPrefix + base64.RawURLEncoding.EncodeToString(rawKey)
	key, err := ParseClientEncryptionKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	profile := strictShareIsolationVectorProfile(t, rawKey)
	store, err := NewClientEncryptedStore(&clientEncryptionVectorStore{}, profile)
	if err != nil {
		t.Fatal(err)
	}
	var rawKeyArray [clientEncryptionKeyBytes]byte
	copy(rawKeyArray[:], rawKey)

	forbidden := []string{
		secret,
		hex.EncodeToString(rawKey),
		strings.ToUpper(hex.EncodeToString(rawKey)),
		fmt.Sprint(rawKey),
		fmt.Sprintf("%#v", rawKey),
		fmt.Sprintf("%#v", rawKeyArray),
		fmt.Sprintf("% x", rawKey),
		base64.RawURLEncoding.EncodeToString(rawKey),
	}
	for _, subject := range []any{key, &key, *profile, profile, *store, store} {
		encoded, err := json.Marshal(subject)
		if err != nil {
			t.Fatal(err)
		}
		for _, diagnostic := range []string{
			fmt.Sprint(subject),
			fmt.Sprintf("%v", subject),
			fmt.Sprintf("%+v", subject),
			fmt.Sprintf("%#v", subject),
			fmt.Sprintf("%x", subject),
			fmt.Sprintf("% x", subject),
			string(encoded),
		} {
			for _, material := range forbidden {
				if material != "" && strings.Contains(diagnostic, material) {
					t.Fatalf("%T diagnostic leaked key representation %q: %s", subject, material, diagnostic)
				}
			}
		}
	}
}

type clientEncryptionVectorStore struct{}

func (*clientEncryptionVectorStore) Get(context.Context, string, GetOptions) (Object, error) {
	return Object{}, ErrObjectNotFound
}

func (*clientEncryptionVectorStore) Head(context.Context, string) (Version, error) {
	return Version{}, ErrObjectNotFound
}

func (*clientEncryptionVectorStore) PutIfAbsent(context.Context, string, []byte) (Version, error) {
	return Version{ETag: "vector"}, nil
}

func (*clientEncryptionVectorStore) CompareAndSwap(context.Context, string, *Version, []byte) (Version, error) {
	return Version{ETag: "vector"}, nil
}
