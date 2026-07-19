package s3disk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Digest is a SHA-256 object identifier. Hashes are domain-separated by object
// type, so a metadata object and a data chunk cannot alias each other.
type Digest [sha256.Size]byte

func digestObject(kind string, data []byte) Digest {
	h := sha256.New()
	_, _ = h.Write([]byte("s3disk\x00v1\x00"))
	_, _ = h.Write([]byte(kind))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(data)
	var digest Digest
	copy(digest[:], h.Sum(nil))
	return digest
}

// ParseDigest parses a lowercase or uppercase hexadecimal SHA-256 digest.
func ParseDigest(value string) (Digest, error) {
	var digest Digest
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(digest) {
		return Digest{}, fmt.Errorf("%w: digest %q", ErrCorruptObject, value)
	}
	copy(digest[:], decoded)
	return digest, nil
}

func (d Digest) String() string { return hex.EncodeToString(d[:]) }

func (d Digest) IsZero() bool { return d == Digest{} }

func (d Digest) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *Digest) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	parsed, err := ParseDigest(value)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}
