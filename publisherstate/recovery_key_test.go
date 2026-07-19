package publisherstate

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestRecoveryKeyGenerateParseExportAndDiagnostics(t *testing.T) {
	t.Parallel()

	key, err := GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	secret := key.ExportSecret()
	if secret == "" || !strings.HasPrefix(secret, recoveryKeySecretPrefix) {
		t.Fatalf("ExportSecret returned a malformed value")
	}
	parsed, err := ParseRecoveryKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ExportSecret() != secret {
		t.Fatal("parsed recovery key did not reproduce its canonical secret")
	}

	other, err := GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	if other.ExportSecret() == secret {
		t.Fatal("two generated recovery keys were equal")
	}

	encoded, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, diagnostic := range map[string]string{
		"String": key.String(), "GoString": key.GoString(), "JSON": string(encoded),
	} {
		if strings.Contains(diagnostic, secret) || strings.Contains(diagnostic, strings.TrimPrefix(secret, recoveryKeySecretPrefix)) {
			t.Fatalf("%s exposed recovery key material", name)
		}
		if !strings.Contains(diagnostic, "redacted") {
			t.Fatalf("%s = %q, want an explicit redaction marker", name, diagnostic)
		}
	}
}

func TestRecoveryKeyRejectsMalformedSecretsWithoutEcho(t *testing.T) {
	t.Parallel()

	valid, err := GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	secret := valid.ExportSecret()
	encoded := strings.TrimPrefix(secret, recoveryKeySecretPrefix)
	tests := []string{
		"",
		"not-a-recovery-key",
		recoveryKeySecretPrefix,
		recoveryKeySecretPrefix + "%%%",
		recoveryKeySecretPrefix + encoded[:len(encoded)-1],
		secret + "=",
		recoveryKeySecretPrefix + strings.Repeat("A", len(encoded)),
	}
	for _, value := range tests {
		if _, err := ParseRecoveryKey(value); !errors.Is(err, ErrInvalidRecoveryKey) {
			t.Errorf("ParseRecoveryKey malformed input error = %v, want ErrInvalidRecoveryKey", err)
		} else if value != "" && strings.Contains(err.Error(), value) {
			t.Errorf("ParseRecoveryKey error echoed malformed secret")
		}
	}
}

func TestZeroRecoveryKeyDiagnosticsRemainRedacted(t *testing.T) {
	t.Parallel()

	var key RecoveryKey
	if got := key.ExportSecret(); got != "" {
		t.Fatalf("zero ExportSecret = %q, want empty", got)
	}
	encoded, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), recoveryKeySecretPrefix) || !strings.Contains(string(encoded), "redacted") {
		t.Fatalf("zero recovery key JSON = %s", encoded)
	}
}
