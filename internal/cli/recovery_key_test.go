package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/publisherstate"
)

func TestRecoveryKeyFileExclusive0600RoundTrip(t *testing.T) {
	requirePrivateSecretFiles(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "publisher-recovery-key.json")
	key, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	written, _, err := writeRecoveryKeyFile(context.Background(), path, key)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("recovery-key mode = %#o, want 0600", info.Mode().Perm())
	}
	loaded, err := readRecoveryKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.keyID != written.keyID || loaded.key.ExportSecret() != key.ExportSecret() {
		t.Fatal("recovery-key round trip changed its key ID or secret")
	}
	if written.keyID != deriveRecoveryKeyID(key.ExportSecret()) ||
		!strings.HasPrefix(written.keyID, recoveryKeyIDPrefix) ||
		len(strings.TrimPrefix(written.keyID, recoveryKeyIDPrefix)) != base64.RawURLEncoding.EncodedLen(recoveryKeyIDHashBytes) {
		t.Fatalf("derived key ID = %q", written.keyID)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _, err := encodeRecoveryKeyFile(key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, canonical) || raw[len(raw)-1] != '\n' {
		t.Fatal("recovery-key file is not the exact canonical encoding")
	}
}

func TestRecoveryKeyIDStableDomainSeparatedVector(t *testing.T) {
	const secret = "s3disk-publisher-recovery-v1.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
	key, err := publisherstate.ParseRecoveryKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	if key.ExportSecret() != secret {
		t.Fatal("test recovery key did not retain its canonical representation")
	}
	if got, want := deriveRecoveryKeyID(secret), "rk1.XwDOwYI3sUSeAKP3jxZ2Rgg0k9h55_Qw"; got != want {
		t.Fatalf("key ID = %q, want stable vector %q", got, want)
	}
}

func TestRecoveryKeyFileRejectsStrictJSONDamageAndWrongKeyID(t *testing.T) {
	requirePrivateSecretFiles(t)
	key, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	valid, _, err := encodeRecoveryKeyFile(key)
	if err != nil {
		t.Fatal(err)
	}
	var wire recoveryKeyFile
	if err := json.Unmarshal(valid, &wire); err != nil {
		t.Fatal(err)
	}
	marshal := func(value recoveryKeyFile) []byte {
		t.Helper()
		encoded, err := json.Marshal(recoveryKeyFileWire(value))
		if err != nil {
			t.Fatal(err)
		}
		return append(encoded, '\n')
	}
	wrongFormat := wire
	wrongFormat.Format++
	wrongID := wire
	wrongID.KeyID = recoveryKeyIDPrefix + strings.Repeat("A", base64.RawURLEncoding.EncodedLen(recoveryKeyIDHashBytes))
	badSecret := wire
	badSecret.RecoveryKey += "="
	withUnknown := append([]byte(`{"format":1,"key_id":"`+wire.KeyID+`","recovery_key":"`+wire.RecoveryKey+`","unknown":true}`), '\n')
	nonCanonical := append([]byte("  "), valid...)
	trailing := append(append([]byte(nil), valid...), []byte("{}\n")...)
	duplicate := append([]byte(`{"format":1,"format":1,"key_id":"`+wire.KeyID+`","recovery_key":"`+wire.RecoveryKey+`"}`), '\n')
	oversized := bytes.Repeat([]byte{'x'}, maximumRecoveryKeyFileBytes+1)

	for name, encoded := range map[string][]byte{
		"unknown field":           withUnknown,
		"trailing value":          trailing,
		"noncanonical whitespace": nonCanonical,
		"duplicate field":         duplicate,
		"wrong format":            marshal(wrongFormat),
		"wrong key ID":            marshal(wrongID),
		"malformed secret":        marshal(badSecret),
		"oversized":               oversized,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "recovery-key.json")
			if err := os.WriteFile(path, encoded, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readRecoveryKeyFile(path); !errors.Is(err, ErrInvalidRecoveryKeyFile) {
				t.Fatalf("error = %v, want ErrInvalidRecoveryKeyFile", err)
			}
		})
	}
}

func TestRecoveryKeyFileRejectsPermissionsAndSymlink(t *testing.T) {
	requirePrivateSecretFiles(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "recovery-key.json")
	key, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := writeRecoveryKeyFile(context.Background(), path, key); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecoveryKeyFile(path); !errors.Is(err, ErrInvalidRecoveryKeyFile) || !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("loose-permission error = %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "recovery-key-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecoveryKeyFile(link); !errors.Is(err, ErrInvalidRecoveryKeyFile) {
		t.Fatalf("symlink error = %v, want ErrInvalidRecoveryKeyFile", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	other, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := writeRecoveryKeyFile(context.Background(), link, other); !errors.Is(err, ErrRecoveryKeyFileExists) {
		t.Fatalf("symlink output error = %v, want ErrRecoveryKeyFileExists", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("symlink target changed: equal=%t err=%v", bytes.Equal(after, before), err)
	}
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecoveryKeyFile(path); !errors.Is(err, ErrInvalidRecoveryKeyFile) || !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("writable-parent error = %v", err)
	}
}

func TestRecoveryKeyFileNeverOverwrites(t *testing.T) {
	requirePrivateSecretFiles(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "recovery-key.json")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := writeRecoveryKeyFile(context.Background(), path, key); !errors.Is(err, ErrRecoveryKeyFileExists) {
		t.Fatalf("error = %v, want ErrRecoveryKeyFileExists", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "keep" {
		t.Fatalf("existing output changed: data=%q err=%v", got, err)
	}
}

func TestRecoveryKeyAtomicInstallLosesRaceWithoutOverwrite(t *testing.T) {
	requirePrivateSecretFiles(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "recovery-key.json")
	key, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	encoded, _, err := encodeRecoveryKeyFile(key)
	if err != nil {
		t.Fatal(err)
	}
	_, err = writeRecoveryKeyBytes(context.Background(), path, encoded, func(temporary, destination string) error {
		if err := os.WriteFile(destination, []byte("race winner"), 0o600); err != nil {
			return err
		}
		return installPrivateFileNoReplace(temporary, destination)
	})
	if !errors.Is(err, ErrRecoveryKeyFileExists) {
		t.Fatalf("error = %v, want ErrRecoveryKeyFileExists", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "race winner" {
		t.Fatalf("race winner changed: data=%q err=%v", got, err)
	}
}

func TestRecoveryKeyFinalPathInvisibleUntilAtomicInstall(t *testing.T) {
	requirePrivateSecretFiles(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "recovery-key.json")
	key, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	encoded, _, err := encodeRecoveryKeyFile(key)
	if err != nil {
		t.Fatal(err)
	}
	wantStop := errors.New("stop before recovery-key install")
	installCalled := false
	var callbackErr error
	_, err = writeRecoveryKeyBytes(context.Background(), path, encoded, func(temporary, destination string) error {
		installCalled = true
		if destination != path {
			callbackErr = fmt.Errorf("destination = %q, want %q", destination, path)
			return wantStop
		}
		if _, statErr := os.Lstat(destination); !errors.Is(statErr, os.ErrNotExist) {
			callbackErr = fmt.Errorf("final path visible before install: %w", statErr)
			return wantStop
		}
		staged, readErr := os.ReadFile(temporary)
		if readErr != nil {
			callbackErr = readErr
			return wantStop
		}
		if !bytes.Equal(staged, encoded) {
			callbackErr = errors.New("staged recovery key is incomplete")
			return wantStop
		}
		info, statErr := os.Stat(temporary)
		if statErr != nil {
			callbackErr = statErr
			return wantStop
		}
		if info.Mode().Perm() != 0o600 {
			callbackErr = fmt.Errorf("staged mode = %#o, want 0600", info.Mode().Perm())
		}
		return wantStop
	})
	if !installCalled {
		t.Fatal("installer was not called")
	}
	if !errors.Is(err, wantStop) {
		t.Fatalf("error = %v, want injected installer failure", err)
	}
	if callbackErr != nil {
		t.Fatal(callbackErr)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("final output exists after pre-install failure: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(directory, ".s3disk-recovery-key-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary recovery-key files remain: %v", matches)
	}
}

func TestRecoveryKeyDiagnosticsAndCommandOutputRedactSecret(t *testing.T) {
	requirePrivateSecretFiles(t)
	path := filepath.Join(t.TempDir(), "recovery-key.json")
	var stdout bytes.Buffer
	if err := runGenerateRecoveryKey(context.Background(), RecoveryKeyGenerateOptions{Out: path, StatusWriter: &stdout}); err != nil {
		t.Fatal(err)
	}
	loaded, err := readRecoveryKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	secret := loaded.key.ExportSecret()
	if secret == "" {
		t.Fatal("loaded recovery key is empty")
	}
	if strings.Contains(stdout.String(), secret) || !strings.Contains(stdout.String(), loaded.keyID) {
		t.Fatalf("unsafe status output: %q", stdout.String())
	}
	wire := recoveryKeyFile{Format: recoveryKeyFileFormat, KeyID: loaded.keyID, RecoveryKey: secret}
	diagnosticJSON, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	for name, diagnostic := range map[string]string{
		"wire String":       fmt.Sprint(wire),
		"wire detailed":     fmt.Sprintf("%+v", wire),
		"wire GoString":     fmt.Sprintf("%#v", wire),
		"material String":   fmt.Sprint(loaded),
		"material detailed": fmt.Sprintf("%+v", loaded),
		"material GoString": fmt.Sprintf("%#v", loaded),
		"wire JSON":         string(diagnosticJSON),
	} {
		if strings.Contains(diagnostic, secret) || !strings.Contains(diagnostic, "redacted") {
			t.Fatalf("%s exposed secret: %q", name, diagnostic)
		}
	}
	other, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := writeRecoveryKeyFile(context.Background(), path, other); !errors.Is(err, ErrRecoveryKeyFileExists) {
		t.Fatalf("existing-file error = %v", err)
	} else if strings.Contains(err.Error(), other.ExportSecret()) {
		t.Fatal("existing-file error exposed the rejected recovery key")
	}
}

func TestRecoveryKeyInstalledUnconfirmedReturnsMaterial(t *testing.T) {
	requirePrivateSecretFiles(t)
	path := filepath.Join(t.TempDir(), "recovery-key.json")
	key, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	syncFailure := errors.New("injected recovery-key directory sync failure")
	operations := privateFileOperationsFor(installPrivateFileNoReplace)
	operations.syncDirectory = func(string) error { return syncFailure }

	material, result, err := writeRecoveryKeyFileWithOperations(context.Background(), path, key, operations)
	if !errors.Is(err, ErrPrivateFileInstalledUnconfirmed) || !errors.Is(err, syncFailure) {
		t.Fatalf("error = %v, want installed-unconfirmed sync failure", err)
	}
	if material.keyID != deriveRecoveryKeyID(key.ExportSecret()) || material.key.ExportSecret() != key.ExportSecret() {
		t.Fatal("installed-unconfirmed result did not preserve recovery-key material")
	}
	if !result.InstallAttempted || !result.InstallResolved || !result.Installed ||
		!result.CleanupConfirmed || result.DurabilityConfirmed || result.NotInstalledConfirmed {
		t.Fatalf("result = %+v, want installed with durability unconfirmed", result)
	}
	loaded, readErr := readRecoveryKeyFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if loaded.keyID != material.keyID || loaded.key.ExportSecret() != key.ExportSecret() {
		t.Fatal("installed recovery-key file differs from returned material")
	}
}

func TestGenerateRecoveryKeyUnconfirmedStatusRequiresSecretSafeReconciliation(t *testing.T) {
	requirePrivateSecretFiles(t)
	path := filepath.Join(t.TempDir(), "recovery-key.json")
	syncFailure := errors.New("injected command directory sync failure")
	operations := privateFileOperationsFor(installPrivateFileNoReplace)
	operations.syncDirectory = func(string) error { return syncFailure }
	var status bytes.Buffer

	err := runGenerateRecoveryKeyWithOperations(context.Background(), RecoveryKeyGenerateOptions{
		Out: path, StatusWriter: &status,
	}, operations)
	if !errors.Is(err, ErrPrivateFileInstalledUnconfirmed) || !errors.Is(err, syncFailure) {
		t.Fatalf("error = %v, want installed-unconfirmed sync failure", err)
	}
	loaded, readErr := readRecoveryKeyFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	secret := loaded.key.ExportSecret()
	output := status.String()
	if !strings.Contains(output, "reconcile_required:") ||
		!strings.Contains(output, path) ||
		!strings.Contains(output, loaded.keyID) ||
		!strings.Contains(output, `outcome="installed_cleanup_or_durability_unconfirmed"`) {
		t.Fatalf("reconciliation status = %q, want path, key ID, and stable outcome", output)
	}
	if strings.Contains(output, "ready:") {
		t.Fatalf("unconfirmed installation reported ready: %q", output)
	}
	if strings.Contains(output, secret) || strings.Contains(err.Error(), secret) {
		t.Fatalf("unconfirmed diagnostics exposed recovery key: status=%q error=%q", output, err)
	}
}

func TestGenerateRecoveryKeyInstallerErrorWithAbsentFinalNeedsNoReconciliation(t *testing.T) {
	requirePrivateSecretFiles(t)
	path := filepath.Join(t.TempDir(), "recovery-key.json")
	installFailure := errors.New("injected command installer rejection")
	operations := privateFileOperationsFor(func(string, string) error { return installFailure })
	var status bytes.Buffer

	err := runGenerateRecoveryKeyWithOperations(context.Background(), RecoveryKeyGenerateOptions{
		Out: path, StatusWriter: &status,
	}, operations)
	if !errors.Is(err, installFailure) {
		t.Fatalf("error = %v, want installer rejection", err)
	}
	if errors.Is(err, ErrPrivateFileInstallIndeterminate) || errors.Is(err, ErrPrivateFileInstalledUnconfirmed) {
		t.Fatalf("confirmed-not-installed error has uncertainty sentinel: %v", err)
	}
	if status.Len() != 0 {
		t.Fatalf("confirmed-not-installed command emitted status: %q", status.String())
	}
	if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("confirmed-not-installed output exists: %v", statErr)
	}
}

func TestRecoveryKeyGenerateCommandHelpRequiredFlagAndInjection(t *testing.T) {
	t.Run("help", func(t *testing.T) {
		root := NewRootCommand(Dependencies{})
		command, _, err := root.Find([]string{"share", "recovery-key", "generate"})
		if err != nil {
			t.Fatal(err)
		}
		if command.CommandPath() != "s3disk share recovery-key generate" || command.Flags().Lookup("out") == nil {
			t.Fatalf("unexpected recovery-key command: %v", command.CommandPath())
		}
		var output bytes.Buffer
		command.SetOut(&output)
		if err := command.Help(); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), "--out") || strings.Contains(strings.ToLower(output.String()), "recovery_key\"") {
			t.Fatalf("unexpected help output: %q", output.String())
		}
	})

	t.Run("required flag", func(t *testing.T) {
		called := false
		root := NewRootCommand(Dependencies{GenerateRecoveryKey: func(context.Context, RecoveryKeyGenerateOptions) error {
			called = true
			return nil
		}})
		root.SetArgs([]string{"share", "recovery-key", "generate"})
		err := root.ExecuteContext(context.Background())
		if err == nil || !strings.Contains(err.Error(), "--out is required") || called {
			t.Fatalf("error=%v called=%t", err, called)
		}
	})

	t.Run("dependency receives safe options", func(t *testing.T) {
		const outputPath = "/private/recovery-key.json"
		called := false
		var stdout bytes.Buffer
		root := NewRootCommand(Dependencies{GenerateRecoveryKey: func(_ context.Context, options RecoveryKeyGenerateOptions) error {
			called = true
			if options.Out != outputPath || options.StatusWriter != &stdout {
				t.Fatalf("options = %#v", options)
			}
			_, _ = fmt.Fprintln(options.StatusWriter, "ready: key generated")
			return nil
		}})
		root.SetOut(&stdout)
		root.SetArgs([]string{"share", "recovery-key", "generate", "--out", outputPath})
		if err := root.ExecuteContext(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !called || stdout.String() != "ready: key generated\n" {
			t.Fatalf("called=%t stdout=%q", called, stdout.String())
		}
	})
}

func FuzzDecodeRecoveryKeyFileNeverPanics(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte("{}\n"))
	key, err := publisherstate.ParseRecoveryKey(
		"s3disk-publisher-recovery-v1.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
	)
	if err != nil {
		f.Fatal(err)
	}
	valid, _, err := encodeRecoveryKeyFile(key)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)

	f.Fuzz(func(t *testing.T, encoded []byte) {
		material, err := decodeRecoveryKeyFile(encoded)
		if err != nil {
			return
		}
		canonical, roundTrip, err := encodeRecoveryKeyFile(material.key)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(canonical)
		if !bytes.Equal(encoded, canonical) || material.keyID != roundTrip.keyID {
			t.Fatal("decoder accepted a non-canonical or unstable recovery-key file")
		}
	})
}

func TestGenerateRecoveryKeyHonorsCanceledContextBeforeCreatingFile(t *testing.T) {
	requirePrivateSecretFiles(t)
	path := filepath.Join(t.TempDir(), "recovery-key.json")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runGenerateRecoveryKey(ctx, RecoveryKeyGenerateOptions{Out: path}); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled command created output: %v", err)
	}
}

func requirePrivateSecretFiles(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		t.Skip("platform intentionally fails closed for private secret files")
	}
}
