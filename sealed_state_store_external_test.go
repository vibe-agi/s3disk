package s3disk_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/publisherstate"
)

var _ s3disk.SealedStateProtector = (*publisherstate.AESGCMProtector)(nil)
var _ s3disk.SealedStateProtector = (*publisherstate.AESGCMKeyring)(nil)

func TestFileSealedStateStoreCreateUpdateAndAliasIsolation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(privateTestDirectory(t), "publisher.state")
	store, _ := newFileSealedStateTestStore(t, path, []byte("repository/share/publisher-state"), "active-key", publisherstate.RecoveryKey{})

	if state, revision, found, err := store.Load(ctx); err != nil || found || state != nil || !revision.IsZero() {
		t.Fatalf("initial Load = %q, %s, %v, %v; want absent", state, revision, found, err)
	}
	first := []byte("first private publisher state")
	firstRevision, err := store.CompareAndSwap(ctx, nil, first)
	if err != nil {
		t.Fatal(err)
	}
	if firstRevision.IsZero() {
		t.Fatal("create returned a zero revision")
	}
	first[0] = 'X'

	loaded, loadedRevision, found, err := store.Load(ctx)
	if err != nil || !found || loadedRevision != firstRevision || string(loaded) != "first private publisher state" {
		t.Fatalf("Load = %q, %s, %v, %v", loaded, loadedRevision, found, err)
	}
	loaded[0] = 'Y'
	reloaded, _, _, err := store.Load(ctx)
	if err != nil || string(reloaded) != "first private publisher state" {
		t.Fatalf("Load after caller mutation = %q, %v", reloaded, err)
	}

	second := []byte("second private publisher state")
	secondRevision, err := store.CompareAndSwap(ctx, &firstRevision, second)
	if err != nil {
		t.Fatal(err)
	}
	if secondRevision.IsZero() || secondRevision == firstRevision {
		t.Fatalf("update revision = %s, want fresh non-zero value", secondRevision)
	}
	thirdRevision, err := store.CompareAndSwap(ctx, &secondRevision, second)
	if err != nil {
		t.Fatal(err)
	}
	if thirdRevision.IsZero() || thirdRevision == secondRevision {
		t.Fatalf("same-state update revision = %s, want fresh non-zero value", thirdRevision)
	}

	if _, err := store.CompareAndSwap(ctx, nil, []byte("must not replace present")); !errors.Is(err, s3disk.ErrPrecondition) {
		t.Fatalf("nil expected on present state error = %v, want ErrPrecondition", err)
	}
	if _, err := store.CompareAndSwap(ctx, &firstRevision, []byte("stale")); !errors.Is(err, s3disk.ErrPrecondition) {
		t.Fatalf("stale CAS error = %v, want ErrPrecondition", err)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("state permissions = %o, want exactly 0600", info.Mode().Perm())
		}
	}
}

func TestFileSealedStateStoreCopiesConstructorBinding(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(privateTestDirectory(t), "binding-copy.state")
	key, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	binding := []byte("durable-binding")
	store, _ := newFileSealedStateTestStore(t, path, binding, "active-key", key)
	peer, _ := newFileSealedStateTestStore(t, path, []byte("durable-binding"), "active-key", key)
	clear(binding)
	if _, err := store.CompareAndSwap(ctx, nil, []byte("state")); err != nil {
		t.Fatal(err)
	}
	state, _, found, err := peer.Load(ctx)
	if err != nil || !found || string(state) != "state" {
		t.Fatalf("peer Load after caller mutated constructor binding = %q, %v, %v", state, found, err)
	}
}

func TestFileSealedStateStoreSerializesConcurrentInstances(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(privateTestDirectory(t), "concurrent.state")
	key, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	left, _ := newFileSealedStateTestStore(t, path, []byte("shared-binding"), "key-1", key)
	right, _ := newFileSealedStateTestStore(t, path, []byte("shared-binding"), "key-1", key)
	baseRevision, err := left.CompareAndSwap(ctx, nil, []byte("base"))
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for index, store := range []*s3disk.FileSealedStateStore{left, right} {
		index, store := index, store
		go func() {
			defer ready.Done()
			<-start
			_, err := store.CompareAndSwap(ctx, &baseRevision, []byte(fmt.Sprintf("winner-%d", index)))
			results <- err
		}()
	}
	close(start)
	firstErr, secondErr := <-results, <-results
	ready.Wait()
	if (firstErr == nil) == (secondErr == nil) {
		t.Fatalf("concurrent CAS errors = (%v, %v), want exactly one success", firstErr, secondErr)
	}
	loser := firstErr
	if loser == nil {
		loser = secondErr
	}
	if !errors.Is(loser, s3disk.ErrPrecondition) {
		t.Fatalf("losing CAS error = %v, want ErrPrecondition", loser)
	}
}

func TestFileSealedStateStoreSerializesConcurrentProcesses(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		t.Skip("private sealed state intentionally fails closed on this platform")
	}

	ctx := context.Background()
	directory := privateTestDirectory(t)
	path := filepath.Join(directory, "cross-process.state")
	key := mustCrossProcessRecoveryKey(t)
	protector := mustPublisherStateProtector(t, "cross-process-key", key)
	store, err := s3disk.NewFileSealedStateStore(path, s3disk.FileSealedStateStoreOptions{
		Protector: protector, Binding: []byte("cross-process-binding"),
	})
	if errors.Is(err, s3disk.ErrTrustStateUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	baseRevision, err := store.CompareAndSwap(ctx, nil, []byte("base"))
	if err != nil {
		t.Fatal(err)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	type child struct {
		command *exec.Cmd
		output  bytes.Buffer
		result  string
	}
	children := make([]child, 2)
	for index := range children {
		children[index].result = filepath.Join(directory, fmt.Sprintf("child-%d.result", index))
		command := exec.Command(executable, "-test.run=^TestFileSealedStateStoreCrossProcessHelper$", "-test.count=1")
		command.Env = append(os.Environ(),
			"S3DISK_SEALED_STATE_HELPER=1",
			"S3DISK_SEALED_STATE_PATH="+path,
			"S3DISK_SEALED_STATE_EXPECTED="+baseRevision.String(),
			"S3DISK_SEALED_STATE_RESULT="+children[index].result,
			fmt.Sprintf("S3DISK_SEALED_STATE_VALUE=winner-%d", index),
		)
		command.Stdout = &children[index].output
		command.Stderr = &children[index].output
		children[index].command = command
	}
	for index := range children {
		if err := children[index].command.Start(); err != nil {
			t.Fatalf("start child %d: %v", index, err)
		}
	}
	for index := range children {
		if err := children[index].command.Wait(); err != nil {
			t.Fatalf("wait child %d: %v\n%s", index, err, children[index].output.String())
		}
	}
	results := make([]string, len(children))
	for index := range children {
		data, err := os.ReadFile(children[index].result)
		if err != nil {
			t.Fatalf("read child %d result: %v\n%s", index, err, children[index].output.String())
		}
		results[index] = string(data)
	}
	if !((results[0] == "success" && results[1] == "precondition") ||
		(results[0] == "precondition" && results[1] == "success")) {
		t.Fatalf("cross-process CAS results = %q, want exactly one success", results)
	}
}

func TestFileSealedStateStoreCrossProcessHelper(t *testing.T) {
	if os.Getenv("S3DISK_SEALED_STATE_HELPER") != "1" {
		t.Skip("helper subprocess only")
	}
	path := os.Getenv("S3DISK_SEALED_STATE_PATH")
	resultPath := os.Getenv("S3DISK_SEALED_STATE_RESULT")
	expected, err := s3disk.ParseDigest(os.Getenv("S3DISK_SEALED_STATE_EXPECTED"))
	if err != nil {
		t.Fatal(err)
	}
	protector := mustPublisherStateProtector(t, "cross-process-key", mustCrossProcessRecoveryKey(t))
	store, err := s3disk.NewFileSealedStateStore(path, s3disk.FileSealedStateStoreOptions{
		Protector: protector, Binding: []byte("cross-process-binding"),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, casErr := store.CompareAndSwap(context.Background(), &expected, []byte(os.Getenv("S3DISK_SEALED_STATE_VALUE")))
	result := "success"
	if errors.Is(casErr, s3disk.ErrPrecondition) {
		result = "precondition"
	} else if casErr != nil {
		result = "error: " + casErr.Error()
	}
	if err := os.WriteFile(resultPath, []byte(result), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFileSealedStateStoreAuthenticatesProtectorKeyAndBinding(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(privateTestDirectory(t), "authenticated.state")
	key, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	store, _ := newFileSealedStateTestStore(t, path, []byte("share-A"), "active-key", key)
	if _, err := store.CompareAndSwap(ctx, nil, []byte("sensitive publisher state")); err != nil {
		t.Fatal(err)
	}

	wrongBinding, _ := newFileSealedStateTestStore(t, path, []byte("share-B"), "active-key", key)
	wrongKey, _ := newFileSealedStateTestStore(t, path, []byte("share-A"), "active-key", publisherstate.RecoveryKey{})
	wrongID, _ := newFileSealedStateTestStore(t, path, []byte("share-A"), "retired-key", key)
	for name, candidate := range map[string]*s3disk.FileSealedStateStore{
		"binding": wrongBinding,
		"key":     wrongKey,
		"key ID":  wrongID,
	} {
		if _, _, _, err := candidate.Load(ctx); !errors.Is(err, publisherstate.ErrAuthenticationFailed) {
			t.Errorf("wrong %s Load error = %v, want ErrAuthenticationFailed", name, err)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Load(ctx); !errors.Is(err, publisherstate.ErrAuthenticationFailed) {
		t.Fatalf("tampered envelope Load error = %v, want ErrAuthenticationFailed", err)
	}
}

func TestFileSealedStateStoreRotatesRecoveryKeyThroughCAS(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(privateTestDirectory(t), "rotated.state")
	binding := []byte("repository/share/rotated-state")
	oldKey, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	oldProtector := mustPublisherStateProtector(t, "old-recovery-key", oldKey)
	newProtector := mustPublisherStateProtector(t, "new-recovery-key", newKey)
	oldKeyring, err := publisherstate.NewAESGCMKeyring(oldProtector)
	if err != nil {
		t.Fatal(err)
	}
	oldStore, err := s3disk.NewFileSealedStateStore(path, s3disk.FileSealedStateStoreOptions{
		Protector: oldKeyring, Binding: binding,
	})
	if errors.Is(err, s3disk.ErrTrustStateUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	originalRevision, err := oldStore.CompareAndSwap(ctx, nil, []byte("publisher recovery state"))
	if err != nil {
		t.Fatal(err)
	}
	originalFile, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	rotationKeyring, err := publisherstate.NewAESGCMKeyring(newProtector, oldProtector)
	if err != nil {
		t.Fatal(err)
	}
	rotatingStore, err := s3disk.NewFileSealedStateStore(path, s3disk.FileSealedStateStoreOptions{
		Protector: rotationKeyring, Binding: binding,
	})
	if err != nil {
		t.Fatal(err)
	}
	state, loadedRevision, found, err := rotatingStore.Load(ctx)
	if err != nil || !found || loadedRevision != originalRevision || string(state) != "publisher recovery state" {
		t.Fatalf("retained-key Load = %q, %s, %v, %v", state, loadedRevision, found, err)
	}
	rotatedRevision, err := rotatingStore.CompareAndSwap(ctx, &loadedRevision, state)
	clear(state)
	if err != nil {
		t.Fatal(err)
	}
	if rotatedRevision.IsZero() || rotatedRevision == originalRevision {
		t.Fatalf("rotation revision = %s, want fresh non-zero revision", rotatedRevision)
	}
	rotatedFile, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(rotatedFile, originalFile) {
		t.Fatal("recovery-key rotation did not replace the sealed file")
	}

	newOnlyKeyring, err := publisherstate.NewAESGCMKeyring(newProtector)
	if err != nil {
		t.Fatal(err)
	}
	newOnlyStore, err := s3disk.NewFileSealedStateStore(path, s3disk.FileSealedStateStoreOptions{
		Protector: newOnlyKeyring, Binding: binding,
	})
	if err != nil {
		t.Fatal(err)
	}
	state, loadedRevision, found, err = newOnlyStore.Load(ctx)
	if err != nil || !found || loadedRevision != rotatedRevision || string(state) != "publisher recovery state" {
		t.Fatalf("active-only Load = %q, %s, %v, %v", state, loadedRevision, found, err)
	}
	clear(state)
	if _, _, _, err := oldStore.Load(ctx); !errors.Is(err, publisherstate.ErrAuthenticationFailed) {
		t.Fatalf("retired-only Load error = %v, want ErrAuthenticationFailed", err)
	}
}

func TestFileSealedStateStoreRejectsTruncatedTrailingOversizedAndUnsafeFiles(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	directory := privateTestDirectory(t)
	path := filepath.Join(directory, "strict.state")
	store, _ := newFileSealedStateTestStoreWithOptions(t, path, s3disk.FileSealedStateStoreOptions{
		Binding: []byte("strict-binding"), MaxEnvelopeBytes: 1024,
	})
	if _, err := store.CompareAndSwap(ctx, nil, []byte("valid")); err != nil {
		t.Fatal(err)
	}
	valid, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	for _, length := range []int{0, 1, len(valid) - 1} {
		if err := os.WriteFile(path, valid[:length], 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := store.Load(ctx); !errors.Is(err, s3disk.ErrCorruptObject) {
			t.Errorf("Load truncated to %d bytes error = %v, want ErrCorruptObject", length, err)
		}
	}
	if err := os.WriteFile(path, append(bytes.Clone(valid), 0), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Load(ctx); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("Load with trailing byte error = %v, want ErrCorruptObject", err)
	}
	if err := os.WriteFile(path, make([]byte, 2048), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Load(ctx); !errors.Is(err, s3disk.ErrCorruptObject) || !errors.Is(err, s3disk.ErrResourceLimit) {
		t.Fatalf("Load oversized error = %v, want ErrCorruptObject and ErrResourceLimit", err)
	}

	if err := os.WriteFile(path, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := store.Load(ctx); !errors.Is(err, s3disk.ErrCorruptObject) {
			t.Fatalf("Load mode 0644 error = %v, want ErrCorruptObject", err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	target := filepath.Join(directory, "target.state")
	if err := os.WriteFile(target, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, _, _, err := store.Load(ctx); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("Load symlink error = %v, want ErrCorruptObject", err)
	}
}

func TestFileSealedStateStoreLimitsCancellationAndDiagnostics(t *testing.T) {
	t.Parallel()

	directory := privateTestDirectory(t)
	path := filepath.Join(directory, "diagnostic-secret-path.state")
	binding := []byte("secret-binding-must-not-appear")
	key, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	store, _ := newFileSealedStateTestStore(t, path, binding, "diagnostic-key", key)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := store.Load(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Load error = %v", err)
	}
	if _, err := store.CompareAndSwap(canceled, nil, []byte("secret-state")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled CAS error = %v", err)
	}
	if _, _, _, err := store.Load(nil); err == nil {
		t.Fatal("Load accepted nil context")
	}
	if _, err := store.CompareAndSwap(nil, nil, nil); err == nil {
		t.Fatal("CompareAndSwap accepted nil context")
	}

	if s3disk.DefaultFileSealedStateMaxEnvelopeBytes < int64(publisherstate.MaximumEnvelopeBytes) {
		t.Fatalf("default envelope limit = %d, cannot contain publisherstate maximum %d", s3disk.DefaultFileSealedStateMaxEnvelopeBytes, publisherstate.MaximumEnvelopeBytes)
	}
	smallStore, _ := newFileSealedStateTestStoreWithOptions(t, filepath.Join(directory, "small.state"), s3disk.FileSealedStateStoreOptions{
		Binding: []byte("small-limit"), MaxEnvelopeBytes: 32,
	})
	if _, err := smallStore.CompareAndSwap(context.Background(), nil, make([]byte, 33)); !errors.Is(err, s3disk.ErrResourceLimit) {
		t.Fatalf("oversized plaintext error = %v, want ErrResourceLimit", err)
	}
	if _, err := s3disk.NewFileSealedStateStore(path, s3disk.FileSealedStateStoreOptions{
		Binding: binding, Protector: mustPublisherStateProtector(t, "limit-key", publisherstate.RecoveryKey{}),
		MaxEnvelopeBytes: s3disk.FileSealedStateMaxEnvelopeBytesLimit + 1,
	}); !errors.Is(err, s3disk.ErrResourceLimit) {
		t.Fatalf("oversized configured limit error = %v, want ErrResourceLimit", err)
	}

	diagnostics := []string{fmt.Sprint(store), fmt.Sprintf("%#v", store)}
	encoded, err := json.Marshal(store)
	if err != nil {
		t.Fatal(err)
	}
	diagnostics = append(diagnostics, string(encoded))
	for _, diagnostic := range diagnostics {
		for _, secret := range []string{path, string(binding), key.ExportSecret(), "diagnostic-key"} {
			if strings.Contains(diagnostic, secret) {
				t.Fatalf("diagnostic %q contains secret/configuration %q", diagnostic, secret)
			}
		}
		if !strings.Contains(diagnostic, "redacted") {
			t.Fatalf("diagnostic %q is not explicitly redacted", diagnostic)
		}
	}
}

func newFileSealedStateTestStore(
	t *testing.T,
	path string,
	binding []byte,
	keyID string,
	key publisherstate.RecoveryKey,
) (*s3disk.FileSealedStateStore, publisherstate.RecoveryKey) {
	t.Helper()
	if key.ExportSecret() == "" {
		var err error
		key, err = publisherstate.GenerateRecoveryKey()
		if err != nil {
			t.Fatal(err)
		}
	}
	protector := mustPublisherStateProtector(t, keyID, key)
	store, err := s3disk.NewFileSealedStateStore(path, s3disk.FileSealedStateStoreOptions{
		Protector: protector, Binding: binding,
	})
	if errors.Is(err, s3disk.ErrTrustStateUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	return store, key
}

func newFileSealedStateTestStoreWithOptions(
	t *testing.T,
	path string,
	options s3disk.FileSealedStateStoreOptions,
) (*s3disk.FileSealedStateStore, publisherstate.RecoveryKey) {
	t.Helper()
	key, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	options.Protector = mustPublisherStateProtector(t, "test-key", key)
	store, err := s3disk.NewFileSealedStateStore(path, options)
	if errors.Is(err, s3disk.ErrTrustStateUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	return store, key
}

func mustPublisherStateProtector(t *testing.T, keyID string, key publisherstate.RecoveryKey) *publisherstate.AESGCMProtector {
	t.Helper()
	if key.ExportSecret() == "" {
		var err error
		key, err = publisherstate.GenerateRecoveryKey()
		if err != nil {
			t.Fatal(err)
		}
	}
	protector, err := publisherstate.NewAESGCMProtector(keyID, key)
	if err != nil {
		t.Fatal(err)
	}
	return protector
}

func mustCrossProcessRecoveryKey(t *testing.T) publisherstate.RecoveryKey {
	t.Helper()
	const secret = "s3disk-publisher-recovery-v1.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
	key, err := publisherstate.ParseRecoveryKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
