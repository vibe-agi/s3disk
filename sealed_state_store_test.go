package s3disk

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk/publisherstate"
)

func TestFileSealedStateStoreOuterFormatAndRevisionAuthentication(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(privateTestDirectory(t), "outer.state")
	store := newInternalFileSealedStateStore(t, path, []byte("outer-binding"))
	if _, err := store.CompareAndSwap(ctx, nil, []byte("outer format state")); err != nil {
		t.Fatal(err)
	}
	valid, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	badMagic := append([]byte(nil), valid...)
	badMagic[0] ^= 1
	badVersion := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(badVersion[sealedStateVersionOffset:], sealedStateFormatVersion+1)
	badReserved := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(badReserved[sealedStateReservedOffset:], 1)
	zeroRevision := append([]byte(nil), valid...)
	clear(zeroRevision[sealedStateRevisionOffset : sealedStateRevisionOffset+len(Digest{})])
	badLength := append([]byte(nil), valid...)
	binary.BigEndian.PutUint64(badLength[sealedStateEnvelopeLengthOffset:], uint64(len(valid)))
	trailing := append(append([]byte(nil), valid...), 0)
	for name, candidate := range map[string][]byte{
		"magic": badMagic, "version": badVersion, "reserved": badReserved,
		"zero revision": zeroRevision, "length": badLength, "trailing": trailing,
	} {
		if err := os.WriteFile(path, candidate, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := store.Load(ctx); !errors.Is(err, ErrCorruptObject) {
			t.Errorf("%s error = %v, want ErrCorruptObject", name, err)
		}
	}

	for length := 0; length < len(valid); length++ {
		if err := os.WriteFile(path, valid[:length], 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := store.Load(ctx); !errors.Is(err, ErrCorruptObject) {
			t.Fatalf("truncation at %d error = %v, want ErrCorruptObject", length, err)
		}
	}

	// A non-zero revision remains syntactically valid, but changing it must alter
	// the derived AEAD binding and therefore fail authentication.
	tamperedRevision := append([]byte(nil), valid...)
	tampered := Digest{1}
	copy(tamperedRevision[sealedStateRevisionOffset:], tampered[:])
	if err := os.WriteFile(path, tamperedRevision, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Load(ctx); !errors.Is(err, publisherstate.ErrAuthenticationFailed) {
		t.Fatalf("tampered revision error = %v, want ErrAuthenticationFailed", err)
	}
}

func TestFileSealedStateStoreReconcilesPostRenameError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(privateTestDirectory(t), "lost-response.state")
	store := newInternalFileSealedStateStore(t, path, []byte("lost-response-binding"))
	errLost := errors.New("test: response lost after rename")
	store.syncDirectory = func(string) error { return errLost }
	candidate, err := store.CompareAndSwap(ctx, nil, []byte("durably reconcile me"))
	if !errors.Is(err, errLost) {
		t.Fatalf("CompareAndSwap error = %v, want injected post-rename error", err)
	}
	if candidate.IsZero() {
		t.Fatal("post-rename error discarded its reconciliation candidate")
	}

	store.syncDirectory = syncWatermarkDirectory
	state, revision, found, err := store.Load(ctx)
	if err != nil || !found || revision.IsZero() || string(state) != "durably reconcile me" {
		t.Fatalf("reconciliation Load = %q, %s, %v, %v", state, revision, found, err)
	}
	if revision != candidate {
		t.Fatalf("reconciled revision = %s, want candidate %s", revision, candidate)
	}
}

func TestFileSealedStateStoreSecondInstanceDurabilizesLostFirstCASBeforePrecondition(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(privateTestDirectory(t), "cross-instance-lost-sync.state")
	key, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	protector, err := publisherstate.NewAESGCMProtector("cross-instance-key", key)
	if err != nil {
		t.Fatal(err)
	}
	options := FileSealedStateStoreOptions{Protector: protector, Binding: []byte("cross-instance-sync-binding")}
	first, err := NewFileSealedStateStore(path, options)
	if errors.Is(err, ErrTrustStateUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewFileSealedStateStore(path, options)
	if err != nil {
		t.Fatal(err)
	}

	errFirstSync := errors.New("test: first process lost parent sync response")
	first.syncDirectory = func(string) error { return errFirstSync }
	candidate, err := first.CompareAndSwap(ctx, nil, []byte("first candidate"))
	if !errors.Is(err, errFirstSync) || candidate.IsZero() {
		t.Fatalf("first CAS = candidate %s, error %v; want non-zero candidate and sync error", candidate, err)
	}

	errSecondSync := errors.New("test: second process cannot complete parent sync")
	second.syncDirectory = func(string) error { return errSecondSync }
	stale := Digest{0x7f}
	if stale == candidate {
		stale[1] = 1
	}
	if revision, err := second.CompareAndSwap(ctx, &stale, []byte("must not install")); !errors.Is(err, errSecondSync) || errors.Is(err, ErrPrecondition) || !revision.IsZero() {
		t.Fatalf("second stale CAS before barrier = revision %s, error %v; want only sync error", revision, err)
	}

	second.syncDirectory = syncWatermarkDirectory
	if _, err := second.CompareAndSwap(ctx, &stale, []byte("must not install")); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("second stale CAS after barrier error = %v, want ErrPrecondition", err)
	}
	state, revision, found, err := second.Load(ctx)
	if err != nil || !found || revision != candidate || string(state) != "first candidate" {
		t.Fatalf("reconciled first candidate = %q, %s, %v, %v", state, revision, found, err)
	}
}

func TestFileSealedStateStoreLoadCompletesDurabilityBarrier(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(privateTestDirectory(t), "load-barrier.state")
	store := newInternalFileSealedStateStore(t, path, []byte("barrier-binding"))
	if _, err := store.CompareAndSwap(ctx, nil, []byte("barrier state")); err != nil {
		t.Fatal(err)
	}
	errUnsynced := errors.New("test: directory sync unavailable")
	store.syncDirectory = func(string) error { return errUnsynced }
	if state, revision, found, err := store.Load(ctx); !errors.Is(err, errUnsynced) || found || state != nil || !revision.IsZero() {
		t.Fatalf("Load without barrier = %q, %s, %v, %v", state, revision, found, err)
	}

	store.syncDirectory = syncWatermarkDirectory
	state, revision, found, err := store.Load(ctx)
	if err != nil || !found || revision.IsZero() || string(state) != "barrier state" {
		t.Fatalf("Load after barrier = %q, %s, %v, %v", state, revision, found, err)
	}
}

func TestFileSealedStateStoreCASDurabilizesCurrentBeforePrecondition(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(privateTestDirectory(t), "cas-current-barrier.state")
	store := newInternalFileSealedStateStore(t, path, []byte("cas-barrier-binding"))
	current, err := store.CompareAndSwap(ctx, nil, []byte("current"))
	if err != nil {
		t.Fatal(err)
	}
	errUnsynced := errors.New("test: current namespace is not durable")
	store.syncDirectory = func(string) error { return errUnsynced }
	stale := Digest{0xff}
	if stale == current {
		stale[1] = 1
	}
	_, casErr := store.CompareAndSwap(ctx, &stale, []byte("must not write"))
	if !errors.Is(casErr, errUnsynced) {
		t.Fatalf("stale CAS before current barrier error = %v, want sync error", casErr)
	}
	if errors.Is(casErr, ErrPrecondition) {
		t.Fatalf("stale CAS returned precondition before current durability barrier: %v", casErr)
	}

	store.syncDirectory = syncWatermarkDirectory
	if _, err := store.CompareAndSwap(ctx, &stale, []byte("must not write")); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("stale CAS after current barrier error = %v, want ErrPrecondition", err)
	}
}

func TestFileSealedStateStoreAllowsCompleteFileReplayButNotPartialSubstitution(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(privateTestDirectory(t), "replay-boundary.state")
	store := newInternalFileSealedStateStore(t, path, []byte("replay-binding"))
	oldRevision, err := store.CompareAndSwap(ctx, nil, []byte("old complete state"))
	if err != nil {
		t.Fatal(err)
	}
	oldFile, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	newRevision, err := store.CompareAndSwap(ctx, &oldRevision, []byte("new complete state"))
	if err != nil {
		t.Fatal(err)
	}
	if newRevision == oldRevision {
		t.Fatal("update reused revision")
	}

	// Replacing the entire authenticated pair is an intentional boundary: this
	// local file alone has integrity, not a monotonic freshness anchor.
	if err := os.WriteFile(path, oldFile, 0o600); err != nil {
		t.Fatal(err)
	}
	state, revision, found, err := store.Load(ctx)
	if err != nil || !found || revision != oldRevision || string(state) != "old complete state" {
		t.Fatalf("whole-file replay Load = %q, %s, %v, %v", state, revision, found, err)
	}

	// Combining an old envelope with the newer outer revision changes the
	// authenticated prefix binding and must fail.
	binary.BigEndian.PutUint64(oldFile[sealedStateEnvelopeLengthOffset:], uint64(len(oldFile)-sealedStateHeaderBytes))
	copy(oldFile[sealedStateRevisionOffset:], newRevision[:])
	if err := os.WriteFile(path, oldFile, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Load(ctx); !errors.Is(err, publisherstate.ErrAuthenticationFailed) {
		t.Fatalf("partial old/new substitution error = %v, want ErrAuthenticationFailed", err)
	}
}

func TestFileSealedStateStoreChecksCancellationAfterProtector(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	path := filepath.Join(privateTestDirectory(t), "cancel-after-seal.state")
	protector := &cancelingSealedStateProtector{cancel: cancel}
	store, err := NewFileSealedStateStore(path, FileSealedStateStoreOptions{
		Protector: protector, Binding: []byte("cancel-binding"), MaxEnvelopeBytes: 1024,
	})
	if errors.Is(err, ErrTrustStateUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompareAndSwap(ctx, nil, []byte("must not reach disk")); !errors.Is(err, context.Canceled) {
		t.Fatalf("CompareAndSwap error = %v, want context.Canceled", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state path after cancellation = %v, want absent", err)
	}
}

func TestFileSealedStateStoreInstanceGateIsContextCancelable(t *testing.T) {
	t.Parallel()

	path := filepath.Join(privateTestDirectory(t), "cancel-gate.state")
	protector := &blockingSealedStateProtector{
		started: make(chan struct{}), release: make(chan struct{}),
	}
	store, err := NewFileSealedStateStore(path, FileSealedStateStoreOptions{
		Protector: protector, Binding: []byte("cancel-gate-binding"), MaxEnvelopeBytes: 1024,
	})
	if errors.Is(err, ErrTrustStateUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	firstResult := make(chan error, 1)
	go func() {
		_, err := store.CompareAndSwap(context.Background(), nil, []byte("first"))
		firstResult <- err
	}()
	<-protector.started

	waitCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, _, err := store.Load(waitCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Load waiting for instance gate error = %v, want DeadlineExceeded", err)
	}
	close(protector.release)
	if err := <-firstResult; err != nil {
		t.Fatalf("first CompareAndSwap after release: %v", err)
	}
}

func TestFileSealedStateStoreRejectsProtectorSelfCheckFailure(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		protector SealedStateProtector
		maximum   int64
	}{
		{name: "open mismatch", protector: &mismatchingSealedStateProtector{}, maximum: 1024},
		{name: "mutating aliases", protector: &mutatingAliasingSealedStateProtector{}, maximum: 1024},
		{name: "oversized envelope", protector: &oversizedSealedStateProtector{}, maximum: 8},
		{name: "oversized opened plaintext", protector: &oversizedOpenSealedStateProtector{}, maximum: 8},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(privateTestDirectory(t), "self-check.state")
			store, err := NewFileSealedStateStore(path, FileSealedStateStoreOptions{
				Protector: test.protector, Binding: []byte("self-check-binding"), MaxEnvelopeBytes: test.maximum,
			})
			if errors.Is(err, ErrTrustStateUnsupported) {
				t.Skip(err)
			}
			if err != nil {
				t.Fatal(err)
			}
			if revision, err := store.CompareAndSwap(context.Background(), nil, []byte("value")); err == nil || !revision.IsZero() {
				t.Fatalf("CompareAndSwap = revision %s, error %v; want pre-install failure", revision, err)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("state path after protector failure = %v, want absent", err)
			}
		})
	}
}

func TestFileSealedStateStoreIsolatesProtectorAliases(t *testing.T) {
	t.Parallel()

	path := filepath.Join(privateTestDirectory(t), "protector-alias.state")
	store, err := NewFileSealedStateStore(path, FileSealedStateStoreOptions{
		Protector: &aliasingSealedStateProtector{}, Binding: []byte("alias-binding"), MaxEnvelopeBytes: 1024,
	})
	if errors.Is(err, ErrTrustStateUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	revision, err := store.CompareAndSwap(context.Background(), nil, []byte("alias-safe-value"))
	if err != nil || revision.IsZero() {
		t.Fatalf("CompareAndSwap = %s, %v", revision, err)
	}
	state, loadedRevision, found, err := store.Load(context.Background())
	if err != nil || !found || loadedRevision != revision || string(state) != "alias-safe-value" {
		t.Fatalf("Load = %q, %s, %v, %v", state, loadedRevision, found, err)
	}
}

func TestNewFileSealedStateStoreRejectsInvalidDependencies(t *testing.T) {
	t.Parallel()

	path := filepath.Join(privateTestDirectory(t), "invalid.state")
	var typedNil *cancelingSealedStateProtector
	for name, options := range map[string]FileSealedStateStoreOptions{
		"nil protector":       {Binding: []byte("binding")},
		"typed nil protector": {Protector: typedNil, Binding: []byte("binding")},
		"empty binding":       {Protector: &cancelingSealedStateProtector{}},
		"oversized binding": {
			Protector: &cancelingSealedStateProtector{},
			Binding:   make([]byte, FileSealedStateMaxBindingBytes+1),
		},
		"negative envelope limit": {
			Protector: &cancelingSealedStateProtector{}, Binding: []byte("binding"), MaxEnvelopeBytes: -1,
		},
	} {
		if _, err := NewFileSealedStateStore(path, options); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func FuzzParseSealedStateFileNeverPanics(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(sealedStateMagic[:])
	revision := SealedStateRevision{1}
	prefix := encodeSealedStatePrefix(revision, 1)
	f.Add(append(prefix, 0xa5))

	f.Fuzz(func(t *testing.T, data []byte) {
		prefix, parsedRevision, envelope, err := parseSealedStateFile(data, 4<<10)
		if err != nil {
			return
		}
		if parsedRevision.IsZero() {
			t.Fatal("accepted a zero revision")
		}
		if len(prefix) != sealedStateHeaderBytes || len(envelope) < 1 || len(envelope) > 4<<10 {
			t.Fatalf("accepted invalid sizes: prefix=%d envelope=%d", len(prefix), len(envelope))
		}
		if len(prefix)+len(envelope) != len(data) || !bytes.Equal(prefix, data[:len(prefix)]) {
			t.Fatal("parser returned slices inconsistent with the input")
		}
	})
}

type cancelingSealedStateProtector struct {
	cancel func()
}

type mismatchingSealedStateProtector struct{}

func (*mismatchingSealedStateProtector) Seal(context.Context, []byte, []byte) ([]byte, error) {
	return []byte("fixed-envelope"), nil
}

func (*mismatchingSealedStateProtector) Open(context.Context, []byte, []byte) ([]byte, error) {
	return []byte("different plaintext"), nil
}

type aliasingSealedStateProtector struct{}

func (*aliasingSealedStateProtector) Seal(_ context.Context, _ []byte, plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

func (*aliasingSealedStateProtector) Open(_ context.Context, _ []byte, envelope []byte) ([]byte, error) {
	return envelope, nil
}

type mutatingAliasingSealedStateProtector struct{}

func (*mutatingAliasingSealedStateProtector) Seal(_ context.Context, binding, plaintext []byte) ([]byte, error) {
	clear(binding)
	if len(plaintext) > 0 {
		plaintext[0] ^= 0xff
	}
	return plaintext, nil
}

func (*mutatingAliasingSealedStateProtector) Open(_ context.Context, binding, envelope []byte) ([]byte, error) {
	clear(binding)
	return envelope, nil
}

type oversizedSealedStateProtector struct{}

func (*oversizedSealedStateProtector) Seal(context.Context, []byte, []byte) ([]byte, error) {
	return make([]byte, 9), nil
}

func (*oversizedSealedStateProtector) Open(context.Context, []byte, []byte) ([]byte, error) {
	return nil, errors.New("must not open oversized envelope")
}

type oversizedOpenSealedStateProtector struct{}

func (*oversizedOpenSealedStateProtector) Seal(_ context.Context, _ []byte, plaintext []byte) ([]byte, error) {
	return append([]byte(nil), plaintext...), nil
}

func (*oversizedOpenSealedStateProtector) Open(context.Context, []byte, []byte) ([]byte, error) {
	return make([]byte, 9), nil
}

type blockingSealedStateProtector struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (protector *blockingSealedStateProtector) Seal(ctx context.Context, _ []byte, plaintext []byte) ([]byte, error) {
	protector.once.Do(func() { close(protector.started) })
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-protector.release:
	}
	return append([]byte{0xa5}, plaintext...), nil
}

func (*blockingSealedStateProtector) Open(_ context.Context, _ []byte, envelope []byte) ([]byte, error) {
	if len(envelope) < 1 || envelope[0] != 0xa5 {
		return nil, errors.New("invalid synthetic envelope")
	}
	return append([]byte(nil), envelope[1:]...), nil
}

func (*cancelingSealedStateProtector) KeyID() string { return "test-key" }

func (protector *cancelingSealedStateProtector) Seal(context.Context, []byte, []byte) ([]byte, error) {
	if protector.cancel != nil {
		protector.cancel()
	}
	return []byte("synthetic envelope"), nil
}

func (*cancelingSealedStateProtector) Open(context.Context, []byte, []byte) ([]byte, error) {
	return []byte("synthetic plaintext"), nil
}

func newInternalFileSealedStateStore(t *testing.T, path string, binding []byte) *FileSealedStateStore {
	t.Helper()
	key, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	protector, err := publisherstate.NewAESGCMProtector("internal-test-key", key)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewFileSealedStateStore(path, FileSealedStateStoreOptions{
		Protector: protector, Binding: binding,
	})
	if errors.Is(err, ErrTrustStateUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	return store
}
