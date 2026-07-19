package s3disk_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestStoreCompatibilityProbe(t *testing.T) {
	t.Parallel()
	repository, err := s3disk.NewRepository(memstore.New(), "compatibility")
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.CheckStoreCompatibility(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestStoreCompatibilityRejectsNonConditionalCAS(t *testing.T) {
	t.Parallel()
	base := memstore.New()
	repository, err := s3disk.NewRepository(&unconditionalCASStore{Store: base, base: base}, "broken-cas")
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.CheckStoreCompatibility(context.Background()); !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("compatibility error = %v, want ErrStoreIncompatible", err)
	}
}

func TestStoreCompatibilityRejectsUnconditionalNilCAS(t *testing.T) {
	t.Parallel()
	base := memstore.New()
	repository, err := s3disk.NewRepository(&unconditionalNilCASStore{Store: base, base: base}, "broken-nil-cas")
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.CheckStoreCompatibility(context.Background()); !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("compatibility error = %v, want ErrStoreIncompatible", err)
	}
}

func TestStoreCompatibilityRejectsNonAtomicReplacementCAS(t *testing.T) {
	t.Parallel()
	base := memstore.New()
	store := &nonAtomicReplacementCASStore{Store: base, base: base, gate: make(chan struct{})}
	repository, err := s3disk.NewRepository(store, "broken-replacement-cas")
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.CheckStoreCompatibility(context.Background()); !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("compatibility error = %v, want ErrStoreIncompatible", err)
	}
}

func TestStoreCompatibilityRejectsAdapterIgnoringReadLimit(t *testing.T) {
	t.Parallel()
	base := memstore.New()
	repository, err := s3disk.NewRepository(&ignoresReadLimitStore{Store: base}, "broken-limit")
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.CheckStoreCompatibility(context.Background()); !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("compatibility error = %v, want ErrStoreIncompatible", err)
	}
}

func TestStoreCompatibilityRejectsRetainedInputBuffer(t *testing.T) {
	t.Parallel()
	base := memstore.New()
	store := &retainedInputStore{Store: base, retained: make(map[string][]byte)}
	repository, err := s3disk.NewRepository(store, "broken-input-alias")
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.CheckStoreCompatibility(context.Background()); !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("compatibility error = %v, want ErrStoreIncompatible", err)
	}
}

func TestStoreCompatibilityRejectsAliasedOutputBuffer(t *testing.T) {
	t.Parallel()
	base := memstore.New()
	store := &aliasedOutputStore{Store: base, returned: make(map[string][]byte)}
	repository, err := s3disk.NewRepository(store, "broken-output-alias")
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.CheckStoreCompatibility(context.Background()); !errors.Is(err, s3disk.ErrStoreIncompatible) {
		t.Fatalf("compatibility error = %v, want ErrStoreIncompatible", err)
	}
}

type unconditionalCASStore struct {
	s3disk.Store
	base *memstore.Store
}

type unconditionalNilCASStore struct {
	s3disk.Store
	base *memstore.Store
}

type nonAtomicReplacementCASStore struct {
	s3disk.Store
	base *memstore.Store

	mu      sync.Mutex
	waiters int
	gate    chan struct{}
}

func (store *nonAtomicReplacementCASStore) CompareAndSwap(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
	if expected == nil || !strings.HasSuffix(key, "/concurrent-replace-cas") {
		return store.Store.CompareAndSwap(ctx, key, expected, data)
	}
	object, err := store.base.Get(ctx, key, s3disk.GetOptions{})
	if err != nil {
		return s3disk.Version{}, err
	}
	if object.Version.ETag != expected.ETag {
		return s3disk.Version{}, s3disk.ErrPrecondition
	}
	store.mu.Lock()
	store.waiters++
	if store.waiters == 8 {
		close(store.gate)
	}
	gate := store.gate
	store.mu.Unlock()
	select {
	case <-gate:
	case <-ctx.Done():
		return s3disk.Version{}, ctx.Err()
	}
	store.base.ForcePut(key, data)
	updated, err := store.base.Get(ctx, key, s3disk.GetOptions{})
	return updated.Version, err
}

func (store *unconditionalNilCASStore) CompareAndSwap(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
	if expected != nil {
		return store.Store.CompareAndSwap(ctx, key, expected, data)
	}
	store.base.ForcePut(key, data)
	object, err := store.base.Get(ctx, key, s3disk.GetOptions{})
	return object.Version, err
}

type ignoresReadLimitStore struct{ s3disk.Store }

func (store *ignoresReadLimitStore) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	options.MaxBytes = 0
	return store.Store.Get(ctx, key, options)
}

type retainedInputStore struct {
	s3disk.Store
	mu       sync.Mutex
	retained map[string][]byte
}

func (store *retainedInputStore) PutIfAbsent(ctx context.Context, key string, data []byte) (s3disk.Version, error) {
	version, err := store.Store.PutIfAbsent(ctx, key, data)
	if err == nil {
		store.mu.Lock()
		store.retained[key] = data
		store.mu.Unlock()
	}
	return version, err
}

func (store *retainedInputStore) CompareAndSwap(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
	version, err := store.Store.CompareAndSwap(ctx, key, expected, data)
	if err == nil {
		store.mu.Lock()
		store.retained[key] = data
		store.mu.Unlock()
	}
	return version, err
}

func (store *retainedInputStore) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	object, err := store.Store.Get(ctx, key, options)
	if err != nil {
		return object, err
	}
	store.mu.Lock()
	retained := store.retained[key]
	object.Data = append([]byte(nil), retained...)
	store.mu.Unlock()
	return object, nil
}

type aliasedOutputStore struct {
	s3disk.Store
	mu       sync.Mutex
	returned map[string][]byte
}

func (store *aliasedOutputStore) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	object, err := store.Store.Get(ctx, key, options)
	if err != nil {
		return object, err
	}
	store.mu.Lock()
	if previous := store.returned[key]; previous != nil {
		object.Data = previous
	} else {
		store.returned[key] = object.Data
	}
	store.mu.Unlock()
	return object, nil
}

func (store *unconditionalCASStore) CompareAndSwap(ctx context.Context, key string, _ *s3disk.Version, data []byte) (s3disk.Version, error) {
	store.base.ForcePut(key, data)
	object, err := store.base.Get(ctx, key, s3disk.GetOptions{})
	return object.Version, err
}
