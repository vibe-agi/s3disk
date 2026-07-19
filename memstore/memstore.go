// Package memstore provides an in-memory s3disk.Store with counters and test
// hooks. It is useful for deterministic unit and fault-injection tests.
package memstore

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/vibe-agi/s3disk"
)

type record struct {
	data    []byte
	version s3disk.Version
}

// Stats reports object-store work since construction or ResetStats.
type Stats struct {
	Gets           int64
	Heads          int64
	Puts           int64
	BytesRead      int64
	BytesWritten   int64
	ChunkGets      int64
	ChunkBytesRead int64
	ChunkPuts      int64
}

type Store struct {
	mu      sync.Mutex
	objects map[string]record
	serial  uint64
	stats   Stats
}

func New() *Store { return &Store{objects: make(map[string]record)} }

func (store *Store) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	if err := ctx.Err(); err != nil {
		return s3disk.Object{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.objects[key]
	if !ok {
		return s3disk.Object{}, s3disk.ErrObjectNotFound
	}
	if options.IfNoneMatch != "" && options.IfNoneMatch == record.version.ETag {
		return s3disk.Object{}, s3disk.ErrNotModified
	}
	if options.MaxBytes < 0 {
		return s3disk.Object{}, fmt.Errorf("%w: negative read limit", s3disk.ErrResourceLimit)
	}
	if options.MaxBytes > 0 && int64(len(record.data)) > options.MaxBytes {
		return s3disk.Object{}, fmt.Errorf("%w: object exceeds %d bytes", s3disk.ErrResourceLimit, options.MaxBytes)
	}
	data := append([]byte(nil), record.data...)
	store.stats.Gets++
	store.stats.BytesRead += int64(len(data))
	if isChunk(key) {
		store.stats.ChunkGets++
		store.stats.ChunkBytesRead += int64(len(data))
	}
	return s3disk.Object{Data: data, Version: record.version}, nil
}

func (store *Store) Head(ctx context.Context, key string) (s3disk.Version, error) {
	if err := ctx.Err(); err != nil {
		return s3disk.Version{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.stats.Heads++
	record, ok := store.objects[key]
	if !ok {
		return s3disk.Version{}, s3disk.ErrObjectNotFound
	}
	return record.version, nil
}

func (store *Store) PutIfAbsent(ctx context.Context, key string, data []byte) (s3disk.Version, error) {
	if err := ctx.Err(); err != nil {
		return s3disk.Version{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.objects[key]; exists {
		return s3disk.Version{}, s3disk.ErrPrecondition
	}
	return store.putLocked(key, data), nil
}

func (store *Store) CompareAndSwap(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
	if err := ctx.Err(); err != nil {
		return s3disk.Version{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	current, exists := store.objects[key]
	if expected == nil {
		if exists {
			return s3disk.Version{}, s3disk.ErrPrecondition
		}
	} else {
		if expected.ETag == "" {
			return s3disk.Version{}, fmt.Errorf("memstore: compare-and-swap requires an ETag")
		}
		if !exists || current.version.ETag != expected.ETag {
			return s3disk.Version{}, s3disk.ErrPrecondition
		}
	}
	return store.putLocked(key, data), nil
}

func (store *Store) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.objects, key)
	return nil
}

func (store *Store) putLocked(key string, data []byte) s3disk.Version {
	store.serial++
	sum := sha256.Sum256(data)
	version := s3disk.Version{
		ETag:      fmt.Sprintf("\"%x\"", sum),
		VersionID: fmt.Sprintf("memory-%d", store.serial),
	}
	store.objects[key] = record{data: append([]byte(nil), data...), version: version}
	store.stats.Puts++
	store.stats.BytesWritten += int64(len(data))
	if isChunk(key) {
		store.stats.ChunkPuts++
	}
	return version
}

// ForcePut bypasses compare-and-swap and exists only for consistency and
// fault-injection tests.
func (store *Store) ForcePut(key string, data []byte) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.putLocked(key, data)
}

func (store *Store) Stats() Stats {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.stats
}

func (store *Store) ResetStats() {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.stats = Stats{}
}

func isChunk(key string) bool { return strings.Contains(key, "/objects/chunk/") }

var (
	_ s3disk.Store         = (*Store)(nil)
	_ s3disk.ObjectDeleter = (*Store)(nil)
	_                      = errors.Is
)
