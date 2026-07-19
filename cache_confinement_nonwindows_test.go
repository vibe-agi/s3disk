//go:build !windows

package s3disk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDiskCacheRejectsReplacedDigestRootWithoutExternalEffects(t *testing.T) {
	ctx := context.Background()
	cache, err := NewDiskCacheWithOptions(privateTestDirectory(t), DiskCacheOptions{
		MaxBytes:      64,
		MaxChunkBytes: 32,
		MaxEntries:    1,
	})
	if err != nil {
		t.Fatal(err)
	}
	closeTestDiskCache(t, cache)
	oldData := []byte("cached-before-replacement")
	oldDigest := digestObject("chunk", oldData)
	if err := cache.Put(ctx, oldDigest, oldData); err != nil {
		t.Fatal(err)
	}

	originalDigestRoot := cache.chunksRoot + ".original"
	if err := os.Rename(cache.chunksRoot, originalDigestRoot); err != nil {
		t.Fatal(err)
	}
	external := privateTestDirectory(t)
	victim := filepath.Join(external, oldDigest.String()[:2], oldDigest.String())
	if err := os.MkdirAll(filepath.Dir(victim), 0o700); err != nil {
		t.Fatal(err)
	}
	victimData := []byte("must-not-be-read-or-removed")
	if err := os.WriteFile(victim, victimData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, cache.chunksRoot); err != nil {
		t.Fatal(err)
	}

	if data, found, err := cache.Get(ctx, oldDigest); !errors.Is(err, ErrCorruptObject) || found || data != nil {
		t.Fatalf("Get after digest-root replacement = (%q, %v, %v), want fail-closed ErrCorruptObject", data, found, err)
	}
	newData, newDigest := digestWithDifferentShard(t, oldDigest.String()[:2])
	if err := cache.Put(ctx, newDigest, newData); !errors.Is(err, ErrCorruptObject) {
		t.Fatalf("Put after digest-root replacement error = %v, want ErrCorruptObject", err)
	}
	assertFileContents(t, victim, victimData)
	if _, err := os.Lstat(filepath.Join(external, newDigest.String()[:2], newDigest.String())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement target contains new cache entry: %v", err)
	}
	externalEntries, err := os.ReadDir(external)
	if err != nil {
		t.Fatal(err)
	}
	if len(externalEntries) != 1 || externalEntries[0].Name() != oldDigest.String()[:2] {
		t.Fatalf("external digest root changed: %v", directoryEntryNames(externalEntries))
	}
	externalShardEntries, err := os.ReadDir(filepath.Dir(victim))
	if err != nil {
		t.Fatal(err)
	}
	if len(externalShardEntries) != 1 || externalShardEntries[0].Name() != oldDigest.String() {
		t.Fatalf("external digest shard changed: %v", directoryEntryNames(externalShardEntries))
	}
	assertFileContents(t, filepath.Join(originalDigestRoot, oldDigest.String()[:2], oldDigest.String()), oldData)
}

func TestDiskCacheRejectsReplacedShardDuringWriteReadAndEviction(t *testing.T) {
	ctx := context.Background()
	cache, err := NewDiskCacheWithOptions(privateTestDirectory(t), DiskCacheOptions{
		MaxBytes:      64,
		MaxChunkBytes: 32,
		MaxEntries:    1,
	})
	if err != nil {
		t.Fatal(err)
	}
	closeTestDiskCache(t, cache)
	oldData := []byte("cached-in-original-shard")
	oldDigest := digestObject("chunk", oldData)
	if err := cache.Put(ctx, oldDigest, oldData); err != nil {
		t.Fatal(err)
	}

	shard := filepath.Dir(cache.chunkPath(oldDigest))
	originalShard := shard + ".original"
	if err := os.Rename(shard, originalShard); err != nil {
		t.Fatal(err)
	}
	externalShard := privateTestDirectory(t)
	victim := filepath.Join(externalShard, oldDigest.String())
	victimData := []byte("external-victim")
	if err := os.WriteFile(victim, victimData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(externalShard, shard); err != nil {
		t.Fatal(err)
	}

	if data, found, err := cache.Get(ctx, oldDigest); !errors.Is(err, ErrCorruptObject) || found || data != nil {
		t.Fatalf("Get after shard replacement = (%q, %v, %v), want fail-closed ErrCorruptObject", data, found, err)
	}
	if err := cache.Put(ctx, oldDigest, oldData); !errors.Is(err, ErrCorruptObject) {
		t.Fatalf("Put through replaced shard error = %v, want ErrCorruptObject", err)
	}

	newData, newDigest := digestWithDifferentShard(t, oldDigest.String()[:2])
	if err := cache.Put(ctx, newDigest, newData); !errors.Is(err, ErrCorruptObject) {
		t.Fatalf("Put requiring eviction through replaced shard error = %v, want ErrCorruptObject", err)
	}
	assertFileContents(t, victim, victimData)
	entries, err := os.ReadDir(externalShard)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != oldDigest.String() {
		t.Fatalf("external shard changed: %v", directoryEntryNames(entries))
	}
	if _, err := os.Lstat(cache.chunkPath(newDigest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed Put left a new cache entry: %v", err)
	}
	assertFileContents(t, filepath.Join(originalShard, oldDigest.String()), oldData)
}

func digestWithDifferentShard(t *testing.T, excluded string) ([]byte, Digest) {
	t.Helper()
	for attempt := 0; attempt < 1024; attempt++ {
		data := []byte(fmt.Sprintf("replacement-%d", attempt))
		digest := digestObject("chunk", data)
		if digest.String()[:2] != excluded {
			return data, digest
		}
	}
	t.Fatal("could not produce a digest in a different shard")
	return nil, Digest{}
}

func assertFileContents(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("file %q = %q, want %q", path, got, want)
	}
}

func directoryEntryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}
