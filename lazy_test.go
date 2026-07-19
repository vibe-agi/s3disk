package s3disk_test

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestMetadataOperationsDoNotFetchFileChunks(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memstore.New()
	repo, err := s3disk.NewRepository(store, "lazy")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repo, s3disk.PublisherOptions{
		Chunking: s3disk.ChunkingOptions{
			MinSize:     64,
			AverageSize: 256,
			MaxSize:     1024,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	data := make([]byte, 16*1024)
	_, _ = rand.New(rand.NewSource(11)).Read(data)
	if err := os.WriteFile(filepath.Join(source, "large.bin"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(source, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "nested", "other.bin"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}

	consumer := newConsumer(t, repo, "main")
	if _, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	store.ResetStats()

	entries, err := consumer.ListDir(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("root entries = %d, want 2", len(entries))
	}
	if _, err := consumer.Stat(ctx, "large.bin"); err != nil {
		t.Fatal(err)
	}
	file, err := consumer.Open(ctx, "large.bin")
	if err != nil {
		t.Fatal(err)
	}
	if stats := store.Stats(); stats.ChunkGets != 0 || stats.ChunkBytesRead != 0 {
		t.Fatalf("metadata/open fetched chunks: %+v", stats)
	}

	buf := make([]byte, 32)
	if _, err := file.ReadAtContext(ctx, buf, 4*1024); err != nil {
		t.Fatal(err)
	}
	stats := store.Stats()
	if stats.ChunkGets != 1 {
		t.Fatalf("one small read fetched %d chunks, want 1", stats.ChunkGets)
	}
	if stats.ChunkBytesRead >= int64(len(data)) {
		t.Fatalf("read transferred %d bytes, whole file is %d", stats.ChunkBytesRead, len(data))
	}

	store.ResetStats()
	if _, err := file.ReadAtContext(ctx, buf, 4*1024); err != nil {
		t.Fatal(err)
	}
	if stats := store.Stats(); stats.ChunkGets != 0 {
		t.Fatalf("second read missed disk cache: %+v", stats)
	}
}
