package s3disk

import (
	"bytes"
	"context"
	"math/rand"
	"testing"
)

func TestContentDefinedChunkingReusesChunksAfterMiddleInsertion(t *testing.T) {
	t.Parallel()

	original := make([]byte, 4<<20)
	_, _ = rand.New(rand.NewSource(101)).Read(original)
	insert := bytes.Repeat([]byte("inserted-data-"), 4096)
	changed := make([]byte, 0, len(original)+len(insert))
	changed = append(changed, original[:len(original)/2]...)
	changed = append(changed, insert...)
	changed = append(changed, original[len(original)/2:]...)
	opts := ChunkingOptions{MinSize: 16 << 10, AverageSize: 64 << 10, MaxSize: 256 << 10}

	first, err := chunkBytes(context.Background(), original, opts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := chunkBytes(context.Background(), changed, opts)
	if err != nil {
		t.Fatal(err)
	}
	secondSet := make(map[Digest]struct{}, len(second))
	for _, chunk := range second {
		secondSet[chunk.Digest] = struct{}{}
	}
	var reused int64
	for _, chunk := range first {
		if _, ok := secondSet[chunk.Digest]; ok {
			reused += chunk.Size
		}
	}
	if ratio := float64(reused) / float64(len(original)); ratio < 0.80 {
		t.Fatalf("reused %.1f%% of original bytes, want at least 80%%", ratio*100)
	}
}
