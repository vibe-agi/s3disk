package s3disk

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPublisherRejectsImpossibleChunkCountBeforeUploading(t *testing.T) {
	t.Parallel()

	store := new(resourceProbeStore)
	repository, err := NewRepository(store, "chunk-count-preflight")
	if err != nil {
		t.Fatal(err)
	}
	options := ChunkingOptions{MinSize: 64, AverageSize: 128, MaxSize: 129}
	publisher, err := NewPublisher(repository, PublisherOptions{DangerouslyAllowUncommissionedRepository: true, Chunking: options})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	file := filepath.Join(source, "too-many-chunks")
	handle, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	tooLarge := int64(maxFileChunks)*int64(options.MaxSize) + 1
	if err := handle.Truncate(tooLarge); err != nil {
		_ = handle.Close()
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := publisher.Stage(context.Background(), source, "main"); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("Stage error = %v, want ErrResourceLimit", err)
	}
	if puts := store.chunkPuts.Load(); puts != 0 {
		t.Fatalf("preflight uploaded %d chunks before rejecting an impossible file", puts)
	}
}

func TestBuildFileClassifiesDisappearanceAfterDirectoryScanAsUnstable(t *testing.T) {
	t.Parallel()

	source := privateTestDirectory(t)
	name := "vanished"
	filename := filepath.Join(source, name)
	if err := os.WriteFile(filename, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	expected, err := os.Lstat(filename)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(source)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Remove(filename); err != nil {
		t.Fatal(err)
	}

	publisher := &Publisher{options: PublisherOptions{StableReadTries: 1}}
	_, _, _, err = publisher.buildFile(context.Background(), root, name, expected, nil)
	if !errors.Is(err, ErrUnstableFile) {
		t.Fatalf("buildFile error = %v, want ErrUnstableFile", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("buildFile error = %v, want os.ErrNotExist detail", err)
	}
}

type resourceProbeStore struct {
	chunkPuts atomic.Int64
}

func (*resourceProbeStore) Get(context.Context, string, GetOptions) (Object, error) {
	return Object{}, ErrObjectNotFound
}

func (*resourceProbeStore) Head(context.Context, string) (Version, error) {
	return Version{}, ErrObjectNotFound
}

func (store *resourceProbeStore) PutIfAbsent(_ context.Context, key string, _ []byte) (Version, error) {
	if strings.Contains(key, "/objects/chunk/") {
		store.chunkPuts.Add(1)
	}
	return Version{ETag: "probe"}, nil
}

func (*resourceProbeStore) CompareAndSwap(context.Context, string, *Version, []byte) (Version, error) {
	return Version{ETag: "probe"}, nil
}

var _ Store = (*resourceProbeStore)(nil)
