package s3disk

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRepositoryRejectsObjectKeysBeyondS3LimitBeforeIO(t *testing.T) {
	t.Parallel()
	store := new(resourceProbeStore)
	withoutPrefix, err := NewRepository(store, "")
	if err != nil {
		t.Fatal(err)
	}
	fixedBytes := len(withoutPrefix.objectKey("symlink", Digest{}))
	maximumPrefix := strings.Repeat("p", maxObjectKeyBytes-fixedBytes-1)
	repository, err := NewRepository(store, maximumPrefix)
	if err != nil {
		t.Fatalf("maximum repository prefix: %v", err)
	}
	if got := len(repository.objectKey("symlink", Digest{})); got != maxObjectKeyBytes {
		t.Fatalf("maximum immutable key length = %d, want %d", got, maxObjectKeyBytes)
	}
	if _, err := NewRepository(store, maximumPrefix+"p"); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("oversized repository prefix error = %v, want ErrInvalidPath", err)
	}

	baseBytes := len(repository.SignedReferenceKey(""))
	channel := ""
	for length := 1; ; length++ {
		candidate := strings.Repeat("c", length)
		if len(repository.SignedReferenceKey(candidate)) > maxObjectKeyBytes {
			break
		}
		channel = candidate
	}
	if channel == "" || baseBytes >= maxObjectKeyBytes {
		t.Fatalf("test prefix leaves no channel capacity: base=%d", baseBytes)
	}
	if err := repository.validateChannel(channel); err != nil {
		t.Fatalf("maximum fitting channel: %v", err)
	}
	if err := repository.validateChannel(channel + "c"); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("oversized channel error = %v, want ErrInvalidPath", err)
	}
	if store.chunkPuts.Load() != 0 {
		t.Fatal("key validation performed object-store I/O")
	}

	// The public entry point must reject the key before reading the source or
	// touching the store as well.
	publisher, err := NewPublisher(repository, PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Stage(context.Background(), privateTestDirectory(t), channel+"c"); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("Stage oversized channel error = %v, want ErrInvalidPath", err)
	}
}
