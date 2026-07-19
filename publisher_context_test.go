package s3disk

import (
	"context"
	"errors"
	"testing"
)

func TestPublisherSourceEntryPointsRejectCanceledContextBeforeFilesystemWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	missing := t.TempDir() + "/must-not-be-inspected"

	var publisher *Publisher
	if _, err := publisher.Stage(ctx, missing, "main"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Stage canceled error = %v, want context.Canceled", err)
	}
	if err := publisher.Watch(ctx, missing, "main", WatchOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Watch canceled error = %v, want context.Canceled", err)
	}
}
