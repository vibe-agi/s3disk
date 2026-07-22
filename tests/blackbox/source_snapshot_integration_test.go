//go:build integration

package s3disk_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

// TestAtomicSourceSnapshotPublication is driven by the platform snapshot drill
// scripts. They provide two mounts of the same source volume: a frozen,
// read-only point-in-time view and a writable live view which has already
// advanced. Continuous writes to the live view while Publisher scans the
// frozen mount prove the publication boundary is the mounted snapshot path.
func TestAtomicSourceSnapshotPublication(t *testing.T) {
	snapshotSource := os.Getenv("S3DISK_TEST_SNAPSHOT_SOURCE")
	liveSource := os.Getenv("S3DISK_TEST_LIVE_SOURCE")
	if snapshotSource == "" || liveSource == "" {
		t.Skip("platform snapshot source mounts are not configured")
	}
	const (
		markerPath     = "workspace/marker.txt"
		frozenContents = "frozen-before-snapshot\n"
	)
	if data, err := os.ReadFile(filepath.Join(snapshotSource, markerPath)); err != nil || string(data) != frozenContents {
		t.Fatalf("snapshot marker = %q, %v", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(liveSource, markerPath)); err != nil || string(data) == frozenContents {
		t.Fatalf("live marker did not advance after snapshot: %q, %v", data, err)
	}
	if err := os.WriteFile(filepath.Join(snapshotSource, "must-remain-read-only"), []byte("write"), 0o600); err == nil {
		t.Fatal("snapshot source mount accepted a write")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	writeErrors := make(chan error, 1)
	writeObserved := make(chan struct{}, 1)
	stopWrites := make(chan struct{})
	writesStopped := make(chan struct{})
	go func() {
		defer close(writesStopped)
		for generation := byte(0); ; generation++ {
			select {
			case <-stopWrites:
				return
			default:
			}
			contents := []byte("live-after-snapshot-a\n")
			if generation%2 == 1 {
				contents = []byte("live-after-snapshot-b\n")
			}
			if err := os.WriteFile(filepath.Join(liveSource, markerPath), contents, 0o600); err != nil {
				select {
				case writeErrors <- err:
				default:
				}
				return
			}
			select {
			case writeObserved <- struct{}{}:
			default:
			}
			time.Sleep(time.Millisecond)
		}
	}()
	defer func() {
		close(stopWrites)
		<-writesStopped
	}()
	select {
	case <-writeObserved:
	case err := <-writeErrors:
		t.Fatalf("start live-source mutation: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "atomic-source-snapshot")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := publisher.Publish(ctx, snapshotSource, "main")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Generation != 1 {
		t.Fatalf("published generation = %d, want 1", snapshot.Generation)
	}
	select {
	case err := <-writeErrors:
		t.Fatalf("mutate live source during frozen publication: %v", err)
	default:
	}

	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := consumer.Refresh(ctx); err != nil || result.Generation != 1 {
		t.Fatalf("refresh frozen publication = %+v, %v", result, err)
	}
	file, err := consumer.Open(ctx, markerPath)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, file.Size())
	if _, err := file.ReadAtContext(ctx, data, 0); err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if string(data) != frozenContents {
		t.Fatalf("published marker = %q, want frozen contents", data)
	}
	if data, err := os.ReadFile(filepath.Join(snapshotSource, markerPath)); err != nil || string(data) != frozenContents {
		t.Fatalf("snapshot marker changed during live writes: %q, %v", data, err)
	}
}
