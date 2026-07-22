//go:build darwin && !cgo

package s3disk_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/vibe-agi/s3disk"
)

func TestDarwinTrustStateRequiresCgo(t *testing.T) {
	root := privateTestDirectory(t)
	if _, err := s3disk.NewFileWatermarkStore(filepath.Join(root, "main.watermark")); !errors.Is(err, s3disk.ErrTrustStateUnsupported) {
		t.Fatalf("NewFileWatermarkStore error = %v, want ErrTrustStateUnsupported", err)
	}
	if _, err := s3disk.NewFilePublicationJournal(filepath.Join(root, "publisher.journal")); !errors.Is(err, s3disk.ErrTrustStateUnsupported) {
		t.Fatalf("NewFilePublicationJournal error = %v, want ErrTrustStateUnsupported", err)
	}
	if _, err := s3disk.NewDiskCache(filepath.Join(root, "cache")); !errors.Is(err, s3disk.ErrTrustStateUnsupported) {
		t.Fatalf("NewDiskCache error = %v, want ErrTrustStateUnsupported", err)
	}
}
