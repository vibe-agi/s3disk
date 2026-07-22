//go:build windows

package s3disk_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/publisherstate"
)

func TestFileSealedStateStoreFailsClosedWhenWindowsSecretProofIsUnavailable(t *testing.T) {
	key, err := publisherstate.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	protector, err := publisherstate.NewAESGCMProtector("windows-test", key)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s3disk.NewFileSealedStateStore(
		filepath.Join(privateTestDirectory(t), "publisher.state"),
		s3disk.FileSealedStateStoreOptions{Protector: protector, Binding: []byte("windows-fail-closed")},
	)
	if !errors.Is(err, s3disk.ErrTrustStateUnsupported) {
		t.Fatalf("NewFileSealedStateStore error = %v, want ErrTrustStateUnsupported", err)
	}
}
