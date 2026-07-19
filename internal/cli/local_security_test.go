package cli

import (
	"path/filepath"
	"testing"
)

func TestProtectedPublisherSourceFilesCoversPublisherSecrets(t *testing.T) {
	t.Parallel()

	shareDirectory := filepath.Join(t.TempDir(), "share")
	recoveryKey := filepath.Join(t.TempDir(), "recovery-key.json")
	handoff := filepath.Join(t.TempDir(), "share.handoff")
	got := protectedPublisherSourceFiles(recoveryKey, handoff, shareDirectory)
	want := []struct {
		path         string
		allowMissing bool
	}{
		{path: recoveryKey},
		{path: filepath.Join(shareDirectory, publisherSessionFileName)},
		{path: filepath.Join(shareDirectory, publicationJournalFileName)},
		{path: filepath.Join(shareDirectory, rootRecoveryFileName)},
		{path: handoff, allowMissing: true},
	}
	if len(got) != len(want) {
		t.Fatalf("protected source files = %d, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index].Path != want[index].path ||
			got[index].AllowMissingInitially != want[index].allowMissing {
			t.Fatalf("protected source file %d = %+v, want path=%q allow_missing=%t",
				index, got[index], want[index].path, want[index].allowMissing)
		}
	}
}
