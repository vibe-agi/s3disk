//go:build darwin && cgo

package localstate_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/internal/localstate"
)

func privateTestDirectory(t testing.TB) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("protect test directory: %v", err)
	}
	return directory
}

func addDarwinACLEntry(t *testing.T, path, entry string) {
	t.Helper()
	output, err := exec.Command("/bin/chmod", "+a", entry, path).CombinedOutput()
	if err != nil {
		t.Fatalf("chmod +a %q: %v: %s", path, err, output)
	}
}

func TestDarwinTrustStateRejectsDirectoryExtendedACL(t *testing.T) {
	directory := filepath.Join(privateTestDirectory(t), "state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	addDarwinACLEntry(t, directory, "everyone allow add_file,delete_child")

	_, err := s3disk.NewFileWatermarkStore(filepath.Join(directory, "main.watermark"))
	if !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("NewFileWatermarkStore ACL error = %v, want ErrCorruptObject", err)
	}
}

func TestDarwinTrustStateRevalidatesExtendedACLs(t *testing.T) {
	newStore := func(t *testing.T) (string, *s3disk.FileWatermarkStore) {
		t.Helper()
		path := filepath.Join(privateTestDirectory(t), "main.watermark")
		store, err := s3disk.NewFileWatermarkStore(path)
		if err != nil {
			t.Fatal(err)
		}
		watermark := s3disk.Watermark{RepositoryID: s3disk.RepositoryID{1}, Generation: 1, Commit: s3disk.Digest{2}}
		if err := store.CompareAndSwap(context.Background(), "main", nil, watermark); err != nil {
			t.Fatal(err)
		}
		return path, store
	}

	t.Run("ancestor", func(t *testing.T) {
		path, store := newStore(t)
		addDarwinACLEntry(t, filepath.Dir(path), "everyone allow add_file,delete_child")
		if _, _, err := store.Load(context.Background(), "main"); !errors.Is(err, s3disk.ErrCorruptObject) {
			t.Fatalf("Load with ancestor ACL error = %v, want ErrCorruptObject", err)
		}
	})

	t.Run("lock", func(t *testing.T) {
		path, store := newStore(t)
		addDarwinACLEntry(t, path+".lock", "everyone allow write,append")
		if _, _, err := store.Load(context.Background(), "main"); !errors.Is(err, s3disk.ErrCorruptObject) {
			t.Fatalf("Load with lock ACL error = %v, want ErrCorruptObject", err)
		}
	})

	t.Run("state", func(t *testing.T) {
		path, store := newStore(t)
		addDarwinACLEntry(t, path, "everyone allow write,append")
		if info, err := os.Stat(path); err != nil {
			t.Fatal(err)
		} else if info.Mode().Perm() != 0o600 {
			t.Fatalf("state mode after chmod +a = %o, want hidden ACL with mode 0600", info.Mode().Perm())
		}
		if _, _, err := store.Load(context.Background(), "main"); !errors.Is(err, s3disk.ErrCorruptObject) {
			t.Fatalf("Load with state ACL error = %v, want ErrCorruptObject", err)
		}
	})
}

func TestProtectWatermarkFileRejectsInheritedDarwinACL(t *testing.T) {
	directory := privateTestDirectory(t)
	addDarwinACLEntry(t, directory, "everyone allow write,append,file_inherit")
	file, err := os.CreateTemp(directory, "state-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if err := localstate.ProtectFile(file.Name(), file); !errors.Is(err, localstate.ErrUnsafe) {
		t.Fatalf("protectWatermarkFile inherited ACL error = %v, want ErrCorruptObject", err)
	}
	if info, err := file.Stat(); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("temporary mode after protection = %o, want 0600", info.Mode().Perm())
	}
}

func TestFilePublicationJournalRevalidatesDarwinLockACL(t *testing.T) {
	path := filepath.Join(privateTestDirectory(t), "publisher.journal")
	journal, err := s3disk.NewFilePublicationJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, found, err := journal.Load(context.Background(), "main"); err != nil || found {
		t.Fatalf("initial journal Load found=%v error=%v", found, err)
	}
	addDarwinACLEntry(t, path+".lock", "everyone allow write,append")
	if _, _, _, err := journal.Load(context.Background(), "main"); !errors.Is(err, s3disk.ErrCorruptObject) {
		t.Fatalf("journal Load with lock ACL error = %v, want ErrCorruptObject", err)
	}
}
