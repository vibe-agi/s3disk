package s3disk_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestPublisherRejectsProtectedSourceHardLinkBeforeChunkUpload(t *testing.T) {
	t.Parallel()

	protectedDirectory := privateTestDirectory(t)
	protectedPath := filepath.Join(protectedDirectory, "private-location-must-not-leak")
	secret := []byte("publisher recovery secret must never reach object storage")
	writeFile(t, protectedPath, secret)
	source := privateTestDirectory(t)
	linkPath := filepath.Join(source, "source-alias")
	requireHardLink(t, protectedPath, linkPath)

	publisher, store := newProtectedSourcePublisher(t, []s3disk.ProtectedSourceFile{{Path: protectedPath}})
	store.ResetStats()
	_, err := publisher.Stage(context.Background(), source, "main")
	if !errors.Is(err, s3disk.ErrProtectedSourceFile) {
		t.Fatalf("Stage error = %v, want ErrProtectedSourceFile", err)
	}
	if stats := store.Stats(); stats.ChunkPuts != 0 {
		t.Fatalf("chunk puts = %d, want zero before protected source rejection", stats.ChunkPuts)
	}
	if strings.Contains(err.Error(), protectedPath) || strings.Contains(err.Error(), string(secret)) {
		t.Fatalf("protected-source error disclosed protected path or bytes: %q", err)
	}
}

func TestPublisherProtectedSourceSelectedProjection(t *testing.T) {
	t.Parallel()

	protectedPath := filepath.Join(privateTestDirectory(t), "secret")
	writeFile(t, protectedPath, []byte("secret bytes"))
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "public.txt"), []byte("public bytes"))
	requireHardLink(t, protectedPath, filepath.Join(source, "unselected-secret"))

	publisher, _ := newProtectedSourcePublisher(t, []s3disk.ProtectedSourceFile{{Path: protectedPath}})
	if _, err := publisher.StageSelected(
		context.Background(), source, "public", []string{"public.txt"},
	); err != nil {
		t.Fatalf("StageSelected unselected alias: %v", err)
	}
	if _, err := publisher.StageSelected(
		context.Background(), source, "secret", []string{"unselected-secret"},
	); !errors.Is(err, s3disk.ErrProtectedSourceFile) {
		t.Fatalf("StageSelected protected alias error = %v, want ErrProtectedSourceFile", err)
	}
}

func TestPublisherProtectedSourceAllowsIndependentCopy(t *testing.T) {
	t.Parallel()

	contents := []byte("identical bytes are not a filesystem alias")
	protectedPath := filepath.Join(privateTestDirectory(t), "protected")
	writeFile(t, protectedPath, contents)
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "copy"), contents)
	publisher, _ := newProtectedSourcePublisher(t, []s3disk.ProtectedSourceFile{{Path: protectedPath}})
	if _, err := publisher.Publish(context.Background(), source, "main"); err != nil {
		t.Fatalf("Publish independent copy: %v", err)
	}
}

func TestPublisherProtectedSourceAppearsAndThenCannotDisappear(t *testing.T) {
	t.Parallel()

	protectedPath := filepath.Join(privateTestDirectory(t), "later-secret")
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "public.txt"), []byte("public bytes"))
	publisher, _ := newProtectedSourcePublisher(t, []s3disk.ProtectedSourceFile{{
		Path: protectedPath, AllowMissingInitially: true,
	}})
	if _, err := publisher.Publish(context.Background(), source, "main"); err != nil {
		t.Fatalf("Publish while protected output is initially absent: %v", err)
	}

	writeFile(t, protectedPath, []byte("created after publisher construction"))
	alias := filepath.Join(source, "later-alias")
	requireHardLink(t, protectedPath, alias)
	if _, err := publisher.Stage(context.Background(), source, "main"); !errors.Is(err, s3disk.ErrProtectedSourceFile) {
		t.Fatalf("Stage after protected output creation error = %v, want ErrProtectedSourceFile", err)
	}
	if err := os.Remove(protectedPath); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Stage(context.Background(), source, "main"); !errors.Is(err, s3disk.ErrProtectedSourceFile) {
		t.Fatalf("Stage after observed protected output disappeared = %v, want ErrProtectedSourceFile", err)
	}
}

func TestPublisherInitiallyOptionalProtectedSourceCannotDisappearAfterConstruction(t *testing.T) {
	t.Parallel()

	protectedPath := filepath.Join(privateTestDirectory(t), "existing-secret")
	writeFile(t, protectedPath, []byte("secret"))
	source := privateTestDirectory(t)
	requireHardLink(t, protectedPath, filepath.Join(source, "old-inode-alias"))
	publisher, _ := newProtectedSourcePublisher(t, []s3disk.ProtectedSourceFile{{
		Path: protectedPath, AllowMissingInitially: true,
	}})
	if err := os.Remove(protectedPath); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Stage(context.Background(), source, "main"); !errors.Is(err, s3disk.ErrProtectedSourceFile) {
		t.Fatalf("Stage after initially observed protected path disappeared = %v, want ErrProtectedSourceFile", err)
	}
}

func TestPublisherInitiallyMissingProtectionLatchesInvalidAppearance(t *testing.T) {
	t.Parallel()

	directory := privateTestDirectory(t)
	protectedPath := filepath.Join(directory, "later-protected")
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "public"), []byte("public"))
	publisher, _ := newProtectedSourcePublisher(t, []s3disk.ProtectedSourceFile{{
		Path: protectedPath, AllowMissingInitially: true,
	}})
	if _, err := publisher.Publish(context.Background(), source, "main"); err != nil {
		t.Fatalf("initial Publish: %v", err)
	}
	target := filepath.Join(directory, "target")
	writeFile(t, target, []byte("secret"))
	if err := os.Symlink(target, protectedPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := publisher.Stage(context.Background(), source, "main"); !errors.Is(err, s3disk.ErrProtectedSourceFile) {
		t.Fatalf("Stage with invalid protected symlink = %v, want ErrProtectedSourceFile", err)
	}
	if err := os.Remove(protectedPath); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Stage(context.Background(), source, "main"); !errors.Is(err, s3disk.ErrProtectedSourceFile) {
		t.Fatalf("Stage after invalid protected pathname disappeared = %v, want latched ErrProtectedSourceFile", err)
	}
}

func TestPublisherProtectedSourcePinsReplacementOnEveryStage(t *testing.T) {
	t.Parallel()

	directory := privateTestDirectory(t)
	protectedPath := filepath.Join(directory, "rotating-secret")
	writeFile(t, protectedPath, []byte("old secret"))
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "public"), []byte("public"))
	publisher, _ := newProtectedSourcePublisher(t, []s3disk.ProtectedSourceFile{{Path: protectedPath}})
	if _, err := publisher.Publish(context.Background(), source, "main"); err != nil {
		t.Fatalf("initial Publish: %v", err)
	}

	replacement := filepath.Join(directory, "replacement")
	writeFile(t, replacement, []byte("new secret with a new identity"))
	if err := os.Remove(protectedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, protectedPath); err != nil {
		t.Fatal(err)
	}
	requireHardLink(t, protectedPath, filepath.Join(source, "new-secret-alias"))
	if _, err := publisher.Stage(context.Background(), source, "main"); !errors.Is(err, s3disk.ErrProtectedSourceFile) {
		t.Fatalf("Stage after protected file replacement = %v, want ErrProtectedSourceFile", err)
	}
}

func TestPublisherProtectedSourceConfigurationIsClonedAndFailsClosed(t *testing.T) {
	t.Parallel()

	protectedPath := filepath.Join(privateTestDirectory(t), "protected")
	writeFile(t, protectedPath, []byte("secret"))
	source := privateTestDirectory(t)
	requireHardLink(t, protectedPath, filepath.Join(source, "alias"))
	configured := []s3disk.ProtectedSourceFile{{Path: protectedPath}}
	publisher, _ := newProtectedSourcePublisher(t, configured)
	configured[0].Path = filepath.Join(t.TempDir(), "caller-mutated")
	if _, err := publisher.Stage(context.Background(), source, "main"); !errors.Is(err, s3disk.ErrProtectedSourceFile) {
		t.Fatalf("Stage after caller mutated options = %v, want ErrProtectedSourceFile", err)
	}

	missing := filepath.Join(t.TempDir(), "required-but-missing")
	required, _ := newProtectedSourcePublisher(t, []s3disk.ProtectedSourceFile{{Path: missing}})
	_, err := required.Stage(context.Background(), source, "required")
	if !errors.Is(err, s3disk.ErrProtectedSourceFile) {
		t.Fatalf("required missing protected file error = %v, want ErrProtectedSourceFile", err)
	}
	if strings.Contains(err.Error(), missing) {
		t.Fatalf("missing protected-file error disclosed configured path: %q", err)
	}
}

func TestPublisherProtectedSourceConfigurationLimits(t *testing.T) {
	t.Parallel()

	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "protected-source-limits")
	if err != nil {
		t.Fatal(err)
	}
	tooMany := make([]s3disk.ProtectedSourceFile, 65)
	if _, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ProtectedSourceFiles:                     tooMany,
	}); !errors.Is(err, s3disk.ErrResourceLimit) {
		t.Fatalf("too many protected files error = %v, want ErrResourceLimit", err)
	}
	duplicate := filepath.Join(t.TempDir(), "same")
	if _, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ProtectedSourceFiles: []s3disk.ProtectedSourceFile{
			{Path: duplicate, AllowMissingInitially: true},
			{Path: duplicate, AllowMissingInitially: true},
		},
	}); !errors.Is(err, s3disk.ErrInvalidPath) {
		t.Fatalf("duplicate protected file error = %v, want ErrInvalidPath", err)
	}
}

func TestPublisherProtectedSourceRejectsSymlinkAndDirectoryConfiguration(t *testing.T) {
	t.Parallel()

	directory := privateTestDirectory(t)
	regular := filepath.Join(directory, "regular")
	writeFile(t, regular, []byte("secret"))
	symlink := filepath.Join(directory, "symlink")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "public"), []byte("public"))
	for name, protectedPath := range map[string]string{
		"symlink":   symlink,
		"directory": directory,
	} {
		t.Run(name, func(t *testing.T) {
			publisher, _ := newProtectedSourcePublisher(t, []s3disk.ProtectedSourceFile{{Path: protectedPath}})
			if _, err := publisher.Stage(context.Background(), source, name); !errors.Is(err, s3disk.ErrProtectedSourceFile) {
				t.Fatalf("Stage error = %v, want ErrProtectedSourceFile", err)
			}
		})
	}
}

func TestPublisherWatchRecoversAfterProtectedAliasIsRemoved(t *testing.T) {
	protectedPath := filepath.Join(privateTestDirectory(t), "protected")
	writeFile(t, protectedPath, []byte("secret"))
	source := privateTestDirectory(t)
	publicPath := filepath.Join(source, "public")
	writeFile(t, publicPath, []byte("one"))
	publisher, _ := newProtectedSourcePublisher(t, []s3disk.ProtectedSourceFile{{Path: protectedPath}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	published := make(chan s3disk.Snapshot, 8)
	watchErrors := make(chan error, 16)
	done := make(chan error, 1)
	go func() {
		done <- publisher.Watch(ctx, source, "main", s3disk.WatchOptions{
			Debounce:          10 * time.Millisecond,
			ReconcileInterval: 50 * time.Millisecond,
			OnPublished:       func(snapshot s3disk.Snapshot) { published <- snapshot },
			OnError:           func(err error) { watchErrors <- err },
		})
	}()
	waitSnapshotGeneration(t, published, watchErrors, 1)

	alias := filepath.Join(source, "alias")
	requireHardLink(t, protectedPath, alias)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case err := <-watchErrors:
			if !errors.Is(err, s3disk.ErrProtectedSourceFile) {
				t.Fatalf("Watch error = %v, want ErrProtectedSourceFile", err)
			}
			goto rejected
		case snapshot := <-published:
			if snapshot.Generation > 1 {
				t.Fatalf("protected alias unexpectedly published generation %d", snapshot.Generation)
			}
		case <-deadline:
			t.Fatal("timed out waiting for protected alias rejection")
		}
	}

rejected:
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	writeFile(t, publicPath, []byte("two"))
	deadline = time.After(5 * time.Second)
	for {
		select {
		case snapshot := <-published:
			if snapshot.Generation == 2 {
				cancel()
				if err := <-done; !errors.Is(err, context.Canceled) {
					t.Fatalf("Watch stopped with %v", err)
				}
				return
			}
		case err := <-watchErrors:
			if !errors.Is(err, s3disk.ErrProtectedSourceFile) {
				t.Fatalf("Watch recovery error: %v", err)
			}
		case <-deadline:
			t.Fatal("timed out waiting for Watch recovery publication")
		}
	}
}

func newProtectedSourcePublisher(
	t *testing.T,
	protected []s3disk.ProtectedSourceFile,
) (*s3disk.Publisher, *memstore.Store) {
	t.Helper()
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "protected-source-test")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ProtectedSourceFiles:                     protected,
	})
	if err != nil {
		t.Fatal(err)
	}
	return publisher, store
}

func requireHardLink(t *testing.T, oldPath, newPath string) {
	t.Helper()
	if err := os.Link(oldPath, newPath); err != nil {
		t.Skipf("hard links unavailable on this filesystem: %v", err)
	}
}
