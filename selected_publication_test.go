package s3disk_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestPublishSelectedHidesUnselectedSiblings(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	source := privateTestDirectory(t)
	if err := os.MkdirAll(filepath.Join(source, "docs", "private"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(source, "top.txt"), []byte("top"))
	writeFile(t, filepath.Join(source, "docs", "readme.txt"), []byte("shared"))
	writeFile(t, filepath.Join(source, "docs", "draft.txt"), []byte("not shared"))
	writeFile(t, filepath.Join(source, "docs", "private", "secret.txt"), []byte("secret"))
	writeFile(t, filepath.Join(source, "root-secret.txt"), []byte("root secret"))

	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "selected-siblings")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishSelected(ctx, source, "share", []string{"docs/readme.txt", "top.txt"}); err != nil {
		t.Fatal(err)
	}
	if puts := store.Stats().ChunkPuts; puts != 2 {
		t.Fatalf("projection uploaded %d chunks, want only the two selected files", puts)
	}

	consumer := newConsumer(t, repository, "share")
	if _, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := entryNames(t, consumer, "."), []string{"docs", "top.txt"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("root entries = %q, want %q", got, want)
	}
	if got, want := entryNames(t, consumer, "docs"), []string{"readme.txt"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("docs entries = %q, want %q", got, want)
	}
	if got := string(readFile(t, consumer, "docs/readme.txt")); got != "shared" {
		t.Fatalf("selected file = %q, want shared", got)
	}
	for _, hidden := range []string{"root-secret.txt", "docs/draft.txt", "docs/private", "docs/private/secret.txt"} {
		if _, err := consumer.Stat(ctx, hidden); !errors.Is(err, s3disk.ErrPathNotFound) {
			t.Fatalf("Stat(%q) error = %v, want ErrPathNotFound", hidden, err)
		}
	}
}

func TestPublishSelectedDirectoryIncludesCompleteSubtree(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	source := privateTestDirectory(t)
	if err := os.MkdirAll(filepath.Join(source, "shared", "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(source, "shared", "a.txt"), []byte("a"))
	writeFile(t, filepath.Join(source, "shared", "nested", "b.txt"), []byte("b"))
	writeFile(t, filepath.Join(source, "outside.txt"), []byte("outside"))

	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "selected-directory")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishSelected(ctx, source, "share", []string{"shared"}); err != nil {
		t.Fatal(err)
	}

	consumer := newConsumer(t, repository, "share")
	if _, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := entryNames(t, consumer, "."), []string{"shared"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("root entries = %q, want %q", got, want)
	}
	if got := string(readFile(t, consumer, "shared/nested/b.txt")); got != "b" {
		t.Fatalf("nested selected file = %q, want b", got)
	}
	if _, err := consumer.Stat(ctx, "outside.txt"); !errors.Is(err, s3disk.ErrPathNotFound) {
		t.Fatalf("outside Stat error = %v, want ErrPathNotFound", err)
	}
}

func TestPublishSelectedSymlinkDoesNotIncludeItsTarget(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "target.txt"), []byte("must remain private"))
	if err := os.Symlink("target.txt", filepath.Join(source, "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "selected-symlink")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.PublishSelected(ctx, source, "share", []string{"link"}); err != nil {
		t.Fatal(err)
	}
	if puts := store.Stats().ChunkPuts; puts != 0 {
		t.Fatalf("selected symlink uploaded %d target chunks", puts)
	}

	consumer := newConsumer(t, repository, "share")
	if _, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if target, err := consumer.Readlink(ctx, "link"); err != nil || target != "target.txt" {
		t.Fatalf("Readlink = %q, %v; want target.txt", target, err)
	}
	if _, err := consumer.Stat(ctx, "target.txt"); !errors.Is(err, s3disk.ErrPathNotFound) {
		t.Fatalf("target Stat error = %v, want ErrPathNotFound", err)
	}
}

func TestPublishSelectedGenerationTracksOnlyProjectedTree(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	source := privateTestDirectory(t)
	if err := os.Mkdir(filepath.Join(source, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	selected := filepath.Join(source, "directory", "selected.txt")
	hidden := filepath.Join(source, "directory", "hidden.txt")
	writeFile(t, selected, []byte("one"))
	writeFile(t, hidden, []byte("hidden one"))

	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "selected-generation")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := publisher.PublishSelected(ctx, source, "share", []string{"directory/selected.txt"})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, hidden, []byte("hidden two"))
	writeFile(t, filepath.Join(source, "directory", "new-hidden.txt"), []byte("new hidden sibling"))
	second, err := publisher.PublishSelected(ctx, source, "share", []string{"directory/selected.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if second != first || second.Generation != 1 {
		t.Fatalf("hidden-only update advanced snapshot from %+v to %+v", first, second)
	}

	writeFile(t, selected, []byte("two"))
	third, err := publisher.PublishSelected(ctx, source, "share", []string{"directory/selected.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if third.Generation != 2 || third.Commit == first.Commit {
		t.Fatalf("selected update snapshot = %+v, want a new generation 2", third)
	}
}

func TestPublishSelectedUsesSignedPublicationPipeline(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repositoryID, signer, _, verifier, _ := signedTestKeys(t)
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "selected-signed")
	if err != nil {
		t.Fatal(err)
	}
	journal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "publisher.journal"))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		ReferenceSigner: signer, ReferenceVerifier: verifier,
		PublicationJournal: journal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "shared.txt"), []byte("shared"))
	writeFile(t, filepath.Join(source, "private.txt"), []byte("private"))
	snapshot, err := publisher.PublishSelected(ctx, source, "share", []string{"shared.txt"})
	if err != nil {
		t.Fatal(err)
	}

	checkpoint := s3disk.Watermark{
		RepositoryID: repositoryID, Generation: snapshot.Generation, Commit: snapshot.Commit,
	}
	consumer := newSignedConsumer(t, repository, "share", verifier, checkpoint)
	if result, err := consumer.Refresh(ctx); err != nil || result.Generation != 1 {
		t.Fatalf("signed selected refresh = %+v, %v", result, err)
	}
	if got := string(readFile(t, consumer, "shared.txt")); got != "shared" {
		t.Fatalf("signed selected read = %q, want shared", got)
	}
	if _, err := consumer.Stat(ctx, "private.txt"); !errors.Is(err, s3disk.ErrPathNotFound) {
		t.Fatalf("private Stat error = %v, want ErrPathNotFound", err)
	}
}

func TestStageSelectedValidatesSelectionBeforeObjectStoreIO(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := &selectedIOCountingStore{delegate: memstore.New()}
	repository, err := s3disk.NewRepository(store, "selected-validation")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "file"), []byte("file"))

	invalid := []struct {
		name  string
		paths []string
	}{
		{name: "nil"},
		{name: "empty list", paths: []string{}},
		{name: "empty path", paths: []string{""}},
		{name: "absolute", paths: []string{"/file"}},
		{name: "parent", paths: []string{"../file"}},
		{name: "unclean parent", paths: []string{"directory/../file"}},
		{name: "dot component", paths: []string{"./file"}},
		{name: "duplicate separator", paths: []string{"directory//file"}},
		{name: "trailing separator", paths: []string{"directory/"}},
		{name: "duplicate", paths: []string{"file", "file"}},
		{name: "ancestor first", paths: []string{"directory", "directory/file"}},
		{name: "descendant first", paths: []string{"directory/file", "directory"}},
		{name: "oversized component", paths: []string{strings.Repeat("x", 256)}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			store.calls.Store(0)
			if _, err := publisher.StageSelected(ctx, source, "share", test.paths); !errors.Is(err, s3disk.ErrInvalidPath) {
				t.Fatalf("StageSelected error = %v, want ErrInvalidPath", err)
			}
			if calls := store.calls.Load(); calls != 0 {
				t.Fatalf("invalid selection performed %d object-store calls", calls)
			}
		})
	}
}

func TestStageSelectedRejectsMissingAndNonDirectoryPaths(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "file"), []byte("file"))
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "selected-resolution")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.StageSelected(ctx, source, "share", []string{"missing"}); !errors.Is(err, s3disk.ErrPathNotFound) {
		t.Fatalf("missing selection error = %v, want ErrPathNotFound", err)
	}
	if _, err := publisher.StageSelected(ctx, source, "share", []string{"file/child"}); !errors.Is(err, s3disk.ErrNotDirectory) {
		t.Fatalf("non-directory selection error = %v, want ErrNotDirectory", err)
	}
}

func entryNames(t *testing.T, consumer *s3disk.Consumer, directory string) []string {
	t.Helper()
	entries, err := consumer.ListDir(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name
	}
	return names
}

type selectedIOCountingStore struct {
	delegate s3disk.Store
	calls    atomic.Int64
}

func (store *selectedIOCountingStore) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	store.calls.Add(1)
	return store.delegate.Get(ctx, key, options)
}

func (store *selectedIOCountingStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	store.calls.Add(1)
	return store.delegate.Head(ctx, key)
}

func (store *selectedIOCountingStore) PutIfAbsent(ctx context.Context, key string, data []byte) (s3disk.Version, error) {
	store.calls.Add(1)
	return store.delegate.PutIfAbsent(ctx, key, data)
}

func (store *selectedIOCountingStore) CompareAndSwap(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
	store.calls.Add(1)
	return store.delegate.CompareAndSwap(ctx, key, expected, data)
}

var _ s3disk.Store = (*selectedIOCountingStore)(nil)
