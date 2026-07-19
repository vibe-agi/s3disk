package s3disk_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	. "github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestResolveSnapshotClosureReturnsExactCurrentTreeAndCommitHistory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := memstore.New()
	repository, err := NewRepository(store, "closures/project")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(repository, PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "docs", "stable.txt"), []byte("stable payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	changing := filepath.Join(source, "docs", "changing.txt")
	if err := os.WriteFile(changing, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := publisher.Publish(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	firstClosure, err := repository.ResolveSnapshotClosure(ctx, "main", SnapshotClosureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if firstClosure.Snapshot != first {
		t.Fatalf("first closure snapshot = %+v, want %+v", firstClosure.Snapshot, first)
	}
	if err := firstClosure.ValidateResolved(); err != nil {
		t.Fatalf("first closure seal: %v", err)
	}

	if err := os.WriteFile(changing, []byte("new payload with a different size"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := publisher.Publish(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	store.ResetStats()
	closure, err := repository.ResolveSnapshotClosure(ctx, "main", SnapshotClosureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if closure.Snapshot != second || closure.Snapshot.Generation != 2 {
		t.Fatalf("closure snapshot = %+v, want generation-two %+v", closure.Snapshot, second)
	}
	if closure.ReferenceKey != repository.ReferenceKey("main") || len(closure.ReferenceData) == 0 || closure.ReferenceVersion.ETag == "" {
		t.Fatalf("closure reference = key %q, bytes %d, version %+v", closure.ReferenceKey, len(closure.ReferenceData), closure.ReferenceVersion)
	}
	if stats := store.Stats(); stats.ChunkGets != 0 || stats.ChunkBytesRead != 0 {
		t.Fatalf("closure downloaded chunk payloads: %+v", stats)
	}
	if !sort.StringsAreSorted(closure.ObjectKeys) {
		t.Fatalf("object keys are not canonical-sorted: %q", closure.ObjectKeys)
	}
	seen := make(map[string]struct{}, len(closure.ObjectKeys))
	counts := make(map[string]int)
	for _, key := range closure.ObjectKeys {
		if key == closure.ReferenceKey {
			t.Fatalf("mutable reference leaked into immutable capability closure: %q", key)
		}
		if _, duplicate := seen[key]; duplicate {
			t.Fatalf("duplicate exact key %q", key)
		}
		seen[key] = struct{}{}
		if _, err := store.Get(ctx, key, GetOptions{}); err != nil {
			t.Fatalf("closure key %q is unreadable: %v", key, err)
		}
		for _, kind := range []string{"commit", "dir", "file", "chunk", "symlink"} {
			if strings.Contains(key, "/objects/"+kind+"/") {
				counts[kind]++
			}
		}
	}
	if counts["commit"] != 2 || counts["dir"] != 2 || counts["file"] != 2 || counts["chunk"] != 2 || counts["symlink"] != 0 {
		t.Fatalf("closure kind counts = %+v, want two commits, dirs, files, and chunks", counts)
	}

	current := make(map[string]struct{}, len(closure.ObjectKeys))
	for _, key := range closure.ObjectKeys {
		current[key] = struct{}{}
	}
	oldTreeObjectOmitted := false
	for _, key := range firstClosure.ObjectKeys {
		if strings.Contains(key, "/objects/commit/") {
			continue
		}
		if _, retained := current[key]; !retained {
			oldTreeObjectOmitted = true
			break
		}
	}
	if !oldTreeObjectOmitted {
		t.Fatal("generation-two closure retained every obsolete generation-one tree object")
	}
	if err := closure.ValidateResolved(); err != nil {
		t.Fatalf("resolved closure seal: %v", err)
	}
	for name, mutate := range map[string]func(*SnapshotClosure){
		"snapshot": func(value *SnapshotClosure) { value.Snapshot.Generation++ },
		"reference": func(value *SnapshotClosure) {
			value.ReferenceData = append([]byte(nil), value.ReferenceData...)
			value.ReferenceData[0] ^= 1
		},
		"version": func(value *SnapshotClosure) { value.ReferenceVersion.ETag += "-changed" },
		"keys": func(value *SnapshotClosure) {
			value.ObjectKeys = append(append([]string(nil), value.ObjectKeys...), "extra")
		},
	} {
		t.Run("seal rejects "+name, func(t *testing.T) {
			tampered := closure
			mutate(&tampered)
			if err := tampered.ValidateResolved(); !errors.Is(err, ErrInvalidSnapshotClosure) {
				t.Fatalf("ValidateResolved error = %v, want ErrInvalidSnapshotClosure", err)
			}
		})
	}
	if err := (SnapshotClosure{}).ValidateResolved(); !errors.Is(err, ErrInvalidSnapshotClosure) {
		t.Fatalf("manually assembled closure error = %v, want ErrInvalidSnapshotClosure", err)
	}
}

func TestResolveSnapshotClosureEnforcesBoundsBeforeUnboundedTraversal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := memstore.New()
	repository, err := NewRepository(store, "closures/bounds")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(repository, PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "one.txt"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ResolveSnapshotClosure(ctx, "main", SnapshotClosureOptions{MaxObjects: 1}); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("one-object closure error = %v, want ErrResourceLimit", err)
	}

	store.ResetStats()
	invalid := []SnapshotClosureOptions{
		{MaxObjects: -1},
		{MaxObjects: MaxSnapshotClosureObjectsLimit + 1},
		{MaxEdges: -1},
		{MaxEdges: MaxSnapshotClosureEdgesLimit + 1},
		{MaxMetadataBytes: -1},
		{MaxMetadataBytes: MaxSnapshotClosureMetadataBytesLimit + 1},
	}
	for _, options := range invalid {
		if _, err := repository.ResolveSnapshotClosure(ctx, "main", options); !errors.Is(err, ErrResourceLimit) {
			t.Errorf("options %+v error = %v, want ErrResourceLimit", options, err)
		}
	}
	if stats := store.Stats(); stats.Gets != 0 || stats.Heads != 0 || stats.Puts != 0 {
		t.Fatalf("invalid closure bounds performed Store I/O: %+v", stats)
	}
}

func TestResolveSnapshotClosureCountsDuplicateManifestEdges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := memstore.New()
	repository, err := NewRepository(store, "closures/edges")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(repository, PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	for _, name := range []string{"first.txt", "second.txt"} {
		if err := os.WriteFile(filepath.Join(source, name), []byte("shared payload"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	// The root has two distinct directory-entry edges to one deduplicated file
	// manifest, which in turn has one chunk edge. Duplicate object keys must not
	// make those three units of traversal work look like only two.
	if _, err := repository.ResolveSnapshotClosure(ctx, "main", SnapshotClosureOptions{MaxEdges: 2}); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("two-edge closure error = %v, want ErrResourceLimit", err)
	}
	if _, err := repository.ResolveSnapshotClosure(ctx, "main", SnapshotClosureOptions{MaxEdges: 3}); err != nil {
		t.Fatalf("exact three-edge closure: %v", err)
	}
}

func TestResolveSnapshotClosureEnforcesExactMetadataByteBudget(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := memstore.New()
	repository, err := NewRepository(store, "closures/metadata-budget")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(repository, PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "payload.txt"), []byte("metadata accounting"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}

	store.ResetStats()
	closure, err := repository.ResolveSnapshotClosure(ctx, "main", SnapshotClosureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Resolve reads the mutable reference plus immutable metadata, but never the
	// chunk body. Subtracting the embedded reference therefore gives the exact
	// aggregate manifest bytes charged by the closure walker.
	stats := store.Stats()
	if stats.Gets != 4 || stats.ChunkGets != 0 {
		t.Fatalf("closure GETs = %+v, want one reference and three single-download manifests", stats)
	}
	metadataBytes := stats.BytesRead - int64(len(closure.ReferenceData))
	if metadataBytes < 1 {
		t.Fatalf("metadata bytes = %d, want a positive charge", metadataBytes)
	}
	if _, err := repository.ResolveSnapshotClosure(ctx, "main", SnapshotClosureOptions{MaxMetadataBytes: metadataBytes}); err != nil {
		t.Fatalf("exact metadata-byte budget: %v", err)
	}
	if _, err := repository.ResolveSnapshotClosure(ctx, "main", SnapshotClosureOptions{MaxMetadataBytes: metadataBytes - 1}); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("short metadata-byte budget error = %v, want ErrResourceLimit", err)
	}
}

func TestResolveSnapshotClosureObservesCancellationInsideManifestEdges(t *testing.T) {
	t.Parallel()
	store := memstore.New()
	repository, err := NewRepository(store, "closures/cancel")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(repository, PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	for index := 0; index < 128; index++ {
		name := filepath.Join(source, strings.Repeat("x", index+1))
		if err := os.WriteFile(name, []byte("same"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := publisher.Publish(context.Background(), source, "main"); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	reader := &cancelAfterDirectoryReader{ObjectReader: store, cancel: cancel}
	readOnly, err := NewReadOnlyRepository(reader, "closures/cancel")
	if err != nil {
		t.Fatal(err)
	}
	// Commit plus root exhaust this object budget. The cancellation triggered by
	// the root GET must be observed at the first directory edge; otherwise the
	// attempted child schedule would incorrectly win with ErrResourceLimit.
	if _, err := readOnly.ResolveSnapshotClosure(ctx, "main", SnapshotClosureOptions{MaxObjects: 2}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled closure error = %v, want context.Canceled", err)
	}
}

func TestSnapshotClosureIsSufficientForExactKeyConsumer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := memstore.New()
	const prefix = "closures/exact-reader"
	repository, err := NewRepository(store, prefix)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(repository, PublisherOptions{Chunking: ChunkingOptions{
		MinSize: 64, AverageSize: 128, MaxSize: 256,
	}})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	fileData := bytes.Repeat([]byte("0123456789abcdef"), 256)
	if err := os.WriteFile(filepath.Join(source, "multi.bin"), fileData, 0o600); err != nil {
		t.Fatal(err)
	}
	versionPath := filepath.Join(source, "version.txt")
	if err := os.WriteFile(versionPath, []byte("generation one"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkAvailable := true
	if err := os.Symlink("multi.bin", filepath.Join(source, "latest.bin")); err != nil {
		if runtime.GOOS != "windows" {
			t.Fatal(err)
		}
		symlinkAvailable = false
	}
	first, err := publisher.Publish(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(versionPath, []byte("generation two"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := publisher.Publish(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	if second.Generation != 2 {
		t.Fatalf("second generation = %d, want 2", second.Generation)
	}
	closure, err := repository.ResolveSnapshotClosure(ctx, "main", SnapshotClosureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	allowed := make(map[string]struct{}, len(closure.ObjectKeys))
	chunkKeys, commitKeys, symlinkKeys := 0, 0, 0
	for _, key := range closure.ObjectKeys {
		allowed[key] = struct{}{}
		switch {
		case strings.Contains(key, "/objects/chunk/"):
			chunkKeys++
		case strings.Contains(key, "/objects/commit/"):
			commitKeys++
		case strings.Contains(key, "/objects/symlink/"):
			symlinkKeys++
		}
	}
	if chunkKeys < 2 {
		t.Fatalf("closure chunk keys = %d, want a multi-chunk file", chunkKeys)
	}
	if commitKeys != 2 {
		t.Fatalf("closure commit keys = %d, want generation-one and generation-two ancestry", commitKeys)
	}
	if symlinkAvailable && symlinkKeys != 1 {
		t.Fatalf("closure symlink keys = %d, want 1", symlinkKeys)
	}

	reader := &exactClosureReader{
		base:         store,
		referenceKey: closure.ReferenceKey,
		reference: Object{
			Data: append([]byte(nil), closure.ReferenceData...), Version: closure.ReferenceVersion,
		},
		allowed: allowed,
	}
	readOnly, err := NewReadOnlyRepository(reader, prefix)
	if err != nil {
		t.Fatal(err)
	}
	watermarks, err := NewFileWatermarkStore(filepath.Join(privateTestDirectory(t), "consumer.watermark"))
	if err != nil {
		t.Fatal(err)
	}
	if err := watermarks.Save(ctx, "main", Watermark{Generation: first.Generation, Commit: first.Commit}); err != nil {
		t.Fatal(err)
	}
	consumer, err := NewConsumer(readOnly, "main", ConsumerOptions{
		Watermarks: watermarks, RequirePersistentWatermark: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := consumer.Refresh(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != RefreshUpdated || result.Generation != second.Generation {
		t.Fatalf("refresh = %+v, want updated generation %d", result, second.Generation)
	}
	entries, err := consumer.ListDir(ctx, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 {
		t.Fatalf("root entries = %d, want at least 2", len(entries))
	}
	file, err := consumer.Open(ctx, "multi.bin")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(fileData))
	if n, err := file.ReadAtContext(ctx, got, 0); err != nil || n != len(got) {
		t.Fatalf("lazy multi-chunk read = %d, %v; want %d, nil", n, err, len(got))
	}
	if !bytes.Equal(got, fileData) {
		t.Fatal("lazy multi-chunk read returned different data")
	}
	if symlinkAvailable {
		if target, err := consumer.Readlink(ctx, "latest.bin"); err != nil || target != "multi.bin" {
			t.Fatalf("readlink = %q, %v; want multi.bin, nil", target, err)
		}
	}
	if denied := reader.deniedKeys(); len(denied) != 0 {
		t.Fatalf("Consumer requested keys outside exact closure: %q", denied)
	}
}

func TestResolveSnapshotClosureUsesAuthenticatedReferenceNamespace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := memstore.New()
	repository, err := NewRepository(store, "closures/signed")
	if err != nil {
		t.Fatal(err)
	}
	repositoryID, err := GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewEd25519ReferenceSigner(repositoryID, "share-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{"share-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := NewFilePublicationJournal(filepath.Join(t.TempDir(), "publisher.journal"))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(repository, PublisherOptions{
		ReferenceSigner: signer, ReferenceVerifier: verifier,
		PublicationJournal: journal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "signed.txt"), []byte("authenticated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	closure, err := repository.ResolveSnapshotClosure(ctx, "main", SnapshotClosureOptions{ReferenceVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	if closure.ReferenceKey != repository.SignedReferenceKey("main") {
		t.Fatalf("signed closure reference key = %q, want %q", closure.ReferenceKey, repository.SignedReferenceKey("main"))
	}
	if _, err := repository.ResolveSnapshotClosure(ctx, "main", SnapshotClosureOptions{}); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("unsigned fallback error = %v, want ErrObjectNotFound", err)
	}
}

type cancelAfterDirectoryReader struct {
	ObjectReader
	cancel context.CancelFunc
	once   sync.Once
}

func (reader *cancelAfterDirectoryReader) Get(ctx context.Context, key string, options GetOptions) (Object, error) {
	object, err := reader.ObjectReader.Get(ctx, key, options)
	if err == nil && strings.Contains(key, "/objects/dir/") {
		reader.once.Do(reader.cancel)
	}
	return object, err
}

type exactClosureReader struct {
	base         ObjectReader
	referenceKey string
	reference    Object
	allowed      map[string]struct{}

	mu     sync.Mutex
	denied []string
}

func (reader *exactClosureReader) Get(ctx context.Context, key string, options GetOptions) (Object, error) {
	if err := ctx.Err(); err != nil {
		return Object{}, err
	}
	if key == reader.referenceKey {
		if options.IfNoneMatch != "" && options.IfNoneMatch == reader.reference.Version.ETag {
			return Object{}, ErrNotModified
		}
		if options.MaxBytes < 0 || (options.MaxBytes > 0 && int64(len(reader.reference.Data)) > options.MaxBytes) {
			return Object{}, ErrResourceLimit
		}
		return Object{Data: append([]byte(nil), reader.reference.Data...), Version: reader.reference.Version}, nil
	}
	if _, ok := reader.allowed[key]; !ok {
		reader.mu.Lock()
		reader.denied = append(reader.denied, key)
		reader.mu.Unlock()
		return Object{}, ErrAccessDenied
	}
	return reader.base.Get(ctx, key, options)
}

func (reader *exactClosureReader) deniedKeys() []string {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return append([]string(nil), reader.denied...)
}
