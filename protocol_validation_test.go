package s3disk

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vibe-agi/s3disk/internal/syncutil"
)

func TestProtocolV1GoldenFixtures(t *testing.T) {
	t.Parallel()
	digest := func(first byte) Digest {
		var value Digest
		for index := range value {
			value[index] = first + byte(index)
		}
		return value
	}
	commitDigest := digest(0x00)
	rootDigest := digest(0x20)
	fileDigest := digest(0x40)
	parent := commitDigest
	fixtures := []struct {
		name     string
		value    any
		fresh    func() any
		validate func(any) error
	}{
		{
			name: "reference.json",
			value: snapshotReference{
				Format: objectFormatVersion, Generation: 7, Commit: commitDigest,
			},
			fresh: func() any { return new(snapshotReference) },
			validate: func(value any) error {
				reference := value.(*snapshotReference)
				if reference.Format != objectFormatVersion || reference.Generation == 0 || reference.Commit.IsZero() {
					return ErrInvalidReference
				}
				return nil
			},
		},
		{
			name: "commit.json",
			value: commitManifest{
				Format: objectFormatVersion, Generation: 7, Parent: &parent,
				Root: rootDigest, PublishedAtUnix: 1_700_000_000_123_456_789,
				ResetChanges: true,
			},
			fresh:    func() any { return new(commitManifest) },
			validate: func(value any) error { return validateCommitManifest(value.(*commitManifest), 7) },
		},
		{
			name: "directory.json",
			value: dirManifest{Format: objectFormatVersion, Entries: []dirEntry{
				{
					Name: []byte("docs"), Type: EntryDir, Node: rootDigest,
					Mode: 0o555, ModTimeUnixNano: 1_700_000_000_000_000_000,
				},
				{
					Name: []byte("report.txt"), Type: EntryFile, Node: fileDigest,
					Mode: 0o444, Size: 5, ModTimeUnixNano: 1_700_000_000_123_456_789,
				},
			}},
			fresh:    func() any { return new(dirManifest) },
			validate: func(value any) error { return validateDirectoryManifest(value.(*dirManifest)) },
		},
		{
			name: "file.json",
			value: fileManifest{
				Format: objectFormatVersion, Algorithm: "rabin-v1", MinSize: 64,
				AvgSize: 128, MaxSize: 256, Polynomial: defaultPolynomial, Size: 5,
				Chunks: []chunkRef{{Offset: 0, Size: 5, Digest: fileDigest}},
			},
			fresh:    func() any { return new(fileManifest) },
			validate: func(value any) error { return validateFileManifest(value.(*fileManifest)) },
		},
		{
			name:     "symlink.json",
			value:    symlinkManifest{Format: objectFormatVersion, Target: []byte("../docs/report.txt")},
			fresh:    func() any { return new(symlinkManifest) },
			validate: func(value any) error { return validateSymlinkManifest(value.(*symlinkManifest)) },
		},
	}

	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join("testdata", "protocol", "v1", fixture.name)
			golden, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read protocol fixture: %v", err)
			}
			encoded, err := canonicalJSON(fixture.value)
			if err != nil {
				t.Fatalf("encode protocol fixture: %v", err)
			}
			golden = []byte(strings.TrimSuffix(string(golden), "\n"))
			if string(encoded) != string(golden) {
				t.Fatalf("v1 protocol drift\n got: %s\nwant: %s", encoded, golden)
			}
			decoded := fixture.fresh()
			if err := decodeJSON(golden, decoded); err != nil {
				t.Fatalf("decode frozen v1 fixture: %v", err)
			}
			if err := fixture.validate(decoded); err != nil {
				t.Fatalf("validate frozen v1 fixture: %v", err)
			}
			if !reflect.DeepEqual(reflect.ValueOf(decoded).Elem().Interface(), fixture.value) {
				t.Fatalf("decoded frozen fixture = %#v, want %#v", decoded, fixture.value)
			}
		})
	}
}

func TestProtocolJSONMustBeCanonical(t *testing.T) {
	digest := digestObject("commit", []byte("commit"))
	canonical, err := canonicalJSON(snapshotReference{Format: objectFormatVersion, Generation: 7, Commit: digest})
	if err != nil {
		t.Fatal(err)
	}
	var decoded snapshotReference
	if err := decodeJSON(canonical, &decoded); err != nil {
		t.Fatalf("decode canonical reference: %v", err)
	}

	cases := [][]byte{
		append([]byte(" "), canonical...),
		[]byte(`{"generation":7,"format":1,"commit":"` + digest.String() + `"}`),
		[]byte(`{"format":1,"generation":7,"generation":7,"commit":"` + digest.String() + `"}`),
		[]byte(`{"format":1,"generation":7,"commit":"` + digest.String() + `","unknown":true}`),
	}
	for _, data := range cases {
		var value snapshotReference
		if err := decodeJSON(data, &value); !errors.Is(err, ErrCorruptObject) {
			t.Fatalf("decode non-canonical %q error = %v, want ErrCorruptObject", data, err)
		}
	}
}

func TestManifestValidationRejectsHostileMetadata(t *testing.T) {
	digest := digestObject("file", []byte("node"))
	consumer := &Consumer{
		downloadSlots: make(chan struct{}, 1),
		downloadBytes: syncutil.NewWeightedSemaphore(DefaultMaxConcurrentDownloadBytes, ErrResourceLimit),
	}
	for _, name := range [][]byte{[]byte("."), []byte(".."), []byte(strings.Repeat("x", maxEntryNameBytes+1))} {
		manifest := dirManifest{Format: objectFormatVersion, Entries: []dirEntry{{
			Name: name, Type: EntryFile, Node: digest, Mode: 0o444, Size: 1,
		}}}
		data, err := canonicalJSON(manifest)
		if err != nil {
			t.Fatal(err)
		}
		store := &manifestStore{data: data, digest: digestObject("dir", data)}
		repository, err := NewRepository(store, "validation")
		if err != nil {
			t.Fatal(err)
		}
		consumer.repository = repository
		if _, err := consumer.loadDirectory(t.Context(), store.digest); !errors.Is(err, ErrCorruptObject) {
			t.Fatalf("directory name %q error = %v, want ErrCorruptObject", name, err)
		}
		consumer.metadata.Clear()
	}

	invalidProfile := &fileManifest{
		Format: objectFormatVersion, Algorithm: "rabin-v1", MinSize: 0,
		AvgSize: 0, MaxSize: 0, Polynomial: 0, Size: 0,
	}
	if err := validateFileManifest(invalidProfile); !errors.Is(err, ErrCorruptObject) {
		t.Fatalf("invalid chunk profile error = %v, want ErrCorruptObject", err)
	}

	if err := validateSymlinkManifest(&symlinkManifest{Format: objectFormatVersion}); !errors.Is(err, ErrCorruptObject) {
		t.Fatalf("empty symlink target error = %v, want ErrCorruptObject", err)
	}
	for _, entry := range []dirEntry{
		{Name: []byte("huge-file"), Type: EntryFile, Node: digest, Size: maxRepresentableFileBytes + 1},
		{Name: []byte("huge-link"), Type: EntrySymlink, Node: digest, Size: maxSymlinkTargetBytes + 1},
		{Name: []byte("empty-link"), Type: EntrySymlink, Node: digest, Size: 0},
	} {
		manifest := &dirManifest{Format: objectFormatVersion, Entries: []dirEntry{entry}}
		if err := validateDirectoryManifest(manifest); !errors.Is(err, ErrCorruptObject) || !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("hostile %s size %d error = %v, want corruption/resource limit", entry.Type, entry.Size, err)
		}
	}
}

func TestReadlinkRejectsDirectoryManifestSizeMismatch(t *testing.T) {
	t.Parallel()
	target := []byte("nested/target")
	symlinkData, err := canonicalJSON(symlinkManifest{Format: objectFormatVersion, Target: target})
	if err != nil {
		t.Fatal(err)
	}
	symlinkDigest := digestObject("symlink", symlinkData)
	directoryData, err := canonicalJSON(dirManifest{Format: objectFormatVersion, Entries: []dirEntry{{
		Name: []byte("link"), Type: EntrySymlink, Node: symlinkDigest,
		Mode: 0o444, Size: int64(len(target) + 1),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	directoryDigest := digestObject("dir", directoryData)
	store := &keyedManifestStore{objects: make(map[string][]byte)}
	repository, err := NewRepository(store, "symlink-size")
	if err != nil {
		t.Fatal(err)
	}
	store.objects[repository.objectKey("dir", directoryDigest)] = directoryData
	store.objects[repository.objectKey("symlink", symlinkDigest)] = symlinkData
	consumer, err := NewConsumer(repository, "main", ConsumerOptions{Symlinks: SymlinkPreserve})
	if err != nil {
		t.Fatal(err)
	}
	consumer.state = &adoptedSnapshot{
		reference: snapshotReference{Format: objectFormatVersion, Generation: 1},
		commit:    commitManifest{Format: objectFormatVersion, Generation: 1, Root: directoryDigest},
	}
	if _, err := consumer.Readlink(t.Context(), "link"); !errors.Is(err, ErrCorruptObject) {
		t.Fatalf("Readlink size mismatch error = %v, want ErrCorruptObject", err)
	}
}

func FuzzDecodeReferenceNeverPanics(f *testing.F) {
	digest := digestObject("commit", []byte("seed"))
	seed, err := canonicalJSON(snapshotReference{Format: objectFormatVersion, Generation: 1, Commit: digest})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"format":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxMetadataObjectBytes+1 {
			t.Skip()
		}
		var reference snapshotReference
		_ = decodeJSON(data, &reference)
	})
}

type manifestStore struct {
	data   []byte
	digest Digest
}

type keyedManifestStore struct {
	objects map[string][]byte
}

func (store *keyedManifestStore) Get(_ context.Context, key string, _ GetOptions) (Object, error) {
	data, ok := store.objects[key]
	if !ok {
		return Object{}, ErrObjectNotFound
	}
	return Object{Data: append([]byte(nil), data...), Version: Version{ETag: "test-manifest"}}, nil
}

func (*keyedManifestStore) Head(context.Context, string) (Version, error) {
	return Version{}, ErrObjectNotFound
}

func (*keyedManifestStore) PutIfAbsent(context.Context, string, []byte) (Version, error) {
	return Version{}, ErrPrecondition
}

func (*keyedManifestStore) CompareAndSwap(context.Context, string, *Version, []byte) (Version, error) {
	return Version{}, ErrPrecondition
}

func (store *manifestStore) Get(_ context.Context, _ string, _ GetOptions) (Object, error) {
	return Object{Data: append([]byte(nil), store.data...), Version: Version{ETag: "test-manifest"}}, nil
}

func (*manifestStore) Head(context.Context, string) (Version, error) {
	return Version{}, ErrObjectNotFound
}

func (*manifestStore) PutIfAbsent(context.Context, string, []byte) (Version, error) {
	return Version{}, ErrPrecondition
}

func (*manifestStore) CompareAndSwap(context.Context, string, *Version, []byte) (Version, error) {
	return Version{}, ErrPrecondition
}
