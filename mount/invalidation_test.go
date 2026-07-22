//go:build linux || darwin || freebsd

package mount

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestNormalizeOptionsRejectsNegativeTTLs(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		options Options
	}{
		{name: "attribute", options: Options{AttrTTL: -time.Nanosecond}},
		{name: "entry", options: Options{EntryTTL: -time.Nanosecond}},
		{name: "negative", options: Options{NegativeTTL: -time.Nanosecond}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := normalizeOptions(test.options); err == nil {
				t.Fatal("normalizeOptions accepted a negative TTL")
			}
			if _, err := ReadOnly(context.Background(), &s3disk.Consumer{}, "unused", test.options); err == nil {
				t.Fatal("ReadOnly accepted a negative TTL")
			}
		})
	}
}

func TestNormalizeOptionsRejectsInvalidMacOSBackend(t *testing.T) {
	t.Parallel()
	if _, err := normalizeOptions(Options{MacOSBackend: MacOSBackend("unknown")}); err == nil {
		t.Fatal("normalizeOptions accepted an unknown macOS backend")
	}
	if runtime.GOOS != "darwin" {
		if _, err := normalizeOptions(Options{MacOSBackend: MacOSBackendFSKit}); err == nil {
			t.Fatal("normalizeOptions accepted a macOS backend on a non-Darwin host")
		}
	}
}

func TestNormalizeOptionsRejectsKernelCache(t *testing.T) {
	t.Parallel()
	options := Options{KernelCache: true}
	if _, err := normalizeOptions(options); !errors.Is(err, ErrKernelCacheUnsupported) {
		t.Fatalf("normalizeOptions error = %v, want ErrKernelCacheUnsupported", err)
	}
	if _, err := ReadOnly(context.Background(), &s3disk.Consumer{}, "unused", options); !errors.Is(err, ErrKernelCacheUnsupported) {
		t.Fatalf("ReadOnly error = %v, want ErrKernelCacheUnsupported", err)
	}
}

func TestNormalizeOptionsRejectsNegativeDentryCache(t *testing.T) {
	t.Parallel()
	options := Options{NegativeTTL: time.Nanosecond}
	if _, err := normalizeOptions(options); !errors.Is(err, ErrNegativeCacheUnsupported) {
		t.Fatalf("normalizeOptions error = %v, want ErrNegativeCacheUnsupported", err)
	}
	if _, err := ReadOnly(context.Background(), &s3disk.Consumer{}, "unused", options); !errors.Is(err, ErrNegativeCacheUnsupported) {
		t.Fatalf("ReadOnly error = %v, want ErrNegativeCacheUnsupported", err)
	}

	normalized, err := normalizeOptions(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if normalized.NegativeTTL != 0 {
		t.Fatalf("default negative TTL = %v, want disabled", normalized.NegativeTTL)
	}
	if got := newFUSEOptions(normalized).NegativeTimeout; got != nil {
		t.Fatalf("FUSE negative timeout = %v, want nil", *got)
	}
}

func TestNormalizeOptionsBoundsInodeIdentities(t *testing.T) {
	t.Parallel()
	for _, invalid := range []int{-1, MaxInodeIdentitiesLimit + 1} {
		if _, err := normalizeOptions(Options{MaxInodeIdentities: invalid}); err == nil {
			t.Fatalf("normalizeOptions accepted MaxInodeIdentities=%d", invalid)
		}
	}
	normalized, err := normalizeOptions(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if normalized.MaxInodeIdentities != DefaultMaxInodeIdentities {
		t.Fatalf("default MaxInodeIdentities = %d, want %d", normalized.MaxInodeIdentities, DefaultMaxInodeIdentities)
	}
	for _, invalid := range []int64{-1, MaxInodeIdentityBytesLimit + 1} {
		if _, err := normalizeOptions(Options{MaxInodeIdentityBytes: invalid}); err == nil {
			t.Fatalf("normalizeOptions accepted MaxInodeIdentityBytes=%d", invalid)
		}
	}
	if normalized.MaxInodeIdentityBytes != DefaultMaxInodeIdentityBytes {
		t.Fatalf("default MaxInodeIdentityBytes = %d, want %d", normalized.MaxInodeIdentityBytes, DefaultMaxInodeIdentityBytes)
	}
}

func TestResolveMountpointPinsSymlinkedPath(t *testing.T) {
	t.Parallel()
	realParent := t.TempDir()
	realMountpoint := filepath.Join(realParent, "mount")
	if err := os.Mkdir(realMountpoint, 0o755); err != nil {
		t.Fatal(err)
	}
	aliasParent := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(realParent, aliasParent); err != nil {
		t.Fatal(err)
	}
	got, err := resolveMountpoint(filepath.Join(aliasParent, "mount"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(realMountpoint)
	if err != nil {
		t.Fatal(err)
	}
	if got != want || !filepath.IsAbs(got) {
		t.Fatalf("resolved mountpoint = %q, want absolute canonical path %q", got, want)
	}

	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveMountpoint(file); err == nil {
		t.Fatal("resolveMountpoint accepted a regular file")
	}
}

func TestNodeGetattrUsesSnapshotPinnedHandleMetadata(t *testing.T) {
	t.Parallel()
	modTime := time.Unix(1_700_000_000, 123_456_789).UTC()
	handle := &fileHandle{entry: s3disk.Entry{
		Name: "deleted", Type: s3disk.EntryFile, Size: 37, Mode: 0o440, ModTime: modTime,
	}}
	// A nil Consumer represents a path which can no longer be resolved. Getattr
	// must not consult it when the kernel supplies an already-open file handle.
	node := &node{}
	var out fuse.AttrOut
	if got := node.Getattr(context.Background(), handle, &out); got != 0 {
		t.Fatalf("node Getattr errno = %v", got)
	}
	assertPinnedAttr(t, out.Attr, handle.entry)

	out = fuse.AttrOut{}
	if got := handle.Getattr(context.Background(), &out); got != 0 {
		t.Fatalf("handle Getattr errno = %v", got)
	}
	assertPinnedAttr(t, out.Attr, handle.entry)
}

func TestNodeGetattrWithoutKernelHandleUsesBoundSnapshotMetadata(t *testing.T) {
	t.Parallel()
	entry := s3disk.Entry{
		Name: "old", Type: s3disk.EntryFile, Size: 41, Mode: 0o440,
		ModTime: time.Unix(1_700_000_001, 987_654_321).UTC(),
	}
	node := &node{entryType: s3disk.EntryFile, snapshotBound: true, snapshotEntry: entry}
	var out fuse.AttrOut
	if got := node.Getattr(context.Background(), nil, &out); got != 0 {
		t.Fatalf("bound node Getattr errno = %v", got)
	}
	assertPinnedAttr(t, out.Attr, entry)

	// go-fuse may choose an arbitrary open handle for Linux GETATTR. The inode's
	// generation is authoritative even if a mismatched handle is supplied.
	other := entry
	other.Size++
	out = fuse.AttrOut{}
	if got := node.Getattr(context.Background(), &fileHandle{entry: other}, &out); got != 0 {
		t.Fatalf("bound node Getattr with handle errno = %v", got)
	}
	assertPinnedAttr(t, out.Attr, entry)
}

func TestOldSnapshotInodeRejectsNewGenerationOpen(t *testing.T) {
	t.Parallel()
	fixture := newInvalidationFixture(t, memstore.New(), "mount-stale-inode-open")
	snapshot, ok := fixture.consumer.CurrentSnapshot()
	if !ok {
		t.Fatal("initial consumer snapshot is absent")
	}
	entry, err := fixture.consumer.Stat(context.Background(), "dir/item")
	if err != nil {
		t.Fatal(err)
	}
	oldNode := &node{
		consumer: fixture.consumer, path: "dir/item", entryType: s3disk.EntryFile,
		snapshotBound: true, snapshot: identityOfSnapshot(snapshot), snapshotEntry: entry,
	}
	fixture.publishUpdate(t)
	handle, flags, errno := oldNode.Open(context.Background(), uint32(syscall.O_RDONLY))
	if errno != syscall.ESTALE || handle != nil || flags != 0 {
		t.Fatalf("Open on old snapshot inode = (%T, %#x, %v), want (nil, 0, ESTALE)", handle, flags, errno)
	}
}

func TestLookupLetsBridgeReplaceStaleChild(t *testing.T) {
	t.Parallel()
	fixture := newInvalidationFixture(t, memstore.New(), "mount-generation-replacement")
	oldDirectory := fixture.root.GetChild("dir")
	if oldDirectory == nil {
		t.Fatal("initial directory child is absent")
	}
	fixture.publishUpdate(t)

	var out fuse.EntryOut
	newDirectory, errno := fixture.root.Lookup(context.Background(), "dir", &out)
	if errno != 0 {
		t.Fatalf("root Lookup after refresh errno = %v", errno)
	}
	if newDirectory == oldDirectory {
		t.Fatal("root Lookup reused an inode bound to the old snapshot")
	}
	// Node.Lookup is only the bridge callback. It must not issue a reverse
	// notification or detach a child while the kernel is waiting for LOOKUP;
	// rawBridge.addNewChild performs the guarded replacement after return.
	if got := fixture.root.GetChild("dir"); got != oldDirectory {
		t.Fatalf("Lookup detached child inline: got %p, want old child %p until bridge replacement", got, oldDirectory)
	}
}

func TestLookupDoesNotEnumerateDirectoryOrFetchChunks(t *testing.T) {
	t.Parallel()
	store := &mountLookupCountingStore{Store: memstore.New()}
	repository, err := s3disk.NewRepository(store, "mount-lookup-transfer")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "item"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(context.Background(), source, "main"); err != nil {
		t.Fatal(err)
	}
	// A one-byte metadata budget deliberately prevents the directory manifest
	// from remaining in the LRU. Every resolve therefore exposes an accidental
	// second ListDir as another object-store GET.
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{MetadataCacheBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	root := newRootNode(consumer, DefaultMaxInodeIdentities, DefaultMaxInodeIdentityBytes)
	_ = fs.NewNodeFS(root, &fs.Options{})

	store.directoryGets.Store(0)
	store.chunkGets.Store(0)
	var out fuse.EntryOut
	if child, got := root.Lookup(context.Background(), "item", &out); child == nil || got != 0 {
		t.Fatalf("existing Lookup = (%p, %v), want child and success", child, got)
	}
	if got := store.directoryGets.Load(); got != 1 {
		t.Fatalf("existing Lookup directory GETs = %d, want exactly one", got)
	}
	if got := store.chunkGets.Load(); got != 0 {
		t.Fatalf("existing Lookup chunk GETs = %d, want zero", got)
	}

	store.directoryGets.Store(0)
	if child, got := root.Lookup(context.Background(), "missing", &out); child != nil || got != syscall.ENOENT {
		t.Fatalf("missing Lookup = (%p, %v), want (nil, ENOENT)", child, got)
	}
	if got := store.directoryGets.Load(); got != 1 {
		t.Fatalf("missing Lookup directory GETs = %d, want exactly one", got)
	}
	if got := store.chunkGets.Load(); got != 0 {
		t.Fatalf("missing Lookup chunk GETs = %d, want zero", got)
	}
}

func TestConcurrentLookupUsesOneStableSnapshotIdentity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repository, err := s3disk.NewRepository(memstore.New(), "mount-concurrent-stable-inode")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	itemPath := filepath.Join(source, "item")
	if err := os.WriteFile(itemPath, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	root := newRootNode(consumer, 8, DefaultMaxInodeIdentityBytes)
	_ = fs.NewNodeFS(root, &fs.Options{})

	const lookups = 64
	start := make(chan struct{})
	attrs := make([]fs.StableAttr, lookups)
	entryInodes := make([]uint64, lookups)
	errnos := make([]syscall.Errno, lookups)
	var wait sync.WaitGroup
	for index := range lookups {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			var out fuse.EntryOut
			inode, lookupErrno := root.Lookup(ctx, "item", &out)
			errnos[index] = lookupErrno
			if inode != nil {
				attrs[index] = inode.StableAttr()
			}
			entryInodes[index] = out.Attr.Ino
		}()
	}
	close(start)
	wait.Wait()
	first := attrs[0]
	if first.Ino < 2 || first.Gen == 0 || first.Mode != syscall.S_IFREG {
		t.Fatalf("first stable identity = %+v, want explicit regular-file inode and generation", first)
	}
	for index := range lookups {
		if errnos[index] != 0 {
			t.Fatalf("Lookup %d errno = %v", index, errnos[index])
		}
		if attrs[index] != first {
			t.Fatalf("Lookup %d stable identity = %+v, want %+v", index, attrs[index], first)
		}
		if entryInodes[index] != first.Ino {
			t.Fatalf("Lookup %d EntryOut inode = %d, want %d", index, entryInodes[index], first.Ino)
		}
	}
	if used := root.inodeIDs.used(); used != 1 {
		t.Fatalf("stable inode identities after concurrent lookup = %d, want 1", used)
	}

	if err := os.WriteFile(itemPath, []byte("second generation"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	var out fuse.EntryOut
	newInode, lookupErrno := root.Lookup(ctx, "item", &out)
	if lookupErrno != 0 || newInode == nil {
		t.Fatalf("new-generation Lookup = (%p, %v)", newInode, lookupErrno)
	}
	newStable := newInode.StableAttr()
	if newStable.Ino == first.Ino || newStable.Gen == first.Gen {
		t.Fatalf("new-generation identity = %+v, old = %+v; want distinct inode and generation", newStable, first)
	}
	if used := root.inodeIDs.used(); used != 2 {
		t.Fatalf("stable inode identities after refresh = %d, want 2", used)
	}
}

func TestLookupFailsClosedAtStableInodeIdentityLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repository, err := s3disk.NewRepository(memstore.New(), "mount-stable-inode-limit")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	for _, name := range []string{"first", "second"} {
		if err := os.WriteFile(filepath.Join(source, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	root := newRootNode(consumer, 1, DefaultMaxInodeIdentityBytes)
	_ = fs.NewNodeFS(root, &fs.Options{})
	var out fuse.EntryOut
	if inode, got := root.Lookup(ctx, "first", &out); inode == nil || got != 0 {
		t.Fatalf("first Lookup = (%p, %v), want success", inode, got)
	}
	out = fuse.EntryOut{}
	if inode, got := root.Lookup(ctx, "second", &out); inode != nil || got != syscall.ENOSPC {
		t.Fatalf("second Lookup at identity limit = (%p, %v), want (nil, ENOSPC)", inode, got)
	}
	if used := root.inodeIDs.used(); used != 1 {
		t.Fatalf("stable inode identities after rejected lookup = %d, want 1", used)
	}
}

func TestStaleBoundDirectoryRejectsNamespaceOperations(t *testing.T) {
	t.Parallel()
	fixture := newInvalidationFixture(t, memstore.New(), "mount-stale-directory")
	fixture.publishUpdate(t)

	var out fuse.EntryOut
	child, lookupErrno := fixture.directory.Lookup(context.Background(), "item", &out)
	if child != nil || lookupErrno != syscall.ESTALE {
		t.Fatalf("old directory Lookup = (%p, %v), want (nil, ESTALE)", child, lookupErrno)
	}
	stream, readdirErrno := fixture.directory.Readdir(context.Background())
	if stream != nil || readdirErrno != syscall.ESTALE {
		t.Fatalf("old directory Readdir = (%T, %v), want (nil, ESTALE)", stream, readdirErrno)
	}
	if opendirErrno := fixture.directory.Opendir(context.Background()); opendirErrno != syscall.ESTALE {
		t.Fatalf("old directory Opendir = %v, want ESTALE", opendirErrno)
	}
}

func TestStaleBoundFileMasksCurrentTypeErrorsWithESTALE(t *testing.T) {
	t.Parallel()
	fixture := newInvalidationFixture(t, memstore.New(), "mount-stale-file-type")
	oldFile, ok := fixture.fileInode.Operations().(*node)
	if !ok {
		t.Fatalf("file inode operations type = %T, want *node", fixture.fileInode.Operations())
	}
	if err := os.Remove(fixture.filePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(fixture.filePath, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.publisher.Publish(context.Background(), fixture.source, "main"); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.consumer.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	if handle, flags, openErrno := oldFile.Open(context.Background(), uint32(syscall.O_RDONLY)); handle != nil || flags != 0 || openErrno != syscall.ESTALE {
		t.Fatalf("old file Open after file-to-directory change = (%T, %#x, %v), want (nil, 0, ESTALE)", handle, flags, openErrno)
	}
	if target, readlinkErrno := oldFile.Readlink(context.Background()); target != nil || readlinkErrno != syscall.ESTALE {
		t.Fatalf("old file Readlink after file-to-directory change = (%q, %v), want (nil, ESTALE)", target, readlinkErrno)
	}
}

func TestCanceledBoundOperationsReturnInterrupted(t *testing.T) {
	t.Parallel()
	fixture := newInvalidationFixture(t, memstore.New(), "mount-canceled-bound-operations")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var out fuse.EntryOut
	if child, got := fixture.directory.Lookup(ctx, "item", &out); child != nil || got != syscall.EINTR {
		t.Fatalf("canceled Lookup = (%p, %v), want (nil, EINTR)", child, got)
	}
	if stream, got := fixture.directory.Readdir(ctx); stream != nil || got != syscall.EINTR {
		t.Fatalf("canceled Readdir = (%T, %v), want (nil, EINTR)", stream, got)
	}
	if got := fixture.directory.Opendir(ctx); got != syscall.EINTR {
		t.Fatalf("canceled Opendir = %v, want EINTR", got)
	}
	oldFile, ok := fixture.fileInode.Operations().(*node)
	if !ok {
		t.Fatalf("file inode operations type = %T, want *node", fixture.fileInode.Operations())
	}
	if handle, flags, got := oldFile.Open(ctx, uint32(syscall.O_RDONLY)); handle != nil || flags != 0 || got != syscall.EINTR {
		t.Fatalf("canceled Open = (%T, %#x, %v), want (nil, 0, EINTR)", handle, flags, got)
	}
	if target, got := oldFile.Readlink(ctx); target != nil || got != syscall.EINTR {
		t.Fatalf("canceled Readlink = (%q, %v), want (nil, EINTR)", target, got)
	}
}

func TestKernelPermissionChecksAreNotBypassed(t *testing.T) {
	t.Parallel()
	if _, implements := any(&node{}).(fs.NodeAccesser); implements {
		t.Fatal("node implements Access and bypasses go-fuse's mode-based default")
	}
	if got, want := kernelMountOptions(Options{}), []string{"ro", "default_permissions"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("kernel mount options = %v, want %v", got, want)
	}
	if runtime.GOOS == "darwin" {
		if got, want := kernelMountOptions(Options{MacOSBackend: MacOSBackendFSKit}),
			[]string{"ro", "default_permissions", "backend=fskit"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("FSKit mount options = %v, want %v", got, want)
		}
	}
	options, err := normalizeOptions(Options{})
	if err != nil {
		t.Fatal(err)
	}
	fuseOptions := newFUSEOptions(options)
	if fuseOptions.UID != uint32(os.Getuid()) || fuseOptions.GID != uint32(os.Getgid()) {
		t.Fatalf("mounted owner = %d:%d, want mounting process %d:%d", fuseOptions.UID, fuseOptions.GID, os.Getuid(), os.Getgid())
	}
	var mode000 fuse.Attr
	fillEntry(&mode000, s3disk.Entry{Type: s3disk.EntryFile, Mode: 0})
	if mode000.Mode&0o777 != 0 {
		t.Fatalf("mode-000 file permissions = %#o", mode000.Mode&0o777)
	}
	var noExecute fuse.Attr
	fillEntry(&noExecute, s3disk.Entry{Type: s3disk.EntryDir, Mode: 0o440})
	if noExecute.Mode&0o111 != 0 {
		t.Fatalf("non-executable directory gained execute bits: %#o", noExecute.Mode&0o777)
	}
}

func assertPinnedAttr(t *testing.T, got fuse.Attr, want s3disk.Entry) {
	t.Helper()
	if got.Size != uint64(want.Size) || got.Mode != syscall.S_IFREG|want.Mode ||
		got.Atime != uint64(want.ModTime.Unix()) || got.Atimensec != uint32(want.ModTime.Nanosecond()) ||
		got.Mtime != uint64(want.ModTime.Unix()) || got.Mtimensec != uint32(want.ModTime.Nanosecond()) {
		t.Fatalf("pinned attr = %+v, want size=%d mode=%#o mtime=%v", got, want.Size, syscall.S_IFREG|want.Mode, want.ModTime)
	}
}

func TestInvalidationCancellationAndErrorReporting(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (&node{}).invalidateMaterialized(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled invalidation error = %v, want context.Canceled", err)
	}

	want := errors.New("invalidation failed")
	var reported error
	reportInvalidationError(func(err error) { reported = err }, want)
	if !errors.Is(reported, want) {
		t.Fatalf("reported invalidation error = %v, want %v", reported, want)
	}
	reported = nil
	reportInvalidationError(func(err error) { reported = err }, context.Canceled)
	if reported != nil {
		t.Fatalf("normal cancellation was reported: %v", reported)
	}
	// A customer callback cannot crash the poller.
	reportInvalidationError(func(error) { panic("test callback panic") }, want)
}

func TestMissingImmutableObjectIsNotReportedAsMissingPath(t *testing.T) {
	t.Parallel()
	if got := errno(s3disk.ErrObjectNotFound); got != syscall.EIO {
		t.Fatalf("ErrObjectNotFound errno = %v, want EIO", got)
	}
	if got := errno(s3disk.ErrPathNotFound); got != syscall.ENOENT {
		t.Fatalf("ErrPathNotFound errno = %v, want ENOENT", got)
	}
}

func TestTransientInvalidationFailureKeepsMaterializedInodes(t *testing.T) {
	t.Parallel()
	base := memstore.New()
	store := &failingGetStore{base: base}
	fixture := newInvalidationFixture(t, store, "mount-transient-invalidation")
	fixture.publishUpdate(t)
	store.fail.Store(true)
	err := fixture.root.invalidateMaterialized(context.Background())
	if !errors.Is(err, errInjectedInvalidationGet) {
		t.Fatalf("transient invalidation error = %v, want injected GET error", err)
	}
	if got := fixture.directory.GetChild("item"); got != fixture.fileInode {
		t.Fatalf("transient error removed materialized inode: got %p, want %p", got, fixture.fileInode)
	}
}

func TestInvalidationCancelsBlockedMetadataGet(t *testing.T) {
	t.Parallel()
	base := memstore.New()
	store := &blockingGetStore{base: base, entered: make(chan struct{}, 1)}
	fixture := newInvalidationFixture(t, store, "mount-cancel-invalidation")
	fixture.publishUpdate(t)
	store.block.Store(true)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- fixture.root.invalidateMaterialized(ctx) }()
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		t.Fatal("invalidation did not enter the blocking metadata GET")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled blocking invalidation error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("invalidation did not return after context cancellation")
	}
}

type invalidationFixture struct {
	publisher *s3disk.Publisher
	consumer  *s3disk.Consumer
	root      *node
	directory *node
	fileInode *fs.Inode
	source    string
	filePath  string
}

func newInvalidationFixture(t *testing.T, store s3disk.Store, prefix string) *invalidationFixture {
	t.Helper()
	ctx := context.Background()
	repository, err := s3disk.NewRepository(store, prefix)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	directoryPath := filepath.Join(source, "dir")
	if err := os.Mkdir(directoryPath, 0o755); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(directoryPath, "item")
	if err := os.WriteFile(filePath, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	snapshot, ok := consumer.CurrentSnapshot()
	if !ok {
		t.Fatal("initial consumer snapshot is absent")
	}
	directoryEntry, err := consumer.Stat(ctx, "dir")
	if err != nil {
		t.Fatal(err)
	}
	fileEntry, err := consumer.Stat(ctx, "dir/item")
	if err != nil {
		t.Fatal(err)
	}
	identity := identityOfSnapshot(snapshot)

	root := newRootNode(consumer, DefaultMaxInodeIdentities, DefaultMaxInodeIdentityBytes)
	_ = fs.NewNodeFS(root, &fs.Options{})
	directory := &node{
		consumer: consumer, path: "dir", entryType: s3disk.EntryDir,
		snapshotBound: true, snapshot: identity, snapshotEntry: directoryEntry,
		inodeIDs: root.inodeIDs,
	}
	directoryInode := root.NewPersistentInode(ctx, directory, fs.StableAttr{Mode: syscall.S_IFDIR})
	if !root.AddChild("dir", directoryInode, false) {
		t.Fatal("attach materialized directory inode")
	}
	fileNode := &node{
		consumer: consumer, path: "dir/item", entryType: s3disk.EntryFile,
		snapshotBound: true, snapshot: identity, snapshotEntry: fileEntry,
		inodeIDs: root.inodeIDs,
	}
	fileInode := directory.NewPersistentInode(ctx, fileNode, fs.StableAttr{Mode: syscall.S_IFREG})
	if !directory.AddChild("item", fileInode, false) {
		t.Fatal("attach materialized file inode")
	}
	return &invalidationFixture{
		publisher: publisher, consumer: consumer, root: root, directory: directory,
		fileInode: fileInode, source: source, filePath: filePath,
	}
}

func (fixture *invalidationFixture) publishUpdate(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if err := os.WriteFile(fixture.filePath, []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.publisher.Publish(ctx, fixture.source, "main"); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
}

var errInjectedInvalidationGet = errors.New("test: transient metadata GET failure")

type mountLookupCountingStore struct {
	s3disk.Store
	directoryGets atomic.Int64
	chunkGets     atomic.Int64
}

func (store *mountLookupCountingStore) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	if strings.Contains(key, "/objects/dir/") {
		store.directoryGets.Add(1)
	}
	if strings.Contains(key, "/objects/chunk/") {
		store.chunkGets.Add(1)
	}
	return store.Store.Get(ctx, key, options)
}

type failingGetStore struct {
	base *memstore.Store
	fail atomic.Bool
}

func (store *failingGetStore) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	if store.fail.Load() {
		return s3disk.Object{}, errInjectedInvalidationGet
	}
	return store.base.Get(ctx, key, options)
}

func (store *failingGetStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	return store.base.Head(ctx, key)
}

func (store *failingGetStore) PutIfAbsent(ctx context.Context, key string, data []byte) (s3disk.Version, error) {
	return store.base.PutIfAbsent(ctx, key, data)
}

func (store *failingGetStore) CompareAndSwap(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
	return store.base.CompareAndSwap(ctx, key, expected, data)
}

var _ s3disk.Store = (*failingGetStore)(nil)

type blockingGetStore struct {
	base    *memstore.Store
	block   atomic.Bool
	entered chan struct{}
}

func (store *blockingGetStore) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	if store.block.Load() {
		select {
		case store.entered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return s3disk.Object{}, ctx.Err()
	}
	return store.base.Get(ctx, key, options)
}

func (store *blockingGetStore) Head(ctx context.Context, key string) (s3disk.Version, error) {
	return store.base.Head(ctx, key)
}

func (store *blockingGetStore) PutIfAbsent(ctx context.Context, key string, data []byte) (s3disk.Version, error) {
	return store.base.PutIfAbsent(ctx, key, data)
}

func (store *blockingGetStore) CompareAndSwap(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
	return store.base.CompareAndSwap(ctx, key, expected, data)
}

var _ s3disk.Store = (*blockingGetStore)(nil)
