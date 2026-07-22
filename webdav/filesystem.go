package webdav

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path"
	"sync"
	"time"

	"github.com/vibe-agi/s3disk"
	xwebdav "golang.org/x/net/webdav"
)

type readOnlyFileSystem struct {
	consumer *s3disk.Consumer
	gate     *sync.RWMutex
}

type snapshotGateHeldKey struct{}
type snapshotHTTPValidatorKey struct{}

func (filesystem *readOnlyFileSystem) Mkdir(context.Context, string, os.FileMode) error {
	return os.ErrPermission
}

func (filesystem *readOnlyFileSystem) RemoveAll(context.Context, string) error {
	return os.ErrPermission
}

func (filesystem *readOnlyFileSystem) Rename(context.Context, string, string) error {
	return os.ErrPermission
}

func (filesystem *readOnlyFileSystem) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	unlock := filesystem.lockSnapshot(ctx)
	defer unlock()
	entry, err := filesystem.consumer.Stat(ctx, name)
	if err != nil {
		return nil, translateFileError("stat", name, err)
	}
	if entry.Type == s3disk.EntrySymlink {
		return nil, translateFileError("stat", name, ErrSymlinkUnsupported)
	}
	snapshot, ok := filesystem.consumer.CurrentSnapshot()
	if !ok {
		return nil, translateFileError("stat", name, s3disk.ErrNoSnapshot)
	}
	return newFileInfo(name, entry, snapshot.Generation, false), nil
}

func (filesystem *readOnlyFileSystem) OpenFile(
	ctx context.Context,
	name string,
	flag int,
	_ os.FileMode,
) (xwebdav.File, error) {
	unlock := filesystem.lockSnapshot(ctx)
	defer unlock()
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_EXCL|os.O_TRUNC) != 0 {
		return nil, translateFileError("open", name, os.ErrPermission)
	}
	entry, err := filesystem.consumer.Stat(ctx, name)
	if err != nil {
		return nil, translateFileError("open", name, err)
	}
	if entry.Type == s3disk.EntrySymlink {
		return nil, translateFileError("open", name, ErrSymlinkUnsupported)
	}
	snapshot, ok := filesystem.consumer.CurrentSnapshot()
	if !ok {
		return nil, translateFileError("open", name, s3disk.ErrNoSnapshot)
	}
	useHTTPValidator := ctx != nil && ctx.Value(snapshotHTTPValidatorKey{}) == true
	opened := &readOnlyFile{
		ctx: ctx, consumer: filesystem.consumer,
		info: newFileInfo(name, entry, snapshot.Generation, useHTTPValidator),
	}
	if entry.Type == s3disk.EntryDir {
		entries, listErr := filesystem.consumer.ListDir(ctx, name)
		if listErr != nil {
			return nil, translateFileError("readdir", name, listErr)
		}
		opened.entries = make([]os.FileInfo, 0, len(entries))
		for _, child := range entries {
			// WebDAV has no portable symbolic-link representation. Omitting links
			// is safer than presenting a file that resolves outside the DAV tree or
			// returning different bytes than a POSIX client would observe.
			if child.Type == s3disk.EntrySymlink {
				continue
			}
			opened.entries = append(opened.entries,
				newFileInfo(path.Join(name, child.Name), child, snapshot.Generation, useHTTPValidator))
		}
		return opened, nil
	}
	file, openErr := filesystem.consumer.Open(ctx, name)
	if openErr != nil {
		return nil, translateFileError("open", name, openErr)
	}
	opened.file = file
	return opened, nil
}

func (filesystem *readOnlyFileSystem) lockSnapshot(ctx context.Context) func() {
	if filesystem == nil || filesystem.gate == nil ||
		(ctx != nil && ctx.Value(snapshotGateHeldKey{}) == true) {
		return func() {}
	}
	filesystem.gate.RLock()
	return filesystem.gate.RUnlock
}

func translateFileError(operation, name string, err error) error {
	if err == nil {
		return nil
	}
	translated := err
	switch {
	case errors.Is(err, s3disk.ErrPathNotFound), errors.Is(err, s3disk.ErrNoSnapshot),
		errors.Is(err, ErrSymlinkUnsupported):
		translated = os.ErrNotExist
	case errors.Is(err, s3disk.ErrInvalidPath), errors.Is(err, s3disk.ErrNotDirectory),
		errors.Is(err, s3disk.ErrIsDirectory), errors.Is(err, s3disk.ErrUnsupportedType):
		translated = os.ErrInvalid
	}
	return &os.PathError{Op: operation, Path: name, Err: translated}
}

type fileInfo struct {
	name       string
	path       string
	entry      s3disk.Entry
	generation uint64
	httpTime   bool
}

func newFileInfo(name string, entry s3disk.Entry, generation uint64, httpTime bool) fileInfo {
	cleaned := path.Clean("/" + name)
	base := path.Base(cleaned)
	if cleaned == "/" {
		base = "/"
	}
	if entry.Name != "" {
		base = entry.Name
	}
	return fileInfo{
		name: base, path: cleaned, entry: entry, generation: generation,
		httpTime: httpTime,
	}
}

func (info fileInfo) Name() string { return info.name }
func (info fileInfo) Size() int64  { return max(info.entry.Size, 0) }
func (info fileInfo) ModTime() time.Time {
	if info.httpTime {
		return snapshotHTTPValidatorTime(info.generation)
	}
	return info.entry.ModTime
}
func (info fileInfo) IsDir() bool { return info.entry.Type == s3disk.EntryDir }
func (info fileInfo) Sys() any    { return nil }

// snapshotHTTPValidatorTime maps every practically representable generation
// to a stable whole-second HTTP date. It is deliberately separate from the
// source mtime exposed by PROPFIND. Generation zero or a value beyond the
// four-digit HTTP year range returns zero, which makes net/http ignore weak
// date validators and safely send the representation in full.
func snapshotHTTPValidatorTime(generation uint64) time.Time {
	const (
		validatorEpochUnix = int64(946684800)    // 2000-01-01T00:00:00Z
		maximumHTTPUnix    = int64(253402300799) // 9999-12-31T23:59:59Z
	)
	if generation == 0 || generation > uint64(maximumHTTPUnix-validatorEpochUnix) {
		return time.Time{}
	}
	return time.Unix(validatorEpochUnix+int64(generation), 0).UTC()
}

func (info fileInfo) Mode() os.FileMode {
	mode := os.FileMode(info.entry.Mode & 0o777)
	switch info.entry.Type {
	case s3disk.EntryDir:
		return mode | os.ModeDir
	case s3disk.EntrySymlink:
		return mode | os.ModeSymlink
	default:
		return mode
	}
}

// ETag uses the immutable snapshot generation and canonical resource path.
// Every publication advances the generation, so metadata and content changes
// necessarily produce a different validator even when size and mtime collide.
func (info fileInfo) ETag(context.Context) (string, error) {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s", info.generation, info.path)))
	return fmt.Sprintf("\"s3disk-%x\"", digest[:16]), nil
}

// ContentType keeps PROPFIND metadata-only. The generic x/net/webdav fallback
// opens and samples unknown files, which would otherwise turn a directory
// listing into lazy chunk downloads.
func (info fileInfo) ContentType(context.Context) (string, error) {
	if contentType := mime.TypeByExtension(path.Ext(info.path)); contentType != "" {
		return contentType, nil
	}
	return "application/octet-stream", nil
}

type readOnlyFile struct {
	mu       sync.Mutex
	ctx      context.Context
	consumer *s3disk.Consumer
	file     *s3disk.File
	info     fileInfo
	offset   int64
	entries  []os.FileInfo
	dirIndex int
	closed   bool
}

func (file *readOnlyFile) Close() error {
	file.mu.Lock()
	defer file.mu.Unlock()
	file.closed = true
	file.file = nil
	file.entries = nil
	return nil
}

func (file *readOnlyFile) Stat() (os.FileInfo, error) {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.closed {
		return nil, os.ErrClosed
	}
	return file.info, nil
}

func (file *readOnlyFile) Read(destination []byte) (int, error) {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.closed {
		return 0, os.ErrClosed
	}
	if file.info.IsDir() {
		return 0, &os.PathError{Op: "read", Path: file.info.path, Err: os.ErrInvalid}
	}
	count, err := file.file.ReadAtContext(file.ctx, destination, file.offset)
	file.offset += int64(count)
	return count, err
}

func (file *readOnlyFile) Seek(offset int64, whence int) (int64, error) {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.closed {
		return 0, os.ErrClosed
	}
	var next int64
	switch whence {
	case io.SeekStart:
		next = offset
	case io.SeekCurrent:
		next = file.offset + offset
	case io.SeekEnd:
		next = file.info.Size() + offset
	default:
		return 0, &os.PathError{Op: "seek", Path: file.info.path, Err: os.ErrInvalid}
	}
	if next < 0 {
		return 0, &os.PathError{Op: "seek", Path: file.info.path, Err: os.ErrInvalid}
	}
	file.offset = next
	return next, nil
}

func (file *readOnlyFile) Readdir(count int) ([]os.FileInfo, error) {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.closed {
		return nil, os.ErrClosed
	}
	if !file.info.IsDir() {
		return nil, &os.PathError{Op: "readdir", Path: file.info.path, Err: os.ErrInvalid}
	}
	if count <= 0 {
		remaining := append([]os.FileInfo(nil), file.entries[file.dirIndex:]...)
		file.dirIndex = len(file.entries)
		return remaining, nil
	}
	if file.dirIndex >= len(file.entries) {
		return nil, io.EOF
	}
	end := min(file.dirIndex+count, len(file.entries))
	result := append([]os.FileInfo(nil), file.entries[file.dirIndex:end]...)
	file.dirIndex = end
	return result, nil
}

func (*readOnlyFile) Write([]byte) (int, error) { return 0, os.ErrPermission }

var _ xwebdav.FileSystem = (*readOnlyFileSystem)(nil)
var _ xwebdav.File = (*readOnlyFile)(nil)
var _ xwebdav.ETager = fileInfo{}
var _ xwebdav.ContentTyper = fileInfo{}
