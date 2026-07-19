package s3disk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const watermarkFormatVersion = 1
const maxWatermarkBytes = 4096

// Watermark is the highest commit a consumer has durably accepted. Persisting
// it prevents a restarted process from accepting an older but otherwise valid
// reference returned by a stale or restored object store.
type Watermark struct {
	RepositoryID RepositoryID
	Generation   uint64
	Commit       Digest
}

// WatermarkStore durably stores a consumer's monotonic anti-rollback anchor.
// CompareAndSwap must be atomic across processes, reject a mismatched expected
// state, and reject lower generations or a different commit at the same
// generation. Load must return only state whose namespace update is durable
// against a later machine crash, including when another process died after a
// visible rename but before its parent-directory sync. Implementations may use
// channel to namespace state.
type WatermarkStore interface {
	Load(ctx context.Context, channel string) (Watermark, bool, error)
	CompareAndSwap(ctx context.Context, channel string, expected *Watermark, next Watermark) error
}

// FileWatermarkStore stores one channel watermark in a crash-safe local file.
// Use a distinct path for every repository/channel pair.
type FileWatermarkStore struct {
	path     string
	lockPath string
	mu       sync.Mutex

	syncDirectory func(string) error
}

type watermarkFile struct {
	Format     int    `json:"format"`
	Channel    string `json:"channel"`
	Repository string `json:"repository_id,omitempty"`
	Generation uint64 `json:"generation"`
	Commit     Digest `json:"commit"`
}

func NewFileWatermarkStore(path string) (*FileWatermarkStore, error) {
	if path == "" {
		return nil, fmt.Errorf("s3disk: empty watermark path")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("s3disk: absolute watermark path: %w", err)
	}
	directory, err := prepareWatermarkDirectory(filepath.Dir(absolute))
	if err != nil {
		return nil, fmt.Errorf("s3disk: create watermark directory: %w", err)
	}
	absolute = filepath.Join(directory, filepath.Base(absolute))
	return &FileWatermarkStore{
		path: absolute, lockPath: absolute + ".lock", syncDirectory: syncWatermarkDirectory,
	}, nil
}

func (store *FileWatermarkStore) Load(ctx context.Context, channel string) (Watermark, bool, error) {
	if err := ctx.Err(); err != nil {
		return Watermark{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	unlock, err := lockWatermarkFile(ctx, store.lockPath)
	if err != nil {
		return Watermark{}, false, err
	}
	watermark, found, loadErr := store.loadLocked(channel)
	if loadErr == nil && found {
		// Complete a rename left visible by a process which crashed before its
		// directory sync. Returning it early can later lose this anti-rollback
		// anchor on a machine crash.
		loadErr = store.syncParentDirectory()
	}
	unlockErr := unlock()
	if loadErr != nil {
		return Watermark{}, false, loadErr
	}
	if unlockErr != nil {
		return Watermark{}, false, unlockErr
	}
	return watermark, found, nil
}

func (store *FileWatermarkStore) loadLocked(channel string) (Watermark, bool, error) {
	linkInfo, err := os.Lstat(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return Watermark{}, false, nil
	}
	if err != nil {
		return Watermark{}, false, fmt.Errorf("s3disk: inspect watermark: %w", err)
	}
	file, err := os.Open(store.path)
	if err != nil {
		return Watermark{}, false, fmt.Errorf("s3disk: open watermark: %w", err)
	}
	defer file.Close()
	info, err := validateWatermarkOpenedPath(store.path, linkInfo, file, false)
	if err != nil {
		return Watermark{}, false, err
	}
	if info.Size() < 1 || info.Size() > maxWatermarkBytes {
		return Watermark{}, false, fmt.Errorf("%w: invalid watermark file", ErrCorruptObject)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxWatermarkBytes+1))
	if err != nil {
		return Watermark{}, false, fmt.Errorf("s3disk: read watermark: %w", err)
	}
	var value watermarkFile
	if err := decodeJSON(data, &value); err != nil {
		return Watermark{}, false, fmt.Errorf("s3disk: decode watermark: %w", err)
	}
	if value.Format != watermarkFormatVersion || value.Channel != channel || value.Generation == 0 || value.Commit.IsZero() {
		return Watermark{}, false, fmt.Errorf("%w: invalid or mismatched watermark", ErrCorruptObject)
	}
	var repositoryID RepositoryID
	if value.Repository != "" {
		repositoryID, err = ParseRepositoryID(value.Repository)
		if err != nil || repositoryID.IsZero() {
			return Watermark{}, false, fmt.Errorf("%w: invalid watermark repository ID", ErrCorruptObject)
		}
	}
	return Watermark{RepositoryID: repositoryID, Generation: value.Generation, Commit: value.Commit}, true, nil
}

// CompareAndSwap atomically installs next only if the durable state exactly
// matches expected. A nil expected value requires the watermark to be absent.
func (store *FileWatermarkStore) CompareAndSwap(ctx context.Context, channel string, expected *Watermark, next Watermark) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateChannel(channel); err != nil {
		return err
	}
	if next.Generation == 0 || next.Commit.IsZero() {
		return fmt.Errorf("%w: invalid watermark", ErrCorruptObject)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	unlock, err := lockWatermarkFile(ctx, store.lockPath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	current, found, err := store.loadLocked(channel)
	if err != nil {
		return err
	}
	if expected == nil {
		if found {
			return ErrPrecondition
		}
	} else if !found || current != *expected {
		return ErrPrecondition
	}
	if found {
		switch {
		case next.RepositoryID != current.RepositoryID:
			return ErrUntrustedReference
		case next.Generation < current.Generation:
			return ErrRollbackDetected
		case next.Generation == current.Generation && next.Commit != current.Commit:
			return ErrSplitBrain
		case next == current:
			// The current file may have been made visible by a process which died
			// after rename but before syncing the parent directory. An idempotent
			// CAS is still a successful durability claim, so complete that barrier
			// before returning without rewriting the file.
			return store.syncParentDirectory()
		}
	}
	repository := ""
	if !next.RepositoryID.IsZero() {
		repository = next.RepositoryID.String()
	}
	data, err := canonicalJSON(watermarkFile{
		Format: watermarkFormatVersion, Channel: channel,
		Repository: repository, Generation: next.Generation, Commit: next.Commit,
	})
	if err != nil {
		return fmt.Errorf("s3disk: encode watermark: %w", err)
	}
	directory := filepath.Dir(store.path)
	temporary, err := os.CreateTemp(directory, ".s3disk-watermark-*")
	if err != nil {
		return fmt.Errorf("s3disk: create watermark temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := protectWatermarkFile(temporaryName, temporary); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("s3disk: protect watermark: %w", err)
	}
	written, err := temporary.Write(data)
	if err != nil {
		_ = temporary.Close()
		return fmt.Errorf("s3disk: write watermark: %w", err)
	}
	if written != len(data) {
		_ = temporary.Close()
		return fmt.Errorf("s3disk: write watermark: %w", io.ErrShortWrite)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("s3disk: sync watermark: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("s3disk: close watermark: %w", err)
	}
	if err := installWatermarkFile(temporaryName, store.path); err != nil {
		return fmt.Errorf("s3disk: install watermark: %w", err)
	}
	removeTemporary = false
	if err := store.syncParentDirectory(); err != nil {
		return err
	}
	return nil
}

func (store *FileWatermarkStore) syncParentDirectory() error {
	syncDirectory := store.syncDirectory
	if syncDirectory == nil {
		syncDirectory = syncWatermarkDirectory
	}
	return syncDirectory(filepath.Dir(store.path))
}

// Save is a convenience method for direct callers. Concurrent users should
// prefer CompareAndSwap so a stale validation cannot overwrite another branch.
func (store *FileWatermarkStore) Save(ctx context.Context, channel string, next Watermark) error {
	current, found, err := store.Load(ctx, channel)
	if err != nil {
		return err
	}
	var expected *Watermark
	if found {
		expected = &current
	}
	return store.CompareAndSwap(ctx, channel, expected, next)
}

func validateWatermarkOpenedPath(path string, linked os.FileInfo, file *os.File, directory bool) (os.FileInfo, error) {
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("s3disk: stat watermark path: %w", err)
	}
	kindMatches := linked.Mode().IsRegular() && opened.Mode().IsRegular()
	if directory {
		kindMatches = linked.IsDir() && opened.IsDir()
	}
	if !kindMatches || !os.SameFile(linked, opened) {
		return nil, fmt.Errorf("%w: unsafe watermark path type or identity", ErrCorruptObject)
	}
	if err := validateWatermarkPathSecurity(path, linked, opened, file, directory); err != nil {
		return nil, err
	}
	return opened, nil
}

var _ WatermarkStore = (*FileWatermarkStore)(nil)
