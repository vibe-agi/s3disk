package s3disk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/bits"
	"time"

	"github.com/restic/chunker"
)

const objectFormatVersion = 1

const (
	maxReferenceBytes      = 4 << 10
	maxMetadataObjectBytes = 16 << 20
	maxChunkObjectBytes    = 64 << 20
	maxDirectoryEntries    = 250_000
	maxFileChunks          = 250_000
	maxEntryNameBytes      = 255
	maxSymlinkTargetBytes  = 64 << 10
	maxLookupPathBytes     = 1 << 20
	maxLookupDepth         = 4096
	maxCommitWalk          = 1_000_000
)

const defaultPolynomial = uint64(0x3DA3358B4DC173)

// EntryType describes a filesystem entry stored in a directory manifest.
type EntryType string

const (
	EntryFile    EntryType = "file"
	EntryDir     EntryType = "directory"
	EntrySymlink EntryType = "symlink"
)

// SymlinkPolicy controls whether links which may escape the snapshot root are
// accepted. Rejecting them is the safe default for a read-only mount: otherwise
// the host kernel can follow a link into a writable path outside the mount.
type SymlinkPolicy uint8

const (
	SymlinkRejectExternal SymlinkPolicy = iota
	SymlinkPreserve
)

// ChunkingOptions controls content-defined chunking. AverageSize must be a
// power of two. Polynomial must be an irreducible degree-53 Rabin polynomial;
// zero selects a stable default. Production repository initialization should
// generate and persist a repository-specific polynomial.
type ChunkingOptions struct {
	MinSize     int
	AverageSize int
	MaxSize     int
	Polynomial  uint64
}

func (options ChunkingOptions) normalized() (ChunkingOptions, error) {
	if options.MinSize == 0 {
		options.MinSize = 256 << 10
	}
	if options.AverageSize == 0 {
		options.AverageSize = 1 << 20
	}
	if options.MaxSize == 0 {
		options.MaxSize = 4 << 20
	}
	if options.Polynomial == 0 {
		options.Polynomial = defaultPolynomial
	}
	if options.MinSize < 64 || options.MinSize >= options.AverageSize || options.AverageSize >= options.MaxSize {
		return ChunkingOptions{}, fmt.Errorf("%w: require 64 <= min < average < max", ErrInvalidChunking)
	}
	if options.AverageSize&(options.AverageSize-1) != 0 {
		return ChunkingOptions{}, fmt.Errorf("%w: average size must be a power of two", ErrInvalidChunking)
	}
	if options.MaxSize > 64<<20 {
		return ChunkingOptions{}, fmt.Errorf("%w: maximum chunk size exceeds 64 MiB", ErrInvalidChunking)
	}
	polynomial := chunker.Pol(options.Polynomial)
	if polynomial.Deg() != 53 || !polynomial.Irreducible() {
		return ChunkingOptions{}, fmt.Errorf("%w: polynomial is not irreducible degree 53", ErrInvalidChunking)
	}
	return options, nil
}

func (options ChunkingOptions) averageBits() int {
	return bits.TrailingZeros64(uint64(options.AverageSize))
}

type chunkRef struct {
	Offset int64  `json:"offset"`
	Size   int64  `json:"size"`
	Digest Digest `json:"digest"`
}

type fileManifest struct {
	Format     int        `json:"format"`
	Algorithm  string     `json:"algorithm"`
	MinSize    int        `json:"min_size"`
	AvgSize    int        `json:"average_size"`
	MaxSize    int        `json:"max_size"`
	Polynomial uint64     `json:"polynomial"`
	Size       int64      `json:"size"`
	Chunks     []chunkRef `json:"chunks"`
}

type symlinkManifest struct {
	Format int    `json:"format"`
	Target []byte `json:"target"`
}

type dirEntry struct {
	Name            []byte    `json:"name"`
	Type            EntryType `json:"type"`
	Node            Digest    `json:"node"`
	Mode            uint32    `json:"mode"`
	Size            int64     `json:"size"`
	ModTimeUnixNano int64     `json:"mtime_unix_nano"`
}

type dirManifest struct {
	Format  int        `json:"format"`
	Entries []dirEntry `json:"entries"`
}

type commitManifest struct {
	Format          int     `json:"format"`
	Generation      uint64  `json:"generation"`
	Parent          *Digest `json:"parent,omitempty"`
	Root            Digest  `json:"root"`
	PublishedAtUnix int64   `json:"published_at_unix_nano"`
	ResetChanges    bool    `json:"reset_changes"`
}

type snapshotReference struct {
	Format     int    `json:"format"`
	Generation uint64 `json:"generation"`
	Commit     Digest `json:"commit"`
}

func canonicalJSON(value any) ([]byte, error) {
	// Protocol structs contain no maps and directory entries are sorted by raw
	// name bytes, making encoding/json output deterministic. Golden tests guard
	// this representation against accidental format changes.
	return json.Marshal(value)
}

func decodeJSON(data []byte, value any) error {
	if len(data) > maxMetadataObjectBytes {
		return fmt.Errorf("%w: %w: metadata object exceeds %d bytes", ErrCorruptObject, ErrResourceLimit, maxMetadataObjectBytes)
	}
	if err := json.Unmarshal(data, value); err != nil {
		return fmt.Errorf("%w: %v", ErrCorruptObject, err)
	}
	canonical, err := canonicalJSON(value)
	if err != nil {
		return fmt.Errorf("%w: re-encode protocol object: %v", ErrCorruptObject, err)
	}
	if !bytes.Equal(data, canonical) {
		return fmt.Errorf("%w: protocol JSON is not canonical", ErrCorruptObject)
	}
	return nil
}

// Snapshot identifies one atomically published tree.
type Snapshot struct {
	Generation  uint64
	Commit      Digest
	Root        Digest
	PublishedAt time.Time
}

// Entry is portable metadata returned by Stat and ListDir. Mode contains only
// permission bits and always has write bits removed for a consumer view.
type Entry struct {
	Name    string
	Type    EntryType
	Size    int64
	Mode    uint32
	ModTime time.Time
}

func readonlyMode(mode uint32) uint32 { return mode &^ 0o222 }
