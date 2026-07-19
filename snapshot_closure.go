package s3disk

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"sort"
	"time"
)

const (
	// DefaultMaxSnapshotClosureObjects bounds the exact object-key set returned
	// by ResolveSnapshotClosure. Flat presigned-capability bundles should usually
	// select a lower product limit; larger shares need a sharded capability
	// index rather than an unbounded in-memory URL list.
	DefaultMaxSnapshotClosureObjects = 100_000
	// MaxSnapshotClosureObjectsLimit is a defensive ceiling on the complete
	// returned key set, including commit history and the current tree. It is
	// independent of the protocol's commit-ancestry edge limit.
	MaxSnapshotClosureObjectsLimit = 1_000_000
	// DefaultMaxSnapshotClosureEdges bounds directory-entry and file-chunk
	// references examined even when many references deduplicate to one key.
	DefaultMaxSnapshotClosureEdges int64 = 1_000_000
	// MaxSnapshotClosureEdgesLimit is the defensive API ceiling for MaxEdges.
	MaxSnapshotClosureEdgesLimit int64 = 100_000_000
	// DefaultMaxSnapshotClosureMetadataBytes bounds the aggregate encoded bytes
	// of commit, directory, file, and symlink manifests read during one walk.
	DefaultMaxSnapshotClosureMetadataBytes int64 = 512 << 20
	// MaxSnapshotClosureMetadataBytesLimit is the defensive API ceiling for the
	// aggregate manifest-byte budget. Individual manifests remain subject to the
	// much smaller protocol limit.
	MaxSnapshotClosureMetadataBytesLimit int64 = 64 << 30
)

// SnapshotClosureOptions controls exact-key closure discovery.
type SnapshotClosureOptions struct {
	// ReferenceVerifier selects and authenticates the signed-reference
	// namespace. Nil selects the unsigned namespace.
	ReferenceVerifier ReferenceVerifier
	// MaxObjects bounds commits, manifests, and chunks in the returned set.
	// Zero selects DefaultMaxSnapshotClosureObjects.
	MaxObjects int
	// MaxEdges bounds directory entries and file chunk references examined,
	// including references which deduplicate to an already-seen object key. Zero
	// selects DefaultMaxSnapshotClosureEdges.
	MaxEdges int64
	// MaxMetadataBytes bounds the aggregate encoded bytes of every immutable
	// manifest downloaded by this operation. Zero selects
	// DefaultMaxSnapshotClosureMetadataBytes.
	MaxMetadataBytes int64
}

// SnapshotClosure is an atomic reference observation plus the exact immutable
// object keys needed to consume it. ReferenceData is embedded by a share
// bundle; ReferenceKey itself therefore does not appear in ObjectKeys.
//
// ObjectKeys contains the current tree closure and every commit object back to
// generation one. The ancestry is required when a consumer which missed one
// or more bundle revisions validates that the newest commit descends from its
// durable watermark. Historical tree data is not included; an expiring share
// reader may retain older exact-key capabilities for already-open handles.
type SnapshotClosure struct {
	Snapshot                   Snapshot
	ReferenceKey               string
	ReferenceData              []byte
	ReferenceVersion           Version
	ObjectKeys                 []string
	resolutionSeal             [sha256.Size]byte
	clientEncryptionConfigured bool
	clientEncryptionBinding    [sha256.Size]byte
}

// ValidateResolved verifies that closure is an unchanged value returned by
// Repository.ResolveSnapshotClosure. The unexported seal prevents a caller
// from manually assembling a plausible closure or adding/removing an object
// key before a least-privilege capability bundle is minted.
func (closure SnapshotClosure) ValidateResolved() error {
	want := snapshotClosureResolutionSeal(closure)
	if closure.resolutionSeal == ([sha256.Size]byte{}) || closure.resolutionSeal != want {
		return ErrInvalidSnapshotClosure
	}
	return nil
}

// ValidateResolvedForClientEncryption additionally proves that closure was
// resolved through a Repository using the same client-encryption profile. A nil
// profile matches only an unencrypted Repository. This prevents a share root
// from sealing capabilities for ciphertext while embedding a plaintext
// reference, or the inverse profile mismatch.
func (closure SnapshotClosure) ValidateResolvedForClientEncryption(profile *ClientEncryptionProfile) error {
	if err := closure.ValidateResolved(); err != nil {
		return err
	}
	configured := profile != nil && profile.configured()
	binding := profile.snapshotClosureBinding()
	if closure.clientEncryptionConfigured != configured ||
		subtle.ConstantTimeCompare(closure.clientEncryptionBinding[:], binding[:]) != 1 {
		return fmt.Errorf("%w: snapshot closure client-encryption profile does not match", ErrInvalidSnapshotClosure)
	}
	return nil
}

// ResolveSnapshotClosure reads one channel reference atomically, authenticates
// it when a verifier is supplied, and walks only immutable objects reachable
// from that observation. It never lists the bucket or repository prefix.
func (repository *Repository) ResolveSnapshotClosure(
	ctx context.Context,
	channel string,
	options SnapshotClosureOptions,
) (SnapshotClosure, error) {
	if repository == nil || !interfaceDependencyConfigured(repository.reader) {
		return SnapshotClosure{}, fmt.Errorf("%w: repository has no object reader", ErrStoreMisconfigured)
	}
	if ctx == nil {
		return SnapshotClosure{}, fmt.Errorf("s3disk: nil snapshot closure context")
	}
	if options.ReferenceVerifier != nil && !interfaceDependencyConfigured(options.ReferenceVerifier) {
		return SnapshotClosure{}, fmt.Errorf("s3disk: reference verifier must not be a typed nil")
	}
	if err := repository.validateChannel(channel); err != nil {
		return SnapshotClosure{}, err
	}
	maximumObjects := options.MaxObjects
	if maximumObjects == 0 {
		maximumObjects = DefaultMaxSnapshotClosureObjects
	}
	if maximumObjects < 1 || maximumObjects > MaxSnapshotClosureObjectsLimit {
		return SnapshotClosure{}, fmt.Errorf(
			"%w: snapshot closure max objects must be between 1 and %d",
			ErrResourceLimit,
			MaxSnapshotClosureObjectsLimit,
		)
	}
	maximumEdges := options.MaxEdges
	if maximumEdges == 0 {
		maximumEdges = DefaultMaxSnapshotClosureEdges
	}
	if maximumEdges < 1 || maximumEdges > MaxSnapshotClosureEdgesLimit {
		return SnapshotClosure{}, fmt.Errorf(
			"%w: snapshot closure max edges must be between 1 and %d",
			ErrResourceLimit,
			MaxSnapshotClosureEdgesLimit,
		)
	}
	maximumMetadataBytes := options.MaxMetadataBytes
	if maximumMetadataBytes == 0 {
		maximumMetadataBytes = DefaultMaxSnapshotClosureMetadataBytes
	}
	if maximumMetadataBytes < 1 || maximumMetadataBytes > MaxSnapshotClosureMetadataBytesLimit {
		return SnapshotClosure{}, fmt.Errorf(
			"%w: snapshot closure max metadata bytes must be between 1 and %d",
			ErrResourceLimit,
			MaxSnapshotClosureMetadataBytesLimit,
		)
	}

	reference, referenceObject, err := repository.getReferenceWithVerifier(
		ctx, channel, "", options.ReferenceVerifier,
	)
	if err != nil {
		return SnapshotClosure{}, fmt.Errorf("resolve snapshot closure reference: %w", err)
	}
	if reference.Generation > uint64(maximumObjects) {
		return SnapshotClosure{}, fmt.Errorf(
			"%w: %d commit objects alone exceed the %d-object snapshot closure bound",
			ErrResourceLimit,
			reference.Generation,
			maximumObjects,
		)
	}

	walker := snapshotClosureWalker{
		repository:           repository,
		maximumObjects:       maximumObjects,
		maximumEdges:         maximumEdges,
		maximumMetadataBytes: maximumMetadataBytes,
		seenKeys:             make(map[string]struct{}),
		scheduled:            make(map[snapshotClosureNode]struct{}),
		fileSizes:            make(map[Digest]int64),
		linkSizes:            make(map[Digest]int64),
	}
	var currentCommit commitManifest
	if err := walker.getManifest(ctx, "commit", reference.Commit, &currentCommit); err != nil {
		return SnapshotClosure{}, fmt.Errorf("resolve snapshot closure commit: %w", err)
	}
	if err := validateCommitManifest(&currentCommit, reference.Generation); err != nil {
		return SnapshotClosure{}, fmt.Errorf("resolve snapshot closure commit/reference mismatch: %w", err)
	}
	commit := currentCommit
	commitDigest := reference.Commit
	for generation := reference.Generation; ; generation-- {
		if err := walker.addKey("commit", commitDigest); err != nil {
			return SnapshotClosure{}, err
		}
		if generation == 1 {
			break
		}
		if err := ctx.Err(); err != nil {
			return SnapshotClosure{}, err
		}
		if commit.Parent == nil || commit.Parent.IsZero() {
			return SnapshotClosure{}, fmt.Errorf("%w: commit ancestry ends before generation one", ErrSplitBrain)
		}
		commitDigest = *commit.Parent
		// JSON fields omitted by an older commit must not retain values from the
		// newer commit previously decoded into this variable.
		commit = commitManifest{}
		if err := walker.getManifest(ctx, "commit", commitDigest, &commit); err != nil {
			return SnapshotClosure{}, fmt.Errorf("resolve snapshot closure ancestry at generation %d: %w", generation-1, err)
		}
		if err := validateCommitManifest(&commit, generation-1); err != nil {
			return SnapshotClosure{}, fmt.Errorf("resolve snapshot closure ancestry at generation %d: %w", generation-1, err)
		}
	}

	if err := walker.schedule(snapshotClosureNode{kind: "dir", digest: currentCommit.Root}, -1, 0); err != nil {
		return SnapshotClosure{}, err
	}
	if err := walker.walk(ctx); err != nil {
		return SnapshotClosure{}, err
	}
	sort.Strings(walker.keys)
	referenceKey := repository.ReferenceKey(channel)
	if options.ReferenceVerifier != nil {
		referenceKey = repository.SignedReferenceKey(channel)
	}
	closure := SnapshotClosure{
		Snapshot: Snapshot{
			Generation:  reference.Generation,
			Commit:      reference.Commit,
			Root:        currentCommit.Root,
			PublishedAt: time.Unix(0, currentCommit.PublishedAtUnix).UTC(),
		},
		ReferenceKey:     referenceKey,
		ReferenceData:    append([]byte(nil), referenceObject.Data...),
		ReferenceVersion: referenceObject.Version,
		ObjectKeys:       append([]string(nil), walker.keys...),
	}
	closure.clientEncryptionConfigured = repository.clientEncryption != nil
	closure.clientEncryptionBinding = repository.clientEncryption.snapshotClosureBinding()
	closure.resolutionSeal = snapshotClosureResolutionSeal(closure)
	return closure, nil
}

func snapshotClosureResolutionSeal(closure SnapshotClosure) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("s3disk\x00resolved-snapshot-closure\x00v1\x00"))
	writeUint64 := func(value uint64) {
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], value)
		_, _ = hash.Write(encoded[:])
	}
	writeBytes := func(value []byte) {
		writeUint64(uint64(len(value)))
		_, _ = hash.Write(value)
	}
	writeString := func(value string) { writeBytes([]byte(value)) }
	writeUint64(closure.Snapshot.Generation)
	_, _ = hash.Write(closure.Snapshot.Commit[:])
	_, _ = hash.Write(closure.Snapshot.Root[:])
	writeUint64(uint64(closure.Snapshot.PublishedAt.UnixNano()))
	writeString(closure.ReferenceKey)
	writeBytes(closure.ReferenceData)
	writeString(closure.ReferenceVersion.ETag)
	writeString(closure.ReferenceVersion.VersionID)
	writeUint64(uint64(len(closure.ObjectKeys)))
	for _, key := range closure.ObjectKeys {
		writeString(key)
	}
	if closure.clientEncryptionConfigured {
		_, _ = hash.Write([]byte{1})
	} else {
		_, _ = hash.Write([]byte{0})
	}
	_, _ = hash.Write(closure.clientEncryptionBinding[:])
	var seal [sha256.Size]byte
	copy(seal[:], hash.Sum(nil))
	return seal
}

type snapshotClosureNode struct {
	kind   string
	digest Digest
}

type snapshotClosureWork struct {
	node  snapshotClosureNode
	depth int
}

type snapshotClosureWalker struct {
	repository           *Repository
	maximumObjects       int
	maximumEdges         int64
	maximumMetadataBytes int64
	edges                int64
	metadataBytes        int64
	keys                 []string
	seenKeys             map[string]struct{}
	scheduled            map[snapshotClosureNode]struct{}
	work                 []snapshotClosureWork
	fileSizes            map[Digest]int64
	linkSizes            map[Digest]int64
}

func (walker *snapshotClosureWalker) addKey(kind string, digest Digest) error {
	key := walker.repository.objectKey(kind, digest)
	if _, exists := walker.seenKeys[key]; exists {
		return nil
	}
	if len(walker.keys) >= walker.maximumObjects {
		return fmt.Errorf(
			"%w: snapshot closure exceeds %d exact object keys",
			ErrResourceLimit,
			walker.maximumObjects,
		)
	}
	walker.seenKeys[key] = struct{}{}
	walker.keys = append(walker.keys, key)
	return nil
}

func (walker *snapshotClosureWalker) addEdge(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if walker.edges >= walker.maximumEdges {
		return fmt.Errorf(
			"%w: snapshot closure exceeds %d manifest edges",
			ErrResourceLimit,
			walker.maximumEdges,
		)
	}
	walker.edges++
	return nil
}

// getManifest applies the aggregate byte budget to the same immutable bytes
// which are subsequently authenticated and decoded. Passing the remaining
// budget to ObjectReader.Get prevents an adapter from buffering beyond the
// operation-wide limit; charging len(data) afterwards keeps accounting exact.
func (walker *snapshotClosureWalker) getManifest(ctx context.Context, kind string, digest Digest, value any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	remaining := walker.maximumMetadataBytes - walker.metadataBytes
	if remaining < 1 {
		return fmt.Errorf(
			"%w: snapshot closure exceeds %d metadata bytes",
			ErrResourceLimit,
			walker.maximumMetadataBytes,
		)
	}
	limit := remaining
	if limit > maxMetadataObjectBytes {
		limit = maxMetadataObjectBytes
	}
	data, err := walker.repository.getImmutableLimited(ctx, kind, digest, limit)
	if err != nil {
		return err
	}
	walker.metadataBytes += int64(len(data))
	return decodeJSON(data, value)
}

func (walker *snapshotClosureWalker) schedule(node snapshotClosureNode, expectedSize int64, depth int) error {
	if depth > maxLookupDepth {
		return fmt.Errorf("%w: snapshot closure exceeds %d directory levels", ErrResourceLimit, maxLookupDepth)
	}
	switch node.kind {
	case "file":
		if known, exists := walker.fileSizes[node.digest]; exists && known != expectedSize {
			return fmt.Errorf("%w: one file manifest is referenced with conflicting sizes", ErrCorruptObject)
		}
		walker.fileSizes[node.digest] = expectedSize
	case "symlink":
		if known, exists := walker.linkSizes[node.digest]; exists && known != expectedSize {
			return fmt.Errorf("%w: one symlink manifest is referenced with conflicting sizes", ErrCorruptObject)
		}
		walker.linkSizes[node.digest] = expectedSize
	}
	if _, exists := walker.scheduled[node]; exists {
		return nil
	}
	if err := walker.addKey(node.kind, node.digest); err != nil {
		return err
	}
	walker.scheduled[node] = struct{}{}
	walker.work = append(walker.work, snapshotClosureWork{node: node, depth: depth})
	return nil
}

func (walker *snapshotClosureWalker) walk(ctx context.Context) error {
	for len(walker.work) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		last := len(walker.work) - 1
		item := walker.work[last]
		walker.work = walker.work[:last]
		switch item.node.kind {
		case "dir":
			var manifest dirManifest
			if err := walker.getManifest(ctx, "dir", item.node.digest, &manifest); err != nil {
				return fmt.Errorf("resolve snapshot closure directory: %w", err)
			}
			if err := validateDirectoryManifest(&manifest); err != nil {
				return err
			}
			for _, entry := range manifest.Entries {
				if err := walker.addEdge(ctx); err != nil {
					return err
				}
				node := snapshotClosureNode{digest: entry.Node}
				expectedSize := entry.Size
				switch entry.Type {
				case EntryDir:
					node.kind = "dir"
					expectedSize = -1
				case EntryFile:
					node.kind = "file"
				case EntrySymlink:
					node.kind = "symlink"
				default:
					return fmt.Errorf("%w: invalid directory entry type", ErrCorruptObject)
				}
				if err := walker.schedule(node, expectedSize, item.depth+1); err != nil {
					return err
				}
			}
		case "file":
			var manifest fileManifest
			if err := walker.getManifest(ctx, "file", item.node.digest, &manifest); err != nil {
				return fmt.Errorf("resolve snapshot closure file: %w", err)
			}
			if err := validateFileManifest(&manifest); err != nil {
				return err
			}
			if expected := walker.fileSizes[item.node.digest]; expected != manifest.Size {
				return fmt.Errorf("%w: directory/file size mismatch", ErrCorruptObject)
			}
			for _, chunk := range manifest.Chunks {
				if err := walker.addEdge(ctx); err != nil {
					return err
				}
				if err := walker.addKey("chunk", chunk.Digest); err != nil {
					return err
				}
			}
		case "symlink":
			var manifest symlinkManifest
			if err := walker.getManifest(ctx, "symlink", item.node.digest, &manifest); err != nil {
				return fmt.Errorf("resolve snapshot closure symlink: %w", err)
			}
			if err := validateSymlinkManifest(&manifest); err != nil {
				return err
			}
			if expected := walker.linkSizes[item.node.digest]; expected != int64(len(manifest.Target)) {
				return fmt.Errorf("%w: directory/symlink size mismatch", ErrCorruptObject)
			}
		default:
			return fmt.Errorf("%w: unsupported snapshot closure object kind", ErrCorruptObject)
		}
	}
	return nil
}
