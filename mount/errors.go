package mount

import "errors"

const (
	// DefaultMaxInodeIdentities bounds the exact, collision-free stable inode
	// registry. One identity is consumed for each snapshot/path/type tuple ever
	// materialized during a mount lifetime.
	DefaultMaxInodeIdentities = 1_000_000
	// MaxInodeIdentitiesLimit prevents a configuration typo from authorizing an
	// effectively unbounded map. Products needing a larger namespace should
	// shard mounts and certify that scale explicitly.
	MaxInodeIdentitiesLimit = 10_000_000
	// DefaultMaxInodeIdentityBytes is the finite retained-memory budget for the
	// exact inode identity registry. The registry charges a conservative
	// estimate for every unique snapshot/path/type tuple.
	DefaultMaxInodeIdentityBytes int64 = 256 << 20
	// MaxInodeIdentityBytesLimit prevents a configuration typo from authorizing
	// an effectively unbounded registry. Larger products should shard mounts
	// and certify the resulting memory envelope explicitly.
	MaxInodeIdentityBytesLimit int64 = 4 << 30
)

// ErrUnsupportedPlatform reports that the current operating system has no
// native mount adapter. It is exported on every platform so callers can use
// errors.Is without conditional source files.
var ErrUnsupportedPlatform = errors.New("s3disk mount: this platform needs a native mount adapter")

// ErrKernelCacheUnsupported reports that KernelCache was requested even though
// the kernel page cache is shared by inode and cannot preserve different bytes
// for old and new snapshot-pinned file handles at the same path.
var ErrKernelCacheUnsupported = errors.New("s3disk mount: kernel page cache is incompatible with snapshot-pinned handles")

// ErrNegativeCacheUnsupported reports that a positive NegativeTTL was
// requested. Several supported Linux kernels fail to invalidate cached
// negative dentries, so the consistency contract disables this optimization
// instead of exposing kernel-version-dependent freshness.
var ErrNegativeCacheUnsupported = errors.New("s3disk mount: negative dentry caching is incompatible with refresh freshness")

// ErrDurableWatermarkRequired reports that a Consumer without a configured
// durable WatermarkStore was passed to ReadOnly without the explicit dangerous
// opt-out. Mounts are long-lived views and must reject rollback across process
// restarts by default.
var ErrDurableWatermarkRequired = errors.New("s3disk mount: durable consumer watermark is required")

// ErrSymlinkPreserveUnsafe reports that a Consumer configured with
// s3disk.SymlinkPreserve was passed to ReadOnly without the explicit dangerous
// opt-out. Preserved links may escape the mount and therefore are not a sandbox.
var ErrSymlinkPreserveUnsafe = errors.New("s3disk mount: SymlinkPreserve is unsafe without explicit opt-out")

// ErrAuthorizationExpired reports that the earliest locally known deadline
// for authorization needed by future lazy reads has already passed. ReadOnly
// checks this after its initial refresh but before starting FUSE. The sentinel
// is also used as the cause of a running mount's authorization deadline.
//
// This is a local lifecycle signal, not a revocation primitive: an unmount
// cannot retract bytes that an application has already read or cached.
var ErrAuthorizationExpired = errors.New("s3disk mount: read authorization expired")

// ErrInodeIdentityLimit reports that a mount has exceeded either the count or
// conservative retained-byte bound for distinct (snapshot, path, type)
// identities. The mount fails the new lookup instead of allocating an
// unbounded identity map or reusing an inode number while an older snapshot
// inode may still be live.
var ErrInodeIdentityLimit = errors.New("s3disk mount: inode identity limit reached")
