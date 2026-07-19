package s3disk

import (
	"context"
	"fmt"
)

// MaxStoreVersionTokenBytes bounds each opaque version field accepted from a
// Store. S3 ETags and version IDs are normally far smaller; the finite bound
// prevents an incompatible endpoint from feeding unbounded tokens into request
// headers or durable publication journals.
const MaxStoreVersionTokenBytes = 4 << 10

// Version describes one observation of an object. ETag is the opaque token
// used by CompareAndSwap; successful ObjectReader reads and Store writes must
// return a non-empty ETag no larger than MaxStoreVersionTokenBytes. VersionID
// is optional backend metadata retained for logging and diagnostics, is subject
// to the same size bound, and is not an additional compare-and-swap condition.
type Version struct {
	ETag      string
	VersionID string
}

func validateStoreVersion(operation string, version Version) error {
	if version.ETag == "" {
		return fmt.Errorf("%w: %s returned an empty ETag", ErrStoreIncompatible, operation)
	}
	if len(version.ETag) > MaxStoreVersionTokenBytes || len(version.VersionID) > MaxStoreVersionTokenBytes {
		return fmt.Errorf("%w: %s returned an oversized version token", ErrStoreIncompatible, operation)
	}
	return nil
}

// GetOptions controls a conditional object read.
type GetOptions struct {
	IfNoneMatch string
	// MaxBytes asks the adapter to reject an object before buffering more than
	// this many bytes. Zero means the adapter's own finite limit.
	MaxBytes int64
}

// Object is a fully-read object and the version observed while reading it.
type Object struct {
	Data    []byte
	Version Version
}

// ObjectReader is the least-privilege object-store contract needed by a
// Consumer. Implementations may obtain individual objects through short-lived,
// exact-key S3 capabilities; a read-only client does not need S3 credentials
// or list, head, or write authority. Get must return a fully buffered object,
// must not alias implementation-owned storage, must enforce a positive
// GetOptions.MaxBytes before returning the object body, and must observe ctx
// throughout request and response-body processing. Each result must be one
// atomic object observation with a valid Version. Missing keys return
// ErrObjectNotFound; when IfNoneMatch equals the current ETag, Get returns
// ErrNotModified without an object body.
type ObjectReader interface {
	Get(ctx context.Context, key string, options GetOptions) (Object, error)
}

// Store is the writable object-store contract used for publication and full
// compatibility commissioning. It extends ObjectReader because publication
// must also read existing references and immutable objects. All Get, Head, and
// write operations for one key must be linearizable: after a write completes,
// a later read must not return an older version. Get and writes of one key must
// also be atomic. PutIfAbsent must create only when the key
// is absent. CompareAndSwap must replace only when the current ETag equals the
// non-empty expected ETag (or create only when expected is nil); VersionID is
// diagnostic metadata and must not strengthen that condition. A failed
// condition returns ErrPrecondition and must not modify data. Returned and
// input byte slices must not alias storage owned by the caller or
// implementation. Get must enforce a positive GetOptions.MaxBytes before
// returning the object body. Every operation must observe ctx throughout
// request and response-body processing and return promptly after ctx.Done
// closes. A custom adapter that ignores cancellation can otherwise halt
// polling, lazy reads, and shutdown; callers cannot safely repair such an
// adapter by wrapping it in an abandoned goroutine.
//
// An S3 adapter is provided by package s3store. Custom writable adapters should
// obtain a passed Repository.ProbeStoreCompatibility report before production
// use. A read-only ObjectReader cannot run that destructive commissioning
// probe; its provider must commission the writable deployment independently.
type Store interface {
	ObjectReader
	Head(ctx context.Context, key string) (Version, error)
	PutIfAbsent(ctx context.Context, key string, data []byte) (Version, error)
	CompareAndSwap(ctx context.Context, key string, expected *Version, data []byte) (Version, error)
}

// ObjectDeleter is an optional extension used to clean compatibility probes.
// Probe cleanup verifies each Delete with Store.Head; a nil Delete alone is not
// evidence that the current object disappeared. The core publication protocol
// never requires delete permission.
type ObjectDeleter interface {
	Delete(ctx context.Context, key string) error
}
