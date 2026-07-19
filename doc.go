// Package s3disk implements a read-only, lazy, snapshot-based filesystem view
// backed by an S3-compatible object store.
//
// Publishers build immutable content-addressed objects and expose a snapshot by
// atomically updating one small reference object. Consumers fetch metadata when
// traversing the tree and fetch file chunks only when a file is read.
//
// Writable deployments should use InitializeRepository to bind a confirmed-new
// prefix to its repository identity, storage profile, and chunking parameters.
// Publisher rejects repositories without that durable descriptor unless the
// caller selects its explicitly dangerous legacy override. The lower-level
// NewRepository constructors deliberately perform no object store I/O.
package s3disk
