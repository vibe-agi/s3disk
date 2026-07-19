// Package s3disk implements a read-only, lazy, snapshot-based filesystem view
// backed by an S3-compatible object store.
//
// Publishers build immutable content-addressed objects and expose a snapshot by
// atomically updating one small reference object. Consumers fetch metadata when
// traversing the tree and fetch file chunks only when a file is read.
package s3disk
