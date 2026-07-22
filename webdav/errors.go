package webdav

import "errors"

var (
	// ErrDurableWatermarkRequired reports a Consumer that cannot preserve its
	// anti-rollback watermark across gateway restarts.
	ErrDurableWatermarkRequired = errors.New("s3disk webdav: durable consumer watermark is required")
	// ErrSymlinkUnsupported reports that WebDAV cannot faithfully expose POSIX
	// symbolic-link semantics. Symlink entries are omitted from directory views.
	ErrSymlinkUnsupported = errors.New("s3disk webdav: symbolic links are unsupported")
	// ErrAuthorizationExpired reports that the immutable handoff authorization
	// deadline has passed.
	ErrAuthorizationExpired = errors.New("s3disk webdav: read authorization expired")
)
