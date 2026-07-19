package mount

import (
	"fmt"
	"time"
)

// normalizeOptions is shared by native and unsupported platforms so invalid
// public options have the same pre-I/O behavior everywhere.
func normalizeOptions(options Options) (Options, error) {
	if options.KernelCache {
		return Options{}, ErrKernelCacheUnsupported
	}
	if err := options.Poll.Validate(); err != nil {
		return Options{}, fmt.Errorf("s3disk mount: invalid poll options: %w", err)
	}
	for _, ttl := range []struct {
		name  string
		value time.Duration
	}{
		{name: "attribute TTL", value: options.AttrTTL},
		{name: "entry TTL", value: options.EntryTTL},
		{name: "negative-entry TTL", value: options.NegativeTTL},
	} {
		if ttl.value < 0 {
			return Options{}, fmt.Errorf("s3disk mount: %s must not be negative", ttl.name)
		}
	}
	if options.NegativeTTL != 0 {
		return Options{}, ErrNegativeCacheUnsupported
	}
	if options.AttrTTL == 0 {
		options.AttrTTL = time.Second
	}
	if options.EntryTTL == 0 {
		options.EntryTTL = time.Second
	}
	if options.FilesystemName == "" {
		options.FilesystemName = "s3disk"
	}
	if options.MaxInodeIdentities < 0 {
		return Options{}, fmt.Errorf("s3disk mount: maximum inode identities must not be negative")
	}
	if options.MaxInodeIdentities == 0 {
		options.MaxInodeIdentities = DefaultMaxInodeIdentities
	}
	if options.MaxInodeIdentities > MaxInodeIdentitiesLimit {
		return Options{}, fmt.Errorf("s3disk mount: maximum inode identities exceeds %d", MaxInodeIdentitiesLimit)
	}
	if options.MaxInodeIdentityBytes < 0 {
		return Options{}, fmt.Errorf("s3disk mount: maximum inode identity bytes must not be negative")
	}
	if options.MaxInodeIdentityBytes == 0 {
		options.MaxInodeIdentityBytes = DefaultMaxInodeIdentityBytes
	}
	if options.MaxInodeIdentityBytes > MaxInodeIdentityBytesLimit {
		return Options{}, fmt.Errorf("s3disk mount: maximum inode identity bytes exceeds %d", MaxInodeIdentityBytesLimit)
	}
	if options.AutoUnmountTimeout < 0 {
		return Options{}, fmt.Errorf("s3disk mount: automatic unmount timeout must not be negative")
	}
	if options.AutoUnmountTimeout == 0 {
		options.AutoUnmountTimeout = DefaultAutoUnmountTimeout
	}
	return options, nil
}
