package cli

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/presignedshare"
)

// consumerRuntime owns the common credential-free reader, rollback state, and
// lazy cache used by FUSE and WebDAV presentation adapters.
type consumerRuntime struct {
	consumer *s3disk.Consumer
	cache    *s3disk.DiskCache
}

func (runtime *consumerRuntime) Close() error {
	if runtime == nil || runtime.cache == nil {
		return nil
	}
	return runtime.cache.Close()
}

func prepareConsumerRuntime(
	ctx context.Context,
	share decodedHandoff,
	stateDir string,
	cacheBase string,
) (*consumerRuntime, error) {
	if ctx == nil {
		return nil, fmt.Errorf("s3disk consumer: context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if share.wire.DangerouslyUseSystemTrust {
		return nil, fmt.Errorf("s3disk consumer: system TLS trust is incompatible with the S3-only CLI profile")
	}
	verifier, err := s3disk.NewEd25519ReferenceVerifier(share.repository, map[string]ed25519.PublicKey{
		share.wire.ReferenceKeyID: share.publicKey,
	})
	if err != nil {
		return nil, fmt.Errorf("s3disk consumer: create offline verifier: %w", err)
	}
	reader, err := presignedshare.NewReader(presignedshare.ReaderConfig{
		RootCapability: share.root, RepositoryPrefix: share.wire.RepositoryPrefix,
		ReferenceKey: share.wire.ReferenceKey, ShareID: share.shareID, Verifier: verifier,
		ClientEncryption: share.profile, TLSRootCAPEM: share.tlsCAPEM,
		AllowInsecureLoopback: share.wire.AllowInsecureLoopback,
	})
	if err != nil {
		return nil, fmt.Errorf("s3disk consumer: create credential-free reader: %w", err)
	}
	repository, err := s3disk.NewReadOnlyRepositoryWithOptions(reader, share.wire.RepositoryPrefix,
		s3disk.RepositoryOptions{ClientEncryption: share.profile})
	if err != nil {
		return nil, fmt.Errorf("s3disk consumer: create read-only repository: %w", err)
	}
	baseStateDir, err := preparePrivateDirectory(stateDir)
	if err != nil {
		return nil, fmt.Errorf("s3disk consumer: state directory: %w", err)
	}
	shareStateDir, err := preparePrivateSubdirectories(baseStateDir, share.wire.RepositoryID, share.wire.ShareID)
	if err != nil {
		return nil, fmt.Errorf("s3disk consumer: isolated state directory: %w", err)
	}
	watermarks, err := s3disk.NewFileWatermarkStore(filepath.Join(shareStateDir, "watermark.json"))
	if err != nil {
		return nil, err
	}
	cachePath, err := prepareConsumerCachePath(cacheBase, shareStateDir, share.wire.RepositoryID, share.wire.ShareID)
	if err != nil {
		return nil, fmt.Errorf("s3disk consumer: isolated cache directory: %w", err)
	}
	cache, err := s3disk.NewDiskCache(cachePath)
	if err != nil {
		return nil, fmt.Errorf("s3disk consumer: create cache: %w", err)
	}
	consumer, err := s3disk.NewConsumer(repository, share.wire.Channel, s3disk.ConsumerOptions{
		Cache: cache, Watermarks: watermarks, RequirePersistentWatermark: true,
		ReferenceVerifier: verifier, TrustedCheckpoint: &share.checkpoint,
		Symlinks: s3disk.SymlinkRejectExternal,
	})
	if err != nil {
		_ = cache.Close()
		return nil, fmt.Errorf("s3disk consumer: create consumer: %w", err)
	}
	return &consumerRuntime{consumer: consumer, cache: cache}, nil
}

func prepareConsumerCachePath(cacheBase, shareStateDir, repositoryID, shareID string) (string, error) {
	if cacheBase == "" {
		return filepath.Join(shareStateDir, "cache"), nil
	}
	base, err := preparePrivateDirectory(cacheBase)
	if err != nil {
		return "", err
	}
	return preparePrivateSubdirectories(base, repositoryID, shareID, "cache")
}

func preparePrivateSubdirectories(base string, names ...string) (string, error) {
	current := base
	for _, name := range names {
		if name == "" || filepath.Base(name) != name {
			return "", fmt.Errorf("invalid state namespace")
		}
		current = filepath.Join(current, name)
		if err := os.Mkdir(current, 0o700); err != nil && !os.IsExist(err) {
			return "", err
		}
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("state namespace is not a private directory")
		}
	}
	return current, nil
}
