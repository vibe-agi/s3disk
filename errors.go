package s3disk

import "errors"

// classifiedObjectNotFoundError marks a provider cause which an adapter has
// conclusively classified as a missing object. The marker is private so cleanup
// can distinguish this explicit adapter boundary from an arbitrary error which
// merely claims to match ErrObjectNotFound.
type classifiedObjectNotFoundError struct {
	cause error
}

func (err *classifiedObjectNotFoundError) Error() string {
	if err == nil || err.cause == nil {
		return ErrObjectNotFound.Error()
	}
	return ErrObjectNotFound.Error() + ": " + err.cause.Error()
}

func (err *classifiedObjectNotFoundError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

func (*classifiedObjectNotFoundError) Is(target error) bool {
	return target == ErrObjectNotFound
}

func (*classifiedObjectNotFoundError) definitiveObjectNotFound() {}

// ClassifyObjectNotFound records that an adapter has conclusively classified
// cause as a missing-object response. Call it only after checking a definitive
// provider response such as a GET/HEAD 404 or NoSuchKey. The returned error
// matches both ErrObjectNotFound and cause through errors.Is/errors.As.
func ClassifyObjectNotFound(cause error) error {
	if cause == nil {
		return ErrObjectNotFound
	}
	return &classifiedObjectNotFoundError{cause: cause}
}

var (
	// Store implementations use these errors to report portable object-store
	// outcomes. Callers should use errors.Is.
	ErrObjectNotFound  = errors.New("s3disk: object not found")
	ErrNotModified     = errors.New("s3disk: object not modified")
	ErrPrecondition    = errors.New("s3disk: precondition failed")
	ErrPublishConflict = errors.New("s3disk: concurrent publish conflict")
	// ErrPublishIndeterminate means the store may have applied a reference
	// compare-and-swap, but the publisher could not yet prove whether it won.
	// Signed publishers retain the exact operation in PublicationJournal and
	// recover it automatically before the next Stage; callers may also invoke
	// RecoverPublication explicitly. For unsigned publishers, retry Commit with
	// the same StagedSnapshot.
	ErrPublishIndeterminate      = errors.New("s3disk: publish outcome indeterminate")
	ErrNoSnapshot                = errors.New("s3disk: no published snapshot")
	ErrPathNotFound              = errors.New("s3disk: path not found")
	ErrInvalidPath               = errors.New("s3disk: invalid path")
	ErrNotDirectory              = errors.New("s3disk: not a directory")
	ErrIsDirectory               = errors.New("s3disk: is a directory")
	ErrUnsupportedType           = errors.New("s3disk: unsupported filesystem entry type")
	ErrCorruptObject             = errors.New("s3disk: corrupt object")
	ErrSplitBrain                = errors.New("s3disk: generation refers to different commits")
	ErrUnstableFile              = errors.New("s3disk: file changed repeatedly while being read")
	ErrInvalidChunking           = errors.New("s3disk: invalid chunking options")
	ErrInvalidReference          = errors.New("s3disk: invalid snapshot reference")
	ErrInvalidSnapshotClosure    = errors.New("s3disk: invalid or modified snapshot closure")
	ErrResourceLimit             = errors.New("s3disk: protocol resource limit exceeded")
	ErrGenerationExhausted       = errors.New("s3disk: snapshot generation exhausted")
	ErrRollbackDetected          = errors.New("s3disk: snapshot rollback detected")
	ErrStoreIncompatible         = errors.New("s3disk: object store is incompatible")
	ErrBucketNotFound            = errors.New("s3disk: bucket not found")
	ErrStoreMisconfigured        = errors.New("s3disk: object store configuration is invalid")
	ErrStoreOperationUnsupported = errors.New("s3disk: object store operation is unsupported")
	ErrAccessDenied              = errors.New("s3disk: object store access denied")
	ErrRateLimited               = errors.New("s3disk: object store rate limited")
	ErrStoreUnavailable          = errors.New("s3disk: object store temporarily unavailable")
	// ErrRepositoryReadOnly reports that an operation requiring Head or write
	// authority was attempted through a repository deliberately constructed
	// with only ObjectReader capability.
	ErrRepositoryReadOnly = errors.New("s3disk: repository is read-only")
	ErrUnsafeSymlink      = errors.New("s3disk: symlink escapes the snapshot root")
	ErrUntrustedReference = errors.New("s3disk: snapshot reference is not trusted")
	ErrTrustStateRequired = errors.New("s3disk: trusted checkpoint state is required")
	// ErrTrustStateUnsupported reports that the current build cannot enforce
	// the local filesystem protections required by FileWatermarkStore,
	// FilePublicationJournal, and DiskCache. Callers must not silently fall back
	// to an unprotected path for anti-rollback or publication state.
	ErrTrustStateUnsupported = errors.New("s3disk: secure local trust state is unsupported")
)
