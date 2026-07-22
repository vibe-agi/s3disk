package localstate

import "errors"

// ErrUnsafe marks local state whose path identity, ownership, permissions, or
// ACLs cannot be trusted. The public package translates it to ErrCorruptObject.
var ErrUnsafe = errors.New("s3disk: unsafe local state")

// ErrUnsupported marks a platform where the required local-state guarantees
// cannot be proven. The public package translates it to
// ErrTrustStateUnsupported.
var ErrUnsupported = errors.New("s3disk: secure local state is unsupported")
