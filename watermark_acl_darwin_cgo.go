//go:build darwin && cgo

package s3disk

/*
#include <errno.h>
#include <sys/acl.h>

// Return 1 when the descriptor has an extended ACL, 0 when it has none, or a
// negative errno on inspection failure. Darwin represents the absence of an
// extended ACL as ENOENT; a returned acl_t is therefore itself sufficient to
// prove that extended ACL metadata is attached.
static int s3disk_darwin_has_extended_acl(int fd) {
	acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
	if (acl == NULL) {
		int saved = errno;
		// Darwin reports ENOENT when no extended ACL is attached on some
		// filesystems/OS releases.
		if (saved == ENOENT) {
			return 0;
		}
		return -(saved == 0 ? EIO : saved);
	}
	acl_free(acl);
	return 1;
}
*/
import "C"

import (
	"fmt"
	"os"
	"syscall"
)

func validateUnixWatermarkACL(file *os.File) error {
	if file == nil {
		return fmt.Errorf("%w: missing Darwin trust-state handle", ErrTrustStateUnsupported)
	}
	result := int(C.s3disk_darwin_has_extended_acl(C.int(file.Fd())))
	switch {
	case result == 0:
		return nil
	case result > 0:
		return fmt.Errorf("%w: Darwin trust-state path has an extended ACL", ErrCorruptObject)
	default:
		return fmt.Errorf("s3disk: inspect Darwin trust-state ACL: %w", syscall.Errno(-result))
	}
}
