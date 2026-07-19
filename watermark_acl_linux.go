//go:build linux

package s3disk

import "os"

// Linux POSIX access ACLs use the group class bits as their effective mask.
// The common mode check therefore rejects every ACL that can grant group or
// named-user write access. Filesystems exposing authorization outside POSIX
// mode/ACL semantics require separate certification and must not host trust
// state.
func validateUnixWatermarkACL(*os.File) error { return nil }
