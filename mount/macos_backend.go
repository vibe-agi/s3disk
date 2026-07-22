package mount

// MacOSBackend selects the macFUSE backend used on macOS. The zero value lets
// macFUSE choose its default backend. Explicit selections are rejected on
// non-macOS hosts.
type MacOSBackend string

const (
	MacOSBackendAuto  MacOSBackend = ""
	MacOSBackendVFS   MacOSBackend = "vfs"
	MacOSBackendFSKit MacOSBackend = "fskit"
)
