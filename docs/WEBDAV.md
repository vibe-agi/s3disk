# Read-only WebDAV access

`s3disk serve webdav` exposes one handoff through an HTTP/WebDAV endpoint on
the reader computer. It reuses the same encrypted S3 reader, durable
anti-rollback watermark, lazy cache, signed-reference verification, snapshot-
pinned file handles, refresh interval, and fixed authorization expiry as the
FUSE adapter. WebDAV is only the local presentation layer.

## Start a reader

```sh
s3disk serve webdav \
  --handoff /secure/workspace-a.handoff \
  --state-dir /var/lib/s3disk/reader \
  --max-stale 5m
```

By default the OS selects a free loopback port and the command prints the
actual URL, for example `http://127.0.0.1:53142/`. Use `--listen
127.0.0.1:9867` when a stable local port is more useful. A custom cache base
can be supplied with `--cache-dir`.

`--max-stale` is optional. When nonzero, repeated S3 refresh failures stop the
server after the configured interval instead of serving an indefinitely stale
snapshot. It must be at least both `--poll-interval` and `--poll-timeout`; zero
preserves the last verified snapshot until authorization expiry. Startup and
refresh messages include the current generation, last successful refresh, and
consecutive failure count.

On macOS, choose **Finder → Go → Connect to Server** and enter the printed
URL. The release test also invokes the built-in `/sbin/mount_webdav` client,
reads a lazy file through the resulting volume, verifies that writes fail, and
unmounts it. The native gate also publishes another generation and proves that
an already-read file plus a new Unicode path appear without remounting.

Apple's current WebDAVFS caches a completely downloaded file for a 60-second
validation window. During that window Finder can show old contents even though
a direct HTTP GET and the server generation are already current; response cache
headers cannot proactively invalidate the OS cache. The server safely handles
WebDAVFS's date-only revalidation even when two revisions have the same
whole-second source modification time by using a stable generation-specific
HTTP validator time; repeated checks of the current generation still receive
304. `PROPFIND` continues to expose the real source mtime. The native gate
allows 75 seconds for the mounted view to advance. Applications that require
sub-minute update visibility should use FUSE or direct HTTP rather than
Finder/WebDAVFS.

On Linux, use the same URL with a WebDAV-capable file manager or client. A
plain protocol check does not require a mount:

```sh
curl --fail http://127.0.0.1:53142/path/to/file
```

## Security boundary

- The CLI accepts only literal loopback IP addresses (`127.0.0.0/8` or `::1`).
  It has no option to expose the endpoint to a LAN or the internet.
- Every request must also carry a `Host` authority naming a loopback IP or
  `localhost`; other authorities receive `421 Misdirected Request` before any
  decrypted metadata or bytes are read. This closes the browser DNS-rebinding
  path. CORS behavior is not treated as an access-control boundary.
- The loopback endpoint has no WebDAV password or TLS. Its security boundary is
  the reader **computer**, not an individual OS account: another local process
  or user on a multi-user host can connect to it. Every mutation method is
  rejected. Use FUSE or add an authenticated local reverse proxy when per-user
  isolation is required.
- The endpoint accepts only `OPTIONS`, `PROPFIND` with Depth 0 or 1, `GET`, and
  `HEAD`. `PUT`, `DELETE`, `MKCOL`, `COPY`, `MOVE`, `LOCK`, `UNLOCK`,
  `PROPPATCH`, and all other methods return `405 Method Not Allowed`.
- A complete `PROPFIND` is serialized against snapshot refresh. `GET` and
  `HEAD` pin the opened file and release the refresh gate before streaming, so
  a slow reader cannot delay later generations. Range requests are supported;
  ambiguous date-based resume requests fall back to a complete response.
- Request headers and bodies have finite read deadlines. The listener accepts
  at most 64 simultaneous connections, and every socket write has a renewable
  idle deadline so a client that stops reading cannot pin a response forever.
  The write deadline is renewed for each write rather than limiting the total
  duration of a legitimate large lazy download.
- Authorization expiry stops the HTTP server. This cannot revoke bytes already
  read or cached; S3 must independently enforce expiration.
- WebDAV omits symbolic links. The protocol has no portable POSIX symlink
  representation, and silently following a link would weaken the tree boundary.

This first version is deliberately a local adapter. A remote WebDAV product
would need a separately designed TLS identity, authentication, authorization,
rate limiting, request accounting, tenant isolation, and denial-of-service
boundary; changing `--listen` is not sufficient.

## FUSE remains available

FUSE usually offers better filesystem semantics and performance. Linux users
with `/dev/fuse`, and macOS users who independently install and enable macFUSE
VFS, can continue to use `s3disk mount`. WebDAV is the zero-driver portable
default, not a removal of the native adapter.
