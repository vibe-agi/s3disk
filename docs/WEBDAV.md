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
  --state-dir /var/lib/s3disk/reader
```

By default the OS selects a free loopback port and the command prints the
actual URL, for example `http://127.0.0.1:53142/`. Use `--listen
127.0.0.1:9867` when a stable local port is more useful. A custom cache base
can be supplied with `--cache-dir`.

On macOS, choose **Finder → Go → Connect to Server** and enter the printed
URL. The release test also invokes the built-in `/sbin/mount_webdav` client,
reads a lazy file through the resulting volume, verifies that writes fail, and
unmounts it.

On Linux, use the same URL with a WebDAV-capable file manager or client. A
plain protocol check does not require a mount:

```sh
curl --fail http://127.0.0.1:53142/path/to/file
```

## Security boundary

- The CLI accepts only literal loopback IP addresses (`127.0.0.0/8` or `::1`).
  It has no option to expose the endpoint to a LAN or the internet.
- The loopback endpoint has no WebDAV password or TLS. Its security boundary is
  the reader **computer**, not an individual OS account: another local process
  or user on a multi-user host can connect to it. Browser CORS is not enabled
  and every mutation method is rejected. Use FUSE or add an authenticated local
  reverse proxy when per-user isolation is required.
- The endpoint accepts only `OPTIONS`, `PROPFIND` with Depth 0 or 1, `GET`, and
  `HEAD`. `PUT`, `DELETE`, `MKCOL`, `COPY`, `MOVE`, `LOCK`, `UNLOCK`,
  `PROPPATCH`, and all other methods return `405 Method Not Allowed`.
- A complete request is serialized against snapshot refresh, while an opened
  file remains pinned to its original generation. Range requests are supported.
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
