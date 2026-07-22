# s3disk

[English](README.md) | [中文](README.zh-CN.md)

Share one or more local workspaces through S3 and mount them read-only on other
computers. Readers receive a short-lived handoff file, need no reusable S3
credentials, and download file contents lazily when they are opened.

```text
publisher computer ── encrypted snapshots ──> S3-compatible storage
                                                  │
reader computer <── private handoff ── read-only lazy mount
```

`s3disk` is a pre-1.0 engineering preview. Linux and macOS have real filesystem
mount gates; review [Platform support](#platform-support) before embedding it
in a product.

## What it provides

- Expiring, encrypted shares backed by an S3-compatible object store.
- Immutable chunks and manifests with an atomically updated signed reference.
- Lazy reads and snapshot-pinned open files.
- One independent share per workspace, plus `mount-set` for supervising several
  reader mountpoints in one process.
- A read-only filesystem: readers cannot modify the publisher's workspace.

## Install

Download a Linux or macOS archive from
[GitHub Releases](https://github.com/vibe-agi/s3disk/releases), or build from a
reviewed checkout with a supported Go toolchain:

```sh
go build -trimpath -o ./s3disk ./cmd/s3disk
./s3disk --help
```

The publisher obtains S3 credentials from the AWS SDK default credential
chain. Credentials are never accepted as command-line flags.

## Quick start

The following example uses an S3-compatible HTTPS endpoint and an explicitly
trusted CA bundle. Use private, non-symlink directories for keys, handoffs, and
state.

On the publisher computer, first validate the selected bucket and endpoint:

```sh
s3disk s3 doctor \
  --bucket example-bucket \
  --prefix private/s3disk-check \
  --endpoint https://s3.example.com \
  --path-style \
  --tls-ca /secure/provider-ca.pem
```

Create a recovery key, then publish the workspace:

```sh
s3disk share recovery-key generate \
  --out /secure/workspace-recovery.json

s3disk share publish \
  --source /srv/workspace \
  --all \
  --bucket example-bucket \
  --prefix private/workspace-a \
  --state-dir /var/lib/s3disk/publisher \
  --recovery-key /secure/workspace-recovery.json \
  --handoff-out /secure/workspace-a.handoff \
  --expires-in 2h \
  --endpoint https://s3.example.com \
  --path-style \
  --tls-ca /secure/provider-ca.pem
```

`share publish` watches for source changes by default. Add `--once` to publish
one snapshot and exit. If the publisher stops before expiry, use `share resume`
with its printed share ID instead of creating a new share.

Transfer `/secure/workspace-a.handoff` to the reader once through a private,
authenticated channel. On a Linux or macOS reader, mount it into an existing
empty directory:

```sh
s3disk mount \
  --handoff /secure/workspace-a.handoff \
  --mountpoint /mnt/workspace-a \
  --state-dir /var/lib/s3disk/reader
```

macOS requires macFUSE to be installed separately. On macOS 15.4 or later,
`--macos-backend fskit` avoids the kernel-extension backend but requires the
mountpoint to be below `/Volumes`. The default `auto` uses macFUSE's default
backend.

For multiple workspaces, publish each source independently and use either one
`s3disk mount` process per handoff or the bounded
[`mount-set`](docs/MOUNT_SET.md) supervisor. It does not create a union mount;
each workspace keeps its own mountpoint and trust boundary.

## Platform support

| Platform | Current status |
| --- | --- |
| Linux | Primary target. Native tests plus real MinIO/FUSE mount tests. |
| macOS | Supported mount target. CI runs real macOS 26 macFUSE/FSKit read-only, refresh, pinned-handle, multi-mount, and clean-unmount tests. Users install macFUSE separately; each shipped macOS/architecture still needs product qualification. |
| Windows | Core packages and native tests work, but filesystem mounting is not implemented. `mount` returns `ErrUnsupportedPlatform`; publisher recovery-state confidentiality also fails closed until Windows ACL handling is complete. |
| FreeBSD | FUSE adapter compiles, but has no dedicated native production test baseline. |

Windows support needs a WinFsp-style filesystem adapter, Windows path/reparse
point and ACL hardening, packaging/driver lifecycle work, and real mount tests.
A GitHub-hosted Windows runner already executes the portable test suite, so the
main gap is implementation—not merely access to a Windows machine.

See the full [compatibility matrix](docs/COMPATIBILITY.md).

## Current boundaries

- A publication scan is not an atomic snapshot of a changing workspace. Use an
  APFS/LVM/filesystem snapshot or pause writes when strict point-in-time
  consistency is required.
- Immutable S3 objects do not yet have garbage collection.
- Published scale evidence is a regression baseline, not a capacity claim for
  large, high-churn, long-running mounts.
- The mount inode-identity table is bounded; reaching the configured limit
  requires a remount or a different sharding strategy.
- `mount-set` supervises independent mounts; it is not a union filesystem or a
  publisher-side supervisor.

The detailed security, recovery, consistency, and object-store contracts live
in the [technical reference](docs/REFERENCE.md).

## Project layout

- `cmd/s3disk`: command-line application.
- Repository root: stable, storage-independent public Go API and its package-private tests.
- `internal`: domain-focused implementation packages for CLI workflows, secure
  local state, platform filesystem operations, and concurrency control.
- `s3store`: AWS SDK v2 S3 adapter.
- `presignedshare`: expiring credential-free read capabilities.
- `publisherstate`: protected publisher recovery envelopes.
- `mount`: read-only filesystem adapter.
- `tests/blackbox`: public-API and end-to-end behavior tests.
- `docs`: operational and protocol documentation.

See the [repository architecture](docs/ARCHITECTURE.md) for dependency direction
and file-placement rules.

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full checks and DCO sign-off.

## License and support

Licensed under [Apache License 2.0](LICENSE). Commercial use, modification, and
redistribution are permitted subject to the license. Releases are provided
without an SLA, warranty, or obligation to operate or support downstream
deployments; embedding products own their validation and operations. See
[`SUPPORT.md`](SUPPORT.md) and [`SECURITY.md`](SECURITY.md).
