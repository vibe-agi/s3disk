# s3disk

[English](README.md) | [中文](README.zh-CN.md)

Share one or more local workspaces through S3 and access them read-only on other
computers. Readers receive a short-lived handoff file, need no reusable S3
credentials, and download file contents lazily when they are opened.

```text
publisher computer ── encrypted snapshots ──> S3-compatible storage
                                                  │
reader computer <── private handoff ── local WebDAV or FUSE view
```

`s3disk` is a pre-1.0 engineering preview. Linux has a passing real FUSE mount
baseline. macOS has a passing mount through its built-in WebDAV client, without
macFUSE or a kernel extension. Review [Platform support](#platform-support)
before embedding it in a product.

## What it provides

- Expiring, encrypted shares backed by an S3-compatible object store.
- Immutable chunks and manifests with an atomically updated signed reference.
- Lazy reads and snapshot-pinned open files.
- Portable loopback-only WebDAV for macOS, Linux, and other WebDAV clients.
- Optional FUSE mounts, plus `mount-set` for supervising several mountpoints.
- Read-only adapters: readers cannot modify the publisher's workspace.

## Install

On macOS or Linux with [Homebrew](https://brew.sh/):

```sh
brew install vibe-agi/tap/s3disk
```

Alternatively, download a Linux or macOS archive from
[GitHub Releases](https://github.com/vibe-agi/s3disk/releases), or build from
a reviewed checkout with a supported Go toolchain:

```sh
go build -trimpath -o ./s3disk ./cmd/s3disk
./s3disk --help
```

## Configure S3 credentials

Obtain an access key and secret key from your S3 provider's console or
administrator. `s3disk` loads publisher credentials through the AWS SDK default
credential chain; it does not create credentials or accept them as command-line
flags.

For an AWS account, prefer an SSO profile or an EC2/ECS/EKS workload role:

```sh
aws configure sso --profile s3disk
aws sso login --profile s3disk
export AWS_PROFILE=s3disk
```

For static keys issued by AWS or another S3-compatible provider:

```sh
aws configure --profile s3disk
export AWS_PROFILE=s3disk
```

`aws configure` writes the profile to the standard AWS configuration files
under `~/.aws`; `s3disk` does not copy reusable credentials into its own state.
Temporary credentials can instead be supplied with `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`. Environment credentials take
precedence over a profile. There is intentionally no `--profile` flag: use the
`AWS_PROFILE` environment variable.

Readers using a handoff file do not need any S3 credentials.

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
authenticated channel. The portable default is a local read-only WebDAV server:

```sh
s3disk serve webdav \
  --handoff /secure/workspace-a.handoff \
  --state-dir /var/lib/s3disk/reader
```

It prints a URL such as `http://127.0.0.1:53142/`. On macOS, open Finder,
choose **Go → Connect to Server**, and enter that URL. Each reader runs this
loopback service locally; it is deliberately not a remote/public WebDAV server.
See [WebDAV access](docs/WEBDAV.md).

For an optional native FUSE mount on Linux—or on macOS after the user installs
macFUSE—run:

```sh
s3disk mount \
  --handoff /secure/workspace-a.handoff \
  --mountpoint /mnt/workspace-a \
  --state-dir /var/lib/s3disk/reader
```

The macOS FUSE path deliberately does not request macFUSE's opt-in
`backend=fskit` mount option, so macFUSE uses its default VFS/kernel backend.
The newer FSKit message transport is not supported by the current go-fuse
adapter.

For multiple workspaces, publish each source independently. Run one WebDAV
process/loopback port per handoff, or use the bounded
[`mount-set`](docs/MOUNT_SET.md) supervisor for FUSE. These views are not union
mounts; each workspace keeps its own trust and expiry boundary.

## Platform support

| Platform | Current status |
| --- | --- |
| Linux | WebDAV server plus primary native FUSE target. Native tests and real MinIO/FUSE mount tests pass. |
| macOS | Built-in WebDAV mount passes without third-party software. macFUSE VFS remains an optional path whose release evidence is pending. |
| Windows | WebDAV server and core packages compile and run native tests, but Explorer integration is not yet certified. FUSE-style `mount` is not implemented; publisher recovery state also fails closed pending Windows ACL work. |
| FreeBSD | FUSE adapter compiles, but has no dedicated native production test baseline. |

Windows support needs a WinFsp-style filesystem adapter, Windows path/reparse
point and ACL hardening, packaging/driver lifecycle work, and real mount tests.
A GitHub-hosted Windows runner already executes the portable test suite, so the
main gap is implementation—not merely access to a Windows machine.

See the full [compatibility matrix](docs/COMPATIBILITY.md).

## Current boundaries

- A publication scan is not an atomic snapshot of a changing workspace. Use an
  APFS/LVM/filesystem snapshot or pause writes when strict point-in-time
  consistency is required; see the [snapshot and recovery runbook](docs/RECOVERY.md).
- Immutable S3 objects do not yet have garbage collection.
- Published scale evidence is a regression baseline, not a capacity claim for
  large, high-churn, long-running mounts.
- WebDAV intentionally omits symbolic links because the protocol has no
  portable POSIX symlink representation, and the CLI is loopback-only.
- macOS's built-in WebDAVFS may retain an already-read file for about 60
  seconds before revalidating it; server refresh is immediate, Finder refresh
  is not. The native release gate verifies eventual refresh without remounting.
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
- `webdav`: portable read-only WebDAV adapter.
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
