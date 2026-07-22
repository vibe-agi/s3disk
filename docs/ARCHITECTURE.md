# Repository architecture

This document defines where code belongs. It is intentionally about package
boundaries rather than a generic directory template.

## Design goals

1. Keep `github.com/vibe-agi/s3disk` a stable, storage-independent public API.
2. Keep implementation packages private unless downstream Go users have a
   concrete reason to import and support them.
3. Put platform-specific code beside the subsystem that owns the behavior.
4. Keep tests beside the package whose invariants they exercise, while public
   behavior and end-to-end tests live in `tests/blackbox`.
5. Prefer small domain packages over catch-all `util`, `common`, or `pkg`
   directories.

This follows [Go's official module-layout guidance](https://go.dev/doc/modules/layout),
which recommends that a larger public package place supporting implementations
under `internal`. Mature storage projects use the same principle, but their
directory names are driven by their domains rather than copied as a template;
for example, [restic](https://github.com/restic/restic/tree/master/internal)
separates repository, backend, filesystem, and archiver internals, while
[rclone](https://github.com/rclone/rclone) gives its VFS and storage backends
explicit packages.

## Dependency direction

```text
cmd/s3disk
    │
    ▼
internal/cli ───────────────┐
                            │
mount  presignedshare       │
  │          │              │
  └──────────┴──────► s3disk (public root package)
                            │
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
     internal/localstate internal/fsutil internal/syncutil

s3store and memstore implement root-package storage interfaces.
publisherstate provides an independently importable recovery envelope.
```

The arrows point from caller to dependency. An internal implementation imported
by the root package must not import the root package back. Errors that cross
that boundary are translated by the root facade into the existing public error
contract.

## Package responsibilities

| Location | Responsibility |
| --- | --- |
| Repository root | Public models, interfaces, constructors, and orchestration for repositories, publishers, consumers, trust, and durable state. |
| `cmd/s3disk` | Thin executable entry point. |
| `internal/cli` | Command parsing and application workflows. |
| `internal/localstate` | Secure local paths, ownership and ACL validation, atomic installation, directory durability, and process locks. |
| `internal/fsutil` | Small platform-specific filesystem operations used by disposable cache state. |
| `internal/syncutil` | Context-aware byte reservations and coalesced immutable downloads. |
| `mount` | Read-only filesystem adapter and inode lifecycle. |
| `presignedshare` | Expiring, credential-free read capabilities. |
| `publisherstate` | Protected publisher recovery envelopes. |
| `s3store` | AWS SDK v2 S3 implementation. |
| `memstore` | Deterministic in-memory store for tests and embedding. |
| `tests/blackbox` | Tests that exercise only public APIs or full workflows. |
| `spec` | Executable protocol and state-machine specifications. |

## Placement rules

When adding code, use the first matching rule:

1. A command-only workflow belongs in `internal/cli`.
2. A storage implementation belongs in its adapter package, not the root.
3. A reusable implementation detail belongs in a narrowly named `internal`
   package.
4. A type or function that downstream Go programs intentionally consume may
   belong in the root public package or an existing public subpackage.
5. A root test that needs unexported root state stays in the root. A test that
   can use public APIs belongs in `tests/blackbox`.

Do not create a public package merely to reduce the root file count. Moving a
Go file to another directory creates a different package and support contract.
Do not merge unrelated files to satisfy a cosmetic file-count target.

## Compatibility rule

Refactors must preserve the root import path, exported declarations, sentinel
error identity, serialized formats, S3 object keys, and command behavior unless
the change is explicitly versioned. Use wrappers at the public boundary when an
internal package needs its own errors or types.
