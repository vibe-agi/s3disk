# Compatibility

This document distinguishes source compatibility, successful compilation, and
validated production support. A build tag is not a support commitment.

## Go and API versions

The module currently declares Go 1.25 as its source-compatibility floor. Go
supports a major release only until two newer major releases exist, so Go 1.25
and 1.26 are supported upstream as of July 2026. Release artifacts are built
with a fully patched supported toolchain. The release workflow currently
requires Go 1.26.5 and must be updated when Go ships a later security patch.
See the official [Go release policy and
history](https://go.dev/doc/devel/release).

The `go 1.25.0` directive is a language/module parsing floor, not a security
support promise. Embedding applications should use a Go branch still supported
upstream at its latest patch level.

There is no stable `v1` API tag yet. Before `v1.0.0`, minor releases may change
public APIs. After `v1`, incompatible Go APIs require a semantic import version
such as `/v2`.

The object namespace is `.s3disk/v1`. Published object formats must never be
changed in place. Any incompatible format requires a new namespace, a documented
reader/writer compatibility window, and migration and rollback tests.
`testdata/protocol/v1` freezes canonical reference, commit, directory, file,
and symlink encodings; the test suite decodes, semantically validates, and
re-encodes every fixture byte-for-byte. These fixtures prevent accidental wire
drift but do not replace the still-required cross-version migration tool and
upgrade/rollback product matrix.

## Platform matrix

| Component | Target | Current status | Additional production consideration |
| --- | --- | --- | --- |
| Core and `s3store` | Go-supported OS/architecture | Core protocols are portable Go; protected publication-journal, watermark, and cache paths are enabled on Linux, Windows, and Darwin with cgo, while the confidentiality-bearing `FileSealedStateStore` is limited to Linux and Darwin with cgo and deliberately fails closed on Windows; other targets fail closed where their ACL semantics are not certified; the checked-in CI workflow runs native tests on Ubuntu, macOS, and Windows | Review CI evidence for the exact release and test every additionally advertised target; do not advertise sealed recovery-WAL support on Windows |
| `mount` | Linux | FUSE implementation and actual `/dev/fuse` E2E tests are present; the MinIO-backed flow passed on Ubuntu 24.04 ARM64, kernel 6.8, on 2026-07-22 | Re-run on each kernel/distribution used by the embedding product and before important rollouts |
| `mount` | macOS | Real macOS 26 macFUSE/FSKit E2E gate covers read-only access, refresh, snapshot-pinned handles, inode reclamation, two concurrent mounts, and clean unmount; VFS and `auto` remain selectable | Requires a separately installed macFUSE runtime. Re-run on every shipped macOS/architecture; FSKit requires macOS 15.4+, macFUSE 5+, and a mountpoint below `/Volumes` |
| `mount` | FreeBSD | Build-tagged implementation present | Compile-only status; no production support until dedicated kernel/runtime E2E coverage exists |
| `mount` | Windows | Returns `ErrUnsupportedPlatform` | Requires a native adapter and separate driver/licensing/security review |

macFUSE states that redistributions bundled with commercial software, including
automated download or installation, require prior written permission. A user
installing macFUSE independently does not make this project responsible for
redistribution, but product counsel must approve the exact onboarding flow.
The repository's pinned CI installation is test infrastructure, not a bundled
product installer.
See macFUSE's [official licensing
announcement](https://macfuse.github.io/2021/05/16/macfuse-4.1.2.html).

## S3-compatible backends

The protocol requires all of the following for the selected bucket and prefix:

- linearizable, atomic single-key `GET`, `HEAD`, and `PUT`; a read beginning
  after a completed write must never return an older version;
- `PUT If-None-Match: *` create-if-absent behavior;
- `PUT If-Match: <ETag>` compare-and-swap behavior;
- stable ETags usable for conditional operations;
- conditional `GET If-None-Match` returning not-modified correctly;
- read-after-write visibility for the mutable reference and immutable objects;
- no gateway, proxy, lifecycle rule, or replication policy that mutates or
  deletes live protocol objects unexpectedly.

Repository construction and channel validation include the caller prefix,
protocol namespace, delimiters, and URL-safe base64 channel in S3's 1,024-byte
UTF-8 object-key limit. Invalid combinations fail before source scanning or
object-store I/O rather than producing a partial immutable upload.

`Repository.ProbeStoreCompatibility` returns a versioned, structured report for
conditional create/replacement, nil-expected CAS, missing-key `If-Match`,
sequential and concurrent single-winner behavior, immediate `HEAD`/`GET`, opaque
version tokens, current and stale conditional `GET`, exact and overflowing
`MaxBytes`, and adapter buffer ownership. The error-only
`CheckStoreCompatibility` wrapper remains available. A semantic contradiction
is `incompatible`; a missing bucket, wrong region, or endpoint mode is
`configuration_error`; access denial is `permission_denied`; cancellation,
timeout, throttling, 5xx, and transport failure are `indeterminate` rather than
false evidence against a provider. See
[S3 backend commissioning](S3_COMPATIBILITY.md).

For archived commercial evidence from the built-in S3 adapter, use
`s3store.Store.ProbeCommissioningWithPresigningStore`; its parent envelope
retains both this 31-check writable report and the 14-check credential-free
presigned-GET report while recording the split Store topology.
`Repository.ProbeStoreCompatibilityWithOptions` remains the focused writable
sub-probe for custom Store adapters and fault isolation. Both forms add
validated caller deployment/build identifiers and redacted timing/prefix
bindings without serializing the raw prefix. `fully_bound` is a syntactic
completeness flag, not authentication; an independent controller must
recompute the expected bindings and sign or tamper-evidently seal the complete
combined report.

The report scope is explicitly `single_client_finite_probe`. A pass can reject
bad endpoint behavior but cannot certify cross-client/gateway-node histories;
the commercial matrix must add independent-client and failure-injection runs.

The probe mutates caller input and returned output buffers to detect adapters
that retain or expose aliased storage. Run it during provisioning for every
vendor, version, gateway, and consistency mode. It is intentionally write-
capable and uses `ObjectDeleter` for cleanup when available. Cleanup is reported
separately because delete is not required by the publication protocol. Each
delete is checked with `HEAD`, and only `ErrObjectNotFound` proves current
absence; no-op deletion and uncertain verification remain cleanup failures
under one overall deadline. Versioned history or a delete marker may remain
after current absence is verified. Cleanup is not a consumer health check and
does not replace longer failure/partition testing.

The `Store` contract now includes `GetOptions.MaxBytes`. Adapters must reject a
body beyond a positive caller limit before buffering it. A zero limit selects
the adapter's own finite cap. The core passes smaller limits for references and
metadata and a bounded chunk limit. An adapter that ignores this contract is
not compatible even if its conditional operations work.

AWS S3 and the pinned MinIO fixture are integration targets, not blanket
certification of every compatible implementation. Each vendor, gateway,
version, consistency mode, and proxy combination needs the same conflict,
stale-read, lazy-read, corruption, timeout, and recovery test suite.

The MinIO integration fixture is bound to an OS-selected loopback port rather
than a fixed host port. `.github/workflows/ci.yml` is configured to run that
fixture separately from the native Ubuntu/macOS/Windows tests, the macOS 26
macFUSE/FSKit mount gate, Linux unit/race/vet/compliance checks, and TLA+ model
checking. The commercial Linux workflow is separate and requires an
owner-controlled runner with `/dev/fuse`;
only artifacts for the exact release revision constitute compatibility
evidence.

## Filesystem behavior

- Files, directories, and symlinks are represented. Device nodes, sockets,
  FIFOs, and other special files are rejected by the publisher.
- Publisher traversal uses `os.Root` and identity checks to prevent source-root
  escape through concurrent path or symlink replacement. It retries ordinary
  changes detected through inode, size, mode, and mtime, but metadata equality
  cannot prove that file bytes were unchanged (for example on coarse timestamp
  filesystems or when a writer restores metadata). It is not an atomic snapshot
  of one adversarially changing file or of the whole tree; use APFS/LVM/VSS or
  an equivalent quiesced producer snapshot for strict content atomicity.
- `SymlinkRejectExternal` is the zero-value/default policy for publisher and
  consumer. It accepts portable relative links only when their resolved target
  stays inside the snapshot root. `SymlinkPreserve` explicitly opts into
  potentially escaping or platform-specific targets. `mount.ReadOnly` rejects
  preserve mode again at the mount boundary unless
  `DangerouslyAllowMountWithPreservedSymlinks` is set.
- Native and unsupported-platform `mount.Options` expose the same two explicit
  security opt-outs. Before mountpoint, Store, or FUSE I/O, `mount.ReadOnly`
  requires `Consumer.SecurityStatus().DurableWatermarkConfigured` unless
  `DangerouslyAllowMountWithoutDurableWatermark` is set. Failures match
  `ErrDurableWatermarkRequired` or `ErrSymlinkPreserveUnsafe`. The status also
  reports whether reference authentication is configured, which product policy
  may require independently; it does not claim a reference has already been
  fetched. A durable watermark is only a monotonic anti-rollback anchor, not an
  offline last-known-good snapshot; a restarted mount must still fetch and
  verify an initial snapshot from the Store.
- After its initial refresh and before FUSE starts, a native mount samples the
  Consumer's optional `AuthorizationExpirySource`. An already expired deadline
  fails with `ErrAuthorizationExpired`; a future deadline is fixed for that
  mount and cannot be extended by later reader state. The earlier of that
  deadline and the caller context stops polling/invalidation and starts bounded
  automatic unmount. Unsupported adapters perform the same local expiry
  validation without Store, filesystem, or FUSE I/O before returning
  `ErrUnsupportedPlatform`.
- Authorization expiry is a local lifecycle signal, not revocation or DRM. It
  requires no publisher-to-consumer callback and does not change the rule that
  S3 is the only runtime publisher-to-reader medium after the initial handoff.
  It cannot retract bytes already read or cached, and S3 must independently
  enforce expiration of the presigned request. A new
  sharing interval requires a new root capability/link and remount rather than
  extending the old mount.
- Permission metadata is portable permission bits with write bits removed on
  consumer views. ACLs, owners, groups, xattrs, hard-link identity, sparse-file
  layout, resource forks, and platform-specific metadata are not preserved.
  A FUSE mount reports the mounting process's UID and GID for every entry, so
  the kernel applies the published owner permission bits to that per-user
  mount. Run separate mounts under separate service identities when isolation
  between local users is required.
- `s3disk mount-set` can supervise up to 128 independent reader mounts in one
  process after strict private-config, handoff, resolved-path, and duplicate
  share preflight. A terminal child error cancels and waits for all peers;
  normal expiry of one workspace does not terminate later-expiring mounts.
  This is operational grouping, not a union mount or a security boundary.
  Configuration hot reload, publisher supervision, automatic child restart,
  and multi-workspace soak evidence remain outside the current compatibility
  claim. The required Linux `/dev/fuse` gate does exercise two simultaneous
  independent mounts and coordinated supervisor cancellation; see
  [`MOUNT_SET.md`](MOUNT_SET.md).
- An open file is snapshot-pinned, including its bytes, size, mode, and mtime.
  Non-root inodes are generation-bound, and stale namespace, open, readlink,
  and directory-open operations return `ESTALE` instead of combining
  generations. Mount file handles always use FUSE direct I/O because the
  kernel page cache is shared by inode and cannot preserve different
  generations for simultaneous old and new handles. The legacy
  `Options.KernelCache` field is rejected with `ErrKernelCacheUnsupported`.
- Kernel negative-dentry caching is disabled. `Options.NegativeTTL` is retained
  only for source compatibility; negative values are invalid and every
  positive value is rejected with `ErrNegativeCacheUnsupported`. Linux
  6.19-era changes caused affected kernels
  to return `ENOENT` when asked to invalidate a negative dentry without
  removing its configured timeout; see the upstream
  [regression commit](https://github.com/torvalds/linux/commit/c9ba789dad15ba65662bba17595c0aeaa0cfcf1c)
  and [maintainer reproduction](https://lkml.iu.edu/2606.0/00386.html).
  Repeated misses traverse cached immutable manifests and do not fetch chunks.
- Refresh notifications are latency optimizations, not a path-level
  linearization barrier. A notification can race a FUSE `LOOKUP` which the
  bridge attaches afterward, and the kernel may enforce cached permission bits
  before calling the adapter. A path converges after successful invalidation or
  `EntryTTL` expiry (one second by default), plus polling and network/store
  delay. Under a partition there is no finite freshness bound. Every successful
  individual operation is single-snapshot, but callers must tolerate transient
  `ESTALE` while a dentry is being replaced.
- Stable inode identities use an exact, collision-free
  `(snapshot,path,type)` registry rather than a truncated hash. The default
  lifetime caps are 1,000,000 identities (`Options.MaxInodeIdentities`) and a
  conservative 256 MiB retained-memory charge
  (`Options.MaxInodeIdentityBytes`). The byte charge includes the inline exact
  key/value, private copies of path and type strings, allocator rounding, and a
  map bucket/growth allowance. Both limits are checked under the allocation
  lock; a new lookup fails with `ErrInodeIdentityLimit` and a used/limit/request
  diagnostic instead of reusing a live identity or exceeding either budget.
  `Mount.Status` exposes both identity count and byte usage/limits plus the
  cumulative reclaimed count. The adapter consumes go-fuse `OnForget`
  lifetime evidence to conditionally release an exact mapping only if it still
  names the forgotten inode. Late and duplicate events cannot remove a newer
  allocation for the same tuple. Inode numbers themselves stay monotonic and
  are never reused, so an old file handle can safely outlive namespace
  reclamation. The Linux `/dev/fuse` gate deliberately sets a four-identity
  limit while materializing more than four cross-generation identities and
  requires observable reclamation. Kernels may delay `FORGET`, so simultaneous
  live identities still need a measured count/byte budget and sharding policy.
- `Mount.Status` separately records refresh, advisory reverse invalidation and
  unmount health. `AuthorizationExpiresAt` is the fixed locally known boundary;
  `AutomaticUnmountReason` reports whether context termination or authorization
  expiry initiated the automatic stop. Notification failures retry in one
  independent coordinator with exponential delay capped at five seconds and
  coalesce to the newest observed snapshot. `NotifiedSnapshot` acknowledges
  only a stable completed sweep, not an inotify or namespace-linearization
  barrier. Customer `OnError`
  delivery is bounded and lossy if the callback blocks; status is the
  authoritative failure record and callbacks must return promptly. `Healthy`
  remains an age-independent structural check. Production monitors should call
  `HealthyAt(now, maxRefreshAge)` with a positive freshness SLA; it also
  requires a nonzero successful refresh no older than the inclusive bound and
  treats a future timestamp after clock skew as fresh. This check is passive,
  while the core poller separately calls `PollOptions.OnAttempt` immediately
  before every refresh and bounds the complete operation with
  `AttemptTimeout` (two minutes by default, at most 30 minutes). A timeout is a
  refresh failure: it reaches `OnError`, degrades mount health, and retries with
  the normal bounded backoff. The mount's initial refresh uses the same bound.
- `Mount.Unmount` cancels its poller only after success and concurrent callers
  join one lock-free physical attempt. A failed attempt leaves polling active
  and may be retried with `UnmountContext`. Context- and authorization-triggered
  automatic retries use exponential delay capped at one second and stop after
  `Options.AutoUnmountTimeout` (30 seconds by default); `LifecycleStopFailed`
  remains observable if the server is still mounted. An operating-system
  unmount call itself may be uninterruptible, so expiry initiates a bounded
  best-effort lifecycle stop rather than hard revocation. `Done` and
  `WaitContext` cover the FUSE server and background-worker shutdown. Later
  calls after a successful stop are idempotent.
- FUSE invalidation and editor file-watch behavior vary by OS and application.
  The Linux gate proves refreshed lookup/read behavior, `EROFS`, snapshot-pinned
  open-handle bytes and `fstat` metadata, type changes, rename, deletion, and
  missing-to-present lookup with negative caching disabled. It does not prove
  that an invalidation produces inotify events. VS Code and other advertised
  clients require separate black-box event/reload certification; callers must
  not promise watcher notifications merely because subsequent reads are fresh.
- `Publisher.Watch` recursively registers real directories through `os.Root`
  in 256-entry read batches. Registration applies the protocol's path depth,
  path byte length, entry-name byte length, and per-directory entry limits and
  rejects a tree requiring more than 100,000 directory watches with
  `ErrResourceLimit`. Kernel or runtime watcher quotas may fail below that cap.
  Event delivery remains a latency optimization; periodic full publication is
  the default correctness fallback.

## Local state and authenticated references

`DiskCache` is bounded and LRU-managed. Its defaults are 10 GiB of payload,
64 MiB per cached chunk, and 100,000 indexed entries. Filesystem metadata and
one serialized temporary write are outside the payload accounting. Configuration
is also constrained by library hard limits: 1,000,000 retained entries, the
protocol's 64 MiB maximum chunk, and the corresponding maximum representable
payload capacity. Startup directory inspection is separately bounded by
`MaxStartupScanEntries` (zero selects twice `MaxEntries` plus 256 digest shards)
and returns `ErrResourceLimit` instead of scanning an arbitrarily populated
cache. Non-empty directories in locations that may only contain chunk files are
also rejected instead of being recursively traversed or deleted. One cache
directory cannot be shared by multiple cache instances or processes. Close a
cache after its users finish so its rooted confinement handle is released.
Cache files are flushed before rooted same-directory rename. Unix targets also
sync the cache directory; Windows deliberately treats the namespace update as
disposable and does not claim power-loss durability for cached entries because
ordinary directory handles lack the required write access. A missing entry
after a crash is a verified cache miss and is fetched again; publisher journals
and consumer watermarks use separate, stronger durability machinery below.
Decoded metadata uses one cross-kind LRU with a conservative retained-memory
budget (64 MiB plus a 4,096-entry secondary bound by default). Same-digest
metadata downloads are coalesced. Application-owned open file handles can keep
their pinned manifest alive after LRU eviction, so the product must separately
bound simultaneous handles.
Same-digest concurrent reads, including cache hits, are singleflight-coalesced.
Cache reads and remote chunk fetches both consume `MaxConcurrentDownloads`
(default 8). They simultaneously consume `MaxConcurrentDownloadBytes`: zero
selects a finite 64 MiB default, and the accepted range is 64 MiB through
64 GiB. A chunk is charged by the exact `chunk.Size` in its validated file
manifest; `(digest, size)` is the singleflight identity so contradictory
manifests cannot share a result. The same exact size is sent to `Store.Get` as
`MaxBytes`, and the returned length is checked again. The shared chunk flight
retains one reservation until every successful waiter finishes copying its
slice; a partial waiter release cannot admit a conflicting new allocation.
Metadata manifests reserve their conservative 16 MiB protocol maximum through
JSON decoding. References reserve 4 KiB even when the JSON is small and discard
the raw body before releasing that charge. Waiting for either the count or
weighted byte limit is context-cancelable and does not start a goroutine per
waiter; error, panic, and all-waiter cancellation paths release ownership.

`DiskCache` bounds each entry and temporary buffer at the 64 MiB protocol
maximum and implements `SizedChunkCache`, rejecting an indexed or on-disk size
mismatch before allocating the body. The legacy `ChunkCache.Get(ctx, digest)`
contract intentionally remains source-compatible and cannot communicate an
expected size before a third-party cache allocates. Custom caches which allocate
on reads should implement the optional sized interface; legacy caches must
enforce a finite per-call allocation bound of at most 64 MiB themselves. The
Consumer reservation includes the cache call, length/digest verification,
hashing, and write-back, but cannot constrain memory that application-defined
cache code allocates internally in violation of that contract.

`FileWatermarkStore` persists the highest accepted generation/commit with an
atomic CAS. Its protected local implementation is available on Linux, Windows,
and Darwin builds with cgo. Other targets return `ErrTrustStateUnsupported`
until their native ACL model has been certified; successful compilation alone
is not a local trust-state support claim. On non-Windows targets, the
constructor resolves and pins intermediate
symlinks before storing its path; every operation revalidates the complete
canonical ancestor chain. State files and directory components must be owned by
the current effective UID or root. State files, lock files, and the final
directory containing them always reject group/world write access. Writable
intermediate components are also rejected even below a currently private
ancestor: a foreign process may have retained a directory descriptor before
the ancestor became private. A trusted sticky ancestor such as `/tmp` is the
only writable-directory exception and may contain the newly created private
directory. New
directories use mode `0700`, and each new directory entry is
followed by a parent-directory sync. Darwin also inspects each already-opened
path component for extended ACLs and rejects any such ACL, including an ACL
inherited by a `0600` temporary file; without cgo these local constructors fail
closed with `ErrTrustStateUnsupported`. On Linux, the effective mask of a POSIX
access ACL is reflected in the group mode bits checked above; filesystems with
different authorization semantics are unsupported for local trust state.
Windows does not use
Go's emulated Unix permission bits as an ACL signal: it rejects reparse-point
path components, requires a trusted owner, and rejects DACLs that grant
modification to trustees other than the current identity, Local System,
built-in administrators, or creator-owner trustees. Windows namespace changes
use same-directory `MoveFileEx` operations with `MOVEFILE_WRITE_THROUGH`; the
implementation does not claim that an ordinary directory `File.Sync` has
Windows durability semantics.

`FilePublicationJournal` uses the same protected-path, cross-process locking,
atomic-replace, and write-through machinery. It persists both the last
`Committed` publication and at most one `Pending` S3 compare-and-swap, including
the exact signed reference bytes needed for deterministic restart recovery.
Both file stores perform a parent-directory durability barrier before returning
a visible state from `Load`; this closes the process-crash window between rename
and the original writer's directory sync.

These guarantees apply to supported local filesystems. Network filesystems are
unsupported unless their lock, atomic-replace, ACL, and write-through semantics
are certified. The Windows ACL, reparse-point, and write-through paths must be
run on native Windows in the release matrix; cross-compilation alone cannot
validate host ACL inheritance or power-loss persistence. Use distinct private
paths for publisher journal and consumer watermark state, namespace each by
repository/channel/role, and preserve them across restarts to retain rollback
defense.

Authenticated references are optional and stored under `signed-refs/v1`,
separate from legacy unsigned `refs`. Signed readers never fall back. The
`RepositoryID` and public verifier keys are caller-provisioned out of band. A
new signed reader requires durable watermark storage plus either an explicit
`TrustedCheckpoint` or an explicit `AllowTrustOnFirstUse` selection.

A signed publisher requires a signer, matching verifier, and durable
`PublicationJournal`. It durably begins a `Pending` intent before the S3
reference CAS and finalizes `Committed` only after reconciling the remote
result. `Publisher.RecoverPublication` replays or reconciles that exact intent
after restart; signed staging performs recovery before constructing a new
snapshot. With no existing committed publisher anchor it also requires an
independently delivered `TrustedCheckpoint` or explicit TOFU; an existing S3
reference cannot bootstrap itself. A brand-new channel therefore uses explicit
TOFU for its first signed publication.

All publisher instances for one repository/channel must share a linearizable
`PublicationJournalStore`. A shared `FilePublicationJournal` serializes
processes on one host; independent per-host files are not a distributed journal
and provide no multi-host monotonicity or split-brain guarantee. A multi-host
publisher deployment needs a separately certified linearizable implementation.
Publisher journal state and consumer adoption anchors are separate role state
and must use distinct protected stores/paths, namespaced by repository and
channel.

The built-in Ed25519 verifier is a finite direct keyring, not threshold root
metadata. Any one configured key is sufficient; there is no in-band expiry or
revocation. `Publisher.ResignReference` changes only the authentication
envelope for the current generation/commit and supports overlap-key rotation.
First-checkpoint distribution, TOFU rollback exposure, old-key removal, and
recovery after trust-state loss remain application/operator responsibilities.
