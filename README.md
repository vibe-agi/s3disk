# s3disk

`s3disk` is a Go library for publishing a local directory through an
S3-compatible object store and exposing it to other machines as a read-only,
lazy filesystem view.

The logical protocol uses immutable, content-addressed chunks and Merkle
manifests. For share/repository objects written through it, the
`strict-share-isolation-v1` profile encrypts each S3 object body and replaces
plaintext-digest object names with keyed opaque identifiers. A small per-channel
reference is updated with compare-and-swap only after all objects for a snapshot
exist. Consumers fetch metadata while traversing the tree and fetch file chunks
only when a caller reads them. An open file remains pinned to the snapshot in
which it was opened.

> **Release status:** pre-1.0 engineering preview. The consistency protocol is
> tested and model-checked, but the product limitations and release blockers in
> [Commercial release](docs/COMMERCIAL_RELEASE.md) still apply. Do not market
> the current tree as generally available production software. The model does
> not prove the client-encryption primitives or confidentiality.

s3disk is an Apache-2.0 open-source project. The license permits commercial
use, modification, and redistribution subject to its terms; that permission is
separate from this repository's pre-release status, support policy, and the
commercial certification gates documented below.

## Packages

- `github.com/vibe-agi/s3disk`: storage-independent publisher, consumer,
  manifests, chunking, cache, polling, and watch logic.
- `github.com/vibe-agi/s3disk/s3store`: AWS SDK v2 adapter for AWS S3 and
  compatible services.
- `github.com/vibe-agi/s3disk/presignedshare`: expiring, signed root bundles
  and a credential-free exact-key GET reader whose only application-data,
  authorization, and control-plane runtime peer is S3.
- `github.com/vibe-agi/s3disk/publisherstate`: bounded cryptographic envelopes
  for A-side recovery state, using an independent recovery key. The package
  deliberately does not provide persistence or a KMS; the core package's
  `FileSealedStateStore` adds crash-safe local CAS persistence on Linux and
  Darwin with cgo, but deliberately fails closed on Windows and cannot provide
  freshness after coordinated rollback by itself.
- `github.com/vibe-agi/s3disk/memstore`: in-memory store for tests.
- `github.com/vibe-agi/s3disk/mount`: read-only FUSE adapter on Linux, macOS,
  and FreeBSD build targets. See [Compatibility](docs/COMPATIBILITY.md) before
  shipping it.

## CLI: one expiring share

Until release artifacts exist, build the command directly from a reviewed
checkout:

```sh
go build -trimpath -o ./s3disk ./cmd/s3disk
```

A obtains S3 credentials from the AWS SDK default credential chain; the CLI
deliberately has no access-key or secret-key flags. Keep those credentials in
the platform's normal short-lived credential/profile mechanism, not shell
history.

Run the compatibility doctor on A before enabling a provider. This HTTPS
example uses an explicitly commissioned CA file:

```sh
s3disk s3 doctor \
  --bucket example-bucket \
  --prefix private/customer/commissioning \
  --endpoint https://s3.example.com \
  --path-style \
  --tls-ca /secure/provider-ca.pem
```

For every invoked probe, the doctor writes one JSON `S3CommissioningReport`
envelope covering both the 31-check writable Store contract and the 14-check
credential-free presigned-GET contract, including failed probes. It records
separate `passed`, `failed`, or `not_run` stage outcomes and a cleanup summary;
cleanup warnings go to standard error and do not rewrite the compatibility
verdict. `--deployment-fingerprint`, `--evidence-id`, and
`--implementation-version` must be supplied together or omitted together;
commercial records should supply all three. `--timeout` bounds the presigned
phase, while `--total-timeout` bounds the combined run. Treat the envelope as
finite, unsigned evidence and seal it in an independent release system before
using it for a commercial backend decision.

Then publish either the whole source with `--all`, as below, or selected
relative paths by replacing it with repeated `--path path/to/item` flags:

Provisioning for A-side publisher recovery can create a standalone recovery-key
file without printing the key to the terminal:

```sh
s3disk share recovery-key generate \
  --out /secure/publisher-recovery-key.json
```

The output is canonical versioned JSON installed without replacement as a
current-owner file with exactly `0600` permissions and, on supported Unix
filesystems, exactly one link. The final path component must be absent and must
not be a symlink; any existing file, directory, or symlink is refused. Parent
components may include a safely resolvable symlink:
the command resolves the parent once before staging, then validates the
resolved hierarchy's ownership, writable permissions, and supported ACLs.
This directory check is a safety proof, not a promise that every parent has
mode `0700`; safe hierarchies may use other modes. Unsupported ACL platforms
fail closed. Protect and back up this file separately from publisher state.

An installer's return value is not treated as proof of what reached the
filesystem. After every attempted install, the command reopens and validates
the final file and uses file identity to prove that it is the staged inode. An
installer that applied the change but returned an error is therefore accepted
only after the staging name is removed and the parent directory is synced. If
final identity, staging cleanup, or directory durability cannot be proved, the
command returns a stable uncertainty error and prints a `reconcile_required`
hint containing only the output path, key ID, and outcome--never the recovery
key. Treat that path as potentially installed and do not overwrite or delete it
until an operator has reconciled the final file and any staging name.
For an idempotent handoff or recovery-key retry, the CLI removes a reserved
staging name left by an earlier hard-link install only after `os.SameFile`
proves that it is another link to the exact final inode; unrelated matching
files are preserved. It then syncs the directory, requires the final file to
have one link, and only then reads and authenticates secret bytes.

`share publish` uses this independent key to seal an A-only session manifest
and exact root recovery WAL before its first S3 object operation. The manifest
contains the per-share encryption key, reference-signing seed, original root
bearer, fixed deadline, source selection, handoff path, and non-credential S3
configuration. It never stores a reusable access-key/secret-key credential
tuple, credential provider, or SDK configuration. The sealed exact-GET root
bearer can still contain its signing access-key ID and a temporary session-token
query value; treat the entire state directory as secret. Keep the recovery key
outside both the source and state directory.

Path separation is reinforced at the publisher boundary. Immediately before
every source scan, the CLI has `Publisher` open and pin the current filesystem
identity of each then-existing protected file: the recovery key, sealed
session, publication journal, root WAL, and handoff. The handoff alone may be
absent initially; after it is first observed, disappearance fails closed. A
selected source file with the same identity is rejected before its contents or
chunks are read or uploaded. This catches hard links and direct file bind
mounts where the platform reports the same identity, including every new scan
performed by `Watch`. Unix secret-file reads and sealed-state updates also
require a single link, so normal state rotation refuses an external hard link
before the old inode can be replaced.

This is not a complete mount or hostile-local-user boundary. Portable Go APIs
do not enumerate mount identities, and a bind mount pinned to an old inode
after canonical state replacement is not represented by the current protected
path or by Unix link count. A same-UID process can also race filesystem changes
and can ordinarily read A's secrets directly. Keep recovery material on
separately controlled storage and forbid source-tree submounts in commercial
deployment policy.

```sh
s3disk share publish \
  --source /srv/source \
  --all \
  --bucket example-bucket \
  --prefix private/customer \
  --state-dir /var/lib/s3disk/publisher \
  --recovery-key /secure/publisher-recovery-key.json \
  --handoff-out /secure/share.json \
  --expires-in 2h \
  --endpoint https://s3.example.com \
  --path-style \
  --tls-ca /secure/provider-ca.pem
```

The strict share CLI requires `--tls-ca` for HTTPS. The file must contain only
headerless `CERTIFICATE` PEM blocks with complete line boundaries; arbitrary
text, private-key blocks, PEM headers, and malformed blocks are rejected. The
CLI will not create a system-trust handoff because an operating-system verifier
may perform network requests outside S3. `s3 doctor` alone retains the explicit
`--dangerously-allow-system-trust` diagnostic opt-out. Literal loopback HTTP is
for local tests only and requires an `http://127.0.0.1:...` endpoint plus
`--dangerously-allow-http`. The publish command watches for changes by default;
add `--once` for one snapshot and exit.

The command emits a `prepared` line with the non-secret share ID as soon as its
two recovery records are durable, then a `ready` line after root and handoff
publication. The same ID is the isolated subdirectory name below `--state-dir`,
so it remains discoverable if A crashes before either status write is observed.
If A exits or crashes before the original fixed deadline, resume that exact
share with only its local recovery coordinates:

```sh
s3disk share resume \
  --state-dir /var/lib/s3disk/publisher \
  --share-id '<share_id from publish>' \
  --recovery-key /secure/publisher-recovery-key.json
```

`resume` intentionally has no source, bucket, prefix, endpoint, channel,
expiry, handoff, or credential override flags. It authenticates the sealed
session before resolving current A-side AWS credentials, then reopens the
descriptor, reconciles the signed-publication journal and exact root WAL,
installs or byte-verifies the original handoff, and continues the original
one-shot or watch mode without extending the deadline. An expired session
fails before AWS credential resolution, S3 access, source scanning, or handoff
I/O. The same recovery-key file may technically open multiple shares, but a
distinct key per share reduces compromise scope and avoids linkability through
the recovery-key identifier.

Copy `/secure/share.json` to B once through a private authenticated channel,
then mount it:

```sh
s3disk mount \
  --handoff /secure/share.json \
  --mountpoint /mnt/share \
  --state-dir /var/lib/s3disk/reader \
  --poll-interval 1s
```

The handoff output and destination parent directories must already be trusted
local directories: no group/world write access or unsupported extended ACLs.
The CLI creates the file exclusively as its current OS owner with exact mode
`0600`, verifies the open file and its directory hierarchy before writing or
reading the bearer/key, and refuses to overwrite an existing path. A custom
`--cache-dir` is a private cache base; the CLI automatically appends isolated
repository/share subdirectories.

The B command deliberately has no bucket, endpoint, region, or credential
flags: the handoff fixes its S3 origin and exact GET authority. After handoff,
the running A/B data path uses S3 only. The mount is read-only and starts a
bounded best-effort automatic unmount at expiry. A fresh `share publish`
creates new encryption/signing/root secrets; use `share resume`, never another
publish invocation, to recover an existing share. Recovery currently relies on
Linux or supported Darwin private-state semantics and fails closed on Windows.
It does not solve coordinated rollback of both local sealed state and matching
S3 state, recovery-key rotation, disaster-recovery backup policy, or early
revocation of the cloud credential that signed the original root URL; those
remain commercial release blockers.

## Publisher

```go
ctx := context.Background()

store, err := s3store.New(ctx, s3store.Config{
	Bucket:           "example-bucket",
	Region:           "us-east-1",
	Endpoint:         "https://s3.example.com", // omit for AWS S3
	UsePathStyle:     true, // normally needed by local compatible services
	RetryMaxAttempts: 3,
})
if err != nil {
	return err
}

repositoryID, err := s3disk.GenerateRepositoryID()
if err != nil {
	return err
}
shareKey, err := s3disk.GenerateClientEncryptionKey() // private handoff secret
if err != nil {
	return err
}
clientEncryption, err := s3disk.NewClientEncryptionProfile(repositoryID, shareKey)
if err != nil {
	return err
}
const sharePrefix = "customer/project/shares/<random-share-id>"
repository, _, err := s3disk.InitializeRepository(ctx, store, sharePrefix,
	s3disk.RepositoryConfig{
		RepositoryID:     repositoryID,
		ClientEncryption: clientEncryption,
		Chunking:         s3disk.ChunkingOptions{}, // use and durably bind the defaults
	},
	s3disk.RepositoryInitializationOptions{ConfirmEmptyPrefix: true})
if err != nil {
	return err
}
publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{})
if err != nil {
	return err
}

snapshot, err := publisher.Publish(ctx, "/srv/source", "main")
```

With no credential fields set, `s3store` uses the AWS SDK's rotating default
credential chain. Applications with their own secret broker can supply
`CredentialsProvider`; the SDK caches each returned value only until its
declared expiry. Because no public API has shipped yet, `Config` deliberately
has no static secret fields; this avoids freezing a reflection-readable key
container into v1. `Config` and each short-lived `Credentials` result redact
key material from ordinary `fmt` and JSON diagnostics, but callers must still
avoid reflection or memory dumps of secret-bearing values. AWS deployments can also
set `ExpectedBucketOwner` to the 12-digit account ID; it is sent on every data-
plane operation to prevent a name or endpoint mistake from silently selecting
another account's bucket. Retry attempts default to three and are explicitly
bounded from one through ten. `OperationTimeout` bounds the complete lifetime
of each GET, HEAD, PUT, or DELETE (including GET body consumption); zero selects
two minutes, the caller's earlier deadline still wins, and the configured value
cannot exceed 30 minutes.

For continuous publication, call `Publisher.Watch`. Filesystem notifications
reduce latency; periodic full reconciliation is the correctness fallback.
Serialize `Stage`/`Commit` pairs for a publisher. A concurrent writer wins or
returns `s3disk.ErrPublishConflict`; it is never silently overwritten.

For an expiring selected share, bind the result of `PublishSelected` with
`RootPublisher.CreatePublishedSnapshot`. Use
`RootPublisher.UpdatePublishedSnapshot` inside `WatchOptions.AfterPublished` so
a generation is not acknowledged until its exact authenticated closure has
been installed at the S3 root. A failed hook is retried for that generation by
an independent bounded exponential backoff whose default base grows from one
second to a 30-second cap with jitter, without waiting for another source event
or the five-minute full reconciliation. Source changes remain behind that
exact-generation barrier. This safe automatic path resolves only the signed
reference namespace and checks the complete Publisher-returned snapshot
identity before minting capabilities.

For restart-safe root publication, configure
`RootPublisherConfig.RecoveryJournal` with a confidential, authenticated,
linearizable `SealedStateStore`. Before any root write, `RootPublisher` records
the exact bytes that will reach the raw Store, including the ciphertext it
seals once when client encryption is enabled. Recovery reconciles a crash after
the pending write, a lost S3 response, and an uncertain journal CAS without
minting replacement URLs. A recovery-only process with the matching identity,
verifier, and closure may settle an existing pending target without a signer or
presigner; creating the next root still requires both. Every operation remains
locally deadline-bounded by the share's original fixed authorization expiry and
cannot extend it. A write already in flight at that boundary may still commit
remotely and is reconciled from the exact pending WAL target.
Likewise, a conditional write which reports success with an invalid Store
version is treated as potentially applied and reconciled immediately. If it
cannot be resolved, the error matches both `ErrRootPublishIndeterminate` and a
sanitized Store classification such as `ErrStoreIncompatible` or
`ErrAccessDenied`; provider response details are not propagated.

If the surrounding application also persists A's share session, call
`RootPublisher.PrepareRecovery` before marking that session resumable or
exposing its handoff. This installs an identity-bound, revision-zero Prepared
record without S3 I/O. After a crash, import the original root bearer with
`ParseBearer` and pass it to `RestoreRootPublisher`; restore authenticates the
existing sealed record and its fixed expiry before it privately re-admits that
bearer for publication. A missing, corrupt, expired, or mismatched record fails
closed without creating recovery state or touching the root Store. Ordinary
`NewRootPublisher` and bundle builders continue to reject imported bearers.
Restore requires the built-in offline reference verifier so recovery validation
cannot invoke an application-defined network verifier.

Immediately after restore, call `RootPublisher.RecoverPending` before resolving
or publishing a newer snapshot. It authenticates and settles the exact WAL
target (or anchors the current root when no operation is pending) without a
closure, signer, or presigner. A recovery-only publisher can also prove an
already matching closure idempotent; if a genuinely new root target is needed,
it returns `ErrRootBuildAuthorityRequired`, and the caller may then restore
again with a signer and a presigner fixed to the original deadline. Store
configuration failures use their own errors and must not trigger presigning.

The journal is a write-ahead log and local monotonic anchor, not an independent
freshness oracle. Replaying both the complete journal and its matching old S3
root remains indistinguishable without a separately protected monotonic backup,
audit receipt, or equivalent external anchor. With client encryption, pass the
raw unwrapped Store: encryption wrappers must preserve the
`ClientEncryptionApplied` marker, and Go cannot identify an opaque custom
wrapper that transforms bytes while hiding that marker.

Watch registration traverses directories in bounded batches and applies the
protocol's path-depth, path-length, entry-name, and per-directory entry limits.
It also refuses to register more than 100,000 directories and reports
`s3disk.ErrResourceLimit` instead of growing without bound. Operators must
still size OS watcher limits for the supported workload.

Publication scans through `os.Root`, so path replacement and symlink tricks
cannot make traversal escape the selected source root. Files and directories
are identity-checked around their reads, which catches ordinary edits but
cannot prove unchanged bytes if a writer or filesystem restores the same
metadata. Strict single-file or cross-file point-in-time consistency requires
an OS/filesystem snapshot or quiesced producer workspace.

## S3-only sharing boundary

After the initial share handoff, S3 is the only runtime medium between A and
B/C/D. A reader never contacts A, an authorization service, a callback, or any
other control plane. A updates one mutable root object in S3; readers poll the
same presigned root URL and lazily fetch only exact immutable objects named by
an authenticated bundle.

Normal hostname endpoints may still require the Reader's private Go resolver to
query the deployment's configured DNS infrastructure. DNS sees the S3 endpoint
hostname, not bearer paths, queries, headers, or object contents, and is not a
publisher-to-reader data or control plane. A deployment requiring literally no
non-S3 network egress must use independently controlled name resolution or add
and certify a pinned-resolution/routing capability; the current Reader does not
provide one.

B has no `SecretAccessKey`, credential provider, or SigV4 signer. It cannot
mint another request or broaden a key, method, bucket, or expiry. A SigV4
presigned URL does expose its access-key ID and, for temporary credentials,
normally its session token. The complete URL is replayable bearer authority
for its one exact GET until expiry and must be protected as a secret.

The safe B-side path requires the exact built-in
`*s3disk.Ed25519ReferenceVerifier`, whose key lookup and signature check are
purely local. A custom verifier is rejected before any of its methods run;
enabling `DangerouslyAllowCustomReferenceVerifier` explicitly gives up the
S3-only guarantee because `RepositoryID` or `Verify` may perform arbitrary
network I/O. Every HTTPS reader supplies its commissioned CA roots as bounded,
certificate-only PEM bytes in `ReaderConfig.TLSRootCAPEM`; Reader rebuilds them
internally with the same strict parser used by the CLI and S3 commissioning
probe. It does not invoke an operating-system verifier that may fetch AIA or
revocation data outside the S3 transport.
`DangerouslyAllowSystemTrustStore` is an explicit interoperability opt-out and
invalidates the strict S3-only claim. Reader also rejects a caller
`*x509.CertPool`, client certificate, TLS callback, proxy, custom dialer, and
caller `httptrace` callback.

One share has a fixed absolute deadline covering the root and every object
capability in every revision. After it, the reader refuses network I/O and the
mount starts automatic unmount. A new sharing period requires a new root link
and remount; there is no renewal callback. See
[S3-only expiring sharing](docs/S3_ONLY_SHARING.md) for the complete protocol,
failure model, compatibility checks, and current flat-bundle limits.

## Client-side share isolation

`strict-share-isolation-v1` uses a fresh random 256-bit key for each share.
HKDF-SHA256, with domain-separated labels and the `RepositoryID`, derives
independent encryption and opaque-index masters. Each envelope carries a fresh
random 16-byte HKDF salt used to derive an independent AES-256 key, then uses
AES-GCM with a fresh random nonce. Authenticated associated data binds the salt,
`RepositoryID`, and exact logical/store key, including its prefix, so moving
ciphertext to another key or prefix fails authentication. HMAC-SHA256 over the
object kind and logical plaintext digest produces the opaque physical ID for
immutable manifests and chunks.

With the profile configured consistently on `Repository`, `RootPublisher`, and
`Reader`, the root bundle, mutable references, manifests, and chunks are all
ciphertext in S3. Metadata traversal and chunk reads remain lazy. Stable keyed
IDs retain deduplication only inside that share; independent shares use new
keys and dedicated random prefixes, so the S3 layer neither shares ciphertext
nor exposes plaintext-digest equality through physical IDs. Encryption keys are
random and are never derived from file contents: convergent encryption is
deliberately not used.

Treat the prefix, `RepositoryID`, profile, and share key as one inseparable
storage domain. Never reuse a prefix with plaintext mode or another profile,
and never combine ciphertext from different prefixes/profiles.
`InitializeRepository` creates or exactly reopens a write-once
`RepositoryDescriptor` that binds the normalized prefix, `RepositoryID`, storage
profile, and Rabin chunking algorithm and parameters. A `Publisher` created from
that repository inherits the descriptor's chunking defaults and rejects a
different chunking profile or signer repository identity. The `share publish`
CLI allocates a fresh random share namespace, explicitly confirms it as new, and
uses this initialized path before publishing its first snapshot.

When the descriptor is absent, `InitializeRepository` writes nothing unless the
caller sets `RepositoryInitializationOptions.ConfirmEmptyPrefix`. That flag is a
caller assertion, not a `Store` proof: the protocol does not require `LIST` and
cannot discover objects left in an uncommissioned legacy prefix. Set it only
after allocating and independently validating a new dedicated namespace. An
existing identical descriptor can be reopened without that creation
confirmation; conflicting configuration fails closed.

The descriptor is an A-side commissioning guard, not B's signed trust root. It
is not yet included in the signed share-root bundle or its capability closure,
so the credential-free B path does not fetch it and continues to construct its
repository from the authenticated handoff and signed root. Low-level
`NewRepositoryWithOptions` constructors can still represent legacy or externally
commissioned storage, but `NewPublisher` rejects such an uncommissioned
repository by default with `ErrRepositoryNotInitialized`. Bypassing that guard
requires the explicitly dangerous
`PublisherOptions.DangerouslyAllowUncommissionedRepository` option and is outside
the commercial path. The descriptor binds the profile name, not proof that a
key/profile is unique to one share. A wrong key, identity, or exact object key
still fails authentication, but reusing one profile across prefixes would
repeat opaque HMAC suffixes and reveal equality. Associated data and the
descriptor do not bind the bucket, account, origin, region, S3 version,
`ShareID`, or expiry; signed capabilities, IAM, TLS, and deployment
commissioning enforce those boundaries.

The private handoff to B contains the share key in addition to the root bearer
and trust bindings, but no `SecretAccessKey`, credential provider, or reusable
SigV4 signer. The bearer can still expose an access-key ID and temporary session
token. Anyone holding reusable S3 credentials can act within that IAM policy:
list opaque keys if allowed, download ciphertext, overwrite or delete it, deny
service, and observe object sizes and access timing. Without the share key those
S3 observations do not decrypt the protected object bodies. Conversely,
compromise of the handoff or share key compromises that share's confidentiality
and cannot revoke plaintext already read or copied. Deliver the handoff through
a private authenticated channel and keep it out of logs, command lines,
telemetry, and support data.

`DiskCache` stores already-decrypted chunks under their logical SHA-256 digest;
it is not bound to a share, profile, or `RepositoryID`. Give every share a
separate private cache directory. Reusing one directory across shares permits
local cross-share plaintext equality and cache hits even though their S3
ciphertext is isolated. Protect and erase caches according to the source-data
policy. Continue to require SSE-S3 or SSE-KMS as defense in depth for S3 media
and operational controls; server-side encryption does not replace this
client-side profile.

## Consumer and lazy reads

```go
// B receives these values through the product's authenticated initial share
// handoff, including the per-share encryption key. It does not construct
// s3store.Store and has no reusable S3 credentials or signer.
clientEncryption, err := s3disk.NewClientEncryptionProfile(repositoryID, shareKey)
if err != nil {
	return err
}
rootCapability, err := presignedshare.ParseBearer(rootBearer,
	presignedshare.CapabilityOptions{})
if err != nil {
	return err
}
reader, err := presignedshare.NewReader(presignedshare.ReaderConfig{
	RootCapability:   rootCapability,
	RepositoryPrefix: sharePrefix,
	ReferenceKey:     signedReferenceKey,
	ShareID:          shareID,
	Verifier:         verifier,
	ClientEncryption: clientEncryption,
	TLSRootCAPEM:     commissionedTLSRoots, // required for every HTTPS origin
})
if err != nil {
	return err
}
repository, err := s3disk.NewReadOnlyRepositoryWithOptions(reader, sharePrefix,
	s3disk.RepositoryOptions{ClientEncryption: clientEncryption})
if err != nil {
	return err
}
cache, err := s3disk.NewDiskCache(shareCachePath) // private to RepositoryID + ShareID
if err != nil {
	return err
}
defer cache.Close()
watermarks, err := s3disk.NewFileWatermarkStore("/var/lib/my-product/s3disk/main.watermark")
if err != nil {
	return err
}
consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
	Cache: cache, Watermarks: watermarks, RequirePersistentWatermark: true,
	ReferenceVerifier: verifier, TrustedCheckpoint: &checkpoint,
})
if err != nil {
	return err
}
if _, err := consumer.Refresh(ctx); err != nil {
	return err
}

file, err := consumer.Open(ctx, "docs/report.pdf")
if err != nil {
	return err
}
buf := make([]byte, 64<<10)
n, err := file.ReadAtContext(ctx, buf, 0)
```

`Stat`, `ListDir`, and `Open` do not download file data. A range read downloads
only intersecting chunks. `Consumer.Poll` advances to newer generations while
retaining the last verified snapshot across transient failures.
`PollOptions.OnResult` runs after every successful check, including unchanged
results, so independent mounts sharing one concurrent-safe `Consumer` still
notice a generation adopted by another poller or an external `Refresh`.
The persistent watermark in the example prevents a restarted unsigned
consumer from accepting a lower generation after an accidental reference
rollback. Without it, monotonicity survives only for the lifetime of one
`Consumer` process. It does not persist enough manifest metadata for an offline
restart: a new process still needs the object store to load its initial
snapshot, while an already running process retains its last verified view
through transient refresh failures.

`Consumer.SecurityStatus` reports whether a durable `WatermarkStore` and
reference authentication are configured, together with the symlink policy. It
is a read-only configuration inspection and performs no object-store or local
state I/O; it does not claim that a reference has already been fetched.

`NewDiskCache` uses finite defaults: 10 GiB of chunk payload, 64 MiB per cached
chunk, and 100,000 indexed entries. `NewDiskCacheWithOptions` can set lower
product limits; least-recently-used entries are evicted and an oversized chunk
is read normally without being cached. The constructor also has a finite
directory-entry scan budget (by default twice `MaxEntries` plus the 256 digest
shards); `MaxStartupScanEntries` can lower or raise it within the library hard
limit. Opening a damaged or unexpectedly overfull cache fails with
`ErrResourceLimit` when that budget is exhausted. Filesystem metadata and at
most one in-flight temporary chunk add overhead beyond the payload limit. Do
not open one cache directory from multiple `DiskCache` instances or processes.
Close each `DiskCache` when its consumers and open files are finished; `Close`
waits for in-flight cache operations and releases the confinement directory
handle.
Concurrent requests for the same chunk, including cache hits, join one
singleflight operation. Cache reads, cache misses, and remote chunk fetches all
consume the `MaxConcurrentDownloads` semaphore, whose default is 8, so a hot
cache cannot bypass the configured work concurrency bound. They also consume a
weighted `MaxConcurrentDownloadBytes` budget. Its zero-value default is 64 MiB,
the protocol maximum for one chunk; accepted values are 64 MiB through 64 GiB.
A chunk is charged at the exact size authenticated by its file manifest, and
that size is passed to the object-store adapter as `GetOptions.MaxBytes` before
the body is buffered. A successful singleflight keeps that reservation while
the shared slice is handed to its joined callers; it is released only after the
last `ReadAtContext` caller finishes copying from it. Metadata manifests are
conservatively charged and limited at 16 MiB through JSON decoding, while
mutable references are charged and limited at 4 KiB and their raw JSON is
dropped before release. Count and byte limits apply simultaneously, and errors,
panics, or canceled waiters cannot retain either resource.

The built-in `DiskCache` implements the optional `SizedChunkCache` extension and
rejects a size mismatch before allocating or reading the entry. The original
`ChunkCache` interface remains source-compatible, but cannot govern allocations
made inside an application-supplied `Get` implementation before it returns.
Custom caches which allocate on reads should implement `SizedChunkCache`; legacy
implementations must enforce their own finite per-call allocation limit no
larger than 64 MiB. The Consumer byte budget still covers the cache call,
returned-buffer verification, hashing, and cache write, and rejects a returned
length that differs from the manifest, but it cannot undo an internal
over-allocation by third-party code.

Decoded directory, file, and symlink manifests share a separate LRU with a
conservative 64 MiB retained-memory budget and a 4,096-entry secondary limit.
Use `MetadataCacheBytes` and `MetadataCacheEntries` to select lower product
limits. Concurrent loads of the same metadata digest are singleflight joined;
an object larger than the whole memory budget is verified and returned to its
caller but is not retained.

## Read-only mount

```go
mounted, err := mount.ReadOnly(ctx, consumer, "/mnt/project", mount.Options{
	Poll:               s3disk.PollOptions{Interval: time.Second},
	AutoUnmountTimeout: 30 * time.Second,
})
if err != nil {
	return err
}
defer func() {
	stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = mounted.UnmountContext(stopCtx)
}()
if err := mounted.WaitContext(ctx); err != nil && !errors.Is(err, context.Canceled) {
	return err
}
```

Before inspecting the mountpoint, refreshing from the Store, or starting FUSE,
`ReadOnly` requires a Consumer with a configured durable watermark and rejects
`SymlinkPreserve`. Callers can distinguish these failures with
`errors.Is(err, mount.ErrDurableWatermarkRequired)` and
`errors.Is(err, mount.ErrSymlinkPreserveUnsafe)`. The only bypasses are the
separate, deliberately named
`DangerouslyAllowMountWithoutDurableWatermark` and
`DangerouslyAllowMountWithPreservedSymlinks` options. Do not set either through
a broad "compatibility mode" switch. Reference authentication remains a
separate policy: inspect
`Consumer.SecurityStatus().ReferenceAuthenticationConfigured`
when the product requires publisher identity rather than integrity and
rollback detection alone.

The FUSE adapter rejects mutation operations with `EROFS`. The default
`SymlinkRejectExternal` policy rejects absolute, cross-platform ambiguous, and
root-escaping links at publication and consumption. `SymlinkPreserve` requires
both Consumer configuration and the mount's explicit dangerous opt-out; with
it, the mount is not a sandbox and a link may lead outside the mounted tree.
The durable watermark is an anti-rollback anchor, not an offline
last-known-good snapshot: a restarted mount still needs the Store to load and
verify its initial snapshot.

If the Consumer's `ObjectReader` implements `AuthorizationExpirySource`,
`ReadOnly` samples its earliest deadline once after the initial refresh and
before starting FUSE. An already expired share fails with
`mount.ErrAuthorizationExpired`. A running mount pins that deadline for its
whole lifetime: later local reader state or a replacement URL set cannot extend
it, while an earlier caller-context cancellation still wins. Expiry cancels
polling and invalidation and starts the same bounded automatic-unmount loop as
context cancellation. This requires no callback or direct network connection
to the publisher; it is a local timer over the read capabilities already
supplied to the `ObjectReader`, whose data path may use only exact-key presigned
S3 URLs.

Automatic unmount is a lifecycle and UX boundary, not DRM. It cannot revoke
bytes already returned to a process, retained by an application or kernel, or
stored in an enabled disk cache. The S3 authorization layer must independently
reject expired object requests. A new authorization period requires a new
root capability/link and a remount rather than extending an existing mount in
place.

Snapshots preserve portable permission bits, not source UID/GID or ACLs. The
mount reports every entry as owned by the mounting process and lets the kernel
enforce those permission bits; use one service identity per local trust domain.

Every file handle uses FUSE direct I/O. `Options.KernelCache` remains in the API
for source compatibility, but setting it returns
`mount.ErrKernelCacheUnsupported`: the kernel page cache is shared by inode and
cannot simultaneously represent an old snapshot-pinned handle and a newer
handle for the same path.

Kernel caching of missing names is also disabled. `Options.NegativeTTL` is
retained for source compatibility; negative values are invalid and a positive
value returns `mount.ErrNegativeCacheUnsupported`. This avoids making new-file
visibility depend on reverse invalidation behavior which differs across Linux
kernels; repeated missing lookups use verified manifest metadata and never
fetch file chunks.

Refresh sends best-effort invalidations for materialized FUSE entries and
pages. A successful operation uses one snapshot, and an already open file keeps
its original bytes and metadata. Path lookup freshness is not instantaneous:
an invalidation racing an in-flight lookup can leave the old dentry until its
`EntryTTL` expires (one second by default), and cached permission checks can
have the same bound. Stale inode operations return `ESTALE` rather than mixing
generations. This still does not guarantee an inotify/FSEvents event for VS Code
or another editor. Certify each advertised editor with black-box tests or
configure it to poll/reload.

`Mount.Status` exposes refresh, reverse-invalidation and unmount health without
performing I/O. `AuthorizationExpiresAt` is the immutable deadline captured at
mount creation, and `AutomaticUnmountReason` distinguishes authorization
expiry from caller-context termination. `ObservedSnapshot` is the latest
adopted view; `NotifiedSnapshot` means only that one complete advisory
invalidation sweep finished for that identity—it is not an inotify or lookup
linearization barrier. `Healthy()` preserves this structural, age-independent
health check; commercial monitors should use
`HealthyAt(time.Now(), maxRefreshAge)` with an explicit freshness SLA. It
additionally requires a nonzero successful refresh
no older than the inclusive positive bound; a future timestamp after local
clock skew is treated as fresh. Notification failures retry independently of
later polls with bounded backoff, while the status retains the last error.
`HealthyAt` is passive: distinguishing and canceling a hung in-flight refresh
still requires a core poll attempt hook and per-attempt child-context deadline.
`Done`/`WaitContext` wait for the FUSE server and background workers.
`UnmountContext` joins concurrent physical attempts and retries transient
failures; context- or authorization-triggered automatic unmount is bounded by
`AutoUnmountTimeout` (30 seconds by default), after which
`LifecycleStopFailed` remains observable for operator action. A blocked or
permanently failing operating-system unmount can therefore leave the namespace
mounted after authorization expiry; the library does not abandon an
uninterruptible physical unmount in additional goroutines or claim hard
revocation.

Stable inode identities also have independent count and retained-byte budgets.
`MaxInodeIdentities` defaults to 1,000,000 and
`MaxInodeIdentityBytes` defaults to a conservative 256 MiB; the latter is a
hard charged limit for exact snapshot/path/type registry entries, including
private string copies and map/allocation allowance. `Mount.Status` reports
`InodeIdentitiesUsed`/`InodeIdentitiesLimit` and
`InodeIdentityBytesUsed`/`InodeIdentityBytesLimit`. Exceeding either limit
fails the new lookup with `ErrInodeIdentityLimit` and never aliases an existing
inode. The registry is monotonic for safety: kernel `FORGET`-based reclamation
is not implemented yet, so plan remounts or mount sharding for high-churn,
long-lived deployments.

## Consistency contract

- A snapshot becomes visible through one conditional reference update after
  all of its immutable objects have been uploaded.
- Consumers never adopt a lower generation. A generation mapped to two
  different commits is reported as `s3disk.ErrSplitBrain`.
- Manifests and chunks are SHA-256 verified before use. Corrupt data is rejected.
- Open handles stay on one generation and never combine chunks from two
  snapshots.
- A persistent `FileWatermarkStore` prevents a restarted consumer from
  accepting a generation below its last durable checkpoint. Its CAS is
  serialized across processes on Linux, macOS, and Windows. Darwin requires
  cgo for native extended-ACL inspection; platforms without a certified ACL
  implementation fail closed with `ErrTrustStateUnsupported`.
- During an arbitrary network partition the library can preserve a coherent
  last-known-good view, but it cannot guarantee bounded freshness. Once the
  network and store remain available and polling continues, consumers converge.

The executable TLA+ model and its assumptions are in [`spec/`](spec/README.md).

## Authenticated references and trust bootstrap

Unsigned references remain the default for compatibility. Applications that
need publisher authentication can configure a `ReferenceSigner` and
`ReferenceVerifier`; signed references live under an independent
`signed-refs/v1` namespace, and a trusted consumer never falls back to an
unsigned reference.

Provision the random `RepositoryID` and trusted public keys out of band, never
from the S3 repository they authenticate. A signed publisher requires the
signer, a verifier that trusts it, and a durable `PublicationJournal`; it fails
closed without all three. The journal atomically records a `Pending` intent,
including the exact signed reference bytes and S3 compare-and-swap precondition,
before the mutable reference is attempted. After S3 accepts the operation, the
journal advances `Committed` and clears `Pending`. A restart calls
`Publisher.RecoverPublication` (and signed staging performs the same recovery
before constructing a new snapshot) to replay or reconcile that exact intent;
it never signs a different operation at the pending generation.

All publishers for the same repository/channel must use one linearizable
`PublicationJournalStore`. `FilePublicationJournal` supplies cross-process
serialization only to publishers sharing its protected local path on one host.
Independent local journal files on multiple publisher hosts do not provide the
required ordering and cannot guarantee rollback or split-brain safety; use a
certified distributed linearizable journal implementation for that topology.
When the journal has no committed anchor, the publisher also requires either an
independently delivered `TrustedCheckpoint` or an explicit
`AllowTrustOnFirstUse` decision. The signed reference already present in S3 is
not an independent bootstrap anchor. A brand-new channel has no checkpoint to
verify, so its first signed publication requires the explicit TOFU selection.

A signed consumer separately requires a durable `WatermarkStore` and one of:

- an explicit `TrustedCheckpoint` delivered over a trusted channel; or
- an explicit `AllowTrustOnFirstUse` decision, which persists the first valid
  signed reference but cannot detect a valid older reference on first contact.

The publisher journal and consumer adoption watermarks are independent durable
role state. Keep them in distinct protected persistent stores and paths;
neither role's state should silently bootstrap or overwrite the other role's
trust decision. Preserve both across restarts.

The built-in Ed25519 verifier is a direct keyring: one trusted key signature is
enough. It is not a threshold/offline-root metadata system and has no signed
expiry or revocation list. Rotate with an overlap keyring, switch the signer,
call `Publisher.ResignReference` to re-sign the current generation, and remove
the old key only after every consumer has received the new trust configuration.
Insecure first-checkpoint delivery, loss of durable journal/watermark state, or
delayed key removal remains an operator trust risk.

## Object-store requirements

The backend must provide linearizable, atomic single-object operations and correctly
implement conditional `PUT` using `If-None-Match: *` and `If-Match: <ETag>`, as
well as conditional `GET`. “S3 compatible” alone is not sufficient evidence.
`Version.ETag` is the sole compare-and-swap token; an optional S3 Version ID is
reported only for diagnostics because `PutObject` cannot condition on it.
For the built-in S3 adapter, prefer
`Store.ProbeCommissioningWithPresigningStore` during production provisioning
for every supported vendor/version and endpoint mode; use
`Store.ProbeCommissioning` only when intentionally commissioning one identity.
The combined envelope preserves both the 31-check writable Store result and the
14-check credential-free presigned-GET result. The nested structured reports distinguish
a proven semantic incompatibility from configuration or permission errors and
an indeterminate timeout, throttle, 5xx, or transport failure. The lower-level
`Repository.ProbeStoreCompatibilityWithOptions`,
`Store.ProbePresignedGetCompatibilityWithOptions`, and error-only
`CheckStoreCompatibility` APIs remain available for focused testing. The
writable probe uses cryptographically random keys below the repository
namespace. It checks
conditional create and replacement, missing-key `If-Match`, nil-expected CAS
create semantics, exactly one winner under concurrent `PutIfAbsent`, first-
writer CAS, and replacement CAS, winner identity, stable opaque ETags and
immediate reads/HEADs, current and stale conditional GET, `MaxBytes` boundaries,
and adapter buffer ownership. It deletes probe keys when the adapter implements
`ObjectDeleter`, then verifies every current object is absent with `HEAD`; a nil
delete response by itself is not accepted as proof. A no-op delete, an object
that remains visible, or an access/network failure during verification produces
a redacted cleanup warning without changing the protocol verdict. Cleanup uses
one bounded overall deadline. A successful current-object check on a versioned
bucket may still leave noncurrent versions or a delete marker, so
`historical_versions_may_remain` remains conservative. Run it with a
commissioning identity if the runtime identity has no delete permission.

A conditional write may have reached S3 even when its response was lost and a
retry finally returned 412. The probe resolves that ambiguity only when a
bounded GET of its isolated random key returns the exact unique payload and a
valid version token. Named retryable 409 responses such as
`ConditionalRequestConflict` and `OperationAborted` remain operationally
indeterminate, rather than being reported as provider incompatibility.

```go
report, err := writerStore.ProbeCommissioningWithPresigningStore(ctx,
	presigningStore,
	s3store.S3CommissioningProbeOptions{
		RepositoryPrefix:      "private/customer/commissioning",
		DeploymentFingerprint: deploymentFingerprint, // canonical non-secret config SHA-256
		EvidenceID:             "commissioning-20260718-001",
		ImplementationVersion:  "commercial-build+17",
		PresignedGet: s3store.PresignedGetCompatibilityProbeOptions{
			TLSRootCAPEM: commissionedTLSRoots,
		},
	})
if err != nil {
	var diagnosis *s3store.S3CommissioningError
	if errors.As(err, &diagnosis) {
		log.Printf("S3 commissioning status=%s writable=%s presigned=%s",
			diagnosis.Status, diagnosis.WritableStoreOutcome,
			diagnosis.PresignedGetOutcome)
	}
	return err
}
log.Printf("S3 commissioning schema=%d scope=%s passed; cleanup_attention=%t",
	report.SchemaVersion, report.Scope, report.Cleanup.AttentionRequired)
```

The combined APIs add UTC start time, cleanup-inclusive duration, a random run
ID, two domain-separated prefix fingerprints, and validated caller binding
fields to the JSON envelope. It never serializes either raw prefix. When the
presigned prefix is omitted it is derived inside the normalized repository
namespace as `.s3disk/v1/probes/presigned-get`; an explicit value must remain
inside that namespace. Because the exact anonymous HTTP route uses a narrower
syntax, the combined repository prefix is currently restricted to bounded
ASCII routes containing only letters, digits, `.`, `_`, `-`, and `/`, with no
`//`, `.` segment, or `..` segment. The resulting presigned prefix may contain
at most 768 bytes, so a derived repository prefix must leave room for the
suffix; the repository prefix itself may be empty.

With no caller deadline, the combined active phases receive a seven-minute
overall deadline and the writable phase retains its independent five-minute
default; each nested probe and cleanup also keeps its own tighter bound. Invalid
options are rejected before Store I/O. Context limits still rely on the Store
honoring cancellation. `Complete` means both nested check sets completed,
independently of whether they passed. Cleanup state is operational evidence and
never changes `Compatible` or a stage outcome.

These hashes and the complete combined report are neither signatures nor
automatic discovery of endpoint, bucket, credential identity, or server
version. Build the deployment digest
from one canonical non-secret inventory, then have an independent release
controller recompute it and tamper-evidently sign or seal the complete report.
Never place access keys, tokens, private certificates, or other secrets in the
caller-controlled fields. `fully_bound` says only that the required declarations
are present, not that they are true.

See [S3 backend commissioning](docs/S3_COMPATIBILITY.md) for verdict semantics,
failure explanations, and why an “S3-compatible” label is insufficient.

Custom `Store` adapters must enforce `GetOptions.MaxBytes` before buffering an
object. The core supplies protocol-specific limits for references, metadata,
and chunks. The protocol plaintext maximum remains 64 MiB; the S3 adapter's raw
fallback/PUT ceiling is 64 MiB plus the fixed 52-byte client-encryption envelope
so a maximum plaintext chunk remains valid when encrypted. Smaller plaintext
limits likewise become that limit plus 52 bytes at the encrypted Store
boundary. Because no public API has shipped, v1 does not expose a configuration
knob that could silently lower plaintext compatibility or raise the raw
allocation ceiling beyond this envelope-adjusted maximum.

The publication/read protocol does not list object keys. Give credentials only
to A and use TLS. B/C/D use `presignedshare.Reader` and therefore have no IAM
principal or reusable S3 signing material; their authority is the fixed root
GET bearer plus the exact GET bearers in authenticated root revisions. A needs
`s3:GetObject` and conditional `s3:PutObject` within the repository and share-
root namespaces. Bucket creation and administration remain outside runtime
roles. Add only the KMS permissions needed by the bucket encryption policy.

A commissioning identity also needs the production A-side data-plane
permissions and may need `s3:DeleteObject` for probe cleanup. Commission both
the writable Store contract and the anonymous presigned-GET path. A pass under
a broader or differently routed identity is not evidence that the production
path works. Content hashing detects corruption; signed references and signed
root bundles authenticate the selected commit. See [Security](SECURITY.md).

`Store.ProbeCommissioning` keeps the convenient same-Store path. For the
recommended least-privilege topology, use
`Store.ProbeCommissioningWithPresigningStore`: the receiver performs every
canary write, credentialed read-back, CAS, and cleanup, while the separately
constructed Store is used only to freeze credentials and issue exact GET
bearers. A successful split report records `presigning_topology=separate_store`
and `cross_configuration_canary_binding_observed=true`. The MinIO gate runs
this path with a writer principal and a second principal whose policy contains
only `s3:GetObject`, while separately confirming that PUT, DELETE, and LIST are
denied.

Those fields prove only what this finite call observed. Separate Go Store
instances are not proof of separate IAM identities, and matching canary bytes
and versions across two routes do not authenticate the provider's complete
bucket/origin configuration. Commercial certification still requires an
independently archived IAM/BPA/routing inventory and provider-specific policy
evidence. The current `s3disk s3 doctor` command deliberately remains the
same-Store commissioning path; use the split library API or a controlled
certification harness for the two-principal topology.

The presigned-path report is finite evidence, not a provider certification or
mathematical proof. It samples unsigned public-policy access, exact signed GET
authority, named request mutations, and credentialed/anonymous read-backs of
two independent canaries, including exact cross-canary payload/version and
foreign-bearer authority disclosure checks. It cannot infer the complete
bucket/IAM/BPA policy, all query/header/method variants, alternate origins,
post-expiry behavior, or future provider and network states. A commercial
backend therefore also
requires a reviewed GetObject-only signing principal scoped to the same single
bucket/origin, a documented BPA/IAM/public-access review, and a raw-wire
HTTP/1.1 and HTTP/2 certification harness for bodyless responses, chunk
metadata, and bytes hidden by Go's `net/http` framing. Explicit commissioned
TLS roots remain mandatory for every HTTPS B-side Reader and probe. See
[S3 backend commissioning](docs/S3_COMPATIBILITY.md) for the exact current
checks and limitations.

## Development checks

The MinIO suite requires Docker Compose v2 and `jq`; Linux FUSE coverage also
requires `/dev/fuse` and `fusermount3`.

```sh
go test ./...
go test -race ./...
go vet ./...
./scripts/test-minio.sh
./scripts/check-model.sh
./scripts/check-project-license.sh
./scripts/check-third-party.sh
./scripts/check-fuzz-wiring.sh
./scripts/test-release-ref.sh
# On a Linux release runner with /dev/fuse:
./scripts/test-mount-linux.sh
```

MinIO is pulled only as an external AGPL-3.0 test fixture. It is not linked into
the Go module and must not be included in a redistributed product image without
a separate licensing review.

The regular CI workflow is configured to run native tests on Ubuntu, macOS, and
Windows, plus Linux quality/race/vet/compliance checks, the pinned MinIO
integration, and TLA+ model checking. The MinIO fixture binds an OS-selected
loopback port so parallel jobs do not depend on a fixed host port. The separate
commercial workflow has an unpublished-candidate mode and a post-publication
tag mode. It runs the fail-closed gate only on a disposable, isolated Linux
runner with `/dev/fuse`, emits a hashed success artifact, and places candidate
promotion behind a post-gate protected environment. A workflow loaded from the
candidate checkout is not an independent authorization root; commercial
promotion still requires the separately controlled release process described
in the release document.

Before publishing a commercial tag, follow [Commercial
release](docs/COMMERCIAL_RELEASE.md). Run the protected workflow against the
untagged branch-head digest, approve and archive that evidence, then create an
OpenPGP-signed annotated tag explicitly at the approved commit in an isolated
release checkout. Release mode requires the authorized primary fingerprint in
a root-owned protected allowlist, pins a root-owned verifier executable, and
revalidates the signed tag name and target after the full gate. Push that exact
ref only after it passes; the tag-triggered workflow is post-publication
verification.

## Contributing

Contributions are welcome under the Apache-2.0 license. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the DCO sign-off, development checks,
and protocol boundaries. Report suspected vulnerabilities through the private
process in [`SECURITY.md`](SECURITY.md), not through a public issue.

## License

s3disk is open-source software licensed under the [Apache License
2.0](LICENSE), including for commercial use subject to that license. This is a
license, not a warranty, support commitment, or statement that the current
preview has passed the commercial release gate. Third-party terms and required
attributions are listed
separately in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and
[`NOTICE`](NOTICE).
