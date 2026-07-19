# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
**Report a vulnerability** workflow for
[`vibe-agi/s3disk`](https://github.com/vibe-agi/s3disk/security/advisories/new).
Include affected versions, impact, deployment assumptions, and a minimal
reproducer when possible.

The repository owner must enable and externally verify private vulnerability
reporting and define an internal response owner before the first public push.
No response or remediation SLA is promised by this pre-release repository.

## Supported versions

There is no production-supported version yet. Until a stable release policy is
published, security fixes are made only on the current development line. A
commercial release must identify its supported major/minor lines and end-of-life
dates in customer-facing terms.

## Security boundaries

- A's bucket/prefix IAM policy and S3's enforcement of exact presigned requests
  are authorization boundaries. B/C/D must not receive `SecretAccessKey`, a
  credential provider, or a signer. Their built-in runtime path uses only one
  root and authenticated exact-key GET bearers through S3; it never contacts A
  or another authorization/control-plane service. SHA-256 verifies object
  integrity but does not authenticate a party that can replace both manifests
  and an unsigned reference. Expiring shares therefore require signed
  references and signed root bundles.
- Keep the commissioned bucket private. Block Public Access (BPA), bucket and
  access-point policies, ACLs, IAM permissions, gateway/origin rules, and any
  provider equivalents must deny anonymous access except through the exact
  presigned operation. Prefer the combined `s3store.Store.ProbeCommissioning`
  envelope so the 31-check writable and 14-check credential-free paths retain
  one run identity and separate stage outcomes. The anonymous compatibility
  phase samples unsigned GET, PUT, and DELETE denial only against its two random
  canaries and selected origin; it cannot audit the complete policy graph or
  every alternate endpoint. The report is unsigned caller-produced evidence,
  not an attestation. A
  documented BPA/IAM/public-access review is a commercial-release gate even
  when the probe reports `Compatible`.
- A SigV4 URL exposes an access-key ID and may expose a temporary session token.
  Neither lets B sign a new request, but the whole URL is a replayable secret
  for its exact operation until expiry. Exclude bearer URLs, bundle bodies, and
  headers from logs, telemetry, command lines, crash reports, and support data.
- A consumer is read-only with respect to S3 and the mount, but the source
  publisher is trusted. Root-escaping symlinks are rejected by default on both
  publication and consumption. `SymlinkPreserve` explicitly accepts them for
  compatibility, in which case the mount is not a sandbox.
- `mount.ReadOnly` fails before mountpoint, Store, or FUSE I/O unless the
  Consumer reports a configured durable watermark and a non-preserving symlink
  policy. The two risks have separate, deliberately dangerous opt-outs; do not
  enable them indirectly. `Consumer.SecurityStatus` also reports whether
  reference authentication is configured. A watermark prevents accepting an
  older generation across restarts but is not an offline last-known-good
  snapshot: restart still requires Store access to reconstruct and verify the
  initial view.
- A standalone `presignedshare.Reader` keeps root revision monotonicity only in
  memory. Cross-restart rollback resistance belongs to the composed
  `Reader` + signed `Consumer` + protected durable watermark + trusted
  checkpoint path. A fresh Reader bootstraps that recovery only through the
  original fixed S3 root bearer; it does not contact A. Do not advertise
  standalone Reader state as a durable rollback anchor.
- Use HTTPS endpoints with certificate verification. Do not place A-side
  credentials or B-side bearer material in source, command-line arguments,
  logs, crash reports, or world-readable configuration. Prefer short-lived
  workload credentials on A and a shorter fixed share deadline.
- The built-in B-side reader makes direct S3-origin requests. It rejects
  environment/application proxies, custom dialers, `TLSNextProto` round
  trippers, redirects, cookies, custom TLS callbacks, client certificates, and
  disabled certificate verification. It also strips caller `httptrace` values
  before transport use and uses a private resolver without an application
  callback. For a hostname endpoint that resolver may still query the
  deployment's configured DNS service; DNS can observe the S3 hostname but not
  the bearer path, query, headers, or object content. Thus S3 is the only
  application-data, authorization, and control-plane peer, not necessarily the
  only network destination. A zero-non-S3-egress profile requires separately
  certified pinned name resolution/routing, which is not implemented. Every
  HTTPS reader must receive bounded commissioned roots through
  `ReaderConfig.TLSRootCAPEM`; they are parsed into Reader-owned certificate
  objects. This avoids platform system verifiers that may fetch AIA or
  revocation data outside the locked S3 dialer. The explicit
  `DangerouslyAllowSystemTrustStore` opt-out invalidates the strict S3-only
  claim and must not be enabled on B/C/D. Caller `*x509.CertPool` values are
  rejected because they can contain executable constraints. A configured root
  CA remains a trusted boundary and can authenticate an S3 impersonator. Do
  not replace this transport boundary in product wrappers without a separate
  bearer-confidentiality review.
- The S3-only consumer path accepts exactly the built-in
  `*Ed25519ReferenceVerifier`. Custom verifier methods can hide network I/O and
  are rejected before invocation. `DangerouslyAllowCustomReferenceVerifier`
  is an explicit interoperability opt-out and invalidates the S3-only claim;
  do not enable it on B/C/D. The same rule applies to the low-level
  `presignedshare.Decode`: its custom-verifier opt-out exposes the signed
  payload, including bearer URLs and headers, to that callback.
- On A, use a separate GetObject-only principal for `PresignSession` when the
  provider permits it, distinct from the writer used for publication and root
  CAS. Both must be commissioned for the same bucket/origin. This
  least-privilege split limits the impact of a gateway that incorrectly treats
  a presigned GET bearer as another HTTP method. For a commercially supported
  backend this is a hard gate: the signing principal must be restricted to
  `GetObject` for the one commissioned bucket (and required key scope), with no
  write, delete, list, or bucket-administration authority. The library cannot
  discover or prove that IAM fact from a presigned URL.
- The `strict-share-isolation-v1` client-encryption profile uses one fresh
  random 256-bit key per share. Domain-separated HKDF-SHA256 derives independent
  encryption/index masters. Each message uses a fresh random 16-byte HKDF salt
  to derive an independent AES-256 key, then AES-GCM uses a fresh random nonce.
  Associated data authenticates the salt, `RepositoryID`, and exact
  logical/store key, including its prefix. HMAC-SHA256 maps immutable plaintext
  digests to keyed opaque physical IDs. With the same profile installed at every
  A/B boundary, root, reference, manifest, and chunk bodies are ciphertext in
  S3. A resolved snapshot closure carries an internal keyed profile binding;
  `RootPublisher` rejects plaintext/encrypted or wrong-key Repository mixing
  before it presigns an object or writes the share root. Writable Repository
  construction only reuses the package's concrete audited encryption wrapper,
  so an external Store cannot self-report that encryption was already applied
  and receive plaintext. This applies only to share/repository objects written through every
  required wrapper; compatibility canaries, local journals, watermarks,
  handoff files, caches, and unrelated bucket objects are outside it.
- The handoff contains that share key and the root bearer, but no
  `SecretAccessKey`, credential provider, or reusable SigV4 signer. The bearer
  can still expose an access-key ID and temporary session token. Deliver the
  handoff through a private authenticated channel and exclude it from logs,
  command lines, telemetry, crash reports, and support data. Reusable S3
  credentials still permit every action allowed by IAM: listing opaque keys if
  granted, downloading ciphertext, overwriting or deleting it, causing denial
  of service, and observing sizes and timing. AEAD/signature checks detect
  unauthorized modification, but cannot preserve availability. Without the
  share key, S3 ciphertext is not decryptable through this profile.
- The handoff file necessarily contains the client key and bearer in usable
  plaintext form. Diagnostic redaction is not memory protection: values may be
  exposed by reflection, debuggers, core dumps, or swap. The library provides
  no `mlock`, automatic handoff deletion, key zeroization, or secure erase;
  products must define those storage, process, backup, and deletion controls.
  The built-in CLI additionally requires an owner/ACL-validated parent
  hierarchy and a current-owner regular file with exact mode `0600`; unsupported
  local ACL platforms fail closed.
- `publisherstate.RecoveryKey` is a separate 256-bit A-side recovery secret;
  never derive it from or replace it with the client share key, an S3 access
  key, customer content, or a password. Its built-in Protector provides a
  bounded HKDF-SHA256/AES-256-GCM envelope with key-ID and caller-binding
  authentication, but no storage, KMS, freshness, backup, or zeroization.
  `FileSealedStateStore` adds protected crash-safe local CAS persistence on
  Linux and Darwin with cgo and can be used as
  `RootPublisherConfig.RecoveryJournal`; it deliberately fails closed on
  Windows, and the cryptographic envelope still does not make an old complete
  file detectably stale. The CLI does not yet persist its publishing state
  through this API. Keep the recovery key in
  an independently protected key file, OS keystore, or KMS and add an external
  monotonic backup or audit anchor where coordinated rollback is in scope.
  `AESGCMKeyring` supports a bounded active-plus-retained-key rewrap operation,
  but old keys cannot be retired until every required live state and backup has
  been durably migrated, installed, and verified.
- Treat each prefix, `RepositoryID`, profile, and share key as one storage
  domain. Do not mix encrypted and plaintext repositories, different profiles,
  or ciphertext copied across prefixes. `InitializeRepository` creates or
  exactly reopens a write-once `RepositoryDescriptor` binding the normalized
  prefix, `RepositoryID`, storage profile, and Rabin chunking algorithm and
  parameters. A descriptor-backed `Publisher` inherits that chunking profile
  and rejects different chunking parameters or a signer for another repository;
  the `share publish` CLI allocates a fresh random share namespace and uses this
  initialized A-side path. If a descriptor is missing, initialization requires
  the caller to set `RepositoryInitializationOptions.ConfirmEmptyPrefix`; without
  it the call fails with `ErrRepositoryNotInitialized` after a read and performs
  no write. This is an assertion that the caller has independently allocated and
  checked a new namespace, not a `Store` verification: the API does not require
  `LIST` and cannot detect objects in an uncommissioned legacy prefix.
  `NewPublisher` likewise rejects a repository without a verified descriptor by
  default. `PublisherOptions.DangerouslyAllowUncommissionedRepository` is the
  explicit legacy escape hatch and is outside the commercial path. A wrong key,
  repository identity, or exact logical key also fails authentication.
  The descriptor is not yet included in the signed root bundle or its exact-GET
  capability closure, so B does not fetch it and must not treat it as signed
  trust evidence. Low-level repository constructors can still create an
  uncommissioned value for read-only or explicit legacy use, but cannot silently
  publish through it. The descriptor does not prove per-share key/profile
  uniqueness. The opaque HMAC suffix does not include prefix or `ShareID`;
  reusing one profile across prefixes leaks equality. Neither associated data
  nor the descriptor binds bucket, account, origin, region, S3 version,
  `ShareID`, or expiry; capability, IAM, TLS, and commissioning controls remain
  mandatory.
  Within-share HMAC IDs preserve lazy loading and S3 deduplication;
  independently keyed shares do not deduplicate with each other at S3. Never
  replace this design with convergent encryption or derive encryption keys from
  customer content.
- The client key is symmetric and shared by every recipient of one handoff.
  Its holder can both decrypt and construct valid AEAD envelopes; AES-GCM does
  not identify publisher A. Publisher/state authenticity instead comes from
  Ed25519 signed references/root bundles, domain-separated SHA-256 object
  verification, and S3 write IAM. One shared handoff cannot distinguish,
  attribute, or revoke B separately from C/D. Use a separate share, prefix,
  random key, and root for each independently revocable recipient.
- Confidentiality relies on the operating system CSPRNG and the standard
  security assumptions of HKDF-SHA256, HMAC-SHA256, SHA-256, and AES-256-GCM.
  The consistency TLA+ model abstracts authorization and collision freedom; it
  does not model these primitives, key compromise, randomness failures, side
  channels, or confidentiality and is not a cryptographic proof.
- AES-GCM does not provide freshness: replaying the same valid ciphertext at
  the same exact key can still decrypt. Signed generations/root revisions,
  conditional S3 updates, trusted checkpoints, and the durable consumer
  watermark provide the separate rollback defenses.
- The S3 adapter does not request server-side object encryption explicitly.
  Continue to enforce SSE-S3 or SSE-KMS as a bucket default and test associated
  KMS permissions. SSE protects a different layer and does not replace the
  client-side profile. No FIPS certification or compliance claim is made.
- Cached chunks contain plaintext source data. Protect the cache directory and
  underlying volume according to the source data classification. `DiskCache`
  keys entries by logical chunk digest and does not bind them to a share,
  profile, or `RepositoryID`; give every share a separate private cache
  directory. Sharing one permits cross-share plaintext equality observations
  and cache hits. `DiskCache`
  has finite byte, per-chunk, and entry limits with LRU eviction, but those
  limits count payload rather than filesystem metadata and allow one in-flight
  temporary chunk. A cache directory is single-instance/single-process.
  Same-digest cache reads are singleflight-coalesced, and both cache hits and
  remote fetches consume `MaxConcurrentDownloads`; size that limit for the
  application's memory and hashing budget.
- Share expiry stops new built-in reader requests locally and starts bounded
  automatic unmount, while S3 must independently reject the expired bearer.
  This is not revocation or DRM: already-read process memory and plaintext disk
  cache entries remain, and an operating-system unmount may fail or block.
  Possession of the share key and captured ciphertext cannot be revoked
  cryptographically. A new period uses a new random share key, root bearer, and
  remount; there is no runtime callback to A or renewal service.
- Decoded manifests share a finite retained-memory LRU (64 MiB and 4,096
  entries by default) and same-digest metadata loads are singleflight joined.
  Set `MetadataCacheBytes` lower for constrained processes. The budget covers
  cache retention, not metadata still referenced by application-owned open
  handles; bound open handles at the product layer.
- The client profile hides plaintext digest equality across independently keyed
  shares, but S3 can still observe the share namespace, protocol object kind,
  object count, and access timing. Because the envelope is unpadded with a fixed
  52-byte overhead, ciphertext length reveals each protected body length. It is
  not an OS/process
  tenant sandbox and does not provide malware scanning or data-loss prevention.
  Repository-level KEK management, repository-dedup mode, key rotation, and
  migration are not implemented.
- `os.Root` confines publisher traversal to the selected source root and the
  scanner rejects identities that change while individual entries are read.
  It does not make a multi-file tree scan atomic. Use an OS/filesystem snapshot
  or quiesced producer when a point-in-time tree is a security requirement.
- Recursive Watch registration also uses `os.Root`, reads directory entries in
  bounded batches, applies protocol path/depth/name/directory-entry limits, and
  caps registration at 100,000 directories. Exceeding a bound fails with
  `ErrResourceLimit`; OS watcher quotas can impose a lower operational limit.
- Custom object-store adapters must enforce `GetOptions.MaxBytes` before
  buffering. Run `Repository.ProbeStoreCompatibility` before enabling a new
  backend and fail closed on every status other than `passed`. The probe uses
  random keys to exercise nil and versioned CAS, missing-key conditions,
  concurrent winner identity, bounded GET, ETag/read behavior, and input and
  returned-buffer non-aliasing; it may delete those keys through
  `ObjectDeleter`. A cleanup warning does not change the protocol verdict.
- The presigned-path probe is a finite application-level sample. Its observable
  responses are scanned for exact cross-canary payload/version and
  foreign-bearer authority values, but arbitrary encoding or transformation is
  outside that finite check. Go's `net/http` API does not expose every byte or
  metadata item received on the
  wire, including illegal bodies on HEAD/bodyless statuses, chunk extensions,
  and bytes beyond declared framing. Before a provider is commercially
  supported, a separate raw-wire HTTP/1.1 and HTTP/2 certification harness must
  test those cases; a passing library probe is not a confidentiality proof or
  a GA/support declaration.
- The combined commissioning probe uses one configured A-side `Store` identity
  for canary writes, credentialed read-backs, cleanup, and GET presigning. It
  does not prove that a distinct production writer and GetObject-only signing
  principal share the same bucket, origin, or route. A commercial deployment
  requiring that split needs independent IAM/routing evidence and a
  split-identity harness; the current combined report cannot replace it.
- Consumers retain a last-known-good snapshot during transient failures. A
  network partition prevents any unconditional guarantee of freshness.

## Root-publication recovery

`RootPublisherConfig.RecoveryJournal` is optional for pre-release API
compatibility, but a production publisher must provide a confidential,
authenticated, linearizable `SealedStateStore`. The recovery record binds the
repository, share, root and reference keys, fixed authorization expiry, root
bearer digest, encryption witness, and publication policy. Before the mutable
root is attempted, the journal durably records the exact raw Store target and
its S3 CAS precondition. With client encryption, `RootPublisher` encrypts once
and records that exact ciphertext; it does not recreate a URL or ciphertext
after restart.

Recovery reconciles process death after installing `Pending`, a lost S3 write
response, and an uncertain journal CAS by reloading the journal and observing
the exact root. A process with the matching identity, verifier, and closure but
no signer or presigner may settle an already recorded target, which avoids
depending on a live signing credential during that crash window. It cannot
construct a later target without both dependencies. The original absolute
authorization expiry is part of the identity and is also installed as the
Store-call context deadline. Recovery never extends a share and does not start
a new write after local expiry. A conditional write already in flight at the
deadline may still be committed remotely after local cancellation and remain
ambiguous; the exact pending WAL target is required to reconcile it.

The current committed journal rejects an older S3 root and a different
authenticated target at the same revision. It is not an independent freshness
oracle: coordinated restoration of both an older complete journal and its
matching S3 root is indistinguishable at this layer. Commercial deployments
whose rollback threat includes local state or backup administration need a
separately protected monotonic receipt, audit service, or equivalent anchor and
tested restore procedures. A local `FileSealedStateStore` is suitable only for
publishers sharing that protected local state and filesystem semantics; a
multi-host writer needs a separately certified distributed linearizable
implementation.

When both recovery and client encryption are configured, pass the raw,
unwrapped S3 Store. Known encryption wrappers advertise
`ClientEncryptionApplied` and are rejected to prevent double encryption. Go
cannot detect an opaque custom byte-transforming wrapper that hides that
marker, so every commercial byte-transforming encryption wrapper must preserve
it. The current `share publish` CLI still does not persist all share secrets or
attach this WAL; its `--state-dir` is not same-share crash recovery.

## Signed-reference trust model

Signed references are optional and use a namespace independent from unsigned
`refs`; a configured verifier never downgrades to unsigned state. The signed
payload binds repository ID, channel, generation, commit, and key ID. Provision
the `RepositoryID`, public keyring, and preferably a `TrustedCheckpoint` over a
channel independent of the S3 store.

A signed publisher requires both a signer and matching verifier plus a durable
`PublicationJournal`; it fails closed without that state. Publication is a
two-phase operation: the journal durably installs one `Pending` intent with the
exact signed bytes and S3 CAS precondition before the S3 write, then advances
`Committed` and clears `Pending` after the result is reconciled. On restart,
call `Publisher.RecoverPublication`; signed staging also recovers an existing
intent before creating a new one. Recovery replays the recorded bytes rather
than invoking the signer for a replacement operation.

Every publisher for one repository/channel must share a linearizable
`PublicationJournalStore`. `FilePublicationJournal` is suitable only when all
such publisher processes share the same protected local file on one host.
Separate local journals on multiple hosts are not mutually ordered and do not
guarantee monotonic publication or split-brain prevention. A multi-host writer
topology requires a separately certified distributed linearizable journal
backend. If no committed publisher anchor exists, an independently delivered
`TrustedCheckpoint` or explicit `AllowTrustOnFirstUse` is required. In
particular, an existing signed reference read from the same S3 trust domain
cannot bootstrap the publisher by itself. A brand-new channel uses explicit
TOFU for its first signed publication because there is no prior checkpoint.

A signed consumer separately requires durable `Watermarks`. The publisher
journal and consumer anti-rollback anchors represent different trust decisions
and must use distinct protected persistent stores and paths. Do not copy one
role's local state to bootstrap the other. `FilePublicationJournal` and
`FileWatermarkStore` use crash-safe replace and CAS, with cross-process file
locking on Linux, macOS, and Windows. Protected local trust-state constructors
fail closed with `ErrTrustStateUnsupported` on platforms whose native ACL model
has not been implemented and certified. Local Unix paths are canonicalized
once and revalidate every
ancestor on each operation, require state owners to be the effective UID or
root, reject untrusted writable directories, and sync newly created namespace
entries. Every non-sticky directory component, the final state directory, and
state/lock files remain strictly non-writable by group/other because current
path isolation cannot revoke a foreign process's previously opened directory
descriptor. A trusted sticky ancestor such as `/tmp` is the only writable
directory exception. Owner, identity, symlink, and ACL checks still apply to
every component. Darwin
additionally rejects every extended ACL on ancestors,
directories, locks, state, and temporary files using the already-open file
descriptor; a Darwin build without cgo returns `ErrTrustStateUnsupported`
instead of relying on mode bits that can hide an ACL writer. A visible state is
not returned until its parent-directory durability barrier succeeds. Windows
validates DACLs instead of emulated Unix mode bits, rejects reparse-point path components, and
uses write-through namespace moves. Do not assume cross-host correctness on NFS
or another network filesystem without certifying its lock, ACL, atomic-replace,
and durability semantics. Protect, back up, and namespace each journal or
watermark path by repository, channel, and role.

`AllowTrustOnFirstUse` is deliberately explicit. TOFU verifies the signature
but cannot distinguish the newest reference from a valid older signed reference
at first contact. Deleting trust state recreates that first-contact risk.

The built-in Ed25519 verifier is a direct, caller-managed keyring rather than a
threshold/offline-root design: any one configured key can authorize the current
reference. There is no signed key metadata, quorum, expiry, or revocation list.
For rotation, distribute an overlap keyring out of band, use
`ResignReference` to sign the unchanged current generation with the new key,
then remove the old key from every consumer. A compromised key remains trusted
by consumers that have not received the removal, and removing a key before the
current reference is re-signed can make that reference unavailable.

## Release security requirements

Every supported release must:

1. build with a currently supported, fully patched Go toolchain;
2. pass `govulncheck -scan=module`, unit tests, race tests, object-store
   integration tests, the required Linux FUSE E2E test, and the repository
   release gate;
3. ship the project license, notices, and third-party license texts;
4. produce an immutable versioned artifact and record its checksum, source
   revision, Go version, dependency graph, and build options;
5. document credential, cache, publication-journal/watermark/checkpoint,
   signing-key, bucket-retention, and incident-recovery procedures for
   operators.

The checked-in CI workflow covers native Go tests on Ubuntu, macOS, and Windows,
Linux quality checks, a dynamically port-bound pinned MinIO fixture, and model
checking. The commercial release workflow requires a disposable, isolated
Linux runner with `/dev/fuse`; candidate code must never receive a persistent
host Docker socket. Its candidate mode binds an unpublished version to an exact
clean commit; release mode additionally requires an annotated OpenPGP tag whose
signed internal name and target match the ref and whose primary fingerprint is
in a root-owned protected allowlist. The exact root-owned verifier executable
is pinned for the check. Both modes revalidate the reference after the full
gate and emit a hashed success manifest. Workflow configuration alone is not an
authorization root: production promotion must be driven by a separately
protected release controller and post-gate approval, with artifacts retained
for the exact version, commit, tree, signer identity, and controller revision.
