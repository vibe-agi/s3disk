# S3-only expiring sharing

This document defines the credential and network boundary for an expiring
share. It is a protocol requirement, not an optional deployment topology.

## Non-negotiable boundary

After B receives the initial share material, S3 is the only runtime medium
between publisher A and readers B/C/D. A reader never calls A, an authorization
broker, a callback endpoint, or another control-plane service. It does not need
network reachability to A.

The initial handoff is deliberately out of band. It contains the secret root
GET bearer, a random 256-bit client-encryption key for this share, and bindings
such as repository prefix, signed-reference key, share ID, `RepositoryID`,
publisher verification key configuration, and trusted checkpoint. It contains
no `SecretAccessKey`, credential provider, or reusable SigV4 signer, although
the root bearer can expose an access-key ID and temporary session token. The
entire handoff is secret material; the product embedding this library owns its
private authenticated delivery. Extending a share requires a new key, handoff,
and remount; it is not an in-band renewal protocol.

The data flow is:

1. A creates a dedicated random share prefix and encryption key, initializes a
   write-once repository descriptor after explicitly confirming that newly
   allocated namespace, binding its prefix, `RepositoryID`, storage profile, and
   Rabin chunking parameters. It then publishes the selected projection as
   encrypted immutable objects with keyed opaque physical IDs and advances its
   encrypted authenticated channel reference.
2. A resolves the exact object closure for that reference, creates exact-key
   presigned `GetObject` capabilities with one fixed absolute expiry, signs the
   capability bundle, encrypts it, durably journals the exact ciphertext target,
   and conditionally creates or replaces one mutable ciphertext root object in
   S3.
3. B polls the same root presigned URL with conditional `GET`, decrypts the root
   with the handed-off share key, and verifies its signature. The bundle
   contains only exact-key GET capabilities for the current closure.
4. B decrypts manifests through those S3 URLs and fetches and decrypts a file
   chunk only when a caller reads bytes intersecting that chunk.
5. A publishes later revisions by replacing the same encrypted S3 root object.
   B learns them through S3 polling; no direct A-to-B notification exists or is
   needed.

For the automatic A-side chain, pass the `Snapshot` returned by
`Publisher.PublishSelected` to
`RootPublisher.CreatePublishedSnapshot`. For continuous publication, call
`RootPublisher.UpdatePublishedSnapshot` from `WatchOptions.AfterPublished`.
That hook is acknowledged only after the root update succeeds; failure is
reported and the same generation is retried by reconciliation. The helper
re-resolves `signed-refs/v1` with the configured verifier and requires the
generation, commit, root digest, and publication time to equal the Publisher
result before it can mint any object capabilities.

A production library composition gives
`RootPublisherConfig.RecoveryJournal` a confidential, authenticated,
linearizable `SealedStateStore`. The pending record is installed before the
mutable S3 write and contains the exact raw Store bytes and CAS precondition,
so recovery never has to regenerate presigned URLs or encryption randomness. It
reconciles crashes and lost S3 or journal-CAS responses by reloading durable
state and reading the exact root. A recovery-only process with the matching
identity, verifier, and closure may settle that pending target without a signer
or presigner, but it needs both before it can create another root.

Before an application declares the rest of its A-side session state resumable,
it calls `RootPublisher.PrepareRecovery`. This persists a canonical Prepared
record (revision zero, no pending or committed root) without accessing S3. A
restart parses the originally exported bearer and uses `RestoreRootPublisher`,
which accepts that imported capability only after the existing sealed WAL has
matched the complete share identity, bearer digest, fixed expiry, trust root,
security flags, and client-encryption witness. It validates pending bytes and
signed references locally with an offline verifier before privately restoring
exact-GET provenance. It never creates an absent WAL or probes the root Store.
The ordinary constructor and bundle builders remain strict and reject imported
bearers.

B's built-in reader performs `GET` only. It does not issue `LIST`, `HEAD`,
`PUT`, `DELETE`, multipart, or bucket administration calls. It cannot broaden
an exact object path or change the signed HTTP method.

For a hostname endpoint, its private Go resolver may query the deployment's
configured DNS infrastructure. DNS observes the S3 hostname but not the bearer
path, query, headers, or object data. “S3-only” therefore means S3 is the only
application-data, authorization, and control-plane peer between A and B/C/D;
it is not a claim of literally zero non-S3 network egress. Such a profile would
need independently controlled or pinned name resolution and routing, which the
current Reader does not implement.

The safe B configuration accepts exactly the built-in
`*s3disk.Ed25519ReferenceVerifier`. It performs finite Ed25519 key lookup and
verification in process. A custom verifier is rejected before
`RepositoryID` or `Verify` can run. The explicitly named
`DangerouslyAllowCustomReferenceVerifier` escape hatch exists for non-sharing
integrations, but using it invalidates the S3-only claim: a custom method can
contact A or any other endpoint. The same default is enforced independently by
`presignedshare.Decode`, `presignedshare.Reader`, and `s3disk.Consumer`.
`DecodeOptions.DangerouslyAllowCustomReferenceVerifier` is the corresponding
low-level opt-out and has the same bearer-exfiltration risk because `Verify`
receives signed bundle bytes containing every exact capability.

## What “B has no S3 key” means

B does not receive `SecretAccessKey`, a reusable credential provider, or a
SigV4 signer. It therefore cannot mint a request for another key, method,
bucket, or expiry.

B does receive the separate client-side share key. That key decrypts and
authenticates ciphertext already obtainable through the exact S3 bearers; it
does not sign S3 requests, list a bucket, or grant access to another object.

A standard SigV4 presigned URL is itself a bearer secret. Its query string
normally reveals the non-secret access-key ID inside `X-Amz-Credential`; when A
uses temporary credentials it also normally contains an `X-Amz-Security-Token`.
Those fields are necessary for S3 to validate the bearer and cannot be hidden
from a holder of an ordinary presigned URL. They do not provide the secret
signing key, but the complete URL can be replayed for its exact operation until
it expires. Root links, bundle bodies, process memory, and diagnostics must
therefore be protected as secrets.

`presignedshare.Capability` redacts bearer material from ordinary formatting
and JSON. Export is possible only through the explicit `ExportBearer` method.
The built-in safe mint path is `s3store.PresignSession`; an unchecked custom
presigner requires APIs whose names begin with `Dangerously` and is outside the
built-in provider proof boundary.

## Client-side encryption boundary

The implemented commercial-target sharing profile is
`strict-share-isolation-v1`:

- `GenerateClientEncryptionKey` obtains a fresh random 256-bit key for every
  share. `NewClientEncryptionProfile` uses domain-separated HKDF-SHA256 with the
  `RepositoryID` to derive independent encryption and opaque-index masters.
- Every envelope carries a fresh random 16-byte HKDF salt that derives an
  independent AES-256 key, then AES-GCM uses a fresh random nonce. Authenticated
  associated data contains the salt, `RepositoryID`, and exact logical/store
  object key, including its prefix. Copying ciphertext to another key or prefix,
  or opening it under another repository identity, fails authentication.
  The fixed envelope overhead is 52 bytes: 8-byte format header, 16-byte salt,
  12-byte nonce, and 16-byte tag. Per-message key derivation prevents mutable
  root/reference replacements from accumulating under one AES-GCM key's
  2^32-message operational bound.
  Associated data does not bind bucket, account, origin, region, S3 version,
  expiry, `ShareID`, or the textual profile name; signed capabilities, IAM, TLS,
  and provider commissioning enforce those separate boundaries.
- HMAC-SHA256 over the immutable object kind and logical plaintext digest
  produces its opaque physical ID. The root, mutable signed reference,
  manifests, and chunks are ciphertext in S3; protocol namespaces, object
  kinds, counts, and access timing remain observable. The unpadded envelope has
  fixed 52-byte overhead, so ciphertext size reveals the exact protected body
  length.
- Stable HMAC IDs preserve lazy loading and S3 deduplication only within one
  share. Every independent share uses a different random key and dedicated
  prefix, so cross-share ciphertext and physical IDs are not reused at S3.
  Encryption keys are not derived from plaintext; convergent encryption is
  forbidden. The HMAC input does not contain prefix or `ShareID`, and the
  constructors cannot enforce per-share key/profile uniqueness. Reusing one
  profile across prefixes would repeat opaque suffixes and reveal equality.

The profile must be configured consistently on A's `Repository` and
`RootPublisher` and on B's `Reader` and read-only `Repository`. Treat the
prefix, `RepositoryID`, profile, and share key as one inseparable storage
domain. Do not use one prefix for plaintext and encrypted modes, point a
different profile at it, or combine objects from different prefixes/profiles.
On A, `InitializeRepository` creates or exactly reopens a write-once
`RepositoryDescriptor` containing the normalized prefix, `RepositoryID`, storage
profile, and Rabin chunking algorithm and parameters. Descriptor-backed
publishers inherit the stored chunking defaults and reject different parameters
or a signer for another repository. A missing descriptor fails closed after its
bounded read by default: `InitializeRepository` performs no write unless the
caller explicitly sets `RepositoryInitializationOptions.ConfirmEmptyPrefix`.
The Store interface
cannot verify that assertion because this protocol neither requires nor grants
`LIST`; allocate and independently validate a fresh namespace before setting it.
The `share publish` CLI does so with its random per-share prefix.
`NewPublisher` also rejects an uncommissioned repository by default with
`ErrRepositoryNotInitialized`; the explicitly dangerous legacy opt-out is not a
commercial sharing mode.
Resolved closures contain an internal keyed profile binding, so
`RootPublisher` rejects an unencrypted, encrypted, or wrong-key Repository
mismatch before presigning or writing a root. Writable Repository construction
also refuses external self-reported encryption boundaries. The current AEAD
fails closed when the key, repository identity, or exact object key is wrong.

The descriptor is not yet included in the signed root bundle or its capability
closure. B therefore receives no exact-GET descriptor capability and continues
to construct its read-only repository from the authenticated handoff and signed
root; the descriptor is an A-side commissioning guard, not B-side trust
evidence. Low-level repository constructors can still represent legacy or
read-only storage, but cannot silently create a Publisher without the dangerous
opt-out. The descriptor binds a storage-profile name but does not prove that a
key/profile is unique to one share, nor does it bind `ShareID`, bucket, account,
origin, region, S3 version, or expiry.

S3 credential compromise does not become harmless. Within its IAM scope an
attacker can list opaque keys if allowed, download ciphertext, overwrite or
delete it, cause denial of service, and observe sizes and timing. AEAD, hashes,
signatures, and watermarks detect corruption or rollback; they cannot restore
availability. Without the share key the attacker cannot decrypt object bodies
through this profile. If the share key or private handoff leaks,
confidentiality of that share is lost for ciphertext the attacker can obtain,
and plaintext already read or copied cannot be revoked.

`DiskCache` receives data after decryption and keys it by logical chunk digest;
it is neither encrypted nor bound to a share, profile, or `RepositoryID`. Give
every share a separate private cache directory. Reusing a directory permits
local cross-share plaintext equality and cache hits even though S3 objects are
isolated. Protect and erase it as customer data. Enforce SSE-S3 or SSE-KMS as
defense in depth for server-side media, backups, and operations; SSE does not
replace the client-side profile. Repository-level KEK and repository-dedup
modes, key rotation, migration, and descriptor inclusion in signed root bundles
are not implemented yet.

## Fixed expiry and mount lifecycle

The root URL and every object capability in all revisions of one share use the
same absolute authorization deadline. At the library level, a product that has
securely persisted all required A-side share key, signing key, root capability,
namespace, and deadline material can create a later presigning session only for
that original deadline. `PrepareRecovery` binds the original bearer before the
application commits its session manifest, and `RestoreRootPublisher` requires
that exact sealed binding before accepting the imported bearer.
`RootPublisher` uses the same deadline for root Store calls. An existing exact
pending target can be recovered without signing again, but recovery cannot renew
or extend the share and does not initiate a new write after local expiry.
A conditional write already in flight at the boundary may still commit remotely
after cancellation and remain ambiguous; recovery uses the exact pending WAL
target to reconcile it. The current CLI does not persist enough of those
secrets or attach the root recovery journal and has no same-share resume
command; restarting `share publish` creates a new share and handoff. The root
URL handed to B never changes during one share.

After the deadline, `presignedshare.Reader` refuses reads locally without
network I/O. A mount pins the reader's deadline when it starts and initiates a
bounded automatic unmount at expiry. Physical unmount is best effort because
an operating-system FUSE unmount can block or fail. Expiry is therefore a
lifecycle and authorization boundary, not DRM: it cannot erase bytes already
read by an application or retained in an enabled plaintext disk cache, revoke a
leaked share key, or make captured ciphertext undecryptable to its holder.

A new authorization period requires a new random share key, newly presigned
root capability, private handoff, and mount. There is intentionally no refresh-
token, broker callback, or publisher connection.

The key is per share, not per recipient. B/C/D given the same handoff have the
same symmetric key and bearer authority; the system cannot attribute their
reads or revoke only one of them, and any holder can copy the handoff. Create a
separate share, prefix, random key, root, and handoff whenever recipients need
independent attribution or revocation.

## Consistency and failure model

The safety argument depends on the commissioned S3 endpoint providing atomic,
linearizable operations for each object key and correct `If-None-Match` and
`If-Match` behavior. Immutable objects retain SHA-256 logical digests for
integrity but use share-keyed HMAC-SHA256 physical IDs; AES-GCM additionally
binds every ciphertext to its repository identity and exact object key. The
authenticated channel reference, signed root bundle, generation, commit, share
ID, exact repository bindings, and durable consumer watermark prevent mixing,
rollback, and same-generation split brain.

`Reader`'s accepted root revision is process-local; it is not by itself a
cross-restart rollback journal. The commercial mount composition therefore
requires `Consumer` with a protected durable `FileWatermarkStore` and an
out-of-band trusted checkpoint. After restart, a fresh Reader uses the same
fixed root bearer to fetch the current S3 root, while Consumer verifies the
durable generation/commit ancestry before exposing a view. Replaying an older
valid root can make recovery fail closed, but cannot make that composition
activate a generation below its watermark. Applications using `Reader`
directly must not claim this cross-restart property.

An A-side root update uses S3 conditional replacement. With a recovery journal,
A first installs a pending record containing the exact raw target (the exact
ciphertext under `strict-share-isolation-v1`). If a write response is lost, A
reads the exact root key back: exact target bytes mean the operation was
applied; another authenticated value is handled as a concurrent state; an
unreadable or ambiguous observation fails closed. Journal CAS response loss is
likewise reconciled by loading and matching the exact durable record. A missing
root during an update is treated as rollback and is never silently recreated.

The journal's committed anchor rejects an older root or a different valid root
at the same revision. It cannot detect coordinated replay of both the complete
journal and the matching old S3 root; deployments with that threat require a
separately protected monotonic receipt, audit service, or equivalent anchor.
With client encryption, `RootPublisher` requires the raw unwrapped Store so it
can encrypt once and journal the exact ciphertext. Known wrappers advertise the
`ClientEncryptionApplied` marker; Go cannot detect an opaque custom wrapper that
transforms bytes without preserving it.

`RootPublisherRecovery.tla` starts after a Prepared record is already durable,
then checks Prepared-to-pending/committed ordering, crash-time loss of volatile
bearer provenance, validated imported-bearer admission without storage effects,
one rejected attempt without authority, absence of local root writes before
admission, lost-response paths, competitor CAS, replay rejection, fixed expiry,
and conditional recovery liveness. A later admission action represents a new
matching input, never reclassification of the rejected input. Prepared-file
installation/CAS faults, URL parsing, bearer-digest and encryption-witness
validation are refined by the Go fault tests rather than multiplied into the
finite model. The model assumes the latest complete journal is present after
restart; whole-journal rollback, torn storage below the `SealedStateStore`
contract, and disaster recovery remain outside the model.

No asynchronous algorithm can guarantee current data during an arbitrary
network partition. The contract is instead:

- safety: B keeps one coherent last-known-good snapshot and never fabricates a
  mixture of revisions, regardless of delay, loss, duplication, or reordering;
- monotonicity: a process and its durable watermark never accept a lower
  generation, and conflicting commits at one generation fail closed;
- conditional liveness: if A finishes publishing, S3 remains reachable and
  linearizable, B keeps polling, and authorization has not expired, B
  eventually observes the newer root and converges;
- no bounded freshness claim is made while the network or S3 is unavailable.

The executable model for these assumptions and properties is described in
[`../spec/README.md`](../spec/README.md).

## Commissioning an S3 implementation

“S3 compatible” is not sufficient evidence. Commission both semantic contracts
against the exact endpoint, bucket, addressing mode, A-side gateway path, and
encryption policy used in production, and bind the intended provider version
and non-secret identity inventory independently. The B-side built-in reader is
deliberately direct and rejects forward proxies, custom dialers, and alternate-
protocol transports:

```go
report, err := writerStore.ProbeCommissioningWithPresigningStore(ctx,
	presigningStore,
	s3store.S3CommissioningProbeOptions{
		RepositoryPrefix:      "private/commissioning",
		DeploymentFingerprint: deploymentFingerprint,
		EvidenceID:             "commissioning-20260718-001",
		ImplementationVersion:  "commercial-build+17",
		PresignedGet: s3store.PresignedGetCompatibilityProbeOptions{
			TLSRootCAPEM: commissionedTLSRoots, // required for every HTTPS origin
		},
	})
if err != nil {
	return err
}
if !report.Compatible || !report.Complete {
	return errors.New("S3 commissioning did not pass")
}
```

The combined envelope preserves separate `passed`, `failed`, or `not_run`
outcomes for the 31-check writable Store phase and 14-check presigned-GET phase.
An omitted presigned prefix is derived as
`<repository-prefix>/.s3disk/v1/probes/presigned-get` and must remain below the
same normalized repository namespace; the combined route grammar is bounded
canonical ASCII rather than the core Repository's full UTF-8 prefix space.
The parent timeout, writable-phase timeout, and both nested cleanup windows are
independently bounded. Cleanup warnings do not change the compatibility
verdict. Prefix fingerprints, run identity, timestamps, and caller declarations
bind audit metadata but do not sign it; an independent controller must verify
and seal the complete report.

The default combined call uses one configured Store. The split form,
`Store.ProbeCommissioningWithPresigningStore`, keeps every canary mutation,
credentialed read-back, and cleanup on the writer while using the second Store
only for exact GET presigning. A successful split run records a separate-Store
topology and cross-configuration canary binding. The MinIO integration test
uses a distinct `GetObject`-only user and verifies PUT, DELETE, and LIST denial.
This finite evidence does not prove credential identity or the complete IAM,
BPA, bucket, origin, and routing graph, so commercial certification still
requires an independent provider review and archived policy evidence. The CLI
doctor currently runs the same-Store form.

The writable phase checks conditional create/replacement, concurrency,
visibility, ETags, conditional GET, bounded reads, and adapter ownership. The
presigned phase currently has 14 stable checks; `RequiredChecks` in the report
is authoritative. They cover independently readable source and target bearers,
a same-context shorter source control, reuse of one URL after replacement,
dynamic `If-None-Match`, an expiry-query mutation, unsigned source/target GET
and source zero/nonempty PUT/DELETE policy controls, eleven named unsigned
method/path override headers, exact-path and HEAD mutations, and signed
zero/nonempty PUT mutations. Full bytes plus ETag/Version ID read-backs and
correct bearer revalidations cover both canaries around the negative families.
Observable bounded bodies, status, headers, and trailers are checked for
cross-canary payload/version disclosure and exact authority unique to the other
bearer (raw URL, signature, capability-header values, and an absent foreign
path/key). Informational 1xx or encoded negative responses cannot pass.

These are named samples, not proof of arbitrary query, header, method, payload,
historical-version, public-policy, bucket, or origin binding. The same-Store
form does not fabricate a distinct host. The split form samples two configured
routes against the same exact canaries but does not authenticate their
provider-side mapping or credential identities. Go's HTTP client also cannot
expose illegal bodies on HEAD/bodyless statuses, chunk extensions, or bytes
beyond declared framing. The report retains all of those limitations, plus
post-expiry and future provider/network states. Stable check IDs and redacted
reason classes let an operator distinguish semantic incompatibility from
permission, endpoint, throttling, timeout, and network failures.

These are finite black-box probes. A pass can disprove observed
incompatibilities but cannot mathematically prove every future provider,
gateway, partition, policy, or upgrade state. The short probe also does not
wait until the bearer expires; production certification must separately sample
post-expiry rejection and repeat tests after material backend changes.

## Current scaling boundaries

The current root is one flat signed bundle, limited to 65,536 exact
capabilities and 64 MiB encoded bytes. Every accepted revision must preserve
the exact capabilities required by older open handles. The reader retains the
deduplicated union within explicit count and byte budgets; if accepting a new
revision would exceed a budget, it keeps the current coherent view and rejects
that revision rather than silently breaking an old handle.

This behavior is safe but means a high-churn, long-lived share can stop
advancing before expiry and require a remount. A sharded capability index is a
future scale feature and must preserve the same exact-key, fixed-expiry, signed
closure, and S3-only constraints.

## Deployment checklist

- Deliver the root bearer, random share key, share bindings, verification trust,
  and initial checkpoint through a private authenticated out-of-band product
  flow. Treat the complete handoff as a secret.
- Give S3 credentials only to A. Do not construct a credentialed `s3store.Store`
  on B; build B's repository with `presignedshare.Reader` and
  `s3disk.NewReadOnlyRepositoryWithOptions`, using the same client-encryption
  profile at both decryption boundaries. The current root closure does not grant
  B descriptor GET authority, so do not replace this with
  `OpenReadOnlyRepository` until the signed protocol explicitly carries that
  capability and binding.
- On A, initialize the dedicated prefix with `InitializeRepository` before the
  first publication, setting `ConfirmEmptyPrefix` only after independently
  allocating and checking a fresh namespace. Require later opens to match its
  `RepositoryID`, storage profile, and chunking parameters exactly. Never enable
  `DangerouslyAllowUncommissionedRepository` in the commercial path. The built-in
  `share publish` CLI performs the confirmed initialization for its random
  per-share prefix.
- Give every share a dedicated random prefix, `RepositoryID`, and encryption
  key. Never reuse a prefix across plaintext/encrypted modes or different
  profiles. Do not claim repository-level rotation, migration, or deduplication
  until those missing facilities are implemented and certified.
- Use HTTPS with certificate verification. Literal loopback HTTP exists only
  for local MinIO tests. B's reader constructs an internal direct transport;
  environment/application proxies, custom dialers, redirects, cookies, custom
  TLS callbacks, caller certificate pools, client certificates, insecure or
  caller-selected TLS algorithms, and alternate-protocol round trippers are
  rejected. Caller `httptrace` values are stripped before a capability request
  reaches `net/http`. Every HTTPS deployment provides bounded commissioned PEM
  roots in `ReaderConfig.TLSRootCAPEM`; Reader parses fresh certificate objects
  into an internal callback-free pool. This avoids operating-system trust
  evaluation that may perform non-S3 network fetches.
  `DangerouslyAllowSystemTrustStore` explicitly gives up the strict S3-only
  guarantee and must not be enabled on B/C/D. Those roots are trusted
  configuration and a malicious root can authenticate an S3 impersonator.
- Prefer two A-side principals against the same commissioned bucket and
  endpoint: a writer for immutable publication and root CAS, and a separate
  `s3:GetObject`-only principal used only to construct `PresignSession`. This
  limits damage if a gateway ever mishandles HTTP-method binding. The library's
  abstract Store/Presigner interfaces cannot prove that both configurations
  target the same bucket and origin, so deployment tests and policy review must
  enforce that binding. For a commercially supported backend, the separate
  GetObject-only principal, its one-bucket/key-scope restriction, and the exact
  origin binding are hard gates, not recommendations.
- Keep the bucket private and archive a review of BPA or the provider's
  equivalent, bucket/access-point policies, ACLs, IAM, and gateway/origin
  public-access rules. The finite probe's unsigned GET/PUT/DELETE samples do
  not prove the full policy graph or exclude an alternate public origin.
- Require separate raw-wire HTTP/1.1 and HTTP/2 provider certification. Go's
  `net/http` cannot expose every illegal body on HEAD/bodyless statuses, chunk
  extension, or byte beyond declared framing, so an application-level probe
  pass alone is not a confidentiality or commercial-support result.
- Keep A's signed-reference publication journal, A's sealed root recovery WAL,
  and B's watermark in separate protected durable storage. Neither is
  bootstrapped from an untrusted S3 object. Back `RootPublisher` with a
  linearizable `SealedStateStore`, and add an external monotonic anchor if
  coordinated journal-plus-S3 rollback is in scope. The current CLI does not
  persist the client key, publisher private signing key, or root capability
  needed to resume the same share; define secure persistence, recovery, backup,
  rotation, and zeroization before certifying CLI resume.
- Protect the handoff, share key, bearer URLs, and cached plaintext from logs,
  command lines, crash reports, telemetry, and other local users. `DiskCache`
  is plaintext even though its S3 source objects are ciphertext; allocate a
  distinct private cache directory for every `RepositoryID` and `ShareID`.
- Enforce and test SSE-S3 or SSE-KMS as defense in depth; it does not replace
  client-side encryption or private handoff delivery.
- Set S3 lifecycle and retention rules so immutable objects cannot disappear
  during the maximum supported share and recovery windows.
- Run the combined commissioning probe and the partition/timeout/expiry/provider
  matrix before claiming a commercial backend is supported. Archive and
  independently seal its unsigned envelope, and treat cleanup attention as an
  operational gate rather than rewriting the semantic verdict.
