# Commercial release gate

This checklist is deliberately fail-closed. “The tests pass” is not sufficient
for a storage component that handles customer source data.

## Current blockers

<!-- RELEASE-BLOCKER: stable-api-support-policy -->

- There is no tagged stable API, compatibility promise, support window, or
  customer migration policy.

<!-- RELEASE-BLOCKER: prepublication-release-promotion -->

- The code now has an unpublished-candidate mode that binds a requested SemVer
  to the full selected-branch commit, rejects an existing release tag, runs the
  complete gate, and rechecks that binding at the end. The blocker remains
  until a separately controlled release workflow runs the gate from a reviewed
  controller revision, the `commercial-release-promotion` environment is
  configured as described below, and a successful candidate artifact has been
  approved and archived. A workflow and checker loaded from the candidate
  commit cannot be their own authorization root. A failed tag-triggered
  run cannot retract a Go module version already seen by a proxy, so the local
  signed-tag gate must pass before the tag is pushed; the tag workflow remains
  post-publication verification.

<!-- RELEASE-BLOCKER: authorized-release-signer -->

- Release mode now accepts only an OpenPGP-signed annotated tag and compares the
  `VALIDSIG` primary-key fingerprint with a canonical protected allowlist. It
  archives both the selected identity and raw machine-readable verification
  status. The blocker remains until the release owner provisions and approves
  the actual primary fingerprint(s), public-key lifecycle, protected runner
  path, rotation procedure, and archived evidence. Merely trusting a key in the
  runner keyring is not release authorization. The allowlist and the exact
  OpenPGP verifier executable must be root-owned below root-owned,
  non-group/world-writable ancestors, while the gate itself must run as a
  non-root user.

<!-- RELEASE-BLOCKER: atomic-source-snapshot -->

- Source-tree scanning is traversal-confined with `os.Root` and retries when
  inode, size, mode, or mtime changes, but these metadata checks are not a
  transaction. A writer or coarse-timestamp filesystem can change file bytes
  and restore the observed metadata, and the whole directory is likewise not
  atomic. Strict single-file and cross-file snapshots require a quiesced
  producer protocol or an OS/filesystem snapshot/version primitive.

<!-- RELEASE-BLOCKER: repository-retention -->

- Immutable repository objects have no garbage collector or retention
  coordinator and can grow without bound. `DiskCache` is now separately bounded
  by bytes, per-chunk size, and entry count with LRU eviction.

<!-- RELEASE-BLOCKER: repository-profile-encryption -->

- The `strict-share-isolation-v1` profile now provides per-share client-side
  encryption, opaque immutable object IDs, and encrypted roots, references,
  manifests, and chunks while retaining lazy reads and within-share
  deduplication. `InitializeRepository` now installs a write-once descriptor
  binding the normalized prefix, `RepositoryID`, storage profile, and Rabin
  chunking algorithm and parameters; identical initialization is idempotent,
  conflicting configuration fails closed, and descriptor creation requires an
  explicit `ConfirmEmptyPrefix` assertion. `NewPublisher` rejects an
  uncommissioned repository by default; the only bypass is the explicitly
  dangerous legacy option. The A-side `share publish` CLI allocates a fresh
  random share namespace, confirms it for initialization, and uses this safe
  path. This narrows but does not close the blocker. The Store interface cannot
  prove a legacy prefix is empty, so an operator must never assert
  `ConfirmEmptyPrefix` for an existing namespace without an independent
  inventory and migration decision. The descriptor is not yet included in the
  signed share-root bundle or its exact capability closure, so B does not fetch
  or authenticate it as part of root adoption.
  There is no repository-level KEK or repository-dedup mode and no certified key
  rotation or migration path. The local `DiskCache` also remains plaintext. The
  `publisherstate` now provides an independently keyed, bounded AES-256-GCM
  envelope for protecting those recovery secrets, but it intentionally does
  not provide storage freshness or rollback detection. Its bounded built-in
  keyring can authenticate retained-key envelopes and rewrap them with an
  active key, but does not install that result. The current CLI does not yet
  persist the share key, publisher private signing key, or root capability
  through that envelope and cannot resume the same share after A crashes;
  durable CAS state, recovery-key provisioning and rotation operations,
  backup, and zeroization remain product work.

<!-- RELEASE-BLOCKER: trust-root-lifecycle -->

- Optional signed references authenticate the selected commit, but the built-in
  verifier is a direct single-signature keyring rather than threshold/offline
  root metadata. First-checkpoint delivery, explicit TOFU risk, expiry,
  revocation, and recovery after trust-state loss need a product policy.

<!-- RELEASE-BLOCKER: platform-release-evidence -->

- A Linux `/dev/fuse` E2E test is now mandatory in the release gate, but it has
  not yet produced archived evidence for a release candidate on every supported
  kernel/distribution/architecture. An ad hoc ARM64 Raspberry Pi 5 run on Linux
  `7.0.0-1011-raspi` passed core, low-FD traversal, MinIO, actual FUSE refresh,
  old-handle `fstat`, type-change, deletion, and missing-to-present tests on
  2026-07-18; that is useful regression evidence, not per-tag certification.
  The gate also verifies refreshed reads, not guaranteed inotify/VS Code
  watcher events. macOS and Windows still lack commercially distributable
  native adapters.

<!-- RELEASE-BLOCKER: backend-fault-certification -->

- MinIO exercises the S3 adapter, but no production provider/version matrix has
  completed both the writable Store and anonymous presigned-GET compatibility
  probes plus partition, timeout-after-write, throttling, credential-expiry,
  bearer post-expiry rejection, stale-read, lifecycle-deletion, and recovery
  certification described below.

<!-- RELEASE-BLOCKER: s3-only-share-scale -->

- The S3-only reader has a flat root-bundle limit of 65,536 exact capabilities
  and 64 MiB. It preserves old-handle lazy reads by retaining a bounded,
  deduplicated union of prior capabilities; high churn can therefore make a
  mount reject later revisions until remount. Supported share size, churn, and
  duration limits have not yet been measured and published. A sharded
  capability index is not implemented.

<!-- RELEASE-BLOCKER: root-revision-durable-anchor -->

- `RootPublisher` authenticates and conditionally updates the current S3 root,
  but it does not yet persist an A-side last-issued root revision in a protected
  durable journal. A replayed, otherwise valid root after A restarts therefore
  fails closed or can be repaired from a newer snapshot, but some valid-replay
  orderings can cause denial of service and do not have a durable local
  monotonic root-revision proof. Commercial multi-process/restart certification
  requires a linearizable root-revision anchor plus replay and lost-response
  recovery tests.

<!-- RELEASE-BLOCKER: supply-chain-evidence-archive -->

- The workflows produce test artifacts, but there is no approved long-lived
  evidence archive containing dependency sources, SBOMs, vulnerability inputs,
  MinIO image provenance/scan results, signed build provenance, native test
  records, and artifact hashes. GitHub Actions retention alone is not the
  commercial evidence-retention policy.

<!-- RELEASE-BLOCKER: independent-release-controller -->

- The checked-in workflow still executes scripts from the candidate checkout.
  Before it can authorize a commercial tag, move orchestration, reference
  verification, evidence sealing, and promotion into a separately protected
  release-control repository or equivalent immutable controller. It must pull
  the product commit by digest into a disposable isolated worker; candidate
  code must not be able to rewrite the gate, trust policy, or final evidence.

<!-- RELEASE-BLOCKER: production-scale-watch-stress -->

- Supported directory/file/change-rate limits have not been established with
  cold-cache, watcher-overflow, concurrent-reader, memory, request-rate, latency,
  and cost measurements. VS Code/inotify behavior and forced process
  termination/restart have not been certified at those limits. Each adopted
  generation currently invalidates every materialized inode, including
  unchanged content, so large-tree inode churn and notification rate remain an
  explicit scale-certification item.

<!-- RELEASE-BLOCKER: disaster-recovery-operations -->

- A tested backup, restore, versioning, retention, replication, and disaster
  recovery procedure for mutable references, immutable objects, publisher
  journals, consumer watermarks, and lost local trust state has not been
  approved.

These are product decisions, not documentation defects. A release owner must
accept or resolve each one explicitly.

## Legal and dependency review

1. Preserve records for the individuals or legal entities represented by
   `The s3disk Authors` and verify the contributor/employment assignment chain.
2. The approved project license is Apache-2.0. Keep the root `LICENSE` equal to
   the approved text, retain the project and upstream attributions in `NOTICE`,
   and require the contribution terms documented in `CONTRIBUTING.md`. Review
   any future license or copyright-attribution change before publication; an
   already granted Apache-2.0 license is not retroactively withdrawn.
3. Run `./scripts/check-third-party.sh`. Review every dependency change and
   regenerate `third_party/modules.txt`, notices, and license texts before merge.
4. Include `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, and
   `third_party/licenses/` in every source archive, binary package, installer,
   container image, and customer attribution bundle where applicable.
5. Do not ship the MinIO test image. MinIO is AGPL-3.0 and is pulled only for
   isolated integration tests. Production use, modification, or redistribution
   needs a separate legal decision. See MinIO's [upstream license and current
   distribution notice](https://github.com/minio/minio).
6. Do not bundle or automatically install macFUSE with a commercial product
   without specific written permission from its licensor.

## Engineering evidence

- Use a fresh disposable VM/JIT runner from a reviewed release-runner image
  containing Go, POSIX shell tools, coreutils, `jq`, ripgrep, `govulncheck`,
  rootless Docker with Compose v2, Java, curl, and `shasum`.
  Pin and inventory that image; do not install unpinned tools during a release.
  Never reuse the worker or give candidate code a host/shared Docker socket.
  Start the fixture with an isolated rootless daemon or an external trusted
  fixture controller and destroy the worker after evidence export.
- The checked-in scanner baseline is `govulncheck v1.6.0`. Its vulnerability
  database is retrieved at scan time; archive the scanner and database metadata
  printed by the gate with the release evidence.
- Pin a currently supported Go toolchain at its latest security patch. The
  current baseline is `go1.26.5`; update the checked-in gate after every Go
  security release rather than overriding it in the environment. Release jobs
  set `GOTOOLCHAIN=local` and assert the installed version before executing
  candidate Go commands, so a candidate `go.mod` cannot trigger an automatic
  toolchain download.
- Run `./scripts/check-release.sh`. Do not waive a vulnerability, race,
  integration, formal-model, dependency, or cross-build failure without a
  dated, owner-approved risk record.
- Run `./scripts/test-release-ref.sh` whenever the Git, GnuPG, shell, or release
  runner baseline changes. It exercises candidate digest binding, SemVer
  rejection, signed-tag validation, unauthorized fingerprints, unsafe
  allowlist/verifier permissions, symlinks, signed-tag internal-name replay,
  build-metadata aliases, and ambiguous tags with a disposable key and
  repository. The permission self-test uses a deliberately modified private
  checker copy because the production entry point has no non-root-owned trust
  downgrade. Third-party enumeration covers both `CGO_ENABLED=0` and `1` for
  every declared build target so native cgo-only imports cannot silently bypass
  the attribution inventory.
- Run `Repository.ProbeStoreCompatibilityWithOptions` with a commissioning
  identity for every advertised backend/version/endpoint mode, then run the
  longer failure suite. Require a caller deployment/config fingerprint,
  evidence ID, and implementation version; reject an archived report unless
  `fully_bound` is true and an independent controller has recomputed those
  bindings and tamper-evidently sealed the report. The hashes are not
  signatures and do not discover credential identity or server version.
  Archive the JSON-safe report and treat `configuration_error`,
  `permission_denied`, or `indeterminate` as “not certified,” not as proof of
  provider incompatibility.
  The commissioning probe covers nil-expected CAS, missing-key `If-Match`, one-
  winner concurrent create and replacement, winner identity, ETag-only CAS,
  `GetOptions.MaxBytes`, immediate HEAD/GET visibility, current/stale conditional
  GET, and adapter input/output-buffer ownership. Also test concurrent
  publishers, stale and reordered reads,
  timeouts after ambiguous writes, corrupted/truncated objects, expired
  credentials, throttling, lifecycle deletion, and recovery after partitions.
  Grant probe cleanup delete access only where its operational policy permits
  it.
- Run `Store.ProbePresignedGetCompatibilityWithOptions` against the same exact
  endpoint path with `TLSRootCAPEM`. Require the report's current 14 stable
  checks (`RequiredChecks` is authoritative): two independently readable exact
  GET bearers, same fixed URL observing root replacement, current/stale ETag
  behavior, a same-signing-context expiry-query mutation, unsigned
  source/target GET and source zero/nonempty PUT/DELETE policy controls, every
  one of the eleven named method/path override-header controls, exact-path and
  HEAD binding, and signed zero/nonempty PUT rejection. Require full bytes plus
  ETag/Version ID read-backs and correct-bearer revalidations covering both
  canaries around negative families, with observable cross-canary
  payload/version and cross-bearer authority disclosure checks.
  Archive the redacted structured report and every limitation. These named
  samples do not prove arbitrary query/header/method/payload or historical-
  version denial, the complete BPA/IAM policy graph, bucket/origin binding,
  post-expiry rejection, future states, or wire bytes hidden by `net/http`.
  Separately test real service-side rejection after expiry because the bounded
  probe deliberately does not wait out the capability lifetime.
- Fail the commercial backend gate unless the presigning credential is a
  separately reviewed `GetObject`-only principal restricted to the one
  commissioned bucket/key scope and the exact production origin. It must have
  no PUT, DELETE, LIST, or bucket-administration authority. The library cannot
  derive this fact from a bearer URL or prove that the writer and signer target
  the same bucket/origin.
- Fail the gate without an archived BPA/IAM/public-access review covering the
  bucket, access points, ACLs, principal and resource policies, gateway/origin
  rules, and provider equivalents. Unsigned canary GET/PUT/DELETE denial is a
  finite control sample, not a proof of the complete policy graph or alternate
  endpoints.
- Fail the gate without separate raw-wire HTTP/1.1 and HTTP/2 provider
  certification for illegal bodies on HEAD/bodyless statuses, chunk
  extensions, bytes beyond declared framing, and cross-canary/bearer leakage.
  Go's `net/http` does not expose all of that wire state, so a passing
  application-level probe cannot waive this requirement.
- Exercise the full S3-only path with B constructed from `presignedshare.Reader`
  and `NewReadOnlyRepositoryWithOptions`, with no credential provider or
  writable Store: private root/key handoff, selected projection, metadata
  refresh while a chunk is absent, lazy chunk read, same-root update, network
  partition, restart watermark, fixed expiry, and automatic unmount. Network
  traces must show that B contacts only the commissioned S3 origin and issues
  GET only.
- Require `strict-share-isolation-v1` on the commercial-target share path. Test
  a fresh random 256-bit key and dedicated prefix per share, domain-separated
  HKDF-SHA256, random per-message salt and GCM nonce, exact-key associated-data
  binding, and HMAC-SHA256 opaque immutable IDs. Raw credentialed S3 reads of
  the root, signed reference, manifests, and chunks must expose ciphertext only;
  unsupported handoff profiles must be rejected, while a wrong share key,
  `RepositoryID`, exact key, or prefix must fail closed. Verify lazy reads and
  deduplication within one share, no cross-share object-ID/ciphertext reuse, and
  no plaintext-derived encryption key. Archive evidence that the B handoff
  contains the share key but no `SecretAccessKey`, credential provider, or
  reusable signer; account for the access-key ID and temporary session token
  that a bearer URL can expose.
- Require A to create or exactly reopen the repository through
  `InitializeRepository`. Test descriptor idempotence, concurrent initialization,
  conflicting repository ID/profile/chunking rejection, encrypted raw storage,
  wrong-key failure, and reconciliation after a lost `PutIfAbsent` response.
  When the descriptor is absent, require `ConfirmEmptyPrefix=false` to return
  `ErrRepositoryNotInitialized` with zero writes, and permit true only for a
  separately allocated and inventoried empty namespace. Test that
  `NewPublisher` rejects an uncommissioned repository by default and that the
  dangerous legacy opt-out is never selected by the commercial CLI or product
  configuration.
  Until the descriptor is cryptographically included in the signed root bundle,
  archive evidence that B neither receives nor requests a descriptor capability
  and instead binds its read-only repository to the authenticated handoff and
  signed root. Do not present the A-side descriptor as B-side trust evidence.
- Require an independent cryptographic design review plus stable envelope test
  vectors, cross-version decode evidence, fuzzing, randomness-failure tests,
  and key-lifecycle/zeroization review. The consistency TLA+ model does not
  model HKDF, HMAC, AES-GCM, CSPRNG failure, key compromise, side channels, or
  confidentiality and must not be treated as a cryptographic proof.
- Keep the MinIO Compose reference pinned to a reviewed manifest-list digest.
  The gate additionally pins the complete fixture bytes, checks the resolved
  Compose JSON against an exact field/value allowlist, rejects API-socket,
  provider and `env_file` injection regressions, and starts a private copied
  fixture which is rechecked afterward. This still relies on the independent
  disposable release controller to exclude same-UID background-process races.
  The image digest makes the fixture reproducible but is not by itself a
  security review; record its SBOM, provenance, platform manifests, and
  vulnerability result in CI. The fixture publishes MinIO on an OS-selected
  loopback port; keep that dynamic binding so parallel test jobs do not contend
  for a hard-coded port.
- Preserve artifacts from the native Ubuntu/macOS/Windows tests, Linux
  unit/race/vet/compliance job, MinIO integration, and TLA+ jobs configured in
  `.github/workflows/ci.yml`. Preserve the full gate artifacts produced by
  `.github/workflows/release-linux.yml` on the reviewed owner-controlled
  `/dev/fuse` runner. Workflow presence or a green unrelated revision is not
  release evidence.
- Preserve the mandatory `scripts/test-mount-linux.sh` result from a Linux
  runner with `/dev/fuse`. Extend it with concurrent readers, forced
  termination/restart and clean unmount. Test IDE watcher behavior separately:
  FUSE invalidation freshness is not evidence of an inotify or VS Code event.
- Test both default symlink rejection and any explicitly supported
  `SymlinkPreserve` workflow. Treat preserve mode as outside the mount sandbox.
- Exercise publication-journal and persistent-watermark CAS from multiple
  processes on each supported OS. Verify rollback after restart, permissions,
  state backup/restore, full disk, lock contention, and loss of each state file.
  Do not certify a network-filesystem location without proving its
  lock/rename semantics.
- If signed references are offered, test trusted-checkpoint bootstrap, explicit
  TOFU, cross-repository/channel replay, tampering, overlap-key rollout,
  `ResignReference`, old-key removal, partial fleet rollout, and compromised-key
  recovery. A signed publisher must have a durable `PublicationJournal`; test
  the two-phase `Pending`/`Committed` transition, process death before and after
  the S3 CAS, lost CAS responses, repeated recovery, concurrent publishers,
  restart rollback, an existing channel with independently supplied checkpoint,
  explicit TOFU, and refusal to bootstrap solely from S3. Verify that
  `RecoverPublication` republishes the exact recorded signed bytes without
  invoking a replacement signer. Keep publisher journal and consumer watermark
  state separate. Provision `RepositoryID`, checkpoints, and public keys
  outside S3.
- Stress repeated cache hits as well as cold reads. Verify same-digest
  singleflight coalescing and that `MaxConcurrentDownloads` bounds cache work,
  remote fetches, and hashing under contention. Also verify the weighted
  `MaxConcurrentDownloadBytes` peak across cache and remote paths, cancellation
  while queued, `(digest, expected-size)` flight separation, exact chunk-size
  `Store.Get` limits, last-waiter lease acknowledgment after returned data is
  copied, and the conservative 16 MiB manifest/4 KiB reference charges. Audit
  every third-party `ChunkCache`: the source-compatible cache
  interface cannot police allocations inside its `Get`, so that implementation
  should implement `SizedChunkCache`, or must independently cap a single legacy
  `Get` call at the 64 MiB protocol maximum.
- Exercise Watch registration at protocol path/depth/name/per-directory limits
  and at the 100,000-directory cap. Verify bounded-batch traversal, OS quota
  errors, watcher overflow recovery, and periodic reconciliation after lost
  events.
- Measure directory size, file count, change rate, memory, object request rate,
  cold-read latency, cache hit ratio, and store cost at supported limits. Publish
  explicit limits and reject inputs beyond them.
- Back up and restore the mutable references and required immutable objects.
  Validate bucket versioning, retention, lifecycle, replication, and disaster
  recovery settings without relying on undocumented provider behavior.

## Security and operations

- Give S3 credentials only to A. B/C/D use the fixed root bearer and
  authenticated exact-key GET bearers plus the separate client-side share key;
  they must not receive a `SecretAccessKey`, credential provider, reusable
  signer, IAM role, or bucket listing authority. After the private authenticated
  initial handoff their only publisher-to-reader runtime medium is S3: no broker
  renewal, A callback, or other control-plane dependency is permitted. A needs
  conditional writes and exact reads only within the repository and share-root
  namespaces; neither role needs bucket administration or normal key listing.
- Require TLS and a trusted endpoint. Provision bounded commissioned CA PEM for
  every HTTPS B-side Reader and presigned probe, including public CAs. Do not
  enable `DangerouslyAllowSystemTrustStore` on B/C/D: platform trust evaluation
  may perform AIA/revocation network I/O outside the locked S3 dialer and breaks
  the strict only-S3 boundary. Define credential rotation, clock-skew,
  retry/backoff, proxy, audit-log, and incident-response procedures.
- Treat the entire handoff, share key, and root/object URLs as secrets. A URL
  exposes an access-key ID and can expose a temporary session token even though
  it contains no `SecretAccessKey`. Exclude all of them from logs, telemetry,
  command lines, crash reports, and support artifacts. Document that expiry
  cannot revoke a leaked share key, erase already read or cached plaintext, or
  make captured ciphertext undecryptable; physical automatic unmount remains
  best effort.
- Treat the symmetric key as per-share, not per-recipient. Every B/C/D given one
  handoff can decrypt and create valid AEAD envelopes, copy the handoff, and is
  indistinguishable at that layer. Ed25519 and SHA-256 authenticate publisher
  state; AEAD possession does not identify A. Issue separate prefixes, keys,
  roots, and handoffs wherever per-recipient attribution or revocation is a
  requirement.
- The current CLI's A-side state directory is not same-share crash recovery: it
  does not retain the client key, publisher private signer, or root capability.
  Do not certify resume until those secrets have an approved persistence,
  wrapping, recovery, backup, rotation, and zeroization design and recovery
  tests.
- Redacted formatting is not a memory boundary. The raw handoff contains a
  usable client key and bearer, and values may remain visible to reflection,
  debuggers, core dumps, or swap. There is no `mlock`, automatic handoff
  deletion, key zeroization, or secure erase; approve product controls for
  secret storage, backups, process dumps/swap, deletion, and endpoint hardening.
- Document and test the S3-credential compromise boundary. IAM authority can
  list opaque keys if permitted, download, overwrite, or delete ciphertext,
  deny service, and reveal sizes and access timing. Without the independently
  delivered share key it must not reveal protected object bodies. Require
  SSE-S3 or SSE-KMS as defense in depth, not as a substitute for client-side
  encryption or private handoff delivery.
- Protect and monitor plaintext disk caches. Configure `DiskCacheOptions` below
  the product quota and account for filesystem metadata plus one temporary
  chunk. `DiskCache` is keyed only by logical chunk digest, not by profile,
  `RepositoryID`, or share; require a separate private cache directory for each
  share. Define secure deletion, single-process ownership, multi-user isolation,
  and behavior on a full disk.
- Use `FilePublicationJournal` for publisher publication state and
  `FileWatermarkStore` for consumer adoption state, with distinct private local
  paths namespaced by repository/channel/role. Their CAS is cross-process on
  Linux, Darwin with cgo, and Windows. Other local platforms fail closed until
  their ACL model is certified; cross-host shared filesystems require separate
  certification.
- Require every publisher for one repository/channel to share the same
  linearizable `PublicationJournalStore`. Independent local journals on
  multiple hosts do not guarantee monotonicity or prevent split brain. Do not
  certify multi-host publishers until a distributed journal implementation and
  its failure semantics have been independently tested.
- Document signed-reference trust bootstrap and key lifecycle. The current
  direct keyring has no threshold root, signed revocation, or expiry metadata;
  TOFU cannot prove first-contact freshness.
- Decide whether untrusted publishers or tenants are in scope. If they are,
  signed-reference policy, channel authorization, symlink policy, resource
  bounds, and stronger isolation are release requirements.
- Define telemetry that excludes credentials, object contents, file names, and
  customer identifiers by default.

## Versioning and artifacts

1. Start with a documented `v0.x` preview or wait until API and format promises
   support `v1.0.0`. Use annotated, signed tags. Run the complete candidate gate
   and approvals before the tag is pushed to any remote or module proxy. Follow
   the exact-digest procedure below; do not create a release tag merely to
   trigger CI.
2. Build from a clean revision with `-trimpath`; record the source revision,
   exact Go version, module graph, build flags, target, and artifact SHA-256.
   Use an approved module proxy/checksum policy, reject unreviewed `replace`
   directives, and archive the resolved dependency sources or proxy evidence.
3. Generate an SBOM for each deliverable and archive test, vulnerability,
   license, and provenance evidence with the release.
4. Test upgrade and rollback from every supported prior version. Never mutate
   `.s3disk/v1` semantics under an existing namespace.
5. Publish support duration, deprecation policy, severity definitions, security
   contact, and patch delivery process before accepting production customers.

### Exact-digest candidate and tag procedure

1. Put the candidate on a protected branch and record its full lowercase commit
   ID. The tree must be committed and clean; test output from an uncommitted
   checkout is not attributable release evidence.
2. Manually run `Commercial Linux release gate`, select that branch, and enter
   the intended `candidate_version` and exact `candidate_commit`. The workflow
   rejects a commit other than the selected branch head and checks out the
   digest explicitly. Candidate mode also rejects any publishable SemVer tag at
   that commit and any existing tag with the requested version.
3. Configure `commercial-release-promotion` with required reviewers,
   prevention of self-review and administrator bypass, and only protected
   deployment branches. The promotion job must depend on the successful Linux
   gate, verify `release-evidence.sha256`, and re-publish the exact success
   artifact under an approved name. An environment attached before tests is
   access control for the runner, not post-test approval.
   Configure the earlier `commercial-release` environment with protected
   `S3DISK_RELEASE_RUNNER_EPHEMERAL=true` and
   `S3DISK_RELEASE_DOCKER_ISOLATED=true`. `DOCKER_HOST` must resolve to a
   rootless-daemon Unix socket below `RUNNER_TEMP`, owned by the non-root runner
   user with mode `0600`; its directories must not be group/world-writable.
   These checks fail closed but do not replace independent runner provisioning
   or destruction evidence.
4. Review and export the approved candidate artifact. In particular,
   `release-gate-success.json` and `release-reference.json` must bind
   `mode=candidate`, the requested version, commit, and tree. Approval applies
   only to those exact values. Verify both `release-evidence.sha256` and the
   outer `workflow-evidence.sha256`; the latter also binds the completed gate
   and environment logs. Native-platform artifacts remain separate records and
   must be bound by the independent release controller's signed evidence
   envelope before commercial promotion. The workflow accepts only the exact
   reviewed regular-file set in both the source and promotion artifacts; extra
   files, directories, and symbolic links fail the handoff. Potentially secret
   or internal Go environment values (`GOPROXY`, `GOSUMDB`, `GONOSUMDB`,
   `GOPRIVATE`, `GOWORK`, and `GOFLAGS`) are represented only by SHA-256
   bindings in `release-environment.log`, never by their raw values. Keep the
   original configuration in the separately protected controller record when
   an audit must later resolve those bindings.
5. In an isolated owner-controlled Linux release checkout of that same commit,
   create the annotated OpenPGP tag explicitly at the approved commit. Never
   rely on the current branch position:

   ```sh
   git tag -s -u "$AUTHORIZED_PRIMARY_OR_SIGNING_KEY" \
     -m "s3disk $VERSION" "$VERSION" "$APPROVED_COMMIT"
   mkdir -p /absolute/private/release-evidence
   S3DISK_RELEASE_MODE=release \
   S3DISK_RELEASE_VERSION="$VERSION" \
   S3DISK_RELEASE_COMMIT="$APPROVED_COMMIT" \
   S3DISK_RELEASE_EVIDENCE_DIR=/absolute/private/release-evidence \
   S3DISK_RELEASE_SIGNERS_FILE=/absolute/protected/authorized-openpgp-fingerprints \
   S3DISK_RELEASE_OPENPGP_PROGRAM=/usr/local/libexec/s3disk-release-gpg-wrapper \
     ./scripts/check-release.sh
   ```

   The allowlist is one uppercase 40- or 64-hex OpenPGP primary fingerprint per
   non-comment line. It, the verifier executable, and every ancestor directory
   must be owned by root and must not be group/world-writable; both files must
   live outside the source checkout. The gate rejects UID 0. The verifier
   should be a reviewed wrapper using an isolated verification keyring; its
   executable digest and the allowlist digest are recorded in evidence. The
   corresponding public key must already be present in that keyring.
6. Compare the release-mode `release-reference.json` with the approved
   candidate evidence: version, commit, and tree must be identical. Archive
   `release-tag-verification.status`. Only then push the single exact ref with
   `git push origin "refs/tags/$VERSION"`; never use `--tags` or force-push a
   release tag. The tag-triggered workflow is independent post-publication
   verification, not the authorization to publish.

For a local unpublished candidate run, set the same variables with
`S3DISK_RELEASE_MODE=candidate` and omit
`S3DISK_RELEASE_SIGNERS_FILE` and `S3DISK_RELEASE_OPENPGP_PROGRAM`.
`S3DISK_RELEASE_EVIDENCE_DIR` must always be an
existing absolute directory outside the checkout. The gate validates the
reference both before and after all tests, so a tag, HEAD, target, tree, or
authorized signer change cannot reuse the original green result.
