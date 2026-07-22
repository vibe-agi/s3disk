# Formal protocol model

`S3Disk.tla` specifies a competing-publisher, read-only multi-consumer protocol
as an immutable MVCC snapshot system. The one remotely mutable `latest` object
is a linearizable compare-and-swap register, so concurrent signed publishers
may prepare different commits but only one reference wins each generation.

The model separates two kinds of guarantee:

- Safety, without timing assumptions: CAS never exposes an incomplete
  snapshot; a publisher pending intent is based on its durable committed
  anchor and survives crashes; a lost successful CAS response cannot make the
  publisher regress or switch to a different branch at the same generation;
  stale, duplicated, reordered, and dropped responses cannot cross a
  consumer's durable anti-rollback watermark; unauthorized references cannot
  become candidates or exposed views; metadata is verified and the watermark
  is persisted before activation; an open handle pins one generation; corrupt
  or wrong-generation lazy-read data is rejected.
- Liveness, with explicit partial-synchrony assumptions: if the network and
  store eventually remain available, publishers and consumers eventually stop
  crashing, and the recovery actions are weakly fair, every durable publisher
  intent is finalized against the proven remote winner and every consumer
  eventually reaches every published stable generation. A restarted consumer
  also eventually re-exposes its durable watermark or a newer authorized
  generation.

An unbounded partition or infinite crash loop cannot have a convergence
deadline. During it, an implementation may serve its coherent last-known-good
snapshot and must fail uncached reads rather than claim freshness it cannot
establish.

## Presigned, S3-only sharing model

`S3Share.tla` is a separate refinement model for the commercial sharing path.
It does not change the semantics or constants of `S3Disk.tla`. Its runtime
topology is deliberately narrower:

```text
out-of-band handoff: A -> B/C: one fixed RootKey exact-GET bearer

A --PUT/CAS--> S3 RootKey             B/C --conditional GET--> S3 RootKey
A --PUT-----> S3 immutable objects    B/C --exact lazy GET----> S3 object

                         no A<->consumer or consumer<->consumer runtime link
```

The consumer has neither a complete S3 credential nor signing authority.
Every entry in the append-only abstract request log must be a GET whose target
is S3 and whose key is either the one fixed root key or an exact immutable key
from a previously authenticated bundle. There is no consumer LIST, HEAD,
write, prefix-wide read, URL derivation, A callback, authorization service, or
peer request transition in the model.

`rootObject` is one mutable S3 key and each `PublishRoot` is its single-key
linearization point. A consumer repeatedly uses the same bearer with an
abstract `If-None-Match` revision. Changed responses can be delayed and
reordered across later replacements; unchanged responses take the explicit
not-modified path. A bundle signature binds revision, generation, commit,
share identity, prefix, fixed expiry, and the complete exact-capability set.
The model separately exercises:

- a field-tampered bundle whose visible prefix no longer equals its signed
  payload; and
- an authentically signed but conflicting commit at an already adopted
  generation, representing a signer fault or compromised signing authority.

Neither can change a consumer's retained capabilities or active bundle.
Accepted revision and generation never regress, and an equal generation may
retain only the same commit. Old authenticated capability sets remain retained
because an open handle can pin an old generation while a newer root response
is adopted. A lazy response is returned only when its exact key and bytes
generation match the request's pinned generation.

The consumer's generation+commit watermark is a separate durable variable.
`CrashRestart` preserves that watermark and the original fixed RootKey bearer,
but clears the fresh process's accepted bundle, exact capabilities, in-flight
requests/responses, open handle, and cache. Consequently no immutable-object
GET is enabled after restart. `StartRootBootstrap` is the only recovery entry:
it performs an unconditional exact GET of the same S3 `RootKey`, because a
watermark alone cannot reconstruct the bundle's exact object capabilities.
There is still no A callback, authorization-service request, peer request, S3
credential, or new signing authority.

Recovery verifies the signed bundle against the durable watermark before it
installs any capability. A current bundle at the same generation and commit is
accepted so a fresh Reader can reconstruct its volatile state from the same
root bearer. A lower, still-valid signed bundle returned by S3 is modeled by
`S3ReturnDurableRollback` and is consumed only by
`RejectDurableRollbackAfterRestart`; the watermark and empty volatile authority
remain unchanged. The fresh process may retry the same fixed root bearer; the
restart gate separately covers both direct recovery and recovery after that
rollback rejection. A later exact lazy GET is enabled only after the current
bundle has been reinstalled. This is fail-closed anti-rollback, assuming the
local watermark itself is durable and not restored from an older disk image.

The service clock and each consumer's local clock are independent. A consumer
never starts a request at or after its local expiry. If that local clock lags,
S3 still rejects a pending request processed at or after service expiry. A
local clock reaching expiry atomically records an unmount request. Physical
unmount can subsequently fail and the mount can remain present; the model does
not claim that unmount revokes copied data. Cached and previously returned
bytes are monotonic, and an explicit post-expiry cached-read action demonstrates
that they can remain observable after an unmount failure.

The principal checked safety obligations are:

- `OnlyS3ExactGetRequests` and `BearerAuthorityOnly`;
- `AuthenticatedBundlesBindAllAuthority` and
  `RetainedBundleHistoryDoesNotFork`;
- `RestartPendingHasNoInstalledAuthority`,
  `RestartBootstrapUsesSameFixedRootBearer`, and
  `RecoveredAuthorityExtendsDurableWatermark`;
- `SuccessfulLazyGetsWereAuthorizedBeforeServiceExpiry` and
  `ReturnedBytesMatchPinnedGeneration`;
- `LocalExpiryRequestsUnmount` and `UnmountIsNotClaimedAsRevocation`; and
- the temporal non-regression and non-revocation properties for the root,
  accepted bundle, retained capabilities, immutable objects, cache, and
  returned-byte log.

Network jitter may partition either consumer, make the store unavailable,
drop requests or responses, and reorder a stale root response around a newer
one. `StabilizeNetwork` ends those faults. The sole liveness property is
conditional: `TimelyStableConsumersConverge` applies only when stabilization
occurs before both service and local expiry, the exact-capability retention
limit can retain every configured revision, and a lazy-fetch attempt remains
funded or in flight. `FairNext` then formalizes “enough authorization window”
by holding the clocks while fair protocol work is outstanding. If the network
stabilizes too late, the share expires, or the reader's retention/request
budget is exhausted, the antecedent is false and the model makes no
convergence claim.

The CI configurations split orthogonal fault dimensions so their independent
state products do not make the required gate needlessly large, without
weakening the shared state machine or architectural constraints:

- `S3Share.cfg` uses two consumers and covers independent partitions, store
  outages, request/response drops, response reordering, conditional polling,
  and lazy reads.
- `S3ShareRevision.cfg` uses one consumer and two root revisions to cover a
  stale generation crossing a later root replacement, retained old exact
  capabilities, field tampering, a signed same-generation fork, and a bad lazy
  response.
- `S3ShareExpiry.cfg` keeps the network/store available and exhaustively checks
  independent service/local expiry, S3 rejection, local unmount request,
  failed and successful physical unmount, and non-revocable cached bytes.
- `S3ShareRestart.cfg` uses one consumer and two revisions to persist the newer
  watermark, crash away every volatile capability, reject an older signed root
  response, bootstrap the current bundle through the same fixed S3 root GET,
  and resume an exact lazy read without any A/control-plane transition.
- `S3ShareLiveness.cfg` uses two consumers and one revision to check the
  conditional fair convergence property after the explicit stabilization
  transition while the separate expiry configuration establishes the
  authorization boundary.

The two-consumer cases use the documented `ConsumerCompositionConstraint`
partial-order reduction: consumers never mutate the root or one another, so
their local transitions commute. TLC explores the configured primary consumer
through completion or expiry before allowing the second consumer to leave its
pristine state. This retains every per-consumer protocol/fault outcome while
removing redundant pairs of independent intermediate states.

The finite lazy-attempt and retention bounds intentionally mirror real reader
resource limits. Increasing them expands the state space; exhausting them is
a safe failure to converge, not permission to evict a capability still needed
by an old pinned handle.

With the pinned TLC jar and one worker, the current share bounds produce:

| Configuration | Generated states | Distinct states | Depth |
| --- | ---: | ---: | ---: |
| `S3Share.cfg` | 5,892 | 828 | 24 |
| `S3ShareRevision.cfg` | 23,266 | 6,117 | 30 |
| `S3ShareExpiry.cfg` | 1,161 | 395 | 17 |
| `S3ShareRestart.cfg` | 1,324 | 487 | 26 |
| `S3ShareLiveness.cfg` | 526 | 142 | 22 |

## Signed-reference abstraction

Every reference is modeled as a `(generation, commit identity)` record. For
the fixed `Repository` and `Channel`, `Authorized(repo, channel, ref)` is the
abstract result of verifying that the signature binds all four values:

```text
repository || channel || generation || commit identity
```

`AttackerInject` can place a `ForgedReference(g)` on the wire. It has a valid
record shape and an abstract structurally/hash-valid commit identity, so
parsing and content hashing alone would not reject it. It is nevertheless not
authorized for this repository/channel tuple. `RejectUnauthorizedReference`
consumes it without changing `known`, `validated`, `durable`, or `view`.

The relevant checked invariants are:

- `VolatileAndDurableReferencesAreAuthorized`
- `ExposedViewsAreAuthorized`
- `WireReferencesWellFormed`

This is an authorization model, not a model of a signature algorithm.
Unforgeability, canonical byte encoding, key generation and rotation, secret
key protection, algorithm agility, and implementation side channels remain
cryptographic and engineering obligations. Commit identities are also
abstract: the compact consumer state assigns one authorized identity per
generation and one attacker identity, while the publisher state retains two
different authorized branch identities, A and B, for a same-generation race.
The implementation uses full content digests and must bind those exact bytes
into the signature. A stolen signing key is outside the model because a
reference made with it satisfies `Authorized`.

## Signed publisher journal and CAS recovery

The publisher-side transition is split at every durability and uncertainty
boundary:

```text
Persist Pending{Base = Committed, Target = exact signed reference}
        -> Load the same Target into a volatile attempt
        -> CAS latest
             |-> response received
             |-> applied, response lost
             |-> a different authorized A/B branch won
        -> Prove the CAS-selected remote reference
        -> Advance Committed and clear Pending
```

`PublisherCASAppliedResponseLost` advances `remotePublisherLatest` and its
history but leaves both the durable anchor and volatile proof unchanged.
`PublisherCrashRestart` clears `publisherAttempt` and `publisherProof`, never
`publisherPending` or `publisherCommitted`. `RecoverPublisherPending` can load
only the exact target from that durable intent. If `CompetingPublisherCASWins`
selects the other valid branch for the same generation, the local publisher
proves and adopts that winner; it cannot finalize its losing target.

The key checked publisher obligations are:

- `PendingBaseEqualsCommittedAnchor`
- `PublisherRecoveryUsesSamePendingIntent`
- `RemotePublisherHistoryIsSingleAuthorizedChain`
- `RemoteExposureCannotForkCommittedAnchor`
- `PublisherCommittedNeverRegressesOrSwitchesBranch`
- `PendingIntentCannotBeRewritten`
- `PendingClearsOnlyAfterProvenRemoteHistory`
- `PublisherPendingEventuallyFinalizes` under partial synchrony and weak
  fairness

Branch A/B represents two legal signed commits, not an attacker commit. CAS
admits at most one into `remotePublisherHistory` for a generation. A branch is
an abstract lineage: after the A/B race at generation 1, every later target
must retain its committed parent's lineage. This makes ancestry part of
`DirectPublisherSuccessor` and prevents a target from being reinterpreted as a
descendant of the other branch without constructing an exponentially growing
commit tree. Pending recovery is exercised at every configured generation.

Together, `PendingIntentCannotBeRewritten` and
`PublisherRecoveryUsesSamePendingIntent` state the crash rule explicitly: an
unresolved `(Base, Target)` is immutable, and every volatile retry after a
restart reloads that exact target. A different target at the same generation
can only be the separately authorized remote CAS winner, never a replacement
for the durable local intent.

## RootPublisher recovery-journal refinement

`RootPublisherRecovery.tla` is a smaller executable refinement focused on the
same-share A-side recovery journal used by `RootPublisher`. Its durable state
starts with the canonical revision-zero Prepared sentinel, then becomes
`Committed{revision,targetDigest}` plus either no pending operation or one
immutable `Pending{base,expectedBase,target,expiresAt}`. The remote S3 root is
an append-only abstract CAS history. Each local write, and the independently
journaled competing publisher write used to exercise a CAS loser, carries the
exact durable intent that existed before that history entry was appended.
The model starts after `PrepareRecovery` has successfully installed that
sentinel; absent-state rejection, the initial journal CAS, response loss, and
concurrent encrypted-witness candidates are covered by Go fault tests.

The model separately exercises a received CAS response, an applied response
whose reply is lost, a correctly journaled competitor winning the CAS,
network and store failures, lower-revision replay, equal-revision/different-
digest replay, and a crash/restart. A crash clears the volatile attempt,
response, proof, and exact-bearer provenance while preserving the complete
journal. Successful imported-bearer admission restores local authority only
after the sealed identity is abstractly validated and has no journal or remote
storage effect; one rejected attempt grants no authority. A later restore action
represents a separate matching input rather than reclassifying the rejected
one. While authority is absent, an advancing remote history can only be an
independently journaled competitor write, never a local root write. Recovery
may load only the exact pending target. Pending cannot be rewritten or cleared until a
validated current remote successor has been proved; finalization adopts that
successor, including a competitor winner. Committed revision is monotonic and
an equal revision cannot change digest. The authorization expiry is fixed,
never extended by recovery, and no modeled publisher can add a remote write at
or after expiry.

`RootPublisherRecovery.cfg` checks those safety obligations without timing
assumptions. `RootPublisherRecoveryLiveness.cfg` adds only weak fairness for
validated bearer admission, the recovery steps, and environment stabilization.
Its conditional liveness claim says an unresolved local pending intent
eventually resolves when the network and store remain stable and the fixed
authorization has not expired. Weak fairness of the abstract admission action
also assumes that the matching original bearer and recovery key remain
available; safety still holds when they are missing or rejected, but progress
does not.
Fault/replay injection stops after stabilization and the small model bounds
crashes to one, so it does not silently claim progress through an infinite
fault or crash schedule.

The abstraction assumes the durable journal presented after restart is the
latest complete journal. Whole-journal rollback/replay, loss of the journal
disk, torn persistence below the sealed-state-store contract, backup restore,
and multi-site disaster recovery are outside the model and require separate
operational and storage evidence. The finite model treats successful admission
as one abstract validation action; concrete URL syntax, bearer digest, namespace,
fixed-expiry, security-flag, and encryption-witness mismatches are refined by Go
fault tests rather than added as a state-space product. It likewise does not
model the initial Prepared-file CAS itself.

With the pinned TLC 1.7.4 jar and one worker, the checked bounds produce:

| Configuration | Generated states | Distinct states | Depth |
| --- | ---: | ---: | ---: |
| `RootPublisherRecovery.cfg` | 399,571 | 80,980 | 23 |
| `RootPublisherRecoveryLiveness.cfg` | 65,015 | 12,820 | 18 |

This publisher state machine models commit-advancing `Publish` intents. It does
not model authentication-envelope-only `ResignReference` operations: an
envelope is not part of the commit DAG, so commit ancestry cannot prove that a
particular re-sign was ever visible. The Go recovery implementation therefore
requires exact current reference bytes to classify a re-sign as applied, and
the competing re-sign/descendant interleavings are covered by fault-injection
tests rather than by the current TLC configurations.

The model assumes the committed anchor and pending intent are atomically and
durably updated together by the local journal. As with the consumer watermark,
torn local storage, restoration of an older disk image, and loss of the entire
journal device are outside this state machine and require an operational
recovery policy.

## Durable watermark and restart order

The consumer transition order is deliberately split so TLC can explore a
crash between every boundary:

```text
Receive authorized ref
        -> Fetch and validate commit/root metadata
        -> Persist generation+commit watermark
        -> Atomically activate view
```

`CrashRestart` clears `wire`, `known`, `validated`, `view`, and open-handle
state for one process, but cannot change `durable`. `LoadDurable` seeds a new
process from that watermark; metadata must still be fetched and verified
before the view is re-exposed. Replayed references at or below the watermark
are consumed without becoming a candidate.

The corresponding invariants and temporal properties are:

- `OldResponsesCannotCrossDurableWatermark`
- `DurableWatermarkNeverRegresses`
- `PersistencePrecedesActivation`
- `VolatileStateOnlyResetsToEmpty`
- `DurableViewRecovery` under the fairness/recovery assumptions

The model assumes a successful watermark write is atomic and durable across a
process or machine restart. It does not model torn sectors, loss of the
watermark device, filesystem rollback, or restoration of an older VM image.
A production implementation must use an atomic replacement plus fsync (or an
equivalent transactional store), authenticate the persisted commit identity,
and define explicit recovery behavior for missing or corrupt watermark state.

## Model-checking bounds

Run all configurations with:

```sh
./scripts/check-model.sh
```

The gate also enables TLC action coverage and fails if any required publisher
journal, authorization, recovery, corruption, partition, persistence,
activation, or verified-read transition has no distinct successor state. This
prevents an accidentally unreachable fault path from producing a misleading
green model-check result.

The CI-sized configurations deliberately split independent dimensions:

- `S3Disk.cfg`: one consumer and two generations, covering authorization,
  replay, durable persistence before activation, crashes at every volatile
  stage, stale generation delivery, lazy reads, corruption, partitions, store
  outages, both publisher CAS response outcomes, publisher restart recovery,
  and a competing same-generation winner.
- `S3DiskTwoConsumers.cfg`: two independently crashable and partitionable
  consumers with one generation, covering independent durable watermarks and
  views as well as the complete publisher journal. Consumers never mutate
  publisher or peer state, so their transition relation composes by client.
- `S3DiskLiveness.cfg`: one consumer and one representative generation plus
  the recovery and fairness assumptions needed for publisher finalization,
  consumer catch-up, and post-restart view recovery. Multi-generation stale
  delivery remains in the main safety configuration; the liveness transition
  is generation independent.

The model uses a documented partial-order reduction for CI: a publisher
selects a new intent only while consumer protocol state is pristine, and
consumer transitions wait while that intent is unresolved. Publisher-only and
consumer-only steps commute until a reference is observed. After publication,
consumers can still receive any historical generation in any order, so stale
replay, a newer activation, and an open handle pinned across that activation
remain reachable. This removes redundant interleavings of every consumer
state with every publisher crash boundary without removing a protocol outcome.

With TLC 1.7.4 and one worker, the current bounds produced:

| Configuration | Generated states | Distinct states | Depth |
| --- | ---: | ---: | ---: |
| `S3Disk.cfg` | 4,200,331 | 299,394 | 38 |
| `S3DiskTwoConsumers.cfg` | 3,959,763 | 250,024 | 33 |
| `S3DiskLiveness.cfg` | 31,851 | 3,580 | 25 |

Larger bounds can be selected by changing the constants in a configuration;
they are useful for scheduled verification but grow the state space quickly.

## Assumptions outside the state machine

- Conditional `latest` writes really are atomic compare-and-swap operations.
- Immutable objects remain retained, and a successful object upload is
  durable. Hash identifiers are treated as collision-free; in code this is a
  cryptographic assumption, not an absolute mathematical fact.
- The consumer has the authentic public-key/configuration root for the exact
  repository and channel it mounts.
- The source presented to the publisher is a valid snapshot. A recursive scan
  of a concurrently changing directory cannot prove it represented one real
  instant. Strict point-in-time input requires a filesystem snapshot,
  cooperative write journal, or equivalent writer-side transaction boundary.
- Activating `view` is an abstract atomic operation. Platform mount adapters
  must refine it with kernel cache invalidation and end-to-end tests. The FUSE
  adapter guarantees single-snapshot successful operations and snapshot-pinned
  open files, but a path can retain an old dentry until successful invalidation
  or `EntryTTL` expiry. Kernel negative-dentry caching is disabled. This
  path-cache convergence interval is outside the abstract protocol model.

TLC exhaustively checks the configured finite state spaces. It is an
executable design constraint, not by itself a proof that the Go implementation
refines the specification; Go state-machine, fault-injection, MinIO, durable
restart, signature-negative, and mount tests provide that connection.
