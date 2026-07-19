----------------------------- MODULE S3Share -----------------------------
EXTENDS Naturals, FiniteSets

(***************************************************************************
This is the presigned, read-only share model.  It is intentionally separate
from S3Disk.tla: the latter models repository publication and consumers that
read a repository reference through an abstract store API, while this module
models the stricter bearer-capability deployment.

After an out-of-band handoff, A and the consumers have no direct runtime
channel.  Each consumer owns one fixed exact-GET bearer for RootKey, no S3
credential, and no signing authority.  A replaces that one S3 object
linearly.  Consumers conditionally poll the same URL, authenticate the bundle,
and may then issue lazy GETs only for the exact immutable object capabilities
bound into an authenticated bundle.

A consumer restart preserves only its durable generation+commit watermark and
the original RootKey bearer.  It clears volatile accepted capabilities, then
must GET that same S3 RootKey and prove the returned bundle extends the durable
watermark before lazy object GETs can resume.  A replay below the watermark
fails closed; restart never introduces an A or control-plane transition.

The network can delay, drop, and reorder requests and responses.  Service and
local clocks are separate: a slow local clock can still issue a request that
S3 rejects after service expiry.  Reaching local expiry requests unmount, but
physical unmount need not succeed.  Bytes returned or cached before expiry
are deliberately never revoked; this is an authorization model, not DRM.
***************************************************************************)

CONSTANTS
    Consumers,
    MaxRevision,
    Expiry,
    InitialLazyBudget,
    RetentionLimit,
    ObjectIndexes,
    RootKey,
    PrimaryConsumer,
    Mode

ASSUME /\ Consumers # {}
       /\ MaxRevision \in Nat \ {0}
       /\ Expiry \in Nat \ {0}
       /\ InitialLazyBudget \in Nat
       /\ RetentionLimit \in Nat \ {0}
       /\ ObjectIndexes # {}
       /\ IsFiniteSet(Consumers)
       /\ IsFiniteSet(ObjectIndexes)
       /\ PrimaryConsumer \in Consumers
       /\ Mode \in {"network", "adversarial", "expiry", "liveness",
                     "restart"}

Revisions == 1..MaxRevision
Times == 0..Expiry
AdversarialMode == Mode = "adversarial"
NetworkFaultMode == Mode = "network"
CanStabilize == Mode \in {"network", "liveness"}
ExpiryMode == Mode = "expiry"
RestartMode == Mode = "restart"

ObjectKey(g, i) == [generation |-> g, index |-> i]
ObjectKeys ==
    UNION {{ObjectKey(g, i) : i \in ObjectIndexes} : g \in Revisions}
Capabilities(g) == {ObjectKey(g, i) : i \in ObjectIndexes}

Payload(revision, generation, commit, capabilities, prefix) ==
    [revision     |-> revision,
     generation   |-> generation,
     commit       |-> commit,
     share        |-> "share-1",
     prefix       |-> prefix,
     expiry       |-> Expiry,
     capabilities |-> capabilities]

Bundle(revision) ==
    LET payload == Payload(revision,
                           revision,
                           revision,
                           Capabilities(revision),
                           "selected-prefix")
    IN  [revision       |-> payload.revision,
         generation     |-> payload.generation,
         commit         |-> payload.commit,
         share          |-> payload.share,
         prefix         |-> payload.prefix,
         expiry         |-> payload.expiry,
         capabilities   |-> payload.capabilities,
         signedPayload  |-> payload,
         signatureValid |-> TRUE]

NoPayload == Payload(0, 0, 0, {}, "")
NoBundle ==
    [revision       |-> 0,
     generation     |-> 0,
     commit         |-> 0,
     share          |-> "",
     prefix         |-> "",
     expiry         |-> Expiry,
     capabilities   |-> {},
     signedPayload  |-> NoPayload,
     signatureValid |-> FALSE]

NoWatermark == [generation |-> 0, commit |-> 0]
BundleWatermark(bundle) ==
    [generation |-> bundle.generation, commit |-> bundle.commit]
Watermarks == {BundleWatermark(Bundle(r)) : r \in Revisions}

(***************************************************************************
TamperedBundle changes a bound prefix without changing the signed payload.
SignedForkBundle represents a signer fault or compromised signing authority,
not a network forgery: its signature binds its fields, but it attempts to
switch commit at an already accepted generation.  The adversarial S3 response
can return it only after generation 1 is accepted so the consumer's
same-generation rule can reject it.  Both adversarial responses consume a
pending RootKey GET; they are not a separate runtime channel.
***************************************************************************)
TamperedBundle ==
    LET original == Payload(1, 1, 1, Capabilities(1), "selected-prefix")
    IN  [revision       |-> original.revision,
         generation     |-> original.generation,
         commit         |-> original.commit,
         share          |-> original.share,
         prefix         |-> "different-prefix",
         expiry         |-> original.expiry,
         capabilities   |-> original.capabilities,
         signedPayload  |-> original,
         signatureValid |-> TRUE]

SignedForkBundle ==
    LET payload == Payload(MaxRevision + 1,
                           1,
                           MaxRevision + 1,
                           Capabilities(1),
                           "selected-prefix")
    IN  [revision       |-> payload.revision,
         generation     |-> payload.generation,
         commit         |-> payload.commit,
         share          |-> payload.share,
         prefix         |-> payload.prefix,
         expiry         |-> payload.expiry,
         capabilities   |-> payload.capabilities,
         signedPayload  |-> payload,
         signatureValid |-> TRUE]

GoodBundles == {Bundle(r) : r \in Revisions}
WireBundles == GoodBundles \cup {TamperedBundle, SignedForkBundle}
BundlesWithNone == WireBundles \cup {NoBundle}

BundleAuthenticated(bundle) ==
    /\ bundle.signatureValid
    /\ bundle.share = "share-1"
    /\ bundle.prefix = "selected-prefix"
    /\ bundle.expiry = Expiry
    /\ bundle.signedPayload =
          Payload(bundle.revision,
                  bundle.generation,
                  bundle.commit,
                  bundle.capabilities,
                  bundle.prefix)

NoRootRequest == MaxRevision + 1

NoHandle == [revision |-> 0, generation |-> 0, key |-> RootKey]
Handle(revision, key) ==
    [revision   |-> revision,
     generation |-> Bundle(revision).generation,
     key         |-> key]
Handles ==
    UNION {{Handle(r, key) : key \in Capabilities(r)} : r \in Revisions}

NoLazyRequest ==
    [consumer |-> 0, revision |-> 0, generation |-> 0, key |-> RootKey]
LazyRequest(c, revision, key) ==
    [consumer   |-> c,
     revision   |-> revision,
     generation |-> Bundle(revision).generation,
     key         |-> key]
LazyRequests ==
    UNION {UNION {{LazyRequest(c, r, key) : key \in Capabilities(r)} :
                     r \in Revisions} : c \in Consumers}

LazyResponse(request, returnedKey, bytesGeneration, valid) ==
    [consumer        |-> request.consumer,
     revision        |-> request.revision,
     pinnedGeneration |-> request.generation,
     requestedKey    |-> request.key,
     returnedKey     |-> returnedKey,
     bytesGeneration |-> bytesGeneration,
     valid           |-> valid]

GoodLazyResponse(request) ==
    LazyResponse(request, request.key, request.generation, TRUE)
BadLazyResponse(request) ==
    LazyResponse(request, request.key, 0, FALSE)

GoodLazyResponses == {GoodLazyResponse(request) : request \in LazyRequests}
BadLazyResponses == {BadLazyResponse(request) : request \in LazyRequests}
LazyResponses == GoodLazyResponses \cup BadLazyResponses

RootAudit(c, issuedAt) ==
    [consumer          |-> c,
     target            |-> "S3",
     method            |-> "GET",
     route             |-> "root",
     key               |-> RootKey,
     capabilityRevision |-> 0,
     issuedLocalTime   |-> issuedAt]

LazyAudit(request, issuedAt) ==
    [consumer          |-> request.consumer,
     target            |-> "S3",
     method            |-> "GET",
     route             |-> "immutable-object",
     key               |-> request.key,
     capabilityRevision |-> request.revision,
     issuedLocalTime   |-> issuedAt]

AllRootAudits == {RootAudit(c, t) : c \in Consumers, t \in Times}
AllLazyAudits ==
    {LazyAudit(request, t) : request \in LazyRequests, t \in Times}
AllAudits == AllRootAudits \cup AllLazyAudits

LazySuccess(request, succeededAt) ==
    [consumer      |-> request.consumer,
     revision      |-> request.revision,
     key           |-> request.key,
     succeededAt   |-> succeededAt]
AllLazySuccesses ==
    {LazySuccess(request, t) : request \in LazyRequests, t \in Times}

ReturnedRecord(response) ==
    [consumer        |-> response.consumer,
     key             |-> response.requestedKey,
     pinnedGeneration |-> response.pinnedGeneration,
     bytesGeneration |-> response.bytesGeneration]
AllReturnedRecords == {ReturnedRecord(response) : response \in GoodLazyResponses}

VARIABLES
    rootObject,             \* the one mutable, linearizable S3 key
    rootHistory,
    immutableObjects,
    requestLog,             \* every consumer network request, never cleared
    rootPending,            \* conditional If-None-Match revision or none
    rootWire,               \* delayed/reordered root responses
    lazyPending,
    lazyWire,               \* delayed object responses
    accepted,
    retainedRevisions,      \* authenticated exact-capability bundles
    openHandle,
    cached,
    returnedLog,
    lazySuccessLog,
    lazyBudget,
    durableWatermark,       \* survives a B process crash/restart
    restartPending,         \* fresh process has no installed capability set
    bootstrapRootRequested, \* fixed RootKey bearer was used after restart
    recoveredAfterRestart,
    connected,
    storeUp,
    stableNetwork,
    serverTime,
    localTime,
    unmountRequested,
    physicallyMounted,
    physicalUnmountFailed,
    servedCachedAfterExpiry,
    rejectedUnauthenticated,
    rejectedFork,
    rejectedDurableRollback,
    rejectedBadLazy

storeVars == <<rootObject, rootHistory, immutableObjects>>
wireVars == <<requestLog, rootPending, rootWire, lazyPending, lazyWire>>
consumerVars ==
    <<accepted, retainedRevisions, openHandle, cached, returnedLog,
      lazySuccessLog, lazyBudget, durableWatermark, restartPending,
      bootstrapRootRequested, recoveredAfterRestart, unmountRequested,
      physicallyMounted, physicalUnmountFailed, servedCachedAfterExpiry,
      rejectedUnauthenticated, rejectedFork, rejectedDurableRollback,
      rejectedBadLazy>>
environmentVars ==
    <<connected, storeUp, stableNetwork, serverTime, localTime>>
vars == <<storeVars, wireVars, consumerVars, environmentVars>>

Init ==
    /\ rootObject = NoBundle
    /\ rootHistory = {}
    /\ immutableObjects = {}
    /\ requestLog = {}
    /\ rootPending = [c \in Consumers |-> NoRootRequest]
    /\ rootWire = [c \in Consumers |-> {}]
    /\ lazyPending = [c \in Consumers |-> NoLazyRequest]
    /\ lazyWire = [c \in Consumers |-> {}]
    /\ accepted = [c \in Consumers |-> NoBundle]
    /\ retainedRevisions = [c \in Consumers |-> {}]
    /\ openHandle = [c \in Consumers |-> NoHandle]
    /\ cached = [c \in Consumers |-> {}]
    /\ returnedLog = {}
    /\ lazySuccessLog = {}
    /\ lazyBudget = [c \in Consumers |-> InitialLazyBudget]
    /\ durableWatermark = [c \in Consumers |-> NoWatermark]
    /\ restartPending = [c \in Consumers |-> FALSE]
    /\ bootstrapRootRequested = [c \in Consumers |-> FALSE]
    /\ recoveredAfterRestart = [c \in Consumers |-> FALSE]
    /\ connected = [c \in Consumers |-> TRUE]
    /\ storeUp = TRUE
    /\ stableNetwork = FALSE
    /\ serverTime = 0
    /\ localTime = [c \in Consumers |-> 0]
    /\ unmountRequested = [c \in Consumers |-> FALSE]
    /\ physicallyMounted = [c \in Consumers |-> TRUE]
    /\ physicalUnmountFailed = [c \in Consumers |-> FALSE]
    /\ servedCachedAfterExpiry = [c \in Consumers |-> FALSE]
    /\ rejectedUnauthenticated = FALSE
    /\ rejectedFork = FALSE
    /\ rejectedDurableRollback = [c \in Consumers |-> FALSE]
    /\ rejectedBadLazy = FALSE

(***************************************************************************
Only A can replace RootKey or add immutable objects.  Both updates occur in
one abstract S3 linearization step, so a visible bundle's complete exact-key
closure already exists.  Consumers learn nothing through this action; they
must poll S3 themselves.
***************************************************************************)
PublishRoot ==
    LET nextRevision == rootObject.revision + 1
        nextBundle == Bundle(nextRevision)
    IN  /\ nextRevision \in Revisions
        /\ rootObject' = nextBundle
        /\ rootHistory' = rootHistory \cup {nextBundle}
        /\ immutableObjects' =
              immutableObjects \cup nextBundle.capabilities
        /\ UNCHANGED <<wireVars, consumerVars, environmentVars>>

StartRootPoll(c) ==
    /\ c \in Consumers
    /\ ~restartPending[c]
    /\ physicallyMounted[c]
    /\ localTime[c] < Expiry
    /\ rootPending[c] = NoRootRequest
    /\ rootPending' =
          [rootPending EXCEPT ![c] = accepted[c].revision]
    /\ requestLog' = requestLog \cup {RootAudit(c, localTime[c])}
    /\ UNCHANGED <<storeVars, rootWire, lazyPending, lazyWire,
                    consumerVars, environmentVars>>

(***************************************************************************
A restarted consumer has retained only its durable anti-rollback watermark
and the original fixed RootKey bearer.  It cannot reconstruct exact object
capabilities from the watermark, so bootstrap is an unconditional exact GET
(the abstract conditional revision is zero), never a callback to A or an
authorization service.
***************************************************************************)
StartRootBootstrap(c) ==
    /\ c \in Consumers
    /\ RestartMode
    /\ restartPending[c]
    /\ ~bootstrapRootRequested[c]
    /\ physicallyMounted[c]
    /\ localTime[c] < Expiry
    /\ rootPending[c] = NoRootRequest
    /\ rootPending' = [rootPending EXCEPT ![c] = 0]
    /\ requestLog' = requestLog \cup {RootAudit(c, localTime[c])}
    /\ bootstrapRootRequested' =
          [bootstrapRootRequested EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<storeVars, rootWire, lazyPending, lazyWire, accepted,
                    retainedRevisions, openHandle, cached, returnedLog,
                    lazySuccessLog, lazyBudget, durableWatermark,
                    restartPending, recoveredAfterRestart, unmountRequested,
                    physicallyMounted, physicalUnmountFailed,
                    servedCachedAfterExpiry, rejectedUnauthenticated,
                    rejectedFork, rejectedDurableRollback, rejectedBadLazy,
                    environmentVars>>

S3ReturnChangedRoot(c) ==
    /\ c \in Consumers
    /\ connected[c]
    /\ storeUp
    /\ serverTime < Expiry
    /\ rootPending[c] # NoRootRequest
    /\ rootObject # NoBundle
    /\ rootObject.revision # rootPending[c]
    /\ Cardinality(rootWire[c]) < 2
    /\ rootPending' = [rootPending EXCEPT ![c] = NoRootRequest]
    /\ rootWire' = [rootWire EXCEPT ![c] = @ \cup {rootObject}]
    /\ UNCHANGED <<storeVars, requestLog, lazyPending, lazyWire,
                    consumerVars, environmentVars>>

(***************************************************************************
An operator or external writer may have replayed an older, still correctly
signed RootKey value.  This is not a second runtime channel: the response is
still produced only while handling B's fixed exact S3 GET.  The restart
configuration makes this response race the current revision so TLC checks
that the durable watermark rejects it without installing old capabilities.
***************************************************************************)
S3ReturnDurableRollback(c) ==
    /\ c \in Consumers
    /\ RestartMode
    /\ restartPending[c]
    /\ bootstrapRootRequested[c]
    /\ MaxRevision > 1
    /\ durableWatermark[c] = BundleWatermark(Bundle(MaxRevision))
    /\ rootObject = Bundle(MaxRevision)
    /\ connected[c]
    /\ storeUp
    /\ serverTime < Expiry
    /\ rootPending[c] # NoRootRequest
    /\ rootPending' = [rootPending EXCEPT ![c] = NoRootRequest]
    /\ rootWire' =
          [rootWire EXCEPT ![c] = @ \cup {Bundle(MaxRevision - 1)}]
    /\ UNCHANGED <<storeVars, requestLog, lazyPending, lazyWire,
                    consumerVars, environmentVars>>

S3ReturnNotModified(c) ==
    /\ c \in Consumers
    /\ connected[c]
    /\ storeUp
    /\ serverTime < Expiry
    /\ rootPending[c] # NoRootRequest
    /\ rootObject # NoBundle
    /\ rootObject.revision = rootPending[c]
    /\ rootPending' = [rootPending EXCEPT ![c] = NoRootRequest]
    /\ UNCHANGED <<storeVars, requestLog, rootWire, lazyPending, lazyWire,
                    consumerVars, environmentVars>>

S3RootMissing(c) ==
    /\ c \in Consumers
    /\ connected[c]
    /\ storeUp
    /\ serverTime < Expiry
    /\ rootPending[c] # NoRootRequest
    /\ rootObject = NoBundle
    /\ rootPending' = [rootPending EXCEPT ![c] = NoRootRequest]
    /\ UNCHANGED <<storeVars, requestLog, rootWire, lazyPending, lazyWire,
                    consumerVars, environmentVars>>

S3RejectExpiredRoot(c) ==
    /\ c \in Consumers
    /\ serverTime = Expiry
    /\ rootPending[c] # NoRootRequest
    /\ rootPending' = [rootPending EXCEPT ![c] = NoRootRequest]
    /\ UNCHANGED <<storeVars, requestLog, rootWire, lazyPending, lazyWire,
                    consumerVars, environmentVars>>

DropRootRequest(c) ==
    /\ c \in Consumers
    /\ NetworkFaultMode
    /\ ~stableNetwork
    /\ rootPending[c] # NoRootRequest
    /\ rootPending' = [rootPending EXCEPT ![c] = NoRootRequest]
    /\ UNCHANGED <<storeVars, requestLog, rootWire, lazyPending, lazyWire,
                    consumerVars, environmentVars>>

DropRootResponse(c) ==
    /\ c \in Consumers
    /\ NetworkFaultMode
    /\ ~stableNetwork
    /\ rootWire[c] # {}
    /\ \E bundle \in rootWire[c]:
          rootWire' = [rootWire EXCEPT ![c] = @ \ {bundle}]
    /\ UNCHANGED <<storeVars, requestLog, rootPending,
                    lazyPending, lazyWire, consumerVars, environmentVars>>

S3ReturnTamperedRoot(c) ==
    /\ c \in Consumers
    /\ AdversarialMode
    /\ ~stableNetwork
    /\ connected[c]
    /\ storeUp
    /\ serverTime < Expiry
    /\ rootPending[c] # NoRootRequest
    /\ Cardinality(rootWire[c]) < 2
    /\ TamperedBundle \notin rootWire[c]
    /\ rootPending' = [rootPending EXCEPT ![c] = NoRootRequest]
    /\ rootWire' = [rootWire EXCEPT ![c] = @ \cup {TamperedBundle}]
    /\ UNCHANGED <<storeVars, requestLog, lazyPending, lazyWire,
                    consumerVars, environmentVars>>

S3ReturnSignedFork(c) ==
    /\ c \in Consumers
    /\ AdversarialMode
    /\ ~stableNetwork
    /\ connected[c]
    /\ storeUp
    /\ serverTime < Expiry
    /\ rootPending[c] # NoRootRequest
    /\ accepted[c] = Bundle(1)
    /\ Cardinality(rootWire[c]) < 2
    /\ SignedForkBundle \notin rootWire[c]
    /\ rootPending' = [rootPending EXCEPT ![c] = NoRootRequest]
    /\ rootWire' = [rootWire EXCEPT ![c] = @ \cup {SignedForkBundle}]
    /\ UNCHANGED <<storeVars, requestLog, lazyPending, lazyWire,
                    consumerVars, environmentVars>>

(***************************************************************************
GoodBundles is the abstraction of the one signature-verified commit lineage:
there is exactly one canonical commit for each generation.  Therefore a newer
GoodBundle whose commit is the canonical commit at that generation represents
successful ancestry verification against an older watermark.  The equality
case permits a fresh process to reinstall the exact bundle it had durably
accepted before crashing; it never permits a same-generation commit switch.
***************************************************************************)
ExtendsWatermark(bundle, watermark) ==
    \/ watermark = NoWatermark
    \/ /\ bundle.generation > watermark.generation
       /\ bundle.commit = Bundle(bundle.generation).commit
    \/ /\ bundle.generation = watermark.generation
       /\ bundle.commit = watermark.commit

CanAdopt(c, bundle) ==
    /\ bundle \in GoodBundles
    /\ BundleAuthenticated(bundle)
    /\ bundle.revision > accepted[c].revision
    /\ ExtendsWatermark(bundle, durableWatermark[c])
    /\ Cardinality(retainedRevisions[c]) < RetentionLimit

AcceptAuthenticatedBundle(c) ==
    /\ c \in Consumers
    /\ ~restartPending[c]
    /\ \E bundle \in rootWire[c]:
          /\ CanAdopt(c, bundle)
          /\ rootWire' = [rootWire EXCEPT ![c] = @ \ {bundle}]
          /\ accepted' = [accepted EXCEPT ![c] = bundle]
          /\ durableWatermark' =
                [durableWatermark EXCEPT ![c] = BundleWatermark(bundle)]
          /\ retainedRevisions' =
                [retainedRevisions EXCEPT ![c] = @ \cup {bundle.revision}]
    /\ UNCHANGED <<storeVars, requestLog, rootPending, lazyPending, lazyWire,
                    openHandle, cached, returnedLog, lazySuccessLog,
                    lazyBudget, restartPending, bootstrapRootRequested,
                    recoveredAfterRestart, unmountRequested,
                    physicallyMounted, physicalUnmountFailed,
                    servedCachedAfterExpiry, rejectedUnauthenticated,
                    rejectedFork, rejectedDurableRollback, rejectedBadLazy,
                    environmentVars>>

InstallAuthenticatedBundleAfterRestart(c) ==
    /\ c \in Consumers
    /\ RestartMode
    /\ restartPending[c]
    /\ bootstrapRootRequested[c]
    /\ \E bundle \in rootWire[c]:
          /\ CanAdopt(c, bundle)
          /\ rootWire' = [rootWire EXCEPT ![c] = @ \ {bundle}]
          /\ accepted' = [accepted EXCEPT ![c] = bundle]
          /\ durableWatermark' =
                [durableWatermark EXCEPT ![c] = BundleWatermark(bundle)]
          /\ retainedRevisions' =
                [retainedRevisions EXCEPT ![c] = {bundle.revision}]
    /\ restartPending' = [restartPending EXCEPT ![c] = FALSE]
    /\ recoveredAfterRestart' =
          [recoveredAfterRestart EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<storeVars, requestLog, rootPending, lazyPending, lazyWire,
                    openHandle, cached, returnedLog, lazySuccessLog,
                    lazyBudget, bootstrapRootRequested, unmountRequested,
                    physicallyMounted, physicalUnmountFailed,
                    servedCachedAfterExpiry, rejectedUnauthenticated,
                    rejectedFork, rejectedDurableRollback, rejectedBadLazy,
                    environmentVars>>

RecoverAuthenticatedBundleAfterRestart(c) ==
    /\ ~rejectedDurableRollback[c]
    /\ InstallAuthenticatedBundleAfterRestart(c)

RecoverAuthenticatedBundleAfterRejectedRollback(c) ==
    /\ rejectedDurableRollback[c]
    /\ InstallAuthenticatedBundleAfterRestart(c)

RejectUnauthenticatedBundle(c) ==
    /\ c \in Consumers
    /\ \E bundle \in rootWire[c]:
          /\ ~BundleAuthenticated(bundle)
          /\ rootWire' = [rootWire EXCEPT ![c] = @ \ {bundle}]
    /\ rejectedUnauthenticated' = TRUE
    /\ UNCHANGED <<storeVars, requestLog, rootPending, lazyPending, lazyWire,
                    accepted, retainedRevisions, openHandle, cached,
                    returnedLog, lazySuccessLog, lazyBudget,
                    durableWatermark, restartPending, bootstrapRootRequested,
                    recoveredAfterRestart,
                    unmountRequested, physicallyMounted,
                    physicalUnmountFailed, servedCachedAfterExpiry,
                    rejectedFork, rejectedDurableRollback, rejectedBadLazy,
                    environmentVars>>

RejectRollbackOrFork(c) ==
    /\ c \in Consumers
    /\ ~restartPending[c]
    /\ \E bundle \in rootWire[c]:
          /\ BundleAuthenticated(bundle)
          /\ bundle.revision > accepted[c].revision
          /\ ~ExtendsWatermark(bundle, durableWatermark[c])
          /\ rootWire' = [rootWire EXCEPT ![c] = @ \ {bundle}]
    /\ rejectedFork' = TRUE
    /\ UNCHANGED <<storeVars, requestLog, rootPending, lazyPending, lazyWire,
                    accepted, retainedRevisions, openHandle, cached,
                    returnedLog, lazySuccessLog, lazyBudget,
                    durableWatermark, restartPending, bootstrapRootRequested,
                    recoveredAfterRestart,
                    unmountRequested, physicallyMounted,
                    physicalUnmountFailed, servedCachedAfterExpiry,
                    rejectedUnauthenticated, rejectedDurableRollback,
                    rejectedBadLazy,
                    environmentVars>>

RejectDurableRollbackAfterRestart(c) ==
    /\ c \in Consumers
    /\ RestartMode
    /\ restartPending[c]
    /\ \E bundle \in rootWire[c]:
          /\ BundleAuthenticated(bundle)
          /\ bundle.revision > accepted[c].revision
          /\ ~ExtendsWatermark(bundle, durableWatermark[c])
          /\ rootWire' = [rootWire EXCEPT ![c] = @ \ {bundle}]
    /\ rejectedDurableRollback' =
          [rejectedDurableRollback EXCEPT ![c] = TRUE]
    /\ bootstrapRootRequested' =
          [bootstrapRootRequested EXCEPT ![c] = FALSE]
    /\ UNCHANGED <<storeVars, requestLog, rootPending, lazyPending, lazyWire,
                    accepted, retainedRevisions, openHandle, cached,
                    returnedLog, lazySuccessLog, lazyBudget,
                    durableWatermark, restartPending, recoveredAfterRestart,
                    unmountRequested,
                    physicallyMounted, physicalUnmountFailed,
                    servedCachedAfterExpiry, rejectedUnauthenticated,
                    rejectedFork, rejectedBadLazy, environmentVars>>

IgnoreStaleBundle(c) ==
    /\ c \in Consumers
    /\ \E bundle \in rootWire[c]:
          /\ BundleAuthenticated(bundle)
          /\ bundle.revision <= accepted[c].revision
          /\ rootWire' = [rootWire EXCEPT ![c] = @ \ {bundle}]
    /\ UNCHANGED <<storeVars, requestLog, rootPending, lazyPending, lazyWire,
                    consumerVars, environmentVars>>

OpenPinned(c) ==
    /\ c \in Consumers
    /\ physicallyMounted[c]
    /\ localTime[c] < Expiry
    /\ openHandle[c] = NoHandle
    /\ accepted[c] # NoBundle
    /\ \E key \in accepted[c].capabilities:
          /\ key \notin cached[c]
          /\ openHandle' =
                [openHandle EXCEPT
                    ![c] = Handle(accepted[c].revision, key)]
    /\ UNCHANGED <<storeVars, wireVars, accepted, retainedRevisions, cached,
                    returnedLog, lazySuccessLog, lazyBudget,
                    durableWatermark, restartPending, bootstrapRootRequested,
                    recoveredAfterRestart,
                    unmountRequested, physicallyMounted,
                    physicalUnmountFailed, servedCachedAfterExpiry,
                    rejectedUnauthenticated, rejectedFork,
                    rejectedDurableRollback, rejectedBadLazy, environmentVars>>

ClosePinned(c) ==
    /\ c \in Consumers
    /\ openHandle[c] # NoHandle
    /\ openHandle[c].key \in cached[c]
    /\ openHandle' = [openHandle EXCEPT ![c] = NoHandle]
    /\ UNCHANGED <<storeVars, wireVars, accepted, retainedRevisions, cached,
                    returnedLog, lazySuccessLog, lazyBudget,
                    durableWatermark, restartPending, bootstrapRootRequested,
                    recoveredAfterRestart,
                    unmountRequested, physicallyMounted,
                    physicalUnmountFailed, servedCachedAfterExpiry,
                    rejectedUnauthenticated, rejectedFork,
                    rejectedDurableRollback, rejectedBadLazy, environmentVars>>

StartLazyGet(c) ==
    LET request == LazyRequest(c,
                               openHandle[c].revision,
                               openHandle[c].key)
    IN  /\ c \in Consumers
        /\ physicallyMounted[c]
        /\ localTime[c] < Expiry
        /\ openHandle[c] # NoHandle
        /\ openHandle[c].revision \in retainedRevisions[c]
        /\ openHandle[c].key \in
              Bundle(openHandle[c].revision).capabilities
        /\ openHandle[c].key \notin cached[c]
        /\ lazyBudget[c] > 0
        /\ lazyPending[c] = NoLazyRequest
        /\ lazyWire[c] = {}
        /\ lazyPending' = [lazyPending EXCEPT ![c] = request]
        /\ requestLog' = requestLog \cup {LazyAudit(request, localTime[c])}
        /\ lazyBudget' = [lazyBudget EXCEPT ![c] = @ - 1]
        /\ UNCHANGED <<storeVars, rootPending, rootWire, lazyWire, accepted,
                        retainedRevisions, openHandle, cached, returnedLog,
                        lazySuccessLog, durableWatermark, restartPending,
                        bootstrapRootRequested, recoveredAfterRestart,
                        unmountRequested, physicallyMounted,
                        physicalUnmountFailed, servedCachedAfterExpiry,
                        rejectedUnauthenticated, rejectedFork,
                        rejectedDurableRollback, rejectedBadLazy,
                        environmentVars>>

S3ReturnLazyObject(c) ==
    LET request == lazyPending[c]
    IN  /\ c \in Consumers
        /\ connected[c]
        /\ storeUp
        /\ serverTime < Expiry
        /\ request # NoLazyRequest
        /\ request.key \in immutableObjects
        /\ lazyWire[c] = {}
        /\ lazyPending' = [lazyPending EXCEPT ![c] = NoLazyRequest]
        /\ lazyWire' =
              [lazyWire EXCEPT ![c] = {GoodLazyResponse(request)}]
        /\ lazySuccessLog' =
              lazySuccessLog \cup {LazySuccess(request, serverTime)}
        /\ UNCHANGED <<storeVars, requestLog, rootPending, rootWire,
                        accepted, retainedRevisions, openHandle, cached,
                        returnedLog, lazyBudget, durableWatermark,
                        restartPending, bootstrapRootRequested,
                        recoveredAfterRestart, unmountRequested,
                        physicallyMounted, physicalUnmountFailed,
                        servedCachedAfterExpiry, rejectedUnauthenticated,
                        rejectedFork, rejectedDurableRollback,
                        rejectedBadLazy, environmentVars>>

S3ReturnBadLazyResponse(c) ==
    LET request == lazyPending[c]
    IN  /\ c \in Consumers
        /\ AdversarialMode
        /\ ~stableNetwork
        /\ connected[c]
        /\ request # NoLazyRequest
        /\ lazyWire[c] = {}
        /\ lazyPending' = [lazyPending EXCEPT ![c] = NoLazyRequest]
        /\ lazyWire' = [lazyWire EXCEPT ![c] = {BadLazyResponse(request)}]
        /\ UNCHANGED <<storeVars, requestLog, rootPending, rootWire,
                        consumerVars, environmentVars>>

S3RejectExpiredLazy(c) ==
    /\ c \in Consumers
    /\ serverTime = Expiry
    /\ lazyPending[c] # NoLazyRequest
    /\ lazyPending' = [lazyPending EXCEPT ![c] = NoLazyRequest]
    /\ UNCHANGED <<storeVars, requestLog, rootPending, rootWire, lazyWire,
                    consumerVars, environmentVars>>

DropLazyRequest(c) ==
    /\ c \in Consumers
    /\ NetworkFaultMode
    /\ ~stableNetwork
    /\ lazyPending[c] # NoLazyRequest
    /\ lazyPending' = [lazyPending EXCEPT ![c] = NoLazyRequest]
    /\ UNCHANGED <<storeVars, requestLog, rootPending, rootWire, lazyWire,
                    consumerVars, environmentVars>>

DropLazyResponse(c) ==
    /\ c \in Consumers
    /\ NetworkFaultMode
    /\ ~stableNetwork
    /\ lazyWire[c] # {}
    /\ lazyWire' = [lazyWire EXCEPT ![c] = {}]
    /\ UNCHANGED <<storeVars, requestLog, rootPending, rootWire, lazyPending,
                    consumerVars, environmentVars>>

ReturnPinnedBytes(c) ==
    /\ c \in Consumers
    /\ connected[c]
    /\ \E response \in lazyWire[c]:
          /\ response.valid
          /\ response.revision \in retainedRevisions[c]
          /\ response.requestedKey \in
                Bundle(response.revision).capabilities
          /\ response.returnedKey = response.requestedKey
          /\ response.bytesGeneration = response.pinnedGeneration
          /\ lazyWire' = [lazyWire EXCEPT ![c] = @ \ {response}]
          /\ cached' =
                [cached EXCEPT ![c] = @ \cup {response.requestedKey}]
          /\ returnedLog' = returnedLog \cup {ReturnedRecord(response)}
    /\ UNCHANGED <<storeVars, requestLog, rootPending, rootWire, lazyPending,
                    accepted, retainedRevisions, openHandle, lazySuccessLog,
                    lazyBudget, durableWatermark, restartPending,
                    bootstrapRootRequested, recoveredAfterRestart,
                    unmountRequested, physicallyMounted,
                    physicalUnmountFailed, servedCachedAfterExpiry,
                    rejectedUnauthenticated, rejectedFork,
                    rejectedDurableRollback, rejectedBadLazy, environmentVars>>

RejectBadLazyResponse(c) ==
    /\ c \in Consumers
    /\ \E response \in lazyWire[c]:
          /\ \/ ~response.valid
             \/ response.returnedKey # response.requestedKey
             \/ response.bytesGeneration # response.pinnedGeneration
          /\ lazyWire' = [lazyWire EXCEPT ![c] = @ \ {response}]
    /\ rejectedBadLazy' = TRUE
    /\ UNCHANGED <<storeVars, requestLog, rootPending, rootWire, lazyPending,
                    accepted, retainedRevisions, openHandle, cached,
                    returnedLog, lazySuccessLog, lazyBudget,
                    durableWatermark, restartPending, bootstrapRootRequested,
                    recoveredAfterRestart,
                    unmountRequested, physicallyMounted,
                    physicalUnmountFailed, servedCachedAfterExpiry,
                    rejectedUnauthenticated, rejectedFork,
                    rejectedDurableRollback, environmentVars>>

(***************************************************************************
CrashRestart represents destruction of B's process-local Reader/Consumer.
The durable generation+commit watermark and the original RootKey bearer are
outside that volatile process and survive.  Installed exact capabilities,
in-flight messages, handles, and cache do not.  The fresh process must take
StartRootBootstrap before any immutable-object request can become enabled.

The restart configuration crashes only after revision MaxRevision is durable;
this keeps the small CI instance focused on the security-relevant case where
S3 can replay an older valid root after B has already observed a newer one.
***************************************************************************)
CrashRestart(c) ==
    /\ c \in Consumers
    /\ RestartMode
    /\ ~restartPending[c]
    /\ ~recoveredAfterRestart[c]
    /\ accepted[c] = Bundle(MaxRevision)
    /\ durableWatermark[c] = BundleWatermark(Bundle(MaxRevision))
    /\ rootPending' = [rootPending EXCEPT ![c] = NoRootRequest]
    /\ rootWire' = [rootWire EXCEPT ![c] = {}]
    /\ lazyPending' = [lazyPending EXCEPT ![c] = NoLazyRequest]
    /\ lazyWire' = [lazyWire EXCEPT ![c] = {}]
    /\ accepted' = [accepted EXCEPT ![c] = NoBundle]
    /\ retainedRevisions' = [retainedRevisions EXCEPT ![c] = {}]
    /\ openHandle' = [openHandle EXCEPT ![c] = NoHandle]
    /\ cached' = [cached EXCEPT ![c] = {}]
    /\ lazyBudget' = [lazyBudget EXCEPT ![c] = InitialLazyBudget]
    /\ restartPending' = [restartPending EXCEPT ![c] = TRUE]
    /\ bootstrapRootRequested' =
          [bootstrapRootRequested EXCEPT ![c] = FALSE]
    /\ recoveredAfterRestart' =
          [recoveredAfterRestart EXCEPT ![c] = FALSE]
    /\ UNCHANGED <<storeVars, requestLog, returnedLog, lazySuccessLog,
                    durableWatermark, unmountRequested, physicallyMounted,
                    physicalUnmountFailed, servedCachedAfterExpiry,
                    rejectedUnauthenticated, rejectedFork,
                    rejectedDurableRollback, rejectedBadLazy,
                    environmentVars>>

PartitionNetwork(c) ==
    /\ c \in Consumers
    /\ NetworkFaultMode
    /\ ~stableNetwork
    /\ connected[c]
    /\ connected' = [connected EXCEPT ![c] = FALSE]
    /\ UNCHANGED <<storeVars, wireVars, consumerVars, storeUp,
                    stableNetwork, serverTime, localTime>>

RestoreNetwork(c) ==
    /\ c \in Consumers
    /\ NetworkFaultMode
    /\ ~stableNetwork
    /\ ~connected[c]
    /\ connected' = [connected EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<storeVars, wireVars, consumerVars, storeUp,
                    stableNetwork, serverTime, localTime>>

SetStoreUnavailable ==
    /\ NetworkFaultMode
    /\ ~stableNetwork
    /\ storeUp
    /\ storeUp' = FALSE
    /\ UNCHANGED <<storeVars, wireVars, consumerVars, connected,
                    stableNetwork, serverTime, localTime>>

SetStoreAvailable ==
    /\ NetworkFaultMode
    /\ ~stableNetwork
    /\ ~storeUp
    /\ storeUp' = TRUE
    /\ UNCHANGED <<storeVars, wireVars, consumerVars, connected,
                    stableNetwork, serverTime, localTime>>

StabilizeNetwork ==
    /\ CanStabilize
    /\ ~stableNetwork
    /\ stableNetwork' = TRUE
    /\ connected' = [c \in Consumers |-> TRUE]
    /\ storeUp' = TRUE
    /\ UNCHANGED <<storeVars, wireVars, consumerVars,
                    serverTime, localTime>>

AdvanceServerClock ==
    /\ ExpiryMode
    /\ serverTime < Expiry
    /\ serverTime' = serverTime + 1
    /\ UNCHANGED <<storeVars, wireVars, consumerVars, connected,
                    storeUp, stableNetwork, localTime>>

AdvanceLocalClock(c) ==
    LET nextTime == localTime[c] + 1
    IN  /\ c \in Consumers
        /\ ExpiryMode
        /\ localTime[c] < Expiry
        /\ localTime' = [localTime EXCEPT ![c] = nextTime]
        /\ unmountRequested' =
              [unmountRequested EXCEPT
                  ![c] = IF nextTime = Expiry THEN TRUE ELSE @]
        /\ UNCHANGED <<storeVars, wireVars, accepted, retainedRevisions,
                        openHandle, cached, returnedLog, lazySuccessLog,
                        lazyBudget, durableWatermark, restartPending,
                        bootstrapRootRequested, recoveredAfterRestart,
                        physicallyMounted,
                        physicalUnmountFailed, servedCachedAfterExpiry,
                        rejectedUnauthenticated, rejectedFork,
                        rejectedDurableRollback, rejectedBadLazy, connected,
                        storeUp, stableNetwork, serverTime>>

PhysicalUnmountFailed(c) ==
    /\ c \in Consumers
    /\ ExpiryMode
    /\ unmountRequested[c]
    /\ physicallyMounted[c]
    /\ ~physicalUnmountFailed[c]
    /\ physicalUnmountFailed' =
          [physicalUnmountFailed EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<storeVars, wireVars, accepted, retainedRevisions,
                    openHandle, cached, returnedLog, lazySuccessLog,
                    lazyBudget, durableWatermark, restartPending,
                    bootstrapRootRequested, recoveredAfterRestart,
                    unmountRequested, physicallyMounted,
                    servedCachedAfterExpiry, rejectedUnauthenticated,
                    rejectedFork, rejectedDurableRollback, rejectedBadLazy,
                    environmentVars>>

CompletePhysicalUnmount(c) ==
    /\ c \in Consumers
    /\ ExpiryMode
    /\ unmountRequested[c]
    /\ physicallyMounted[c]
    /\ physicallyMounted' = [physicallyMounted EXCEPT ![c] = FALSE]
    /\ openHandle' = [openHandle EXCEPT ![c] = NoHandle]
    /\ UNCHANGED <<storeVars, wireVars, accepted, retainedRevisions, cached,
                    returnedLog, lazySuccessLog, lazyBudget,
                    durableWatermark, restartPending, bootstrapRootRequested,
                    recoveredAfterRestart,
                    unmountRequested, physicalUnmountFailed,
                    servedCachedAfterExpiry, rejectedUnauthenticated,
                    rejectedFork, rejectedDurableRollback, rejectedBadLazy,
                    environmentVars>>

ServeCachedAfterExpiry(c) ==
    /\ c \in Consumers
    /\ ExpiryMode
    /\ localTime[c] = Expiry
    /\ unmountRequested[c]
    /\ physicallyMounted[c]
    /\ physicalUnmountFailed[c]
    /\ cached[c] # {}
    /\ ~servedCachedAfterExpiry[c]
    /\ servedCachedAfterExpiry' =
          [servedCachedAfterExpiry EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<storeVars, wireVars, accepted, retainedRevisions,
                    openHandle, cached, returnedLog, lazySuccessLog,
                    lazyBudget, durableWatermark, restartPending,
                    bootstrapRootRequested, recoveredAfterRestart,
                    unmountRequested, physicallyMounted,
                    physicalUnmountFailed, rejectedUnauthenticated,
                    rejectedFork, rejectedDurableRollback, rejectedBadLazy,
                    environmentVars>>

Next ==
    \/ PublishRoot
    \/ \E c \in Consumers:
          \/ StartRootPoll(c)
          \/ StartRootBootstrap(c)
          \/ S3ReturnChangedRoot(c)
          \/ S3ReturnDurableRollback(c)
          \/ S3ReturnNotModified(c)
          \/ S3RootMissing(c)
          \/ S3RejectExpiredRoot(c)
          \/ DropRootRequest(c)
          \/ DropRootResponse(c)
          \/ S3ReturnTamperedRoot(c)
          \/ S3ReturnSignedFork(c)
          \/ AcceptAuthenticatedBundle(c)
          \/ RecoverAuthenticatedBundleAfterRestart(c)
          \/ RecoverAuthenticatedBundleAfterRejectedRollback(c)
          \/ RejectUnauthenticatedBundle(c)
          \/ RejectRollbackOrFork(c)
          \/ RejectDurableRollbackAfterRestart(c)
          \/ IgnoreStaleBundle(c)
          \/ OpenPinned(c)
          \/ ClosePinned(c)
          \/ StartLazyGet(c)
          \/ S3ReturnLazyObject(c)
          \/ S3ReturnBadLazyResponse(c)
          \/ S3RejectExpiredLazy(c)
          \/ DropLazyRequest(c)
          \/ DropLazyResponse(c)
          \/ ReturnPinnedBytes(c)
          \/ RejectBadLazyResponse(c)
          \/ CrashRestart(c)
          \/ PartitionNetwork(c)
          \/ RestoreNetwork(c)
          \/ AdvanceLocalClock(c)
          \/ PhysicalUnmountFailed(c)
          \/ CompletePhysicalUnmount(c)
          \/ ServeCachedAfterExpiry(c)
    \/ SetStoreUnavailable
    \/ SetStoreAvailable
    \/ StabilizeNetwork
    \/ AdvanceServerClock

Spec == Init /\ [][Next]_vars

(***************************************************************************
Safety predicates.  Bearer possession and signer/credential absence are
constants in this abstraction: no transition can manufacture broader S3
authority.  The append-only request log is the observable refinement point
for checking that consumers perform only S3 GETs to RootKey or authenticated
exact immutable keys.
***************************************************************************)
ConsumerHasRootBearer(c) == c \in Consumers
ConsumerHasFullS3Credential(c) == FALSE
ConsumerCanSign(c) == FALSE

TypeOK ==
    /\ rootObject \in GoodBundles \cup {NoBundle}
    /\ rootHistory \subseteq GoodBundles
    /\ immutableObjects \subseteq ObjectKeys
    /\ requestLog \subseteq AllAudits
    /\ rootPending \in [Consumers -> 0..(MaxRevision + 1)]
    /\ rootWire \in [Consumers -> SUBSET WireBundles]
    /\ \A c \in Consumers: Cardinality(rootWire[c]) <= 2
    /\ lazyPending \in [Consumers -> LazyRequests \cup {NoLazyRequest}]
    /\ \A c \in Consumers:
          lazyPending[c] = NoLazyRequest
          \/ lazyPending[c].consumer = c
    /\ lazyWire \in [Consumers -> SUBSET LazyResponses]
    /\ \A c \in Consumers:
          /\ Cardinality(lazyWire[c]) <= 1
          /\ \A response \in lazyWire[c]: response.consumer = c
    /\ accepted \in [Consumers -> GoodBundles \cup {NoBundle}]
    /\ retainedRevisions \in [Consumers -> SUBSET Revisions]
    /\ \A c \in Consumers:
          Cardinality(retainedRevisions[c]) <= RetentionLimit
    /\ openHandle \in [Consumers -> Handles \cup {NoHandle}]
    /\ cached \in [Consumers -> SUBSET ObjectKeys]
    /\ returnedLog \subseteq AllReturnedRecords
    /\ lazySuccessLog \subseteq AllLazySuccesses
    /\ lazyBudget \in [Consumers -> 0..InitialLazyBudget]
    /\ durableWatermark \in [Consumers -> Watermarks \cup {NoWatermark}]
    /\ restartPending \in [Consumers -> BOOLEAN]
    /\ bootstrapRootRequested \in [Consumers -> BOOLEAN]
    /\ recoveredAfterRestart \in [Consumers -> BOOLEAN]
    /\ connected \in [Consumers -> BOOLEAN]
    /\ storeUp \in BOOLEAN
    /\ stableNetwork \in BOOLEAN
    /\ serverTime \in Times
    /\ localTime \in [Consumers -> Times]
    /\ unmountRequested \in [Consumers -> BOOLEAN]
    /\ physicallyMounted \in [Consumers -> BOOLEAN]
    /\ physicalUnmountFailed \in [Consumers -> BOOLEAN]
    /\ servedCachedAfterExpiry \in [Consumers -> BOOLEAN]
    /\ rejectedUnauthenticated \in BOOLEAN
    /\ rejectedFork \in BOOLEAN
    /\ rejectedDurableRollback \in [Consumers -> BOOLEAN]
    /\ rejectedBadLazy \in BOOLEAN

BearerAuthorityOnly ==
    /\ \A c \in Consumers:
          /\ ConsumerHasRootBearer(c)
          /\ ~ConsumerHasFullS3Credential(c)
          /\ ~ConsumerCanSign(c)
    /\ \A request \in requestLog: request.consumer \in Consumers

OnlyS3ExactGetRequests ==
    \A request \in requestLog:
        /\ request.consumer \in Consumers
        /\ request.target = "S3"
        /\ request.method = "GET"
        /\ request.issuedLocalTime < Expiry
        /\ \/ /\ request.route = "root"
              /\ request.key = RootKey
              /\ request.capabilityRevision = 0
              /\ ConsumerHasRootBearer(request.consumer)
           \/ /\ request.route = "immutable-object"
              /\ request.capabilityRevision \in Revisions
              /\ Bundle(request.capabilityRevision).generation <=
                    durableWatermark[request.consumer].generation
              /\ request.key \in
                    Bundle(request.capabilityRevision).capabilities

AuthenticatedBundlesBindAllAuthority ==
    \A c \in Consumers:
        /\ \A revision \in retainedRevisions[c]:
              BundleAuthenticated(Bundle(revision))
        /\ accepted[c] = NoBundle \/ BundleAuthenticated(accepted[c])
        /\ durableWatermark[c] = NoWatermark
           \/ durableWatermark[c] \in Watermarks

VolatileAuthorityDoesNotCrossDurableWatermark ==
    \A c \in Consumers:
        /\ accepted[c] = NoBundle
           \/ BundleWatermark(accepted[c]) = durableWatermark[c]
        /\ \A revision \in retainedRevisions[c]:
              Bundle(revision).generation <=
                  durableWatermark[c].generation

RestartPendingHasNoInstalledAuthority ==
    \A c \in Consumers:
        restartPending[c] =>
            /\ accepted[c] = NoBundle
            /\ retainedRevisions[c] = {}
            /\ openHandle[c] = NoHandle
            /\ cached[c] = {}
            /\ lazyPending[c] = NoLazyRequest
            /\ lazyWire[c] = {}

RestartBootstrapUsesSameFixedRootBearer ==
    \A c \in Consumers:
        (bootstrapRootRequested[c] \/ recoveredAfterRestart[c]) =>
            /\ ConsumerHasRootBearer(c)
            /\ ~ConsumerHasFullS3Credential(c)
            /\ ~ConsumerCanSign(c)
            /\ \E issuedAt \in Times:
                  RootAudit(c, issuedAt) \in requestLog

RecoveredAuthorityExtendsDurableWatermark ==
    \A c \in Consumers:
        recoveredAfterRestart[c] =>
            /\ ~restartPending[c]
            /\ bootstrapRootRequested[c]
            /\ accepted[c] # NoBundle
            /\ BundleWatermark(accepted[c]) = durableWatermark[c]
            /\ accepted[c].revision \in retainedRevisions[c]

RetainedBundleHistoryDoesNotFork ==
    \A c \in Consumers:
        /\ \A revision \in retainedRevisions[c]:
              /\ revision <= accepted[c].revision
              /\ Bundle(revision).generation <= accepted[c].generation
        /\ \A r1, r2 \in retainedRevisions[c]:
              /\ r1 < r2 =>
                    Bundle(r1).generation <= Bundle(r2).generation
              /\ Bundle(r1).generation = Bundle(r2).generation =>
                    Bundle(r1).commit = Bundle(r2).commit

PublishedRootHasCompleteImmutableClosure ==
    /\ rootObject = NoBundle
       \/ rootObject.capabilities \subseteq immutableObjects
    /\ \A bundle \in rootHistory:
          bundle.capabilities \subseteq immutableObjects

RootHistoryIsOneLinearRegister ==
    /\ \A bundle \in rootHistory:
          bundle.revision <= rootObject.revision
    /\ \A r \in Revisions:
          Bundle(r) \in rootHistory =>
              \A earlier \in 1..r: Bundle(earlier) \in rootHistory

SuccessfulLazyGetsWereAuthorizedBeforeServiceExpiry ==
    \A success \in lazySuccessLog:
        /\ success.succeededAt < Expiry
        /\ success.revision \in Revisions
        /\ success.key \in Bundle(success.revision).capabilities

ReturnedBytesMatchPinnedGeneration ==
    \A returned \in returnedLog:
        /\ returned.bytesGeneration = returned.pinnedGeneration
        /\ returned.key.generation = returned.pinnedGeneration

CachedBytesCameFromVerifiedReturns ==
    \A c \in Consumers:
        \A key \in cached[c]:
            \E returned \in returnedLog:
                /\ returned.consumer = c
                /\ returned.key = key
                /\ returned.bytesGeneration = key.generation

LocalExpiryRequestsUnmount ==
    \A c \in Consumers:
        localTime[c] = Expiry => unmountRequested[c]

UnmountIsNotClaimedAsRevocation ==
    \A c \in Consumers:
        /\ ~physicallyMounted[c] => unmountRequested[c]
        /\ servedCachedAfterExpiry[c] =>
              /\ unmountRequested[c]
              /\ physicalUnmountFailed[c]
              /\ cached[c] # {}

RootRevisionNeverRegresses ==
    [][rootObject'.revision >= rootObject.revision]_vars

AcceptedRevisionAndGenerationNeverRegressOrFork ==
    [][\A c \in Consumers:
          /\ accepted'[c].revision >= accepted[c].revision
          /\ accepted'[c].generation >= accepted[c].generation
          /\ accepted'[c].generation = accepted[c].generation =>
                accepted'[c].commit = accepted[c].commit]_vars

DurableWatermarkNeverRegressesOrForks ==
    [][\A c \in Consumers:
          /\ durableWatermark'[c].generation >=
                durableWatermark[c].generation
          /\ durableWatermark'[c].generation =
                durableWatermark[c].generation =>
                    durableWatermark'[c].commit =
                        durableWatermark[c].commit]_vars

CrashClearsOnlyVolatileAuthority ==
    [][\A c \in Consumers:
          (~restartPending[c] /\ restartPending'[c]) =>
              /\ durableWatermark'[c] = durableWatermark[c]
              /\ accepted'[c] = NoBundle
              /\ retainedRevisions'[c] = {}
              /\ openHandle'[c] = NoHandle
              /\ cached'[c] = {}
              /\ ~bootstrapRootRequested'[c]]_vars

DurableRollbackRejectionFailsClosed ==
    [][\A c \in Consumers:
          (~rejectedDurableRollback[c]
           /\ rejectedDurableRollback'[c]) =>
              /\ restartPending'[c]
              /\ accepted'[c] = accepted[c]
              /\ retainedRevisions'[c] = retainedRevisions[c]
              /\ durableWatermark'[c] = durableWatermark[c]]_vars

RestartRecoveryExtendsPreviousWatermark ==
    [][\A c \in Consumers:
          (~recoveredAfterRestart[c] /\ recoveredAfterRestart'[c]) =>
              /\ bootstrapRootRequested[c]
              /\ ExtendsWatermark(accepted'[c], durableWatermark[c])
              /\ BundleWatermark(accepted'[c]) =
                    durableWatermark'[c]]_vars

RetainedCapabilitiesNeverDisappear ==
    [][\A c \in Consumers:
          retainedRevisions[c] \subseteq retainedRevisions'[c]]_vars

CachedBytesCannotBeRevoked ==
    [][\A c \in Consumers: cached[c] \subseteq cached'[c]]_vars

ReturnedBytesCannotBeRevoked ==
    [][returnedLog \subseteq returnedLog']_vars

ImmutableObjectsNeverDisappear ==
    [][immutableObjects \subseteq immutableObjects']_vars

(***************************************************************************
Liveness is conditional.  Weak fairness alone gives no finite-time deadline,
so the WindowStep conjunct in FairNext states the precise "enough
authorization window" assumption: once the network/store are stable while
resources can still complete the target, service and local clocks do not reach
expiry before convergence.  Without TimelyStable the leads-to property is
vacuous; this is intentional for an unbounded partition, exhausted retention
budget, or late stabilization.
***************************************************************************)
TargetKey == CHOOSE key \in Capabilities(MaxRevision): TRUE

TargetFetchFunded(c) ==
    \/ TargetKey \in cached[c]
    \/ lazyBudget[c] > 0
    \/ /\ lazyPending[c] # NoLazyRequest
       /\ lazyPending[c].key = TargetKey
    \/ \E response \in lazyWire[c]:
          /\ response.valid
          /\ response.requestedKey = TargetKey

ResourcesSufficient ==
    /\ RetentionLimit >= MaxRevision
    /\ \A c \in Consumers: TargetFetchFunded(c)

Converged ==
    /\ rootObject = Bundle(MaxRevision)
    /\ \A c \in Consumers:
          /\ accepted[c] = Bundle(MaxRevision)
          /\ TargetKey \in cached[c]

TimelyStable ==
    /\ stableNetwork
    /\ storeUp
    /\ serverTime < Expiry
    /\ \A c \in Consumers:
          /\ connected[c]
          /\ localTime[c] < Expiry
    /\ ResourcesSufficient

WindowStep ==
    (TimelyStable /\ ~Converged) =>
        /\ serverTime' = serverTime
        /\ localTime' = localTime

FairNext == Next /\ WindowStep

ConvergingConsumerStep(c) ==
    \/ /\ rootObject # NoBundle
       /\ accepted[c].revision < rootObject.revision
       /\ rootWire[c] = {}
       /\ StartRootPoll(c)
    \/ /\ rootObject \notin rootWire[c]
       /\ S3ReturnChangedRoot(c)
    \/ AcceptAuthenticatedBundle(c)
    \/ RejectUnauthenticatedBundle(c)
    \/ RejectRollbackOrFork(c)
    \/ IgnoreStaleBundle(c)
    \/ OpenPinned(c)
    \/ StartLazyGet(c)
    \/ S3ReturnLazyObject(c)
    \/ ReturnPinnedBytes(c)
    \/ RejectBadLazyResponse(c)
    \/ ClosePinned(c)

FairSpec ==
    /\ Init
    /\ [][FairNext]_vars
    /\ WF_vars(PublishRoot)
    /\ \A c \in Consumers: WF_vars(ConvergingConsumerStep(c))

TimelyStableConsumersConverge == TimelyStable ~> Converged

(***************************************************************************
CI partial-order reduction for multiple consumers.  Consumers never mutate
each other or RootKey, so their local protocol transitions commute.  The
configured primary consumer is explored first; another consumer remains
pristine until the primary has either completed the configured target or
locally expired.  The two-consumer configuration still exercises every local
state and network/expiry fault for both clients without multiplying all pairs
of independent intermediate states.  The one-consumer revision configuration
satisfies this constraint trivially.
***************************************************************************)
ConsumerPristine(c) ==
    /\ rootPending[c] = NoRootRequest
    /\ rootWire[c] = {}
    /\ lazyPending[c] = NoLazyRequest
    /\ lazyWire[c] = {}
    /\ accepted[c] = NoBundle
    /\ retainedRevisions[c] = {}
    /\ openHandle[c] = NoHandle
    /\ cached[c] = {}
    /\ lazyBudget[c] = InitialLazyBudget
    /\ durableWatermark[c] = NoWatermark
    /\ ~restartPending[c]
    /\ ~bootstrapRootRequested[c]
    /\ ~recoveredAfterRestart[c]
    /\ ~rejectedDurableRollback[c]
    /\ localTime[c] = 0
    /\ ~unmountRequested[c]
    /\ ~physicalUnmountFailed[c]
    /\ ~servedCachedAfterExpiry[c]
    /\ \A request \in requestLog: request.consumer # c

PrimaryConsumerSettled ==
    \/ localTime[PrimaryConsumer] = Expiry
    \/ /\ accepted[PrimaryConsumer] = Bundle(MaxRevision)
       /\ TargetKey \in cached[PrimaryConsumer]
       /\ rootPending[PrimaryConsumer] = NoRootRequest
       /\ rootWire[PrimaryConsumer] = {}
       /\ lazyPending[PrimaryConsumer] = NoLazyRequest
       /\ lazyWire[PrimaryConsumer] = {}
       /\ openHandle[PrimaryConsumer] = NoHandle

ConsumerCompositionConstraint ==
    \A c \in Consumers \ {PrimaryConsumer}:
        ConsumerPristine(c) \/ PrimaryConsumerSettled

=============================================================================
