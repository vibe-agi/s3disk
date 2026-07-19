------------------------------ MODULE S3Disk ------------------------------
EXTENDS Naturals, FiniteSets

(***************************************************************************
This model specifies one repository/channel, competing signed publishers, and
multiple read-only consumers.

Each published generation abstracts:
  * one immutable, hash-addressed closure of file data;
  * one immutable, verified commit/root-manifest anchor; and
  * one reference whose signature binds repository, channel, generation, and
    commit identity.

"latest" is the only remotely mutable object. A winning publisher CAS is its
linearization point. The local publisher first persists a pending intent whose
base is its committed anchor. It clears that intent only after proving which
authorized reference the remote history exposes; this includes recovery when
the CAS applied but its response was lost and when a competing branch won.

The network may delay, duplicate, reorder, or drop responses. An attacker may
also inject a reference whose structure and referenced hashes are valid but
whose authorization is not. Consumers verify authorization and metadata,
persist an anti-rollback watermark, and only then activate a view.
***************************************************************************)

CONSTANTS Consumers, MaxGeneration, Repository, Channel

ASSUME /\ Consumers # {}
       /\ MaxGeneration \in Nat \ {0}

Generations == 1..MaxGeneration

(***************************************************************************
Reference values explicitly retain commit identity. Commit 0 represents an
attacker-controlled, structurally valid and hash-valid commit identity. The
model does not implement cryptography: Authorized is the abstraction boundary
for successful signature verification in the selected repository/channel.
***************************************************************************)
NoReference == [generation |-> 0, commit |-> 0]
SignedReference(g) == [generation |-> g, commit |-> g]
ForgedReference(g) == [generation |-> g, commit |-> 0]
SignedReferences == {SignedReference(g) : g \in Generations}
ForgedReferences == {ForgedReference(g) : g \in Generations}
References == SignedReferences \cup ForgedReferences
ReferencesWithNone == References \cup {NoReference}

RefGeneration(ref) == ref.generation
RefCommit(ref) == ref.commit

(***************************************************************************
The publisher journal retains branch lineage independently of the compact
consumer abstraction above. BranchA and BranchB are two different, validly
signed commit identities for generation 1. A later abstract commit retains its
parent's lineage, so DirectPublisherSuccessor cannot reinterpret one target as
descending from a different committed branch. Every generation passes through
the same intent/CAS/proof/finalize protocol.

An intent is crash-persistent. publisherAttempt and publisherProof are
volatile: after a crash, the exact target stored in publisherPending is loaded
again. remotePublisherHistory is the single CAS-selected history, not the set
of all uploaded candidate commits.
***************************************************************************)
BranchA == 1
BranchB == 2
PublisherBranches == {BranchA, BranchB}

NoPublisherReference == [generation |-> 0, branch |-> 0]
PublisherReference(g, branch) == [generation |-> g, branch |-> branch]
PublisherReferences ==
    UNION {{PublisherReference(g, branch) :
              branch \in PublisherBranches} : g \in Generations}
PublisherReferencesWithNone ==
    PublisherReferences \cup {NoPublisherReference}

PublisherBranch(ref) == ref.branch
NoPublisherIntent ==
    [base |-> NoPublisherReference, target |-> NoPublisherReference]
PublisherIntent(base, target) == [base |-> base, target |-> target]

DirectPublisherSuccessor(base, target) ==
    /\ target \in PublisherReferences
    /\ RefGeneration(target) = RefGeneration(base) + 1
    /\ \/ base = NoPublisherReference
       \/ /\ base \in PublisherReferences
          /\ PublisherBranch(target) = PublisherBranch(base)

PublisherReferenceAuthorized(ref) == ref \in PublisherReferences

VARIABLES
    uploadedData,       \* immutable data closures durably stored
    validData,          \* stored data closures that currently hash correctly
    storedManifests,    \* immutable commit/root anchors durably stored
    validManifests,     \* anchors that currently hash and parse correctly
    published,          \* generations that won the latest CAS
    latest,             \* generation in the mutable latest reference
    wire,               \* in-flight authorized or attacker references
    known,              \* best in-process reference candidate, per consumer
    validated,          \* metadata-verified in-process reference
    durable,            \* crash-persistent generation/commit watermark
    view,               \* atomically exposed in-process mount reference
    openGen,            \* generation pinned by one abstract open handle
    lastReadGen,        \* generation of bytes returned through that handle
    connected,
    storeUp,
    stableNetwork,      \* also means no more process crashes
    rejectedUnauthorizedReference,
    rejectedBadResponse,
    returnedBadBytes,
    remotePublisherLatest,  \* signed reference currently exposed by latest
    remotePublisherHistory, \* the one CAS-selected signed reference per gen
    publisherCommitted,     \* durable, proven anti-rollback anchor
    publisherPending,       \* durable intent: {base, exact target}
    publisherAttempt,       \* volatile target loaded from pending
    publisherProof          \* volatile proof of the remote CAS-selected ref

Authorized(repo, channel, ref) ==
    /\ repo = Repository
    /\ channel = Channel
    /\ ref \in SignedReferences
    /\ RefGeneration(ref) \in published

protocolVars ==
    <<uploadedData, validData, storedManifests, validManifests,
      published, latest, wire, known, validated, durable, view, openGen,
      lastReadGen, connected, storeUp, stableNetwork,
      rejectedUnauthorizedReference, rejectedBadResponse, returnedBadBytes>>

publisherVars ==
    <<remotePublisherLatest, remotePublisherHistory, publisherCommitted,
      publisherPending, publisherAttempt, publisherProof>>

vars == <<protocolVars, publisherVars>>

Init ==
    /\ uploadedData = {}
    /\ validData = {}
    /\ storedManifests = {}
    /\ validManifests = {}
    /\ published = {}
    /\ latest = 0
    /\ wire = [c \in Consumers |-> {}]
    /\ known = [c \in Consumers |-> NoReference]
    /\ validated = [c \in Consumers |-> NoReference]
    /\ durable = [c \in Consumers |-> NoReference]
    /\ view = [c \in Consumers |-> NoReference]
    /\ openGen = [c \in Consumers |-> 0]
    /\ lastReadGen = [c \in Consumers |-> 0]
    /\ connected = [c \in Consumers |-> TRUE]
    /\ storeUp = TRUE
    /\ stableNetwork = FALSE
    /\ rejectedUnauthorizedReference = FALSE
    /\ rejectedBadResponse = FALSE
    /\ returnedBadBytes = FALSE
    /\ remotePublisherLatest = NoPublisherReference
    /\ remotePublisherHistory = {}
    /\ publisherCommitted = NoPublisherReference
    /\ publisherPending = NoPublisherIntent
    /\ publisherAttempt = NoPublisherReference
    /\ publisherProof = NoPublisherReference

(***************************************************************************
CI partial-order reduction: publisher-only transitions commute with consumer
transitions until a consumer has observed a reference. A new durable intent is
therefore selected only while consumer protocol state is pristine, and a
consumer step waits while an intent is unresolved. TLC still explores all
historical generations after publication, including stale replay and an open
handle spanning a later activation, without multiplying every consumer state
by every publisher crash/recovery phase.
***************************************************************************)
ConsumerProtocolPristine ==
    /\ wire = [c \in Consumers |-> {}]
    /\ known = [c \in Consumers |-> NoReference]
    /\ validated = [c \in Consumers |-> NoReference]
    /\ durable = [c \in Consumers |-> NoReference]
    /\ view = [c \in Consumers |-> NoReference]
    /\ openGen = [c \in Consumers |-> 0]
    /\ lastReadGen = [c \in Consumers |-> 0]
    /\ connected = [c \in Consumers |-> TRUE]
    /\ ~rejectedUnauthorizedReference
    /\ ~rejectedBadResponse
    /\ ~returnedBadBytes

PublisherJournalQuiescent ==
    /\ publisherPending = NoPublisherIntent
    /\ publisherAttempt = NoPublisherReference
    /\ publisherProof = NoPublisherReference
    /\ publisherCommitted = remotePublisherLatest

UploadData(g) ==
    /\ g \in Generations \ uploadedData
    /\ uploadedData' = uploadedData \cup {g}
    /\ validData' = validData \cup {g}
    /\ UNCHANGED <<storedManifests, validManifests, published, latest, wire,
                    known, validated, durable, view, openGen, lastReadGen,
                    connected, storeUp, stableNetwork,
                    rejectedUnauthorizedReference, rejectedBadResponse,
                    returnedBadBytes>>
    /\ UNCHANGED publisherVars

(***************************************************************************
A manifest can be installed only after every immutable object reachable from
it is durable. This is the model's StoreClosure assumption.
***************************************************************************)
PutManifest(g) ==
    /\ g \in uploadedData
    /\ g \notin storedManifests
    /\ storedManifests' = storedManifests \cup {g}
    /\ validManifests' = validManifests \cup {g}
    /\ UNCHANGED <<uploadedData, validData, published, latest, wire, known,
                    validated, durable, view, openGen, lastReadGen, connected,
                    storeUp, stableNetwork, rejectedUnauthorizedReference,
                    rejectedBadResponse, returnedBadBytes>>
    /\ UNCHANGED publisherVars

(***************************************************************************
The publisher protocol makes the local durability boundary explicit:

  RecordPublisherIntent
      -> RecoverPublisherPending
      -> one remote CAS winner
      -> ProveRemotePublisherHistory
      -> FinalizePublisherJournal

The remote CAS is the publication linearization point. The response-lost
action deliberately advances the remote history without advancing either the
durable publisher anchor or its volatile proof. A restarted publisher must
load the exact pending target and prove the remote winner before finalizing.
***************************************************************************)
RecordPublisherIntent(branch) ==
    LET g == latest + 1
        target == PublisherReference(g, branch)
    IN  /\ ConsumerProtocolPristine
        /\ publisherPending = NoPublisherIntent
        /\ publisherAttempt = NoPublisherReference
        /\ publisherProof = NoPublisherReference
        /\ publisherCommitted = remotePublisherLatest
        /\ g \in Generations
        /\ branch \in PublisherBranches
        /\ DirectPublisherSuccessor(publisherCommitted, target)
        /\ g \in validManifests
        /\ g \in validData
        /\ publisherPending' = PublisherIntent(publisherCommitted, target)
        /\ UNCHANGED <<publisherCommitted, publisherAttempt, publisherProof,
                        remotePublisherLatest, remotePublisherHistory>>
        /\ UNCHANGED protocolVars

RecoverPublisherPending ==
    /\ publisherPending # NoPublisherIntent
    /\ publisherAttempt = NoPublisherReference
    /\ publisherAttempt' = publisherPending.target
    /\ UNCHANGED <<remotePublisherLatest, remotePublisherHistory,
                    publisherCommitted, publisherPending, publisherProof>>
    /\ UNCHANGED protocolVars

PublisherCASAppliedResponseLost ==
    LET target == publisherPending.target
        g == RefGeneration(target)
    IN  /\ ~stableNetwork
        /\ storeUp
        /\ publisherPending # NoPublisherIntent
        /\ publisherAttempt = target
        /\ remotePublisherLatest = publisherPending.base
        /\ DirectPublisherSuccessor(remotePublisherLatest, target)
        /\ g = latest + 1
        /\ g \in validManifests
        /\ g \in validData
        /\ remotePublisherLatest' = target
        /\ remotePublisherHistory' = remotePublisherHistory \cup {target}
        /\ latest' = g
        /\ published' = published \cup {g}
        /\ UNCHANGED <<publisherCommitted, publisherPending,
                        publisherAttempt, publisherProof>>
        /\ UNCHANGED <<uploadedData, validData, storedManifests,
                        validManifests, wire, known, validated, durable, view,
                        openGen, lastReadGen, connected, storeUp, stableNetwork,
                        rejectedUnauthorizedReference, rejectedBadResponse,
                        returnedBadBytes>>

PublisherCASAppliedResponseReceived ==
    LET target == publisherPending.target
        g == RefGeneration(target)
    IN  /\ storeUp
        /\ publisherPending # NoPublisherIntent
        /\ publisherAttempt = target
        /\ publisherProof = NoPublisherReference
        /\ remotePublisherLatest = publisherPending.base
        /\ DirectPublisherSuccessor(remotePublisherLatest, target)
        /\ g = latest + 1
        /\ g \in validManifests
        /\ g \in validData
        /\ remotePublisherLatest' = target
        /\ remotePublisherHistory' = remotePublisherHistory \cup {target}
        /\ latest' = g
        /\ published' = published \cup {g}
        /\ publisherProof' = target
        /\ UNCHANGED <<publisherCommitted, publisherPending,
                        publisherAttempt>>
        /\ UNCHANGED <<uploadedData, validData, storedManifests,
                        validManifests, wire, known, validated, durable, view,
                        openGen, lastReadGen, connected, storeUp, stableNetwork,
                        rejectedUnauthorizedReference, rejectedBadResponse,
                        returnedBadBytes>>

(***************************************************************************
A second, correctly authorized publisher may race the journaled target with a
different commit for the same generation. CAS admits exactly one winner. The
local publisher subsequently proves and adopts that winner; it never changes
its committed anchor directly to its losing target.
***************************************************************************)
CompetingPublisherCASWins(winner) ==
    LET g == RefGeneration(winner)
    IN  /\ storeUp
        /\ publisherPending # NoPublisherIntent
        /\ remotePublisherLatest = publisherPending.base
        /\ DirectPublisherSuccessor(remotePublisherLatest, winner)
        /\ winner # publisherPending.target
        /\ g = latest + 1
        /\ g \in validManifests
        /\ g \in validData
        /\ remotePublisherLatest' = winner
        /\ remotePublisherHistory' = remotePublisherHistory \cup {winner}
        /\ latest' = g
        /\ published' = published \cup {g}
        /\ UNCHANGED <<publisherCommitted, publisherPending,
                        publisherAttempt, publisherProof>>
        /\ UNCHANGED <<uploadedData, validData, storedManifests,
                        validManifests, wire, known, validated, durable, view,
                        openGen, lastReadGen, connected, storeUp, stableNetwork,
                        rejectedUnauthorizedReference, rejectedBadResponse,
                        returnedBadBytes>>

ProveRemotePublisherHistory ==
    /\ storeUp
    /\ publisherPending # NoPublisherIntent
    /\ publisherAttempt = publisherPending.target
    /\ publisherProof # remotePublisherLatest
    /\ DirectPublisherSuccessor(publisherPending.base,
                                remotePublisherLatest)
    /\ publisherProof' = remotePublisherLatest
    /\ UNCHANGED <<remotePublisherLatest, remotePublisherHistory,
                    publisherCommitted, publisherPending, publisherAttempt>>
    /\ UNCHANGED protocolVars

FinalizePublisherJournal ==
    /\ publisherPending # NoPublisherIntent
    /\ publisherProof # NoPublisherReference
    /\ publisherProof = remotePublisherLatest
    /\ publisherProof \in remotePublisherHistory
    /\ DirectPublisherSuccessor(publisherPending.base, publisherProof)
    /\ publisherCommitted' = publisherProof
    /\ publisherPending' = NoPublisherIntent
    /\ publisherAttempt' = NoPublisherReference
    /\ publisherProof' = NoPublisherReference
    /\ UNCHANGED <<remotePublisherLatest, remotePublisherHistory>>
    /\ UNCHANGED protocolVars

PublisherCrashRestart ==
    /\ ~stableNetwork
    /\ publisherPending # NoPublisherIntent
    /\ (publisherAttempt # NoPublisherReference
        \/ publisherProof # NoPublisherReference)
    /\ publisherAttempt' = NoPublisherReference
    /\ publisherProof' = NoPublisherReference
    /\ UNCHANGED <<remotePublisherLatest, remotePublisherHistory,
                    publisherCommitted, publisherPending>>
    /\ UNCHANGED protocolVars

(***************************************************************************
PollResponse may put any historical, legitimately published reference on the
wire. This models stale reads, replay, duplication, and reordering.
***************************************************************************)
PollResponse(c, g) ==
    /\ c \in Consumers
    /\ PublisherJournalQuiescent
    /\ connected[c]
    /\ storeUp
    /\ g \in published
    /\ SignedReference(g) \notin wire[c]
    /\ wire' = [wire EXCEPT ![c] = @ \cup {SignedReference(g)}]
    /\ UNCHANGED <<uploadedData, validData, storedManifests, validManifests,
                    published, latest, known, validated, durable, view,
                    openGen, lastReadGen, connected, storeUp, stableNetwork,
                    rejectedUnauthorizedReference, rejectedBadResponse,
                    returnedBadBytes>>
    /\ UNCHANGED publisherVars

PollLatest(c) ==
    /\ latest > 0
    /\ PollResponse(c, latest)

(***************************************************************************
The attacker reference has a valid shape and an abstract hash-valid commit,
but it is not signed for this repository/channel/generation/commit tuple.
***************************************************************************)
AttackerInject(c, g) ==
    /\ c \in Consumers
    /\ PublisherJournalQuiescent
    /\ ForgedReference(g) \notin wire[c]
    /\ wire' = [wire EXCEPT ![c] = @ \cup {ForgedReference(g)}]
    /\ UNCHANGED <<uploadedData, validData, storedManifests, validManifests,
                    published, latest, known, validated, durable, view,
                    openGen, lastReadGen, connected, storeUp, stableNetwork,
                    rejectedUnauthorizedReference, rejectedBadResponse,
                    returnedBadBytes>>
    /\ UNCHANGED publisherVars

DropResponse(c, ref) ==
    /\ ~stableNetwork
    /\ c \in Consumers
    /\ PublisherJournalQuiescent
    /\ ref \in wire[c]
    /\ wire' = [wire EXCEPT ![c] = @ \ {ref}]
    /\ UNCHANGED <<uploadedData, validData, storedManifests, validManifests,
                    published, latest, known, validated, durable, view,
                    openGen, lastReadGen, connected, storeUp, stableNetwork,
                    rejectedUnauthorizedReference, rejectedBadResponse,
                    returnedBadBytes>>
    /\ UNCHANGED publisherVars

(***************************************************************************
Authorization is checked before a reference can become known. Even an
authorized replay must be strictly above both the durable watermark and the
current in-process candidate.
***************************************************************************)
ReceiveAuthorizedReference(c, ref) ==
    /\ c \in Consumers
    /\ PublisherJournalQuiescent
    /\ connected[c]
    /\ ref \in wire[c]
    /\ Authorized(Repository, Channel, ref)
    /\ wire' = [wire EXCEPT ![c] = @ \ {ref}]
    /\ known' = [known EXCEPT ![c] =
          IF RefGeneration(ref) > RefGeneration(durable[c])
             /\ RefGeneration(ref) > RefGeneration(@)
          THEN ref
          ELSE @]
    /\ UNCHANGED <<uploadedData, validData, storedManifests, validManifests,
                    published, latest, validated, durable, view, openGen,
                    lastReadGen, connected, storeUp, stableNetwork,
                    rejectedUnauthorizedReference, rejectedBadResponse,
                    returnedBadBytes>>
    /\ UNCHANGED publisherVars

RejectUnauthorizedReference(c, ref) ==
    /\ c \in Consumers
    /\ PublisherJournalQuiescent
    /\ connected[c]
    /\ ref \in wire[c]
    /\ ~Authorized(Repository, Channel, ref)
    /\ wire' = [wire EXCEPT ![c] = @ \ {ref}]
    /\ rejectedUnauthorizedReference' = TRUE
    /\ UNCHANGED <<uploadedData, validData, storedManifests, validManifests,
                    published, latest, known, validated, durable, view,
                    openGen, lastReadGen, connected, storeUp, stableNetwork,
                    rejectedBadResponse, returnedBadBytes>>
    /\ UNCHANGED publisherVars

ReceiveLatest(c) ==
    /\ latest > 0
    /\ ReceiveAuthorizedReference(c, SignedReference(latest))

(***************************************************************************
After a crash, the persistent watermark can seed the volatile candidate. It
does not bypass metadata verification before re-exposure.
***************************************************************************)
LoadDurable(c) ==
    /\ c \in Consumers
    /\ PublisherJournalQuiescent
    /\ durable[c] # NoReference
    /\ RefGeneration(known[c]) < RefGeneration(durable[c])
    /\ known' = [known EXCEPT ![c] = durable[c]]
    /\ UNCHANGED <<uploadedData, validData, storedManifests, validManifests,
                    published, latest, wire, validated, durable, view,
                    openGen, lastReadGen, connected, storeUp, stableNetwork,
                    rejectedUnauthorizedReference, rejectedBadResponse,
                    returnedBadBytes>>
    /\ UNCHANGED publisherVars

(***************************************************************************
Only the commit/root metadata anchor is fetched before activation. File data
is deliberately absent from this transition, preserving lazy reads.
***************************************************************************)
FetchKnownManifest(c) ==
    /\ c \in Consumers
    /\ PublisherJournalQuiescent
    /\ connected[c]
    /\ storeUp
    /\ known[c] # NoReference
    /\ Authorized(Repository, Channel, known[c])
    /\ RefGeneration(known[c]) \in validManifests
    /\ validated[c] # known[c]
    /\ validated' = [validated EXCEPT ![c] = known[c]]
    /\ UNCHANGED <<uploadedData, validData, storedManifests, validManifests,
                    published, latest, wire, known, durable, view, openGen,
                    lastReadGen, connected, storeUp, stableNetwork,
                    rejectedUnauthorizedReference, rejectedBadResponse,
                    returnedBadBytes>>
    /\ UNCHANGED publisherVars

(***************************************************************************
The anti-rollback watermark is persisted before activation. A crash between
this step and ActivatePersisted is safe: restart retains the newer watermark.
***************************************************************************)
PersistValidated(c) ==
    /\ c \in Consumers
    /\ PublisherJournalQuiescent
    /\ validated[c] # NoReference
    /\ Authorized(Repository, Channel, validated[c])
    /\ RefGeneration(validated[c]) > RefGeneration(durable[c])
    /\ durable' = [durable EXCEPT ![c] = validated[c]]
    /\ UNCHANGED <<uploadedData, validData, storedManifests, validManifests,
                    published, latest, wire, known, validated, view, openGen,
                    lastReadGen, connected, storeUp, stableNetwork,
                    rejectedUnauthorizedReference, rejectedBadResponse,
                    returnedBadBytes>>
    /\ UNCHANGED publisherVars

ActivatePersisted(c) ==
    /\ c \in Consumers
    /\ PublisherJournalQuiescent
    /\ durable[c] # NoReference
    /\ validated[c] = durable[c]
    /\ RefGeneration(durable[c]) > RefGeneration(view[c])
    /\ view' = [view EXCEPT ![c] = durable[c]]
    /\ UNCHANGED <<uploadedData, validData, storedManifests, validManifests,
                    published, latest, wire, known, validated, durable,
                    openGen, lastReadGen, connected, storeUp, stableNetwork,
                    rejectedUnauthorizedReference, rejectedBadResponse,
                    returnedBadBytes>>
    /\ UNCHANGED publisherVars

(***************************************************************************
Open pins the current generation. A later Activate cannot change openGen.
***************************************************************************)
Open(c) ==
    /\ c \in Consumers
    /\ PublisherJournalQuiescent
    /\ openGen[c] = 0
    /\ view[c] # NoReference
    /\ openGen' = [openGen EXCEPT ![c] = RefGeneration(view[c])]
    /\ lastReadGen' = [lastReadGen EXCEPT ![c] = 0]
    /\ UNCHANGED <<uploadedData, validData, storedManifests, validManifests,
                    published, latest, wire, known, validated, durable, view,
                    connected, storeUp, stableNetwork,
                    rejectedUnauthorizedReference, rejectedBadResponse,
                    returnedBadBytes>>
    /\ UNCHANGED publisherVars

Close(c) ==
    /\ c \in Consumers
    /\ PublisherJournalQuiescent
    /\ openGen[c] > 0
    /\ openGen' = [openGen EXCEPT ![c] = 0]
    /\ lastReadGen' = [lastReadGen EXCEPT ![c] = 0]
    /\ UNCHANGED <<uploadedData, validData, storedManifests, validManifests,
                    published, latest, wire, known, validated, durable, view,
                    connected, storeUp, stableNetwork,
                    rejectedUnauthorizedReference, rejectedBadResponse,
                    returnedBadBytes>>
    /\ UNCHANGED publisherVars

ReturnVerifiedBytes(c) ==
    /\ c \in Consumers
    /\ PublisherJournalQuiescent
    /\ connected[c]
    /\ storeUp
    /\ openGen[c] > 0
    /\ openGen[c] \in validData
    /\ lastReadGen[c] = 0
    /\ lastReadGen' = [lastReadGen EXCEPT ![c] = openGen[c]]
    /\ returnedBadBytes' =
          (returnedBadBytes \/ (openGen[c] \notin validData))
    /\ UNCHANGED <<uploadedData, validData, storedManifests, validManifests,
                    published, latest, wire, known, validated, durable, view,
                    openGen, connected, storeUp, stableNetwork,
                    rejectedUnauthorizedReference, rejectedBadResponse>>
    /\ UNCHANGED publisherVars

(***************************************************************************
A wrong-generation response or hash failure changes only rejection state; it
can never change lastReadGen or expose bytes to the application.
***************************************************************************)
RejectBadReadResponse(c, g) ==
    /\ c \in Consumers
    /\ PublisherJournalQuiescent
    /\ g \in Generations
    /\ openGen[c] > 0
    /\ (g # openGen[c] \/ g \notin validData)
    /\ ~rejectedBadResponse
    /\ rejectedBadResponse' = TRUE
    /\ UNCHANGED <<uploadedData, validData, storedManifests, validManifests,
                    published, latest, wire, known, validated, durable, view,
                    openGen, lastReadGen, connected, storeUp, stableNetwork,
                    rejectedUnauthorizedReference, returnedBadBytes>>
    /\ UNCHANGED publisherVars

(***************************************************************************
CrashRestart clears all volatile per-process state and in-flight responses for
one consumer. The durable watermark is deliberately UNCHANGED. It is disabled
after StabilizeNetwork, which is the eventual-no-more-crashes liveness
assumption, not a safety assumption.
***************************************************************************)
CrashRestart(c) ==
    /\ ~stableNetwork
    /\ c \in Consumers
    /\ PublisherJournalQuiescent
    /\ \/ known[c] # NoReference
       \/ validated[c] # NoReference
       \/ view[c] # NoReference
       \/ openGen[c] # 0
       \/ lastReadGen[c] # 0
       \/ wire[c] # {}
    /\ wire' = [wire EXCEPT ![c] = {}]
    /\ known' = [known EXCEPT ![c] = NoReference]
    /\ validated' = [validated EXCEPT ![c] = NoReference]
    /\ view' = [view EXCEPT ![c] = NoReference]
    /\ openGen' = [openGen EXCEPT ![c] = 0]
    /\ lastReadGen' = [lastReadGen EXCEPT ![c] = 0]
    /\ UNCHANGED <<uploadedData, validData, storedManifests, validManifests,
                    published, latest, durable, connected, storeUp,
                    stableNetwork, rejectedUnauthorizedReference,
                    rejectedBadResponse, returnedBadBytes>>
    /\ UNCHANGED publisherVars

Partition(c) ==
    /\ ~stableNetwork
    /\ c \in Consumers
    /\ PublisherJournalQuiescent
    /\ connected[c]
    /\ connected' = [connected EXCEPT ![c] = FALSE]
    /\ UNCHANGED <<uploadedData, validData, storedManifests, validManifests,
                    published, latest, wire, known, validated, durable, view,
                    openGen, lastReadGen, storeUp, stableNetwork,
                    rejectedUnauthorizedReference, rejectedBadResponse,
                    returnedBadBytes>>
    /\ UNCHANGED publisherVars

Reconnect(c) ==
    /\ ~stableNetwork
    /\ c \in Consumers
    /\ PublisherJournalQuiescent
    /\ ~connected[c]
    /\ connected' = [connected EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<uploadedData, validData, storedManifests, validManifests,
                    published, latest, wire, known, validated, durable, view,
                    openGen, lastReadGen, storeUp, stableNetwork,
                    rejectedUnauthorizedReference, rejectedBadResponse,
                    returnedBadBytes>>
    /\ UNCHANGED publisherVars

ToggleStore ==
    /\ ~stableNetwork
    /\ storeUp' = ~storeUp
    /\ UNCHANGED <<uploadedData, validData, storedManifests, validManifests,
                    published, latest, wire, known, validated, durable, view,
                    openGen, lastReadGen, connected, stableNetwork,
                    rejectedUnauthorizedReference, rejectedBadResponse,
                    returnedBadBytes>>
    /\ UNCHANGED publisherVars

CorruptData(g) ==
    /\ ~stableNetwork
    /\ g \in validData
    /\ validData' = validData \ {g}
    /\ UNCHANGED <<uploadedData, storedManifests, validManifests, published,
                    latest, wire, known, validated, durable, view, openGen,
                    lastReadGen, connected, storeUp, stableNetwork,
                    rejectedUnauthorizedReference, rejectedBadResponse,
                    returnedBadBytes>>
    /\ UNCHANGED publisherVars

CorruptManifest(g) ==
    /\ ~stableNetwork
    /\ g \in validManifests
    /\ validManifests' = validManifests \ {g}
    /\ UNCHANGED <<uploadedData, validData, storedManifests, published, latest,
                    wire, known, validated, durable, view, openGen,
                    lastReadGen, connected, storeUp, stableNetwork,
                    rejectedUnauthorizedReference, rejectedBadResponse,
                    returnedBadBytes>>
    /\ UNCHANGED publisherVars

(***************************************************************************
This is the explicit partial-synchrony assumption used only by FairSpec:
eventually communication and storage stay usable, immutable objects recover,
and consumers stop crashing. Safety uses Spec and needs no such assumption.
***************************************************************************)
StabilizeNetwork ==
    /\ ~stableNetwork
    /\ stableNetwork' = TRUE
    /\ connected' = [c \in Consumers |-> TRUE]
    /\ storeUp' = TRUE
    /\ validData' = uploadedData
    /\ validManifests' = storedManifests
    /\ UNCHANGED <<uploadedData, storedManifests, published, latest, wire,
                    known, validated, durable, view, openGen, lastReadGen,
                    rejectedUnauthorizedReference, rejectedBadResponse,
                    returnedBadBytes>>
    /\ UNCHANGED publisherVars

Next ==
    \/ \E g \in Generations : UploadData(g)
    \/ \E g \in Generations : PutManifest(g)
    \/ \E c \in Consumers, g \in Generations : PollResponse(c, g)
    \/ \E c \in Consumers, g \in Generations : AttackerInject(c, g)
    \/ \E c \in Consumers, ref \in References : DropResponse(c, ref)
    \/ \E c \in Consumers, ref \in References :
          ReceiveAuthorizedReference(c, ref)
    \/ \E c \in Consumers, ref \in References :
          RejectUnauthorizedReference(c, ref)
    \/ \E c \in Consumers : LoadDurable(c)
    \/ \E c \in Consumers : FetchKnownManifest(c)
    \/ \E c \in Consumers : PersistValidated(c)
    \/ \E c \in Consumers : ActivatePersisted(c)
    \/ \E c \in Consumers : Open(c)
    \/ \E c \in Consumers : Close(c)
    \/ \E c \in Consumers : ReturnVerifiedBytes(c)
    \/ \E c \in Consumers, g \in Generations : RejectBadReadResponse(c, g)
    \/ \E c \in Consumers : CrashRestart(c)
    \/ \E c \in Consumers : Partition(c)
    \/ \E c \in Consumers : Reconnect(c)
    \/ ToggleStore
    \/ \E g \in Generations : CorruptData(g)
    \/ \E g \in Generations : CorruptManifest(g)
    \/ StabilizeNetwork
    \/ \E branch \in PublisherBranches : RecordPublisherIntent(branch)
    \/ RecoverPublisherPending
    \/ PublisherCASAppliedResponseLost
    \/ PublisherCASAppliedResponseReceived
    \/ \E winner \in PublisherReferences :
          CompetingPublisherCASWins(winner)
    \/ ProveRemotePublisherHistory
    \/ FinalizePublisherJournal
    \/ PublisherCrashRestart

Spec == Init /\ [][Next]_vars

(***************************************************************************
After StabilizeNetwork, weak fairness says that a continuously enabled poll,
receive, local watermark load, metadata fetch, persistence, and activation
eventually run. A durable publisher intent is likewise recovered, gets one CAS
outcome, proves the selected remote history, and finalizes. Without eventual
network/storage/process stability, convergence and post-restart recovery are
intentionally not claimed.
***************************************************************************)
PublisherCASOutcome ==
    PublisherCASAppliedResponseLost \/ PublisherCASAppliedResponseReceived

FairSpec ==
    /\ Spec
    /\ WF_vars(StabilizeNetwork)
    /\ WF_vars(RecoverPublisherPending)
    /\ WF_vars(PublisherCASOutcome)
    /\ WF_vars(ProveRemotePublisherHistory)
    /\ WF_vars(FinalizePublisherJournal)
    /\ \A c \in Consumers :
          /\ WF_vars(PollLatest(c))
          /\ WF_vars(ReceiveLatest(c))
          /\ WF_vars(LoadDurable(c))
          /\ WF_vars(FetchKnownManifest(c))
          /\ WF_vars(PersistValidated(c))
          /\ WF_vars(ActivatePersisted(c))

TypeOK ==
    /\ uploadedData \subseteq Generations
    /\ validData \subseteq uploadedData
    /\ storedManifests \subseteq Generations
    /\ validManifests \subseteq storedManifests
    /\ published \subseteq Generations
    /\ latest \in 0..MaxGeneration
    /\ wire \in [Consumers -> SUBSET References]
    /\ known \in [Consumers -> ReferencesWithNone]
    /\ validated \in [Consumers -> ReferencesWithNone]
    /\ durable \in [Consumers -> ReferencesWithNone]
    /\ view \in [Consumers -> ReferencesWithNone]
    /\ openGen \in [Consumers -> 0..MaxGeneration]
    /\ lastReadGen \in [Consumers -> 0..MaxGeneration]
    /\ connected \in [Consumers -> BOOLEAN]
    /\ storeUp \in BOOLEAN
    /\ stableNetwork \in BOOLEAN
    /\ rejectedUnauthorizedReference \in BOOLEAN
    /\ rejectedBadResponse \in BOOLEAN
    /\ returnedBadBytes \in BOOLEAN
    /\ remotePublisherLatest \in PublisherReferencesWithNone
    /\ remotePublisherHistory \subseteq PublisherReferences
    /\ publisherCommitted \in PublisherReferencesWithNone
    /\ publisherAttempt \in PublisherReferencesWithNone
    /\ publisherProof \in PublisherReferencesWithNone
    /\ \/ publisherPending = NoPublisherIntent
       \/ /\ publisherPending.base \in PublisherReferencesWithNone
          /\ publisherPending.target \in PublisherReferences
          /\ DirectPublisherSuccessor(publisherPending.base,
                                      publisherPending.target)

StoreClosure ==
    \A g \in storedManifests : g \in uploadedData

PublishedClosure ==
    /\ (latest = 0) <=> (published = {})
    /\ published = 1..latest
    /\ published \subseteq storedManifests
    /\ published \subseteq uploadedData

(***************************************************************************
Publisher safety is intentionally stated both as state invariants and as
transition properties. The journal's pending base is always the durable
committed anchor. Volatile recovery may load only the exact pending target.
The remote history contains one authorized winner per generation and can be
at most one direct successor ahead of the committed anchor while an intent is
unresolved.
***************************************************************************)
PendingBaseEqualsCommittedAnchor ==
    publisherPending = NoPublisherIntent
    \/ publisherPending.base = publisherCommitted

PublisherRecoveryUsesSamePendingIntent ==
    /\ (publisherPending # NoPublisherIntent
        \/ /\ publisherAttempt = NoPublisherReference
           /\ publisherProof = NoPublisherReference)
    /\ (publisherAttempt = NoPublisherReference
        \/ /\ publisherPending # NoPublisherIntent
           /\ publisherAttempt = publisherPending.target)
    /\ (publisherProof = NoPublisherReference
        \/ /\ publisherPending # NoPublisherIntent
           /\ publisherProof = remotePublisherLatest
           /\ publisherProof \in remotePublisherHistory
           /\ DirectPublisherSuccessor(publisherPending.base,
                                       publisherProof))

RemotePublisherHistoryIsSingleAuthorizedChain ==
    /\ remotePublisherHistory \subseteq PublisherReferences
    /\ (remotePublisherLatest = NoPublisherReference)
       <=> (remotePublisherHistory = {})
    /\ RefGeneration(remotePublisherLatest) = latest
    /\ (remotePublisherLatest = NoPublisherReference
        \/ remotePublisherLatest \in remotePublisherHistory)
    /\ (remotePublisherLatest = NoPublisherReference
        \/ \A ref \in remotePublisherHistory :
              PublisherBranch(ref) = PublisherBranch(remotePublisherLatest))
    /\ \A g \in Generations :
          Cardinality({ref \in remotePublisherHistory :
                         RefGeneration(ref) = g}) =
              IF g <= latest THEN 1 ELSE 0

RemoteExposureCannotForkCommittedAnchor ==
    LET committedGeneration == RefGeneration(publisherCommitted)
        remoteGeneration == RefGeneration(remotePublisherLatest)
    IN  /\ remoteGeneration >= committedGeneration
        /\ remoteGeneration <= committedGeneration + 1
        /\ (publisherCommitted = NoPublisherReference
            \/ /\ PublisherReferenceAuthorized(publisherCommitted)
               /\ publisherCommitted \in remotePublisherHistory)
        /\ (remoteGeneration = committedGeneration
            => remotePublisherLatest = publisherCommitted)
        /\ (remoteGeneration = committedGeneration + 1
            => /\ publisherPending # NoPublisherIntent
               /\ publisherPending.base = publisherCommitted
               /\ PublisherReferenceAuthorized(remotePublisherLatest)
               /\ DirectPublisherSuccessor(publisherCommitted,
                                           remotePublisherLatest))

WireReferencesWellFormed ==
    \A c \in Consumers : wire[c] \subseteq References

ConsumerStateIsCommitted ==
    \A c \in Consumers :
        /\ (known[c] = NoReference
            \/ RefGeneration(known[c]) \in published)
        /\ (validated[c] = NoReference
            \/ RefGeneration(validated[c]) \in storedManifests)
        /\ (durable[c] = NoReference
            \/ RefGeneration(durable[c]) \in published)
        /\ (view[c] = NoReference
            \/ RefGeneration(view[c]) \in published)
        /\ RefGeneration(known[c]) <= latest
        /\ RefGeneration(validated[c]) <= RefGeneration(known[c])
        /\ RefGeneration(view[c]) <= RefGeneration(durable[c])
        /\ (known[c] = NoReference
            \/ RefGeneration(durable[c]) <= RefGeneration(known[c]))
        /\ (validated[c] = NoReference
            \/ RefGeneration(durable[c]) <= RefGeneration(validated[c]))
        /\ (openGen[c] = 0 \/ openGen[c] \in published)
        /\ openGen[c] <= RefGeneration(view[c])

VolatileAndDurableReferencesAreAuthorized ==
    \A c \in Consumers :
        /\ (known[c] = NoReference
            \/ Authorized(Repository, Channel, known[c]))
        /\ (validated[c] = NoReference
            \/ Authorized(Repository, Channel, validated[c]))
        /\ (durable[c] = NoReference
            \/ Authorized(Repository, Channel, durable[c]))

ExposedViewsAreAuthorized ==
    \A c \in Consumers :
        view[c] = NoReference
        \/ Authorized(Repository, Channel, view[c])

OldResponsesCannotCrossDurableWatermark ==
    \A c \in Consumers :
        /\ (known[c] = NoReference
            \/ RefGeneration(known[c]) >= RefGeneration(durable[c]))
        /\ (validated[c] = NoReference
            \/ RefGeneration(validated[c]) >= RefGeneration(durable[c]))
        /\ RefGeneration(view[c]) <= RefGeneration(durable[c])

ActivatedMetadataWasValidated ==
    \A c \in Consumers :
        RefGeneration(view[c]) <= RefGeneration(validated[c])

OpenHandlePinsEverySuccessfulRead ==
    \A c \in Consumers :
        lastReadGen[c] = 0 \/ lastReadGen[c] = openGen[c]

NoCorruptBytesReturned == ~returnedBadBytes

LatestNeverRegresses ==
    [][latest' >= latest]_vars

PublisherCommittedNeverRegressesOrSwitchesBranch ==
    [][ /\ RefGeneration(publisherCommitted') >=
              RefGeneration(publisherCommitted)
        /\ ((RefGeneration(publisherCommitted') =
             RefGeneration(publisherCommitted)
             /\ publisherCommitted # NoPublisherReference)
            => publisherCommitted' = publisherCommitted) ]_vars

PendingIntentCannotBeRewritten ==
    [][ (publisherPending # NoPublisherIntent
         /\ publisherPending' # NoPublisherIntent)
        => publisherPending' = publisherPending ]_vars

PendingClearsOnlyAfterProvenRemoteHistory ==
    [][ (publisherPending # NoPublisherIntent
         /\ publisherPending' = NoPublisherIntent)
        => /\ publisherProof # NoPublisherReference
           /\ publisherProof = remotePublisherLatest
           /\ publisherProof \in remotePublisherHistory
           /\ publisherCommitted' = publisherProof ]_vars

DurableWatermarkNeverRegresses ==
    [][\A c \in Consumers :
          RefGeneration(durable'[c]) >= RefGeneration(durable[c])]_vars

VolatileStateOnlyResetsToEmpty ==
    [][\A c \in Consumers :
          /\ (RefGeneration(known'[c]) >= RefGeneration(known[c])
              \/ known'[c] = NoReference)
          /\ (RefGeneration(view'[c]) >= RefGeneration(view[c])
              \/ view'[c] = NoReference)]_vars

PersistencePrecedesActivation ==
    [][\A c \in Consumers :
          (view'[c] # view[c] /\ view'[c] # NoReference)
          => view'[c] = durable'[c]]_vars

ImmutableStateOnlyGrows ==
    [][ /\ uploadedData \subseteq uploadedData'
        /\ storedManifests \subseteq storedManifests'
        /\ published \subseteq published' ]_vars

PerPublishedGenerationCatchUp ==
    \A g \in Generations :
        (stableNetwork /\ g \in published)
        ~>
        (\A c \in Consumers : RefGeneration(view[c]) >= g)

DurableViewRecovery ==
    \A c \in Consumers :
        (stableNetwork /\ durable[c] # NoReference)
        ~>
        (view[c] = durable[c])

PublisherPendingEventuallyFinalizes ==
    (stableNetwork /\ publisherPending # NoPublisherIntent)
    ~>
    (publisherPending = NoPublisherIntent
     /\ publisherCommitted = remotePublisherLatest)

=============================================================================
