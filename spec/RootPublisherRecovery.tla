----------------------- MODULE RootPublisherRecovery -----------------------
EXTENDS Naturals, FiniteSets, Sequences, TLC

(***************************************************************************
Small executable model of one RootPublisher recovery journal.  The local
journal contains a durable committed root plus, while a CAS is unresolved, an
immutable exact target and its expected base.  remoteHistory is the abstract
linearizable S3 root-key CAS history.  intentHistory is a proof-only ghost set
showing that every local or competing write had a matching durable intent
before it entered that history; an implementation need not retain completed
intents forever.

CrashRestart destroys only volatile attempt/response/proof state.  Complete
local-journal rollback, replay of an older journal file, and physical loss of
the journal disk are deliberately outside this model and require independent
sealed-state backup and disaster-recovery controls.
***************************************************************************)

CONSTANTS Digests, MaxRevision, FixedExpiry

ASSUME /\ Digests # {}
       /\ Cardinality(Digests) >= 2
       /\ MaxRevision \in Nat \ {0}
       /\ FixedExpiry \in Nat \ {0}

Genesis == [revision |-> 0, targetDigest |-> "genesis"]

NoRoot == [revision |-> 0, targetDigest |-> "no-root"]

NoPending ==
    [base |-> Genesis,
     expectedBase |-> Genesis,
     target |-> Genesis,
     expiresAt |-> 0]

NonGenesisRoots ==
    [revision : 1..MaxRevision, targetDigest : Digests]

Roots == {Genesis} \cup NonGenesisRoots

DirectSuccessor(base, target) ==
    target.revision = base.revision + 1

PendingRecords ==
    {p \in [base : Roots,
            expectedBase : Roots,
            target : Roots,
            expiresAt : {FixedExpiry}] :
       /\ p.base = p.expectedBase
       /\ DirectSuccessor(p.base, p.target)}

Writers == {"initial", "local", "competitor"}

RemoteEntries ==
    [root : Roots,
     writer : Writers,
     writtenAt : 0..FixedExpiry,
     intent : PendingRecords \cup {NoPending}]

InitialRemoteEntry ==
    [root |-> Genesis,
     writer |-> "initial",
     writtenAt |-> 0,
     intent |-> NoPending]

Outcomes ==
    {"none", "loaded", "network-fault", "store-fault",
     "applied-response-received", "applied-response-lost",
     "competitor-won", "current-returned", "lower-replay-returned",
     "equal-fork-returned", "replay-rejected", "remote-proven",
     "committed"}

VARIABLES
    journalCommitted,
    journalPending,
    competitorPending,
    intentHistory,
    remoteHistory,
    volatileAttempt,
    volatileObservation,
    volatileProof,
    volatileOutcome,
    replayRejected,
    networkUp,
    storeUp,
    environmentStable,
    now,
    authorizationExpiry,
    crashesRemaining

vars ==
    <<journalCommitted, journalPending, competitorPending, intentHistory,
      remoteHistory, volatileAttempt, volatileObservation, volatileProof,
      volatileOutcome, replayRejected, networkUp, storeUp,
      environmentStable, now, authorizationExpiry, crashesRemaining>>

RemoteRoot == remoteHistory[Len(remoteHistory)].root

HistoryRoots ==
    {remoteHistory[index].root : index \in 1..Len(remoteHistory)}

Intent(base, target) ==
    [base |-> base,
     expectedBase |-> base,
     target |-> target,
     expiresAt |-> authorizationExpiry]

Target(digest) ==
    [revision |-> journalCommitted.revision + 1,
     targetDigest |-> digest]

RemoteEntry(root, writer, intent) ==
    [root |-> root,
     writer |-> writer,
     writtenAt |-> now,
     intent |-> intent]

ObservationIsProvable(observation) ==
    /\ journalPending # NoPending
    /\ observation # NoRoot
    /\ observation = RemoteRoot
    /\ DirectSuccessor(journalPending.base, observation)
    /\ observation \in HistoryRoots

Init ==
    /\ journalCommitted = Genesis
    /\ journalPending = NoPending
    /\ competitorPending = NoPending
    /\ intentHistory = {}
    /\ remoteHistory = <<InitialRemoteEntry>>
    /\ volatileAttempt = NoPending
    /\ volatileObservation = NoRoot
    /\ volatileProof = NoRoot
    /\ volatileOutcome = "none"
    /\ replayRejected = FALSE
    /\ networkUp = TRUE
    /\ storeUp = TRUE
    /\ environmentStable = FALSE
    /\ now = 0
    /\ authorizationExpiry = FixedExpiry
    /\ crashesRemaining = 1

RecordPublisherIntent(digest) ==
    /\ digest \in Digests
    /\ journalPending = NoPending
    /\ journalCommitted.revision < MaxRevision
    /\ RemoteRoot = journalCommitted
    /\ now < authorizationExpiry
    /\ journalPending' = Intent(journalCommitted, Target(digest))
    /\ intentHistory' = intentHistory \cup {journalPending'}
    /\ volatileOutcome' = "none"
    /\ UNCHANGED <<journalCommitted, competitorPending, remoteHistory,
                    volatileAttempt, volatileObservation, volatileProof,
                    replayRejected, networkUp, storeUp, environmentStable,
                    now, authorizationExpiry, crashesRemaining>>

(***************************************************************************
The competitor represents another correctly journaled publisher.  Its own
recovery lifecycle is not modeled, but its durable exact intent is recorded
in a separate slot before it can win the shared S3 CAS.
***************************************************************************)
RecordCompetitorIntent(digest) ==
    /\ digest \in Digests
    /\ journalPending # NoPending
    /\ competitorPending = NoPending
    /\ digest # journalPending.target.targetDigest
    /\ competitorPending' =
          Intent(journalPending.expectedBase,
                 [revision |-> journalPending.target.revision,
                  targetDigest |-> digest])
    /\ intentHistory' = intentHistory \cup {competitorPending'}
    /\ UNCHANGED <<journalCommitted, journalPending, remoteHistory,
                    volatileAttempt, volatileObservation, volatileProof,
                    volatileOutcome, replayRejected, networkUp, storeUp,
                    environmentStable, now, authorizationExpiry,
                    crashesRemaining>>

LoadPendingExactTarget ==
    /\ journalPending # NoPending
    /\ volatileAttempt = NoPending
    /\ volatileAttempt' = journalPending
    /\ volatileOutcome' = "loaded"
    /\ UNCHANGED <<journalCommitted, journalPending, competitorPending,
                    intentHistory, remoteHistory, volatileObservation,
                    volatileProof, replayRejected, networkUp, storeUp,
                    environmentStable, now, authorizationExpiry,
                    crashesRemaining>>

LocalCASReady ==
    /\ journalPending # NoPending
    /\ volatileAttempt = journalPending
    /\ volatileObservation = NoRoot
    /\ volatileProof = NoRoot
    /\ RemoteRoot = journalPending.expectedBase
    /\ networkUp
    /\ storeUp
    /\ now < authorizationExpiry

CASAppliedResponseReceived ==
    /\ LocalCASReady
    /\ remoteHistory' =
          Append(remoteHistory,
                 RemoteEntry(journalPending.target, "local", journalPending))
    /\ volatileObservation' = journalPending.target
    /\ volatileOutcome' = "applied-response-received"
    /\ UNCHANGED <<journalCommitted, journalPending, competitorPending,
                    intentHistory, volatileAttempt, volatileProof,
                    replayRejected, networkUp, storeUp, environmentStable,
                    now, authorizationExpiry, crashesRemaining>>

CASAppliedResponseLost ==
    /\ LocalCASReady
    /\ ~environmentStable
    /\ remoteHistory' =
          Append(remoteHistory,
                 RemoteEntry(journalPending.target, "local", journalPending))
    /\ volatileOutcome' = "applied-response-lost"
    /\ networkUp' = FALSE
    /\ UNCHANGED <<journalCommitted, journalPending, competitorPending,
                    intentHistory, volatileAttempt, volatileObservation,
                    volatileProof, replayRejected, storeUp, environmentStable,
                    now, authorizationExpiry, crashesRemaining>>

CompetitorCASWins ==
    /\ journalPending # NoPending
    /\ competitorPending # NoPending
    /\ RemoteRoot = competitorPending.expectedBase
    /\ networkUp
    /\ storeUp
    /\ now < authorizationExpiry
    /\ remoteHistory' =
          Append(remoteHistory,
                 RemoteEntry(competitorPending.target,
                             "competitor", competitorPending))
    /\ volatileOutcome' = "competitor-won"
    /\ UNCHANGED <<journalCommitted, journalPending, competitorPending,
                    intentHistory, volatileAttempt, volatileObservation,
                    volatileProof, replayRejected, networkUp, storeUp,
                    environmentStable, now, authorizationExpiry,
                    crashesRemaining>>

ObserveNetworkFault ==
    /\ journalPending # NoPending
    /\ volatileAttempt = journalPending
    /\ ~networkUp
    /\ volatileOutcome # "network-fault"
    /\ volatileOutcome' = "network-fault"
    /\ UNCHANGED <<journalCommitted, journalPending, competitorPending,
                    intentHistory, remoteHistory, volatileAttempt,
                    volatileObservation, volatileProof, replayRejected,
                    networkUp, storeUp, environmentStable, now,
                    authorizationExpiry, crashesRemaining>>

ObserveStoreFault ==
    /\ journalPending # NoPending
    /\ volatileAttempt = journalPending
    /\ networkUp
    /\ ~storeUp
    /\ volatileOutcome # "store-fault"
    /\ volatileOutcome' = "store-fault"
    /\ UNCHANGED <<journalCommitted, journalPending, competitorPending,
                    intentHistory, remoteHistory, volatileAttempt,
                    volatileObservation, volatileProof, replayRejected,
                    networkUp, storeUp, environmentStable, now,
                    authorizationExpiry, crashesRemaining>>

ReturnCurrentRemoteRoot ==
    /\ journalPending # NoPending
    /\ volatileAttempt = journalPending
    /\ volatileObservation = NoRoot
    /\ RemoteRoot.revision = journalPending.target.revision
    /\ networkUp
    /\ storeUp
    /\ volatileObservation' = RemoteRoot
    /\ volatileOutcome' = "current-returned"
    /\ UNCHANGED <<journalCommitted, journalPending, competitorPending,
                    intentHistory, remoteHistory, volatileAttempt,
                    volatileProof, replayRejected, networkUp, storeUp,
                    environmentStable, now, authorizationExpiry,
                    crashesRemaining>>

ReturnLowerReplay ==
    /\ journalPending # NoPending
    /\ volatileAttempt = journalPending
    /\ volatileObservation = NoRoot
    /\ RemoteRoot.revision = journalPending.target.revision
    /\ ~environmentStable
    /\ networkUp
    /\ storeUp
    /\ volatileObservation' = journalPending.base
    /\ volatileOutcome' = "lower-replay-returned"
    /\ UNCHANGED <<journalCommitted, journalPending, competitorPending,
                    intentHistory, remoteHistory, volatileAttempt,
                    volatileProof, replayRejected, networkUp, storeUp,
                    environmentStable, now, authorizationExpiry,
                    crashesRemaining>>

ReturnEqualRevisionFork(digest) ==
    /\ digest \in Digests
    /\ journalPending # NoPending
    /\ volatileAttempt = journalPending
    /\ volatileObservation = NoRoot
    /\ RemoteRoot.revision = journalPending.target.revision
    /\ digest # RemoteRoot.targetDigest
    /\ ~environmentStable
    /\ networkUp
    /\ storeUp
    /\ volatileObservation' =
          [revision |-> RemoteRoot.revision, targetDigest |-> digest]
    /\ volatileOutcome' = "equal-fork-returned"
    /\ UNCHANGED <<journalCommitted, journalPending, competitorPending,
                    intentHistory, remoteHistory, volatileAttempt,
                    volatileProof, replayRejected, networkUp, storeUp,
                    environmentStable, now, authorizationExpiry,
                    crashesRemaining>>

RejectInvalidObservation ==
    /\ volatileObservation # NoRoot
    /\ ~ObservationIsProvable(volatileObservation)
    /\ volatileObservation' = NoRoot
    /\ volatileOutcome' = "replay-rejected"
    /\ replayRejected' = TRUE
    /\ UNCHANGED <<journalCommitted, journalPending, competitorPending,
                    intentHistory, remoteHistory, volatileAttempt,
                    volatileProof, networkUp, storeUp, environmentStable,
                    now, authorizationExpiry, crashesRemaining>>

ProveRemoteRoot ==
    /\ ObservationIsProvable(volatileObservation)
    /\ volatileProof' = volatileObservation
    /\ volatileOutcome' = "remote-proven"
    /\ UNCHANGED <<journalCommitted, journalPending, competitorPending,
                    intentHistory, remoteHistory, volatileAttempt,
                    volatileObservation, replayRejected, networkUp, storeUp,
                    environmentStable, now, authorizationExpiry,
                    crashesRemaining>>

FinalizeCommitted ==
    /\ journalPending # NoPending
    /\ volatileProof # NoRoot
    /\ volatileProof = RemoteRoot
    /\ DirectSuccessor(journalPending.base, volatileProof)
    /\ volatileProof \in HistoryRoots
    /\ journalCommitted' = volatileProof
    /\ journalPending' = NoPending
    /\ volatileAttempt' = NoPending
    /\ volatileObservation' = NoRoot
    /\ volatileProof' = NoRoot
    /\ volatileOutcome' = "committed"
    /\ UNCHANGED <<competitorPending, intentHistory, remoteHistory,
                    replayRejected, networkUp, storeUp, environmentStable,
                    now, authorizationExpiry, crashesRemaining>>

CrashRestart ==
    /\ crashesRemaining > 0
    /\ journalPending # NoPending
    /\ \/ volatileAttempt # NoPending
       \/ volatileObservation # NoRoot
       \/ volatileProof # NoRoot
       \/ volatileOutcome # "none"
    /\ volatileAttempt' = NoPending
    /\ volatileObservation' = NoRoot
    /\ volatileProof' = NoRoot
    /\ volatileOutcome' = "none"
    /\ crashesRemaining' = crashesRemaining - 1
    /\ UNCHANGED <<journalCommitted, journalPending, competitorPending,
                    intentHistory, remoteHistory, replayRejected, networkUp,
                    storeUp, environmentStable, now, authorizationExpiry>>

PartitionNetwork ==
    /\ ~environmentStable
    /\ networkUp
    /\ networkUp' = FALSE
    /\ UNCHANGED <<journalCommitted, journalPending, competitorPending,
                    intentHistory, remoteHistory, volatileAttempt,
                    volatileObservation, volatileProof, volatileOutcome,
                    replayRejected, storeUp, environmentStable, now,
                    authorizationExpiry, crashesRemaining>>

RestoreNetwork ==
    /\ ~environmentStable
    /\ ~networkUp
    /\ networkUp' = TRUE
    /\ UNCHANGED <<journalCommitted, journalPending, competitorPending,
                    intentHistory, remoteHistory, volatileAttempt,
                    volatileObservation, volatileProof, volatileOutcome,
                    replayRejected, storeUp, environmentStable, now,
                    authorizationExpiry, crashesRemaining>>

SetStoreUnavailable ==
    /\ ~environmentStable
    /\ storeUp
    /\ storeUp' = FALSE
    /\ UNCHANGED <<journalCommitted, journalPending, competitorPending,
                    intentHistory, remoteHistory, volatileAttempt,
                    volatileObservation, volatileProof, volatileOutcome,
                    replayRejected, networkUp, environmentStable, now,
                    authorizationExpiry, crashesRemaining>>

SetStoreAvailable ==
    /\ ~environmentStable
    /\ ~storeUp
    /\ storeUp' = TRUE
    /\ UNCHANGED <<journalCommitted, journalPending, competitorPending,
                    intentHistory, remoteHistory, volatileAttempt,
                    volatileObservation, volatileProof, volatileOutcome,
                    replayRejected, networkUp, environmentStable, now,
                    authorizationExpiry, crashesRemaining>>

StabilizeEnvironment ==
    /\ ~environmentStable
    /\ environmentStable' = TRUE
    /\ networkUp' = TRUE
    /\ storeUp' = TRUE
    /\ UNCHANGED <<journalCommitted, journalPending, competitorPending,
                    intentHistory, remoteHistory, volatileAttempt,
                    volatileObservation, volatileProof, volatileOutcome,
                    replayRejected, now, authorizationExpiry,
                    crashesRemaining>>

AdvanceTime ==
    /\ now < authorizationExpiry
    /\ now' = now + 1
    /\ UNCHANGED <<journalCommitted, journalPending, competitorPending,
                    intentHistory, remoteHistory, volatileAttempt,
                    volatileObservation, volatileProof, volatileOutcome,
                    replayRejected, networkUp, storeUp, environmentStable,
                    authorizationExpiry, crashesRemaining>>

LocalCASOutcome ==
    CASAppliedResponseReceived \/ CASAppliedResponseLost

Next ==
    \/ \E digest \in Digests : RecordPublisherIntent(digest)
    \/ \E digest \in Digests : RecordCompetitorIntent(digest)
    \/ LoadPendingExactTarget
    \/ CASAppliedResponseReceived
    \/ CASAppliedResponseLost
    \/ CompetitorCASWins
    \/ ObserveNetworkFault
    \/ ObserveStoreFault
    \/ ReturnCurrentRemoteRoot
    \/ ReturnLowerReplay
    \/ \E digest \in Digests : ReturnEqualRevisionFork(digest)
    \/ RejectInvalidObservation
    \/ ProveRemoteRoot
    \/ FinalizeCommitted
    \/ CrashRestart
    \/ PartitionNetwork
    \/ RestoreNetwork
    \/ SetStoreUnavailable
    \/ SetStoreAvailable
    \/ StabilizeEnvironment
    \/ AdvanceTime

Spec == Init /\ [][Next]_vars

(***************************************************************************
Weak fairness is required only for recovery work and the one-way environment
stabilization action.  Replay/fault injection is disabled after stabilization;
crashes are finitely bounded.  The liveness property below additionally
requires the fixed authorization window to remain unexpired.
***************************************************************************)
FairSpec ==
    /\ Spec
    /\ WF_vars(StabilizeEnvironment)
    /\ WF_vars(LoadPendingExactTarget)
    /\ WF_vars(LocalCASOutcome)
    /\ WF_vars(ReturnCurrentRemoteRoot)
    /\ WF_vars(RejectInvalidObservation)
    /\ WF_vars(ProveRemoteRoot)
    /\ WF_vars(FinalizeCommitted)

TypeOK ==
    /\ journalCommitted \in Roots
    /\ journalPending \in PendingRecords \cup {NoPending}
    /\ competitorPending \in PendingRecords \cup {NoPending}
    /\ intentHistory \subseteq PendingRecords
    /\ remoteHistory \in Seq(RemoteEntries)
    /\ Len(remoteHistory) \in 1..(MaxRevision + 1)
    /\ volatileAttempt \in PendingRecords \cup {NoPending}
    /\ volatileObservation \in Roots \cup {NoRoot}
    /\ volatileProof \in Roots \cup {NoRoot}
    /\ volatileOutcome \in Outcomes
    /\ replayRejected \in BOOLEAN
    /\ networkUp \in BOOLEAN
    /\ storeUp \in BOOLEAN
    /\ environmentStable \in BOOLEAN
    /\ now \in 0..authorizationExpiry
    /\ authorizationExpiry = FixedExpiry
    /\ crashesRemaining \in 0..1

JournalPendingIsExactAndAnchored ==
    journalPending = NoPending
    \/ /\ journalPending \in intentHistory
       /\ journalPending.base = journalCommitted
       /\ journalPending.expectedBase = journalCommitted
       /\ journalPending.expiresAt = authorizationExpiry
       /\ DirectSuccessor(journalCommitted, journalPending.target)

CompetitorWriteIsJournaled ==
    competitorPending = NoPending
    \/ /\ competitorPending \in intentHistory
       /\ competitorPending.expiresAt = authorizationExpiry
       /\ DirectSuccessor(competitorPending.base,
                          competitorPending.target)

RetryUsesExactDurableTarget ==
    volatileAttempt = NoPending
    \/ /\ journalPending # NoPending
       /\ volatileAttempt = journalPending

ProofIsCurrentRemoteSuccessor ==
    volatileProof = NoRoot
    \/ /\ journalPending # NoPending
       /\ volatileProof = RemoteRoot
       /\ DirectSuccessor(journalPending.base, volatileProof)
       /\ volatileProof \in HistoryRoots

RemoteRootCASHistoryIsLinearAndJournaled ==
    /\ remoteHistory[1] = InitialRemoteEntry
    /\ Len(remoteHistory) = RemoteRoot.revision + 1
    /\ \A index \in 2..Len(remoteHistory) :
          LET previous == remoteHistory[index - 1]
              current == remoteHistory[index]
          IN  /\ current.root.revision = previous.root.revision + 1
              /\ current.writer \in {"local", "competitor"}
              /\ current.intent # NoPending
              /\ current.intent \in intentHistory
              /\ current.intent.base = previous.root
              /\ current.intent.expectedBase = previous.root
              /\ current.intent.target = current.root
              /\ current.writtenAt < current.intent.expiresAt

CommittedIsOneMonotonicRemoteHistoryEntry ==
    /\ journalCommitted \in HistoryRoots
    /\ journalCommitted.revision <= RemoteRoot.revision

CommittedRevisionAndDigestNeverRegressOrFork ==
    [][ /\ journalCommitted'.revision >= journalCommitted.revision
        /\ (journalCommitted'.revision = journalCommitted.revision
            => journalCommitted'.targetDigest =
                 journalCommitted.targetDigest) ]_vars

PendingCannotBeRewritten ==
    [][ (journalPending # NoPending
         /\ journalPending' # NoPending)
        => journalPending' = journalPending ]_vars

PendingWithoutProofCannotChangeOrClear ==
    [][ (journalPending # NoPending /\ volatileProof = NoRoot)
        => journalPending' = journalPending ]_vars

PendingClearsOnlyAfterMatchingRemoteProof ==
    [][ (journalPending # NoPending
         /\ journalPending' = NoPending)
        => /\ volatileProof # NoRoot
           /\ volatileProof = RemoteRoot
           /\ DirectSuccessor(journalPending.base, volatileProof)
           /\ journalCommitted' = volatileProof ]_vars

InvalidReplayCannotAdvanceJournal ==
    [][ (journalPending # NoPending
         /\ volatileObservation # NoRoot
         /\ ~ObservationIsProvable(volatileObservation))
        => /\ journalCommitted' = journalCommitted
           /\ journalPending' = journalPending
           /\ volatileProof' = volatileProof ]_vars

CrashClearsOnlyVolatileAndPreservesJournal ==
    [][ (crashesRemaining' < crashesRemaining)
        => /\ journalCommitted' = journalCommitted
           /\ journalPending' = journalPending
           /\ competitorPending' = competitorPending
           /\ intentHistory' = intentHistory
           /\ remoteHistory' = remoteHistory
           /\ authorizationExpiry' = authorizationExpiry
           /\ volatileAttempt' = NoPending
           /\ volatileObservation' = NoRoot
           /\ volatileProof' = NoRoot ]_vars

NoRemoteWriteWhileNetworkOrStoreUnavailable ==
    [][ (~networkUp \/ ~storeUp)
        => remoteHistory' = remoteHistory ]_vars

ExpiryIsFixedAndNeverExtended ==
    [][authorizationExpiry' = authorizationExpiry]_vars

NoRemoteWriteAtOrAfterExpiry ==
    [][now >= authorizationExpiry
       => remoteHistory' = remoteHistory]_vars

EventuallyStableAndUnexpired ==
    <>[](environmentStable /\ networkUp /\ storeUp
         /\ now < authorizationExpiry)

EveryPendingEventuallyResolves ==
    [](journalPending # NoPending => <> (journalPending = NoPending))

StableUnexpiredPendingEventuallyResolves ==
    EventuallyStableAndUnexpired => EveryPendingEventuallyResolves

=============================================================================
