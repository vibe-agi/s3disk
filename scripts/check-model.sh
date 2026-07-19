#!/bin/sh
set -eu

jar_path="${TLA2TOOLS_JAR:-${TMPDIR:-/tmp}/s3disk-tla2tools-1.8.0.jar}"
expected_sha256="58d44845a37a8d776deaf8cf3a623213b59d311bc0ec287bcdfbe148dd11bb3d"

if [ ! -f "$jar_path" ]; then
  curl -fsSL https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar -o "$jar_path"
fi

actual_sha256="$(shasum -a 256 "$jar_path" | awk '{print $1}')"
if [ "$actual_sha256" != "$expected_sha256" ]; then
  echo "unexpected tla2tools.jar checksum" >&2
  exit 1
fi

# Keep the required module/config matrix explicit. A renamed, deleted, or
# accidentally unhooked model must fail before TLC starts rather than leaving
# a misleading green check for whichever configurations remain.
required_model_files='spec/S3Disk.tla
spec/S3Disk.cfg
spec/S3DiskTwoConsumers.cfg
spec/S3DiskLiveness.cfg
spec/S3Share.tla
spec/S3Share.cfg
spec/S3ShareRevision.cfg
spec/S3ShareExpiry.cfg
spec/S3ShareRestart.cfg
spec/S3ShareLiveness.cfg'

for required_model_file in $required_model_files; do
  if [ ! -f "$required_model_file" ]; then
    echo "required formal-model file is missing: $required_model_file" >&2
    exit 1
  fi
done

for safety_config in \
  spec/S3Share.cfg \
  spec/S3ShareRevision.cfg \
  spec/S3ShareExpiry.cfg \
  spec/S3ShareRestart.cfg
do
  if ! grep -Eq '^SPECIFICATION[[:space:]]+Spec$' "$safety_config"; then
    echo "required S3Share safety specification missing in $safety_config" >&2
    exit 1
  fi
done

restart_obligations='BearerAuthorityOnly
OnlyS3ExactGetRequests
RestartPendingHasNoInstalledAuthority
RestartBootstrapUsesSameFixedRootBearer
RecoveredAuthorityExtendsDurableWatermark
DurableWatermarkNeverRegressesOrForks
CrashClearsOnlyVolatileAuthority
DurableRollbackRejectionFailsClosed
RestartRecoveryExtendsPreviousWatermark'

for restart_obligation in $restart_obligations; do
  if ! grep -Eq "^[[:space:]]+${restart_obligation}$" \
    spec/S3ShareRestart.cfg
  then
    echo "required S3Share restart obligation is missing: $restart_obligation" >&2
    exit 1
  fi
done

if ! grep -Eq '^SPECIFICATION[[:space:]]+FairSpec$' \
  spec/S3ShareLiveness.cfg \
  || ! grep -Eq '^[[:space:]]+TimelyStableConsumersConverge$' \
    spec/S3ShareLiveness.cfg
then
  echo "required S3Share liveness specification/property is missing" >&2
  exit 1
fi

model_tmp="$(mktemp -d "${TMPDIR:-/tmp}/s3disk-tlc.XXXXXX")"
trap 'rm -rf -- "$model_tmp"' EXIT HUP INT TERM

main_log="$model_tmp/S3Disk.log"
if ! java -XX:+UseParallelGC -jar "$jar_path" -workers 1 -coverage 1 \
  -metadir "$model_tmp/S3Disk" \
  -config spec/S3Disk.cfg spec/S3Disk.tla >"$main_log" 2>&1
then
  cat "$main_log"
  exit 1
fi
cat "$main_log"

# TLC can report success even when a specification edit accidentally makes an
# important action unreachable. Require non-zero distinct coverage for the
# safety, recovery, adversarial, and availability transitions exercised by the
# main model. DropResponse and Reconnect deliberately are not listed: in the
# current abstraction their enabled executions can be state-equivalent and TLC
# consequently reports zero distinct successor states for them.
critical_actions='RecordPublisherIntent
RecoverPublisherPending
PublisherCASAppliedResponseLost
PublisherCASAppliedResponseReceived
CompetingPublisherCASWins
ProveRemotePublisherHistory
FinalizePublisherJournal
PublisherCrashRestart
PollResponse
AttackerInject
ReceiveAuthorizedReference
RejectUnauthorizedReference
LoadDurable
FetchKnownManifest
PersistValidated
ActivatePersisted
Open
Close
ReturnVerifiedBytes
RejectBadReadResponse
CrashRestart
Partition
ToggleStore
CorruptData
CorruptManifest
StabilizeNetwork'

for action in $critical_actions; do
  if ! grep -Eq "^<${action} .*>: [1-9][0-9]*:" "$main_log"; then
    echo "TLC did not exercise critical action $action" >&2
    exit 1
  fi
done

run_share_case() {
  share_config="$1"
  share_case_name="$(basename "$share_config" .cfg)"
  share_case_log="$model_tmp/$share_case_name.log"
  if ! java -XX:+UseParallelGC -jar "$jar_path" -workers 1 -coverage 1 \
    -metadir "$model_tmp/$share_case_name" \
    -config "$share_config" spec/S3Share.tla >"$share_case_log" 2>&1
  then
    cat "$share_case_log"
    exit 1
  fi
  cat "$share_case_log"
  if ! grep -Fq 'Model checking completed. No error has been found.' \
    "$share_case_log"
  then
    echo "TLC success marker missing for $share_case_name" >&2
    exit 1
  fi
}

require_share_distinct_actions() {
  coverage_log="$1"
  shift
  for action in "$@"; do
    if ! grep -Eq "^<${action} .*>: [1-9][0-9]*:" "$coverage_log"; then
      echo "TLC did not produce a distinct state for $action in $(basename "$coverage_log" .log)" >&2
      exit 1
    fi
  done
}

require_share_enabled_actions() {
  coverage_log="$1"
  shift
  for action in "$@"; do
    if ! grep -Eq "^<${action} .*>: [0-9]+:[1-9][0-9]*" "$coverage_log"; then
      echo "TLC did not enable $action in $(basename "$coverage_log" .log)" >&2
      exit 1
    fi
  done
}

run_share_case spec/S3Share.cfg
share_network_log="$model_tmp/S3Share.log"
require_share_distinct_actions "$share_network_log" \
  PublishRoot StartRootPoll S3ReturnChangedRoot DropRootRequest \
  AcceptAuthenticatedBundle OpenPinned StartLazyGet S3ReturnLazyObject \
  DropLazyRequest DropLazyResponse ReturnPinnedBytes PartitionNetwork \
  SetStoreUnavailable StabilizeNetwork
require_share_enabled_actions "$share_network_log" \
  S3ReturnNotModified DropRootResponse IgnoreStaleBundle RestoreNetwork \
  SetStoreAvailable

run_share_case spec/S3ShareRevision.cfg
share_revision_log="$model_tmp/S3ShareRevision.log"
require_share_distinct_actions "$share_revision_log" \
  PublishRoot StartRootPoll S3ReturnChangedRoot S3ReturnTamperedRoot \
  S3ReturnSignedFork AcceptAuthenticatedBundle RejectUnauthenticatedBundle \
  RejectRollbackOrFork OpenPinned StartLazyGet S3ReturnLazyObject \
  S3ReturnBadLazyResponse ReturnPinnedBytes RejectBadLazyResponse
require_share_enabled_actions "$share_revision_log" \
  S3ReturnNotModified IgnoreStaleBundle

run_share_case spec/S3ShareExpiry.cfg
share_expiry_log="$model_tmp/S3ShareExpiry.log"
require_share_distinct_actions "$share_expiry_log" \
  PublishRoot StartRootPoll S3ReturnChangedRoot S3RejectExpiredRoot \
  AcceptAuthenticatedBundle OpenPinned StartLazyGet S3ReturnLazyObject \
  S3RejectExpiredLazy ReturnPinnedBytes AdvanceServerClock \
  AdvanceLocalClock PhysicalUnmountFailed CompletePhysicalUnmount \
  ServeCachedAfterExpiry
require_share_enabled_actions "$share_expiry_log" \
  S3ReturnNotModified IgnoreStaleBundle

run_share_case spec/S3ShareRestart.cfg
share_restart_log="$model_tmp/S3ShareRestart.log"
require_share_distinct_actions "$share_restart_log" \
  PublishRoot StartRootPoll S3ReturnChangedRoot \
  AcceptAuthenticatedBundle CrashRestart StartRootBootstrap \
  S3ReturnDurableRollback RejectDurableRollbackAfterRestart \
  RecoverAuthenticatedBundleAfterRestart \
  RecoverAuthenticatedBundleAfterRejectedRollback OpenPinned StartLazyGet \
  S3ReturnLazyObject ReturnPinnedBytes

run_share_case spec/S3ShareLiveness.cfg
share_liveness_log="$model_tmp/S3ShareLiveness.log"
if ! grep -Fq 'Checking temporal properties for the complete state space' \
  "$share_liveness_log"
then
  echo "TLC did not check the complete S3Share liveness state space" >&2
  exit 1
fi

for config in \
  spec/S3DiskTwoConsumers.cfg \
  spec/S3DiskLiveness.cfg
do
  case_name="$(basename "$config" .cfg)"
  case_log="$model_tmp/$case_name.log"
  if ! java -XX:+UseParallelGC -jar "$jar_path" -workers 1 -coverage 1 \
    -metadir "$model_tmp/$case_name" \
    -config "$config" spec/S3Disk.tla >"$case_log" 2>&1
  then
    cat "$case_log"
    exit 1
  fi
  cat "$case_log"
  for action in $critical_actions; do
    if ! grep -Eq "^<${action} .*>: [1-9][0-9]*:" "$case_log"; then
      echo "TLC did not exercise critical action $action in $case_name" >&2
      exit 1
    fi
  done
done
