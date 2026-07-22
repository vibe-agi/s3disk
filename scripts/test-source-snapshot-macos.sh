#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$project_dir"

[ "$(uname -s)" = Darwin ] || {
  echo "the APFS source-snapshot drill requires macOS" >&2
  exit 1
}
command -v hdiutil >/dev/null 2>&1 || {
  echo "hdiutil is required for the APFS source-snapshot drill" >&2
  exit 1
}

test_root=$(mktemp -d "${TMPDIR:-/tmp}/s3disk-apfs-drill.XXXXXX")
case "$test_root" in
  "${TMPDIR:-/tmp}"/s3disk-apfs-drill.*) ;;
  *)
    echo "refusing unexpected APFS drill directory: $test_root" >&2
    exit 1
    ;;
esac
image_path="$test_root/source.dmg"
shadow_path="$test_root/live.shadow"
live_mount="$test_root/live"
snapshot_mount="$test_root/snapshot"
live_attached=false
snapshot_attached=false
mkdir "$live_mount" "$snapshot_mount"

cleanup() {
  original_status=$?
  cleanup_failed=false
  if [ "$live_attached" = true ]; then
    if hdiutil detach "$live_mount" >/dev/null 2>&1; then
      live_attached=false
    else
      echo "could not detach APFS live mount $live_mount" >&2
      cleanup_failed=true
    fi
  fi
  if [ "$snapshot_attached" = true ]; then
    if hdiutil detach "$snapshot_mount" >/dev/null 2>&1; then
      snapshot_attached=false
    else
      echo "could not detach APFS snapshot mount $snapshot_mount" >&2
      cleanup_failed=true
    fi
  fi
  if [ "$cleanup_failed" = false ]; then
    if ! find "$test_root" -depth -delete >/dev/null 2>&1; then
      echo "could not remove APFS drill directory $test_root" >&2
      cleanup_failed=true
    fi
  else
    echo "retained isolated APFS drill resources below $test_root for safe cleanup" >&2
  fi
  trap - EXIT HUP INT TERM
  if [ "$cleanup_failed" = true ] && [ "$original_status" -eq 0 ]; then
    original_status=1
  fi
  exit "$original_status"
}
trap cleanup EXIT HUP INT TERM

# A detached APFS image is the atomic checkpoint. The read-only attachment is
# the publisher source; a second attachment writes through a COW shadow file,
# preserving the exact base image while the live workspace keeps changing.
hdiutil create -quiet -size 128m -fs APFS -volname S3DiskSource -type UDIF "$image_path"
hdiutil attach -quiet -nobrowse -mountpoint "$live_mount" "$image_path"
live_attached=true
mkdir -p "$live_mount/workspace"
printf 'frozen-before-snapshot\n' >"$live_mount/workspace/marker.txt"
dd if=/dev/zero of="$live_mount/workspace/payload.bin" bs=1m count=16 2>/dev/null
sync
hdiutil detach "$live_mount" >/dev/null
live_attached=false

hdiutil attach -quiet -readonly -nobrowse -mountpoint "$snapshot_mount" "$image_path"
snapshot_attached=true
hdiutil attach -quiet -shadow "$shadow_path" -nobrowse -mountpoint "$live_mount" "$image_path"
live_attached=true
printf 'changed-after-snapshot\n' >"$live_mount/workspace/marker.txt"
sync

S3DISK_TEST_SNAPSHOT_SOURCE="$snapshot_mount" \
S3DISK_TEST_LIVE_SOURCE="$live_mount" \
./scripts/run-required-go-test.sh ./tests/blackbox \
  TestAtomicSourceSnapshotPublication 90s integration
