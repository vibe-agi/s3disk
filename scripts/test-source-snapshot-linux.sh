#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$project_dir"

[ "$(uname -s)" = Linux ] || {
  echo "the LVM source-snapshot drill requires Linux" >&2
  exit 1
}
[ "$(id -u)" -eq 0 ] || {
  echo "the isolated loop/LVM source-snapshot drill must run as root" >&2
  exit 1
}
for tool in losetup pvcreate vgcreate lvcreate lvremove vgremove pvremove mkfs.ext4 fsfreeze mount umount truncate; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "$tool is required for the LVM source-snapshot drill" >&2
    exit 1
  }
done

test_root=$(mktemp -d /var/tmp/s3disk-lvm-drill.XXXXXX)
case "$test_root" in
  /var/tmp/s3disk-lvm-drill.*) ;;
  *)
    echo "refusing unexpected LVM drill directory: $test_root" >&2
    exit 1
    ;;
esac
backing_file="$test_root/lvm.img"
live_mount="$test_root/live"
snapshot_mount="$test_root/snapshot"
volume_group="s3diskdr$$"
loop_device=""
live_mounted=false
snapshot_mounted=false
live_frozen=false
volume_group_created=false
physical_volume_created=false
live_volume_created=false
snapshot_volume_created=false
mkdir "$live_mount" "$snapshot_mount"

cleanup() {
  original_status=$?
  cleanup_failed=false
  if [ "$live_frozen" = true ]; then
    if fsfreeze --unfreeze "$live_mount" >/dev/null 2>&1; then
      live_frozen=false
    else
      echo "could not unfreeze isolated live mount $live_mount" >&2
      cleanup_failed=true
    fi
  fi
  if [ "$snapshot_mounted" = true ]; then
    if umount "$snapshot_mount" >/dev/null 2>&1; then
      snapshot_mounted=false
    else
      echo "could not unmount isolated snapshot $snapshot_mount" >&2
      cleanup_failed=true
    fi
  fi
  if [ "$live_mounted" = true ]; then
    if umount "$live_mount" >/dev/null 2>&1; then
      live_mounted=false
    else
      echo "could not unmount isolated live volume $live_mount" >&2
      cleanup_failed=true
    fi
  fi
  if [ "$cleanup_failed" = false ] && [ "$snapshot_volume_created" = true ]; then
    if lvremove --force --yes "/dev/$volume_group/frozen" >/dev/null 2>&1; then
      snapshot_volume_created=false
    else
      echo "could not remove isolated snapshot LV $volume_group/frozen" >&2
      cleanup_failed=true
    fi
  fi
  if [ "$cleanup_failed" = false ] && [ "$live_volume_created" = true ]; then
    if lvremove --force --yes "/dev/$volume_group/live" >/dev/null 2>&1; then
      live_volume_created=false
    else
      echo "could not remove isolated live LV $volume_group/live" >&2
      cleanup_failed=true
    fi
  fi
  if [ "$cleanup_failed" = false ] && [ "$volume_group_created" = true ]; then
    if vgremove --force --yes "$volume_group" >/dev/null 2>&1; then
      volume_group_created=false
    else
      echo "could not remove isolated volume group $volume_group" >&2
      cleanup_failed=true
    fi
  fi
  if [ "$cleanup_failed" = false ] && [ "$physical_volume_created" = true ] && [ -n "$loop_device" ]; then
    if pvremove --force --yes "$loop_device" >/dev/null 2>&1; then
      physical_volume_created=false
    else
      echo "could not remove isolated physical volume $loop_device" >&2
      cleanup_failed=true
    fi
  fi
  if [ "$cleanup_failed" = false ] && [ -n "$loop_device" ]; then
    if losetup --detach "$loop_device" >/dev/null 2>&1; then
      loop_device=""
    else
      echo "could not detach isolated loop device $loop_device" >&2
      cleanup_failed=true
    fi
  fi
  if [ "$cleanup_failed" = false ]; then
    if ! find "$test_root" -depth -delete >/dev/null 2>&1; then
      echo "could not remove LVM drill directory $test_root" >&2
      cleanup_failed=true
    fi
  else
    echo "retained isolated LVM drill resources below $test_root for safe cleanup" >&2
  fi
  trap - EXIT HUP INT TERM
  if [ "$cleanup_failed" = true ] && [ "$original_status" -eq 0 ]; then
    original_status=1
  fi
  exit "$original_status"
}
trap cleanup EXIT HUP INT TERM

truncate --size 512M "$backing_file"
loop_device=$(losetup --find --show "$backing_file")
pvcreate --yes --force "$loop_device" >/dev/null
physical_volume_created=true
vgcreate "$volume_group" "$loop_device" >/dev/null
volume_group_created=true
lvcreate --yes --size 192M --name live "$volume_group" >/dev/null
live_volume_created=true
mkfs.ext4 -q "/dev/$volume_group/live"
mount "/dev/$volume_group/live" "$live_mount"
live_mounted=true
mkdir -p "$live_mount/workspace"
printf 'frozen-before-snapshot\n' >"$live_mount/workspace/marker.txt"
dd if=/dev/zero of="$live_mount/workspace/payload.bin" bs=1M count=16 status=none
sync

# The freeze is a short application-consistency barrier. LVM then creates an
# atomic COW snapshot, which is mounted read-only and becomes Publisher's source.
fsfreeze --freeze "$live_mount"
live_frozen=true
lvcreate --yes --snapshot --size 192M --name frozen "/dev/$volume_group/live" >/dev/null
snapshot_volume_created=true
fsfreeze --unfreeze "$live_mount"
live_frozen=false
mount -o ro,noload "/dev/$volume_group/frozen" "$snapshot_mount"
snapshot_mounted=true
printf 'changed-after-snapshot\n' >"$live_mount/workspace/marker.txt"
sync

S3DISK_TEST_SNAPSHOT_SOURCE="$snapshot_mount" \
S3DISK_TEST_LIVE_SOURCE="$live_mount" \
./scripts/run-required-go-test.sh ./tests/blackbox \
  TestAtomicSourceSnapshotPublication 90s integration
