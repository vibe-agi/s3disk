#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$project_dir"

[ "$(go env GOOS)" = darwin ] || {
  echo "macOS is required for the macFUSE integration gate" >&2
  exit 1
}

mount_helper=
for candidate in \
  /Library/Filesystems/macfuse.fs/Contents/Resources/mount_macfuse \
  /Library/Filesystems/osxfuse.fs/Contents/Resources/mount_osxfuse
do
  if [ -x "$candidate" ]; then
    mount_helper=$candidate
    break
  fi
done
[ -n "$mount_helper" ] || {
  echo "a separately installed macFUSE runtime is required for the macOS mount gate" >&2
  exit 1
}

printf 'macFUSE helper: %s\n' "$mount_helper"
backend=${S3DISK_TEST_MACOS_BACKEND:-auto}
case "$backend" in
  auto|vfs) ;;
  fskit)
    mount_root=${S3DISK_TEST_MOUNT_ROOT:-}
    [ -n "$mount_root" ] && [ -d "$mount_root" ] && [ -w "$mount_root" ] || {
      echo "FSKit tests require a writable S3DISK_TEST_MOUNT_ROOT below /Volumes" >&2
      exit 1
    }
    case "$mount_root" in
      /Volumes/*) ;;
      *)
        echo "FSKit test mount root must be below /Volumes: $mount_root" >&2
        exit 1
        ;;
    esac
    ;;
  *)
    echo "S3DISK_TEST_MACOS_BACKEND must be auto, vfs, or fskit" >&2
    exit 1
    ;;
esac
printf 'macFUSE backend: %s\n' "$backend"
S3DISK_REQUIRE_FUSE=1 ./scripts/run-required-go-test.sh \
  ./mount TestFUSEMountRefreshAndSnapshotPinning 60s integration

S3DISK_REQUIRE_FUSE=1 ./scripts/run-required-go-test.sh \
  ./internal/cli TestMountSetSupervisesTwoRealFUSEMounts 60s integration
