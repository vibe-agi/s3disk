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
S3DISK_REQUIRE_FUSE=1 ./scripts/run-required-go-test.sh \
  ./mount TestFUSEMountRefreshAndSnapshotPinning 60s integration

S3DISK_REQUIRE_FUSE=1 ./scripts/run-required-go-test.sh \
  ./internal/cli TestMountSetSupervisesTwoRealFUSEMounts 60s integration
