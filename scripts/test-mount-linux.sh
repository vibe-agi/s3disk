#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$project_dir"

[ "$(go env GOOS)" = linux ] || {
  echo "Linux is required for the FUSE integration gate" >&2
  exit 1
}
[ -c /dev/fuse ] || {
  echo "/dev/fuse is required for the FUSE integration gate" >&2
  exit 1
}

S3DISK_REQUIRE_FUSE=1 ./scripts/run-required-go-test.sh \
  ./mount TestLinuxMountRefreshAndSnapshotPinning 45s integration

S3DISK_REQUIRE_FUSE=1 ./scripts/run-required-go-test.sh \
  ./internal/cli TestLinuxMountSetSupervisesTwoRealFUSEMounts 45s integration
