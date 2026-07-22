#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$project_dir"

S3DISK_RUN_SCALE=1
S3DISK_SCALE_FILES=${S3DISK_SCALE_FILES:-2000}
S3DISK_SCALE_FILE_BYTES=${S3DISK_SCALE_FILE_BYTES:-1024}
S3DISK_SCALE_GENERATIONS=${S3DISK_SCALE_GENERATIONS:-3}
S3DISK_SCALE_READERS=${S3DISK_SCALE_READERS:-8}
export S3DISK_RUN_SCALE S3DISK_SCALE_FILES S3DISK_SCALE_FILE_BYTES
export S3DISK_SCALE_GENERATIONS S3DISK_SCALE_READERS

./scripts/run-required-go-test.sh ./tests/blackbox TestWorkspaceScaleProfile 10m scale
