#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$project_dir"

# A bounded sustained-churn profile for scheduled CI. It reuses the scale gate,
# which now reads every generation through both Consumer and WebDAV surfaces.
S3DISK_SCALE_FILES=${S3DISK_SCALE_FILES:-5000}
S3DISK_SCALE_FILE_BYTES=${S3DISK_SCALE_FILE_BYTES:-4096}
S3DISK_SCALE_GENERATIONS=${S3DISK_SCALE_GENERATIONS:-20}
S3DISK_SCALE_READERS=${S3DISK_SCALE_READERS:-16}
export S3DISK_SCALE_FILES S3DISK_SCALE_FILE_BYTES
export S3DISK_SCALE_GENERATIONS S3DISK_SCALE_READERS

exec ./scripts/test-scale.sh
