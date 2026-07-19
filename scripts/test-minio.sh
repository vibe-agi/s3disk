#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$project_dir"

compose_file=${S3DISK_MINIO_COMPOSE_FILE:-testdata/minio.compose.yml}
case "$compose_file" in
  /*) ;;
  *) compose_file="$project_dir/$compose_file" ;;
esac
[ -f "$compose_file" ] && [ ! -L "$compose_file" ] || {
  echo "MinIO Compose fixture must be a regular non-symbolic-link file: $compose_file" >&2
  exit 1
}

project_name="s3disk-test-$$"
cleanup() {
  docker compose --project-name "$project_name" -f "$compose_file" \
    down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker compose --project-name "$project_name" -f "$compose_file" up --detach
port_binding=$(docker compose --project-name "$project_name" \
  -f "$compose_file" port minio 9000)
minio_port=${port_binding##*:}
case "$minio_port" in
  ''|*[!0-9]*)
    echo "could not determine the dynamically published MinIO port: $port_binding" >&2
    exit 1
    ;;
esac

S3DISK_TEST_S3_ENDPOINT="http://127.0.0.1:$minio_port" \
S3DISK_TEST_S3_ACCESS_KEY=s3disk \
S3DISK_TEST_S3_SECRET_KEY=s3disk-secret \
./scripts/run-required-go-test.sh ./s3store TestMinIOAtomicPublishAndLazyRead 60s integration

S3DISK_TEST_S3_ENDPOINT="http://127.0.0.1:$minio_port" \
S3DISK_TEST_S3_ACCESS_KEY=s3disk \
S3DISK_TEST_S3_SECRET_KEY=s3disk-secret \
./scripts/run-required-go-test.sh ./s3store TestMinIOPresignedGetCompatibility 60s integration

S3DISK_TEST_S3_ENDPOINT="http://127.0.0.1:$minio_port" \
S3DISK_TEST_S3_ACCESS_KEY=s3disk \
S3DISK_TEST_S3_SECRET_KEY=s3disk-secret \
./scripts/run-required-go-test.sh ./s3store TestMinIOS3Commissioning 90s integration

S3DISK_TEST_S3_ENDPOINT="http://127.0.0.1:$minio_port" \
S3DISK_TEST_S3_ACCESS_KEY=s3disk \
S3DISK_TEST_S3_SECRET_KEY=s3disk-secret \
./scripts/run-required-go-test.sh ./internal/cli TestMinIOCLIDoctorCommissioning 90s integration

S3DISK_TEST_S3_ENDPOINT="http://127.0.0.1:$minio_port" \
S3DISK_TEST_S3_ACCESS_KEY=s3disk \
S3DISK_TEST_S3_SECRET_KEY=s3disk-secret \
./scripts/run-required-go-test.sh ./s3store TestMinIOOnlyS3PresignedShare 90s integration

S3DISK_TEST_S3_ENDPOINT="http://127.0.0.1:$minio_port" \
S3DISK_TEST_S3_ACCESS_KEY=s3disk \
S3DISK_TEST_S3_SECRET_KEY=s3disk-secret \
./scripts/run-required-go-test.sh ./s3store TestMinIOOnlyS3EncryptedPresignedShare 90s integration

S3DISK_TEST_S3_ENDPOINT="http://127.0.0.1:$minio_port" \
S3DISK_TEST_S3_ACCESS_KEY=s3disk \
S3DISK_TEST_S3_SECRET_KEY=s3disk-secret \
./scripts/run-required-go-test.sh ./internal/cli TestMinIOCLIContinuousHandoffAndCredentialFreeRead 90s integration

if [ "$(go env GOOS)" = linux ]; then
  S3DISK_TEST_S3_ENDPOINT="http://127.0.0.1:$minio_port" \
  S3DISK_TEST_S3_ACCESS_KEY=s3disk \
  S3DISK_TEST_S3_SECRET_KEY=s3disk-secret \
  ./scripts/run-required-go-test.sh ./mount TestLinuxMinIOFUSEEndToEnd 90s integration
else
  if [ "${S3DISK_REQUIRE_FUSE:-0}" = 1 ]; then
    echo "MinIO/FUSE integration requires a Linux host" >&2
    exit 1
  fi
  echo "MinIO/FUSE integration skipped: Linux is required"
fi
