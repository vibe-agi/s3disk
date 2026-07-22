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
  if ! docker compose --project-name "$project_name" -f "$compose_file" \
    down --volumes --remove-orphans >/dev/null 2>&1
  then
    echo "warning: could not remove the MinIO test project $project_name" >&2
  fi
}
trap cleanup EXIT HUP INT TERM

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

command -v jq >/dev/null 2>&1 || {
  echo "jq is required to provision the split-identity MinIO policy" >&2
  exit 1
}
minio_container=$(docker compose --project-name "$project_name" \
  -f "$compose_file" ps -q minio)
[ -n "$minio_container" ] || {
  echo "could not resolve the MinIO test container" >&2
  exit 1
}
ready_attempt=0
until docker exec "$minio_container" mc alias set s3disk-local \
  http://127.0.0.1:9000 s3disk s3disk-secret >/dev/null 2>&1
do
  ready_attempt=$((ready_attempt + 1))
  [ "$ready_attempt" -lt 30 ] || {
    echo "MinIO did not become ready for split-identity provisioning" >&2
    exit 1
  }
  sleep 1
done

split_bucket="s3disk-split-$project_name"
split_signer_access_key="s3disksigner$$"
split_signer_secret_key="s3disk-signer-secret-$$"
split_policy_name="s3disk-split-get-$$"
docker exec "$minio_container" mc mb --ignore-existing \
  "s3disk-local/$split_bucket" >/dev/null
split_policy_json=$(jq -cn --arg bucket "$split_bucket" '{
  Version: "2012-10-17",
  Statement: [{
    Effect: "Allow",
    Action: ["s3:GetObject"],
    Resource: [("arn:aws:s3:::" + $bucket + "/*")]
  }]
}')
docker exec \
  --env "S3DISK_SPLIT_POLICY_JSON=$split_policy_json" \
  --env "S3DISK_SPLIT_POLICY_NAME=$split_policy_name" \
  --env "S3DISK_SPLIT_SIGNER_ACCESS_KEY=$split_signer_access_key" \
  --env "S3DISK_SPLIT_SIGNER_SECRET_KEY=$split_signer_secret_key" \
  "$minio_container" /bin/sh -c '
    set -eu
    umask 077
    policy_file=/tmp/s3disk-split-get-policy.json
    cleanup_policy() { rm -f -- "$policy_file"; }
    trap cleanup_policy EXIT INT TERM
    printf "%s\n" "$S3DISK_SPLIT_POLICY_JSON" >"$policy_file"
    mc admin policy create s3disk-local "$S3DISK_SPLIT_POLICY_NAME" "$policy_file" >/dev/null
    mc admin user add s3disk-local "$S3DISK_SPLIT_SIGNER_ACCESS_KEY" \
      "$S3DISK_SPLIT_SIGNER_SECRET_KEY" >/dev/null
    mc admin policy attach s3disk-local "$S3DISK_SPLIT_POLICY_NAME" \
      --user "$S3DISK_SPLIT_SIGNER_ACCESS_KEY" >/dev/null
  '

S3DISK_TEST_S3_ENDPOINT="http://127.0.0.1:$minio_port" \
S3DISK_TEST_S3_ACCESS_KEY=s3disk \
S3DISK_TEST_S3_SECRET_KEY=s3disk-secret \
./scripts/run-required-go-test.sh ./s3store TestMinIOAtomicPublishAndLazyRead 60s integration

S3DISK_TEST_S3_ENDPOINT="http://127.0.0.1:$minio_port" \
S3DISK_TEST_S3_ACCESS_KEY=s3disk \
S3DISK_TEST_S3_SECRET_KEY=s3disk-secret \
./scripts/run-required-go-test.sh ./s3store \
  TestMinIODisasterBackupRestoreAndKeyRetirement 120s integration

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
S3DISK_TEST_S3_SPLIT_BUCKET="$split_bucket" \
S3DISK_TEST_S3_SIGNER_ACCESS_KEY="$split_signer_access_key" \
S3DISK_TEST_S3_SIGNER_SECRET_KEY="$split_signer_secret_key" \
./scripts/run-required-go-test.sh ./s3store \
  TestMinIOSplitWriterPresignerCommissioning 90s integration

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

S3DISK_TEST_S3_ENDPOINT="http://127.0.0.1:$minio_port" \
S3DISK_TEST_S3_ACCESS_KEY=s3disk \
S3DISK_TEST_S3_SECRET_KEY=s3disk-secret \
./scripts/run-required-go-test.sh ./internal/cli TestMinIOCLIOneShotPublishAndResume 90s integration

S3DISK_TEST_S3_ENDPOINT="http://127.0.0.1:$minio_port" \
S3DISK_TEST_S3_ACCESS_KEY=s3disk \
S3DISK_TEST_S3_SECRET_KEY=s3disk-secret \
./scripts/run-required-go-test.sh ./webdav TestMinIOWebDAVEndToEnd 90s integration

fuse_available=false
case "$(go env GOOS)" in
  linux)
    if [ -r /dev/fuse ] && [ -w /dev/fuse ] && command -v fusermount3 >/dev/null 2>&1; then
      fuse_available=true
    fi
    ;;
  darwin)
    macfuse_helper=false
    for mount_helper in \
      /Library/Filesystems/macfuse.fs/Contents/Resources/mount_macfuse \
      /Library/Filesystems/osxfuse.fs/Contents/Resources/mount_osxfuse
    do
      if [ -x "$mount_helper" ]; then
        macfuse_helper=true
        break
      fi
    done
    if [ "$macfuse_helper" = true ]; then
      for fuse_device in /dev/macfuse* /dev/osxfuse*
      do
        if [ -c "$fuse_device" ] && [ -r "$fuse_device" ] && [ -w "$fuse_device" ]; then
          fuse_available=true
          break
        fi
      done
    fi
    ;;
esac

if [ "$fuse_available" = true ]; then
  S3DISK_TEST_S3_ENDPOINT="http://127.0.0.1:$minio_port" \
  S3DISK_TEST_S3_ACCESS_KEY=s3disk \
  S3DISK_TEST_S3_SECRET_KEY=s3disk-secret \
  ./scripts/run-required-go-test.sh ./mount TestMinIOFUSEEndToEnd 90s integration
else
  if [ "${S3DISK_REQUIRE_FUSE:-0}" = 1 ]; then
    echo "MinIO/FUSE integration requires an available FUSE runtime" >&2
    exit 1
  fi
  echo "MinIO/FUSE integration skipped: no usable FUSE runtime"
fi
