#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
cd "$project_dir"

fail() {
  echo "MinIO Compose policy: $*" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$1" | awk '{ print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -- "$1" | awk '{ print $1 }'
  else
    fail "sha256sum or shasum is required"
  fi
}

compose_file=${1:-testdata/minio.compose.yml}
[ -f "$compose_file" ] || fail "fixture is not a regular file: $compose_file"
command -v docker >/dev/null 2>&1 || fail "Docker is required"
command -v jq >/dev/null 2>&1 || fail "jq is required"
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"

expected_fixture_sha256='750e73b1f3371457ffc2600ff9e30197f660b8d49b3daf1fa48ae3290ba95eb7'
actual_fixture_sha256=$(sha256_file "$compose_file")
[ "$actual_fixture_sha256" = "$expected_fixture_sha256" ] || \
  fail "fixture bytes do not match the reviewed SHA-256 digest"

# Validate the fully resolved model rather than grepping source YAML. This is
# an exact allowlist: newly introduced Compose capabilities fail closed until
# their normalized representation and security impact are reviewed.
compose_json=$(docker compose --project-name testdata -f "$compose_file" \
  config --format json) || \
  fail "Docker Compose could not normalize the fixture"
expected_image='quay.io/minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e'
if ! printf '%s\n' "$compose_json" | jq -e --arg image "$expected_image" '
  (keys == ["name", "networks", "services"]) and
  (.name == "testdata") and
  (.networks | keys == ["default"]) and
  (.networks.default | keys == ["ipam", "name"]) and
  (.networks.default.ipam == {}) and
  (.networks.default.name == "testdata_default") and
  (.services | keys == ["minio"]) and
  (.services.minio | keys ==
    ["command", "entrypoint", "environment", "image", "networks", "ports"]) and
  (.services.minio.command ==
    ["server", "/data", "--console-address", ":9001"]) and
  (.services.minio.entrypoint == null) and
  (.services.minio.environment == {
    "MINIO_ROOT_PASSWORD": "s3disk-secret",
    "MINIO_ROOT_USER": "s3disk"
  }) and
  (.services.minio.image == $image) and
  (.services.minio.networks == {"default": null}) and
  (.services.minio.ports == [{
    "mode": "ingress",
    "host_ip": "127.0.0.1",
    "target": 9000,
    "published": "0",
    "protocol": "tcp"
  }])
' >/dev/null
then
  fail "normalized fixture does not match the reviewed exact allowlist"
fi

echo "MinIO Compose policy: fixture digest and normalized model match the reviewed exact allowlist"
