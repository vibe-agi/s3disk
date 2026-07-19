#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
cd "$project_dir"

fail() {
  echo "MinIO Compose policy test: $*" >&2
  exit 1
}

test_tmp=$(mktemp -d "${TMPDIR:-/tmp}/s3disk-compose-policy.XXXXXX")
cleanup() {
  rm -rf -- "$test_tmp"
}
trap cleanup EXIT HUP INT TERM

./scripts/check-minio-compose.sh testdata/minio.compose.yml >/dev/null
clean_copy="$test_tmp/minio.compose.yml"
cp testdata/minio.compose.yml "$clean_copy"
./scripts/check-minio-compose.sh "$clean_copy" >/dev/null || \
  fail "a clean fixture copy did not pass independently of its directory name"

make_attack_fixture() {
  injected_line=$1
  output_file=$2
  awk -v injected="$injected_line" '
    { print }
    $0 == "  minio:" { print "    " injected }
  ' testdata/minio.compose.yml >"$output_file"
}

expect_policy_rejection() {
  attack_name=$1
  attack_file=$2
  if ./scripts/check-minio-compose.sh "$attack_file" \
    >"$test_tmp/$attack_name.stdout" 2>"$test_tmp/$attack_name.stderr"
  then
    fail "$attack_name unexpectedly passed"
  fi
  if ! rg --fixed-strings --quiet \
    'fixture bytes do not match the reviewed SHA-256 digest' \
    "$test_tmp/$attack_name.stderr"
  then
    cat "$test_tmp/$attack_name.stdout" "$test_tmp/$attack_name.stderr" >&2
    fail "$attack_name was not rejected by the exact allowlist"
  fi
}

use_api_socket_fixture="$test_tmp/use-api-socket.compose.yml"
make_attack_fixture 'use_api_socket: true' "$use_api_socket_fixture"
expect_policy_rejection use-api-socket "$use_api_socket_fixture"

provider_fixture="$test_tmp/provider.compose.yml"
make_attack_fixture 'provider: {type: exploit}' "$provider_fixture"
expect_policy_rejection provider "$provider_fixture"

env_file_fixture="$test_tmp/env-file.compose.yml"
make_attack_fixture 'env_file: /dev/null' "$env_file_fixture"
expect_policy_rejection env-file "$env_file_fixture"

echo "MinIO Compose policy test: reviewed fixture passed and API, provider, and env-file injection was rejected"
