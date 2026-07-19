#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$project_dir"

# Do not let a caller's workspace or module flags change the dependency graph
# used for release evidence.
GOWORK=off
GOFLAGS=-mod=readonly
GOTOOLCHAIN=local
export GOWORK GOFLAGS GOTOOLCHAIN

fail() {
  echo "commercial release gate: $*" >&2
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

write_sha256_manifest() {
  manifest_directory=$1
  shift
  manifest_tmp=$(mktemp "$manifest_directory/.release-evidence.XXXXXX")
  (
    cd "$manifest_directory"
    for manifest_file in "$@"
    do
      printf '%s  %s\n' "$(sha256_file "$manifest_file")" "$manifest_file"
    done
  ) >"$manifest_tmp"
  mv -f -- "$manifest_tmp" "$manifest_directory/release-evidence.sha256"
}

[ "$(id -u)" -ne 0 ] || fail "the commercial release gate must not run as root"
[ -z "${S3DISK_RELEASE_TESTING-}" ] || \
  fail "S3DISK_RELEASE_TESTING is forbidden in the commercial release gate"

release_tmp=$(mktemp -d "${TMPDIR:-/tmp}/s3disk-release-gate.XXXXXX")
cleanup() {
  rm -rf -- "$release_tmp"
}
trap cleanup EXIT HUP INT TERM

require_clean_tree() {
  git diff --quiet || fail "working tree has unstaged tracked changes"
  git diff --cached --quiet || fail "working tree has staged changes"
  git status --porcelain=v1 --untracked-files=all --ignored=matching >"$release_tmp/status"
  [ ! -s "$release_tmp/status" ] || {
    cat "$release_tmp/status" >&2
    fail "working tree contains tracked changes, untracked files, or ignored files; run the gate from a pristine checkout"
  }
}

for required_file in \
  LICENSE NOTICE README.md CONTRIBUTING.md SECURITY.md THIRD_PARTY_NOTICES.md \
  docs/COMPATIBILITY.md docs/COMMERCIAL_RELEASE.md .github/CODEOWNERS \
  .github/workflows/ci.yml .github/workflows/dco.yml \
  scripts/check-dco.sh scripts/test-dco.sh
do
  [ -s "$required_file" ] || fail "missing or empty $required_file"
done
if rg --ignore-case --quiet 'license[[:space:]]+pending|distribution[[:space:]]+is[[:space:]]+not[[:space:]]+authorized' LICENSE; then
  fail "LICENSE still contains a pending or non-authorization notice"
fi

release_blocker_marker='RELEASE''-BLOCKER'
if release_blockers=$(rg --hidden --line-number --fixed-strings \
	  --no-ignore --glob '!.git/**' -- "$release_blocker_marker" . 2>&1)
then
  printf '%s\n' "$release_blockers" >&2
  fail "one or more release blockers remain; resolve every marker before release"
else
  blocker_scan_status=$?
  if [ "$blocker_scan_status" -ne 1 ]; then
    printf '%s\n' "$release_blockers" >&2
    fail "could not complete the release-blocker scan"
  fi
fi

required_go_version=go1.26.5
actual_go_version=$(go env GOVERSION)
[ "$actual_go_version" = "$required_go_version" ] || \
  fail "use patched toolchain $required_go_version (found $actual_go_version); update the baseline after each Go security release"

git rev-parse --verify HEAD >/dev/null 2>&1 || fail "repository has no release commit"
require_clean_tree
for required_environment in \
  S3DISK_RELEASE_MODE S3DISK_RELEASE_VERSION S3DISK_RELEASE_COMMIT \
  S3DISK_RELEASE_EVIDENCE_DIR
do
  eval "required_value=\${$required_environment-}"
  [ -n "$required_value" ] || fail "$required_environment is required"
done
release_mode=$S3DISK_RELEASE_MODE
release_version=$S3DISK_RELEASE_VERSION
release_commit=$S3DISK_RELEASE_COMMIT
release_evidence_input=$S3DISK_RELEASE_EVIDENCE_DIR
release_signers_file=${S3DISK_RELEASE_SIGNERS_FILE-}
release_openpgp_program=${S3DISK_RELEASE_OPENPGP_PROGRAM-}
if [ "$release_mode" = release ]; then
  [ -n "$release_signers_file" ] || \
    fail "S3DISK_RELEASE_SIGNERS_FILE is required in release mode"
  [ -n "$release_openpgp_program" ] || \
    fail "S3DISK_RELEASE_OPENPGP_PROGRAM is required in release mode"
fi

# Never expose protected release-policy paths or the upload directory to code
# from the candidate checkout. Reference checks receive them only for the
# duration of the checker process.
unset S3DISK_RELEASE_MODE S3DISK_RELEASE_VERSION S3DISK_RELEASE_COMMIT \
  S3DISK_RELEASE_EVIDENCE_DIR S3DISK_RELEASE_SIGNERS_FILE \
  S3DISK_RELEASE_OPENPGP_PROGRAM S3DISK_RELEASE_TESTING

case "$release_evidence_input" in
  /*) ;;
  *) fail "S3DISK_RELEASE_EVIDENCE_DIR must be an absolute path" ;;
esac
[ -d "$release_evidence_input" ] || fail "release evidence directory does not exist"
[ ! -L "$release_evidence_input" ] || \
  fail "release evidence directory must not be a symbolic link"
release_evidence_dir=$(CDPATH= cd -- "$release_evidence_input" && pwd -P) || \
  fail "cannot resolve release evidence directory"
case "$release_evidence_dir" in
  "$project_dir"|"$project_dir"/*)
    fail "release evidence must be written outside the source checkout"
    ;;
esac
for reserved_evidence in \
  release-reference.json release-tag-verification.status \
  release-gate-success.json release-evidence.sha256
do
  [ ! -e "$release_evidence_dir/$reserved_evidence" ] || \
    fail "release evidence directory contains stale $reserved_evidence"
done

run_reference_check() {
  reference_evidence_dir=$1
  if [ "$release_mode" = release ]; then
    S3DISK_RELEASE_MODE=$release_mode \
    S3DISK_RELEASE_VERSION=$release_version \
    S3DISK_RELEASE_COMMIT=$release_commit \
    S3DISK_RELEASE_EVIDENCE_DIR=$reference_evidence_dir \
    S3DISK_RELEASE_SIGNERS_FILE=$release_signers_file \
    S3DISK_RELEASE_OPENPGP_PROGRAM=$release_openpgp_program \
      ./scripts/check-release-ref.sh
  else
    S3DISK_RELEASE_MODE=$release_mode \
    S3DISK_RELEASE_VERSION=$release_version \
    S3DISK_RELEASE_COMMIT=$release_commit \
    S3DISK_RELEASE_EVIDENCE_DIR=$reference_evidence_dir \
      ./scripts/check-release-ref.sh
  fi
}

initial_reference_dir="$release_tmp/initial-reference"
mkdir "$initial_reference_dir"
chmod 700 "$initial_reference_dir"
run_reference_check "$initial_reference_dir"
initial_reference_sha256=$(sha256_file "$initial_reference_dir/release-reference.json")

go list -m -json all >"$release_tmp/modules.json"
if rg --quiet '"Replace"[[:space:]]*:' "$release_tmp/modules.json"; then
  fail "go.mod build list contains a replace directive"
fi

tidy_diff=$(go mod tidy -diff)
[ -z "$tidy_diff" ] || {
  printf '%s\n' "$tidy_diff" >&2
  fail "go.mod or go.sum is not tidy"
}
go mod verify

unformatted=$(rg --files -g '*.go' -0 | xargs -0 gofmt -l)
[ -z "$unformatted" ] || {
  printf '%s\n' "$unformatted" >&2
  fail "Go source is not gofmt-formatted"
}

./scripts/check-project-license.sh
./scripts/check-third-party.sh
./scripts/check-dco.sh HEAD
./scripts/test-dco.sh
./scripts/test-release-ref.sh

command -v actionlint >/dev/null 2>&1 || fail "actionlint v1.7.7 is required on the reviewed release runner"
actionlint_version=$(actionlint -version)
printf '%s\n' "$actionlint_version"
printf '%s\n' "$actionlint_version" | rg --quiet '(^|[[:space:]@])1\.7\.7($|[[:space:]])' || \
  fail "use reviewed actionlint v1.7.7"
actionlint -color=false

go test ./... -count=1 -timeout=90s
go test -race ./... -count=1 -timeout=180s
go vet ./...

[ "$(go env GOOS)" = linux ] || fail "the commercial release gate must run on Linux for the FUSE E2E test"
./scripts/test-mount-linux.sh

for target in \
  linux/amd64 linux/arm64 \
  darwin/amd64 darwin/arm64 \
  freebsd/amd64 \
  windows/amd64 windows/arm64
do
  target_os=${target%/*}
  target_arch=${target#*/}
  echo "commercial release gate: build $target_os/$target_arch"
  GOOS="$target_os" GOARCH="$target_arch" CGO_ENABLED=0 \
    go build -trimpath ./...
done

command -v govulncheck >/dev/null 2>&1 || \
  fail "govulncheck is required; install it with: go install golang.org/x/vuln/cmd/govulncheck@v1.6.0"
required_govulncheck_version=v1.6.0
govulncheck_metadata=$(govulncheck -version)
printf '%s\n' "$govulncheck_metadata"
printf '%s\n' "$govulncheck_metadata" | \
  rg --quiet "^[[:space:]]*Scanner: govulncheck@$required_govulncheck_version[[:space:]]*$" || \
  fail "use govulncheck $required_govulncheck_version and update the checked-in baseline after review"
govulncheck -scan=module

command -v docker >/dev/null 2>&1 || fail "Docker is required for the MinIO integration gate"
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
reviewed_compose="$release_tmp/minio.compose.yml"
cp testdata/minio.compose.yml "$reviewed_compose"
chmod 400 "$reviewed_compose"
./scripts/check-minio-compose.sh "$reviewed_compose"
./scripts/test-minio-compose-policy.sh
S3DISK_REQUIRE_FUSE=1 S3DISK_MINIO_COMPOSE_FILE="$reviewed_compose" \
  ./scripts/test-minio.sh
./scripts/check-minio-compose.sh "$reviewed_compose"

./scripts/check-model.sh

require_clean_tree

final_reference_dir="$release_tmp/final-reference"
mkdir "$final_reference_dir"
chmod 700 "$final_reference_dir"
run_reference_check "$final_reference_dir"
final_reference_sha256=$(sha256_file "$final_reference_dir/release-reference.json")
if [ "$initial_reference_sha256" != "$final_reference_sha256" ]; then
  diff -u "$initial_reference_dir/release-reference.json" \
    "$final_reference_dir/release-reference.json" >&2 || true
  fail "release reference identity changed while the commercial gate was running"
fi

# Only now, after every candidate-controlled test has exited, publish the
# verified identity and an unambiguous success marker to the upload directory.
reference_tmp=$(mktemp "$release_evidence_dir/.release-reference.XXXXXX")
cp "$final_reference_dir/release-reference.json" "$reference_tmp"
mv -f -- "$reference_tmp" "$release_evidence_dir/release-reference.json"
[ "$(sha256_file "$release_evidence_dir/release-reference.json")" = \
  "$final_reference_sha256" ] || fail "exported release reference hash changed"
evidence_files="release-reference.json"
if [ "$release_mode" = release ]; then
  status_tmp=$(mktemp "$release_evidence_dir/.release-tag-verification.XXXXXX")
  cp "$final_reference_dir/release-tag-verification.status" "$status_tmp"
  mv -f -- "$status_tmp" "$release_evidence_dir/release-tag-verification.status"
  evidence_files="$evidence_files release-tag-verification.status"
fi
release_tree=$(git rev-parse --verify "$release_commit^{tree}")
success_tmp=$(mktemp "$release_evidence_dir/.release-gate-success.XXXXXX")
cat >"$success_tmp" <<EOF
{
  "schema_version": 1,
  "mode": "$release_mode",
  "version": "$release_version",
  "commit": "$release_commit",
  "tree": "$release_tree"
}
EOF
mv -f -- "$success_tmp" "$release_evidence_dir/release-gate-success.json"
# Word splitting here is intentional: evidence_files contains only the fixed
# filenames selected above, never caller-controlled data.
# shellcheck disable=SC2086
write_sha256_manifest "$release_evidence_dir" $evidence_files release-gate-success.json
success_manifest_sha256=$(sha256_file "$release_evidence_dir/release-gate-success.json")
evidence_hashes_sha256=$(sha256_file "$release_evidence_dir/release-evidence.sha256")

echo "commercial release gate: automated checks passed"
echo "commercial release gate: success manifest sha256 $success_manifest_sha256"
echo "commercial release gate: evidence manifest sha256 $evidence_hashes_sha256"
if [ "$release_mode" = candidate ]; then
  echo "Candidate $release_version at $release_commit is eligible for post-gate protected approval."
  echo "Create and push no tag unless the archived candidate evidence has been approved."
else
  echo "Post-publication verification passed for $release_version at $release_commit."
fi
