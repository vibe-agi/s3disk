#!/bin/sh
set -eu

fail() {
  echo "DCO audit self-test: $*" >&2
  exit 1
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
checker="$script_dir/check-dco.sh"
test_repository=$(mktemp -d "${TMPDIR:-/tmp}/s3disk-dco-test.XXXXXX")
cleanup() {
  rm -rf -- "$test_repository"
}
trap cleanup EXIT HUP INT TERM

git -C "$test_repository" init -q
git -C "$test_repository" config user.name "DCO Test Contributor"
git -C "$test_repository" config user.email "dco-test@example.invalid"

printf '%s\n' first >"$test_repository/tracked.txt"
git -C "$test_repository" add tracked.txt
git -C "$test_repository" commit -q -s -m "Signed commit"
(
  cd "$test_repository"
  "$checker" 'HEAD^!' >/dev/null
)

printf '%s\n' second >>"$test_repository/tracked.txt"
git -C "$test_repository" add tracked.txt
git -C "$test_repository" commit -q -m "Unsigned commit"
if (
  cd "$test_repository"
  "$checker" 'HEAD^!' >/dev/null 2>&1
); then
  fail "unsigned commit passed"
fi
if (
  cd "$test_repository"
  "$checker" HEAD~1..HEAD >/dev/null 2>&1
); then
  fail "unsigned range passed"
fi

git -C "$test_repository" commit -q --amend -s --no-edit
(
  cd "$test_repository"
  "$checker" HEAD~1..HEAD >/dev/null
)

printf '%s\n' third >>"$test_repository/tracked.txt"
git -C "$test_repository" add tracked.txt
git -C "$test_repository" commit -q -m "Mismatched sign-off" \
  -m "Signed-off-by: Different Person <different@example.invalid>"
if (
  cd "$test_repository"
  "$checker" 'HEAD^!' >/dev/null 2>&1
); then
  fail "mismatched sign-off passed"
fi

printf '%s\n' fourth >>"$test_repository/tracked.txt"
git -C "$test_repository" add tracked.txt
git -C "$test_repository" commit -q -s -m "Signed after unsigned"
if (
  cd "$test_repository"
  "$checker" HEAD~2..HEAD >/dev/null 2>&1
); then
  fail "multi-commit range ignored an earlier unsigned commit"
fi
if (
  cd "$test_repository"
  "$checker" HEAD >/dev/null 2>&1
); then
  fail "single revision did not scan its unsigned ancestry"
fi

if (
  cd "$test_repository"
  "$checker" does-not-exist >/dev/null 2>&1
); then
  fail "invalid revision passed"
fi

echo "DCO audit self-test: pass"
