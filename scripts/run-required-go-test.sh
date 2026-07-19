#!/bin/sh
set -eu

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  echo "usage: $0 PACKAGE EXACT_TEST TIMEOUT [TAGS]" >&2
  exit 2
fi

package_name=$1
test_name=$2
test_timeout=$3
test_tags=${4:-}
case "$test_name" in
  Test*) ;;
  *)
    echo "required Go test has an unsafe name: $test_name" >&2
    exit 2
    ;;
esac
case "$test_name" in
  *[!A-Za-z0-9_]*)
    echo "required Go test has an unsafe name: $test_name" >&2
    exit 2
    ;;
esac

test_log=$(mktemp "${TMPDIR:-/tmp}/s3disk-required-test.XXXXXX")
cleanup() {
  rm -f -- "$test_log"
}
trap cleanup EXIT HUP INT TERM

if [ -n "$test_tags" ]; then
  test_status=0
  go test -json -tags="$test_tags" "$package_name" \
    -run "^${test_name}$" -count=1 -timeout="$test_timeout" >"$test_log" 2>&1 || test_status=$?
else
  test_status=0
  go test -json "$package_name" \
    -run "^${test_name}$" -count=1 -timeout="$test_timeout" >"$test_log" 2>&1 || test_status=$?
fi
cat "$test_log"
[ "$test_status" -eq 0 ] || exit "$test_status"

# `go test -run` exits successfully when no test matches. Require an exact,
# non-skipped test event so a rename or build-tag mistake cannot make a release
# gate silently green.
if ! awk -v test="$test_name" '
  index($0, "\"Test\":\"" test "\"") {
    if (index($0, "\"Action\":\"run\"")) run = 1
    if (index($0, "\"Action\":\"pass\"")) pass = 1
    if (index($0, "\"Action\":\"skip\"") || index($0, "\"Action\":\"fail\"")) bad = 1
  }
  END { exit !(run && pass && !bad) }
' "$test_log"
then
  echo "required Go test $test_name did not run and pass without skipping" >&2
  exit 1
fi
