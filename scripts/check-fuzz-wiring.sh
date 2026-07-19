#!/bin/sh
set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$project_dir"

workflow=.github/workflows/ci.yml
[ -f "$workflow" ] || {
  echo "fuzz wiring audit: missing $workflow" >&2
  exit 1
}
command -v rg >/dev/null 2>&1 || {
  echo "fuzz wiring audit: rg is required" >&2
  exit 1
}

source_targets=$(mktemp "${TMPDIR:-/tmp}/s3disk-fuzz-source.XXXXXX")
wired_targets=$(mktemp "${TMPDIR:-/tmp}/s3disk-fuzz-wired.XXXXXX")
cleanup() {
  rm -f "$source_targets" "$wired_targets"
}
trap cleanup EXIT HUP INT TERM

# Keep the package path in the identity. Go permits the same fuzz function name
# in different packages, and wiring either one to the wrong package must fail
# this audit instead of being hidden by a name-only comparison.
rg --files -g '*_test.go' |
  while IFS= read -r source_file; do
    case "$source_file" in
      */*) package_path=./${source_file%/*} ;;
      *) package_path=./ ;;
    esac
    awk -v package_path="$package_path" '
      /^func Fuzz[A-Za-z0-9_]+\(/ {
        target = $0
        sub(/^func /, "", target)
        sub(/\(.*/, "", target)
        print package_path "\t" target
      }
    ' "$source_file"
  done |
  sort >"$source_targets"

# CI fuzz commands intentionally use this regular shape:
#   go test <package> ... -fuzz='^FuzzName$' ...
# Parsing shell command fields (rather than arbitrary YAML text) prevents a
# comment or echo from satisfying the gate. Exact package/name pairs also catch
# commands that invoke a real target in the wrong package.
awk '
  $1 == "go" && $2 == "test" {
    package_path = $3
    for (field = 4; field <= NF; field++) {
      if ($field ~ /^-fuzz=\047\^Fuzz[A-Za-z0-9_]+\$\047$/) {
        target = $field
        sub(/^-fuzz=\047\^/, "", target)
        sub(/\$\047$/, "", target)
        print package_path "\t" target
      }
    }
  }
' "$workflow" |
  sort >"$wired_targets"

if ! cmp -s "$source_targets" "$wired_targets"; then
  echo "fuzz wiring audit: source fuzz targets and CI smoke targets differ" >&2
  diff -u "$source_targets" "$wired_targets" >&2 || true
  exit 1
fi

target_count=$(wc -l <"$source_targets" | tr -d ' ')
[ "$target_count" -gt 0 ] || {
  echo "fuzz wiring audit: no fuzz targets were discovered" >&2
  exit 1
}
echo "fuzz wiring audit: all $target_count source package/target pairs are exercised by CI"
