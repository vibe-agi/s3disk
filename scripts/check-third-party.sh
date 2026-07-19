#!/bin/sh
set -eu

# Keep this audit read-only and independent of a caller's workspace or
# toolchain auto-upgrade policy. Missing sums or dependencies must fail instead
# of silently modifying the release input.
GOWORK=off
GOFLAGS=-mod=readonly
GOTOOLCHAIN=local
export GOWORK GOFLAGS GOTOOLCHAIN

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$project_dir"

actual_modules=$(mktemp "${TMPDIR:-/tmp}/s3disk-actual-modules.XXXXXX")
unsorted_modules=$(mktemp "${TMPDIR:-/tmp}/s3disk-unsorted-modules.XXXXXX")
target_modules=$(mktemp "${TMPDIR:-/tmp}/s3disk-target-modules.XXXXXX")
compiled_packages=$(mktemp "${TMPDIR:-/tmp}/s3disk-compiled-packages.XXXXXX")
expected_modules=$(mktemp "${TMPDIR:-/tmp}/s3disk-expected-modules.XXXXXX")
normalized_upstream=$(mktemp "${TMPDIR:-/tmp}/s3disk-upstream-license.XXXXXX")
normalized_bundled=$(mktemp "${TMPDIR:-/tmp}/s3disk-bundled-license.XXXXXX")
original_go_mod=$(mktemp "${TMPDIR:-/tmp}/s3disk-go-mod.XXXXXX")
original_go_sum=$(mktemp "${TMPDIR:-/tmp}/s3disk-go-sum.XXXXXX")
cp go.mod "$original_go_mod"
cp go.sum "$original_go_sum"
cleanup() {
  rm -f "$actual_modules" "$unsorted_modules" "$target_modules" "$compiled_packages" \
    "$expected_modules" "$normalized_upstream" "$normalized_bundled" \
    "$original_go_mod" "$original_go_sum"
}
trap cleanup EXIT INT TERM

for required_file in \
  LICENSE \
  NOTICE \
  THIRD_PARTY_NOTICES.md \
  third_party/modules.txt \
  third_party/licenses/Apache-2.0.txt \
  third_party/licenses/Go-BSD-3-Clause.txt \
  third_party/licenses/Go-PATENTS.txt \
  third_party/licenses/fsnotify-BSD-3-Clause.txt \
  third_party/licenses/go-fuse-BSD-3-Clause.txt \
  third_party/licenses/go-singleflight-BSD-3-Clause.txt \
  third_party/licenses/pflag-BSD-3-Clause.txt \
  third_party/licenses/restic-chunker-BSD-2-Clause.txt \
  third_party/licenses/x-sys-BSD-3-Clause.txt
do
  if [ ! -s "$required_file" ]; then
    echo "third-party audit: missing or empty $required_file" >&2
    exit 1
  fi
done

if ! cmp -s LICENSE third_party/licenses/Apache-2.0.txt; then
  echo "third-party audit: root project LICENSE differs from approved Apache-2.0 text" >&2
  exit 1
fi

if ! diff -u "$(go env GOROOT)/LICENSE" third_party/licenses/Go-BSD-3-Clause.txt >/dev/null; then
  echo "third-party audit: bundled Go license differs from the active toolchain" >&2
  echo "Review the toolchain license before updating the attribution bundle." >&2
  exit 1
fi
if ! diff -u "$(go env GOROOT)/PATENTS" third_party/licenses/Go-PATENTS.txt >/dev/null; then
  echo "third-party audit: bundled Go patent grant differs from the active toolchain" >&2
  echo "Review the toolchain terms before updating the attribution bundle." >&2
  exit 1
fi
x_sys_dir=$(go list -m -f '{{.Dir}}' golang.org/x/sys)
if ! diff -u "$x_sys_dir/PATENTS" third_party/licenses/Go-PATENTS.txt >/dev/null; then
  echo "third-party audit: bundled x/sys patent grant differs from upstream" >&2
  echo "Review the module terms before updating the attribution bundle." >&2
  exit 1
fi

if ! go list -deps ./... >"$compiled_packages"; then
  echo "third-party audit: could not enumerate compiled packages" >&2
  exit 1
fi
for embedded_package in \
  github.com/aws/aws-sdk-go-v2/internal/sync/singleflight \
  github.com/aws/smithy-go/internal/sync/singleflight
do
  if ! rg --fixed-strings --line-regexp --quiet "$embedded_package" "$compiled_packages"; then
    echo "third-party audit: expected embedded package is no longer compiled: $embedded_package" >&2
    echo "Review upstream license changes and update the attribution bundle." >&2
    exit 1
  fi
done

if ! awk '
  /^[[:space:]]*#/ || NF == 0 { next }
  NF != 3 { print "invalid manifest row at line " NR > "/dev/stderr"; failed = 1; next }
  $3 != "Apache-2.0" && $3 != "BSD-2-Clause" && $3 != "BSD-3-Clause" {
    print "unapproved license " $3 " at line " NR > "/dev/stderr"
    failed = 1
  }
  END { exit failed }
' third_party/modules.txt; then
  exit 1
fi

for target in \
  linux/amd64 linux/arm64 \
  darwin/amd64 darwin/arm64 \
  freebsd/amd64 \
  windows/amd64 windows/arm64
do
  target_os=${target%/*}
  target_arch=${target#*/}
  for cgo_enabled in 0 1
  do
    if ! GOOS="$target_os" GOARCH="$target_arch" CGO_ENABLED="$cgo_enabled" \
      go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}}{{end}}{{end}}' ./... >"$target_modules"
    then
      echo "third-party audit: dependency enumeration failed for $target with CGO_ENABLED=$cgo_enabled" >&2
      exit 1
    fi
    awk 'NF == 2' "$target_modules" >>"$unsorted_modules"
  done
done
LC_ALL=C sort -u "$unsorted_modules" >"$actual_modules"

awk '
  /^[[:space:]]*#/ || NF == 0 { next }
  { print $1 " " $2 }
' third_party/modules.txt | LC_ALL=C sort -u >"$expected_modules"

if ! cmp -s "$expected_modules" "$actual_modules"; then
  echo "third-party audit: compiled module inventory changed" >&2
  diff -u "$expected_modules" "$actual_modules" >&2 || true
  echo "Review the new code and license, then update third_party/modules.txt," >&2
  echo "THIRD_PARTY_NOTICES.md, NOTICE, and bundled license texts." >&2
  exit 1
fi

while read -r module version spdx
do
  case "$module" in
    ''|'#'*) continue ;;
  esac
  if ! rg --fixed-strings --quiet -- "| \`$module\` | \`$version\` |" THIRD_PARTY_NOTICES.md; then
    echo "third-party audit: notice is missing $module $version" >&2
    exit 1
  fi
  module_dir=$(go list -m -f '{{.Dir}}' "$module@$version")
  if ! rg --files -g 'LICENSE*' -g 'LICENCE*' -g 'COPYING*' "$module_dir" | rg --quiet .; then
    echo "third-party audit: upstream module has no discoverable license: $module $version" >&2
    exit 1
  fi
  case "$spdx" in
    Apache-2.0) bundled_license=third_party/licenses/Apache-2.0.txt ;;
    BSD-2-Clause) bundled_license=third_party/licenses/restic-chunker-BSD-2-Clause.txt ;;
    BSD-3-Clause)
      case "$module" in
        github.com/fsnotify/fsnotify) bundled_license=third_party/licenses/fsnotify-BSD-3-Clause.txt ;;
        github.com/hanwen/go-fuse/v2) bundled_license=third_party/licenses/go-fuse-BSD-3-Clause.txt ;;
        github.com/spf13/pflag) bundled_license=third_party/licenses/pflag-BSD-3-Clause.txt ;;
        golang.org/x/sys) bundled_license=third_party/licenses/x-sys-BSD-3-Clause.txt ;;
        *)
          echo "third-party audit: no bundled BSD-3-Clause text mapped for $module" >&2
          exit 1
          ;;
      esac
      ;;
    *)
      echo "third-party audit: unsupported SPDX identifier $spdx" >&2
      exit 1
      ;;
  esac
  if [ ! -s "$bundled_license" ]; then
    echo "third-party audit: missing $bundled_license" >&2
    exit 1
  fi
  upstream_license=
  for candidate in LICENSE LICENSE.txt LICENCE LICENCE.txt COPYING COPYING.txt
  do
    if [ -f "$module_dir/$candidate" ]; then
      upstream_license="$module_dir/$candidate"
      break
    fi
  done
  if [ -z "$upstream_license" ]; then
    echo "third-party audit: no root upstream license for $module $version" >&2
    exit 1
  fi
  if [ "$spdx" = Apache-2.0 ]; then
    if [ "$module" = github.com/inconshreveable/mousetrap ]; then
      sed 's/Copyright 2022 Alan Shreve (@inconshreveable)/Copyright [yyyy] [name of copyright owner]/' \
        "$upstream_license" | awk 'NF != 0' >"$normalized_upstream"
      if ! rg --fixed-strings --quiet -- \
        'Copyright 2022 Alan Shreve' THIRD_PARTY_NOTICES.md; then
        echo "third-party audit: mousetrap copyright notice is missing" >&2
        exit 1
      fi
    else
      awk 'NF != 0' "$upstream_license" >"$normalized_upstream"
    fi
    upstream_line_count=$(wc -l <"$normalized_upstream" | tr -d ' ')
    awk 'NF != 0' "$bundled_license" | head -n "$upstream_line_count" >"$normalized_bundled"
  else
    awk 'NF != 0' "$upstream_license" >"$normalized_upstream"
    awk 'NF != 0' "$bundled_license" >"$normalized_bundled"
  fi
  if ! diff -w "$normalized_upstream" "$normalized_bundled" >/dev/null; then
    echo "third-party audit: bundled license differs from $module $version" >&2
    echo "Review the upstream terms before updating the attribution bundle." >&2
    exit 1
  fi
  for upstream_notice in "$module_dir"/NOTICE "$module_dir"/NOTICE.txt
  do
    [ -f "$upstream_notice" ] || continue
    while IFS= read -r notice_line
    do
      [ -n "$notice_line" ] || continue
      if ! rg --fixed-strings --quiet -- "$notice_line" NOTICE; then
        echo "third-party audit: NOTICE is missing attribution from $module: $notice_line" >&2
        exit 1
      fi
    done <"$upstream_notice"
  done
done <third_party/modules.txt

if ! cmp -s go.mod "$original_go_mod" || ! cmp -s go.sum "$original_go_sum"; then
  echo "third-party audit: module files changed during a read-only audit" >&2
  exit 1
fi

reviewed_module_count=$(wc -l <"$actual_modules" | tr -d ' ')
echo "third-party audit: $reviewed_module_count compiled modules reviewed; permissive license set unchanged"
