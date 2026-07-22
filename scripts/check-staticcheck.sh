#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$project_dir"

required_version='staticcheck 2026.1 (v0.7.0)'
required_package='honnef.co/go/tools/cmd/staticcheck'
required_module='honnef.co/go/tools'
required_module_version='v0.7.0'
required_module_sum='h1:w6WUp1VbkqPEgLz4rkBzH/CSU6HkoqNLp6GstyTx3lU='
if ! command -v staticcheck >/dev/null 2>&1; then
	echo "staticcheck audit: staticcheck v0.7.0 is required" >&2
	echo "Install it with: go install honnef.co/go/tools/cmd/staticcheck@v0.7.0" >&2
	exit 1
fi

GOWORK=off
GOFLAGS=-mod=readonly
GOTOOLCHAIN=local
export GOWORK GOFLAGS GOTOOLCHAIN

staticcheck_path=$(command -v staticcheck)
actual_version=$(staticcheck -version)
if [ "$actual_version" != "$required_version" ]; then
	printf 'staticcheck audit: expected %s, found %s\n' "$required_version" "$actual_version" >&2
	exit 1
fi
if ! build_info=$(go version -m "$staticcheck_path"); then
	echo "staticcheck audit: cannot read Go build information" >&2
	exit 1
fi
package_matches=$(printf '%s\n' "$build_info" | awk -v expected="$required_package" '
	$1 == "path" && $2 == expected { count++ }
	END { print count + 0 }
')
module_matches=$(printf '%s\n' "$build_info" | awk \
	-v expected_module="$required_module" \
	-v expected_version="$required_module_version" \
	-v expected_sum="$required_module_sum" '
	$1 == "mod" && $2 == expected_module && $3 == expected_version && $4 == expected_sum { count++ }
	END { print count + 0 }
')
if [ "$package_matches" -ne 1 ] || [ "$module_matches" -ne 1 ]; then
	echo "staticcheck audit: binary build identity does not match the reviewed module" >&2
	printf '%s\n' "$build_info" >&2
	exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
	staticcheck_sha256=$(sha256sum -- "$staticcheck_path" | awk '{ print $1 }')
elif command -v shasum >/dev/null 2>&1; then
	staticcheck_sha256=$(shasum -a 256 -- "$staticcheck_path" | awk '{ print $1 }')
else
	echo "staticcheck audit: sha256sum or shasum is required" >&2
	exit 1
fi

printf '%s\n' "$actual_version"
printf '%s\n' "$build_info"
printf 'staticcheck_sha256=%s\n' "$staticcheck_sha256"
staticcheck ./...
echo "staticcheck audit: all packages passed"
