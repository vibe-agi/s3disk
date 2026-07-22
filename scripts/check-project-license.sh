#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$project_dir"

for required_file in LICENSE NOTICE README.md README.zh-CN.md CONTRIBUTING.md \
  THIRD_PARTY_NOTICES.md third_party/licenses/Apache-2.0.txt
do
  if [ ! -s "$required_file" ]; then
    echo "project license audit: missing or empty $required_file" >&2
    exit 1
  fi
done

if ! cmp -s LICENSE third_party/licenses/Apache-2.0.txt; then
  echo "project license audit: LICENSE is not the approved Apache-2.0 text" >&2
  exit 1
fi

if ! rg --fixed-strings --quiet 'Copyright 2026 The s3disk Authors' NOTICE; then
  echo "project license audit: NOTICE is missing the approved project attribution" >&2
  exit 1
fi

if ! rg --fixed-strings --quiet '](LICENSE)' README.md; then
  echo "project license audit: README does not link to LICENSE" >&2
  exit 1
fi

if pending=$(rg --hidden --line-number --ignore-case --no-ignore \
  --glob '!.git/**' --glob '!scripts/check-project-license.sh' \
  'license[[:space:]]+pending|RELEASE-BLOCKER:[[:space:]]*project-license|distribution[[:space:]]+is[[:space:]]+not[[:space:]]+authorized' . 2>&1)
then
  printf '%s\n' "$pending" >&2
  echo "project license audit: pending project-license language remains" >&2
  exit 1
else
  audit_code=$?
  if [ "$audit_code" -ne 1 ]; then
    printf '%s\n' "$pending" >&2
    echo "project license audit: could not complete repository scan" >&2
    exit 1
  fi
fi

echo "project license audit: Apache-2.0 project license and attribution verified"
