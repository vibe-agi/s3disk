#!/bin/sh
set -eu

fail() {
  echo "DCO audit: $*" >&2
  exit 1
}

[ "$#" -eq 1 ] || fail "usage: $0 <git-revision-or-range>"
revision=$1
case "$revision" in
  ""|-*|*[!0-9A-Za-z._^~:/!-]*)
    fail "revision contains unsupported characters"
    ;;
esac

commits=$(git rev-list --no-merges "$revision") ||
  fail "could not resolve revision $revision"

checked=0
missing=0
for commit in $commits; do
  author=$(git show -s --format='%an <%ae>' "$commit") ||
    fail "could not read commit $commit"
  committer=$(git show -s --format='%cn <%ce>' "$commit") ||
    fail "could not read committer for $commit"
  trailers=$(git show -s --format='%(trailers:key=Signed-off-by,valueonly,unfold=true)' "$commit") ||
    fail "could not read trailers from commit $commit"
  signed_off=false
  if printf '%s\n' "$trailers" | grep -Fqx -- "$author"; then
    signed_off=true
  # GitHub-created Dependabot commits use the bot account's noreply address
  # as author and its support address in the DCO trailer. Treat only this exact
  # author/committer/trailer triple as one bot identity; near matches still fail.
  elif [ "$author" = 'dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>' ] &&
    [ "$committer" = 'GitHub <noreply@github.com>' ] &&
    printf '%s\n' "$trailers" | grep -Fqx -- 'dependabot[bot] <support@github.com>'
  then
    signed_off=true
  fi
  if [ "$signed_off" != true ]; then
    short=$(git rev-parse --short=12 "$commit") || short=$commit
    echo "DCO audit: commit $short lacks a Signed-off-by trailer matching its author" >&2
    missing=$((missing + 1))
  fi
  checked=$((checked + 1))
done

[ "$missing" -eq 0 ] || fail "$missing of $checked non-merge commits failed"
echo "DCO audit: $checked non-merge commits carry matching sign-offs"
