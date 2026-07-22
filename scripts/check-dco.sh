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
  author_email=$(git show -s --format='%ae' "$commit") ||
    fail "could not read author email for $commit"
  [ -n "$author_email" ] || fail "commit $commit has an empty author email"
  committer=$(git show -s --format='%cn <%ce>' "$commit") ||
    fail "could not read committer for $commit"
  trailers=$(git show -s --format='%(trailers:key=Signed-off-by,valueonly,unfold=true)' "$commit") ||
    fail "could not read trailers from commit $commit"
  signed_off=false
  # DCO identity follows the author's email address. GitHub squash merges can
  # replace the commit author's display name with the account profile name
  # while retaining the contributor's email and original Signed-off-by name.
  # Require a non-empty name and an exact author-email suffix so those
  # platform-created commits do not turn the protected branch red.
  while IFS= read -r trailer; do
    case "$trailer" in
      ?*" <$author_email>") signed_off=true ;;
    esac
  done <<EOF
$trailers
EOF
  if [ "$signed_off" = true ]; then
    :
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
    echo "DCO audit: commit $short lacks a Signed-off-by trailer matching its author email" >&2
    missing=$((missing + 1))
  fi
  checked=$((checked + 1))
done

[ "$missing" -eq 0 ] || fail "$missing of $checked non-merge commits failed"
echo "DCO audit: $checked non-merge commits carry matching sign-offs"
