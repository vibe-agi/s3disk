#!/bin/sh
set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
checker_source="$script_dir/check-release-ref.sh"

fail() {
  echo "release reference test: $*" >&2
  exit 1
}

sha256_file() {
  hashed_file=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$hashed_file" | awk '{ print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -- "$hashed_file" | awk '{ print $1 }'
  else
    fail "sha256sum or shasum is required"
  fi
}

# Keep GNUPGHOME short enough for platforms whose agent transport uses a
# length-limited Unix-domain socket. The directory itself is private and
# unpredictable.
release_test_tmp_root=${S3DISK_SHORT_TMPDIR:-/tmp}
case "$release_test_tmp_root" in
  /*) ;;
  *) fail "S3DISK_SHORT_TMPDIR must be an absolute path" ;;
esac
test_tmp=$(mktemp -d "$release_test_tmp_root/s3disk-release-ref-test.XXXXXX")
chmod 700 "$test_tmp"
test_uid=$(id -u)
[ "$test_uid" -ne 0 ] || fail "release reference self-tests must not run as root"

# Protected production inputs must have a non-writable ancestry. Keep the
# fixture outside both /tmp and the source checkout so the test-only checker
# still exercises the complete ancestor walk. A caller may select another
# secure, user-writable parent when the checkout parent is not writable.
source_project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
protected_parent=${S3DISK_RELEASE_TRUST_TEST_PARENT:-$(dirname -- "$source_project_dir")}
case "$protected_parent" in
  /*) ;;
  *) fail "S3DISK_RELEASE_TRUST_TEST_PARENT must be an absolute path" ;;
esac
[ -d "$protected_parent" ] || fail "release trust test parent does not exist"
[ ! -L "$protected_parent" ] || fail "release trust test parent must not be a symbolic link"
protected=$(mktemp -d "$protected_parent/.s3disk-release-ref-protected.XXXXXX") ||
  fail "cannot create protected release test fixture below $protected_parent"
chmod 700 "$protected"

gnupg_home="$test_tmp/gnupg"
mkdir "$gnupg_home"
chmod 700 "$gnupg_home"
cleanup() {
  GNUPGHOME="$gnupg_home" gpgconf --kill all >/dev/null 2>&1 || true
  rm -rf -- "$test_tmp"
  rm -rf -- "$protected"
}
trap cleanup EXIT HUP INT TERM

repo="$test_tmp/repo"
evidence="$test_tmp/evidence"
mkdir "$repo" "$evidence"
chmod 700 "$evidence"
git -C "$repo" init -q
git -C "$repo" config user.name 'S3Disk Release Test'
git -C "$repo" config user.email 'release-test@example.invalid'
mkdir "$repo/scripts"
checker="$repo/scripts/check-release-ref.sh"

# Production accepts only root-owned policy and verifier files. The self-test
# runs unprivileged, so generate an isolated checker copy which additionally
# accepts this process UID while retaining all mode, type, symlink, ancestry,
# and hashing checks. Exact rewrite counts make checker refactors fail closed.
# The production source is hashed before and after to prove it was not altered.
if rg --fixed-strings --quiet 'S3DISK_RELEASE_TESTING' "$checker_source"; then
  fail "production release reference checker contains a testing bypass"
fi
checker_source_sha256=$(sha256_file "$checker_source")
if ! awk -v uid="$test_uid" '
  $0 == "  if [ \"$file_owner\" != 0 ]; then" {
    print "  if [ \"$file_owner\" != 0 ] && [ \"$file_owner\" != " uid " ]; then"
    file_owner_rewrites++
    next
  }
  $0 == "    [ \"$parent_owner\" = 0 ] || \\" {
    print "    [ \"$parent_owner\" = 0 ] || [ \"$parent_owner\" = " uid " ] || \\"
    parent_owner_rewrites++
    next
  }
  { print }
  END {
    if (file_owner_rewrites != 1 || parent_owner_rewrites != 1) {
      print "release reference test: protected-owner rewrite count changed" > "/dev/stderr"
      exit 1
    }
  }
' "$checker_source" >"$checker"
then
  fail "could not create the test-only release reference checker"
fi
chmod 700 "$checker"
[ "$(sha256_file "$checker_source")" = "$checker_source_sha256" ] ||
  fail "production release reference checker changed while creating the test copy"
[ "$(sha256_file "$checker")" != "$checker_source_sha256" ] ||
  fail "test-only release reference checker was not isolated"

printf 'release reference test\n' >"$repo/input"
git -C "$repo" add input scripts/check-release-ref.sh
git -C "$repo" commit -qm initial
commit=$(git -C "$repo" rev-parse HEAD)

run_check() {
  (
    cd "$repo"
    S3DISK_RELEASE_MODE=$1 \
    S3DISK_RELEASE_VERSION=$2 \
    S3DISK_RELEASE_COMMIT=$3 \
    S3DISK_RELEASE_EVIDENCE_DIR=$4 \
    S3DISK_RELEASE_SIGNERS_FILE=${5-} \
    S3DISK_RELEASE_OPENPGP_PROGRAM=${6-} \
      "$checker"
  )
}

run_signed_check() {
  GNUPGHOME="$gnupg_home" run_check "$@"
}

expect_failure() {
  failure_name=$1
  expected_diagnostic=$2
  shift 2
  if "$@" >"$test_tmp/failure.stdout" 2>"$test_tmp/failure.stderr"; then
    fail "$failure_name unexpectedly succeeded"
  fi
  if ! rg --fixed-strings --quiet -- "$expected_diagnostic" "$test_tmp/failure.stderr"; then
    cat "$test_tmp/failure.stdout" "$test_tmp/failure.stderr" >&2
    fail "$failure_name failed for the wrong reason; expected: $expected_diagnostic"
  fi
}

run_check candidate v1.2.3 "$commit" "$evidence"
rg --fixed-strings --quiet '"schema_version": 2' "$evidence/release-reference.json" || \
  fail "candidate evidence does not use the current schema"
rg --fixed-strings --quiet '"mode": "candidate"' "$evidence/release-reference.json" || \
  fail "candidate evidence does not record its mode"
rg --fixed-strings --quiet "\"commit\": \"$commit\"" "$evidence/release-reference.json" || \
  fail "candidate evidence does not bind the exact commit"

expect_failure invalid-semver 'is not a publishable v0/v1 SemVer version' \
  run_check candidate v1.02.3 "$commit" "$evidence"
expect_failure unsupported-major 'is not a publishable v0/v1 SemVer version' \
  run_check candidate v2.0.0 "$commit" "$evidence"
expect_failure build-metadata 'is not a publishable v0/v1 SemVer version' \
  run_check candidate v1.2.3+commercial "$commit" "$evidence"
expect_failure abbreviated-commit 'must be a full lowercase Git object ID' \
  run_check candidate v1.2.3 "$(printf '%s' "$commit" | cut -c1-12)" "$evidence"
expect_failure wrong-commit 'does not match expected commit' \
  run_check candidate v1.2.3 0000000000000000000000000000000000000000 "$evidence"

git -C "$repo" tag -a -m 'existing candidate tag' v1.2.3
expect_failure already-tagged-candidate 'candidate HEAD already has a publishable SemVer tag' \
  run_check candidate v1.2.3 "$commit" "$evidence"
git -C "$repo" tag -d v1.2.3 >/dev/null

if ! GNUPGHOME="$gnupg_home" gpg --batch --pinentry-mode loopback --passphrase '' \
  --quick-generate-key 'S3Disk Release Test <release-test@example.invalid>' ed25519 sign 1d \
  >"$test_tmp/gpg-generate.log" 2>&1
then
  cat "$test_tmp/gpg-generate.log" >&2
  fail "could not generate the test OpenPGP key"
fi
fingerprint=$(GNUPGHOME="$gnupg_home" gpg --batch --with-colons --list-secret-keys 2>/dev/null | \
  awk -F: '$1 == "fpr" { print $10; exit }')
[ -n "$fingerprint" ] || fail "could not create the test OpenPGP key"
git -C "$repo" config user.signingkey "$fingerprint"
git -C "$repo" config gpg.program gpg
GNUPGHOME="$gnupg_home" git -C "$repo" tag -s -m 'signed release' v1.2.3
signed_tag_object=$(git -C "$repo" rev-parse --verify 'refs/tags/v1.2.3^{tag}')

allowlist="$protected/authorized-openpgp-fingerprints"
printf '%s\n' "$fingerprint" >"$allowlist"
chmod 600 "$allowlist"
system_gpg=$(command -v gpg) || fail "gpg is required"
case "$system_gpg" in
  /*) ;;
  *) fail "gpg must resolve to an absolute path" ;;
esac
openpgp_program="$protected/openpgp-verifier"
cp "$system_gpg" "$openpgp_program"
chmod 700 "$openpgp_program"

# A persistent runner or candidate checkout may carry hostile Git config. The
# checker must override both OpenPGP program keys with the protected absolute
# verifier path instead of trusting repository configuration.
configured_fake_verifier="$protected/configured-fake-verifier"
printf '#!/bin/sh\nexit 97\n' >"$configured_fake_verifier"
chmod 700 "$configured_fake_verifier"
git -C "$repo" config gpg.openpgp.program "$configured_fake_verifier"

run_signed_check release v1.2.3 "$commit" "$evidence" "$allowlist" "$openpgp_program" \
  >"$test_tmp/release-success.stdout" 2>"$test_tmp/release-success.stderr"
[ ! -s "$test_tmp/release-success.stderr" ] || {
  cat "$test_tmp/release-success.stderr" >&2
  fail "successful release reference validation wrote unexpected diagnostics"
}
cat "$test_tmp/release-success.stdout"
# Command-scope config injected through the process environment must not outrank
# the checker's final protected-program override.
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=gpg.openpgp.program \
GIT_CONFIG_VALUE_0="$configured_fake_verifier" \
  run_signed_check release v1.2.3 "$commit" "$evidence" "$allowlist" "$openpgp_program" \
  >"$test_tmp/release-config-override.stdout" \
  2>"$test_tmp/release-config-override.stderr"
[ ! -s "$test_tmp/release-config-override.stderr" ] || {
  cat "$test_tmp/release-config-override.stderr" >&2
  fail "environment Git config overrode the protected OpenPGP verifier"
}
unset GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0
git -C "$repo" config --unset gpg.openpgp.program
rg --fixed-strings --quiet '"signer_scheme": "openpgp"' "$evidence/release-reference.json" || \
  fail "release evidence does not record the signer scheme"
rg --fixed-strings --quiet "\"signer_primary_fingerprint\": \"$fingerprint\"" \
  "$evidence/release-reference.json" || fail "release evidence does not record the authorized signer"
rg --fixed-strings --quiet "\"signer_signing_fingerprint\": \"$fingerprint\"" \
  "$evidence/release-reference.json" || fail "release evidence does not record the signing key"
rg --quiet '"signature_created_unix": "[1-9][0-9]*"' \
  "$evidence/release-reference.json" || fail "release evidence does not record signature creation time"
allowlist_sha256=$(sha256_file "$allowlist")
verifier_sha256=$(sha256_file "$openpgp_program")
rg --fixed-strings --quiet "\"signer_allowlist_sha256\": \"$allowlist_sha256\"" \
  "$evidence/release-reference.json" || fail "release evidence does not bind the signer allowlist"
rg --fixed-strings --quiet "\"openpgp_verifier_sha256\": \"$verifier_sha256\"" \
  "$evidence/release-reference.json" || fail "release evidence does not bind the OpenPGP verifier"
rg --fixed-strings --quiet '[GNUPG:] VALIDSIG' "$evidence/release-tag-verification.status" || \
  fail "raw OpenPGP verification status was not archived"

printf '%040d\n' 0 >"$allowlist"
expect_failure unauthorized-signer 'is not authorized to release' run_signed_check \
  release v1.2.3 "$commit" "$evidence" "$allowlist" "$openpgp_program"
printf '%s\n' "$fingerprint" | tr 'A-F' 'a-f' >"$allowlist"
expect_failure noncanonical-allowlist 'release signer allowlist is invalid' run_signed_check \
  release v1.2.3 "$commit" "$evidence" "$allowlist" "$openpgp_program"
printf '%s\n' "$fingerprint" >"$allowlist"
chmod 666 "$allowlist"
expect_failure writable-allowlist 'must not be group- or world-writable' run_signed_check \
  release v1.2.3 "$commit" "$evidence" "$allowlist" "$openpgp_program"
chmod 600 "$allowlist"

linked_allowlist="$protected/linked-allowlist"
ln -s "$allowlist" "$linked_allowlist"
expect_failure symlink-allowlist 'must not be a symbolic link' run_signed_check \
  release v1.2.3 "$commit" "$evidence" "$linked_allowlist" "$openpgp_program"

chmod 600 "$openpgp_program"
expect_failure nonexecutable-verifier 'OpenPGP verifier program must be executable' run_signed_check \
  release v1.2.3 "$commit" "$evidence" "$allowlist" "$openpgp_program"
chmod 722 "$openpgp_program"
expect_failure writable-verifier 'OpenPGP verifier program must not be group- or world-writable' \
  run_signed_check release v1.2.3 "$commit" "$evidence" "$allowlist" "$openpgp_program"
chmod 700 "$openpgp_program"
linked_verifier="$protected/linked-verifier"
ln -s "$openpgp_program" "$linked_verifier"
expect_failure symlink-verifier 'OpenPGP verifier program must not be a symbolic link' \
  run_signed_check release v1.2.3 "$commit" "$evidence" "$allowlist" "$linked_verifier"

GNUPGHOME="$gnupg_home" git -C "$repo" tag -s -m 'mismatched signed tag name' v1.2.4
mismatched_tag_object=$(git -C "$repo" rev-parse --verify 'refs/tags/v1.2.4^{tag}')
git -C "$repo" update-ref refs/tags/v1.2.3 "$mismatched_tag_object"
git -C "$repo" update-ref -d refs/tags/v1.2.4
expect_failure mismatched-signed-tag-name 'ref does not match the signed tag object name' \
  run_signed_check release v1.2.3 "$commit" "$evidence" "$allowlist" "$openpgp_program"
git -C "$repo" update-ref refs/tags/v1.2.3 "$signed_tag_object"

git -C "$repo" tag -a -m 'second release tag' v1.2.4
expect_failure multiple-release-tags 'must have exactly one publishable SemVer tag' run_signed_check \
  release v1.2.3 "$commit" "$evidence" "$allowlist" "$openpgp_program"

git -C "$repo" tag -d v1.2.4 >/dev/null
git -C "$repo" tag -d v1.2.3 >/dev/null
git -C "$repo" tag -a -m 'unsigned release' v1.2.3
expect_failure unsigned-release-tag 'does not have a valid OpenPGP signature' run_signed_check \
  release v1.2.3 "$commit" "$evidence" "$allowlist" "$openpgp_program"

[ "$(sha256_file "$checker_source")" = "$checker_source_sha256" ] ||
  fail "production release reference checker changed during its self-test"

echo "release reference test: candidate binding, protected verifier, signed tag, and evidence checks passed"
