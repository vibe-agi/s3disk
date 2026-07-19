#!/bin/sh
set -eu

LC_ALL=C
export LC_ALL
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
cd "$project_dir"

fail() {
  echo "release reference check: $*" >&2
  exit 1
}

required_environment() {
  variable_name=$1
  eval "variable_value=\${$variable_name-}"
  [ -n "$variable_value" ] || fail "$variable_name is required"
}

valid_object_id() {
  printf '%s\n' "$1" | awk '
    NR != 1 { bad = 1 }
    length($0) != 40 && length($0) != 64 { bad = 1 }
    $0 !~ /^[0-9a-f]+$/ { bad = 1 }
    END { exit bad }
  '
}

valid_release_version() {
  printf '%s\n' "$1" | awk '
    function numeric(value) {
      return value == "0" || value ~ /^[1-9][0-9]*$/
    }
    function identifiers(value, prerelease, count, item, item_index) {
      if (value == "") return 0
      count = split(value, item, ".")
      for (item_index = 1; item_index <= count; item_index++) {
        if (item[item_index] == "" || item[item_index] !~ /^[0-9A-Za-z-]+$/) return 0
        if (prerelease && item[item_index] ~ /^[0-9]+$/ && !numeric(item[item_index])) return 0
      }
      return 1
    }
    NR != 1 { bad = 1; next }
    {
      tag = $0
      if (substr(tag, 1, 1) != "v") { bad = 1; next }
      version = substr(tag, 2)
      # Go module tags must be canonical versions. Build metadata is not a
      # publishable module version and can create ignored/normalized aliases.
      if (index(version, "+")) { bad = 1; next }
      dash = index(version, "-")
      if (dash) {
        prerelease = substr(version, dash + 1)
        version = substr(version, 1, dash - 1)
        if (!identifiers(prerelease, 1)) { bad = 1; next }
      }
      count = split(version, core, ".")
      if (count != 3 || !numeric(core[1]) || !numeric(core[2]) || !numeric(core[3])) {
        bad = 1
        next
      }
      # The module path has no /v2 suffix, so only v0 and v1 are publishable.
      if (core[1] != "0" && core[1] != "1") bad = 1
    }
    END { exit bad }
  '
}

path_owner_and_mode() {
  inspected_path=$1
  case "$(uname -s)" in
    Linux)
      path_owner=$(stat -c '%u' -- "$inspected_path") || return 1
      path_mode=$(stat -c '%a' -- "$inspected_path") || return 1
      ;;
    Darwin|FreeBSD)
      path_owner=$(stat -f '%u' "$inspected_path") || return 1
      path_mode=$(stat -f '%Lp' "$inspected_path") || return 1
      ;;
    *)
      return 1
      ;;
  esac
  printf '%s %s\n' "$path_owner" "$path_mode"
}

mode_is_group_or_world_writable() {
  awk -v mode="$1" 'BEGIN {
    group_digit = int((mode + 0) / 10) % 10
    other_digit = (mode + 0) % 10
    group_write = int(group_digit / 2) % 2
    other_write = int(other_digit / 2) % 2
    exit !(group_write || other_write)
  }'
}

validate_protected_file() {
  protected_file=$1
  protected_description=$2
  require_executable=$3
  case "$protected_file" in
    /*) ;;
    *) fail "$protected_description must be an absolute path" ;;
  esac
  [ -f "$protected_file" ] || fail "$protected_description is not a regular file"
  [ ! -L "$protected_file" ] || fail "$protected_description must not be a symbolic link"
  if [ "$require_executable" = yes ] && [ ! -x "$protected_file" ]; then
    fail "$protected_description must be executable"
  fi

  protected_parent=$(CDPATH= cd -- "$(dirname -- "$protected_file")" && pwd -P) || \
    fail "cannot resolve the $protected_description directory"
  protected_file="$protected_parent/$(basename -- "$protected_file")"
  case "$protected_file" in
    "$project_dir"|"$project_dir"/*)
      fail "$protected_description must live outside the source checkout"
      ;;
  esac

  set -- $(path_owner_and_mode "$protected_file") || \
    fail "cannot inspect $protected_description permissions on this platform"
  file_owner=$1
  file_mode=$2
  if [ "$file_owner" != 0 ]; then
    fail "$protected_description must be owned by root"
  fi
  if mode_is_group_or_world_writable "$file_mode"; then
    fail "$protected_description must not be group- or world-writable"
  fi

  inspected_parent=$protected_parent
  while :
  do
    set -- $(path_owner_and_mode "$inspected_parent") || \
      fail "cannot inspect an ancestor of $protected_description"
    parent_owner=$1
    parent_mode=$2
    [ "$parent_owner" = 0 ] || \
      fail "every $protected_description directory ancestor must be owned by root"
    if mode_is_group_or_world_writable "$parent_mode"; then
      fail "no $protected_description directory ancestor may be group- or world-writable"
    fi
    [ "$inspected_parent" != / ] || break
    inspected_parent=$(dirname -- "$inspected_parent")
  done

  printf '%s\n' "$protected_file"
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

collect_release_tags() {
  tags_file=$1
  output_file=$2
  : >"$output_file"
  while IFS= read -r candidate_tag
  do
    [ -n "$candidate_tag" ] || continue
    if valid_release_version "$candidate_tag"; then
      printf '%s\n' "$candidate_tag" >>"$output_file"
    fi
  done <"$tags_file"
}

write_reference_evidence() {
  evidence_mode=$1
  evidence_version=$2
  evidence_commit=$3
  evidence_tree=$4
  evidence_tag_object=$5
  evidence_signing_fingerprint=$6
  evidence_primary_fingerprint=$7
  evidence_signature_created_unix=$8
  evidence_signers_sha256=$9
  shift 9
  evidence_verifier_sha256=$1
  evidence_tmp=$(mktemp "$evidence_dir/.release-reference.XXXXXX")
  cat >"$evidence_tmp" <<EOF
{
  "schema_version": 2,
  "mode": "$evidence_mode",
  "version": "$evidence_version",
  "commit": "$evidence_commit",
  "tree": "$evidence_tree",
  "tag_object": "$evidence_tag_object",
  "signer_scheme": "$(if [ -n "$evidence_primary_fingerprint" ]; then printf openpgp; fi)",
  "signer_signing_fingerprint": "$evidence_signing_fingerprint",
  "signer_primary_fingerprint": "$evidence_primary_fingerprint",
  "signature_created_unix": "$evidence_signature_created_unix",
  "signer_allowlist_sha256": "$evidence_signers_sha256",
  "openpgp_verifier_sha256": "$evidence_verifier_sha256"
}
EOF
  mv -f -- "$evidence_tmp" "$evidence_dir/release-reference.json"
}

required_environment S3DISK_RELEASE_MODE
required_environment S3DISK_RELEASE_VERSION
required_environment S3DISK_RELEASE_COMMIT
required_environment S3DISK_RELEASE_EVIDENCE_DIR

[ "$(id -u)" -ne 0 ] || fail "release reference checks must not run as root"

release_mode=$S3DISK_RELEASE_MODE
release_version=$S3DISK_RELEASE_VERSION
expected_commit=$S3DISK_RELEASE_COMMIT
evidence_dir_input=$S3DISK_RELEASE_EVIDENCE_DIR

case "$release_mode" in
  candidate|release) ;;
  *) fail "S3DISK_RELEASE_MODE must be candidate or release" ;;
esac
valid_release_version "$release_version" || \
  fail "$release_version is not a publishable v0/v1 SemVer version"
valid_object_id "$expected_commit" || \
  fail "S3DISK_RELEASE_COMMIT must be a full lowercase Git object ID"

case "$evidence_dir_input" in
  /*) ;;
  *) fail "S3DISK_RELEASE_EVIDENCE_DIR must be an absolute path" ;;
esac
[ -d "$evidence_dir_input" ] || fail "release evidence directory does not exist"
[ ! -L "$evidence_dir_input" ] || fail "release evidence directory must not be a symbolic link"
evidence_dir=$(CDPATH= cd -- "$evidence_dir_input" && pwd -P) || \
  fail "cannot resolve release evidence directory"
case "$evidence_dir" in
  "$project_dir"|"$project_dir"/*)
    fail "release evidence must be written outside the source checkout"
    ;;
esac

git rev-parse --verify 'HEAD^{commit}' >/dev/null 2>&1 || fail "repository has no HEAD commit"
head_commit=$(git rev-parse --verify 'HEAD^{commit}')
[ "$head_commit" = "$expected_commit" ] || \
  fail "checked-out HEAD $head_commit does not match expected commit $expected_commit"
head_tree=$(git rev-parse --verify 'HEAD^{tree}')

reference_tmp=$(mktemp -d "${TMPDIR:-/tmp}/s3disk-release-ref.XXXXXX")
cleanup() {
  rm -rf -- "$reference_tmp"
}
trap cleanup EXIT HUP INT TERM

git tag --points-at "$head_commit" >"$reference_tmp/head-tags"
collect_release_tags "$reference_tmp/head-tags" "$reference_tmp/release-tags"
release_tag_count=$(awk 'END { print NR + 0 }' "$reference_tmp/release-tags")

case "$release_mode" in
  candidate)
    [ "$release_tag_count" -eq 0 ] || \
      fail "candidate HEAD already has a publishable SemVer tag"
    if git show-ref --verify --quiet "refs/tags/$release_version"; then
      fail "candidate version $release_version already exists as a local tag"
    fi

    [ "$(git rev-parse --verify 'HEAD^{commit}')" = "$head_commit" ] || \
      fail "HEAD changed during candidate reference validation"
    if git show-ref --verify --quiet "refs/tags/$release_version"; then
      fail "candidate version $release_version was tagged during validation"
    fi
    write_reference_evidence candidate "$release_version" "$head_commit" "$head_tree" \
      "" "" "" "" "" ""
    echo "release reference check: unpublished candidate $release_version is bound to $head_commit"
    ;;

  release)
    required_environment S3DISK_RELEASE_SIGNERS_FILE
    required_environment S3DISK_RELEASE_OPENPGP_PROGRAM
    [ "$release_tag_count" -eq 1 ] || \
      fail "release HEAD must have exactly one publishable SemVer tag"
    actual_release_tag=$(sed -n '1p' "$reference_tmp/release-tags")
    [ "$actual_release_tag" = "$release_version" ] || \
      fail "release HEAD tag $actual_release_tag does not match expected version $release_version"
    tag_ref="refs/tags/$release_version"
    [ "$(git cat-file -t "$tag_ref")" = tag ] || \
      fail "$release_version must be an annotated tag"
    tag_object=$(git rev-parse --verify "$tag_ref^{tag}")
    tag_commit=$(git rev-parse --verify "$tag_ref^{commit}")
    [ "$tag_commit" = "$head_commit" ] || \
      fail "$release_version does not point to expected HEAD $head_commit"

    git cat-file tag "$tag_object" >"$reference_tmp/tag-object"
    [ "$(sed -n '1p' "$reference_tmp/tag-object")" = "object $head_commit" ] || \
      fail "$release_version signed tag object does not directly name expected HEAD $head_commit"
    [ "$(sed -n '2p' "$reference_tmp/tag-object")" = "type commit" ] || \
      fail "$release_version signed tag object type is not commit"
    [ "$(sed -n '3p' "$reference_tmp/tag-object")" = "tag $release_version" ] || \
      fail "$release_version ref does not match the signed tag object name"

    signers_file=$(validate_protected_file \
      "$S3DISK_RELEASE_SIGNERS_FILE" "release signer allowlist" no)
    openpgp_program=$(validate_protected_file \
      "$S3DISK_RELEASE_OPENPGP_PROGRAM" "OpenPGP verifier program" yes)
    signers_sha256=$(sha256_file "$signers_file")
    verifier_sha256=$(sha256_file "$openpgp_program")
    if ! awk '
      /^[[:space:]]*$/ || /^[[:space:]]*#/ { next }
      length($0) != 40 && length($0) != 64 {
        print "invalid OpenPGP fingerprint length at allowlist line " NR > "/dev/stderr"
        bad = 1
        next
      }
      $0 !~ /^[0-9A-F]+$/ {
        print "non-canonical OpenPGP fingerprint at allowlist line " NR > "/dev/stderr"
        bad = 1
        next
      }
      { print; count++ }
      END {
        if (count == 0) print "release signer allowlist is empty" > "/dev/stderr"
        exit bad || count == 0
      }
    ' "$signers_file" >"$reference_tmp/authorized-signers"
    then
      fail "release signer allowlist is invalid"
    fi

    verify_status=0
    git -c gpg.format=openpgp \
      -c "gpg.program=$openpgp_program" \
      -c "gpg.openpgp.program=$openpgp_program" \
      verify-tag --raw "$release_version" \
      >"$reference_tmp/verify.stdout" 2>"$reference_tmp/verify.status" || verify_status=$?
    if [ "$verify_status" -ne 0 ]; then
      cat "$reference_tmp/verify.stdout" "$reference_tmp/verify.status" >&2
      fail "$release_version does not have a valid OpenPGP signature"
    fi
    if ! awk '
      $1 == "[GNUPG:]" && $2 ~ /^(BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG)$/ {
        bad = 1
      }
      END { exit bad }
    ' "$reference_tmp/verify.status"
    then
      cat "$reference_tmp/verify.status" >&2
      fail "$release_version has an expired, revoked, invalid, or unverifiable signature"
    fi
    if ! awk '
      $1 == "[GNUPG:]" && $2 == "VALIDSIG" {
        count++
        if (NF != 12) bad = 1
        if ((length($3) != 40 && length($3) != 64) || $3 !~ /^[0-9A-F]+$/) bad = 1
        if ((length($NF) != 40 && length($NF) != 64) || $NF !~ /^[0-9A-F]+$/) bad = 1
        if ($5 !~ /^[0-9]+$/ || $5 == 0) bad = 1
        signing_fingerprint = $3
        signature_created_unix = $5
        primary_fingerprint = $NF
      }
      END {
        if (count == 1 && !bad) {
          print signing_fingerprint, primary_fingerprint, signature_created_unix
        }
        exit count != 1 || bad
      }
    ' "$reference_tmp/verify.status" >"$reference_tmp/verified-fingerprints"
    then
      cat "$reference_tmp/verify.status" >&2
      fail "could not extract one canonical OpenPGP VALIDSIG identity"
    fi
    read -r signing_fingerprint primary_fingerprint signature_created_unix \
      <"$reference_tmp/verified-fingerprints"
    if ! awk -v wanted="$primary_fingerprint" '$0 == wanted { found = 1 } END { exit !found }' \
      "$reference_tmp/authorized-signers"
    then
      fail "OpenPGP primary fingerprint $primary_fingerprint is not authorized to release"
    fi

    [ "$(git rev-parse --verify 'HEAD^{commit}')" = "$head_commit" ] || \
      fail "HEAD changed during release tag verification"
    [ "$(git rev-parse --verify "$tag_ref^{tag}")" = "$tag_object" ] || \
      fail "$release_version tag object changed during signature verification"
    [ "$(git rev-parse --verify "$tag_ref^{commit}")" = "$head_commit" ] || \
      fail "$release_version target changed during signature verification"
    [ "$(sha256_file "$signers_file")" = "$signers_sha256" ] || \
      fail "release signer allowlist changed during signature verification"
    [ "$(sha256_file "$openpgp_program")" = "$verifier_sha256" ] || \
      fail "OpenPGP verifier program changed during signature verification"

    status_tmp=$(mktemp "$evidence_dir/.release-tag-verification.XXXXXX")
    cat "$reference_tmp/verify.status" >"$status_tmp"
    mv -f -- "$status_tmp" "$evidence_dir/release-tag-verification.status"
    write_reference_evidence release "$release_version" "$head_commit" "$head_tree" \
      "$tag_object" "$signing_fingerprint" "$primary_fingerprint" \
      "$signature_created_unix" "$signers_sha256" "$verifier_sha256"
    echo "release reference check: $release_version at $head_commit is signed by authorized OpenPGP primary $primary_fingerprint"
    ;;
esac
