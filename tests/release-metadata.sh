#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

die() {
    echo "release metadata test: $*" >&2
    exit 1
}

TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/masque-release-metadata.XXXXXX")
MANIFEST=$TEST_TMP/Cargo.toml
LOCKFILE=$TEST_TMP/Cargo.lock
CHANGELOG=$TEST_TMP/CHANGELOG.md
VALIDATOR=$PWD/scripts/validate-release.sh

cleanup() {
    rm -rf -- "$TEST_TMP"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

write_manifest() {
    version=$1
    cat >"$MANIFEST" <<EOF
[workspace]
members = ["."]

[package]
name = "masque-server"
version = "$version"
EOF
}

write_lockfile() {
    version=$1
    cat >"$LOCKFILE" <<EOF
version = 4

[[package]]
name = "masque-server"
version = "$version"
EOF
}

write_changelog() {
    version=$1
    date=$2
    cat >"$CHANGELOG" <<EOF
# Changelog

## Unreleased

## $version - $date

### Fixed

- Fixture.
EOF
}

validate() {
    MASQUE_RELEASE_MANIFEST=$MANIFEST \
        MASQUE_RELEASE_LOCK=$LOCKFILE \
        MASQUE_RELEASE_CHANGELOG=$CHANGELOG \
        "$VALIDATOR" "$1"
}

expect_failure() {
    label=$1
    shift
    if "$@" >"$TEST_TMP/failure.log" 2>&1; then
        die "$label unexpectedly passed"
    fi
}

write_manifest 0.5.1
write_lockfile 0.5.1
write_changelog 0.5.1 2026-08-21
validate v0.5.1 >/dev/null || die "matching release metadata was rejected"

expect_failure "mismatched tag" validate v0.5.0

write_manifest 0.5.2
expect_failure "mismatched manifest" validate v0.5.1
write_manifest 0.5.1

write_lockfile 0.5.0
expect_failure "mismatched lockfile" validate v0.5.1
write_lockfile 0.5.1

write_changelog 0.5.1 not-a-date
expect_failure "malformed changelog date" validate v0.5.1

cat >"$CHANGELOG" <<'EOF'
# Changelog

## 0.5.1 - 2026-08-21

## Unreleased
EOF
expect_failure "release before Unreleased" validate v0.5.1

cat >"$CHANGELOG" <<'EOF'
# Changelog

## Unreleased

## 0.5.1 - 2026-08-21

## 0.5.1 - 2026-08-22
EOF
expect_failure "duplicate release heading" validate v0.5.1

echo "release metadata validation passed"
