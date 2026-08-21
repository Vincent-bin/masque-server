#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

die() {
    echo "release metadata error: $*" >&2
    exit 1
}

release_tag=${1:-}
case "$release_tag" in
    v[0-9]*) ;;
    *) die "expected a tag beginning with 'v' followed by a digit" ;;
esac

release_version=${release_tag#v}
case "$release_version" in
    ""|*[!0-9A-Za-z.+-]*) die "invalid release version: $release_version" ;;
esac

manifest_path=${MASQUE_RELEASE_MANIFEST:-Cargo.toml}
lock_path=${MASQUE_RELEASE_LOCK:-Cargo.lock}
changelog_path=${MASQUE_RELEASE_CHANGELOG:-CHANGELOG.md}

[ -r "$manifest_path" ] || die "cannot read manifest: $manifest_path"
[ -r "$lock_path" ] || die "cannot read lockfile: $lock_path"
[ -r "$changelog_path" ] || die "cannot read changelog: $changelog_path"

manifest_version=$(awk '
    /^\[package\]$/ { in_package=1; next }
    /^\[/ { in_package=0 }
    in_package && /^version[[:space:]]*=/ {
        value=$0
        sub(/^[^=]*=[[:space:]]*"/, "", value)
        sub(/".*$/, "", value)
        print value
        exit
    }
' "$manifest_path")
[ -n "$manifest_version" ] || die "could not find [package].version in $manifest_path"
[ "$manifest_version" = "$release_version" ] ||
    die "tag $release_tag does not match Cargo version $manifest_version"

lock_version=$(awk '
    /^\[\[package\]\]$/ { target=0; next }
    /^name = "masque-server"$/ { target=1; next }
    target && /^version = / {
        value=$3
        gsub(/"/, "", value)
        print value
        exit
    }
' "$lock_path")
[ -n "$lock_version" ] || die "could not find masque-server in $lock_path"
[ "$lock_version" = "$release_version" ] ||
    die "tag $release_tag does not match lockfile version $lock_version"

heading_prefix="## $release_version - "
line_number=0
unreleased_line=0
release_line=0
release_count=0
release_date=
while IFS= read -r line || [ -n "$line" ]; do
    line_number=$((line_number + 1))
    if [ "$line" = "## Unreleased" ] && [ "$unreleased_line" -eq 0 ]; then
        unreleased_line=$line_number
    fi
    case "$line" in
        "$heading_prefix"*)
            release_count=$((release_count + 1))
            release_line=$line_number
            release_date=${line#"$heading_prefix"}
            ;;
    esac
done <"$changelog_path"

[ "$unreleased_line" -gt 0 ] || die "$changelog_path has no Unreleased heading"
[ "$release_count" -eq 1 ] ||
    die "$changelog_path must contain exactly one dated heading for $release_version"
printf '%s\n' "$release_date" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' ||
    die "the $release_version changelog heading has an invalid date"
[ "$unreleased_line" -lt "$release_line" ] ||
    die "the $release_version changelog heading must follow Unreleased"

echo "Release metadata valid: $release_tag ($release_date)"
