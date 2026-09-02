#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET="${TARGET:-}"
if [ -z "$TARGET" ]; then
    echo "error: TARGET is required" >&2
    exit 1
fi

case "$TARGET" in
    x86_64-unknown-linux-*) PLATFORM=linux; TARGET_ARCH=x86_64 ;;
    aarch64-unknown-linux-*) PLATFORM=linux; TARGET_ARCH=aarch64 ;;
    x86_64-apple-darwin) PLATFORM=macos; TARGET_ARCH=x86_64 ;;
    aarch64-apple-darwin) PLATFORM=macos; TARGET_ARCH=aarch64 ;;
    *)
        echo "error: unsupported masque-probe release target: $TARGET" >&2
        exit 1
        ;;
esac

ARCH="${ARCH:-$TARGET_ARCH}"
if [ "$ARCH" != "$TARGET_ARCH" ]; then
    echo "error: ARCH=$ARCH does not match TARGET=$TARGET" >&2
    exit 1
fi

PACKAGE_VERSION=$(awk '
    /^\[package\]$/ { in_package=1; next }
    /^\[/ { in_package=0 }
    in_package && /^version = / { gsub(/[" ]/, "", $3); print $3; exit }
' Cargo.toml)
PROBE_VERSION=$(awk '
    /^\[package\]$/ { in_package=1; next }
    /^\[/ { in_package=0 }
    in_package && /^version = / { gsub(/[" ]/, "", $3); print $3; exit }
' tools/masque-probe/Cargo.toml)
if [ -z "$PACKAGE_VERSION" ] || [ "$PACKAGE_VERSION" != "$PROBE_VERSION" ]; then
    echo "error: masque-server and masque-probe package versions must match" >&2
    exit 1
fi

VERSION="${VERSION:-$PROBE_VERSION}"
OUTPUT_DIR="${OUTPUT_DIR:-dist}"
ARCHIVE_NAME="masque-probe-v${VERSION}-${PLATFORM}-${ARCH}"
STAGING_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/masque-probe-package.XXXXXX")

cleanup() {
    rm -rf -- "$STAGING_ROOT"
}
trap cleanup EXIT INT TERM

if [ "${SKIP_BUILD:-0}" != 1 ]; then
    cargo build --locked --release --target "$TARGET" -p masque-probe
fi

PROBE_BINARY="target/$TARGET/release/masque-probe"
[ -x "$PROBE_BINARY" ] || {
    echo "error: built probe is missing or not executable: $PROBE_BINARY" >&2
    exit 1
}

install -d "$STAGING_ROOT/$ARCHIVE_NAME/bin"
install -m 0755 "$PROBE_BINARY" "$STAGING_ROOT/$ARCHIVE_NAME/bin/masque-probe"
install -m 0644 README.md "$STAGING_ROOT/$ARCHIVE_NAME/README.md"
install -m 0644 LICENSE "$STAGING_ROOT/$ARCHIVE_NAME/LICENSE"

mkdir -p "$OUTPUT_DIR"
COPYFILE_DISABLE=1 tar -C "$STAGING_ROOT" -czf \
    "$OUTPUT_DIR/$ARCHIVE_NAME.tar.gz" "$ARCHIVE_NAME"
(
    cd "$OUTPUT_DIR"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$ARCHIVE_NAME.tar.gz" >"$ARCHIVE_NAME.tar.gz.sha256"
    else
        shasum -a 256 "$ARCHIVE_NAME.tar.gz" >"$ARCHIVE_NAME.tar.gz.sha256"
    fi
)

echo "Created $OUTPUT_DIR/$ARCHIVE_NAME.tar.gz"
