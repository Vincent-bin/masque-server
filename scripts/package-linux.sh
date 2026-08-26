#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET="${TARGET:-x86_64-unknown-linux-musl}"
case "$TARGET" in
    x86_64-unknown-linux-*) TARGET_ARCH=x86_64 ;;
    aarch64-unknown-linux-*) TARGET_ARCH=aarch64 ;;
    *)
        echo "error: unsupported Linux release target: $TARGET" >&2
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
[ -n "$PACKAGE_VERSION" ] && [ "$PACKAGE_VERSION" = "$PROBE_VERSION" ] || {
    echo "error: masque-server and masque-probe package versions must match" >&2
    exit 1
}
VERSION="${VERSION:-$PACKAGE_VERSION}"
OUTPUT_DIR="${OUTPUT_DIR:-dist}"
ARCHIVE_NAME="masque-v${VERSION}-linux-${ARCH}"
STAGING_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/masque-package.XXXXXX")"

cleanup() {
    rm -rf -- "$STAGING_ROOT"
}
trap cleanup EXIT INT TERM

if [ "${USE_ZIGBUILD:-0}" = "1" ]; then
    cargo zigbuild --locked --release --target "$TARGET" \
        -p masque-server -p masque-probe
else
    cargo build --locked --release --target "$TARGET" \
        -p masque-server -p masque-probe
fi

install -d \
    "$STAGING_ROOT/$ARCHIVE_NAME/bin" \
    "$STAGING_ROOT/$ARCHIVE_NAME/config" \
    "$STAGING_ROOT/$ARCHIVE_NAME/monitoring" \
    "$STAGING_ROOT/$ARCHIVE_NAME/systemd"
install -m 0755 "target/$TARGET/release/masque-server" \
    "$STAGING_ROOT/$ARCHIVE_NAME/bin/masque-server"
install -m 0755 "target/$TARGET/release/masque-probe" \
    "$STAGING_ROOT/$ARCHIVE_NAME/bin/masque-probe"
install -m 0755 deploy/install.sh "$STAGING_ROOT/$ARCHIVE_NAME/install.sh"
install -m 0644 deploy/config/masque.toml "$STAGING_ROOT/$ARCHIVE_NAME/config/masque.toml"
install -m 0644 deploy/systemd/masque.service \
    "$STAGING_ROOT/$ARCHIVE_NAME/systemd/masque.service"
install -m 0644 deploy/monitoring/prometheus-rules.yml \
    "$STAGING_ROOT/$ARCHIVE_NAME/monitoring/prometheus-rules.yml"
install -m 0644 deploy/monitoring/grafana-dashboard.json \
    "$STAGING_ROOT/$ARCHIVE_NAME/monitoring/grafana-dashboard.json"
install -m 0644 README.md "$STAGING_ROOT/$ARCHIVE_NAME/README.md"
install -m 0644 CHANGELOG.md "$STAGING_ROOT/$ARCHIVE_NAME/CHANGELOG.md"
install -m 0644 LICENSE "$STAGING_ROOT/$ARCHIVE_NAME/LICENSE"

mkdir -p "$OUTPUT_DIR"
# macOS otherwise records com.apple.* xattrs in PAX headers. They are harmless
# but make a locally built Linux archive noisy to extract with GNU tar.
COPYFILE_DISABLE=1 tar --no-xattrs -C "$STAGING_ROOT" -czf \
    "$OUTPUT_DIR/$ARCHIVE_NAME.tar.gz" "$ARCHIVE_NAME"
(
    cd "$OUTPUT_DIR"
    sha256sum "$ARCHIVE_NAME.tar.gz" >"$ARCHIVE_NAME.tar.gz.sha256"
)

echo "Created $OUTPUT_DIR/$ARCHIVE_NAME.tar.gz"
