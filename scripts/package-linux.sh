#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET="${TARGET:-x86_64-unknown-linux-musl}"
VERSION="${VERSION:-$(awk '
    /^\[package\]$/ { in_package=1; next }
    /^\[/ { in_package=0 }
    in_package && /^version = / { gsub(/[" ]/, "", $3); print $3; exit }
' Cargo.toml)}"
OUTPUT_DIR="${OUTPUT_DIR:-dist}"
ARCHIVE_NAME="masque-v${VERSION}-linux-x86_64"
STAGING_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/masque-package.XXXXXX")"

cleanup() {
    rm -rf -- "$STAGING_ROOT"
}
trap cleanup EXIT INT TERM

cargo build --locked --release --target "$TARGET" --bin masque

install -d \
    "$STAGING_ROOT/$ARCHIVE_NAME/bin" \
    "$STAGING_ROOT/$ARCHIVE_NAME/config" \
    "$STAGING_ROOT/$ARCHIVE_NAME/systemd"
install -m 0755 "target/$TARGET/release/masque" \
    "$STAGING_ROOT/$ARCHIVE_NAME/bin/masque-server"
install -m 0755 packaging/install.sh "$STAGING_ROOT/$ARCHIVE_NAME/install.sh"
install -m 0644 packaging/masque.toml "$STAGING_ROOT/$ARCHIVE_NAME/config/masque.toml"
install -m 0644 packaging/masque.service \
    "$STAGING_ROOT/$ARCHIVE_NAME/systemd/masque.service"
install -m 0644 README.md "$STAGING_ROOT/$ARCHIVE_NAME/README.md"

mkdir -p "$OUTPUT_DIR"
tar -C "$STAGING_ROOT" -czf "$OUTPUT_DIR/$ARCHIVE_NAME.tar.gz" "$ARCHIVE_NAME"
(
    cd "$OUTPUT_DIR"
    sha256sum "$ARCHIVE_NAME.tar.gz" >"$ARCHIVE_NAME.tar.gz.sha256"
)

echo "Created $OUTPUT_DIR/$ARCHIVE_NAME.tar.gz"
