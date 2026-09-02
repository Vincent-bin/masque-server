#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

PACKAGE_VERSION=$(awk '
    /^\[package\]$/ { in_package=1; next }
    /^\[/ { in_package=0 }
    in_package && /^version = / { gsub(/[" ]/, "", $3); print $3; exit }
' Cargo.toml)
OPS_VERSION=$(awk 'NF { print $1; exit }' .agents/skills/masque-ops/VERSION)
if [ -z "$PACKAGE_VERSION" ] || [ "$PACKAGE_VERSION" != "$OPS_VERSION" ]; then
    echo "error: masque-server and masque-ops versions must match" >&2
    exit 1
fi

VERSION="${VERSION:-$OPS_VERSION}"
if [ "$VERSION" != "$OPS_VERSION" ]; then
    echo "error: VERSION=$VERSION does not match masque-ops $OPS_VERSION" >&2
    exit 1
fi

cmp install-latest.sh .agents/skills/masque-ops/scripts/install-latest.sh
cmp install-probe.sh .agents/skills/masque-ops/scripts/install-probe.sh
cmp deploy/config/fleet.example.toml \
    .agents/skills/masque-ops/assets/fleet.example.toml

OUTPUT_DIR="${OUTPUT_DIR:-dist}"
ARCHIVE_NAME="masque-ops-v${VERSION}"
STAGING_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/masque-ops-package.XXXXXX")

cleanup() {
    rm -rf -- "$STAGING_ROOT"
}
trap cleanup EXIT INT TERM

SKILL_SOURCE=.agents/skills/masque-ops
SKILL_DESTINATION=$STAGING_ROOT/$ARCHIVE_NAME/skills/masque-ops
install -d \
    "$SKILL_DESTINATION/agents" \
    "$SKILL_DESTINATION/assets" \
    "$SKILL_DESTINATION/references" \
    "$SKILL_DESTINATION/scripts"
install -m 0644 "$SKILL_SOURCE/SKILL.md" "$SKILL_DESTINATION/SKILL.md"
install -m 0644 "$SKILL_SOURCE/VERSION" "$SKILL_DESTINATION/VERSION"
install -m 0644 "$SKILL_SOURCE/agents/openai.yaml" \
    "$SKILL_DESTINATION/agents/openai.yaml"
install -m 0644 "$SKILL_SOURCE/assets/fleet.example.toml" \
    "$SKILL_DESTINATION/assets/fleet.example.toml"
install -m 0644 "$SKILL_SOURCE/references/inventory.md" \
    "$SKILL_DESTINATION/references/inventory.md"
install -m 0644 "$SKILL_SOURCE/references/runbooks.md" \
    "$SKILL_DESTINATION/references/runbooks.md"
install -m 0755 "$SKILL_SOURCE/scripts/masque-ops.py" \
    "$SKILL_DESTINATION/scripts/masque-ops.py"
install -m 0755 "$SKILL_SOURCE/scripts/install-latest.sh" \
    "$SKILL_DESTINATION/scripts/install-latest.sh"
install -m 0755 "$SKILL_SOURCE/scripts/install-probe.sh" \
    "$SKILL_DESTINATION/scripts/install-probe.sh"
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
