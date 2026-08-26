#!/usr/bin/env sh
set -eu

REPOSITORY=${MASQUE_GITHUB_REPOSITORY:-Vincent-bin/masque-server}
DOWNLOAD_DIR=

die() {
    echo "error: $*" >&2
    exit 1
}

cleanup() {
    if [ -n "$DOWNLOAD_DIR" ] && [ -d "$DOWNLOAD_DIR" ]; then
        rm -rf -- "$DOWNLOAD_DIR"
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

if [ "$(id -u)" -ne 0 ]; then
    die "run this installer as root (for example: curl ... | sudo sh)"
fi
if [ "$(uname -s)" != Linux ]; then
    die "the prebuilt service package supports Linux only"
fi
case "$(uname -m)" in
    x86_64|amd64) ARCH=x86_64 ;;
    aarch64|arm64) ARCH=aarch64 ;;
    *) die "the prebuilt service package supports Linux x86_64 and ARM64 only" ;;
esac

for required_command in curl tar sha256sum awk grep mktemp; do
    command -v "$required_command" >/dev/null 2>&1 ||
        die "required command not found: $required_command"
done

if ! printf '%s\n' "$REPOSITORY" |
    grep -Eq '^[0-9A-Za-z_.-]+/[0-9A-Za-z_.-]+$'; then
    die "MASQUE_GITHUB_REPOSITORY must be in owner/repository form"
fi

if [ -n "${MASQUE_VERSION:-}" ]; then
    case "$MASQUE_VERSION" in
        v*) RELEASE_TAG=$MASQUE_VERSION ;;
        *) RELEASE_TAG=v$MASQUE_VERSION ;;
    esac
else
    LATEST_URL=https://github.com/$REPOSITORY/releases/latest
    if ! RESOLVED_URL=$(curl -fsSL --retry 3 -o /dev/null \
        -w '%{url_effective}' "$LATEST_URL"); then
        die "no stable GitHub release is available; set MASQUE_VERSION to a published tag"
    fi
    case "$RESOLVED_URL" in
        */tag/v*) RELEASE_TAG=${RESOLVED_URL##*/tag/} ;;
        */releases) die "no stable GitHub release is available; set MASQUE_VERSION to a published tag" ;;
        *) die "could not determine the latest release tag from $RESOLVED_URL" ;;
    esac
fi

case "$RELEASE_TAG" in
    v[0-9A-Za-z]*) ;;
    *) die "invalid release tag: $RELEASE_TAG" ;;
esac
case "$RELEASE_TAG" in
    *[!0-9A-Za-z._-]*) die "invalid release tag: $RELEASE_TAG" ;;
esac

VERSION=${RELEASE_TAG#v}
ARCHIVE_NAME=masque-v${VERSION}-linux-${ARCH}.tar.gz
CHECKSUM_NAME=$ARCHIVE_NAME.sha256
DOWNLOAD_BASE=https://github.com/$REPOSITORY/releases/download/$RELEASE_TAG

DOWNLOAD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/masque-install.XXXXXX")
chmod 0700 "$DOWNLOAD_DIR"
ARCHIVE_PATH=$DOWNLOAD_DIR/$ARCHIVE_NAME
CHECKSUM_PATH=$DOWNLOAD_DIR/$CHECKSUM_NAME

echo "Downloading MASQUE Server $RELEASE_TAG ..."
curl -fL --retry 3 -o "$ARCHIVE_PATH" "$DOWNLOAD_BASE/$ARCHIVE_NAME"
curl -fL --retry 3 -o "$CHECKSUM_PATH" "$DOWNLOAD_BASE/$CHECKSUM_NAME"

EXPECTED_SHA256=$(awk 'NF >= 1 { print $1; exit }' "$CHECKSUM_PATH")
if ! printf '%s\n' "$EXPECTED_SHA256" | grep -Eq '^[0-9A-Fa-f]{64}$'; then
    die "the release checksum file is malformed"
fi
ACTUAL_SHA256=$(sha256sum "$ARCHIVE_PATH" | awk '{ print $1 }')
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
    die "SHA-256 verification failed for $ARCHIVE_NAME"
fi
echo "Verified SHA-256: $ACTUAL_SHA256"

if tar tzf "$ARCHIVE_PATH" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
    die "the release archive contains an unsafe path"
fi
tar xzf "$ARCHIVE_PATH" -C "$DOWNLOAD_DIR"

PACKAGE_DIR=$DOWNLOAD_DIR/masque-v${VERSION}-linux-${ARCH}
if [ ! -x "$PACKAGE_DIR/install.sh" ]; then
    die "the release archive does not contain an executable install.sh"
fi

# The one-command path is expected to activate the new binary. The package
# installer still permits MASQUE_START_SERVICE=0 for staged deployments.
MASQUE_START_SERVICE=${MASQUE_START_SERVICE:-1}
export MASQUE_START_SERVICE

echo "Installing $RELEASE_TAG from its verified release archive ..."
"$PACKAGE_DIR/install.sh"
