#!/usr/bin/env sh
set -eu

REPOSITORY=${MASQUE_GITHUB_REPOSITORY:-Vincent-bin/masque-server}
DOWNLOAD_DIR=
INSTALL_TMP=

die() {
    echo "error: $*" >&2
    exit 1
}

cleanup() {
    [ -z "$INSTALL_TMP" ] || rm -f -- "$INSTALL_TMP"
    if [ -n "$DOWNLOAD_DIR" ] && [ -d "$DOWNLOAD_DIR" ]; then
        rm -rf -- "$DOWNLOAD_DIR"
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

case "$(uname -s)" in
    Linux) PLATFORM=linux ;;
    Darwin) PLATFORM=macos ;;
    *) die "masque-probe prebuilt binaries support Linux and macOS only" ;;
esac
case "$(uname -m)" in
    x86_64|amd64) ARCH=x86_64 ;;
    aarch64|arm64) ARCH=aarch64 ;;
    *) die "masque-probe prebuilt binaries support x86_64 and ARM64 only" ;;
esac

for required_command in curl tar awk grep mktemp install; do
    command -v "$required_command" >/dev/null 2>&1 ||
        die "required command not found: $required_command"
done
if command -v sha256sum >/dev/null 2>&1; then
    SHA256_COMMAND=sha256sum
elif command -v shasum >/dev/null 2>&1; then
    SHA256_COMMAND='shasum -a 256'
else
    die "required SHA-256 command not found (sha256sum or shasum)"
fi

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
ARCHIVE_NAME=masque-probe-v${VERSION}-${PLATFORM}-${ARCH}.tar.gz
CHECKSUM_NAME=$ARCHIVE_NAME.sha256
DOWNLOAD_BASE=https://github.com/$REPOSITORY/releases/download/$RELEASE_TAG

DOWNLOAD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/masque-probe-install.XXXXXX")
chmod 0700 "$DOWNLOAD_DIR"
ARCHIVE_PATH=$DOWNLOAD_DIR/$ARCHIVE_NAME
CHECKSUM_PATH=$DOWNLOAD_DIR/$CHECKSUM_NAME

echo "Downloading masque-probe $RELEASE_TAG for $PLATFORM/$ARCH ..."
curl -fL --retry 3 -o "$ARCHIVE_PATH" "$DOWNLOAD_BASE/$ARCHIVE_NAME"
curl -fL --retry 3 -o "$CHECKSUM_PATH" "$DOWNLOAD_BASE/$CHECKSUM_NAME"

EXPECTED_SHA256=$(awk 'NF >= 1 { print $1; exit }' "$CHECKSUM_PATH")
if ! printf '%s\n' "$EXPECTED_SHA256" | grep -Eq '^[0-9A-Fa-f]{64}$'; then
    die "the release checksum file is malformed"
fi
ACTUAL_SHA256=$($SHA256_COMMAND "$ARCHIVE_PATH" | awk '{ print $1 }')
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
    die "SHA-256 verification failed for $ARCHIVE_NAME"
fi

if tar tzf "$ARCHIVE_PATH" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
    die "the release archive contains an unsafe path"
fi
tar xzf "$ARCHIVE_PATH" -C "$DOWNLOAD_DIR"

PACKAGE_DIR=$DOWNLOAD_DIR/masque-probe-v${VERSION}-${PLATFORM}-${ARCH}
CANDIDATE=$PACKAGE_DIR/bin/masque-probe
[ -x "$CANDIDATE" ] || die "the release archive does not contain masque-probe"
CANDIDATE_VERSION=$($CANDIDATE --version 2>/dev/null) ||
    die "the downloaded masque-probe cannot run on this machine"
case "$CANDIDATE_VERSION" in
    *" $VERSION") ;;
    *) die "the downloaded probe version does not match $RELEASE_TAG" ;;
esac

if [ -n "${MASQUE_PROBE_INSTALL_DIR:-}" ]; then
    INSTALL_DIR=$MASQUE_PROBE_INSTALL_DIR
elif [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR=/usr/local/bin
else
    INSTALL_DIR=${HOME:?HOME is required}/.local/bin
fi
case "$INSTALL_DIR" in
    /*) ;;
    *) die "MASQUE_PROBE_INSTALL_DIR must be an absolute path" ;;
esac

install -d -m 0755 "$INSTALL_DIR"
INSTALL_TMP=$(mktemp "$INSTALL_DIR/.masque-probe.install.XXXXXX")
install -m 0755 "$CANDIDATE" "$INSTALL_TMP"
mv -f -- "$INSTALL_TMP" "$INSTALL_DIR/masque-probe"
INSTALL_TMP=

echo "Verified SHA-256: $ACTUAL_SHA256"
echo "Installed $CANDIDATE_VERSION at $INSTALL_DIR/masque-probe"
case ":${PATH:-}:" in
    *":$INSTALL_DIR:"*) ;;
    *) echo "Add $INSTALL_DIR to PATH, or set probe_binary to this absolute path." ;;
esac
