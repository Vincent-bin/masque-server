#!/usr/bin/env sh
set -eu

REPOSITORY=${MASQUE_GITHUB_REPOSITORY:-Vincent-bin/masque-server}
DOWNLOAD_DIR=
STAGED_SKILL=
BACKUP_DIR=
LINK_TMP=
SKILL_TARGET=

die() {
    echo "error: $*" >&2
    exit 1
}

ensure_directory() {
    directory=$1
    mode=$2
    label=$3
    if [ -L "$directory" ]; then
        die "$label must not be a symbolic link: $directory"
    fi
    if [ -e "$directory" ]; then
        [ -d "$directory" ] || die "$label is not a directory: $directory"
    else
        install -d -m "$mode" "$directory"
    fi
}

cleanup() {
    [ -z "$LINK_TMP" ] || rm -f -- "$LINK_TMP"
    [ -z "$STAGED_SKILL" ] || rm -rf -- "$STAGED_SKILL"
    if [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
        if [ -n "$SKILL_TARGET" ] &&
            [ ! -e "$SKILL_TARGET" ] && [ ! -L "$SKILL_TARGET" ] &&
            [ -e "$BACKUP_DIR/masque-ops" ]; then
            mv -- "$BACKUP_DIR/masque-ops" "$SKILL_TARGET" || true
        fi
        if [ ! -e "$BACKUP_DIR/masque-ops" ]; then
            rm -rf -- "$BACKUP_DIR"
        elif [ -e "$SKILL_TARGET" ] || [ -L "$SKILL_TARGET" ]; then
            rm -rf -- "$BACKUP_DIR"
        else
            echo "warning: previous Skill retained at $BACKUP_DIR/masque-ops" >&2
        fi
    fi
    if [ -n "$DOWNLOAD_DIR" ] && [ -d "$DOWNLOAD_DIR" ]; then
        rm -rf -- "$DOWNLOAD_DIR"
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

for required_command in curl tar awk grep mktemp install cp mv ln rm chmod id ssh; do
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

PYTHON=${MASQUE_OPS_PYTHON:-python3}
command -v "$PYTHON" >/dev/null 2>&1 || die "Python 3.11 or newer is required"
PYTHON_SUPPORTED=$(
    "$PYTHON" -c 'import sys; print("yes" if sys.version_info >= (3, 11) else "no")' \
        2>/dev/null
) || die "could not run $PYTHON"
[ "$PYTHON_SUPPORTED" = yes ] || die "Python 3.11 or newer is required"

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
ARCHIVE_NAME=masque-ops-v${VERSION}.tar.gz
CHECKSUM_NAME=$ARCHIVE_NAME.sha256
DOWNLOAD_BASE=https://github.com/$REPOSITORY/releases/download/$RELEASE_TAG

DOWNLOAD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/masque-ops-install.XXXXXX")
chmod 0700 "$DOWNLOAD_DIR"
ARCHIVE_PATH=$DOWNLOAD_DIR/$ARCHIVE_NAME
CHECKSUM_PATH=$DOWNLOAD_DIR/$CHECKSUM_NAME

echo "Downloading masque-ops $RELEASE_TAG ..."
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

PACKAGE_DIR=$DOWNLOAD_DIR/masque-ops-v${VERSION}
CANDIDATE_SKILL=$PACKAGE_DIR/skills/masque-ops
CANDIDATE_CLI=$CANDIDATE_SKILL/scripts/masque-ops.py
[ -r "$CANDIDATE_SKILL/SKILL.md" ] || die "the archive does not contain the Skill"
[ -x "$CANDIDATE_CLI" ] || die "the archive does not contain the operations CLI"
[ -x "$CANDIDATE_SKILL/scripts/install-latest.sh" ] ||
    die "the archive does not contain the server bootstrap installer"
[ -x "$CANDIDATE_SKILL/scripts/install-probe.sh" ] ||
    die "the archive does not contain the probe installer"
CANDIDATE_VERSION=$(awk 'NF { print $1; exit }' "$CANDIDATE_SKILL/VERSION")
[ "$CANDIDATE_VERSION" = "$VERSION" ] ||
    die "the bundled Skill version does not match $RELEASE_TAG"
[ "$("$PYTHON" "$CANDIDATE_CLI" --version)" = "masque-ops $VERSION" ] ||
    die "the downloaded operations CLI cannot run or has the wrong version"

HOME_DIR=${HOME:?HOME is required}
case "$HOME_DIR" in
    /*) ;;
    *) die "HOME must be an absolute path" ;;
esac
SKILLS_DIR=${MASQUE_OPS_SKILLS_DIR:-$HOME_DIR/.agents/skills}
if [ -n "${MASQUE_OPS_BIN_DIR:-}" ]; then
    BIN_DIR=$MASQUE_OPS_BIN_DIR
elif [ "$(id -u)" -eq 0 ]; then
    BIN_DIR=/usr/local/bin
else
    BIN_DIR=$HOME_DIR/.local/bin
fi
CONFIG_DIR=${MASQUE_OPS_CONFIG_DIR:-$HOME_DIR/.config/masque-server}
for destination in "$SKILLS_DIR" "$BIN_DIR" "$CONFIG_DIR"; do
    case "$destination" in
        /*) ;;
        *) die "installation destinations must be absolute paths" ;;
    esac
done

case "${MASQUE_OPS_INSTALL_PROBE:-1}" in
    0) INSTALL_PROBE=0 ;;
    1) INSTALL_PROBE=1 ;;
    *) die "MASQUE_OPS_INSTALL_PROBE must be 0 or 1" ;;
esac

ensure_directory "$SKILLS_DIR" 0755 "Skill installation directory"
ensure_directory "$BIN_DIR" 0755 "CLI installation directory"
ensure_directory "$CONFIG_DIR" 0700 "operations configuration directory"
chmod 0700 "$CONFIG_DIR"
SKILL_TARGET=$SKILLS_DIR/masque-ops
if [ -e "$BIN_DIR/masque-ops" ] &&
    [ ! -f "$BIN_DIR/masque-ops" ] && [ ! -L "$BIN_DIR/masque-ops" ]; then
    die "$BIN_DIR/masque-ops exists and is not a file or symbolic link"
fi

STAGED_SKILL=$(mktemp -d "$SKILLS_DIR/.masque-ops.install.XXXXXX")
cp -R "$CANDIDATE_SKILL/." "$STAGED_SKILL/"
chmod 0755 "$STAGED_SKILL/scripts/masque-ops.py" \
    "$STAGED_SKILL/scripts/install-latest.sh" \
    "$STAGED_SKILL/scripts/install-probe.sh"

if [ "$INSTALL_PROBE" = 1 ]; then
    echo "Installing the release-matched local probe ..."
    MASQUE_VERSION=$RELEASE_TAG \
        MASQUE_GITHUB_REPOSITORY=$REPOSITORY \
        MASQUE_PROBE_INSTALL_DIR=$BIN_DIR \
        "$CANDIDATE_SKILL/scripts/install-probe.sh"
fi

if [ -e "$SKILL_TARGET" ] || [ -L "$SKILL_TARGET" ]; then
    BACKUP_DIR=$(mktemp -d "$SKILLS_DIR/.masque-ops.backup.XXXXXX")
    mv -- "$SKILL_TARGET" "$BACKUP_DIR/masque-ops"
fi
if ! mv -- "$STAGED_SKILL" "$SKILL_TARGET"; then
    if [ -n "$BACKUP_DIR" ] && [ -e "$BACKUP_DIR/masque-ops" ]; then
        mv -- "$BACKUP_DIR/masque-ops" "$SKILL_TARGET"
    fi
    die "could not activate the downloaded Skill"
fi
STAGED_SKILL=

LINK_TMP=$(mktemp "$BIN_DIR/.masque-ops.link.XXXXXX")
rm -f -- "$LINK_TMP"
ln -s "$SKILL_TARGET/scripts/masque-ops.py" "$LINK_TMP"
mv -f -- "$LINK_TMP" "$BIN_DIR/masque-ops"
LINK_TMP=

EXAMPLE_TARGET=$CONFIG_DIR/fleet.example.toml
if [ ! -e "$EXAMPLE_TARGET" ] && [ ! -L "$EXAMPLE_TARGET" ]; then
    install -m 0600 "$SKILL_TARGET/assets/fleet.example.toml" "$EXAMPLE_TARGET"
    EXAMPLE_RESULT="Installed inventory example at $EXAMPLE_TARGET"
else
    EXAMPLE_RESULT="Kept existing inventory example at $EXAMPLE_TARGET"
fi

[ -z "$BACKUP_DIR" ] || rm -rf -- "$BACKUP_DIR"
BACKUP_DIR=

echo "Verified SHA-256: $ACTUAL_SHA256"
echo "Installed masque-ops $VERSION at $BIN_DIR/masque-ops"
echo "Installed Codex Skill at $SKILL_TARGET"
echo "$EXAMPLE_RESULT"
case ":${PATH:-}:" in
    *":$BIN_DIR:"*) ;;
    *) echo "Add $BIN_DIR to PATH before invoking masque-ops directly." ;;
esac
echo "Restart Codex to discover the installed Skill, then invoke \$masque-ops."
