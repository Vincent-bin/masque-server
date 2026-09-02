#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

die() {
    echo "operations installer test: $*" >&2
    exit 1
}

TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/masque-ops-installer.XXXXXX")
cleanup() {
    rm -rf -- "$TEST_TMP"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

VERSION=$(awk '
    /^\[package\]$/ { in_package=1; next }
    /^\[/ { in_package=0 }
    in_package && /^version = / { gsub(/[" ]/, "", $3); print $3; exit }
' Cargo.toml)
FIXTURES=$TEST_TMP/fixtures
MOCK_BIN=$TEST_TMP/mock-bin
SKILLS_DIR=$TEST_TMP/home/.agents/skills
BIN_DIR=$TEST_TMP/home/.local/bin
CONFIG_DIR=$TEST_TMP/home/.config/masque-server
install -d "$FIXTURES" "$MOCK_BIN"
export FIXTURES

OUTPUT_DIR=$FIXTURES scripts/package-ops.sh >"$TEST_TMP/package.log"

PROBE_ROOT=masque-probe-v${VERSION}-linux-x86_64
install -d "$TEST_TMP/$PROBE_ROOT/bin"
cat >"$TEST_TMP/$PROBE_ROOT/bin/masque-probe" <<EOF
#!/usr/bin/env sh
echo 'masque-probe $VERSION'
EOF
chmod 0755 "$TEST_TMP/$PROBE_ROOT/bin/masque-probe"
tar -C "$TEST_TMP" -czf "$FIXTURES/$PROBE_ROOT.tar.gz" "$PROBE_ROOT"
(
    cd "$FIXTURES"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$PROBE_ROOT.tar.gz" >"$PROBE_ROOT.tar.gz.sha256"
    else
        shasum -a 256 "$PROBE_ROOT.tar.gz" >"$PROBE_ROOT.tar.gz.sha256"
    fi
)

cat >"$MOCK_BIN/uname" <<'EOF'
#!/usr/bin/env sh
case "${1:-}" in
    -s) printf '%s\n' Linux ;;
    -m) printf '%s\n' x86_64 ;;
    *) exit 2 ;;
esac
EOF

cat >"$MOCK_BIN/curl" <<'EOF'
#!/usr/bin/env sh
set -eu
output=
url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o)
            output=$2
            shift 2
            ;;
        *)
            url=$1
            shift
            ;;
    esac
done
[ -n "$output" ] && [ -n "$url" ]
cp -- "$FIXTURES/${url##*/}" "$output"
EOF
chmod 0755 "$MOCK_BIN/uname" "$MOCK_BIN/curl"

run_installer() {
    HOME=$TEST_TMP/home \
        MASQUE_VERSION=$VERSION \
        MASQUE_OPS_SKILLS_DIR=$SKILLS_DIR \
        MASQUE_OPS_BIN_DIR=$BIN_DIR \
        MASQUE_OPS_CONFIG_DIR=$CONFIG_DIR \
        PATH=$MOCK_BIN:$PATH \
        ./install-ops.sh
}

run_installer >"$TEST_TMP/install.log"
[ -x "$SKILLS_DIR/masque-ops/scripts/masque-ops.py" ] ||
    die "the self-contained CLI was not installed with the Skill"
[ -x "$SKILLS_DIR/masque-ops/scripts/install-latest.sh" ] ||
    die "the server bootstrap installer was not installed with the Skill"
[ -L "$BIN_DIR/masque-ops" ] || die "the CLI launcher is not a symbolic link"
[ -x "$BIN_DIR/masque-probe" ] || die "the release-matched probe was not installed"
[ "$("$BIN_DIR/masque-ops" --version)" = "masque-ops $VERSION" ] ||
    die "the installed CLI reported the wrong version"
[ "$("$BIN_DIR/masque-probe" --version)" = "masque-probe $VERSION" ] ||
    die "the installed probe reported the wrong version"
[ -f "$CONFIG_DIR/fleet.example.toml" ] ||
    die "the private inventory example was not installed"
[ "$(stat -c '%a' "$CONFIG_DIR/fleet.example.toml" 2>/dev/null || \
    stat -f '%Lp' "$CONFIG_DIR/fleet.example.toml")" = 600 ] ||
    die "the inventory example does not have mode 0600"

printf '%s\n' 'private inventory fixture' >"$CONFIG_DIR/fleet.toml"
printf '%s\n' '# operator note' >>"$CONFIG_DIR/fleet.example.toml"
printf '%s\n' obsolete >"$SKILLS_DIR/masque-ops/obsolete"
run_installer >"$TEST_TMP/upgrade.log"
grep -q 'private inventory fixture' "$CONFIG_DIR/fleet.toml" ||
    die "an upgrade changed the private inventory"
grep -q '# operator note' "$CONFIG_DIR/fleet.example.toml" ||
    die "an upgrade replaced the existing inventory example"
[ ! -e "$SKILLS_DIR/masque-ops/obsolete" ] ||
    die "an upgrade did not replace the old Skill atomically"
grep -q 'Kept existing inventory example' "$TEST_TMP/upgrade.log" ||
    die "the upgrade did not report that the example was preserved"

printf '%s\n' tampered >>"$FIXTURES/masque-ops-v${VERSION}.tar.gz"
if run_installer >"$TEST_TMP/tampered.log" 2>&1; then
    die "a tampered operations archive passed SHA-256 verification"
fi
[ "$("$BIN_DIR/masque-ops" --version)" = "masque-ops $VERSION" ] ||
    die "checksum failure replaced the installed CLI"
grep -q 'private inventory fixture' "$CONFIG_DIR/fleet.toml" ||
    die "checksum failure changed the private inventory"

echo "operations installer tests passed"
