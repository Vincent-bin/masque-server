#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

die() {
    echo "probe installer test: $*" >&2
    exit 1
}

TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/masque-probe-installer.XXXXXX")
cleanup() {
    rm -rf -- "$TEST_TMP"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

FIXTURES=$TEST_TMP/fixtures
MOCK_BIN=$TEST_TMP/mock-bin
install -d "$FIXTURES" "$MOCK_BIN"
export FIXTURES

cat >"$MOCK_BIN/uname" <<'EOF'
#!/usr/bin/env sh
case "${1:-}" in
    -s) printf '%s\n' "${FAKE_UNAME_SYSTEM:?}" ;;
    -m) printf '%s\n' "${FAKE_UNAME_ARCH:?}" ;;
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

make_fixture() {
    platform=$1
    arch=$2
    archive_root=masque-probe-v0.12.2-${platform}-${arch}
    staging=$TEST_TMP/$archive_root
    install -d "$staging/bin"
    cat >"$staging/bin/masque-probe" <<'EOF'
#!/usr/bin/env sh
echo 'masque-probe 0.12.2'
EOF
    chmod 0755 "$staging/bin/masque-probe"
    tar -C "$TEST_TMP" -czf "$FIXTURES/$archive_root.tar.gz" "$archive_root"
    (
        cd "$FIXTURES"
        sha256sum "$archive_root.tar.gz" >"$archive_root.tar.gz.sha256"
    )
}

make_fixture macos aarch64
make_fixture macos x86_64

for pair in 'arm64:aarch64' 'x86_64:x86_64'; do
    machine=${pair%%:*}
    normalized=${pair#*:}
    destination=$TEST_TMP/install-$normalized
    FAKE_UNAME_SYSTEM=Darwin \
        FAKE_UNAME_ARCH=$machine \
        MASQUE_VERSION=0.12.2 \
        MASQUE_PROBE_INSTALL_DIR=$destination \
        PATH=$MOCK_BIN:$PATH \
        ./install-probe.sh >"$TEST_TMP/$normalized.log"
    [ -x "$destination/masque-probe" ] ||
        die "macOS $machine probe was not installed"
    [ "$("$destination/masque-probe" --version)" = 'masque-probe 0.12.2' ] ||
        die "macOS $machine probe version was not preserved"
    grep -q "macos/$normalized" "$TEST_TMP/$normalized.log" ||
        die "macOS $machine was normalized incorrectly"
done

# A changed archive must fail before replacing the verified executable.
printf '%s\n' tampered >>"$FIXTURES/masque-probe-v0.12.2-macos-aarch64.tar.gz"
if FAKE_UNAME_SYSTEM=Darwin \
    FAKE_UNAME_ARCH=arm64 \
    MASQUE_VERSION=0.12.2 \
    MASQUE_PROBE_INSTALL_DIR=$TEST_TMP/install-aarch64 \
    PATH=$MOCK_BIN:$PATH \
    ./install-probe.sh >"$TEST_TMP/tampered.log" 2>&1; then
    die "a tampered probe archive passed SHA-256 verification"
fi
[ "$("$TEST_TMP/install-aarch64/masque-probe" --version)" = \
    'masque-probe 0.12.2' ] || die "checksum failure replaced the installed probe"

echo "probe installer tests passed"
