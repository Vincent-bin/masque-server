#!/usr/bin/env sh
# Destructive only inside a fresh GitHub-hosted Linux runner. This exercises
# the real production paths because path indirection in the installer could
# hide exactly the replacement/rollback mistakes the test is meant to catch.
set -eu

die() {
    echo "installer upgrade test: $*" >&2
    exit 1
}

[ "${CI:-}" = true ] || die "refusing to run outside CI"
[ "${MASQUE_INSTALLER_TEST:-}" = 1 ] || die "MASQUE_INSTALLER_TEST=1 is required"
[ "$(id -u)" -eq 0 ] || die "the test must run as root on a disposable runner"

CANDIDATE=${MASQUE_TEST_PACKAGE_BIN:-}
[ -x "$CANDIDATE" ] || die "MASQUE_TEST_PACKAGE_BIN must name an executable"

BIN_PATH=/usr/local/bin/masque-server
CONFIG_PATH=/etc/masque/masque.toml
UNIT_PATH=/etc/systemd/system/masque.service
for protected_path in "$BIN_PATH" "$CONFIG_PATH" "$UNIT_PATH"; do
    [ ! -e "$protected_path" ] || die "runner is not clean: $protected_path already exists"
done

TEST_TMP=$(mktemp -d /tmp/masque-installer-upgrade.XXXXXX)

cleanup() {
    cleanup_status=$?
    trap - EXIT
    set +e
    rm -f -- \
        "$BIN_PATH" \
        "$CONFIG_PATH" \
        /etc/masque/.masque.toml.lock \
        "$UNIT_PATH" \
        /etc/masque/certs/server.crt \
        /etc/masque/certs/server.key
    rmdir /etc/masque/certs /etc/masque >/dev/null 2>&1
    rm -rf -- "$TEST_TMP"
    exit "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

PACKAGE_DIR=$TEST_TMP/package
MOCK_BIN=$TEST_TMP/mock-bin
MOCK_STATE=$TEST_TMP/restart-count
install -d "$PACKAGE_DIR/bin" "$PACKAGE_DIR/config" "$PACKAGE_DIR/systemd" "$MOCK_BIN"
install -m 0755 "$CANDIDATE" "$PACKAGE_DIR/bin/masque-server"
install -m 0755 deploy/install.sh "$PACKAGE_DIR/install.sh"
install -m 0644 deploy/config/masque.toml "$PACKAGE_DIR/config/masque.toml"
install -m 0644 deploy/systemd/masque.service "$PACKAGE_DIR/systemd/masque.service"

cat >"$MOCK_BIN/systemctl" <<'EOF'
#!/usr/bin/env sh
set -eu
case "${1:-}" in
    is-active)
        [ "${MOCK_ACTIVE:-0}" = 1 ]
        ;;
    is-enabled)
        [ "${MOCK_ENABLED:-0}" = 1 ]
        ;;
    restart)
        count=0
        if [ -s "$MOCK_STATE" ]; then
            count=$(sed -n '1p' "$MOCK_STATE")
        fi
        count=$((count + 1))
        printf '%s\n' "$count" >"$MOCK_STATE"
        if [ "${MOCK_FAIL_FIRST_RESTART:-0}" = 1 ] && [ "$count" -eq 1 ]; then
            exit 1
        fi
        ;;
    daemon-reload|enable|disable|stop)
        ;;
    *)
        echo "unexpected systemctl invocation: $*" >&2
        exit 2
        ;;
esac
EOF
chmod 0755 "$MOCK_BIN/systemctl"
PATH=$MOCK_BIN:$PATH
export PATH MOCK_STATE

install -d /etc/masque/certs /usr/local/bin /etc/systemd/system
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -days 1 -subj /CN=localhost \
    -keyout /etc/masque/certs/server.key \
    -out /etc/masque/certs/server.crt >/dev/null 2>&1

write_config() {
    cc_algorithm=$1
    cat >"$CONFIG_PATH" <<EOF
[tls]
cert_path = "/etc/masque/certs/server.crt"
key_path = "/etc/masque/certs/server.key"

[quic]
cc_algorithm = "$cc_algorithm"

[ip_proxy]
enabled = false

[[listeners]]
listen_addr = "127.0.0.1:8449"
shards = 1

[listeners.auth]
enabled = false
EOF
    chmod 0640 "$CONFIG_PATH"
}

write_old_installation() {
    cat >"$BIN_PATH" <<'EOF'
#!/usr/bin/env sh
echo old-masque-server
EOF
    chmod 0755 "$BIN_PATH"
    printf '%s\n' 'old systemd unit' >"$UNIT_PATH"
    chmod 0644 "$UNIT_PATH"
}

assert_sha_unchanged() {
    path=$1
    expected=$2
    actual=$(sha256sum "$path" | awk '{print $1}')
    [ "$actual" = "$expected" ] || die "$path changed unexpectedly"
}

# A fresh dual installation writes a two-listener configuration and provisions
# both authentication modes. This runs first, while the runner still has no
# configuration; the upgrade cases below overwrite everything it leaves behind.
DUAL_CLIENT_JSON=$TEST_TMP/dual-client.json
MASQUE_AUTH_MODE=dual \
    MASQUE_AUTH_USERNAME=proxy-user \
    MASQUE_AUTH_PASSWORD=a-strong-password \
    MASQUE_LISTEN_PORT=8449 \
    MASQUE_CERT_LISTEN_PORT=8450 \
    MASQUE_CLIENT_NAME=laptop \
    MASQUE_CLIENT_ENDPOINT=203.0.113.9:8450 \
    MASQUE_CLIENT_CONFIG_OUT="$DUAL_CLIENT_JSON" \
    MASQUE_START_SERVICE=0 \
    "$PACKAGE_DIR/install.sh" >"$TEST_TMP/dual.log" 2>&1 ||
    die "fresh dual installation failed; see $TEST_TMP/dual.log"

[ "$(grep -c '^\[\[listeners\]\]$' "$CONFIG_PATH")" -eq 2 ] ||
    die "dual mode did not write two listeners"
grep -q '^listen_addr = "0.0.0.0:8449"$' "$CONFIG_PATH" ||
    die "the Basic listener did not take MASQUE_LISTEN_PORT"
grep -q '^listen_addr = "0.0.0.0:8450"$' "$CONFIG_PATH" ||
    die "the certificate listener did not take MASQUE_CERT_LISTEN_PORT"
# [server] contains only process-wide limits; listeners name every socket.
grep -q '^\[server\]$' "$CONFIG_PATH" ||
    die "the [server] section disappeared from the dual configuration"
! grep -q '^listen_addr = "0.0.0.0:443"$' "$CONFIG_PATH" ||
    die "the template listener port was not replaced"
grep -q '^\[\[clients\]\]$' "$CONFIG_PATH" ||
    die "dual mode did not enroll the first certificate client"
[ -s "$DUAL_CLIENT_JSON" ] || die "dual mode did not write the client JSON"

# The server itself must agree about what those listeners are.
"$CANDIDATE" --config "$CONFIG_PATH" check-config >"$TEST_TMP/dual-check.log" 2>&1 ||
    die "the dual configuration failed check-config"
grep -q '^listener 0.0.0.0:8449 auth=basic shards=1$' "$TEST_TMP/dual-check.log" ||
    die "the Basic listener was not reported by check-config"
grep -q '^listener 0.0.0.0:8450 auth=client_cert shards=1$' "$TEST_TMP/dual-check.log" ||
    die "the certificate listener was not reported by check-config"
# The installed binary must be able to add a third listener to the file the
# installer wrote, in place, without an operator editing TOML.
config_owner_before=$(stat -c '%U:%G %a' "$CONFIG_PATH")
"$BIN_PATH" --config "$CONFIG_PATH" add-listener \
    --listen-addr 0.0.0.0:8451 --mode client_cert --yes \
    >"$TEST_TMP/add-listener.log" 2>&1 ||
    die "add-listener failed; see $TEST_TMP/add-listener.log"
[ "$(grep -c '^\[\[listeners\]\]$' "$CONFIG_PATH")" -eq 3 ] ||
    die "add-listener did not append a third listener"
grep -q '^username = "proxy-user"$' "$CONFIG_PATH" ||
    die "add-listener lost the Basic credentials already in the file"
grep -q '^\[quic\]$' "$CONFIG_PATH" ||
    die "add-listener lost the sections the installer wrote"
# The file holds a password hash and is read by the service account, so an
# in-place edit must not change who owns it or who may read it.
[ "$(stat -c '%U:%G %a' "$CONFIG_PATH")" = "$config_owner_before" ] ||
    die "add-listener changed the configuration file's owner or mode"
"$CANDIDATE" --config "$CONFIG_PATH" check-config >"$TEST_TMP/added-check.log" 2>&1 ||
    die "the configuration failed check-config after add-listener"
grep -q '^listener 0.0.0.0:8451 auth=client_cert shards=1$' "$TEST_TMP/added-check.log" ||
    die "the added listener was not reported by check-config"

added_config_sha=$(sha256sum "$CONFIG_PATH" | awk '{print $1}')

# A reinstall over it is an upgrade, and must report both modes rather than one.
MASQUE_START_SERVICE=0 "$PACKAGE_DIR/install.sh" \
    >"$TEST_TMP/dual-upgrade.log" 2>&1 ||
    die "upgrading over the dual configuration failed"
grep -q 'Authentication: basic + client_cert' "$TEST_TMP/dual-upgrade.log" ||
    die "the upgrade summary did not report both authentication modes"
# An upgrade keeps what the operator added, including a listener this installer
# never writes on its own.
assert_sha_unchanged "$CONFIG_PATH" "$added_config_sha"
grep -q '^listener 0.0.0.0:8451 auth=client_cert shards=1$' "$TEST_TMP/dual-upgrade.log" ||
    die "the upgrade summary did not report the added listener"
grep -q 'add-listener' "$TEST_TMP/dual-upgrade.log" ||
    die "the upgrade summary did not name the command that adds a listener"

rm -f -- "$CONFIG_PATH" "$(dirname "$CONFIG_PATH")/.masque.toml.lock"

# An incompatible existing configuration must fail before replacement.
write_old_installation
write_config not-a-controller
old_binary_sha=$(sha256sum "$BIN_PATH" | awk '{print $1}')
old_unit_sha=$(sha256sum "$UNIT_PATH" | awk '{print $1}')
bad_config_sha=$(sha256sum "$CONFIG_PATH" | awk '{print $1}')
if MASQUE_START_SERVICE=0 "$PACKAGE_DIR/install.sh" >"$TEST_TMP/preflight.log" 2>&1; then
    die "incompatible configuration unexpectedly passed"
fi
assert_sha_unchanged "$BIN_PATH" "$old_binary_sha"
assert_sha_unchanged "$UNIT_PATH" "$old_unit_sha"
assert_sha_unchanged "$CONFIG_PATH" "$bad_config_sha"

# A staged upgrade replaces the program and unit, never the configuration.
write_config cubic
valid_config_sha=$(sha256sum "$CONFIG_PATH" | awk '{print $1}')
MOCK_ACTIVE=0 MOCK_ENABLED=0 MASQUE_START_SERVICE=0 \
    "$PACKAGE_DIR/install.sh" >"$TEST_TMP/staged.log" 2>&1
assert_sha_unchanged "$CONFIG_PATH" "$valid_config_sha"
candidate_sha=$(sha256sum "$CANDIDATE" | awk '{print $1}')
assert_sha_unchanged "$BIN_PATH" "$candidate_sha"

# A failed activation restores both files and the prior service state.
write_old_installation
old_binary_sha=$(sha256sum "$BIN_PATH" | awk '{print $1}')
old_unit_sha=$(sha256sum "$UNIT_PATH" | awk '{print $1}')
: >"$MOCK_STATE"
if MOCK_ACTIVE=1 MOCK_ENABLED=1 MOCK_FAIL_FIRST_RESTART=1 \
    MASQUE_START_SERVICE=1 "$PACKAGE_DIR/install.sh" \
    >"$TEST_TMP/rollback.log" 2>&1; then
    die "failed activation unexpectedly reported success"
fi
assert_sha_unchanged "$BIN_PATH" "$old_binary_sha"
assert_sha_unchanged "$UNIT_PATH" "$old_unit_sha"
assert_sha_unchanged "$CONFIG_PATH" "$valid_config_sha"
grep -q 'Previous binary, systemd unit, and service state restored' \
    "$TEST_TMP/rollback.log" || die "rollback confirmation was not printed"

echo "installer upgrade preflight, preservation, and rollback passed"
