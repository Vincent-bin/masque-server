#!/usr/bin/env sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run this installer as root (for example: sudo ./install.sh)" >&2
    exit 1
fi

PACKAGE_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
CANDIDATE_BIN=$PACKAGE_DIR/bin/masque-server
CANDIDATE_PROBE=$PACKAGE_DIR/bin/masque-probe
BIN_PATH=/usr/local/bin/masque-server
PROBE_PATH=/usr/local/bin/masque-probe
CONFIG_PATH=/etc/masque/masque.toml
TLS_CERT_PATH=/etc/masque/certs/server.crt
TLS_KEY_PATH=/etc/masque/certs/server.key
UNIT_PATH=/etc/systemd/system/masque.service
MONITORING_DIR=/usr/local/share/masque-server/monitoring
PROMETHEUS_RULES_PATH=$MONITORING_DIR/prometheus-rules.yml
GRAFANA_DASHBOARD_PATH=$MONITORING_DIR/grafana-dashboard.json

AUTH_MODE=
AUTH_USERNAME=
AUTH_PASSWORD=
GENERATED_PASSWORD=0
CONFIG_CHANGED=0
FRESH_CONFIG=0
CONFIG_TMP=
CONFIG_REWRITE_TMP=
CHECK_CONFIG_OUTPUT=
ENROLL_OUTPUT=
CLIENT_BLOCK_TMP=
CLIENT_CONFIG_OUT=
BASIC_CLIENT_CONFIG_OUT=
BASIC_CLIENT_CONFIG_CREATED=0
BINARY_INSTALL_TMP=
PROBE_INSTALL_TMP=
UNIT_INSTALL_TMP=
PROMETHEUS_RULES_INSTALL_TMP=
GRAFANA_DASHBOARD_INSTALL_TMP=
UPGRADE_BACKUP_DIR=
ROLLBACK_PENDING=0
HAD_BINARY=0
HAD_PROBE=0
HAD_UNIT=0
HAD_PROMETHEUS_RULES=0
HAD_GRAFANA_DASHBOARD=0
WAS_SERVICE_ACTIVE=0
WAS_SERVICE_ENABLED=0
SERVICE_RESULT="enabled, not started"
RUN_HOST_DIAGNOSTICS=1
HOST_DIAGNOSTICS_RESULT="not run"

cleanup() {
    cleanup_status=$?
    trap - EXIT
    set +e
    if [ "$ROLLBACK_PENDING" -eq 1 ]; then
        echo "Installation failed after replacement; restoring the previous version." >&2
        rollback_installation
    fi
    [ -z "$CONFIG_TMP" ] || rm -f -- "$CONFIG_TMP"
    [ -z "$CONFIG_REWRITE_TMP" ] || rm -f -- "$CONFIG_REWRITE_TMP"
    [ -z "$ENROLL_OUTPUT" ] || rm -f -- "$ENROLL_OUTPUT"
    [ -z "$CLIENT_BLOCK_TMP" ] || rm -f -- "$CLIENT_BLOCK_TMP"
    [ -z "$BINARY_INSTALL_TMP" ] || rm -f -- "$BINARY_INSTALL_TMP"
    [ -z "$PROBE_INSTALL_TMP" ] || rm -f -- "$PROBE_INSTALL_TMP"
    [ -z "$UNIT_INSTALL_TMP" ] || rm -f -- "$UNIT_INSTALL_TMP"
    [ -z "$PROMETHEUS_RULES_INSTALL_TMP" ] || rm -f -- "$PROMETHEUS_RULES_INSTALL_TMP"
    [ -z "$GRAFANA_DASHBOARD_INSTALL_TMP" ] || rm -f -- "$GRAFANA_DASHBOARD_INSTALL_TMP"
    [ -z "$UPGRADE_BACKUP_DIR" ] || rm -rf -- "$UPGRADE_BACKUP_DIR"
    if [ "$cleanup_status" -ne 0 ] && [ "$BASIC_CLIENT_CONFIG_CREATED" -eq 1 ]; then
        rm -f -- "$BASIC_CLIENT_CONFIG_OUT"
    fi
    exit "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

die() {
    echo "error: $*" >&2
    exit 1
}

rollback_installation() {
    rollback_ok=1

    if [ "$HAD_BINARY" -eq 1 ]; then
        if ! cp -p -- "$UPGRADE_BACKUP_DIR/masque-server" "$BIN_PATH"; then
            echo "error: could not restore $BIN_PATH" >&2
            rollback_ok=0
        fi
    elif ! rm -f -- "$BIN_PATH"; then
        echo "error: could not remove the newly installed $BIN_PATH" >&2
        rollback_ok=0
    fi

    if [ "$HAD_PROBE" -eq 1 ]; then
        if ! cp -p -- "$UPGRADE_BACKUP_DIR/masque-probe" "$PROBE_PATH"; then
            echo "error: could not restore $PROBE_PATH" >&2
            rollback_ok=0
        fi
    elif ! rm -f -- "$PROBE_PATH"; then
        echo "error: could not remove the newly installed $PROBE_PATH" >&2
        rollback_ok=0
    fi

    if [ "$HAD_UNIT" -eq 1 ]; then
        if ! cp -p -- "$UPGRADE_BACKUP_DIR/masque.service" "$UNIT_PATH"; then
            echo "error: could not restore $UNIT_PATH" >&2
            rollback_ok=0
        fi
    elif ! rm -f -- "$UNIT_PATH"; then
        echo "error: could not remove the newly installed $UNIT_PATH" >&2
        rollback_ok=0
    fi

    if [ "$HAD_PROMETHEUS_RULES" -eq 1 ]; then
        if ! cp -p -- "$UPGRADE_BACKUP_DIR/prometheus-rules.yml" \
            "$PROMETHEUS_RULES_PATH"; then
            echo "error: could not restore $PROMETHEUS_RULES_PATH" >&2
            rollback_ok=0
        fi
    elif ! rm -f -- "$PROMETHEUS_RULES_PATH"; then
        echo "error: could not remove the newly installed $PROMETHEUS_RULES_PATH" >&2
        rollback_ok=0
    fi

    if [ "$HAD_GRAFANA_DASHBOARD" -eq 1 ]; then
        if ! cp -p -- "$UPGRADE_BACKUP_DIR/grafana-dashboard.json" \
            "$GRAFANA_DASHBOARD_PATH"; then
            echo "error: could not restore $GRAFANA_DASHBOARD_PATH" >&2
            rollback_ok=0
        fi
    elif ! rm -f -- "$GRAFANA_DASHBOARD_PATH"; then
        echo "error: could not remove the newly installed $GRAFANA_DASHBOARD_PATH" >&2
        rollback_ok=0
    fi

    if ! systemctl daemon-reload; then
        echo "error: systemd did not reload the restored unit" >&2
        rollback_ok=0
    fi
    if [ "$WAS_SERVICE_ENABLED" -eq 1 ]; then
        if ! systemctl enable masque.service >/dev/null; then
            echo "error: could not restore the enabled service state" >&2
            rollback_ok=0
        fi
    elif ! systemctl disable masque.service >/dev/null 2>&1; then
        # A never-installed unit has nothing to disable.
        :
    fi

    if [ "$WAS_SERVICE_ACTIVE" -eq 1 ]; then
        if ! systemctl restart masque.service; then
            echo "error: the previous binary was restored but its service did not restart" >&2
            rollback_ok=0
        fi
    elif ! systemctl stop masque.service >/dev/null 2>&1; then
        :
    fi

    ROLLBACK_PENDING=0
    if [ "$rollback_ok" -eq 1 ]; then
        echo "Previous binaries, systemd unit, monitoring assets, and service state restored." >&2
    else
        echo "error: rollback was incomplete; inspect the paths and service above" >&2
    fi
}

parse_start_requested() {
    case "${MASQUE_START_SERVICE:-0}" in
        0|false|no)
            START_REQUESTED=0
            ;;
        1|true|yes)
            START_REQUESTED=1
            ;;
        *)
            die "MASQUE_START_SERVICE must be 0 or 1"
            ;;
    esac
}

parse_host_diagnostics_requested() {
    requested=${MASQUE_RUN_HOST_DIAGNOSTICS:-}
    if [ -z "$requested" ]; then
        if can_prompt; then
            {
                echo
                echo "CONNECT-IP host egress needs Linux forwarding, firewall routing,"
                echo "and sometimes NAT. This installer never changes those settings."
            } >/dev/tty
            requested=$(prompt_value \
                "Run read-only CONNECT-IP host diagnostics after installation? (yes/no)" yes)
        else
            requested=yes
        fi
    fi

    case "$requested" in
        1|true|yes)
            RUN_HOST_DIAGNOSTICS=1
            ;;
        0|false|no)
            RUN_HOST_DIAGNOSTICS=0
            HOST_DIAGNOSTICS_RESULT="not requested"
            ;;
        *)
            die "MASQUE_RUN_HOST_DIAGNOSTICS must be 0 or 1"
            ;;
    esac
}

can_prompt() {
    # Device-node permissions alone are not enough: CI containers often expose
    # /dev/tty without giving the process a controlling terminal. Actually open
    # it so a non-interactive install falls back to defaults instead of failing
    # on the first prompt.
    (: </dev/tty >/dev/tty) 2>/dev/null
}

prompt_value() {
    prompt_text=$1
    prompt_default=$2

    if [ -n "$prompt_default" ]; then
        printf '%s [%s]: ' "$prompt_text" "$prompt_default" >/dev/tty
    else
        printf '%s: ' "$prompt_text" >/dev/tty
    fi
    if ! IFS= read -r prompt_answer </dev/tty; then
        die "failed to read an answer from /dev/tty"
    fi
    if [ -z "$prompt_answer" ]; then
        prompt_answer=$prompt_default
    fi
    printf '%s\n' "$prompt_answer"
}

normalize_auth_mode() {
    case "$1" in
        1|basic)
            printf '%s\n' basic
            ;;
        2|cert|certs|client-cert|client_cert)
            printf '%s\n' client_cert
            ;;
        3|dual|both)
            printf '%s\n' dual
            ;;
        *)
            die "authentication mode must be 'basic', 'client_cert', or 'dual'"
            ;;
    esac
}

# Whether this mode enrolls a certificate client and therefore needs the server
# TLS material at install time.
mode_uses_client_certs() {
    [ "$AUTH_MODE" = client_cert ] || [ "$AUTH_MODE" = dual ]
}

# Whether this mode issues Basic credentials.
mode_uses_basic() {
    [ "$AUTH_MODE" = basic ] || [ "$AUTH_MODE" = dual ]
}

choose_auth_mode() {
    requested_mode=${MASQUE_AUTH_MODE:-}
    if [ -z "$requested_mode" ]; then
        if can_prompt; then
            {
                echo
                echo "Choose an authentication mode:"
                echo "  1) Basic          username and password on every CONNECT request"
                echo "  2) Client cert    TLS client certificate for usque/mihomo-style clients"
                echo "  3) Dual           both, on two ports of one server"
            } >/dev/tty
            requested_mode=$(prompt_value "Authentication mode" 1)
        else
            requested_mode=basic
        fi
    fi
    AUTH_MODE=$(normalize_auth_mode "$requested_mode")
}

# Report what the deployed configuration actually authenticates with.
#
# Taken from `check-config`, which validates and resolves the listeners the same
# way the server does, rather than reimplement that logic in shell.
# Every distinct mode is reported, `disabled` included. Summarising a
# basic + disabled server as "basic" would tell an administrator that every port
# demands credentials when one of them accepts anyone, which is the reading that
# leaves an open proxy in place.
detect_existing_auth_mode() {
    detected_modes=$(printf '%s\n' "$CHECK_CONFIG_OUTPUT" |
        sed -n 's/^listener .* auth=\([a-z_]*\) .*$/\1/p' | sort -u)

    AUTH_MODE=
    for detected_mode in $detected_modes; do
        if [ -z "$AUTH_MODE" ]; then
            AUTH_MODE=$detected_mode
        else
            AUTH_MODE="$AUTH_MODE + $detected_mode"
        fi
    done
    [ -n "$AUTH_MODE" ] || AUTH_MODE=unknown
}

generate_auth_credentials() {
    AUTH_USERNAME=${MASQUE_AUTH_USERNAME:-}
    if [ -z "$AUTH_USERNAME" ]; then
        if can_prompt; then
            AUTH_USERNAME=$(prompt_value "Basic authentication username" masque)
        else
            AUTH_USERNAME=masque
        fi
    fi
    case "$AUTH_USERNAME" in
        ""|*[!A-Za-z0-9._-]*)
            die "the Basic username may only contain letters, digits, '.', '_' and '-'"
            ;;
    esac

    if [ "${MASQUE_AUTH_PASSWORD+x}" = x ]; then
        AUTH_PASSWORD=$MASQUE_AUTH_PASSWORD
        [ -n "$AUTH_PASSWORD" ] || die "MASQUE_AUTH_PASSWORD must not be empty"
    else
        AUTH_PASSWORD=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
        GENERATED_PASSWORD=1
    fi
    AUTH_PASSWORD_HASH=$(printf '%s' "$AUTH_PASSWORD" | "$CANDIDATE_BIN" hash-password)
}

generate_basic_client_config() {
    basic_client_endpoint=${MASQUE_BASIC_CLIENT_ENDPOINT:-}
    if [ -z "$basic_client_endpoint" ] && can_prompt; then
        {
            echo
            echo "A Surge configuration can be generated while the plaintext Basic"
            echo "password is available. The server cannot recover it from its hash later."
        } >/dev/tty
        basic_client_endpoint=$(prompt_value \
            "Public Basic endpoint (host:port; leave empty to skip)" "")
    fi
    [ -n "$basic_client_endpoint" ] || return

    BASIC_CLIENT_CONFIG_OUT=${MASQUE_BASIC_CLIENT_CONFIG_OUT:-}
    if [ -z "$BASIC_CLIENT_CONFIG_OUT" ]; then
        if can_prompt; then
            BASIC_CLIENT_CONFIG_OUT=$(prompt_value \
                "Secret Surge configuration output path" /root/masque-surge.conf)
        else
            BASIC_CLIENT_CONFIG_OUT=/root/masque-surge.conf
        fi
    fi
    case "$BASIC_CLIENT_CONFIG_OUT" in
        /*) ;;
        *) die "the Basic client configuration output path must be absolute" ;;
    esac
    [ ! -e "$BASIC_CLIENT_CONFIG_OUT" ] || die \
        "refusing to overwrite existing client configuration: $BASIC_CLIENT_CONFIG_OUT"

    set -- "$CANDIDATE_BIN" client-config surge \
        --endpoint "$basic_client_endpoint" --username "$AUTH_USERNAME" \
        --out "$BASIC_CLIENT_CONFIG_OUT"
    if [ -n "${MASQUE_BASIC_CLIENT_NAME:-}" ]; then
        set -- "$@" --name "$MASQUE_BASIC_CLIENT_NAME"
    fi
    if ! printf '%s' "$AUTH_PASSWORD" | "$@"; then
        # client-config normally creates atomically and then exits. If a later
        # output/sync error happens after creation, do not leave a secret for a
        # credential the fresh installation will not commit.
        rm -f -- "$BASIC_CLIENT_CONFIG_OUT"
        die "failed to generate the Basic client configuration"
    fi
    BASIC_CLIENT_CONFIG_CREATED=1
}

install_tls_material() {
    prompt_for_tls=$1
    cert_source=${MASQUE_TLS_CERT:-}
    key_source=${MASQUE_TLS_KEY:-}

    if { [ -n "$cert_source" ] && [ -z "$key_source" ]; } ||
        { [ -z "$cert_source" ] && [ -n "$key_source" ]; }; then
        die "MASQUE_TLS_CERT and MASQUE_TLS_KEY must be supplied together"
    fi

    if [ "$prompt_for_tls" -eq 1 ] && [ -z "$cert_source" ] &&
        { [ ! -r "$TLS_CERT_PATH" ] || [ ! -r "$TLS_KEY_PATH" ]; } &&
        can_prompt; then
        if mode_uses_client_certs; then
            echo "Client-certificate enrollment needs the server certificate now." \
                >/dev/tty
            cert_source=$(prompt_value "PEM full-chain certificate path" "")
        else
            cert_source=$(prompt_value \
                "PEM full-chain certificate path (leave empty to install later)" "")
        fi
        if [ -n "$cert_source" ]; then
            key_source=$(prompt_value "Unencrypted PEM private-key path" "")
        fi
    fi

    if [ -n "$cert_source" ]; then
        [ -f "$cert_source" ] || die "TLS certificate not found: $cert_source"
        [ -f "$key_source" ] || die "TLS private key not found: $key_source"
        if [ "$cert_source" != "$TLS_CERT_PATH" ]; then
            install -o root -g masque -m 0640 "$cert_source" "$TLS_CERT_PATH"
        fi
        if [ "$key_source" != "$TLS_KEY_PATH" ]; then
            install -o root -g masque -m 0640 "$key_source" "$TLS_KEY_PATH"
        fi
    fi

    if [ "$prompt_for_tls" -eq 1 ] && mode_uses_client_certs &&
        { [ ! -r "$TLS_CERT_PATH" ] || [ ! -r "$TLS_KEY_PATH" ]; }; then
        die "$AUTH_MODE requires $TLS_CERT_PATH and $TLS_KEY_PATH; set MASQUE_TLS_CERT and MASQUE_TLS_KEY"
    fi
}

create_config_tmp() {
    CONFIG_TMP=$(mktemp /etc/masque/.masque.toml.XXXXXX)
    chmod 0600 "$CONFIG_TMP"
}

render_new_config() {
    create_config_tmp
    case "$AUTH_MODE" in
        basic|dual)
            generate_auth_credentials
            sed \
                -e "s|__MASQUE_AUTH_USERNAME__|$AUTH_USERNAME|" \
                -e "s|__MASQUE_AUTH_PASSWORD_HASH__|$AUTH_PASSWORD_HASH|" \
                "$PACKAGE_DIR/config/masque.toml" >"$CONFIG_TMP"
            ;;
        client_cert)
            sed \
                -e 's|^mode = "basic"$|mode = "client_cert"|' \
                -e '/^\[\[listeners\.auth\.users\]\]$/d' \
                -e '/^username = "__MASQUE_AUTH_USERNAME__"$/d' \
                -e '/^password_hash = "__MASQUE_AUTH_PASSWORD_HASH__"$/d' \
                "$PACKAGE_DIR/config/masque.toml" >"$CONFIG_TMP"
            ;;
    esac
    if grep -q '__MASQUE_AUTH_' "$CONFIG_TMP"; then
        die "failed to render authentication configuration"
    fi
}

# Append the certificate listener to the Basic listener already rendered from
# the package template.
append_certificate_listener() {
    cert_port=$1

    cat >>"$CONFIG_TMP" <<EOF

# TLS client certificates on this socket, Basic credentials on the first. The
# authentication mode fixes what the TLS handshake demands, so the two cannot
# share a socket; everything behind them — the client roster, the TUN device,
# the CONNECT-IP address pool — is shared by the one process.
[[listeners]]
listen_addr = "0.0.0.0:$cert_port"
transport = "http3"
shards = 1

[listeners.auth]
enabled = true
mode = "client_cert"
EOF
}

# Read and validate the numeric port for a fresh HTTP/3 listener.
choose_listen_port() {
    port_prompt=$1
    port_default=$2
    port_value=$3

    if [ -z "$port_value" ]; then
        if can_prompt; then
            port_value=$(prompt_value "$port_prompt" "$port_default")
        else
            port_value=$port_default
        fi
    fi
    case "$port_value" in
        ""|*[!0-9]*) die "$port_prompt must be an integer from 1 to 65535" ;;
    esac
    if [ "$port_value" -lt 1 ] || [ "$port_value" -gt 65535 ]; then
        die "$port_prompt must be an integer from 1 to 65535"
    fi
    printf '%s\n' "$port_value"
}

configure_fresh_listen_port() {
    listen_port=$(choose_listen_port "Public UDP listen port" 443 \
        "${MASQUE_LISTEN_PORT:-}")

    CONFIG_REWRITE_TMP=$(mktemp /etc/masque/.masque-listen.XXXXXX)
    chmod 0600 "$CONFIG_REWRITE_TMP"
    sed "s|^listen_addr = \"0.0.0.0:443\"$|listen_addr = \"0.0.0.0:$listen_port\"|" \
        "$CONFIG_TMP" >"$CONFIG_REWRITE_TMP"
    if ! grep -q "^listen_addr = \"0.0.0.0:$listen_port\"$" \
        "$CONFIG_REWRITE_TMP"; then
        die "failed to set the server listen port"
    fi
    mv -- "$CONFIG_REWRITE_TMP" "$CONFIG_TMP"
    CONFIG_REWRITE_TMP=

    if [ "$AUTH_MODE" = dual ]; then
        cert_listen_port=$(choose_listen_port \
            "Public UDP listen port for certificate clients" 4443 \
            "${MASQUE_CERT_LISTEN_PORT:-}")
        if [ "$cert_listen_port" = "$listen_port" ]; then
            die "the two listeners need different ports; both asked for $listen_port"
        fi
        append_certificate_listener "$cert_listen_port"
    fi
}

normalize_optional_address() {
    case "$1" in
        none|NONE|-)
            printf '\n'
            ;;
        *)
            printf '%s\n' "$1"
            ;;
    esac
}

enroll_first_client() {
    client_name=${MASQUE_CLIENT_NAME:-}
    if [ -z "$client_name" ]; then
        if can_prompt; then
            client_name=$(prompt_value "Client name" client)
        else
            client_name=client
        fi
    fi
    [ -n "$client_name" ] || die "the client name must not be empty"

    client_endpoint=${MASQUE_CLIENT_ENDPOINT:-}
    if [ -z "$client_endpoint" ] && can_prompt; then
        client_endpoint=$(prompt_value "Public server endpoint (IP:port)" "")
    fi
    [ -n "$client_endpoint" ] || die \
        "client_cert requires MASQUE_CLIENT_ENDPOINT in IP:port form"

    if [ "${MASQUE_CLIENT_IPV4+x}" = x ]; then
        client_ipv4=$MASQUE_CLIENT_IPV4
    elif can_prompt; then
        client_ipv4=$(prompt_value "Pinned client IPv4 ('none' to omit)" 10.89.0.2)
    else
        client_ipv4=10.89.0.2
    fi
    client_ipv4=$(normalize_optional_address "$client_ipv4")

    if [ "${MASQUE_CLIENT_IPV6+x}" = x ]; then
        client_ipv6=$MASQUE_CLIENT_IPV6
    elif can_prompt; then
        client_ipv6=$(prompt_value "Pinned client IPv6 ('none' to omit)" fd00:abcd::2)
    else
        client_ipv6=fd00:abcd::2
    fi
    client_ipv6=$(normalize_optional_address "$client_ipv6")

    if [ -z "$client_ipv4" ] && [ -z "$client_ipv6" ]; then
        die "client_cert setup requires at least one pinned client address"
    fi

    CLIENT_CONFIG_OUT=${MASQUE_CLIENT_CONFIG_OUT:-}
    if [ -z "$CLIENT_CONFIG_OUT" ]; then
        if can_prompt; then
            CLIENT_CONFIG_OUT=$(prompt_value "Secret client JSON output path" \
                /root/masque-client.json)
        else
            CLIENT_CONFIG_OUT=/root/masque-client.json
        fi
    fi
    case "$CLIENT_CONFIG_OUT" in
        /*) ;;
        *) die "the client JSON output path must be absolute" ;;
    esac
    [ ! -e "$CLIENT_CONFIG_OUT" ] || die \
        "refusing to overwrite existing client configuration: $CLIENT_CONFIG_OUT"

    ENROLL_OUTPUT=$(mktemp /etc/masque/.enrollment.XXXXXX)
    CLIENT_BLOCK_TMP=$(mktemp /etc/masque/.client-block.XXXXXX)
    chmod 0600 "$ENROLL_OUTPUT" "$CLIENT_BLOCK_TMP"

    set -- "$CANDIDATE_BIN" --config "$CONFIG_TMP" enroll-client \
        --name "$client_name" --endpoint "$client_endpoint" \
        --out "$CLIENT_CONFIG_OUT"
    if [ -n "$client_ipv4" ]; then
        set -- "$@" --ipv4 "$client_ipv4"
    fi
    if [ -n "$client_ipv6" ]; then
        set -- "$@" --ipv6 "$client_ipv6"
    fi
    "$@" >"$ENROLL_OUTPUT"

    awk '
        /^\[\[clients\]\]$/ { capture = 1 }
        capture && /^$/ { exit }
        capture { print }
    ' "$ENROLL_OUTPUT" >"$CLIENT_BLOCK_TMP"
    if ! grep -q '^public_key = ' "$CLIENT_BLOCK_TMP"; then
        die "failed to extract the generated client roster entry"
    fi
    printf '\n' >>"$CONFIG_TMP"
    cat "$CLIENT_BLOCK_TMP" >>"$CONFIG_TMP"
}

print_redacted_config() {
    echo
    echo "Effective server configuration (password hash redacted):"
    echo "--- $CONFIG_PATH ---"
    sed 's/^\([[:space:]]*password_hash[[:space:]]*=\).*/\1 "<redacted>"/' \
        "$CONFIG_PATH"
    echo "--- end configuration ---"
}

# Preflight a configuration with the candidate binary.
#
# The output is kept in CHECK_CONFIG_OUTPUT as well as shown: it carries the
# resolved listener list, which is where the deployed authentication modes are
# read from rather than re-derived from the TOML.
check_config_compatibility() {
    config_to_check=$1
    candidate_version=$("$CANDIDATE_BIN" --version)
    echo "Checking configuration compatibility with $candidate_version ..."
    if ! CHECK_CONFIG_OUTPUT=$("$CANDIDATE_BIN" --config "$config_to_check" check-config); then
        die "configuration compatibility check failed; no binary or systemd unit was replaced"
    fi
    printf '%s\n' "$CHECK_CONFIG_OUTPUT"
}

snapshot_installed_files() {
    UPGRADE_BACKUP_DIR=$(mktemp -d /var/tmp/masque-upgrade.XXXXXX)
    chmod 0700 "$UPGRADE_BACKUP_DIR"

    if [ -e "$BIN_PATH" ]; then
        cp -p -- "$BIN_PATH" "$UPGRADE_BACKUP_DIR/masque-server"
        HAD_BINARY=1
    fi
    if [ -e "$PROBE_PATH" ]; then
        cp -p -- "$PROBE_PATH" "$UPGRADE_BACKUP_DIR/masque-probe"
        HAD_PROBE=1
    fi
    if [ -e "$UNIT_PATH" ]; then
        cp -p -- "$UNIT_PATH" "$UPGRADE_BACKUP_DIR/masque.service"
        HAD_UNIT=1
    fi
    if [ -e "$PROMETHEUS_RULES_PATH" ]; then
        cp -p -- "$PROMETHEUS_RULES_PATH" "$UPGRADE_BACKUP_DIR/prometheus-rules.yml"
        HAD_PROMETHEUS_RULES=1
    fi
    if [ -e "$GRAFANA_DASHBOARD_PATH" ]; then
        cp -p -- "$GRAFANA_DASHBOARD_PATH" "$UPGRADE_BACKUP_DIR/grafana-dashboard.json"
        HAD_GRAFANA_DASHBOARD=1
    fi
    if systemctl is-active --quiet masque.service; then
        WAS_SERVICE_ACTIVE=1
    fi
    if systemctl is-enabled --quiet masque.service; then
        WAS_SERVICE_ENABLED=1
    fi
}

install_program_and_unit() {
    BINARY_INSTALL_TMP=$(mktemp /usr/local/bin/.masque-server.install.XXXXXX)
    PROBE_INSTALL_TMP=$(mktemp /usr/local/bin/.masque-probe.install.XXXXXX)
    UNIT_INSTALL_TMP=$(mktemp /etc/systemd/system/.masque.service.install.XXXXXX)
    PROMETHEUS_RULES_INSTALL_TMP=$(mktemp "$MONITORING_DIR/.prometheus-rules.install.XXXXXX")
    GRAFANA_DASHBOARD_INSTALL_TMP=$(mktemp "$MONITORING_DIR/.grafana-dashboard.install.XXXXXX")
    install -m 0755 "$CANDIDATE_BIN" "$BINARY_INSTALL_TMP"
    install -m 0755 "$CANDIDATE_PROBE" "$PROBE_INSTALL_TMP"
    install -m 0644 "$PACKAGE_DIR/systemd/masque.service" "$UNIT_INSTALL_TMP"
    install -m 0644 "$PACKAGE_DIR/monitoring/prometheus-rules.yml" \
        "$PROMETHEUS_RULES_INSTALL_TMP"
    install -m 0644 "$PACKAGE_DIR/monitoring/grafana-dashboard.json" \
        "$GRAFANA_DASHBOARD_INSTALL_TMP"

    snapshot_installed_files
    ROLLBACK_PENDING=1

    mv -f -- "$BINARY_INSTALL_TMP" "$BIN_PATH"
    BINARY_INSTALL_TMP=
    mv -f -- "$PROBE_INSTALL_TMP" "$PROBE_PATH"
    PROBE_INSTALL_TMP=
    mv -f -- "$UNIT_INSTALL_TMP" "$UNIT_PATH"
    UNIT_INSTALL_TMP=
    mv -f -- "$PROMETHEUS_RULES_INSTALL_TMP" "$PROMETHEUS_RULES_PATH"
    PROMETHEUS_RULES_INSTALL_TMP=
    mv -f -- "$GRAFANA_DASHBOARD_INSTALL_TMP" "$GRAFANA_DASHBOARD_PATH"
    GRAFANA_DASHBOARD_INSTALL_TMP=

    systemctl daemon-reload
    systemctl enable masque.service

    if [ "$START_REQUESTED" -eq 1 ]; then
        if [ "$FRESH_CONFIG" -eq 0 ] ||
            { [ -r "$TLS_CERT_PATH" ] && [ -r "$TLS_KEY_PATH" ]; }; then
            systemctl restart masque.service
            SERVICE_RESULT="started or restarted"
        else
            SERVICE_RESULT="enabled, not started (TLS certificate or key is missing)"
        fi
    fi

    ROLLBACK_PENDING=0
    rm -rf -- "$UPGRADE_BACKUP_DIR"
    UPGRADE_BACKUP_DIR=
}

run_host_diagnostics() {
    if [ "$RUN_HOST_DIAGNOSTICS" -eq 0 ]; then
        return
    fi
    if [ ! -r "$TLS_CERT_PATH" ] || [ ! -r "$TLS_KEY_PATH" ]; then
        HOST_DIAGNOSTICS_RESULT="deferred until TLS material is installed"
        return
    fi

    echo
    echo "Checking CONNECT-IP host prerequisites (read-only) ..."
    if "$BIN_PATH" --config "$CONFIG_PATH" doctor; then
        HOST_DIAGNOSTICS_RESULT="passed"
    else
        HOST_DIAGNOSTICS_RESULT="attention required; run masque-server --config $CONFIG_PATH doctor"
        echo "warning: CONNECT-IP host diagnostics found missing or unverified prerequisites." >&2
        echo "warning: installation continues; no forwarding, firewall, routing, or NAT setting was changed." >&2
    fi
}

[ -x "$CANDIDATE_BIN" ] || die "release package is missing executable $CANDIDATE_BIN"
[ -x "$CANDIDATE_PROBE" ] || die "release package is missing executable $CANDIDATE_PROBE"
if ! CANDIDATE_VERSION_OUTPUT=$("$CANDIDATE_BIN" --version); then
    die "the packaged server binary cannot run on this host"
fi
if ! CANDIDATE_PROBE_VERSION_OUTPUT=$("$CANDIDATE_PROBE" --version); then
    die "the packaged probe binary cannot run on this host"
fi
CANDIDATE_VERSION=$(printf '%s\n' "$CANDIDATE_VERSION_OUTPUT" | awk '{print $NF}')
CANDIDATE_PROBE_VERSION=$(printf '%s\n' "$CANDIDATE_PROBE_VERSION_OUTPUT" | awk '{print $NF}')
[ -n "$CANDIDATE_VERSION" ] && [ -n "$CANDIDATE_PROBE_VERSION" ] || die \
    "could not read the packaged binary versions"
[ "$CANDIDATE_VERSION" = "$CANDIDATE_PROBE_VERSION" ] || die \
    "packaged binary versions differ: server $CANDIDATE_VERSION, probe $CANDIDATE_PROBE_VERSION"
parse_start_requested
parse_host_diagnostics_requested

if [ -e "$CONFIG_PATH" ]; then
    check_config_compatibility "$CONFIG_PATH"
    detect_existing_auth_mode
    echo "Keeping existing $CONFIG_PATH and all referenced TLS files unchanged."
    echo "Authentication, listen, TLS, and client provisioning variables are ignored on upgrade."
else
    FRESH_CONFIG=1
fi

if ! getent group masque >/dev/null 2>&1; then
    groupadd --system masque
fi
if ! id masque >/dev/null 2>&1; then
    useradd --system --gid masque --home-dir /var/lib/masque \
        --create-home --shell /usr/sbin/nologin masque
fi

install -d -m 0755 /usr/local/bin /etc/masque /etc/systemd/system \
    /usr/local/share/masque-server "$MONITORING_DIR"
install -d -o root -g masque -m 0750 /etc/masque/certs

if [ "$FRESH_CONFIG" -eq 1 ]; then
    choose_auth_mode
    install_tls_material 1
    render_new_config
    configure_fresh_listen_port

    if mode_uses_basic; then
        generate_basic_client_config
    fi

    if mode_uses_client_certs; then
        enroll_first_client
    fi

    if [ -r "$TLS_CERT_PATH" ] && [ -r "$TLS_KEY_PATH" ]; then
        check_config_compatibility "$CONFIG_TMP"
    else
        echo "TLS material is not installed; full compatibility checking is deferred."
    fi

    install -o root -g masque -m 0640 "$CONFIG_TMP" "$CONFIG_PATH"
    CONFIG_CHANGED=1
fi

install_program_and_unit
run_host_diagnostics

echo
echo "MASQUE installation result"
echo "  Version:        $("$BIN_PATH" --version)"
echo "  Binary:         $BIN_PATH"
echo "  Probe:          $PROBE_PATH"
echo "  Configuration:  $CONFIG_PATH"
echo "  Authentication: $AUTH_MODE"
echo "  Service:        $SERVICE_RESULT"
echo "  Host diagnostics: $HOST_DIAGNOSTICS_RESULT"
echo "  Logs:           journalctl -u masque -f"
echo "  Prometheus rules (optional): $PROMETHEUS_RULES_PATH"
echo "  Grafana JSON (optional):     $GRAFANA_DASHBOARD_PATH"

# The per-socket truth behind the summary line above, so a server that
# authenticates on one port and not another cannot read as if it did both.
listener_summary=$(printf '%s\n' "$CHECK_CONFIG_OUTPUT" | sed -n 's/^listener /  /p')
if [ -n "$listener_summary" ]; then
    echo
    echo "Listeners:"
    printf '%s\n' "$listener_summary"
fi

# CONFIG_CHANGED first: only a freshly rendered configuration has credentials to
# print, and on an upgrade AUTH_MODE is a summary of what was found rather than
# one of the modes this installer writes.
if [ "$CONFIG_CHANGED" -eq 1 ] && mode_uses_basic; then
    echo
    echo "Basic client credentials:"
    echo "  Username: $AUTH_USERNAME"
    if [ "$GENERATED_PASSWORD" -eq 1 ]; then
        echo "  Password: $AUTH_PASSWORD"
        echo "  Store this password now; it will not be shown again."
    else
        echo "  Password: supplied through MASQUE_AUTH_PASSWORD (not repeated)"
    fi
    if [ -n "$BASIC_CLIENT_CONFIG_OUT" ]; then
        echo "  Secret Surge configuration: $BASIC_CLIENT_CONFIG_OUT"
    fi
fi

if [ "$CONFIG_CHANGED" -eq 1 ]; then
    print_redacted_config
else
    echo
    echo "Existing configuration was preserved and is not printed during upgrades."
fi

if [ -n "$ENROLL_OUTPUT" ]; then
    echo
    echo "Client-certificate enrollment result"
    echo "  Secret usque JSON: $CLIENT_CONFIG_OUT"
    echo "  The mihomo block below also contains the client private key."
    echo
    cat "$ENROLL_OUTPUT"
fi

echo
if [ "$FRESH_CONFIG" -eq 1 ] &&
    { [ ! -r "$TLS_CERT_PATH" ] || [ ! -r "$TLS_KEY_PATH" ]; }; then
    echo "Next: install the TLS certificate and key at:"
    echo "  $TLS_CERT_PATH"
    echo "  $TLS_KEY_PATH"
    echo "Then run: systemctl start masque"
elif [ "$START_REQUESTED" -eq 0 ]; then
    echo "Start the service with: systemctl start masque"
fi
echo "Review $CONFIG_PATH, especially the proxy allow/deny policy."
echo "Diagnose from a client host with: masque-probe <host:port> --username <user> --password-stdin"
echo "Create a support report with: masque-server --config $CONFIG_PATH support-bundle --out masque-support.json"

# Listeners are written only for a fresh installation; an upgrade keeps the
# existing file. Adding one later is a separate, deliberate command, so name it
# here rather than leaving hand-edited TOML as the discoverable option.
echo
echo "To serve another authentication mode, or another port, add a listener:"
echo "  masque-server --config $CONFIG_PATH add-listener"
echo "Then open its UDP (http3) or TCP (http2) port and run: systemctl restart masque"
