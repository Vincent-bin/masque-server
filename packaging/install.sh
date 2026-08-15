#!/usr/bin/env sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run this installer as root (for example: sudo ./install.sh)" >&2
    exit 1
fi

PACKAGE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
GENERATED_PASSWORD=0

generate_auth_credentials() {
    AUTH_USERNAME=${MASQUE_AUTH_USERNAME:-masque}
    case "$AUTH_USERNAME" in
        ""|*[!A-Za-z0-9._-]*)
            echo "error: MASQUE_AUTH_USERNAME may only contain letters, digits, '.', '_' and '-'" >&2
            exit 1
            ;;
    esac

    if [ -n "${MASQUE_AUTH_PASSWORD:-}" ]; then
        AUTH_PASSWORD=$MASQUE_AUTH_PASSWORD
    else
        AUTH_PASSWORD=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
        GENERATED_PASSWORD=1
    fi
    AUTH_PASSWORD_HASH=$(printf '%s' "$AUTH_PASSWORD" | \
        "$PACKAGE_DIR/bin/masque-server" hash-password)
}

if ! getent group masque >/dev/null 2>&1; then
    groupadd --system masque
fi
if ! id masque >/dev/null 2>&1; then
    useradd --system --gid masque --home-dir /var/lib/masque \
        --create-home --shell /usr/sbin/nologin masque
fi

install -d -m 0755 /usr/local/bin /etc/masque /etc/systemd/system
install -d -o root -g masque -m 0750 /etc/masque/certs
install -m 0755 "$PACKAGE_DIR/bin/masque-server" /usr/local/bin/masque-server
install -m 0644 "$PACKAGE_DIR/systemd/masque.service" /etc/systemd/system/masque.service

if [ ! -e /etc/masque/masque.toml ]; then
    generate_auth_credentials

    CONFIG_TMP=$(mktemp /etc/masque/.masque.toml.XXXXXX)
    trap 'rm -f -- "$CONFIG_TMP"' EXIT HUP INT TERM
    sed \
        -e "s|__MASQUE_AUTH_USERNAME__|$AUTH_USERNAME|" \
        -e "s|__MASQUE_AUTH_PASSWORD_HASH__|$AUTH_PASSWORD_HASH|" \
        "$PACKAGE_DIR/config/masque.toml" >"$CONFIG_TMP"
    if grep -q '__MASQUE_AUTH_' "$CONFIG_TMP"; then
        echo "error: failed to configure generated proxy credentials" >&2
        exit 1
    fi
    install -o root -g masque -m 0640 "$CONFIG_TMP" /etc/masque/masque.toml
    rm -f -- "$CONFIG_TMP"
    trap - EXIT HUP INT TERM
elif ! grep -Eq '^[[:space:]]*\[auth\][[:space:]]*(#.*)?$' \
    /etc/masque/masque.toml; then
    generate_auth_credentials

    CONFIG_TMP=$(mktemp /etc/masque/.masque.toml.XXXXXX)
    trap 'rm -f -- "$CONFIG_TMP"' EXIT HUP INT TERM
    {
        cat /etc/masque/masque.toml
        printf '\n[auth]\n'
        printf 'enabled = true\n'
        printf 'username = "%s"\n' "$AUTH_USERNAME"
        printf 'password_hash = "%s"\n' "$AUTH_PASSWORD_HASH"
    } >"$CONFIG_TMP"
    if [ ! -e /etc/masque/masque.toml.before-auth ]; then
        cp -p -- /etc/masque/masque.toml \
            /etc/masque/masque.toml.before-auth
    fi
    install -o root -g masque -m 0640 "$CONFIG_TMP" /etc/masque/masque.toml
    rm -f -- "$CONFIG_TMP"
    trap - EXIT HUP INT TERM
    echo "Added HTTP proxy authentication to the existing configuration."
    echo "Backup: /etc/masque/masque.toml.before-auth"
else
    echo "Keeping existing /etc/masque/masque.toml"
fi

systemctl daemon-reload
systemctl enable masque.service

echo
echo "MASQUE server installed and enabled."
echo "1. Put the TLS certificate and key at:"
echo "     /etc/masque/certs/server.crt"
echo "     /etc/masque/certs/server.key"
echo "2. Ensure root:masque ownership and 0640 permissions on both files."
echo "3. Review /etc/masque/masque.toml, especially the proxy allow/deny policy."
echo "4. Start it with: sudo systemctl start masque"
echo "5. View logs with: sudo journalctl -u masque -f"
if [ "$GENERATED_PASSWORD" -eq 1 ]; then
    echo
    echo "Generated HTTP proxy credentials (shown once):"
    echo "  Username: $AUTH_USERNAME"
    echo "  Password: $AUTH_PASSWORD"
fi
