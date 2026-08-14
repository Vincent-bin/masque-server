#!/usr/bin/env sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run this installer as root (for example: sudo ./install.sh)" >&2
    exit 1
fi

PACKAGE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

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
    install -o root -g masque -m 0640 \
        "$PACKAGE_DIR/config/masque.toml" /etc/masque/masque.toml
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
