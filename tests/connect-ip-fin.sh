#!/usr/bin/env bash
# Verify late native IP datagrams with TUN offload on and off, in isolation.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo 'root is required for an isolated TUN namespace' >&2; exit 2; }
bin="${MASQUE_TEST_BIN_DIR:?set MASQUE_TEST_BIN_DIR to the compiled test executables}"
for offload in 0 1; do
    unshare --net -- env MASQUE_TEST_NETNS=1 MASQUE_IP_TEST_TUN_OFFLOAD="$offload" \
        bash -seuo pipefail -- "$bin/client_cert_connect_ip" <<'INSIDE'
ip link set lo up
ip -6 addr add 2001:db8::1/128 dev lo
exec "$1" ip_fin::ip_native_datagrams_stop_at_request_fin_while_control_reply_is_blocked --ignored --exact --nocapture
INSIDE
done
