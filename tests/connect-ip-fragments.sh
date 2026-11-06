#!/usr/bin/env bash
# Run only the privileged IPv6 fragmentation regression in disposable namespaces.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo 'root is required for an isolated TUN namespace' >&2; exit 2; }
if [ "${1:-}" = --inside ]; then
    ip link set lo up
    ip -6 addr add 2001:db8::1/128 dev lo
    exec "$2" ip_fragments::ipv6_fragments_reach_udp_target --ignored --exact --nocapture
fi
bin="${MASQUE_TEST_BIN_DIR:?set MASQUE_TEST_BIN_DIR to the compiled test executables}"
for offload in 0 1; do
    for test in http2_connect client_cert_connect_ip; do
        unshare --net -- env MASQUE_TEST_NETNS=1 MASQUE_IP_TEST_TUN_OFFLOAD="$offload" \
            bash "$0" --inside "$bin/$test"
    done
done
