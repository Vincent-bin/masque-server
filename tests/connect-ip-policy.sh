#!/usr/bin/env bash
# Real H2/H3 IP forwarding and ACL checks in a disposable Linux network namespace.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
if [ "${1:-}" != --inside ]; then
    [ "$(id -u)" = 0 ] || { echo 'root is required for an isolated TUN namespace' >&2; exit 2; }
    exec unshare --net -- bash "$0" --inside
fi
bin="${MASQUE_TEST_BIN_DIR:-target/release}"
case "${MASQUE_IP_TEST_TUN_OFFLOAD:-1}" in
    0) offload=false ;;
    1) offload=true ;;
    *) echo 'MASQUE_IP_TEST_TUN_OFFLOAD must be 0 or 1' >&2; exit 2 ;;
esac
[ -x "$bin/masque-server" ] && [ -x "$bin/masque-probe" ] || exit 2
tmp="$(mktemp -d /tmp/masque-ip-policy.XXXXXX)"
server_pid=''
echo_pid=''
cleanup() {
    [ -z "$server_pid" ] || { kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; }
    [ -z "$echo_pid" ] || { kill "$echo_pid" 2>/dev/null || true; wait "$echo_pid" 2>/dev/null || true; }
    rm -rf -- "$tmp"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
ip link set lo up
ip addr add 198.18.0.1/32 dev lo
ip addr add 10.20.0.1/32 dev lo
ip -6 addr add 2001:db8::1/128 dev lo
ip -6 addr add fd00:1234::1/128 dev lo
bash scripts/gen-certs.sh "$tmp/certs" >/dev/null 2>&1
python3 - <<'PY' &
import socket, threading

def echo(address):
    sock = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((address, 9999))
    while True:
        payload, peer = sock.recvfrom(65535)
        sock.sendto(payload, peer)

threads = [threading.Thread(target=echo, args=(address,)) for address in ('198.18.0.1', '10.20.0.1', '2001:db8::1', 'fd00:1234::1')]
for thread in threads: thread.start()
for thread in threads: thread.join()
PY
echo_pid=$!

start_server() {
    cat >"$tmp/config.toml" <<CONFIG
[tls]
cert_path = "$tmp/certs/server.crt"
key_path = "$tmp/certs/server.key"
[udp_proxy]
allow_targets = ["0.0.0.0/0", "::/0"]
deny_targets = []
[ip_proxy]
enabled = true
require_tun = true
tun_offload = $offload
$1
[[listeners]]
listen_addr = "127.0.0.1:4433"
transport = "http3"
shards = 1
[listeners.auth]
enabled = false
[[listeners]]
listen_addr = "127.0.0.1:4433"
transport = "http2"
[listeners.auth]
enabled = false
CONFIG
    "$bin/masque-server" --config "$tmp/config.toml" --status-socket "$tmp/status.sock" >"$tmp/server.log" 2>&1 &
    server_pid=$!
    for ((attempt=0; attempt<100; attempt++)); do
        [ ! -S "$tmp/status.sock" ] || return 0
        kill -0 "$server_pid" 2>/dev/null || { echo 'isolated server failed to start' >&2; return 1; }
        sleep 0.05
    done
    echo 'isolated server startup timed out' >&2
    return 1
}

probe_ip() {
    local transport="$1" target="$2" expected="$3" family="$4"
    local result=0
    "$bin/masque-probe" 127.0.0.1:4433 --insecure --transport "$transport" \
        --skip-tcp --skip-udp --connect-ip --ip-mode echo --ip-target "$target" \
        --timeout 2 --json >"$tmp/probe.json" || result=$?
    python3 - "$tmp/probe.json" "$expected" "$result" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
check = next(check for check in report['checks'] if check['name'] == 'connect_ip')
if sys.argv[2] == 'allow':
    assert sys.argv[3] == '0' and report['success'] and check['code'] == 'CONNECT_IP_ROUND_TRIP', check
else:
    assert sys.argv[3] != '0' and not report['success'] and check['code'] == 'CONNECT_IP_RESPONSE_TIMEOUT', check
PY
    printf 'IP_POLICY_RESULT transport=%s family=%s expected=%s passed=true\n' "$transport" "$family" "$expected"
}

start_server ''
for transport in http2 http3; do
    probe_ip "$transport" 198.18.0.1:9999 allow ipv4
    probe_ip "$transport" '[2001:db8::1]:9999' allow ipv6
    probe_ip "$transport" 10.20.0.1:9999 deny ipv4
    probe_ip "$transport" '[fd00:1234::1]:9999' deny ipv6
    # An independent UDP policy permits the same private target.
    "$bin/masque-probe" 127.0.0.1:4433 --insecure --transport "$transport" \
        --skip-tcp --udp-target 10.20.0.1:9999 --udp-mode echo --timeout 2 --json >"$tmp/udp.json"
done
kill "$server_pid"
wait "$server_pid"
server_pid=''
# Explicitly opt in to one private subnet; unrelated destinations stay denied.
start_server $'allow_targets = ["10.20.0.0/16", "fd00:1234::/64"]\ndeny_targets = []'
for transport in http2 http3; do
    probe_ip "$transport" 10.20.0.1:9999 allow ipv4
    probe_ip "$transport" '[fd00:1234::1]:9999' allow ipv6
    probe_ip "$transport" 198.18.0.1:9999 deny ipv4
    probe_ip "$transport" '[2001:db8::1]:9999' deny ipv6
done
printf 'IP_POLICY_SUITE tun_offload_requested=%s passed=true\n' "$offload"
