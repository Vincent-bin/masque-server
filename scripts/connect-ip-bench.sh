#!/usr/bin/env bash
# Local CONNECT-IP echo benchmark in an ephemeral Linux network namespace.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."

if [ "${1:-}" != --inside ]; then
    [ "$(id -u)" = 0 ] || { echo 'root is required for an isolated TUN namespace' >&2; exit 2; }
    exec unshare --net -- bash "$0" --inside
fi

case "${MASQUE_IP_BENCH_TUN_OFFLOAD:-1}" in
    0) tun_offload=false ;;
    1) tun_offload=true ;;
    *) echo 'MASQUE_IP_BENCH_TUN_OFFLOAD must be 0 or 1' >&2; exit 2 ;;
esac
bin="${MASQUE_BENCH_BIN_DIR:-target/release}"
client="${MASQUE_IP_BENCH_CLIENT_BIN:-$bin/masque-e2e}"
server="$bin/masque-server"
if [ ! -x "$client" ] || [ ! -x "$server" ]; then
    echo 'benchmark executables missing' >&2
    exit 2
fi
tmp="$(mktemp -d "${TMPDIR:-/tmp}/masque-ip-bench.XXXXXX")"
server_job=''
echo_pid=''
cleanup() {
    [ -z "$server_job" ] || { kill "$server_job" 2>/dev/null || true; wait "$server_job" 2>/dev/null || true; }
    [ -z "$echo_pid" ] || { kill "$echo_pid" 2>/dev/null || true; wait "$echo_pid" 2>/dev/null || true; }
    [ ! -f "$tmp/server-resource.txt" ] || cat "$tmp/server-resource.txt"
    if [ -n "${MASQUE_BENCH_RESULTS_DIR:-}" ]; then
        mkdir -p "$MASQUE_BENCH_RESULTS_DIR"
        cp "$tmp/server.log" "$MASQUE_BENCH_RESULTS_DIR/server.log" 2>/dev/null || true
        cp "$tmp/server-resource.txt" "$MASQUE_BENCH_RESULTS_DIR/server-resource.txt" 2>/dev/null || true
    fi
    rm -rf -- "$tmp"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ip link set lo up
ip addr add 198.18.0.1/32 dev lo
bash scripts/gen-certs.sh "$tmp/certs" >/dev/null 2>&1
cat >"$tmp/config.toml" <<EOF
[tls]
cert_path = "$tmp/certs/server.crt"
key_path = "$tmp/certs/server.key"

[quic]
enable_udp_gso = false

[ip_proxy]
enabled = true
tun_offload = $tun_offload

[[listeners]]
listen_addr = "127.0.0.1:4433"
shards = 1

[listeners.auth]
enabled = false
EOF
MASQUE_ECHO_SERVER_ADDR=198.18.0.1:9999 RUST_LOG=warn "$client" >"$tmp/echo.log" 2>&1 &
echo_pid=$!
RUST_LOG=info python3 scripts/bench-process.py --pid-file "$tmp/server.pid" \
    --result-file "$tmp/server-resource.txt" -- "$server" --config "$tmp/config.toml" \
    >"$tmp/server.log" 2>&1 &
server_job=$!
for ((attempt=0; attempt<100; attempt++)); do
    [ ! -s "$tmp/server.pid" ] || break
    kill -0 "$server_job" 2>/dev/null || { echo 'server failed to start' >&2; exit 1; }
    sleep 0.05
done
[ -s "$tmp/server.pid" ] || { echo 'server start timed out' >&2; exit 1; }
printf 'IP_BENCH_CONFIG tun_offload_requested=%s\n' "$tun_offload"
MASQUE_IP_BENCH=1 MASQUE_SERVER_ADDR=127.0.0.1:4433 ECHO_SERVER_ADDR=198.18.0.1:9999 \
    RUST_LOG=warn "$client"
python3 - "$tmp/server.log" <<'PY'
import re
import sys

log = open(sys.argv[1], encoding="utf-8", errors="replace").read()
log = re.sub(r"\x1b\[[0-9;]*m", "", log)
lines = [line for line in log.splitlines() if "TUN device created" in line]
match = re.search(r"offload=(true|false)", lines[-1]) if lines else None
print(f"IP_BENCH_TUN effective_offload={match.group(1) if match else 'unknown'}")
PY
