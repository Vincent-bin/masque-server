#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

BENCH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/masque-network-bench.XXXXXX")"
SERVER_PID=""
ECHO_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [ -n "$ECHO_PID" ]; then
        kill "$ECHO_PID" 2>/dev/null || true
        wait "$ECHO_PID" 2>/dev/null || true
    fi
    rm -rf -- "$BENCH_DIR"
}
trap cleanup EXIT INT TERM

bash scripts/gen-certs.sh "$BENCH_DIR/certs"

cat >"$BENCH_DIR/masque.toml" <<EOF
[server]
listen_addr = "127.0.0.1:4433"
idle_timeout_secs = 30

[tls]
cert_path = "$BENCH_DIR/certs/server.crt"
key_path = "$BENCH_DIR/certs/server.key"

[quic]
max_datagram_size = 1350
enable_dgram = true

[udp_proxy]
enabled = true
allow_targets = ["127.0.0.0/8"]
deny_targets = []

[ip_proxy]
enabled = false
EOF

cargo build --workspace --release

python3 tests/e2e/echo-server.py 9999 >"$BENCH_DIR/echo.log" 2>&1 &
ECHO_PID=$!

RUST_LOG=warn target/release/masque --config "$BENCH_DIR/masque.toml" \
    >"$BENCH_DIR/server.log" 2>&1 &
SERVER_PID=$!

MASQUE_BENCH=1 \
MASQUE_SERVER_ADDR=127.0.0.1:4433 \
ECHO_SERVER_ADDR=127.0.0.1:9999 \
RUST_LOG=warn \
cargo run --release -p masque-e2e
