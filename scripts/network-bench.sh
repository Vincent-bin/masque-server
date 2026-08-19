#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

BENCH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/masque-network-bench.XXXXXX")"
SERVER_PID=""
ECHO_PID=""
HTTP_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [ -n "$ECHO_PID" ]; then
        kill "$ECHO_PID" 2>/dev/null || true
        wait "$ECHO_PID" 2>/dev/null || true
    fi
    if [ -n "$HTTP_PID" ]; then
        kill "$HTTP_PID" 2>/dev/null || true
        wait "$HTTP_PID" 2>/dev/null || true
    fi
    rm -rf -- "$BENCH_DIR"
}
trap cleanup EXIT INT TERM

bash scripts/gen-certs.sh "$BENCH_DIR/certs"

cat >"$BENCH_DIR/masque.toml" <<EOF
[server]
idle_timeout_secs = 30

[tls]
cert_path = "$BENCH_DIR/certs/server.crt"
key_path = "$BENCH_DIR/certs/server.key"

[[listeners]]
listen_addr = "127.0.0.1:4433"

[listeners.auth]
enabled = true
username = "test"
password_hash = "\$argon2id\$v=19\$m=19456,t=2,p=1\$1xNVXhqKU7jJ6cqTBJKphQ\$GXXAINVTW1qhloFtN1IR8lSr7pI7QEY79fq4K6d8scQ"

[quic]
max_datagram_size = 1350
enable_dgram = true

[tcp_proxy]
enabled = true
allow_targets = ["127.0.0.0/8"]
deny_targets = []

[udp_proxy]
enabled = true
allow_targets = ["127.0.0.0/8"]
deny_targets = []

[ip_proxy]
enabled = false
EOF

case "${MASQUE_BENCH_OBSERVABILITY:-0}" in
    0) ;;
    1)
        cat >>"$BENCH_DIR/masque.toml" <<'EOF'

[observability]
listen_addr = "127.0.0.1:0"
EOF
        ;;
    *)
        echo "MASQUE_BENCH_OBSERVABILITY must be 0 or 1" >&2
        exit 2
        ;;
esac

cargo build --workspace --release

truncate -s 67108864 "$BENCH_DIR/masque-bench.bin"
python3 -m http.server 9998 --bind 127.0.0.1 --directory "$BENCH_DIR" \
    >"$BENCH_DIR/http.log" 2>&1 &
HTTP_PID=$!

MASQUE_ECHO_SERVER_ADDR=127.0.0.1:9999 \
RUST_LOG=warn \
target/release/masque-e2e >"$BENCH_DIR/echo.log" 2>&1 &
ECHO_PID=$!

RUST_LOG=warn target/release/masque-server --config "$BENCH_DIR/masque.toml" \
    >"$BENCH_DIR/server.log" 2>&1 &
SERVER_PID=$!

MASQUE_AUTH_CHECK=1 \
MASQUE_SERVER_ADDR=127.0.0.1:4433 \
ECHO_SERVER_ADDR=127.0.0.1:9999 \
RUST_LOG=warn \
target/release/masque-e2e

MASQUE_TCP_CHECK=1 \
MASQUE_SERVER_ADDR=127.0.0.1:4433 \
ECHO_SERVER_ADDR=127.0.0.1:9999 \
MASQUE_USERNAME=test \
MASQUE_PASSWORD=test-password \
RUST_LOG=warn \
target/release/masque-e2e

MASQUE_TCP_DOWNLOAD=1 \
MASQUE_SERVER_ADDR=127.0.0.1:4433 \
MASQUE_TCP_TARGET=127.0.0.1:9998 \
MASQUE_TCP_DOWNLOAD_BYTES=67108864 \
MASQUE_TCP_DOWNLOAD_REPEATS=2 \
MASQUE_USERNAME=test \
MASQUE_PASSWORD=test-password \
RUST_LOG=warn \
target/release/masque-e2e

MASQUE_BENCH=1 \
MASQUE_SERVER_ADDR=127.0.0.1:4433 \
ECHO_SERVER_ADDR=127.0.0.1:9999 \
MASQUE_USERNAME=test \
MASQUE_PASSWORD=test-password \
RUST_LOG=warn \
cargo run --release -p masque-e2e
