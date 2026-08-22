#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

BENCH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/masque-network-bench.XXXXXX")"
SERVER_PID=""
ECHO_PID=""
HTTP_PID=""
TCP_DOWNLOAD_BYTES="${MASQUE_TCP_DOWNLOAD_BYTES:-67108864}"
TCP_DOWNLOAD_REPEATS="${MASQUE_TCP_DOWNLOAD_REPEATS:-2}"
TCP_DIRECT_BASELINE="${MASQUE_TCP_DIRECT_BASELINE:-1}"
BENCH_MODE="${MASQUE_BENCH_MODE:-all}"
BENCH_SHARDS="${MASQUE_BENCH_SHARDS:-1}"
BENCH_TRANSPORT="${MASQUE_BENCH_TRANSPORT:-http3}"
BENCH_QUIC_RETRY="${MASQUE_BENCH_QUIC_RETRY:-adaptive}"
LOAD_CONNS="${MASQUE_LOAD_CONNS:-}"

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

case "$BENCH_MODE" in
    all|smoke|tcp|udp|load) ;;
    *)
        echo "MASQUE_BENCH_MODE must be all, smoke, tcp, udp, or load" >&2
        exit 2
        ;;
esac

case "$BENCH_TRANSPORT" in
    http2) BENCH_TRANSPORTS="http2" ;;
    http3) BENCH_TRANSPORTS="http3" ;;
    both) BENCH_TRANSPORTS="http3 http2" ;;
    *)
        echo "MASQUE_BENCH_TRANSPORT must be http2, http3, or both" >&2
        exit 2
        ;;
esac

case "$BENCH_QUIC_RETRY" in
    adaptive|always|off) ;;
    *)
        echo "MASQUE_BENCH_QUIC_RETRY must be adaptive, always, or off" >&2
        exit 2
        ;;
esac

if [ "$BENCH_MODE" = load ] && [ "$BENCH_TRANSPORT" != http3 ]; then
    echo "MASQUE_BENCH_MODE=load currently requires MASQUE_BENCH_TRANSPORT=http3" >&2
    exit 2
fi

case "$BENCH_SHARDS" in
    ''|*[!0-9]*)
        echo "MASQUE_BENCH_SHARDS must be a non-negative integer" >&2
        exit 2
        ;;
esac

if [ "$BENCH_TRANSPORT" = both ] && [ "$BENCH_SHARDS" = 0 ]; then
    echo "MASQUE_BENCH_SHARDS=0 is ambiguous with two listeners; choose an explicit HTTP/3 shard count" >&2
    exit 2
fi

case "$LOAD_CONNS" in
    ''|0) ;;
    *[!0-9]*)
        echo "MASQUE_LOAD_CONNS must be a positive integer" >&2
        exit 2
        ;;
esac

case "${MASQUE_BENCH_TARGET_GSO:-0}" in
    0) TARGET_GSO_TOML=false ;;
    1) TARGET_GSO_TOML=true ;;
    *)
        echo "MASQUE_BENCH_TARGET_GSO must be 0 or 1" >&2
        exit 2
        ;;
esac

case "${MASQUE_BENCH_QUIC_GSO:-0}" in
    0) QUIC_GSO_TOML=false ;;
    1) QUIC_GSO_TOML=true ;;
    *)
        echo "MASQUE_BENCH_QUIC_GSO must be 0 or 1" >&2
        exit 2
        ;;
esac

case "$TCP_DIRECT_BASELINE" in
    0) unset MASQUE_TCP_DIRECT_BASELINE ;;
    1) export MASQUE_TCP_DIRECT_BASELINE=1 ;;
    *)
        echo "MASQUE_TCP_DIRECT_BASELINE must be 0 or 1" >&2
        exit 2
        ;;
esac

bash scripts/gen-certs.sh "$BENCH_DIR/certs"

cat >"$BENCH_DIR/masque.toml" <<EOF
[server]
idle_timeout_secs = 30

[tls]
cert_path = "$BENCH_DIR/certs/server.crt"
key_path = "$BENCH_DIR/certs/server.key"

[quic]
max_datagram_size = 1350
enable_dgram = true
enable_udp_gso = $QUIC_GSO_TOML
retry_mode = "$BENCH_QUIC_RETRY"

[tcp_proxy]
enabled = true
allow_targets = ["127.0.0.0/8"]
deny_targets = []

[udp_proxy]
enabled = true
enable_udp_gso = $TARGET_GSO_TOML
allow_targets = ["127.0.0.0/8"]
deny_targets = []

[ip_proxy]
enabled = false
EOF


if [ "$BENCH_TRANSPORT" = http3 ] || [ "$BENCH_TRANSPORT" = both ]; then
    cat >>"$BENCH_DIR/masque.toml" <<EOF

[[listeners]]
listen_addr = "127.0.0.1:4433"
transport = "http3"
shards = $BENCH_SHARDS

[listeners.auth]
enabled = true
username = "test"
password_hash = "\$argon2id\$v=19\$m=19456,t=2,p=1\$1xNVXhqKU7jJ6cqTBJKphQ\$GXXAINVTW1qhloFtN1IR8lSr7pI7QEY79fq4K6d8scQ"
EOF
fi

if [ "$BENCH_TRANSPORT" = http2 ] || [ "$BENCH_TRANSPORT" = both ]; then
    cat >>"$BENCH_DIR/masque.toml" <<'EOF'

[[listeners]]
listen_addr = "127.0.0.1:4433"
transport = "http2"
shards = 1

[listeners.auth]
enabled = true
username = "test"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$1xNVXhqKU7jJ6cqTBJKphQ$GXXAINVTW1qhloFtN1IR8lSr7pI7QEY79fq4K6d8scQ"
EOF
fi

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

case "$BENCH_MODE" in
    all|tcp)
        truncate -s "$TCP_DOWNLOAD_BYTES" "$BENCH_DIR/masque-bench.bin"
        python3 -m http.server 9998 --bind 127.0.0.1 --directory "$BENCH_DIR" \
            >"$BENCH_DIR/http.log" 2>&1 &
        HTTP_PID=$!
        ;;
esac

case "$BENCH_MODE" in
    all|smoke|udp|load)
        MASQUE_ECHO_SERVER_ADDR=127.0.0.1:9999 \
        RUST_LOG=warn \
        target/release/masque-e2e >"$BENCH_DIR/echo.log" 2>&1 &
        ECHO_PID=$!
        ;;
esac

RUST_LOG=warn target/release/masque-server --config "$BENCH_DIR/masque.toml" \
    >"$BENCH_DIR/server.log" 2>&1 &
SERVER_PID=$!

case "$BENCH_MODE" in
    all|smoke)
        for transport in $BENCH_TRANSPORTS; do
            MASQUE_AUTH_CHECK=1 \
            MASQUE_BENCH_TRANSPORT="$transport" \
            MASQUE_SERVER_ADDR=127.0.0.1:4433 \
            ECHO_SERVER_ADDR=127.0.0.1:9999 \
            RUST_LOG=warn \
            target/release/masque-e2e

            MASQUE_TCP_CHECK=1 \
            MASQUE_BENCH_TRANSPORT="$transport" \
            MASQUE_SERVER_ADDR=127.0.0.1:4433 \
            ECHO_SERVER_ADDR=127.0.0.1:9999 \
            MASQUE_USERNAME=test \
            MASQUE_PASSWORD=test-password \
            RUST_LOG=warn \
            target/release/masque-e2e

            MASQUE_UDP_CHECK=1 \
            MASQUE_BENCH_TRANSPORT="$transport" \
            MASQUE_SERVER_ADDR=127.0.0.1:4433 \
            ECHO_SERVER_ADDR=127.0.0.1:9999 \
            MASQUE_USERNAME=test \
            MASQUE_PASSWORD=test-password \
            RUST_LOG=warn \
            target/release/masque-e2e
        done
        ;;
esac

case "$BENCH_MODE" in
    all|tcp)
        for transport in $BENCH_TRANSPORTS; do
            MASQUE_TCP_DOWNLOAD=1 \
            MASQUE_BENCH_TRANSPORT="$transport" \
            MASQUE_SERVER_ADDR=127.0.0.1:4433 \
            MASQUE_TCP_TARGET=127.0.0.1:9998 \
            MASQUE_TCP_DOWNLOAD_BYTES="$TCP_DOWNLOAD_BYTES" \
            MASQUE_TCP_DOWNLOAD_REPEATS="$TCP_DOWNLOAD_REPEATS" \
            MASQUE_USERNAME=test \
            MASQUE_PASSWORD=test-password \
            RUST_LOG=warn \
            target/release/masque-e2e
        done
        ;;
esac

case "$BENCH_MODE" in
    all|udp)
        for transport in $BENCH_TRANSPORTS; do
            MASQUE_BENCH=1 \
            MASQUE_BENCH_TRANSPORT="$transport" \
            MASQUE_SERVER_ADDR=127.0.0.1:4433 \
            ECHO_SERVER_ADDR=127.0.0.1:9999 \
            MASQUE_USERNAME=test \
            MASQUE_PASSWORD=test-password \
            RUST_LOG=warn \
            target/release/masque-e2e
        done
        ;;
esac

if [ "$BENCH_MODE" = load ] || {
    [ "$BENCH_MODE" = all ] && [ -n "$LOAD_CONNS" ] && [ "$LOAD_CONNS" != 0 ]
}; then
    MASQUE_LOAD=1 \
    MASQUE_LOAD_CONNS="${LOAD_CONNS:-32}" \
    MASQUE_BENCH_TRANSPORT=http3 \
    MASQUE_SERVER_ADDR=127.0.0.1:4433 \
    ECHO_SERVER_ADDR=127.0.0.1:9999 \
    MASQUE_USERNAME=test \
    MASQUE_PASSWORD=test-password \
    RUST_LOG=warn \
    target/release/masque-e2e
fi
