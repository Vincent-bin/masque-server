#!/usr/bin/env bash
set -euo pipefail
umask 077

cd "$(dirname "$0")/.."

BENCH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/masque-network-bench.XXXXXX")"
BIN_DIR="${MASQUE_BENCH_BIN_DIR:-target/release}"
SERVER_BIN="${MASQUE_BENCH_SERVER_BIN:-$BIN_DIR/masque-server}"
RESULTS_DIR="${MASQUE_BENCH_RESULTS_DIR:-}"
PERF_BIN="${MASQUE_BENCH_PERF_BIN:-perf}"
PERF_PID=""
SERVER_PID=""
SERVER_JOB_PID=""
ECHO_PID=""
HTTP_PID=""
TCP_DOWNLOAD_BYTES="${MASQUE_TCP_DOWNLOAD_BYTES:-67108864}"
TCP_DOWNLOAD_REPEATS="${MASQUE_TCP_DOWNLOAD_REPEATS:-2}"
TCP_DIRECT_BASELINE="${MASQUE_TCP_DIRECT_BASELINE:-1}"
BENCH_MODE="${MASQUE_BENCH_MODE:-all}"
BENCH_SHARDS="${MASQUE_BENCH_SHARDS:-1}"
BENCH_TRANSPORT="${MASQUE_BENCH_TRANSPORT:-http3}"
BENCH_QUIC_RETRY="${MASQUE_BENCH_QUIC_RETRY:-adaptive}"
BENCH_CC="${MASQUE_BENCH_CC:-cubic}"
LOAD_CONNS="${MASQUE_LOAD_CONNS:-}"

# Pick unused loopback ports for each run. Explicit ports are available for
# controlled environments; a bind collision still fails rather than reusing a
# service. The kernel can allocate a port again after this preflight closes.
read -r SERVER_PORT ECHO_PORT HTTP_PORT < <(python3 - <<'PYPORT'
import socket
sockets = []
try:
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(("127.0.0.1", 0))
    sockets.append(tcp)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", tcp.getsockname()[1]))
    sockets.append(udp)
    for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
        sock = socket.socket(socket.AF_INET, kind)
        sock.bind(("127.0.0.1", 0))
        sockets.append(sock)
    print(tcp.getsockname()[1], sockets[2].getsockname()[1], sockets[3].getsockname()[1])
finally:
    for sock in sockets:
        sock.close()
PYPORT
)
SERVER_PORT="${MASQUE_BENCH_SERVER_PORT:-$SERVER_PORT}"
ECHO_PORT="${MASQUE_BENCH_ECHO_PORT:-$ECHO_PORT}"
HTTP_PORT="${MASQUE_BENCH_HTTP_PORT:-$HTTP_PORT}"
for port in "$SERVER_PORT" "$ECHO_PORT" "$HTTP_PORT"; do
    case "$port" in ''|*[!0-9]*) echo "benchmark ports must be integers" >&2; exit 2 ;; esac
    if [ "${#port}" -gt 5 ] || [ "$((10#$port))" -lt 1 ] || [ "$((10#$port))" -gt 65535 ]; then
        echo "benchmark ports must be between 1 and 65535" >&2; exit 2
    fi
done

cleanup() {
    if [ -n "$PERF_PID" ]; then
        kill -INT "$PERF_PID" 2>/dev/null || true
        wait "$PERF_PID" 2>/dev/null || true
    fi
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
    fi
    if [ -n "$SERVER_JOB_PID" ]; then
        if [ -z "$SERVER_PID" ]; then
            kill "$SERVER_JOB_PID" 2>/dev/null || true
        fi
        wait "$SERVER_JOB_PID" 2>/dev/null || true
    fi
    if [ -f "$BENCH_DIR/server-resource.txt" ]; then
        cat "$BENCH_DIR/server-resource.txt"
    fi
    if [ -n "$ECHO_PID" ]; then
        kill "$ECHO_PID" 2>/dev/null || true
        wait "$ECHO_PID" 2>/dev/null || true
    fi
    if [ -n "$HTTP_PID" ]; then
        kill "$HTTP_PID" 2>/dev/null || true
        wait "$HTTP_PID" 2>/dev/null || true
    fi
    if [ -n "$RESULTS_DIR" ]; then
        mkdir -p "$RESULTS_DIR"
        for artifact in server.log echo.log http.log perf.data perf.log server-resource.txt; do
            if [ -f "$BENCH_DIR/$artifact" ]; then
                cp "$BENCH_DIR/$artifact" "$RESULTS_DIR/$artifact"
            fi
        done
    fi
    rm -rf -- "$BENCH_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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

case "$BENCH_CC" in
    cubic|reno|bbr2) ;;
    *) echo "MASQUE_BENCH_CC must be cubic, reno, or bbr2" >&2; exit 2 ;;
esac

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

case "${MASQUE_BENCH_QUIC_GRO:-1}" in
    0) QUIC_GRO_TOML=false ;;
    1) QUIC_GRO_TOML=true ;;
    *) echo "MASQUE_BENCH_QUIC_GRO must be 0 or 1" >&2; exit 2 ;;
esac

case "$TCP_DIRECT_BASELINE" in
    0) unset MASQUE_TCP_DIRECT_BASELINE ;;
    1) export MASQUE_TCP_DIRECT_BASELINE=1 ;;
    *)
        echo "MASQUE_TCP_DIRECT_BASELINE must be 0 or 1" >&2
        exit 2
        ;;
esac

case "${MASQUE_BENCH_PERF:-0}" in
    0|1) ;;
    *) echo "MASQUE_BENCH_PERF must be 0 or 1" >&2; exit 2 ;;
esac
case "${MASQUE_LOAD_WARM_AUTH:-1}" in
    0|1) ;;
    *) echo "MASQUE_LOAD_WARM_AUTH must be 0 or 1" >&2; exit 2 ;;
esac
if [ "${MASQUE_BENCH_PERF:-0}" = 1 ]; then
    command -v "$PERF_BIN" >/dev/null || { echo "perf is required for sampling" >&2; exit 2; }
    [ -n "$RESULTS_DIR" ] || { echo "MASQUE_BENCH_RESULTS_DIR is required for sampling" >&2; exit 2; }
fi

bash scripts/gen-certs.sh "$BENCH_DIR/certs"

case "${MASQUE_BENCH_VERIFY_TLS:-0}" in
    0) ;;
    1)
        [ "$BENCH_TRANSPORT" = http3 ] || { echo "TLS verification check requires HTTP/3" >&2; exit 2; }
        export MASQUE_BENCH_CA_CERT="$BENCH_DIR/certs/server.crt"
        export MASQUE_SERVER_NAME="${MASQUE_SERVER_NAME:-server}"
        ;;
    *) echo "MASQUE_BENCH_VERIFY_TLS must be 0 or 1" >&2; exit 2 ;;
esac

cat >"$BENCH_DIR/masque.toml" <<EOF
[server]
idle_timeout_secs = 30

[tls]
cert_path = "$BENCH_DIR/certs/server.crt"
key_path = "$BENCH_DIR/certs/server.key"

[quic]
cc_algorithm = "$BENCH_CC"
max_datagram_size = 1350
enable_dgram = true
enable_udp_gso = $QUIC_GSO_TOML
enable_udp_gro = $QUIC_GRO_TOML
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
listen_addr = "127.0.0.1:$SERVER_PORT"
transport = "http3"
shards = $BENCH_SHARDS

[listeners.auth]
enabled = true
mode = "basic"

[[listeners.auth.users]]
username = "test"
password_hash = "\$argon2id\$v=19\$m=19456,t=2,p=1\$1xNVXhqKU7jJ6cqTBJKphQ\$GXXAINVTW1qhloFtN1IR8lSr7pI7QEY79fq4K6d8scQ"
EOF
fi

if [ "$BENCH_TRANSPORT" = http2 ] || [ "$BENCH_TRANSPORT" = both ]; then
    cat >>"$BENCH_DIR/masque.toml" <<EOF

[[listeners]]
listen_addr = "127.0.0.1:$SERVER_PORT"
transport = "http2"
shards = 1

[listeners.auth]
enabled = true
mode = "basic"

[[listeners.auth.users]]
username = "test"
password_hash = "\$argon2id\$v=19\$m=19456,t=2,p=1\$1xNVXhqKU7jJ6cqTBJKphQ\$GXXAINVTW1qhloFtN1IR8lSr7pI7QEY79fq4K6d8scQ"
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

if [ -z "${MASQUE_BENCH_BIN_DIR:-}" ]; then
    cargo build --workspace --release
fi
[ -x "$BIN_DIR/masque-e2e" ] || { echo "missing benchmark client executable" >&2; exit 2; }
[ -x "$SERVER_BIN" ] || { echo "benchmark server is not executable" >&2; exit 2; }
printf 'BENCH_CONFIG transport=%s cc=%s shards=%s quic_gso=%s quic_gro=%s target_gso=%s load_warm_auth=%s\n' \
    "$BENCH_TRANSPORT" "$BENCH_CC" "$BENCH_SHARDS" "$QUIC_GSO_TOML" "$QUIC_GRO_TOML" "$TARGET_GSO_TOML" "${MASQUE_LOAD_WARM_AUTH:-1}"

case "$BENCH_MODE" in
    all|tcp)
        truncate -s "$TCP_DOWNLOAD_BYTES" "$BENCH_DIR/masque-bench.bin"
        python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 --directory "$BENCH_DIR" \
            >"$BENCH_DIR/http.log" 2>&1 &
        HTTP_PID=$!
        # The direct baseline starts immediately and otherwise races Python's
        # HTTP listener on slower hosts.
        python3 - "$HTTP_PORT" <<'PYREADY'
import socket, sys, time
port = int(sys.argv[1])
for attempt in range(100):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
            break
    except OSError:
        time.sleep(0.05)
else:
    raise SystemExit("benchmark HTTP target did not start")
PYREADY
        ;;
esac

case "$BENCH_MODE" in
    all|smoke|udp|load)
        MASQUE_ECHO_SERVER_ADDR="127.0.0.1:$ECHO_PORT" \
        RUST_LOG=warn \
        "$BIN_DIR/masque-e2e" >"$BENCH_DIR/echo.log" 2>&1 &
        ECHO_PID=$!
        ;;
esac

RUST_LOG=warn python3 scripts/bench-process.py \
    --pid-file "$BENCH_DIR/server.pid" --result-file "$BENCH_DIR/server-resource.txt" \
    -- "$SERVER_BIN" --config "$BENCH_DIR/masque.toml" \
    >"$BENCH_DIR/server.log" 2>&1 &
SERVER_JOB_PID=$!
for ((attempt=0; attempt<100; attempt++)); do
    if [ -s "$BENCH_DIR/server.pid" ]; then
        read -r SERVER_PID <"$BENCH_DIR/server.pid" || true
        break
    fi
    if ! kill -0 "$SERVER_JOB_PID" 2>/dev/null; then
        echo "benchmark server failed to launch" >&2
        exit 1
    fi
    sleep 0.05
done
[ -n "$SERVER_PID" ] || { echo "benchmark server launch timed out" >&2; exit 1; }
kill -0 "$SERVER_PID" 2>/dev/null || { echo "benchmark server exited during launch" >&2; exit 1; }
if [ "${MASQUE_BENCH_PERF:-0}" = 1 ]; then
    "$PERF_BIN" record --event "${MASQUE_BENCH_PERF_EVENT:-cpu-clock:u}" -F 99 --call-graph dwarf,8192 \
        -p "$SERVER_PID" -o "$BENCH_DIR/perf.data" >"$BENCH_DIR/perf.log" 2>&1 &
    PERF_PID=$!
fi

case "$BENCH_MODE" in
    all|smoke)
        for transport in $BENCH_TRANSPORTS; do
            MASQUE_AUTH_CHECK=1 \
            MASQUE_BENCH_TRANSPORT="$transport" \
            MASQUE_SERVER_ADDR="127.0.0.1:$SERVER_PORT" \
            ECHO_SERVER_ADDR="127.0.0.1:$ECHO_PORT" \
            RUST_LOG=warn \
            "$BIN_DIR/masque-e2e"

            MASQUE_TCP_CHECK=1 \
            MASQUE_BENCH_TRANSPORT="$transport" \
            MASQUE_SERVER_ADDR="127.0.0.1:$SERVER_PORT" \
            ECHO_SERVER_ADDR="127.0.0.1:$ECHO_PORT" \
            MASQUE_USERNAME=test \
            MASQUE_PASSWORD=test-password \
            RUST_LOG=warn \
            "$BIN_DIR/masque-e2e"

            MASQUE_UDP_CHECK=1 \
            MASQUE_BENCH_TRANSPORT="$transport" \
            MASQUE_SERVER_ADDR="127.0.0.1:$SERVER_PORT" \
            ECHO_SERVER_ADDR="127.0.0.1:$ECHO_PORT" \
            MASQUE_USERNAME=test \
            MASQUE_PASSWORD=test-password \
            RUST_LOG=warn \
            "$BIN_DIR/masque-e2e"

            if [ "$transport" = http3 ]; then
                MASQUE_MIGRATION_CHECK=1 \
                MASQUE_BENCH_TRANSPORT=http3 \
                MASQUE_SERVER_ADDR="127.0.0.1:$SERVER_PORT" \
                ECHO_SERVER_ADDR="127.0.0.1:$ECHO_PORT" \
                MASQUE_USERNAME=test \
                MASQUE_PASSWORD=test-password \
                RUST_LOG=warn \
                "$BIN_DIR/masque-e2e"
            fi
        done
        ;;
esac

case "$BENCH_MODE" in
    all|tcp)
        for transport in $BENCH_TRANSPORTS; do
            MASQUE_TCP_DOWNLOAD=1 \
            MASQUE_BENCH_TRANSPORT="$transport" \
            MASQUE_SERVER_ADDR="127.0.0.1:$SERVER_PORT" \
            MASQUE_TCP_TARGET="127.0.0.1:$HTTP_PORT" \
            MASQUE_TCP_DOWNLOAD_BYTES="$TCP_DOWNLOAD_BYTES" \
            MASQUE_TCP_DOWNLOAD_REPEATS="$TCP_DOWNLOAD_REPEATS" \
            MASQUE_USERNAME=test \
            MASQUE_PASSWORD=test-password \
            RUST_LOG=warn \
            "$BIN_DIR/masque-e2e"
        done
        ;;
esac

case "$BENCH_MODE" in
    all|udp)
        for transport in $BENCH_TRANSPORTS; do
            MASQUE_BENCH=1 \
            MASQUE_BENCH_TRANSPORT="$transport" \
            MASQUE_SERVER_ADDR="127.0.0.1:$SERVER_PORT" \
            ECHO_SERVER_ADDR="127.0.0.1:$ECHO_PORT" \
            MASQUE_USERNAME=test \
            MASQUE_PASSWORD=test-password \
            RUST_LOG=warn \
            "$BIN_DIR/masque-e2e"
        done
        ;;
esac

if [ "$BENCH_MODE" = load ] || {
    [ "$BENCH_MODE" = all ] && [ -n "$LOAD_CONNS" ] && [ "$LOAD_CONNS" != 0 ]
}; then
    if [ "${MASQUE_LOAD_WARM_AUTH:-1}" = 1 ]; then
        MASQUE_UDP_CHECK=1 MASQUE_BENCH_TRANSPORT=http3 \
        MASQUE_SERVER_ADDR="127.0.0.1:$SERVER_PORT" ECHO_SERVER_ADDR="127.0.0.1:$ECHO_PORT" \
        MASQUE_USERNAME=test MASQUE_PASSWORD=test-password RUST_LOG=warn \
        "$BIN_DIR/masque-e2e"
    fi
    MASQUE_LOAD=1 \
    MASQUE_LOAD_CONNS="${LOAD_CONNS:-32}" \
    MASQUE_BENCH_TRANSPORT=http3 \
    MASQUE_SERVER_ADDR="127.0.0.1:$SERVER_PORT" \
    ECHO_SERVER_ADDR="127.0.0.1:$ECHO_PORT" \
    MASQUE_USERNAME=test \
    MASQUE_PASSWORD=test-password \
    RUST_LOG=warn \
    "$BIN_DIR/masque-e2e"
fi

kill -0 "$SERVER_PID" 2>/dev/null || { echo "benchmark server exited during measurement" >&2; exit 1; }
if [ -n "$PERF_PID" ] && ! kill -0 "$PERF_PID" 2>/dev/null; then
    cat "$BENCH_DIR/perf.log" >&2
    echo "perf sampling failed" >&2
    exit 1
fi
