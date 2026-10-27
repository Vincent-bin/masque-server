#!/usr/bin/env bash
# Isolate the two GSO switches; alternate order to reduce order bias.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."

ROUNDS="${MASQUE_GSO_ROUNDS:-3}"
case "$ROUNDS" in
    [1-9]) ;;
    *) echo "MASQUE_GSO_ROUNDS must be between 1 and 9" >&2; exit 2 ;;
esac
RESULTS="${MASQUE_GSO_RESULTS_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/masque-gso-bench.XXXXXX")}"
mkdir -p "$RESULTS"
if [ -z "${MASQUE_BENCH_BIN_DIR:-}" ]; then
    cargo build --workspace --release
fi
BIN_DIR="${MASQUE_BENCH_BIN_DIR:-target/release}"
for ((round=1; round<=ROUNDS; round++)); do
    if ((round % 2)); then
        CASES="off quic target both"
    else
        CASES="both target quic off"
    fi
    for name in $CASES; do
        quic=0; target=0
        case "$name" in
            quic) quic=1 ;;
            target) target=1 ;;
            both) quic=1; target=1 ;;
        esac
        run="$RESULTS/$round-$name"
        # Refuse to mix old and new measurements in one case directory.
        mkdir "$run"
        MASQUE_BENCH_BIN_DIR="$BIN_DIR" \
        MASQUE_BENCH_MODE="${MASQUE_BENCH_MODE:-udp}" \
        MASQUE_BENCH_TRANSPORT=http3 \
        MASQUE_BENCH_QUIC_GSO="$quic" MASQUE_BENCH_TARGET_GSO="$target" \
        MASQUE_BENCH_RESULTS_DIR="$run" \
            bash scripts/network-bench.sh 2>&1 | tee "$run/output.log"
    done
done
printf 'GSO results: %s\n' "$RESULTS"
