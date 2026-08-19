#!/usr/bin/env sh
# Exercise the production stop signal against a real server. Linux uses two
# shards to prove the process-wide broadcast; platforms without SO_REUSEPORT
# use one. The GitHub Linux runner is not booted with systemd as PID 1, so
# sending the unit's configured KillSignal is the closest test of the
# service-manager boundary.
set -eu

die() {
    echo "systemd shutdown test: $*" >&2
    exit 1
}

case "$(uname -s)" in
    Linux) EXPECTED_SHARDS=2 ;;
    Darwin) EXPECTED_SHARDS=1 ;;
    *) die "unsupported test platform" ;;
esac

CANDIDATE=${MASQUE_TEST_BIN:-target/debug/masque-server}
[ -x "$CANDIDATE" ] || die "MASQUE_TEST_BIN must name an executable"

grep -q '^KillSignal=SIGTERM$' deploy/systemd/masque.service ||
    die "the systemd unit does not send SIGTERM"
grep -q '^TimeoutStopSec=10s$' deploy/systemd/masque.service ||
    die "the systemd unit does not leave time for the bounded drain"

TEST_TMP=$(mktemp -d /tmp/masque-systemd-shutdown.XXXXXX)
SERVER_PID=

cleanup() {
    cleanup_status=$?
    trap - EXIT
    set +e
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -KILL "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
    fi
    rm -rf -- "$TEST_TMP"
    exit "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -days 1 -subj /CN=localhost \
    -keyout "$TEST_TMP/server.key" \
    -out "$TEST_TMP/server.crt" >/dev/null 2>&1

cat >"$TEST_TMP/masque.toml" <<EOF
[tls]
cert_path = "$TEST_TMP/server.crt"
key_path = "$TEST_TMP/server.key"

[ip_proxy]
enabled = false

[[listeners]]
listen_addr = "127.0.0.1:0"
shards = $EXPECTED_SHARDS

[listeners.auth]
enabled = false
EOF

run_signal_case() {
    signal=$1
    log=$TEST_TMP/$signal.log

    RUST_LOG=masque=debug "$CANDIDATE" --config "$TEST_TMP/masque.toml" \
        >"$log" 2>&1 &
    SERVER_PID=$!

    attempts=0
    until grep -q 'shutdown signal handlers installed' "$log"; do
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            wait "$SERVER_PID" || true
            SERVER_PID=
            sed -n '1,200p' "$log" >&2
            die "server exited before installing signal handlers"
        fi
        attempts=$((attempts + 1))
        [ "$attempts" -lt 100 ] || die "server did not become ready"
        sleep 0.1
    done

    kill "-$signal" "$SERVER_PID"

    attempts=0
    while kill -0 "$SERVER_PID" 2>/dev/null; do
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 100 ]; then
            sed -n '1,200p' "$log" >&2
            die "server did not exit after $signal"
        fi
        sleep 0.1
    done

    if wait "$SERVER_PID"; then
        status=0
    else
        status=$?
    fi
    SERVER_PID=
    [ "$status" -eq 0 ] || {
        sed -n '1,200p' "$log" >&2
        die "server exited with status $status after $signal"
    }

    grep -q "$signal" "$log" || die "the central listener did not report $signal"
    [ "$(grep -c 'shutdown signal received, draining shards' "$log")" -eq 1 ] ||
        die "$signal did not start exactly one global shutdown"
    [ "$(grep -c 'shard draining connections' "$log")" -eq "$EXPECTED_SHARDS" ] ||
        die "$signal did not reach all $EXPECTED_SHARDS shards"
    [ "$(grep -c 'all connections drained, exiting' "$log")" -eq "$EXPECTED_SHARDS" ] ||
        die "all $EXPECTED_SHARDS shards did not complete their drain after $signal"
}

run_signal_case TERM
run_signal_case INT

echo "SIGTERM and SIGINT drained every shard cleanly"
