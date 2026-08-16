# Testing

## Validation matrix

| Layer | Command | Purpose |
| --- | --- | --- |
| Formatting | `cargo fmt --all --check` | Stable source formatting |
| Static analysis | `cargo clippy --workspace --all-targets --locked -- -D warnings` | Rust correctness and maintainability |
| MSRV | `cargo +1.88.0 check --workspace --locked` | Declared minimum compiler support |
| Unit/integration | `cargo test --workspace --locked` | Codecs, policy, config, scheduling, tunnels |
| Release tests | `cargo test --workspace --release --locked` | Optimized-profile behavior |
| Microbenchmark | `cargo bench --bench core` | Codec, routing, and allocation regressions |
| Network benchmark | `scripts/network-bench.sh` | Local direct-vs-MASQUE throughput and RTT |
| Docker E2E | `scripts/e2e-test.sh` | TCP, UDP, IP/TUN, and container networking |
| Linux package | `scripts/package-linux.sh` | Artifact layout and static binary build |

## Local tests

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo +1.88.0 check --workspace --locked
cargo test --workspace --locked
```

macOS covers portable CONNECT, CONNECT-UDP, authentication, protocol codecs,
and scheduling. It does not validate Linux `recvmmsg`/`sendmmsg`, GSO/GRO,
`SO_REUSEPORT`, TUN offload, capabilities, or systemd.

## Docker E2E

```sh
scripts/e2e-test.sh
```

The script creates development certificates, builds the server and E2E client,
starts an echo target, grants the server container `NET_ADMIN` and TUN access,
runs the suite, and removes the Compose network and volumes.

Failures should retain enough logs for diagnosis but must not print production
credentials or certificates.

## Network benchmark

```sh
scripts/network-bench.sh
```

Run several repetitions and preserve the direct UDP baseline. When changing
batching, readiness, pacing, flow control, or buffers, test both 64-byte and
1200-byte payloads. Use multiple connections for shard tests.

See [Performance](performance.md) for methodology and reporting requirements.

## Linux-specific checks

A release candidate is not complete until an x86_64 Linux host verifies:

1. the musl archive installs and starts through systemd;
2. authentication accepts correct credentials and rejects missing/wrong ones;
3. standard CONNECT and CONNECT-UDP work through a real client;
4. `sendmmsg` and `recvmmsg` appear under traffic;
5. UDP GSO on/off behavior is tested across the external path;
6. single- and multi-shard modes pass concurrent traffic; and
7. memory and CPU remain bounded under invalid authentication load.

For target datagram sizing, raise `quic.max_datagram_size` above 2048 in a test
configuration and verify oversized responses are rejected rather than silently
truncated.

## Release checklist

- Update `CHANGELOG.md` and package version.
- Run formatting, Clippy with warnings denied, and release tests.
- Build `x86_64-unknown-linux-musl` with the same command used by CI.
- Extract the archive into a temporary directory and inspect permissions and
  paths.
- Verify `masque-server --help` and `hash-password` from the packaged binary.
- Install on a disposable Linux host and run a client smoke test.
- Tag only the commit that passed these checks.

Tags containing a hyphen are published as GitHub pre-releases.
