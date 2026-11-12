# Raw QUIC comparison

This isolated experiment compares **quiche 0.30.0** with **Quinn 0.11.12**,
without HTTP/3, MASQUE, authentication admission, DNS, target sockets, or TUN.
It does not change the production workspace or its dependency lockfile.
See the [measured results and limitations](../../docs/performance-quic-comparison.md).

## Workloads and controls

- One connection, one single-thread Tokio runtime per process, release + fat LTO.
- QUIC v1, CUBIC, initial congestion window 10 × 1350 bytes, fixed 1350-byte
  packet ceiling, PMTUD disabled, no Retry or 0-RTT.
- AES-128-GCM: Rustls advertises only this suite; quiche checks the negotiated
  suite through BoringSSL's handshake callback and fails on a mismatch.
- Fresh ECDSA P-256 test identity; clients verify the test certificate and the
  synthetic `localhost` name. No production credentials or certificates.
- Both socket adapters use ordinary UDP syscalls, without GSO/GRO or ECN.
  Quinn uses a deliberately minimal `AsyncUdpSocket`; quiche uses a bounded
  event loop that drives receives, QUIC deadlines, and paced sends.
- Request 2 MiB socket buffers and record the actual sizes. Linux reports
  doubled sizes, so compare implementations **within a topology**, not raw
  macOS-versus-Linux buffer values.
- Connection/stream receive windows are 16 MiB; QUIC datagram queues are
  bounded (quiche: 2048 packets; Quinn: 2048 × 1350 bytes). The application
  permits only 256 outstanding requests, below both queue limits.
- DATAGRAM echo: 64- and 1200-byte payloads, 256 outstanding requests,
  250 ms request expiry, five seconds of offered load, bounded final drain.
  Multiple small application DATAGRAM frames may share one QUIC packet.
- Low-load RTT: 64 bytes, one outstanding request, target 100 requests/s.
  Report actual achieved rate; OS timer granularity may make it lower.
- Reliable stream: request a 256 MiB download using eight request bytes on
  bidirectional stream 0. Read/write application buffers are 64 KiB. Verify
  total bytes and FIN. This is a fresh-connection transfer, not a warmed
  congestion-window measurement.
- Run all four client/server library combinations. Reverse their order on
  alternating repetitions; report three repetitions individually and medians.

DATAGRAM goodput is matched, unexpired echo payload divided by the offered-load
duration; it excludes all headers and counts an echo once, although the network
carries both request and reply. `shortfall` includes expiry and loss anywhere
in the path; it is not a NIC drop counter. RTT quantiles cover successful
requests only. Stream timing starts after handshake, just before requesting
the response, and ends on response FIN. Process CPU includes initialization,
handshake and shutdown; it is reported separately for the client and server.

## Run

```sh
cargo build --release --locked --manifest-path experiments/quic-compare/Cargo.toml
cargo clippy --locked --all-targets --manifest-path experiments/quic-compare/Cargo.toml -- -D warnings
python3 experiments/quic-compare/run.py --smoke
python3 experiments/quic-compare/run.py --repeats 3 --seconds 5
```

The runner stores raw logs and short-lived certificates in a private temporary
directory outside the repository. `results.jsonl` contains only numerical
results, library names and generic topology names. Never copy raw logs,
private connection configuration, or certificates into a report or commit.

For a Linux test peer, cross-compile with the repository's existing build tools:

```sh
cargo zigbuild --release --locked --target x86_64-unknown-linux-musl \
  --manifest-path experiments/quic-compare/Cargo.toml
```

Create a private JSON file **outside this repository** with `ssh_target`,
`linux_address`, `mac_address`, and an isolated `/tmp/quic-compare-*`
`remote_dir`. SSH handles authentication; the runner never stores a password.
Use `--remote-config <private-file> --topology <topology>` with `linux-local`,
`mac-linux`, or `linux-mac`. The first component is the client location.
The runner copies only its binary and test identity to a unique subdirectory;
it does not install software, change services, configure firewalls, or alter
host network settings. Remove the experiment's temporary directories and
test credentials after collecting sanitized numerical results.

Each executable is bounded to 90 seconds, and remote invocations have an
additional 95-second timeout. A failed SSH session can leave the remote
experiment running until that timeout; wait for it before subsequent timed
runs. Do not run timed experiments concurrently with compilation or other
load tests on either participating machine.

For a focused follow-up, select `--case stream`, `--server-backend quinn`,
`--client-backend quinn` and `--repeats 10`. `--keep-going` records failed attempts in
`failures.jsonl` and continues the selected matrix, but still exits nonzero
if any attempt failed. Do not replace failed observations with successful
retries when reporting the original matrix.

## Interpretation limits

This compares the libraries **plus the supplied drivers and crypto providers**
(BoringSSL versus Rustls/ring). It is not a benchmark of isolated QUIC state
machine instructions. Neither the production server's batching, pacing horizon,
BBR2, reusable TCP buffers and shard routing nor Quinn's native UDP offload
adapter are represented. A result here cannot establish the performance of a
future MASQUE migration. Single-connection results also do not establish
multi-connection scalability, long-RTT/loss behavior, or Internet performance.

The `h3` compatibility, certificate roster, reload, migration admission and
configuration checks in the architecture proposal remain separate gates.
