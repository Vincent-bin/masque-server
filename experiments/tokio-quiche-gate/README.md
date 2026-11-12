# tokio-quiche compatibility gate

P1 of the [integration plan](../../docs/tokio-quiche-integration-plan.md).
This is an isolated HTTP/3 driver experiment with a bounded test workload, **not a production
MASQUE backend**. It neither changes the production workspace/lockfile nor
implements authentication, target forwarding or TUN. See the
[implementation evidence](../../docs/tokio-quiche-g0-results.md) before using
its results to make an adoption decision.

## Reproduce

The standalone lockfile pins tokio-quiche 0.23.0, quiche 0.30.1 and BoringSSL
bindings 4.22.0. tokio-quiche default features are disabled; no gcongestion or
deprecated zero-copy feature is enabled. Run from the repository root:

```sh
cargo build --locked --manifest-path experiments/tokio-quiche-gate/Cargo.toml
python3 experiments/tokio-quiche-gate/run.py \
  --binary experiments/tokio-quiche-gate/target/debug/tokio-quiche-gate
```

Every observation is a fresh process with a current-thread Tokio runtime,
one loopback listener and one independent quiche client. Both endpoints live
on the machine running the binary. Every client verifies a fresh synthetic
server certificate for `localhost`. Test identities and raw stderr remain in
private temporary directories and are removed; JSON contains no endpoints,
hostnames, account names, identity paths or raw logs. No service, host route,
firewall, network interface or deployed configuration is changed.

The executable limits each observation to 15 seconds; the runner enforces a
20-second process deadline. Its exit codes are intentional:

- **0:** all selected focused contracts passed. This does not mean G0 or
  production MASQUE compatibility passed.
- **1:** one or more compatibility contracts are blocked. The current stock
  library and prototype patch both produce this result.
- **2:** a harness/build/runtime failure prevented a valid observation.

Use repeated `--case` options for focused runs. `--output report.json` writes
only the sanitized report. The report includes binary SHA-256, target system,
architecture, candidate, debug/release profile and per-case evidence. Reports
from the recorded run are under `results/2026-11-13/`.

## Prototype patches

```sh
python3 experiments/tokio-quiche-gate/prepare.py
cargo build --locked --features upstream-patch \
  --manifest-path experiments/tokio-quiche-gate/target/patched-workspace/Cargo.toml \
  --target-dir experiments/tokio-quiche-gate/target
python3 experiments/tokio-quiche-gate/run.py \
  --binary experiments/tokio-quiche-gate/target/debug/tokio-quiche-gate \
  --socket-build-patch
```

`prepare.py` finds the exact downloaded package versions through Cargo metadata,
checks the original source hashes, and applies the checked-in patches to copies
under `target/`. It never patches the Cargo registry, the production manifest,
or the checked-in lockfiles. Re-running it restores published sources before
applying the same patches. Save a stock binary separately before building the
prototype into the same target directory. `upstream-patch` is only an experiment
feature and requires the prepared workspace; it is not a server Cargo feature.

The protocol patch adds an explicit CID-length contract and opt-in settings
for directional shutdown and DATAGRAM input policy. Defaults retain upstream
shutdown and pre-CONNECT buffering behavior. Another opt-in setting suppresses
per-read body progress events while preserving the audit byte count and FIN
event; this does not bound the remaining event or command queues. It also maps malformed QSID input
to `H3_DATAGRAM_ERROR`. It does **not** fix unbounded event/control queues,
pre-allocation admission, Retry policy, blocked-body FIN, migration or fleet
lifecycle integration. The second patch initializes `msghdr` portably, including
musl's private padding; each new unsafe operation documents its invariant.

These are local feasibility patches, not an accepted upstream release, an
approved production fork, or a complete fix. Source provenance and license
attribution are in [patches/](patches/README.md).

## Linux and release checks

Stock tokio-quiche links on GNU Linux; stock datagram-socket 0.8.1 fails to
compile on x86_64 musl. The prepared compatibility workspace includes the
minimal musl build patch:

```sh
cargo zigbuild --locked --target x86_64-unknown-linux-musl \
  --features upstream-patch \
  --manifest-path experiments/tokio-quiche-gate/target/patched-workspace/Cargo.toml \
  --target-dir experiments/tokio-quiche-gate/target
```

For a stock-protocol musl control, prepare with `--variant socket-only`, use
`target/socket-workspace/Cargo.toml`, and omit `--features upstream-patch`.
Pass `--socket-build-patch` to the runner to record that dependency change.
Cross-compilation is not a substitute for executing the resulting binary on
Linux. The runner can be copied together with the binary to an isolated lab
directory; keep connection details outside the repository and remove that
directory afterwards. Set `TMPDIR` to that directory to contain test artifacts.

Repeat builds and probes with `--release`: the upstream body channel has
capacity 1 in debug and 16 in release. These probes measure observable
correctness, not throughput; they are not the planned LAN performance matrix.

## Contracts

| Cases | What is observed |
| --- | --- |
| `stream_control`, `empty_error` | Independent upload FIN, exact response bytes/status and response FIN |
| `cid16`, `raw_cid16` | Request delivery using the project's CID length through the stock router and public raw interface |
| `shutdown_read`, `shutdown_write` | Whether the opposite stream direction remains usable |
| `native_datagram_control` | Successful native round trip with exactly one QSID prefix and preserved Context ID |
| `unknown_flow` | Whether a pre-CONNECT datagram is replayed after headers |
| `late_datagram` | DATAGRAM after delivered request FIN; response output must remain usable |
| `blocked_body_fin` | Full body channel, terminal body/FIN behind it, then native input; the driver-side readable barrier avoids relying on an arbitrary sleep |
| `qsid_empty`, `qsid_truncated`, `qsid_out_of_range` | Application close code observed by the independent peer within three seconds |
| `event_backlog` | Event receiver paused while a body consumer reads 512 bounded chunks; queue length, audit byte count, and FIN notification after resuming |
| `retry_privacy` | Whether the observed Retry token exposes the synthetic source address |
| `tls_hook` | Prebuilt custom TLS context actually used, with the client verifying the server certificate |
| `raw_worker_shutdown` | The raw API's worker completion notification after peer close |

Arrival/control barriers run through the driver or its QUIC owner. No test
deliberately drives the host to OOM: event backlog uses only 32 KiB of payload.
Raw-mode routing is intentionally limited to one connection; it is not a
production replacement for admission, adaptive Retry, CID rotation or path
migration. A successful TLS hook test does not cover roster, reload, tickets,
client-certificate authentication or 0-RTT. A completed raw worker does not prove
that the standard listener has a supervisable lifecycle.

## Static checks

```sh
cargo fmt --manifest-path experiments/tokio-quiche-gate/Cargo.toml --check
cargo clippy --locked --all-targets \
  --manifest-path experiments/tokio-quiche-gate/Cargo.toml -- -D warnings
cargo audit --file experiments/tokio-quiche-gate/Cargo.lock
cargo deny --manifest-path experiments/tokio-quiche-gate/Cargo.toml \
  --locked check licenses sources bans
```

Dependency findings are reported without weakening the production policy.
The ordinary workspace checks remain separate: they do not discover this
isolated crate and cannot establish that the new driver is compatible.
