# HTTP/3 multi-tunnel UDP scheduling investigation

## Decision

Keep production UDP scheduling unchanged. The per-datagram linear
`staged_udp_tunnels.contains()` in `relay_client_datagrams` remains a plausible
micro-optimization target, but these measurements do not establish that it is
a material bottleneck. No production hot-path variant was implemented or
qualified from these results.

At saturation, 64 active tunnels had similar median throughput to one tunnel,
with roughly 9–12% higher server CPU per successful echo. At a fixed aggregate
30,000 packets/s, the CPU increase was roughly 2–4%. Having 64 open tunnels
but only one active did not show a consistent throughput penalty. The
1200-byte saturation samples varied substantially, including overlapping
ranges. This is evidence about complete tunnel topologies, not attribution to
the membership scan: spreading traffic also changes per-socket send batching,
receive task wakeups, channel batches, and scheduler behavior.

## Method

The baseline was main commit `63d746f12b26b9127df3e8f850d37d161be68afe`
(v0.14.8), built with Rust 1.97.1 and the existing fat-LTO release profile.
The Linux x86_64 sandbox exposed nine logical CPUs to affinity; host CPU
quotas were not available. Client, server, and target shared this sandbox.
Server processes were pinned to CPUs 0–1, the client to CPU 2, and the echo
target to CPU 3. Other coordinated builds and performance runs were stopped.
This does not exclude unrelated host contention or sandbox overhead.

Every case used one HTTP/3 connection, one server shard, CUBIC, verified TLS,
synthetic Basic authentication, QUIC and target GSO disabled, and QUIC GRO
enabled. Socket receive/send buffers requested 2 MiB each; effective kernel
buffer values were not independently checked. The cases were:

- one open, one active tunnel;
- 64 open tunnels, only the first active; and
- 64 open, 64 active tunnels, with round-robin requests.

The aggregate window stayed at 256 outstanding requests per connection,
expiry at one second, and traffic duration at five seconds. Payloads were
64 and 1200 bytes. Both saturation and a fixed aggregate target of 30,000
packets/s were measured. All 36 cases completed without setup or runtime
failures. Each result below is the median of three repetitions; the entire
case order was reversed in the second repetition. Ranges are individual-run
minima/maxima, not confidence intervals.

CPU was the server process's user plus system ticks from `/proc/<pid>/stat`,
read by a separate collector when it consumed the flushed `LOAD_PHASE`
start/end records. Resolution was 10 ms. The start is after every tunnel
setup, immediately before the shared start barrier; the end is after all
workers have finished draining. Saturation drain phases extended wall time
to about 5.8–6 seconds. CPU per echo includes that drain but excludes setup,
authentication warmup, the direct controls, and shutdown. Marker-consumption
latency adds a small unbounded scheduling error. The ordinary whole-process
`SERVER_RESOURCE_RESULT` was not used to calculate these CPU costs.

Completed echoes are divided by the five-second sending interval, as in the
existing load harness. Shortfall includes expired requests and is not a
measurement of wire loss. RTT values are histogram upper bounds, not exact
percentiles or unloaded latency.

## Saturating results

| Payload | Open / active streams | Echo pps, median (range) | Server CPU µs / echo | Shortfall % | Loaded p95 upper bound µs |
| --- | --- | ---: | ---: | ---: | ---: |
| 64 B | 1 / 1 | 344,402 (322,597–346,593) | 4.42 | 0.0169 | 960 |
| 64 B | 64 / 1 | 342,951 (326,026–373,964) | 4.47 | 0.0155 | 960 |
| 64 B | 64 / 64 | 350,394 (328,669–358,055) | 4.82 | 0.0113 | 1,152 |
| 1200 B | 1 / 1 | 107,025 (102,847–129,296) | 11.49 | 0.1595 | 2,048 |
| 1200 B | 64 / 1 | 121,587 (110,263–127,182) | 10.84 | 0.1357 | 1,792 |
| 1200 B | 64 / 64 | 107,824 (86,087–116,335) | 12.89 | 0.1250 | 2,560 |

## Fixed aggregate rate results

| Payload | Open / active streams | Echo pps, median (range) | Server CPU µs / echo | Shortfall % | Loaded p95 upper bound µs |
| --- | --- | ---: | ---: | ---: | ---: |
| 64 B | 1 / 1 | 30,000 (30,000–30,000) | 38.00 | 0.0000 | 208 |
| 64 B | 64 / 1 | 30,000 (29,995–30,000) | 39.67 | 0.0000 | 208 |
| 64 B | 64 / 64 | 30,000 (29,999–30,000) | 39.67 | 0.0000 | 248 |
| 1200 B | 1 / 1 | 29,988 (29,956–29,990) | 39.21 | 0.0413 | 320 |
| 1200 B | 64 / 1 | 29,994 (29,982–29,998) | 39.67 | 0.0187 | 352 |
| 1200 B | 64 / 64 | 29,987 (29,983–30,000) | 40.08 | 0.0427 | 320 |

The observed sent rates were close to the requested 30,000 packets/s. Compare
CPU only within a given offered-load regime: paced single-packet traffic has
very different batching and wakeup costs from saturation.

## Direct controls and limits

Three subsequent direct UDP controls used the same client/echo CPU placement,
window, expiry, payloads, and three-second sending intervals. Median direct
rates were 574,485 pps at 64 bytes (552,785–589,634) and 527,456 pps at
1200 bytes (506,302–529,129). Median shortfalls were 0.0110% and 0.0354%.
These controls establish substantial local target headroom, but ran after the
matrix rather than interleaved with it and cannot rule out time drift.

No server sampling profile, instrumented membership-scan timing, or scheduler
A/B variant was run. No external network, multi-shard scaling, HTTP/2
multi-stream performance, privileged Docker/TUN E2E, or production setting
was evaluated. Before keeping a membership-marking or scratch-buffer change,
run an isolated A/B with the same benchmark client and topology, retain the
idle-tunnel control, and compare CPU per echo, throughput, shortfall, and
loaded latency. Do not infer a specific-code speedup from a topology change.

## Reproduction

The HTTP/3 load harness now supports bounded opened/active stream counts and
an aggregate per-connection target rate, while retaining the same packet
engine, window, expiry, and response validation as the one-stream benchmark.
See [Testing](testing.md#network-benchmark) for all controls. For one case:

```sh
MASQUE_BENCH_MODE=load MASQUE_BENCH_TRANSPORT=http3 \
MASQUE_BENCH_SHARDS=1 MASQUE_LOAD_CONNS=1 \
MASQUE_LOAD_STREAMS_PER_CONN=64 \
MASQUE_LOAD_ACTIVE_STREAMS_PER_CONN=64 \
MASQUE_LOAD_PPS_PER_CONN=30000 \
MASQUE_LOAD_PAYLOAD=64 MASQUE_LOAD_WINDOW=256 \
MASQUE_LOAD_EXPIRY_MS=1000 MASQUE_LOAD_DURATION_SECS=5 \
MASQUE_BENCH_VERIFY_TLS=1 MASQUE_BENCH_QUIC_GSO=0 \
MASQUE_BENCH_TARGET_GSO=0 MASQUE_BENCH_QUIC_GRO=1 \
MASQUE_BENCH_UDP_RECV_BUFFER_SIZE=2097152 \
MASQUE_BENCH_UDP_SEND_BUFFER_SIZE=2097152 \
scripts/network-bench.sh
```

Use the same already-built release client/server binaries for every case,
apply process CPU affinity consistently, and do not compile during timing.
The command alone does not apply affinity or collect phase CPU: a collector
must sample the actual server PID around `LOAD_PHASE` as described above.
Set PPS to 0 for saturation, and repeat with open/active counts 1/1, 64/1,
and 64/64. Keep the aggregate window fixed rather than multiplying it by the
number of tunnels.
