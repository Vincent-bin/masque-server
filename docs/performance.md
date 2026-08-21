# Performance

## What is measured

Performance results must distinguish:

- direct UDP echo capacity;
- CONNECT-UDP payload packet rate and payload bit rate;
- standard CONNECT byte throughput;
- connection setup rate and per-connection latency;
- RTT percentiles;
- server and client CPU; and
- loss or expired requests.

Payload bit rate excludes QUIC, UDP, IP, Ethernet, TLS, and proxy framing. A
1200-byte payload can show fewer packets per second than a 64-byte payload yet
carry much more useful bandwidth. Always report both pps and Gbit/s.

## HTTP/2 compatibility path

HTTP/2 standard CONNECT uses H2 DATA frames with explicit flow-control
backpressure in both directions. CONNECT-UDP and CONNECT-IP place each HTTP
Datagram payload inside a DATAGRAM capsule carried by DATA frames. That makes
loss recoverable and ordered by the outer TCP connection; it also introduces
head-of-line blocking and nested loss recovery that HTTP/3 DATAGRAM avoids.
Treat HTTP/2 as a reachability fallback, not as a replacement for HTTP/3 in
performance comparisons.

The current network benchmark drives HTTP/3. HTTP/2 is covered by real TLS/H2
relay integration tests, but no HTTP/2 throughput number should be compared to
the network benchmark until the same harness can drive both transports with
the same targets, payloads, windows, and CPU placement.

## Linux fast paths

### QUIC socket

The Linux adapter drains packets with `recvmmsg`, optionally receives GRO
aggregates, and restores logical QUIC packet boundaries. Output is grouped by
destination and segment size. With UDP GSO, one message contains multiple
segments; `sendmmsg` submits multiple messages in one kernel entry.

The batch is constrained by quiche's `send_quantum()` and pacing metadata.
Batching never sends a packet before the time supplied by quiche.

### Target UDP sockets

Client bursts are staged per tunnel during one shard iteration and submitted
with a direct `SYS_sendmmsg`. Target responses are drained with
`SYS_recvmmsg`. On non-Linux systems, Tokio sends and receives individual
datagrams. When `udp_proxy.enable_udp_gso = true`, equal-sized large client
payloads are submitted as scatter/gather segments of one UDP super-packet,
avoiding a userspace concatenation copy. Small payloads remain on `sendmmsg`;
an explicit kernel error disables GSO on that tunnel and retries through
`sendmmsg`.

Static releases use musl. Its public 64-bit `sendmmsg` wrapper loops through
`sendmsg` to handle ABI differences, so both Linux send adapters deliberately
use the raw kernel syscall with zero-initialized ABI-compatible storage. A GNU
build is therefore not required to retain batching.

### TCP relay

Target readers hand 64 KiB `Bytes` chunks to the owning shard under a 256 KiB
per-tunnel credit. A shard consumes a bounded group of events that are already
queued, places all accepted chunks into HTTP/3, and then drives the QUIC
connection once. This keeps the existing memory ceiling while avoiding a full
event-loop and QUIC-drive round for every individual read. The exported TCP
relay event/batch counters reveal the effective coalescing factor.

### TUN

When `tun_offload = true` and the kernel accepts `IFF_VNET_HDR`, TUN reads and
writes carry GSO aggregates with virtio metadata. The server falls back to
ordinary packets if setup is rejected.

## Tuning order

Change one dimension at a time:

1. Establish the direct echo or `iperf3` baseline.
2. Confirm one-shard throughput and CPU.
3. Verify `sendmmsg`/`recvmmsg` are active.
4. A/B test UDP GSO across the real external path.
5. Raise shards only when one event-loop core is saturated and traffic has
   multiple connections.
6. Adjust flow-control windows for measured bandwidth-delay product.
7. Adjust datagram queues only after observing burst loss or excess latency.

Important settings:

| Setting | Effect |
| --- | --- |
| `listeners[].shards` | Aggregate multi-connection CPU parallelism for that listener |
| `http2.initial_*_window` | HTTP/2 initial bandwidth-delay credit |
| `http2.max_concurrent_streams` | HTTP/2 per-connection stream concurrency |
| `http2.max_send_buffer_size` | HTTP/2 buffered response bound per stream |
| `http2.data_frame_budget` | Small DATA-frame burst tolerance versus per-connection memory-abuse bound |
| `http2.max_datagram_size` | HTTP/2 CONNECT-UDP payload / CONNECT-IP packet ceiling |
| `quic.enable_udp_gso` | QUIC send syscall and per-packet overhead |
| `quic.enable_udp_gro` | QUIC receive syscall overhead |
| `udp_proxy.enable_udp_gso` | Client-to-target UDP kernel overhead |
| `quic.max_datagram_size` | Packet size and PMTU ceiling |
| `quic.initial_max_*` | Initial bandwidth-delay window |
| `quic.max_*_window` | Autotuning ceiling and memory bound |
| `quic.dgram_*_queue_len` | Burst loss versus memory/latency |
| `quic.cc_algorithm` | Congestion response and pacing behavior |

GSO remains disabled by default because support reported by a virtual NIC does
not guarantee that every overlay or provider egress path preserves the
super-packet correctly.

## Local benchmark

```sh
scripts/network-bench.sh
```

Useful controls include:

```sh
MASQUE_BENCH_MODE=udp \
MASQUE_BENCH_DURATION_SECS=10 \
MASQUE_BENCH_WINDOW=256 \
MASQUE_BENCH_EXPIRY_MS=1000 \
MASQUE_BENCH_RTT_SAMPLES=100 \
MASQUE_BENCH_QUIC_GSO=0 \
MASQUE_BENCH_TARGET_GSO=1 \
MASQUE_TCP_DOWNLOAD_BYTES=536870912 \
MASQUE_TCP_DOWNLOAD_REPEATS=3 \
scripts/network-bench.sh
```

`MASQUE_BENCH_MODE` accepts `all` (the default), `smoke`, `tcp`, `udp`, or
`load`. Focused modes still build the release workspace and start only the
supporting processes needed by that measurement. `MASQUE_BENCH_SHARDS`
selects the listener shard count; `0` retains the server's documented
one-shard-per-core behavior.

For a repeatable multi-connection run:

```sh
MASQUE_BENCH_MODE=load \
MASQUE_BENCH_SHARDS=1 \
MASQUE_LOAD_CONNS=2 \
MASQUE_LOAD_DURATION_SECS=30 \
MASQUE_LOAD_PAYLOAD=1200 \
MASQUE_LOAD_WINDOW=256 \
MASQUE_LOAD_EXPIRY_MS=1000 \
scripts/network-bench.sh
```

The final `LOAD_RESULT` line is intended for scripts. It includes requested
and established connections, packet counts and rates, application goodput,
bidirectional relay rate, response shortfall, expired packets, and setup and
runtime failure counts. A non-zero worker failure makes the command fail after
printing the record.

Use `MASQUE_BENCH_QUIC_GSO=0|1` for the outer QUIC socket and
`MASQUE_BENCH_TARGET_GSO=0|1` for CONNECT-UDP target egress; both default to
`0`. Test them separately so a result can be attributed to one egress path. Set
`MASQUE_BENCH_OBSERVABILITY=1` to enable the loopback endpoint and metric
updates during an A/B run; the default `0` measures the uninstrumented packet
path.

CONNECT-TCP alternates a direct origin download with each proxy sample by
default, then prints the median throughput and proxy/direct ratio. Set
`MASQUE_TCP_DIRECT_BASELINE=0` only when the benchmark host intentionally
cannot reach the target directly.

A loopback GSO gain is evidence of reduced local kernel work, not evidence that
a virtual NIC or provider overlay handles the same super-packets efficiently.
The effective GSO/GRO gauges confirm socket setup, but only an alternating
external-path test can qualify a deployment. Keep GSO disabled when external
throughput is flat, regresses, or varies too much to separate from the direct
baseline.

The expiry interval must exceed network RTT plus expected queueing. Otherwise
the load generator spends its window on requests it has already classified as
expired and the result measures the benchmark harness rather than the server.

For connection load tests, each worker records its own setup duration. Report
batch wall-clock throughput as connections per second, and report individual
average/p50/p95/p99 latency separately. Dividing concurrent batch duration by
connection count is not connection latency.

The load generator uses one native thread per connection. When the objective
is a single-shard server ceiling, give the client enough independent CPU cores
that it cannot become the first saturated endpoint, and keep the target echo
process on another core. Pinning a single client and the server to one core
each can produce a client ceiling that looks like a server result. Always
record `response_shortfall_pct`; higher offered load is not an improvement if
fewer responses complete.

## Linux verification

During a controlled run:

```sh
sudo strace -f -c -e trace=sendmmsg,sendmsg,recvmmsg \
  -p "$(pidof masque-server)"
```

The musl binary should show `sendmmsg` and `recvmmsg` on active UDP paths.
Tracing perturbs performance; use it to verify behavior, then benchmark again
without tracing. For CPU attribution, prefer `perf record` or a sampled flame
graph over conclusions drawn from aggregate process CPU alone.

## Reporting results

Record at minimum:

- exact commit and release profile;
- musl or GNU target;
- kernel, CPU, NIC or VPS type, and vCPU count;
- client/server placement and RTT;
- payload size, connection count, duration, and in-flight window;
- shards, congestion controller, GSO/GRO, and MTU settings;
- pps, payload Gbit/s, RTT percentiles, loss, and CPU; and
- at least three runs with variability.

Do not compare a loopback run, a cross-region run, and a provider-limited VPS
as if they isolate server implementation cost.
