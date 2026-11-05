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

The network benchmark drives either transport with the same direct targets,
credentials, payload sizes, windows, expiry rules, and result fields. Use
`MASQUE_BENCH_TRANSPORT=both` to run HTTP/3 and HTTP/2 sequentially against two
listeners sharing one numeric address. It still does not make the transports
semantically identical: HTTP/2 DATAGRAM capsules are reliable and ordered,
while HTTP/3 DATAGRAM frames are not. Compare reachability cost, application
goodput, CPU, latency, and response shortfall rather than treating the result as
a claim that the wire protocols have equal behavior.

HTTP/2 sends small DATA frames with `TCP_NODELAY`. The CONNECT-UDP
response path combines already queued datagrams into a bounded group of
capsules before handing them to H2 flow control. It sends when the batch limit
is reached or no more packets are ready, without waiting for more packets.

An alternating Linux loopback run used the same release benchmark client,
a window of 256, and three seconds per payload. Medians from three runs per
variant:

| Server variant | 64 B (pps) | 1200 B (pps) | Unloaded 64 B p99 (µs) | CPU time per echo (µs) |
| --- | ---: | ---: | ---: | ---: |
| v0.14.4 baseline | 136,906 | 82,847 | 262 | 8.31 |
| TCP_NODELAY only | 253,502 | 63,260 | 326 | 7.89 |
| TCP_NODELAY and capsule batching | 245,521 | 131,860 | 324 | 6.58 |

The combined variant reduced response shortfall from 0.056% to 0.033% at
64 bytes and from 0.199% to 0.131% at 1200 bytes. Total measured server CPU
time rose from 5.47 s to 7.46 s as the server handled more packets. CPU time
per echo is the whole-run CPU time divided by echoes across both payloads,
including setup costs. A batching-only variant regressed sharply at 64 bytes
and was discarded. The unloaded p99 comes from 50 probes per run and does
not establish tail latency under load.

## Linux fast paths

### QUIC socket

See the [GSO and socket-buffer verification report](performance-gso-buffers.md)
for local and external-path measurements, including their limits.

QUIC socket buffers can be tuned independently with
`quic.udp_recv_buffer_size` and `quic.udp_send_buffer_size`. They default to
zero when omitted, preserving OS defaults; the fresh-install template requests
2 MiB each. Both settings apply per shard on restart. Start a controlled
buffer-size experiment at 2 MiB each; verify the actual values in startup logs
or `masque_quic_udp_socket_buffer_bytes`. A larger `net.core.rmem_max` or
`net.core.wmem_max` only raises the Linux request ceiling; it does not enlarge
existing sockets or make an application request more buffer. Linux normally
reports twice the accepted `SO_RCVBUF` / `SO_SNDBUF` request. Keep host defaults
unchanged when using these per-socket settings.

Compare GSO with the same effective buffers, warmup, traffic, and client.
Record listener socket-drop deltas and host UDP `RcvbufErrors` /
`SndbufErrors` deltas during each measurement. Host counters include other
UDP sockets, and cumulative totals cannot establish loss in the test window.
Buffering may absorb bursts, but does not prove an external path can carry
GSO traffic or guarantee higher throughput.

The local harness accepts `MASQUE_BENCH_UDP_RECV_BUFFER_SIZE` and
`MASQUE_BENCH_UDP_SEND_BUFFER_SIZE` in bytes. Unset variables omit the new
fields so the same harness still works with older server binaries. For example:

```sh
MASQUE_BENCH_MODE=udp MASQUE_BENCH_TRANSPORT=http3 \
MASQUE_BENCH_QUIC_GSO=1 \
MASQUE_BENCH_UDP_RECV_BUFFER_SIZE=2097152 \
MASQUE_BENCH_UDP_SEND_BUFFER_SIZE=2097152 \
scripts/network-bench.sh
```

The Linux adapter drains packets with `recvmmsg`, optionally receives GRO
aggregates, and restores logical QUIC packet boundaries. Output is grouped by
destination and segment size. With UDP GSO, one message contains multiple
segments; `sendmmsg` submits multiple messages in one kernel entry.

The batch is constrained by quiche's `send_quantum()` and pacing metadata.
To account for millisecond timer resolution, packets may be sent up to 1 ms
before the time supplied by quiche. This trades a bounded burst for fewer timer
wakeups; it is not kernel-precision pacing.

Paced output retains at most 64 packets and 128 KiB of payload per connection.
The event loop wakes for the first queued deadline and releases packets through
one millisecond beyond the current time. Prefetch is bounded to roughly that
window, with one extra packet retained for the next deadline. The queue reuses packet buffers under a separate 128 KiB spare-buffer
budget and is discarded when a connection closes. This lets per-packet pacers
such as BBR2 prepare a bounded burst instead of serializing only one packet per
timer wakeup. CUBIC remains the default controller.

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
| `listeners[].max_datagram_size` | Optional HTTP/3 packet ceiling for a low-MTU or nested listener; otherwise inherits `quic.max_datagram_size` |
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

The HTTP/3 client retries temporarily blocked request headers within a
ten-second deadline and stops if the connection closes. Time spent waiting
for QUIC capacity is included in the reported CONNECT setup interval.

### Linux HTTP/3 GSO comparison

A November 2026 check measured the v0.14.5 server on a four-vCPU Linux x86_64
host. Release binaries used Rust 1.97.1 and GNU libc. The benchmark client,
server and local targets shared the host inside an isolated container. The
server used CUBIC, Basic authentication, verified TLS, one QUIC connection,
one shard and target UDP GSO disabled, with QUIC GSO varied as shown.

Values are medians of three runs, reversing case order on alternate rounds.
Each TCP run downloaded 256 MiB three times; its warm rate is the median of
downloads two and three. UDP samples ran for three seconds per payload with
512 requests in flight and a one-second expiry. Mixed samples offered 3,000
64-byte UDP packets/s alongside an unrestricted download on the same
connection.

| Metric | QUIC GSO off | QUIC GSO on |
| --- | ---: | ---: |
| TCP warm download (Gbit/s) | 2.46 | 7.13 |
| TCP warm rate range (Gbit/s) | 2.43–2.47 | 7.10–7.26 |
| 64 B UDP echo (kpps) | 275.0 | 280.1 |
| 64 B UDP response shortfall | 0.119% | 0.119% |
| 64 B UDP loaded p99 upper bound (ms) | 0.832 | 0.832 |
| 1200 B UDP echo (Gbit/s) | 1.24 | 1.83 |
| 1200 B UDP response shortfall | 0.213% | 0.177% |
| 1200 B UDP loaded p99 upper bound (ms) | 3.712 | 2.304 |
| Mixed TCP download (Gbit/s) | 2.34 | 6.62 |
| Mixed UDP p99 upper bound (ms) | 7.936 | 2.688 |
| Mixed UDP response shortfall | 16.833% | 0.000% |

These measurements cover local processing and queueing. They do not qualify
GSO on an external network path or measure multi-host scaling. UDP p99 counts
completed echoes; expired requests appear in response shortfall. The fixed
in-flight window and differing shortfall must be considered together with
the latency figures.

Two further experiments used three alternating A/B runs with QUIC GSO on,
four-second samples and the same client. A 64-packet budget for draining
target responses changed 1200-byte UDP p99 from 2.176 to 2.432 ms with almost
unchanged throughput. Increasing target-side batches from 16 to 32 packets
changed that p99 from 2.176 to 2.304 ms. In the latter experiment, eight
connections with 128 in-flight requests each went from 138.8 to 129.3 kpps
and from 5.120 to 6.144 ms p99. Both experimental changes were discarded.

### Running the benchmark

```sh
scripts/network-bench.sh
```

Useful controls include:

```sh
MASQUE_BENCH_MODE=udp \
MASQUE_BENCH_TRANSPORT=both \
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

`MASQUE_BENCH_MODE` accepts `all` (the default), `smoke`, `tcp`, `udp`,
`load`, or `mixed`. Focused modes still build the release workspace and start only the
supporting processes needed by that measurement. `MASQUE_BENCH_SHARDS`
selects the listener shard count; `0` retains the server's documented
one-shard-per-core behavior.

For CONNECT-IP, use a Linux host with `unshare`, `ip`, and TUN support. The
script creates an ephemeral network namespace and needs root or equivalent
privileges; its echo target and TUN exist only in that namespace:

```sh
cargo build --workspace --release
sudo env MASQUE_BENCH_BIN_DIR=target/release MASQUE_IP_BENCH_TUN_OFFLOAD=1 \
  bash scripts/connect-ip-bench.sh
```

Alternate `MASQUE_IP_BENCH_TUN_OFFLOAD=0` and `1` for at least three rounds,
and confirm `IP_BENCH_TUN effective_offload` before interpreting the results.
The test uses UDP echo packets inside CONNECT-IP; it does not measure TCP
goodput through a client TUN or performance over a real network path.

`MASQUE_BENCH_TRANSPORT` accepts `http3` (the default), `http2`, or `both` for
the smoke, TCP, and UDP modes. `both` binds TCP and UDP on the same address and
runs HTTP/3 first, then HTTP/2. It requires an explicit non-zero HTTP/3 shard
count. `load` accepts either transport or `both`. HTTP/2 uses asynchronous
stream workers and HTTP/3 uses one native thread per connection.

For a fixed offered load over HTTP/2, set the number of connections, the
number of CONNECT-UDP streams per connection, and the per-stream rate:

```sh
MASQUE_BENCH_MODE=load MASQUE_BENCH_TRANSPORT=http2 \
  MASQUE_LOAD_CONNS=8 MASQUE_LOAD_STREAMS_PER_CONN=2 \
  MASQUE_LOAD_PPS_PER_STREAM=4000 MASQUE_LOAD_WINDOW=256 \
  MASQUE_LOAD_PAYLOAD=64 MASQUE_LOAD_DURATION_SECS=6 scripts/network-bench.sh
```

`MASQUE_LOAD_PPS_PER_STREAM=0` saturates each stream. With a fixed rate,
compare the achieved `tx_pps` to the requested total before comparing RTT
or CPU. `H2_LOAD_RESULT` reports the achieved rates, response shortfall,
expired echoes, and RTT histogram bounds across all streams.

An alternating comparison of the checksummed Linux x86_64 release binaries
used one benchmark client, eight connections with two tunnels each, 64-byte
packets, a window of 256 per tunnel, and six seconds of traffic per run.
The table shows medians of three runs per version and load level.

| Offered load | Version | Actual TX (kpps) | Echo RX (kpps) | Loaded p99 upper bound (ms) | Response shortfall | Server CPU time (s) |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 64 kpps | v0.14.4 | 63.99 | 63.99 | 3.20 | 0.00% | 2.79 |
| 64 kpps | v0.14.5 | 64.00 | 64.00 | 0.99 | 0.00% | 3.37 |
| 160 kpps | v0.14.4 | 159.60 | 156.27 | 3.07 | 2.14% | 5.49 |
| 160 kpps | v0.14.5 | 159.98 | 157.25 | 1.41 | 1.71% | 7.26 |
| Saturation | v0.14.4 | 331.54 | 327.63 | 1.34 | 1.18% | 9.41 |
| Saturation | v0.14.5 | 340.27 | 336.34 | 1.22 | 1.15% | 9.77 |

v0.14.5 reduced the measured tail at both fixed rates while using more CPU.
At saturation, received throughput rose 2.7%, with nearly flat CPU time per
echo (4.79 to 4.83 µs). CPU totals include setup. These are co-located Linux
loopback results, so the ceiling includes contention with the benchmark
client and echo process. They measure the two releases as shipped, including
both TCP_NODELAY and capsule batching.

Use `mixed` to compare paced 64-byte UDP with and without a bulk TCP download.
Set `MASQUE_MIXED_DOWNLOAD=0` for UDP alone, `1` for both tunnels on the same
HTTP/3 connection, or `separate` for one connection per tunnel. One benchmark
thread drives both sockets in the separate mode:

```sh
MASQUE_BENCH_MODE=mixed MASQUE_BENCH_TRANSPORT=http3 \
  MASQUE_MIXED_DOWNLOAD=1 MASQUE_MIXED_UDP_PPS=3000 \
  MASQUE_BENCH_DURATION_SECS=8 MASQUE_BENCH_WINDOW=512 \
  MASQUE_TCP_DOWNLOAD_BYTES=4294967296 scripts/network-bench.sh
```

The local target serves a sparse file. The mixed run rejects a download
that finishes during the sample or sends no body bytes in the sample.
`H3_MIXED_RESULT` reports connection topology, achieved UDP rate, application RTT p99, response
shortfall, and TCP body goodput during the same interval. Repeat with the
isolated `tc` profile below for a controlled delayed or lossy path.

The following v0.14.5 Linux x86_64 results used CUBIC, one shard, QUIC GSO
off, a window of 512, and 3,000 offered 64-byte packets per second for
eight seconds. The qdisc delayed traffic 30 ms each way. Values are medians
of three alternating runs per combination.

| Injected loss per direction | Workload | Echo RX (pps) | UDP p99 upper bound (ms) | UDP response shortfall | TCP download (Mbit/s) |
| --- | --- | ---: | ---: | ---: | ---: |
| 0% | UDP only | 3,000 | 61.44 | 0.00% | — |
| 0% | UDP + download, shared connection | 3,000 | 114.69 | 0.00% | 765.02 |
| 0% | UDP + download, separate connections | 3,000 | 63.49 | 0.00% | 566.96 |
| 0.2% | UDP only | 2,990 | 147.46 | 0.34% | — |
| 0.2% | UDP + download, shared connection | 2,990 | 245.76 | 0.33% | 49.75 |
| 0.2% | UDP + download, separate connections | 2,988 | 221.18 | 0.41% | 74.40 |

Without injected loss, separating the connections recovered most of the
extra UDP latency in the shared connection. With loss, the p99 ranges
overlapped: 147–213 ms for UDP alone, 180–246 ms shared, and 147–279 ms
separate. The sample measures application RTT across the client, proxy,
and target. Download throughput varied across runs and was measured only
in the mixed workloads.

A separate diagnostic build sampled one in 64 UDP echoes on the server in
the no-loss profile. It tracked the return path from reading the UDP target
socket through QUIC queueing, packet generation, and successful submission
to the server socket. Each run contributed 375 samples. Values are medians
of the three per-run p99s and are calculated independently for each stage.

| Workload | Target response to QUIC enqueue | QUIC enqueue to packet generation | Packet generation to socket submission | Total |
| --- | ---: | ---: | ---: | ---: |
| UDP only | 23 µs | 9 µs | 18 µs | 32 µs |
| UDP + download, shared | 1.31 ms | 47.30 ms | 213 µs | 47.39 ms |
| UDP + download, separate | 657 µs | 10 µs | 21 µs | 664 µs |

The queue wait before packet generation accounts for most of the observed
server-side delay in the shared workload. This measurement ends at socket
submission and includes no kernel or network transit time. Sharing a
connection also shares its congestion and pacing state, so this experiment
does not distinguish a congestion-credit wait from frame selection.

An experimental server limited TCP response writes to 16 KiB per drive
when DATAGRAMs were queued. In three alternating shared-connection runs
against the same diagnostic build, it reduced median server queue p99 from
50.47 to 46.76 ms. Application UDP p99 remained 114.69 ms in all six runs,
and TCP throughput varied substantially. The cap was left out of the server.

A follow-up diagnostic build counted quiche short-packet construction
attempts while a DATAGRAM was pending. In the same no-loss, 60 ms RTT
shared-connection profile, the congestion allowance was too small for
the head DATAGRAM on 76–82% of attempts. A DATAGRAM could fit but frame
selection preferred STREAM on 0.5–0.7% of attempts. These are counts of
attempts rather than fractions of elapsed queue time.

Forcing DATAGRAM selection when it fit eliminated the STREAM preference
cases. Over three alternating runs per variant, median DATAGRAM enqueue
to packet-generation p99 remained about 47.4 ms and application UDP p99
remained 114.69 ms. All runs delivered 3,000 echoes/s with no response
shortfall. The experiment supports a congestion-budget explanation for
this workload, so the temporary frame-selection change was discarded.

The same diagnostic build also tested quiche's send-capacity factor at
1.00, 0.75, and 0.50. This factor scales how much STREAM data the
application can enqueue against the current send capacity. It does not
reserve congestion window space for DATAGRAM frames. Each factor ran three
times in rotating order in the same shared-connection profile.

| Send-capacity factor | UDP p99 upper bound (ms) | QUIC enqueue to packet-generation p99 (ms) | TCP download median (Mbit/s) | TCP download range (Mbit/s) |
| --- | ---: | ---: | ---: | ---: |
| 1.00 (default) | 114.69 | 48.66 | 145.90 | 32.70–865.05 |
| 0.75 | 114.69 | 51.04 | 108.66 | 87.84–249.36 |
| 0.50 | 114.69 | 53.51 | 79.01 | 30.72–120.13 |

All nine runs delivered 3,000 echoes/s with no response shortfall. The lower
factors did not reduce UDP tail latency or the measured queue wait. Download
rates varied widely, so this sample does not establish the size of a TCP
throughput penalty. The server retained quiche's default factor.

The same shared-connection profile compared CUBIC and BBR2 using the
checksummed v0.14.5 Linux x86_64 release binary. Five runs per algorithm
and loss level alternated order. Only the server congestion controller
changed. All samples used a 60 ms configured RTT, 3,000 offered 64-byte UDP
packets/s, and a concurrent unrestricted TCP download.

| Injected loss per direction | Server algorithm | UDP p99 upper bound (ms) | UDP response shortfall | TCP download median (Mbit/s) | TCP download range (Mbit/s) |
| --- | --- | ---: | ---: | ---: | ---: |
| 0% | CUBIC | 114.69 | 0.00% | 459.76 | 101.10–982.25 |
| 0% | BBR2 | 253.95 | 0.69% | 1026.10 | 921.51–1035.64 |
| 0.2% | CUBIC | 163.84 | 0.36% | 33.62 | 11.77–125.47 |
| 0.2% | BBR2 | 212.99 | 0.41% | 668.84 | 645.03–677.98 |

BBR2 delivered more download throughput and a higher UDP p99 in these
mixed runs. With loss, the per-run UDP p99 ranges overlapped (139–246 ms
for CUBIC and 147–311 ms for BBR2). The TCP rate was an outcome of each
run, so the comparison measures the trade-off under an unrestricted
download and does not isolate latency at equal TCP throughput.

For local HTTP/3 TLS verification checks, set `MASQUE_BENCH_VERIFY_TLS=1`.
The generated loopback certificate is then trusted and its `server` hostname
is verified. When using the HTTP/3 client directly against a remote endpoint,
set `MASQUE_BENCH_CA_CERT` to a trusted CA PEM file and `MASQUE_SERVER_NAME`
to the expected certificate name. Without the CA setting the E2E client does
not verify the server certificate; do not use credentials you care about on
that path. This option currently applies to HTTP/3 only.

`MASQUE_BENCH_CC=cubic|reno|bbr2` selects the server's QUIC congestion
controller for a benchmark; the default is `cubic`. Alternate controllers over
at least three runs with the same payload, window, duration, and expiry. Inspect
goodput, RTT, response shortfall, and the direct baseline together.

For controlled HTTP/3 WAN tests, run the benchmark in an isolated Linux
container or network namespace with `tc`. Match only UDP packets with the
benchmark server port as source or destination so the target echo and direct
baseline stay unshaped. For example, in the isolated namespace:

```sh
port=19443
tc qdisc add dev lo root handle 1: prio bands 3 priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
tc qdisc add dev lo parent 1:1 handle 10: netem delay 30ms loss 0.2% limit 20000
tc filter add dev lo protocol ip parent 1: pref 1 flower ip_proto udp dst_port "$port" classid 1:1
tc filter add dev lo protocol ip parent 1: pref 2 flower ip_proto udp src_port "$port" classid 1:1
MASQUE_BENCH_SERVER_PORT="$port" MASQUE_BENCH_MODE=udp \
  MASQUE_BENCH_TRANSPORT=http3 MASQUE_BENCH_WINDOW=512 scripts/network-bench.sh
tc -s qdisc show dev lo
```

Compare GSO on/off with the same binary and pacing variants with GSO fixed.
`MASQUE_BENCH_SERVER_BIN` selects a different server while keeping the same
client binary. Check the qdisc counters and observed RTT before comparing
results. Record both the single-connection UDP run and the loaded RTT
percentiles from a multi-connection run.

In a three-run Linux loopback comparison with the profile above, CUBIC, one
shard, and target GSO disabled, the isolated qdisc recorded 668 drops across
375,917 transmitted packets. The table reports medians. The single connection
used a window of 512 for four seconds per payload. The eight-connection run
used a window of 128 per connection and 64-byte payloads for five seconds.

| QUIC variant | Single 64 B (pps) | Single 1200 B (Mbit/s) | Eight connections (pps) | Loaded p99 upper bound (ms) | Loaded response shortfall |
| --- | ---: | ---: | ---: | ---: | ---: |
| GSO off, 1 ms pacing horizon | 7,441 | 22.52 | 12,771 | 69.63 | 1.94% |
| GSO requested, 1 ms pacing horizon | 7,180 | 17.65 | 12,587 | 65.54 | 2.13% |
| GSO off, zero pacing horizon | 7,065 | 21.13 | 11,593 | 65.54 | 2.71% |

The eight-connection server CPU totals were 0.44 s, 0.42 s, and 0.39 s
respectively, including setup. Neither variant improved goodput and shortfall
together in this run, so the defaults were kept. The loopback qdisc operates
on kernel packets, and its loss behavior with GSO can differ from physical
network loss. Confirm the result on the intended network before tuning GSO.

UDP runs emit one `UDP_RESULT` record per payload and path. TCP runs include a
`transport` field in every `TCP_DOWNLOAD_RESULT` and `TCP_DOWNLOAD_SUMMARY`, so
automation does not have to infer which listener produced a number from output
order.

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
`MASQUE_BENCH_QUIC_GRO=0|1` to compare QUIC receive coalescing; it defaults
to `1`, matching the server default. Set
`MASQUE_BENCH_OBSERVABILITY=1` to enable the loopback endpoint and metric
updates during an A/B run; the default `0` measures the uninstrumented packet
path.

For a privileged Linux profiling run, `MASQUE_BENCH_PERF=1` records the server
only. Set `MASQUE_BENCH_PERF_EVENT=cpu-clock` to include kernel samples; the
default `cpu-clock:u` samples userspace only. Sampling adds overhead and should
be run separately from throughput comparisons.

For HTTP/3 migration A/B testing, run the same UDP command once normally and
once with `MASQUE_BENCH_MIGRATED=1`. The latter replaces the client's UDP
socket after CONNECT-UDP setup, waits for the new path to validate, and labels
machine-readable results as `path=masque_migrated`. Compare medians from at
least three alternating runs; the unchanged-path run detects ordinary hot-path
regressions, while the migrated run verifies Linux CID-based SO_REUSEPORT
steering keeps the steady-state path on its original shard. A non-zero
`masque_quic_cross_shard_forwarded_packets_total` identifies use of the bounded
userspace fallback.

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

`scripts/gso-bench.sh` runs three rounds of all four combinations: both off,
QUIC only, target only, and both on. It reverses the case order on alternating
rounds, builds once, and retains each case's output and server log. Set
`MASQUE_GSO_ROUNDS=1..9` and `MASQUE_GSO_RESULTS_DIR` to change repetition and
output location. `MASQUE_BENCH_MODE=tcp` measures TCP instead of the default
UDP workload; target UDP GSO has no effect on that workload.

Both scripts accept `MASQUE_BENCH_BIN_DIR` to use prebuilt executables without
running Cargo. `MASQUE_BENCH_RESULTS_DIR` retains logs from an individual
network-bench run. Load mode warms authentication with one successful UDP
request by default so it measures established-connection traffic. Set
`MASQUE_LOAD_WARM_AUTH=0` for a cold authentication burst; requests beyond
`server.max_pending_auth_per_ip` may then correctly receive 503. Label cold
and warm measurements separately.

Use `masque_auth_cache_hits_total`, `masque_auth_coalesced_total`, and
`masque_auth_argon2_total` to distinguish accepted requests from actual hash
work. The first request for an account or after a reload/expiry remains cold.
TCP download samples on the same listener therefore include a cold first
CONNECT followed by warm CONNECTs; report these setup times separately.

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

## Repeatable performance baseline

Run the standard local matrix with three rounds and a single release build:

```sh
python3 scripts/performance-baseline.py
```

The matrix covers HTTP/3 and HTTP/2 UDP and TCP, plus one-connection and
multi-connection HTTP/3 load. Linux also runs two-shard load; other platforms
record that case as skipped because server sharding requires Linux. UDP uses both 64-byte and
1200-byte payloads. `--profile gso` adds the three enabled GSO combinations
on Linux; the normal HTTP/3 case supplies the both-disabled control.
`--profile quick --rounds 1 --duration 1` is a harness smoke test, not a
performance conclusion. `--cc cubic|reno|bbr2` holds the chosen congestion
controller constant throughout a run.

Compare two compatible MASQUE Server builds with one identical client:

```sh
python3 scripts/performance-baseline.py \
  --bin-dir target/release \
  --reference-server /private/benchmark/reference/masque-server \
  --rounds 3 --duration 10 \
  --output /private/benchmark/comparison
```

Replace the documentation-only paths with private local locations. The output
directory must be new and outside the checkout. The runner alternates A/B
order and reverses workload order on alternate rounds. It clears inherited
`MASQUE_*` settings, so an ambient endpoint, interface, or authentication setting
cannot redirect the local test. `--bin-dir` skips rebuilding; both server
binaries must accept the same MASQUE Server benchmark configuration.

The private `report.json` includes binary SHA-256 values, workload settings,
raw numeric records, medians and ranges, and optional A/B comparisons. It omits
hostnames, addresses, credentials, and executable paths. Per-run logs remain
in private subdirectories. Server CPU seconds and peak RSS come from `wait4`
for only the temporary server; they exclude the client and target processes.
Resource accounting covers the whole case, including startup and direct-control
intervals. CPU percentage can exceed 100% for multiple busy cores. Compare
resource usage only alongside equivalent completed traffic.
The report is checkpointed after every successful workload; `complete = false`
identifies an interrupted or failed matrix.

UDP RTT percentiles are sequential 64-byte probes before throughput load;
they do not describe tail latency under saturation. Load setup percentiles are
connection setup measurements. TCP samples retain their sample indices so a
cold first CONNECT is not pooled with later warm requests.

HTTP/3 also records completed echo-request RTT while the throughput engine is
running, in `UDP_LOAD_LATENCY_RESULT` and the `load_rtt_*` fields of
`LOAD_RESULT`. This is application echo RTT, including client and server
queueing, encryption, and scheduling, rather than QUIC's path RTT estimate.
These use a fixed-memory histogram, with sixteen buckets per
power of two and quantiles reported as `*_us_upper` bucket upper bounds.
Buckets above 16 microseconds are at most 6.25% wide. Multi-connection results
merge packet counts, not per-connection percentiles. Expired requests have no
completed RTT and remain visible in the separate response-shortfall figures.
The client also bounds completed-entry bookkeeping when an older request is
lost, so the measurement window does not create an ever-growing tombstone queue.

For an alternating controller comparison using the same server and client:

```sh
python3 scripts/performance-baseline.py --bin-dir target/release \
  --profile congestion --reference-cc cubic --cc bbr2 \
  --rounds 3 --duration 10
```

The congestion profile only runs QUIC workloads. `--reference-cc` and
`--reference-server` are mutually exclusive to keep controller and build
changes separate. The report records each controller explicitly. Loopback
results validate the harness and local CPU cost; selecting a deployment default
requires controlled bandwidth, RTT, and loss experiments on an isolated Linux
test path. Host networking must not be modified to manufacture these conditions.

A/B comparisons need at least three samples. Noisy samples, zero baselines,
and a drifting direct control are marked `inconclusive`, with explicit reasons
in each comparison. More unanswered UDP
responses cannot qualify as a throughput improvement. By default the runner
reports findings without failing on speed differences. On an isolated, stable
benchmark machine, add `--fail-on-regression` to return exit code 3 for a
confirmed regression or 4 for an inconclusive or empty comparison;
the default tolerance is 10%, with a one-percentage-point response-shortfall
tolerance. Shared CI runners should validate the harness rather than enforce
throughput thresholds. This local matrix does not substitute for external-path
GSO qualification or a controlled RTT/loss/MTU test.

Network benchmark runs select temporary loopback ports by default. For a
controlled environment, `MASQUE_BENCH_SERVER_PORT`, `MASQUE_BENCH_ECHO_PORT`,
and `MASQUE_BENCH_HTTP_PORT` select explicit ports for `network-bench.sh`.
Selection does not reserve the port until bind, so a concurrent user of the
same port can still make a run fail; rerun it after resolving the collision.

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

On Linux, `MASQUE_BENCH_PERF=1` attaches `perf record` to only the temporary
benchmark server, with user-space CPU-clock samples and DWARF call graphs.
Set `MASQUE_BENCH_RESULTS_DIR` to retain `perf.data` and `perf.log`, and use
`MASQUE_BENCH_PERF_BIN` for a non-default perf path. Sampling failures make
the benchmark fail. Use a release build with symbols (for example
`CARGO_PROFILE_RELEASE_DEBUG=1 CARGO_PROFILE_RELEASE_STRIP=none`), a longer
TCP workload, and `perf report --stdio --no-children` to inspect self cost.
Do not mix sampled and unsampled throughput results.

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
