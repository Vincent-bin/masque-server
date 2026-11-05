# QUIC GSO and socket-buffer verification

This experiment separates application/socket limits from external-path GSO
support. It adds explicit, bounded per-shard `SO_RCVBUF` / `SO_SNDBUF` requests
and actual-size reporting; old configurations retain their OS defaults.

## External path

The canary kept the released v0.14.5 binary. A privileged, temporary socket
adjustment changed only its existing QUIC listener buffers; no global sysctl,
client profile, certificate, authentication, or binary changed. QUIC GSO was
switched through validated configuration with a protected backup and service
restart. Target UDP GSO stayed disabled throughout this TCP-download experiment.
This was an operator experiment, not a new supported remote configuration API.

The sequence was GSO off, on, off. Each phase discarded two warmup downloads,
then used the buffer order small, large, large, small, small, large. Each cell
below has three completed downloads. Small means 64 KiB actual kernel readback
per direction. Large means a 2 MiB setsockopt request, read back as 4 MiB per
direction under Linux accounting. The client used the same bandwidth test in
all phases and retained its normal connection reuse behavior.

| Phase | Actual buffer per direction | Download median (Mbps) | Listener receive-drop delta, sum | Host UDP SndbufErrors delta, sum |
| --- | ---: | ---: | ---: | ---: |
| GSO off, before | 64 KiB | 315.46 | 20,427 | 27,073 |
| GSO off, before | 4 MiB | 200.32 | 0 | 14,466 |
| GSO on | 64 KiB | 289.03 | 5,040 | 823 |
| GSO on | 4 MiB | 260.22 | 0 | 0 |
| GSO off, after | 64 KiB | 198.13 | 4,248 | 10,853 |
| GSO off, after | 4 MiB | 152.45 | 0 | 12,468 |

With large buffers, GSO-on samples were 260.22, 249.45, and 350.05 Mbps;
the combined six GSO-off samples had a median of 176.39 Mbps. This establishes
that GSO carried substantial real external traffic in this environment. The
larger receive buffer eliminated observed listener receive drops in every
measured large-buffer window. GSO plus large buffers also avoided observed
host UDP send-buffer errors in its three windows.

The throughput spread, phase ordering, and reused congestion-control state
prevent treating the median difference as a stable speedup. Larger buffers
alone did not consistently increase download speed. Host UDP counters include
other UDP sockets; SndbufErrors are not an end-to-end packet-loss measurement
and can include retryable send-buffer pressure. This test covers one external
path, one client, and TCP download, not all fleet paths or CONNECT-UDP egress.

The original buffers and both disabled GSO settings were restored. Service
health and the configured external TCP/UDP probe passed after restoration.
Persistent per-socket sizing requires a release containing the new settings;
the experimental socket adjustment does not survive a service restart.

## Linux local results

The same candidate binary and client ran on an isolated Linux loopback network
with four CPU cores available, one HTTP/3 shard, CUBIC, target UDP GSO disabled,
GRO enabled, and TLS verification. Three rounds alternated case order. UDP
used a five-second windowed run per payload (window 512); TCP downloaded 1 GiB
per sample. These measure processing capacity, not external-link capacity.

| QUIC GSO | Receive/send request | TCP download (Gbit/s) | 64 B UDP (Gbit/s) | 1200 B UDP (Gbit/s) | 1200 B response shortfall |
| --- | ---: | ---: | ---: | ---: | ---: |
| Off | OS default | 2.385 | 0.1415 | 1.2426 | 0.2452% |
| Off | 2 MiB each | 2.270 | 0.1370 | 1.2906 | 0.2290% |
| On | OS default | 6.946 | 0.1419 | 1.8462 | 0.1807% |
| On | 2 MiB each | 6.970 | 0.1417 | 1.8152 | 0.2013% |

Values are medians of three runs. The buffer setting preserves the large local
GSO benefit, but is not a new throughput improvement on an uncongested
loopback path. The primary observed buffer benefit is fewer kernel receive
drops on the external path. The benchmark's warning-level server log does not
include startup buffer readback; separate startup/E2E verification checks the
actual values. No global buffer sysctls were changed during these tests.

With 2 MiB requests, median process CPU time for the 1 GiB TCP download was
5.193 CPU-seconds with GSO off and 1.574 CPU-seconds with it on. Peak process
RSS stayed around 31–32 MiB across the matrix. RSS excludes kernel socket
memory; larger buffer limits still need a budget per listener and shard.

Validation included the macOS full check (formatting, Clippy, shell/operations
tests, MSRV, and workspace tests), Linux workspace tests and Clippy, and an
HTTP/2 + HTTP/3 smoke run. The repository's Docker E2E suite also ran against
the prebuilt candidate with two shards and 2 MiB buffer requests: all 12 checks
passed with GSO off and all 12 with it on, including real CONNECT-IP/TUN
forwarding. Both shard sockets read back 4 MiB in each direction, with no
buffer-cap warnings. Experimental containers and networks were removed.
The unmodified `scripts/e2e-test.sh` workflow also rebuilt the Docker images
and passed all 12 checks with its standard configuration.

## Target UDP GSO and CPU

Three alternating-order rounds measured one HTTP/3 connection on an isolated
Linux loopback host with four CPU cores available. Each case used one UDP
payload size for ten seconds, a 512-request window, one server shard, 2 MiB
socket-buffer requests and QUIC GSO enabled. The server and client shared the
host. The only changed setting was target-side UDP GSO.

| Payload | Target GSO | Goodput (Gbit/s) | Response shortfall | RTT p99 upper bound (ms) | Server CPU (% of one core) | CPU seconds per million replies |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 64 B | Off | 0.1379 | 0.1217% | 0.896 | 150.1% | 6.083 |
| 64 B | On | 0.1393 | 0.1197% | 0.864 | 152.4% | 6.111 |
| 1200 B | Off | 1.8036 | 0.1891% | 2.688 | 148.6% | 8.446 |
| 1200 B | On | 1.9328 | 0.1468% | 2.560 | 137.3% | 7.315 |

Values are medians of three runs. For 1200-byte payloads, observed goodput
rose by about 7%, while server CPU seconds per million replies fell by about
13%. The CPU figures account for the whole server process and include startup
and the drain period. The target socket uses ordinary batching for 64-byte
payloads, so their small differences should not be attributed to GSO.

A separate traced run with QUIC GSO disabled and target UDP GSO enabled saw
10,961 successful segmented `sendmmsg` calls and no errors; this confirms the
target path used GSO. Tracing was excluded from the benchmark timings. These
are local processing measurements and do not qualify a WAN target path.

### LAN target egress

A second three-round comparison used a UDP echo target on a separate machine
on the local network. The benchmark client and server remained on the Linux
host; each case used a single HTTP/3 connection, one shard, ten seconds,
512 in-flight requests, QUIC GSO enabled and 2 MiB buffer requests. Only
`udp_proxy.enable_udp_gso` changed. The echo target was a single-process
Python server, which may limit throughput independently of the proxy.

| Payload | Target GSO | Goodput (Gbit/s) | Response shortfall | RTT p99 upper bound (ms) | Server CPU (% of one core) | CPU seconds per million replies |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 64 B | Off | 0.0306 | 0.0002% | 9.728 | 99.2% | 17.498 |
| 64 B | On | 0.0304 | 0.0002% | 9.728 | 98.4% | 17.122 |
| 1200 B | Off | 0.5688 | 0.0212% | 9.728 | 122.0% | 20.975 |
| 1200 B | On | 0.5670 | 0.0035% | 9.728 | 115.7% | 20.529 |

Values are medians. In this workload throughput and the histogram's p99 bound
were similar, while server CPU was lower in the GSO-on sample. These few runs
are not sufficient to establish a general CPU improvement, and the LAN path
is not a WAN test. CPU accounting includes startup and drain; normalizing by
completed replies still leaves those fixed costs in the measurement.

A separate traced 1200-byte LAN run kept QUIC GSO off and target GSO on: all
11,586 observed segmented `sendmmsg` calls succeeded. Tracing was not used in
the comparison runs.

## Reproduction

Use `quic.udp_recv_buffer_size = 2097152` and
`quic.udp_send_buffer_size = 2097152`, restart, and verify actual values before
comparing `quic.enable_udp_gso`. Keep `udp_proxy.enable_udp_gso` fixed when
isolating outer QUIC sends. Linux needs `net.core.rmem_max` and
`net.core.wmem_max` at least as large as the requested sizes; changing those
limits alone does not resize sockets. The application does not change sysctls.

For local tests, pass `MASQUE_BENCH_UDP_RECV_BUFFER_SIZE` and
`MASQUE_BENCH_UDP_SEND_BUFFER_SIZE` to `scripts/network-bench.sh`. Record 64-byte
and 1200-byte UDP, TCP goodput, response shortfall, CPU/RSS, and kernel readback.
Alternate test order, discard equal warmup periods, and retain a GSO-off
baseline. A successful local GSO run does not qualify a different external path.
