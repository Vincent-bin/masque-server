# Linux loopback performance investigation

These measurements are from a four-vCPU Linux test VM using the v0.14.1
server. The client, server and echo target shared the VM. They do not measure a
provider's virtual NIC, an external network, or a production deployment. The
server configuration was created for each test; production settings were not
changed.

Each reported A/B value is the median of three alternating runs. UDP runs used
an HTTP/3 connection, 1,200-byte application payloads, a 256-request window,
and two seconds per payload and path. TCP runs used three 256 MiB downloads
per run. The server CPU measurements include setup and the direct comparison
phases, so they are useful for comparing runs but are not per-packet CPU costs.
An interval response shortfall includes requests that expired; it is not a
direct measurement of wire loss.

| Test | Baseline | Variant | Outcome |
| --- | ---: | ---: | --- |
| CONNECT TCP, QUIC GSO off/on | 2.05 Gbit/s | 6.07 Gbit/s | Median download goodput; server CPU time for the complete run 4.64/1.64 seconds |
| CONNECT-UDP, QUIC GSO off/on | 1.070 Gbit/s | 1.674 Gbit/s | Response shortfall 0.151%/0.084%; loaded p95 RTT upper bound 2,304/1,408 µs |
| CONNECT-UDP, QUIC GRO on/off | 1.070 Gbit/s | 1.072 Gbit/s | No clear throughput change in this workload |
| CONNECT-UDP, QUIC and target UDP GSO enabled | 1.070 Gbit/s | 1.856 Gbit/s | Both enabled; response shortfall 0.085% |
| CONNECT-UDP, QUIC packet batch cap 64/8 | 1.078 Gbit/s | 0.939 Gbit/s | A separate experimental server build; smaller cap reduced throughput |
| CONNECT-IP, TUN offload off/on | 0.743 Gbit/s | 0.717 Gbit/s | Three seconds per payload; UDP echo inside IP packets; offload negotiation confirmed |

TUN-offload response shortfall was 0.069%/0.000%, with loaded p95 RTT upper
bounds of 3,456/3,584 µs. These short loopback runs do not establish a general
benefit or regression for TUN offload. They do not measure TCP through a client
TUN, nor prove that individual packets used the negotiated offload.

For the HTTP/3 UDP load harness, one connection measured 1.047–1.087 Gbit/s
across one- and two-shard cases. Four connections measured medians of 0.885 and
0.847 Gbit/s with one and two shards respectively, with roughly 1% response
shortfall. Since all processes competed for four vCPUs, this does not establish
the server's multi-core scaling. A separate load-generator host is needed.

An additional `perf` run used an optimized build with debug symbols and sampled
only the server, including kernel and userspace. In the TCP run, individual
flat samples included `memcpyFast` at 3.00%, an AES-GCM routine at 2.03%, and
QUIC packet sending at 1.15%; scheduler and socket paths were also prominent.
The UDP run showed `memcpyFast` at 1.11% and the AES-GCM routine at 1.18%.
These are individual sampled symbols, not complete categories. Inlining,
sampling noise and loopback scheduling limit attribution; the samples do not
establish how much copying comes from the deferred-send queue.

Keep existing production defaults. In particular, the local GSO improvement is
not evidence that a provider's real egress path handles GSO correctly. Before
changing production settings, repeat an alternating test over the intended
network path, verify GSO is active, and compare throughput, CPU, latency and
loss. Further copying or wakeup changes need a focused profile or an A/B test
that identifies the specific path.

## External-path follow-up

A separate Linux load generator exercised a short-lived v0.14.1 test server on
a VPS. The server used an independent listener, temporary certificate and
test-only authentication. HTTP/3 certificate and hostname verification were
enabled. The target echo and HTTP services were local to the VPS; the QUIC path
between the load generator and VPS crossed the real network. The production
service and its configuration were not changed. All test services and
temporary server files were removed after the run.

The unloaded TCP connection RTT was approximately 133–139 ms. With 16 MiB TCP
downloads, three alternating samples with GSO configured off were 95.4, 90.7
and 11.8 Mbit/s; the corresponding configured-on samples were 12.8, 52.6 and
61.0 Mbit/s. The variation was too large for a reliable GSO conclusion. The
test did not verify the effective GSO gauge and had no direct-download
baseline, so it cannot qualify a production setting.

For 1,200-byte CONNECT-UDP echo traffic with a 256-request window and a
three-second expiry, completed five-second samples ranged from 1.34 to
2.62 Mbit/s, with 0.2%–7.3% response shortfall and a loaded median RTT upper
bound between roughly 0.85 and 1.84 seconds. One further connection timed out
before a result was available. These overloaded, short runs are not a valid GSO
comparison.

Reducing the window to 16 and using a five-second expiry yielded the following
three-run medians with one server shard and GSO configured off:

| Concurrent connections | UDP echo goodput | Loaded RTT p50 upper bound | Response shortfall | Server CPU time / wall time |
| --- | ---: | ---: | ---: | ---: |
| 1 | 0.989 Mbit/s | 147 ms | 0% | 0.05 s / about 6.2 s |
| 2 | 1.966 Mbit/s | 139 ms | 0% | 0.09 s / about 6.3 s |

The small in-flight window constrains goodput on this high-RTT path; these
numbers are not the link's capacity. Setup and idle time are included in the
server resource interval. The two-connection test used one shard and does
not establish multi-shard scaling. No external CONNECT-IP benchmark was run:
that requires an isolated routed TUN setup. Longer alternating measurements,
a direct baseline and GSO runtime verification remain necessary before
changing any production configuration.
