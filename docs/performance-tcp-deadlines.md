# TCP deadline and buffer reuse measurements

HTTP/3 download experiments separate wakeup precision, send batching, and target
read allocation. All numbers below are measurements of the stated variants,
not guarantees for other clients or paths. Private endpoints, configuration,
and raw host diagnostics are excluded.

## Implementation

Linux TCP-only connections can use a shard-owned nonblocking `timerfd` to avoid
rounding every pacing deadline to Tokio's millisecond ticks. Other traffic and
platforms retain Tokio; a timer creation or I/O failure permanently selects that
fallback for the shard. Both timer paths retain the original 1 ms send batching
horizon. Deferred packet and spare-buffer limits are unchanged.

TCP target reads retain their 64 KiB maximum size. Four per-tunnel pool slots
bound whole allocations to 256 KiB, in addition to the existing payload credit.
Allocation is lazy. The final `Bytes` owner returns the cleared buffer using a
nonblocking channel operation, so retained slices cannot expose recycled data.
Neither partial HTTP/3 writes nor reader cancellation can reuse live memory.

## Experiments that selected the candidate

The initial timer prototype combined fine wakeups with a 250 microsecond
batching horizon. A three-pair external HTTPS test improved the 10-second
median from 87.19 to 96.61 Mbit/s, primarily at startup. The mean of seconds
4–10 changed from 121.51 to 119.32 Mbit/s. A separate download process through
a local SOCKS proxy did not reproduce a consistent gain: adjacent paired
changes were -6.5%, -7.5%, and +9.6%. Fine wakeups alone therefore do not
establish a stable reduction in the throughput gap to other protocols.

Keeping fine wakeups while restoring the original 1 ms horizon reduced CPU
seconds per Gbit from 3.6361 to 3.2212 in another three-pair external HTTPS run.
Throughput medians were 93.33 and 97.41 Mbit/s, with variable paired changes.
This motivated separating timer precision from batching.

Reducing reads to 32 KiB did not improve controlled throughput or CPU. A 16 KiB
variant reduced minor faults but did not give consistent throughput gains,
including when combined with the 1 ms horizon. Both size changes were rejected.

A first 64 KiB recycling prototype used a separate buffer-slot semaphore and
retained the 1 ms horizon on both sides of the comparison. Each row below uses
three samples per variant in alternating order, BBR2, QUIC GSO, cold connections,
and a 10-second download. The controlled source used about 120 ms QUIC RTT and
20 ms target-side egress delay. The external HTTPS comparison used the same
server, UDP port, and fixed target IPv4 address, verified in every sample.

| Recycling prototype measurement | Without reuse | With reuse |
| --- | ---: | ---: |
| Controlled throughput median (Mbit/s) | 481.77 | 482.56 |
| Controlled CPU per 100 Mbit/s, percent of one core | 7.5140 | 6.7971 |
| Controlled minor faults per Mbit | 35.6822 | 3.6778 |
| External HTTPS throughput median (Mbit/s) | 93.83 | 97.45 |
| External server CPU seconds per Gbit | 3.3363 | 2.7903 |
| External minor faults per Gbit | 37,484.8 | 4,672.4 |

The external prototype reduced normalized CPU in all three adjacent pairs;
the median reduction was 16.4%. Its throughput changes were variable. Minor
faults represent demand for memory pages, not network packet loss. Lower CPU
cost is useful evidence for recycling but does not prove faster downloads on a
path that is limited elsewhere.

The working candidate replaces the prototype's separate semaphore with four
channel slots. A returned slot carries its reusable buffer, making the same
allocation bound explicit without another per-read semaphore operation. The
prototype measurements above do not substitute for testing this exact version.

## Current candidate against the main branch

The exact working candidate was compared with main-branch commit `0f915a6`,
using release binaries built with the same toolchain. This comparison includes
both the deadline timer and the final four-slot buffer pool. Six external HTTPS
samples used the order baseline, candidate, candidate, baseline, baseline,
candidate, with the same fixed destination, port, BBR2, and GSO. Every sample
verified the actual destination address and the expected timer implementation.

| External HTTPS measurement | Main-branch median | Current candidate median |
| --- | ---: | ---: |
| Full 10-second throughput (Mbit/s) | 93.90 | 100.03 |
| Mean throughput during seconds 4–10 (Mbit/s) | 122.17 | 122.69 |
| Server CPU seconds per Gbit | 3.2692 | 2.5982 |
| Minor faults per Gbit | 38,375.8 | 4,438.9 |

Full-run throughput increased 6.5%; the later portion changed by only 0.4%.
The gain is primarily at startup. Adjacent throughput changes were +3.2%,
+8.4%, and +14.8%. Normalized server CPU fell 20.5% by the medians and fell in
each pair. Three samples per variant remain a small sample; these measurements
alone do not establish sustained gains or a ranking against other protocols.

### Follow-up through the local SOCKS entry point

A separate comparison used a single HTTP/1.1 download through the same local
proxy application's SOCKS entry point. It measured five variants five times
each in interleaved order: main, the exact working candidate, two TCP-based
references, and a QUIC-based reference. Each download lasted 10 seconds. Both
phases retained the same fixed destination IPv4 address and verified unchanged
source, candidate binaries, and reference executable hashes.

All 25 downloads passed. Server socket counters verified traffic to the fixed
destination in every sample. Each MASQUE sample started a new server instance;
the TCP references established new inbound sockets, and the QUIC reference's
Initial packets were observed. Packet contents were not retained. Reference
services remained running between samples. TLS resumption and 0-RTT state were
not matched, so the results describe these configured implementations and
connection conditions rather than intrinsic protocol limits.

| SOCKS-entry measurement | Main | Candidate | Fastest reference |
| --- | ---: | ---: | ---: |
| Throughput median (Mbit/s) | 367.42 | 402.80 | 457.93 |
| Throughput range (Mbit/s) | 341.79–403.19 | 361.43–434.64 | 418.50–487.67 |
| Server CPU seconds per Gbit, median | 2.1035 | 1.9563 | 1.8324 |

The candidate's throughput median increased 9.6%. All five adjacent MASQUE
pairs improved: +4.3%, +7.9%, +7.8%, +3.4%, and +18.0%. Its shortfall from the
fastest reference median fell from 19.8% to 12.0%. Normalized server CPU fell
7.0% by the medians, decreasing in four pairs and increasing 0.4% in one.
These are combined timer-and-buffer results; they do not isolate the benefit
of either change. The earlier interrupted pilot is excluded.

The sample ranges overlap, the external path can vary, and five samples per
variant do not establish a universal improvement. This SOCKS-entry result must
also remain separate from the application's built-in speed test above: their
absolute throughput differs substantially.

### Confirmation with the built-in speed test

The built-in test was then repeated against a fresh independent QUIC reference
using BBR. All three variants used the same server host, UDP port, fixed target
IPv4 address, 10-second download, and single connection. Every sample used a new
server process and certificate. The reference executable matched the earlier
control, but its fresh test configuration fixed the target address and disabled
0-RTT; it was a separate instance from the persistent reference above.

The nine-sample order was main, candidate, reference, reference, candidate,
main, main, candidate, reference. All samples passed target and new-connection
checks. An earlier attempt that reached a different target through the reference
was stopped, cleaned up, and excluded from this comparison.

| Built-in measurement | Main | Candidate | QUIC reference |
| --- | ---: | ---: | ---: |
| Full 10-second throughput median (Mbit/s) | 87.17 | 93.82 | 196.50 |
| Throughput range (Mbit/s) | 86.82–87.38 | 93.24–97.43 | 194.93–210.70 |
| Mean throughput during seconds 4–10, median (Mbit/s) | 120.18 | 114.92 | 232.81 |
| Server CPU seconds per Gbit, median | 4.0390 | 3.5167 | 2.1013 |

All three adjacent MASQUE pairs improved full-run throughput: +6.7%, +12.2%,
and +7.6%. The median increased 7.6%, reducing the shortfall from the reference
median from 55.6% to 52.3%. Normalized server CPU fell 12.9% by the medians.

The improvement remains primarily at startup. The later portion fell 4.4% in
this run, compared with a 0.4% increase in the earlier built-in comparison.
There is no demonstrated sustained-throughput improvement, and the candidate
still trails this reference substantially in the built-in test. The SOCKS-entry
numbers must not be used to imply that this remaining difference is resolved.

Temporary instances, policies, rules, and handshake observers were removed.
All four original services retained their versions and configuration hashes;
the tested original service also passed external TCP and UDP probes.

### Correctness checks

The exact source passed the native full check, including MSRV and HTTP/2 and
HTTP/3 tests, plus Linux Clippy, workspace tests, and Docker E2E. The buffer
tests exercise retained slices, partial writes, exhaustion of all four slots,
reuse after full consumption, and a response outliving reader teardown.
Scheduled ASan, fuzzing, and the full resource-pressure suite were not run for
this experiment; these checks do not constitute release qualification.

## Datagram and mixed checks

An initial saturated eight-connection check shared four host cores between the
server and load generator. At 1200 bytes, candidate results initially fell far
below baseline, then varied from about 82k to 141k responses/s for the identical
binary. The container used almost all four cores; measured quota throttling was
small. Those shared-host runs do not establish stable per-server capacity, and
their apparent regression must not be silently discarded.

A follow-up reserved one core for the server and three for the client and
targets. Two samples per variant used baseline, candidate, candidate, baseline,
BBR2, GSO, eight connections, and six seconds per payload:

| Saturated UDP payload | Baseline responses/s | Candidate responses/s | Baseline response shortfall | Candidate response shortfall |
| --- | ---: | ---: | ---: | ---: |
| 64 bytes | 320,954 | 320,866 | 4.198% | 4.267% |
| 1200 bytes | 152,392 | 152,087 | 4.602% | 4.725% |

There were no setup or runtime failures. Peak server RSS stayed near 31 MiB.
The large throughput reduction did not reproduce with separated cores, which
points toward scheduling contention in the combined load generator/server
setup. CPU affinity can also change the default runtime worker count, so these
numbers alone do not rule out regressions under other thread placements.

A further saturated check reserved two server cores and two generator/target
cores while explicitly retaining four Tokio worker threads. Two samples per
variant at 1200 bytes produced 185,317 versus 181,639 responses/s, a 2.0%
median difference with overlapping sample ranges. The median p99 bucket rose
from 311.296 to 360.448 ms and response shortfall from 4.889% to 5.100%.
This did not reproduce the large capacity reduction, but it does not establish
unchanged latency at an equal offered rate.

A fixed-rate follow-up kept that two-core/four-worker server layout and offered
8,000 packets/s on each of eight connections. Both variants sustained about
64k responses/s. Baseline p99 buckets were 224–272 microseconds; candidate
buckets were 216–224 microseconds. One candidate run had three missing responses
out of about 384,000 requests, or 0.000781%; the other runs had no response
shortfall. No setup or runtime failures occurred. This equal-load check did
not reproduce the saturated-tail increase.

A shared-connection mixed test used the same core separation, about 60 ms QUIC
RTT, and 3,000 offered 64-byte UDP packets/s alongside a bulk TCP download.
Three alternating samples per variant retained the 69.632 ms UDP p99 bucket
and zero response shortfall. TCP medians were 1060.507 and 1072.286 Mbit/s.
