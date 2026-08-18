# Architecture

## Goals

MASQUE Server is a single-process HTTP/3 proxy optimized for bounded resource
use and high UDP throughput. Its core rules are:

- one owner event loop mutates each QUIC connection;
- slow setup work never blocks that event loop;
- every queue and buffer has an explicit upper bound;
- TCP backpressure is preserved end to end;
- UDP overload results in bounded loss rather than unbounded latency; and
- Linux fast paths remain isolated from portable protocol code.

## Runtime components

```text
                       +-----------------------+
UDP/QUIC packets ----> | shard event loop      |
                       |                       |
wrong-shard packet --->| connection + H3 state |---> QUIC UDP batch
auth result ---------->| request dispatch      |
TCP relay event ------>| tunnel scheduling     |
target UDP batch ----->| timeout scheduling    |
TUN packet ----------->|                       |
                       +-----+------------+----+
                             |            |
                    +--------v--+      +--v-----------+
                    | TCP tasks |      | UDP targets  |
                    +-----------+      +--------------+
                             |
                       +-----v------+
                       | shared TUN |
                       +------------+
```

`Server` validates configuration, creates shared policy and routing state, and
starts one or more `Shard` instances. A shard owns:

- one QUIC UDP socket, bound with `SO_REUSEPORT` when its listener has more
  than one shard;
- its QUIC and HTTP/3 connections;
- tunnel state for those connections;
- connection and pacing timers; and
- bounded receivers for setup and relay events.

No connection is concurrently mutated by two shards.

## Source layout

| Path | Responsibility |
| --- | --- |
| `src/server/mod.rs` | Server startup, shard event loop, and tunnel coordination |
| `src/server/request.rs` | CONNECT classification, auth precheck, and authorized dispatch |
| `src/server/authentication.rs` | Bounded Argon2 scheduling, cancellation, and request resumption |
| `src/connection.rs` | Per-client QUIC/H3 state and deferred sends |
| `src/net/quic.rs` | QUIC UDP receive/send batching, GSO/GRO, and portable fallbacks |
| `src/net/target_udp.rs` | Batched target UDP I/O and truncation detection |
| `src/tunnel/tcp.rs` | TCP connection setup and bounded bidirectional relay |
| `src/tunnel/udp.rs` | Per-target CONNECT-UDP state and send staging |
| `src/tunnel/ip.rs` | CONNECT-IP assignment and activity state |
| `src/capsule/` | Capsule Protocol encoding and incremental decoding |
| `src/datagram.rs` | HTTP Datagram framing and Context ID handling |
| `src/scheduler.rs` | Dirty-connection and deadline scheduling |
| `src/auth.rs` | Basic credential parsing and Argon2id verification |
| `src/policy.rs` | CIDR target allow/deny decisions |
| `src/tun.rs` | Linux TUN creation and offloaded packet batches |
| `src/address_pool.rs` | CONNECT-IP address allocation |
| `src/routing.rs` | Assigned-address to tunnel ownership mapping |

The primary server remains one crate so release LTO can optimize across the
QUIC, scheduler, and tunnel boundary. Platform-specific network code is a
module boundary rather than a crate boundary.

## Event loop

Each shard waits directly on all sources that can make progress:

- QUIC socket readability;
- target UDP response batches;
- TCP relay events;
- completed authentication;
- forwarded packets from another shard;
- TUN packets; and
- the nearest QUIC, pacing, or housekeeping deadline.

Target UDP readability participates directly in the wakeup path. It is not
polled by a coarse periodic timer, so idle-to-active traffic does not inherit a
timer-sized latency penalty.

When work arrives, only affected connections enter the dirty set. The shard
drives those connections, stages output using quiche's send quantum, emits a
bounded UDP batch, and reschedules their next deadlines.

## Listeners and sharding

`shards = N` on a listener creates N independent event loops on that listener's
address using `SO_REUSEPORT`. The kernel normally keeps a client 4-tuple on one
of them.

QUIC permits address migration, so a packet can arrive on a shard that does
not own its connection. A shared connection-ID registry identifies the owner,
and the receiving shard forwards the packet through a bounded channel. TUN
input uses the same ownership model. This keeps connection state single-owner
without dropping legitimate migration traffic.

One connection still uses one shard. Sharding improves aggregate throughput
across multiple connections; it cannot parallelize a single QUIC connection.

`[[listeners]]` runs several listeners in one process. Each is materialized
into its own `ServerConfig`, so a shard reads one listener's settings and never
has to know it is one listener among several; the multi-listener change does
not reach the request or packet paths. The authentication mode is the reason
this exists: `auth.mode` decides which TLS context `build_quic_config` returns,
and that is fixed when the socket binds.

Shards are numbered across the whole server rather than within a listener,
which is what lets the cross-shard queues, the connection-ID registry, and the
TUN ownership map stay single and listener-agnostic. Everything in `Shared` is
server-wide: the address pool, the routing table, the TUN device, the client
roster, and the credential-verification budget. A forwarded packet is re-handled
by its owner using that shard's own local address, so a reply always leaves the
socket the connection actually lives on — including when the owner belongs to a
different listener.

One shard reads the TUN device and distributes packets to the connections that
own their addresses. Shard 0 is an arbitrary but stable choice, unrelated to
which listener it serves.

## Authentication pipeline

Credential processing is split into two stages:

1. The shard synchronously validates the request shape, Basic scheme, username,
   encoded length, and configured authentication state.
2. Argon2id verification runs on Tokio's blocking pool under shared permits.

The queue has a global bound as well as a per-connection bound. A request must
reserve a global slot before a task is spawned. Reset streams and closed
connections abort waiting tasks and mark running work cancelled; an Argon2
invocation already executing cannot be interrupted, but concurrency remains
bounded and its result is discarded.

Only a compact pending request is retained while authentication completes.
Target resolution, sockets, TUN addresses, and tunnel buffers are allocated
after successful verification.

## Tunnel data paths

### Standard CONNECT

After authorization and policy checks, a background task resolves and connects
to the TCP target. Request-body bytes and target responses use bounded queues.
The target reader waits for acknowledgement from the shard before reusing
buffer capacity, carrying HTTP/3 flow control back to the upstream socket.
A failure resets only the affected stream.

### CONNECT-UDP

One connected UDP socket is created per tunnel. Client datagrams are decoded,
staged during an event-loop round, and sent to the target in one `sendmmsg`
call on Linux. A background readiness task drains target responses with
`recvmmsg` and sends a bounded batch to the owning shard.

Receive buffers are sized from the configured maximum QUIC datagram size plus
one sentinel byte. Linux also checks `MSG_TRUNC`; the sentinel makes oversized
datagrams detectable on platforms that do not expose truncation flags through
the portable socket API.

### CONNECT-IP

The server allocates IPv4/IPv6 addresses, publishes them through
`ADDRESS_ASSIGN`, and advertises routes with `ROUTE_ADVERTISEMENT`. Client
packets are accepted only when their source matches the tunnel assignment.
A shared routing table maps return traffic to the owning connection and shard.

CONNECT-IP requires Linux TUN support and `CAP_NET_ADMIN`. With TUN offload,
the file descriptor carries virtio headers and GSO aggregates; setup falls back
when the kernel rejects the feature.

## Linux UDP fast path

QUIC output first groups adjacent equal-size packets up to quiche's send
quantum. With UDP GSO enabled, one message can describe several UDP segments;
`sendmmsg` then submits several messages in one syscall. Receive uses
`recvmmsg`, and UDP GRO aggregates are split back into logical QUIC packets.

Release binaries are musl linked. The 64-bit musl `sendmmsg` wrapper loops over
`sendmsg`, so the Linux send adapters invoke `SYS_sendmmsg` directly. Header
and control arrays are zero-initialized, including the padding required by the
musl userspace/kernel ABI. This preserves real kernel batching in static
binaries.

## Resource bounds and failure model

- Connections and tunnels are capped by configuration.
- QUIC DATAGRAM queues are bounded by configuration.
- Authentication work has global, per-connection, and concurrent limits.
- Cross-shard, target-response, and TCP-event channels are bounded.
- TCP tunnel buffers have compile-time caps and backpressure.
- UDP partial sends and full queues cause logged datagram loss, not retries
  without a bound.
- Malformed or failed tunnel setup returns an HTTP error when possible.
- Relay failure closes the affected stream; transport failure closes the
  connection; listener failure stops the shard.

These bounds are part of correctness. Changes that replace a bound with an
implicitly growing `Vec`, task queue, or channel require explicit review.
