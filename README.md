# masque

A MASQUE proxy server in Rust implementing standard CONNECT, CONNECT-UDP
(RFC 9298), and CONNECT-IP (RFC 9484) over HTTP/3.

## Overview

MASQUE (Multiplexed Application Substrate over QUIC Encryption) is an IETF protocol framework for transport proxying over HTTP/3 + QUIC. This server supports:

- **CONNECT-UDP** — proxy UDP traffic through the server (e.g. DNS, QUIC)
- **CONNECT-IP** — proxy IP traffic through the server (full VPN mode via TUN device)
- **Standard CONNECT** — proxy TCP byte streams for HTTP/3 proxy clients
- **Capsule Protocol** (RFC 9297) — TLV framing for ADDRESS_ASSIGN, ROUTE_ADVERTISEMENT
- **HTTP Datagrams** — efficient datagram transport over QUIC DATAGRAM frames

Built on [quiche](https://github.com/cloudflare/quiche) (Cloudflare's QUIC/HTTP/3 library) and [tokio](https://tokio.rs) for async I/O.

## Architecture

```
src/
  main.rs            CLI entry point (clap)
  lib.rs             Module declarations
  auth.rs            HTTP Basic proxy authentication and Argon2id verification
  server.rs          QUIC listener, HTTP/3 event loop, tunnel management
  connection.rs      Per-client connection state
  config.rs          TOML configuration parsing
  error.rs           Error types with HTTP status mapping
  varint.rs          QUIC variable-length integer codec (RFC 9000)
  datagram.rs        HTTP Datagram framing (Quarter Stream ID + Context ID)
  uri.rs             Target parser for CONNECT / CONNECT-UDP / CONNECT-IP
  policy.rs          Allow/deny target filtering by CIDR
  capsule/
    mod.rs           Capsule frame types and constants
    encoder.rs       TLV serializer
    decoder.rs       Incremental TLV parser
  tunnel/
    mod.rs
    tcp.rs           Standard CONNECT tunnel with bounded backpressure
    udp.rs           CONNECT-UDP tunnel (per-target UDP socket)
    ip.rs            CONNECT-IP tunnel (assigned addresses, activity tracking)
  address_pool.rs    IPv4/IPv6 address allocation from CIDR pools
  routing.rs         Destination IP to tunnel routing table
  ip_packet.rs       Minimal IPv4/IPv6 header parser
  tun.rs             TUN device manager (tun-rs)
docs/
  design.md          Comprehensive design document
```

## Building

```sh
cargo build --release
```

### Linux x86_64 release package

GitHub Actions builds a static `x86_64-unknown-linux-musl` archive on every
`v*` tag and attaches it to the corresponding GitHub Release. It can also be
run manually from the Actions page to produce a workflow artifact.

```sh
git tag v0.1.0
git push origin v0.1.0
```

On the Linux host, extract the archive and install the binary, example config,
and systemd unit:

```sh
tar xzf masque-v0.1.0-linux-x86_64.tar.gz
cd masque-v0.1.0-linux-x86_64
sudo ./install.sh
```

For a new installation, the installer enables HTTP proxy authentication and
prints a randomly generated `masque` password once. Set
`MASQUE_AUTH_USERNAME` and `MASQUE_AUTH_PASSWORD` when invoking the installer
to supply credentials instead. When upgrading a configuration without an
`[auth]` section, the installer preserves the existing settings, saves a
`masque.toml.before-auth` backup, and adds generated credentials.

Then install the TLS certificate and private key under `/etc/masque/certs/`,
review `/etc/masque/masque.toml`, and start the service with
`sudo systemctl start masque`.

### Dependencies

- Rust 2024 edition
- quiche 0.29.3 (requires BoringSSL — built automatically by quiche)
- tun-rs 2 (TUN device support, requires Linux `CAP_NET_ADMIN` for CONNECT-IP)
- tokio 1 (async runtime)

On Linux, the QUIC listener automatically uses `recvmmsg`/`sendmmsg` and UDP
GRO. UDP GSO is available as an opt-in optimization because some virtual NICs
advertise support but silently drop GSO traffic on their external path. Enable
`quic.enable_udp_gso` only after an end-to-end A/B test. Other platforms use
the portable Tokio UDP path.

## Usage

```sh
# With a config file
masque-server -c masque.toml

# With CLI overrides
masque-server --listen 0.0.0.0:8443 --cert certs/server.crt --key certs/server.key

# Increase log verbosity
masque-server -vv

# Generate an Argon2id PHC hash for auth.password_hash (reads stdin)
printf '%s' 'a-strong-password' | masque-server hash-password
```

### Configuration

The server reads a TOML config file (default: `masque.toml`). Sections use
sensible defaults, but proxy credentials must be configured unless
authentication is explicitly disabled:

```toml
[server]
listen_addr = "0.0.0.0:443"
idle_timeout_secs = 30
max_connections = 10000
max_tunnels_per_connection = 100
shards = 1

[tls]
cert_path = "certs/server.crt"
key_path = "certs/server.key"

[auth]
enabled = true
username = "masque"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."

[quic]
max_datagram_size = 1350
initial_max_streams_bidi = 128
enable_dgram = true
enable_udp_gso = false
enable_udp_gro = true
cc_algorithm = "cubic"
initial_congestion_window_packets = 32
initial_max_data = 16777216
initial_max_stream_data = 4194304
max_connection_window = 25165824
max_stream_window = 16777216
dgram_recv_queue_len = 2048
dgram_send_queue_len = 2048
discover_pmtu = false

[tcp_proxy]
enabled = true
connect_timeout_secs = 10
allow_targets = ["0.0.0.0/0", "::/0"]
deny_targets = ["127.0.0.0/8", "10.0.0.0/8", "::1/128"]

[udp_proxy]
enabled = true
uri_template = "/.well-known/masque/udp/{target_host}/{target_port}/"
allow_targets = ["0.0.0.0/0"]
deny_targets = ["127.0.0.0/8", "10.0.0.0/8", "::1/128"]

[ip_proxy]
enabled = true
uri_template = "/.well-known/masque/ip/{target}/{ipproto}/"
tun_name = "masque0"
tun_mtu = 1280
tun_offload = true
ipv4_pool = "10.89.0.0/16"
ipv6_pool = "fd00:abcd::/64"
```

Authentication is fail-closed by default: when `auth.enabled = true`, the
server refuses to start unless the username is valid and `password_hash` is a
valid Argon2id PHC string. Clients authenticate each CONNECT request with
`Proxy-Authorization: Basic ...`; missing or invalid credentials receive
`407 Proxy Authentication Required`. Set `auth.enabled = false` only for an
isolated development environment.

### Performance tuning

The `[quic]` defaults are tuned for a proxy carrying bulk transfers over paths
it does not control. The knobs worth revisiting per deployment:

| Setting | Default | When to change it |
| --- | --- | --- |
| `cc_algorithm` | `cubic` | `bbr2` and `reno` are accepted, but **bbr2 is currently much slower here** — see the note below. |
| `initial_congestion_window_packets` | `32` | Lower to the IETF-default `10` on links where a 32-packet initial burst causes loss. |
| `initial_max_stream_data` | 4 MiB | A single CONNECT stream is capped at this ÷ RTT until autotuning grows it. Raise for high bandwidth-delay paths. |
| `max_stream_window` / `max_connection_window` | 16 / 24 MiB | These are the autotuning ceilings, and the bound on per-connection receive memory. Lower them if `max_connections` × window exceeds your memory budget. |
| `dgram_recv_queue_len` / `dgram_send_queue_len` | 2048 | Raise if CONNECT-IP or CONNECT-UDP bursts are dropping datagrams; lower to cut latency under load. Datagrams are never retransmitted. |
| `enable_udp_gso` | `false` | Enable on physical NICs for a large send-path win. Some virtual NICs advertise GSO and then silently drop super-packets, which is why it is opt-in. |
| `server.shards` | `1` | Independent event loops, each on its own `SO_REUSEPORT` socket. Raise it (or set `0` for one per core) to let a busy server use more than one core — see below. Linux only. |
| `discover_pmtu` | `false` | Only useful together with a raised `max_datagram_size` (e.g. 1500), since probes stop at that value. |
| `ip_proxy.tun_offload` | `true` | Linux GSO/GRO on the TUN device. Turn off to rule it out when debugging CONNECT-IP; it falls back automatically if the kernel refuses `IFF_VNET_HDR`. |

Two per-tunnel buffers are compile-time constants rather than config, and they
bound the proxy's memory alongside `max_connections` × `max_tunnels_per_connection`:
a standard CONNECT tunnel holds up to 1 MiB of client-to-target data
(`MAX_BUFFERED_CLIENT_BYTES`) and up to 256 KiB of target-to-client data
(`MAX_BUFFERED_RESPONSE_BYTES`). The latter is what lets the target reader run
several 64 KiB chunks ahead of the event loop instead of stopping after each one.

Release builds use fat LTO and a single codegen unit, which matters because
the packet path spans this crate and quiche. `panic` stays at `unwind` on
purpose: relay tasks are spawned, so a panic in one tunnel stays contained
instead of aborting the whole proxy.

#### Sharding across cores

QUIC's per-packet crypto is what saturates a CPU, and a connection is always
handled by one event loop, so a single-loop server tops out at one core no
matter how many it has. `server.shards` runs N loops, each binding the listen
address with `SO_REUSEPORT`; the kernel hashes each 4-tuple to one of them.

Correctness details worth knowing:

- A client that changes address can have its packets steered to a shard that
  does not own the connection. Rather than dropping them, that shard looks the
  connection ID up in a shared registry and hands the packet to its owner, so
  migration keeps working without an eBPF steering program.
- The TUN device is read by shard 0 only; CONNECT-IP packets for connections
  owned by other shards are routed to them. The address pool and routing table
  are shared behind locks that are never taken on the per-packet path.

Measured on a 4-core Ryzen 7940HS with 64 concurrent CONNECT-UDP connections at
64-byte payloads:

| | throughput | server CPU |
| --- | --- | --- |
| `shards = 1` | ~98k pkt/s | 88% of one core |
| `shards = 4` | ~121k pkt/s | **134%** of one core |

The CPU figure is the real result: a single-shard server is pinned below one
core however hard it is pushed, and a sharded one is not. The throughput
figure is *not* a clean scaling measurement — no load generator available here
could saturate four shards, and run-to-run variance was roughly ±15%. Expect
the win to matter only on a server that is actually CPU-bound with many
concurrent connections, and measure your own traffic before raising it, which
is why the default is `1`.

#### Why not BBR2

A pacing-blocked connection holds back exactly one serialized packet
(`DeferredSend`) and waits for the event loop to reach its release time. BBR2
assigns a release time to every packet, so that structure limits the server to
roughly one packet per wakeup; quiche's CUBIC pacing releases in bursts and
mostly avoids the path. On a loopback CONNECT-UDP benchmark at 1200B:

| `cc_algorithm` | throughput | RTT p50 |
| --- | --- | --- |
| `cubic` | 127k pkt/s (1.23 Gbit/s) | 75 µs |
| `bbr2` | 34k pkt/s (0.33 Gbit/s) | 1228 µs |

BBR2 should be the better choice for a proxy on lossy paths, so this is a
limitation of the send path rather than of BBR2. Letting a pacing-blocked
connection retain a burst instead of a single packet is the fix; until then
`cubic` is the default.

## Protocol Flow

### Standard CONNECT (TCP)

1. Client sends an authenticated HTTP/3 `CONNECT` with the target in
   `:authority`
2. Server resolves the target and applies the TCP allow/deny policy
3. Server connects to the target and responds `200`
4. HTTP/3 request and response body bytes are relayed bidirectionally with
   bounded backpressure

### CONNECT-UDP

1. Client sends authenticated Extended CONNECT with `:protocol = connect-udp`
2. Server validates proxy credentials before allocating tunnel resources
3. Server parses URI template, checks target against allow/deny policy
4. Server responds `200` with `Capsule-Protocol: ?1`
5. Client/server exchange UDP payloads via QUIC DATAGRAM frames
6. Server relays datagrams to/from the target UDP socket

### CONNECT-IP

1. Client sends authenticated Extended CONNECT with `:protocol = connect-ip`
2. Server validates proxy credentials before allocating tunnel resources
3. Server responds `200`, allocates IPv4 + IPv6 addresses from pool
4. Server sends `ADDRESS_ASSIGN` capsule with assigned addresses
5. Server sends `ROUTE_ADVERTISEMENT` capsule with default routes
6. Client/server exchange IP packets via QUIC DATAGRAM frames
7. Server validates source addresses and relays through a shared TUN device

## Testing

```sh
cargo test
```

The test suite covers protocol codecs, address management, routing, configuration,
and end-to-end tunnel behavior.

### Benchmarks

Run the allocation and codec microbenchmarks in release mode:

```sh
cargo bench --bench core
```

Run the loopback CONNECT-UDP latency and throughput benchmark:

```sh
scripts/network-bench.sh
```

The network benchmark builds release binaries and reports both a direct Rust
UDP echo baseline and the MASQUE path, so echo-server or load-generator limits
are visible. Its duration, in-flight window, response-expiry interval, and RTT
sample count can be tuned:

```sh
MASQUE_BENCH_DURATION_SECS=10 \
MASQUE_BENCH_WINDOW=256 \
MASQUE_BENCH_EXPIRY_MS=1000 \
MASQUE_BENCH_RTT_SAMPLES=100 \
scripts/network-bench.sh
```

For a high-latency or deliberately oversized-window test, set
`MASQUE_BENCH_EXPIRY_MS` comfortably above the RTT plus expected queueing
delay. An expiry that is too short measures the benchmark's stale request
queue rather than the server's sustainable throughput.

## References

- [RFC 9297 — HTTP Datagrams and the Capsule Protocol](https://www.rfc-editor.org/rfc/rfc9297)
- [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298)
- [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484)
- [RFC 9000 — QUIC Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9114 — HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)

## License

MIT
