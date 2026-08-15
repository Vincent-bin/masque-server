# MASQUE Server — Design Document

## 1. Protocol Overview

MASQUE (Multiplexed Application Substrate over QUIC Encryption) is an IETF
protocol framework that enables transport proxying over HTTP/3 + QUIC. This
server implements the following RFCs:

| RFC   | Title                            | Role                         |
|-------|----------------------------------|------------------------------|
| 9297  | HTTP Datagrams & Capsule Protocol | Datagram transport layer     |
| 9298  | Proxying UDP in HTTP             | CONNECT-UDP tunnelling       |
| 9484  | Proxying IP in HTTP              | CONNECT-IP tunnelling        |

### Protocol Stack

```
┌─────────────────────────────────────────────┐
│           CONNECT-UDP / CONNECT-IP          │  Application tunnels
├─────────────────────────────────────────────┤
│           HTTP Datagrams (RFC 9297)         │  Context-ID multiplexing
├─────────────────────────────────────────────┤
│           HTTP/3 (Extended CONNECT)         │  Request/response framing
├─────────────────────────────────────────────┤
│           QUIC (RFC 9000/9001)              │  Encrypted transport
├─────────────────────────────────────────────┤
│           UDP                               │  Network layer
└─────────────────────────────────────────────┘
```

Clients establish an HTTP/3 connection to the proxy, then issue Extended
CONNECT requests with `:protocol` set to `connect-udp` or `connect-ip`. The
proxy relays traffic between the HTTP/3 stream (or QUIC DATAGRAM frames) and
the target network.

---

## 2. Architecture

### Module Structure

```
src/
├── main.rs              # CLI entry point, signal handling
├── config.rs            # Configuration loading (TOML + CLI)
├── server.rs            # QUIC listener, connection accept loop
├── connection.rs        # Per-connection state machine & H3 event loop
├── tunnel/
│   ├── mod.rs           # Tunnel trait, shared types
│   ├── udp.rs           # CONNECT-UDP tunnel implementation
│   └── ip.rs            # CONNECT-IP tunnel implementation
├── capsule/
│   ├── mod.rs           # Capsule type definitions
│   ├── decoder.rs       # Incremental TLV decoder
│   └── encoder.rs       # Capsule encoder
├── datagram.rs          # HTTP Datagram framing (Context ID + payload)
├── tun.rs               # TUN device management, address pool, routing
└── error.rs             # Error types with HTTP status code mapping
```

### Key Types

```rust
/// Top-level server that owns the QUIC listener.
struct Server {
    quic_config: quiche::Config,
    h3_config: quiche::h3::Config,
    socket: UdpSocket,
    connections: HashMap<ConnectionId, ClientConnection>,
    tun_manager: TunManager,          // shared across CONNECT-IP tunnels
    config: ServerConfig,
}

/// Per-client QUIC + HTTP/3 connection state.
struct ClientConnection {
    quic_conn: quiche::Connection,
    h3_conn: Option<quiche::h3::Connection>,
    tunnels: HashMap<u64, Tunnel>,    // stream_id -> tunnel
    partial_reads: HashMap<u64, Vec<u8>>,
}

/// A single proxy tunnel, created per Extended CONNECT request.
enum Tunnel {
    Udp(UdpTunnel),
    Ip(IpTunnel),
}

/// CONNECT-UDP tunnel state.
struct UdpTunnel {
    stream_id: u64,
    target_socket: UdpSocket,         // proxy-side socket to target
    target_addr: SocketAddr,
    last_activity: Instant,
}

/// CONNECT-IP tunnel state.
struct IpTunnel {
    stream_id: u64,
    assigned_addrs: Vec<IpPrefix>,    // addresses assigned to client
    routes: Vec<RouteEntry>,          // advertised routes
    tun_handle: TunHandle,            // reference to shared TUN device
}
```

### Data Flow — CONNECT-UDP

```
Client App          MASQUE Proxy               Target Server
    │                    │                          │
    │── QUIC CONNECT ──>│                          │
    │   :protocol=       │                          │
    │   connect-udp      │                          │
    │<── 200 OK ────────│                          │
    │                    │── bind UDP socket ──────>│
    │                    │                          │
    │== DATAGRAM ======>│                          │
    │  [QID][CID=0]     │── UDP packet ──────────>│
    │  [UDP payload]     │                          │
    │                    │<── UDP packet ──────────│
    │<== DATAGRAM ======│                          │
    │  [QID][CID=0]     │                          │
    │  [UDP payload]     │                          │
```

### Data Flow — CONNECT-IP

```
Client App          MASQUE Proxy               Network
    │                    │                        │
    │── QUIC CONNECT ──>│                        │
    │   :protocol=       │                        │
    │   connect-ip       │                        │
    │<── 200 OK ────────│                        │
    │                    │                        │
    │<── ADDRESS_ASSIGN  │  (capsule on stream)   │
    │<── ROUTE_ADVERT    │                        │
    │                    │                        │
    │== DATAGRAM ======>│                        │
    │  [QID][CID=0]     │── IP packet ─────────>│  (via TUN)
    │  [IP packet]       │                        │
    │                    │<── IP packet ─────────│
    │<== DATAGRAM ======│                        │
```

---

## 3. CONNECT-UDP Flow (RFC 9298)

### URI Template

The server exposes a configurable URI template. Default:

```
https://{host}:{port}/.well-known/masque/udp/{target_host}/{target_port}/
```

### Request Handling

1. Client sends Extended CONNECT with `:protocol = connect-udp`.
2. Server extracts `target_host` and `target_port` from the `:path`.
3. Server validates the target against an allow/deny list.
4. Server binds a local UDP socket and connects it to `target_host:target_port`.
5. Server responds with HTTP 200 and `Capsule-Protocol: ?1` header.
6. Tunnel enters the relay phase.

### Datagram Relay

- **Client → Target**: Receive QUIC DATAGRAM frame, strip Quarter Stream ID,
  parse Context ID (must be 0 for UDP payload), forward raw UDP payload via the
  bound socket.
- **Target → Client**: Receive UDP packet from the bound socket, prepend Context
  ID = 0, wrap in QUIC DATAGRAM frame with the tunnel's Quarter Stream ID, send
  to client.

### Capsule Fallback

If the client does not negotiate QUIC DATAGRAM support
(`SETTINGS_H3_DATAGRAM`), payloads are sent as `DATAGRAM` capsules (type 0x00)
on the request stream using the Capsule Protocol.

### Inactivity Timeout

Each tunnel tracks `last_activity`. If no datagram is relayed in
`idle_timeout` seconds (configurable, default 30s), the server closes the
stream with `H3_NO_ERROR`.

### Error Responses

| Condition                          | HTTP Status |
|------------------------------------|-------------|
| Malformed URI / missing variables  | 400         |
| Target host in deny list           | 403         |
| DNS resolution failure             | 502         |
| UDP socket bind failure            | 502         |
| Upstream unreachable               | 504         |

---

## 4. CONNECT-IP Flow (RFC 9484)

### URI Template

```
https://{host}:{port}/.well-known/masque/ip/{target}/{ipproto}/
```

`target` and `ipproto` are optional. When absent, the tunnel carries all IP
traffic (full VPN mode).

### Request Handling

1. Client sends Extended CONNECT with `:protocol = connect-ip`.
2. Server parses optional `target` (IP prefix) and `ipproto` (protocol number
   or `*`).
3. Server validates the request against policy.
4. Server responds with HTTP 200 and `Capsule-Protocol: ?1`.
5. Server sends capsules to configure the client's network:
   - `ADDRESS_ASSIGN` — assign IP addresses to the client.
   - `ROUTE_ADVERTISEMENT` — advertise reachable routes.
6. Tunnel enters the relay phase.

### Capsule Types

#### ADDRESS_REQUEST (0x02) — Client → Proxy

```
ADDRESS_REQUEST {
  Assigned Address (..) {
    Request ID (i),
    IP Version (8),          // 4 or 6
    IP Address (32..128),    // 4 bytes for v4, 16 bytes for v6
    IP Prefix Length (8),
  }
}
```

#### ADDRESS_ASSIGN (0x01) — Proxy → Client

Same wire format as ADDRESS_REQUEST. Request ID = 0 for server-initiated
assignments. An empty capsule withdraws all previously assigned addresses.

#### ROUTE_ADVERTISEMENT (0x03) — Proxy → Client

```
ROUTE_ADVERTISEMENT {
  IP Address Range (..) {
    IP Version (8),
    Start IP Address (32..128),
    End IP Address (32..128),
    IP Protocol (8),         // 0 = all protocols
  }
}
```

Ranges must be non-overlapping and sorted.

### IP Packet Relay

- **Client → Network**: Receive QUIC DATAGRAM (Context ID = 0), extract raw IP
  packet, validate source address matches assigned address, write to TUN device.
- **Network → Client**: Read IP packet from TUN device, match destination
  against assigned client addresses, wrap in QUIC DATAGRAM with Context ID = 0,
  send to client.

### Address Pool

The server maintains an IP address pool (configurable CIDR range, e.g.
`10.89.0.0/16` for IPv4, `fd00::/64` for IPv6). Each CONNECT-IP tunnel is
assigned one or more addresses from this pool. Addresses are returned to the
pool when the tunnel is torn down.

---

## 5. Capsule Protocol (RFC 9297)

### Wire Format (TLV)

```
Capsule {
  Type   (variable-length integer),
  Length (variable-length integer),
  Value  (Length bytes),
}
```

Variable-length integers use QUIC encoding (RFC 9000, Section 16): 1, 2, 4, or
8 bytes depending on value magnitude.

### Known Capsule Types

| Type ID | Name              | Direction       |
|---------|-------------------|-----------------|
| 0x00    | DATAGRAM          | bidirectional   |
| 0x01    | ADDRESS_ASSIGN    | proxy → client  |
| 0x02    | ADDRESS_REQUEST   | client → proxy  |
| 0x03    | ROUTE_ADVERTISEMENT | proxy → client|

Unknown capsule types must be silently ignored (forward compatibility).

### Incremental Decoder

The decoder handles partial reads from the HTTP/3 stream:

```rust
struct CapsuleDecoder {
    state: DecodeState,
    buf: BytesMut,
}

enum DecodeState {
    ReadingType,
    ReadingLength { capsule_type: u64 },
    ReadingValue  { capsule_type: u64, remaining: u64 },
}

enum CapsuleFrame {
    Datagram(Bytes),
    AddressAssign(Vec<AssignedAddress>),
    AddressRequest(Vec<RequestedAddress>),
    RouteAdvertisement(Vec<IpAddressRange>),
    Unknown { capsule_type: u64, value: Bytes },
}
```

The decoder is called each time `h3_conn.recv_body()` returns data. It
accumulates bytes in `buf` and yields zero or more `CapsuleFrame` values per
call.

### Encoder

```rust
fn encode_capsule(capsule: &CapsuleFrame, buf: &mut Vec<u8>);
```

Serialises a capsule into TLV format. The caller writes the result to the
stream via `h3_conn.send_body()`.

---

## 6. HTTP Datagram Handling (RFC 9297)

### QUIC DATAGRAM Frame Layout

```
QUIC DATAGRAM Frame {
  Quarter Stream ID (i),    // stream_id / 4
  Context ID (i),           // 0 for UDP/IP payload
  Payload (..),
}
```

`Quarter Stream ID` identifies which HTTP/3 request stream the datagram belongs
to. Only client-initiated bidirectional streams are valid (stream IDs divisible
by 4).

### Context ID

- `0` — Raw UDP payload (CONNECT-UDP) or raw IP packet (CONNECT-IP).
- Even non-zero — allocated by the client for extensions.
- Odd non-zero — allocated by the proxy for extensions.

This server only handles Context ID 0 in the initial implementation. Unknown
Context IDs are silently dropped.

### Datagram Dispatching

On receiving a QUIC DATAGRAM (`quic_conn.dgram_recv()`):

1. Parse the Quarter Stream ID → `stream_id = qid * 4`.
2. Look up the `Tunnel` in `ClientConnection::tunnels[stream_id]`.
3. Parse the Context ID from the remaining payload.
4. If Context ID = 0, forward the payload to the tunnel's target.
5. Otherwise, drop silently.

### Sending Datagrams

To send a datagram back to the client:

1. Encode: `[Quarter Stream ID][Context ID = 0][payload]`.
2. Call `quic_conn.dgram_send(&encoded)`.
3. If the send queue is full, either buffer briefly or drop (UDP semantics
   tolerate loss).

### SETTINGS_H3_DATAGRAM

The server advertises `SETTINGS_H3_DATAGRAM = 1` (setting ID `0x33`) in its
HTTP/3 SETTINGS frame. This is required before sending or receiving QUIC
DATAGRAM frames. Check `h3_conn.dgram_enabled_by_peer()` before using the
datagram path.

---

## 7. TUN Device Integration (CONNECT-IP only)

### Shared TUN Device

A single TUN device is created at server startup and shared across all
CONNECT-IP tunnels. This avoids per-tunnel device overhead and simplifies
routing.

```rust
struct TunManager {
    device: AsyncDevice,              // tun-rs async TUN device
    address_pool: AddressPool,        // manages IP address allocation
    routing_table: RoutingTable,      // maps dest IP → stream owner
}

struct AddressPool {
    v4_range: Ipv4Net,                // e.g. 10.89.0.0/16
    v6_range: Ipv6Net,                // e.g. fd00::/64
    allocated: HashSet<IpAddr>,
}

struct RoutingTable {
    /// Maps a client-assigned IP to (connection_id, stream_id) for
    /// routing inbound TUN packets back to the correct tunnel.
    entries: HashMap<IpAddr, (ConnectionId, u64)>,
}
```

### Outbound (Client → Network)

1. Receive IP packet from client via QUIC DATAGRAM.
2. Validate source IP matches the tunnel's assigned address.
3. Write packet to TUN device via `device.send()`.
4. The kernel routes the packet normally.

### Inbound (Network → Client)

1. Read IP packet from TUN device via `device.recv()`.
2. Extract destination IP from the packet header.
3. Look up `(connection_id, stream_id)` in the routing table.
4. Wrap the packet in a QUIC DATAGRAM with the correct Quarter Stream ID.
5. Send to the client.

### MTU Considerations

The TUN device MTU must account for QUIC + HTTP/3 overhead:

```
TUN MTU = QUIC max_datagram_size
        - QUIC DATAGRAM frame overhead (~3 bytes)
        - Quarter Stream ID (1-8 bytes varint)
        - Context ID (1 byte for ID=0)
```

A typical value: if QUIC path MTU is 1200 bytes, TUN MTU ≈ 1180 bytes.

### Cleanup

When a CONNECT-IP tunnel closes:

1. Remove the client's address from the routing table.
2. Return the assigned IP addresses to the address pool.
3. Optionally remove host routes from the kernel.

---

## 8. Error Handling

### Error Type Hierarchy

```rust
#[derive(Debug, thiserror::Error)]
enum MasqueError {
    // Transport layer
    #[error("QUIC error: {0}")]
    Quic(#[from] quiche::Error),

    #[error("HTTP/3 error: {0}")]
    H3(#[from] quiche::h3::Error),

    // Tunnel layer
    #[error("Invalid URI template path: {0}")]
    BadRequest(String),

    #[error("Target denied by policy: {0}")]
    Forbidden(String),

    #[error("DNS resolution failed for {host}: {source}")]
    DnsResolution { host: String, source: std::io::Error },

    #[error("Upstream connection failed: {0}")]
    UpstreamConnect(std::io::Error),

    // Capsule layer
    #[error("Malformed capsule: {0}")]
    CapsuleDecode(String),

    // TUN layer
    #[error("TUN device error: {0}")]
    Tun(std::io::Error),

    #[error("Address pool exhausted")]
    AddressPoolExhausted,

    // I/O
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
```

### HTTP Status Code Mapping

```rust
impl MasqueError {
    fn http_status(&self) -> u16 {
        match self {
            Self::BadRequest(_) | Self::CapsuleDecode(_) => 400,
            Self::Forbidden(_)                           => 403,
            Self::DnsResolution { .. }                   => 502,
            Self::UpstreamConnect(_)                     => 502,
            Self::AddressPoolExhausted                   => 503,
            _                                            => 500,
        }
    }
}
```

### Strategy

- **Transport errors** (QUIC/H3): Log and drop the connection. These are
  unrecoverable at the application level.
- **Tunnel setup errors**: Respond with the appropriate HTTP error status before
  the tunnel enters relay mode.
- **Relay errors**: Log and close the individual stream. Do not tear down the
  entire QUIC connection — other tunnels on the same connection may be healthy.
- **TUN errors**: Log and close the affected CONNECT-IP tunnel. The TUN device
  itself is shared and should remain operational.

---

## 9. Configuration

### TOML Config File (`masque.toml`)

```toml
[server]
listen_addr = "0.0.0.0:443"
idle_timeout_secs = 30            # per-tunnel inactivity timeout
max_connections = 10000
max_tunnels_per_connection = 100

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
enable_dgram = true               # QUIC DATAGRAM extension
enable_udp_gso = false            # opt in after verifying the Linux egress path
enable_udp_gro = true             # Linux UDP generic receive offload

[udp_proxy]
enabled = true
uri_template = "/.well-known/masque/udp/{target_host}/{target_port}/"
allow_targets = ["0.0.0.0/0"]     # CIDR allow list
deny_targets = ["127.0.0.0/8", "10.0.0.0/8", "::1/128"]

[ip_proxy]
enabled = true
uri_template = "/.well-known/masque/ip/{target}/{ipproto}/"
tun_name = "masque0"
tun_mtu = 1280
ipv4_pool = "10.89.0.0/16"
ipv6_pool = "fd00:masq::/64"
```

### CLI Overrides

```
masque-server [OPTIONS]
masque-server hash-password

OPTIONS:
  -c, --config <PATH>       Config file path [default: masque.toml]
  -l, --listen <ADDR:PORT>  Override listen address
      --cert <PATH>         TLS certificate path
      --key <PATH>          TLS private key path
  -v, --verbose             Increase log verbosity (repeatable)
```

CLI flags override the corresponding TOML values. Environment variables are
**not** supported in the initial version to keep the configuration surface
small.

---

## 10. Dependencies

| Crate          | Version | Purpose                                    |
|----------------|---------|--------------------------------------------|
| `quiche`       | 0.29    | QUIC transport + HTTP/3 + DATAGRAM frames  |
| `argon2`       | 0.5     | Argon2id proxy password hashing             |
| `base64`       | 0.22    | RFC 7617 Basic credential decoding          |
| `tokio`        | 1       | Async runtime, UDP sockets, timers         |
| `tun-rs`       | latest  | TUN device creation and async I/O          |
| `clap`         | 4       | CLI argument parsing                       |
| `toml`         | 0.8+    | Config file parsing                        |
| `serde`        | 1       | Serialization for config structs           |
| `thiserror`    | 2       | Derive macro for error types               |
| `tracing`      | 0.1     | Structured logging                         |
| `tracing-subscriber` | 0.3 | Log output formatting                   |
| `ring`         | —       | Pulled in by quiche for TLS (BoringSSL)    |
| `bytes`        | 1       | Efficient byte buffer management           |
| `ipnet`        | 2       | CIDR / IP prefix types                     |

### Why `quiche` (not `quinn` + `h3`)?

- `quiche` is a battle-tested, sans-I/O implementation from Cloudflare that
  natively supports QUIC DATAGRAM frames and HTTP/3 Extended CONNECT.
- It gives full control over the event loop, which is essential for
  multiplexing tunnel I/O with TUN device I/O.
- `quinn` + `h3` would work but adds an extra abstraction layer that makes
  low-level datagram handling harder.

### Why not `tokio-quiche`?

`tokio-quiche` provides an opinionated actor model that is designed for
Cloudflare's internal use. For this project, we build a thinner async wrapper
directly over `quiche` + `tokio::net::UdpSocket` + `mio` polling, which gives
more control over the connection loop and avoids coupling to Cloudflare's
internal abstractions. This can be revisited if `tokio-quiche` stabilises its
public API.

---

## 11. Implementation Phases

### Phase 1: QUIC + HTTP/3 Skeleton

- Accept QUIC connections on a UDP socket.
- Complete the TLS handshake (server certificate).
- Drive the `quiche` event loop with `tokio`.
- Handle basic HTTP/3 requests (return 404 for everything).
- Advertise `SETTINGS_H3_DATAGRAM = 1` and Extended CONNECT support.

**Deliverable**: A server that accepts HTTP/3 connections and logs requests.

### Phase 2: CONNECT-UDP

- Parse the URI template and extract `target_host` / `target_port`.
- Respond to Extended CONNECT with `connect-udp` protocol.
- Bind a UDP socket to the target and relay datagrams bidirectionally.
- Implement the HTTP Datagram framing (Quarter Stream ID + Context ID).
- Add idle timeout and stream cleanup.
- Add allow/deny target filtering.

**Deliverable**: A working UDP proxy (e.g., proxying DNS queries).

### Phase 3: Capsule Protocol

- Implement the incremental TLV decoder and encoder.
- Support `DATAGRAM` capsule (type 0x00) as a fallback when QUIC DATAGRAMs are
  not negotiated.
- Parse `ADDRESS_REQUEST`, encode `ADDRESS_ASSIGN` and `ROUTE_ADVERTISEMENT`.

**Deliverable**: Capsule codec with unit tests.

### Phase 4: CONNECT-IP

- Create and configure a shared TUN device at startup.
- Implement the address pool and routing table.
- Handle Extended CONNECT with `connect-ip` protocol.
- Send `ADDRESS_ASSIGN` and `ROUTE_ADVERTISEMENT` capsules after tunnel setup.
- Relay IP packets between QUIC DATAGRAMs and the TUN device.
- Validate source addresses on client packets.

**Deliverable**: A working IP proxy (full VPN mode).

### Phase 5: Hardening

- Comprehensive integration tests (use `quiche` client).
- Fuzz the capsule decoder.
- Rate limiting and connection limits.
- Graceful shutdown (GOAWAY frame, drain tunnels).
- Metrics and observability (Prometheus endpoint or `tracing` spans).
- Documentation and usage examples.

**Deliverable**: Production-ready server.

---

## References

- [RFC 9297 — HTTP Datagrams and the Capsule Protocol](https://www.rfc-editor.org/rfc/rfc9297)
- [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298)
- [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484)
- [RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9114 — HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)
- [quiche — Cloudflare's QUIC and HTTP/3 library](https://github.com/cloudflare/quiche)
- [tun-rs — Cross-platform TUN device library](https://crates.io/crates/tun-rs)
