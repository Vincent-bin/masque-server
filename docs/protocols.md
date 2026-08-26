# Protocol behavior

## Standards

| Standard | Use |
| --- | --- |
| [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) | QUIC transport and variable-length integers |
| [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) | HTTP/2 streams and flow control |
| [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) | HTTP/3 request streams |
| [RFC 8441](https://www.rfc-editor.org/rfc/rfc8441) | HTTP/2 Extended CONNECT |
| [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297) | HTTP Datagrams and Capsule Protocol |
| [RFC 9298](https://www.rfc-editor.org/rfc/rfc9298) | CONNECT-UDP |
| [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484) | CONNECT-IP |
| [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617) | Basic authentication syntax |

An HTTP/3 listener negotiates an HTTP/3 ALPN through quiche and advertises QUIC
DATAGRAM plus Extended CONNECT. An HTTP/2 listener negotiates only the `h2`
ALPN over TCP/TLS and advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`.

## Authentication

With a listener's `auth.mode = "basic"`, every CONNECT form passes through the
same proxy authentication pipeline. The client supplies:

```text
Proxy-Authorization: Basic BASE64(username:password)
```

The server validates syntax, looks up the username in that listener's account
set, and snapshots only the matching Argon2id hash before scheduling password
verification. Missing or invalid credentials return:

```text
:status: 407
proxy-authenticate: Basic realm="masque", charset="UTF-8"
```

Authentication is per request, so one authenticated tunnel does not authorize
later streams that omit the header.

With a listener's `auth.mode = "client_cert"` there is no per-request step: the client is
identified once, from its TLS client certificate, during the TLS handshake. An
unregistered key never reaches the request path — it is refused with a TLS
`access_denied` alert. See
[Cloudflare-compatible clients](#cloudflare-compatible-clients).

## Standard CONNECT

The request uses `:method = CONNECT` and places the TCP destination in
`:authority` as `host:port`. It does not use `:protocol`.

After authentication, resolution, and policy checks, the server connects to
the target and returns `200`. Request-body bytes flow to the target and target
bytes flow in the response body. Either side's end-of-stream is relayed as a
half-close when possible. This behavior is the same over HTTP/2 and HTTP/3.

## CONNECT-UDP

The request contains:

```text
:method: CONNECT
:protocol: connect-udp
:scheme: https
:path: /.well-known/masque/udp/{target_host}/{target_port}/
```

The URI template is configurable but must expose both target variables. After
authentication, resolution, and UDP policy, a connected target socket is
created and the server returns `200` with `Capsule-Protocol: ?1`.

On HTTP/3, each HTTP Datagram starts with the request stream's Quarter Stream
ID followed by Context ID `0` and the UDP payload. QUIC does not retransmit a
lost datagram.

HTTP/2 has no native HTTP Datagram frame. The client must negotiate Capsule
Protocol with `Capsule-Protocol: ?1`; each request and response DATA stream then
carries RFC 9297 DATAGRAM capsules whose value is Context ID `0` followed by
the UDP payload. Those capsules inherit HTTP/2's reliable, ordered TCP delivery,
so this mode is for compatibility rather than maximum datagram performance.
Capsules are decoded incrementally and oversized declarations are rejected
before their values are buffered. Unknown capsule types are ignored. The same
stream fallback carries CONNECT-IP packets over HTTP/2.

## CONNECT-IP

The request contains a `:protocol` from `ip_proxy.connect_protocols` — the
registered `connect-ip`, or Cloudflare's `cf-connect-ip` — and follows the
configured URI template. A successful setup assigns addresses and returns `200`,
followed by:

- `ADDRESS_ASSIGN` capsules for assigned IPv4 and IPv6 addresses; and
- `ROUTE_ADVERTISEMENT` capsules for reachable prefixes.

Addresses come from the pool, unless the client authenticated with a certificate
whose `[[clients]]` entry pins them. A pinned client receives exactly its pinned
addresses and nothing from the pool. Reconnection may briefly overlap a stale
connection carrying the same enrolled key; the newest tunnel atomically takes
over the return route, while reference-counted leases keep later cleanup from
freeing an address that is still live.

IP packets use HTTP Datagrams with Context ID `0`. HTTP/3 sends them as QUIC
DATAGRAM frames; HTTP/2 sends the same payload inside DATAGRAM capsules on the
request/response DATA stream. Before writing a client packet to TUN, the server
checks the source address against the tunnel's assignment. Return packets are
routed only to the owning tunnel through transport-specific bounded queues.

CONNECT-IP depends on Linux TUN, host routing, and firewall configuration; the
HTTP transport does not configure NAT or upstream routes for the host. HTTP/2
improves reachability where UDP is blocked, but its ordered TCP stream can
head-of-line block unrelated IP packets after loss.

## Response status

| Status | Typical meaning |
| --- | --- |
| `200` | Tunnel established |
| `400` | Malformed headers, authority, URI, datagram, or capsule |
| `403` | Target rejected by policy or proxy type disabled |
| `404` | Request is not a supported CONNECT endpoint |
| `407` | Proxy credentials missing or invalid |
| `429` / `503` | Per-connection or global setup capacity exhausted |
| `502` | DNS, target socket, or upstream TCP setup failed |

Once a tunnel is established, relay errors normally reset that stream rather
than close every tunnel on the HTTP connection.

## Interoperability

Clients must support proxy CONNECT on the selected transport and the relevant
MASQUE extension. Standards-based HTTP/2 CONNECT-UDP and CONNECT-IP require
Extended CONNECT and Capsule Protocol support; an ordinary HTTP proxy client
is sufficient only for standard CONNECT. The additional Cloudflare-compatible
CONNECT-IP shape below is deliberately supported for deployed clients.
Configuration syntaxes in products such as Surge are client-specific and are
not part of the RFCs. Test authentication, target policy, TCP, UDP, and DNS
separately when qualifying a client.

## Cloudflare-compatible clients

VPN-style MASQUE clients modelled on Cloudflare WARP — for example
[usque](https://github.com/Diniboy1123/usque) and
[mihomo](https://wiki.metacubex.one/config/proxies/masque/) — diverge from
RFC 9484 in ways the server accommodates. Everything below is on by default
except the authentication mode.

**HTTP/3 `:protocol` is `cf-connect-ip`.** Cloudflare's endpoint uses that
instead of the registered `connect-ip`, and these clients send only it. Both are in
`ip_proxy.connect_protocols` by default. This is not optional: usque and mihomo
are independent implementations, and both were observed sending byte-identical
requests — `:protocol: cf-connect-ip`, `:authority: cloudflareaccess.com`,
`:path: /` — so a server accepting only `connect-ip` answers `404` to every
client in this family.

**HTTP/3 `:authority` and `:path` are fixed.** The request arrives as
`:authority: cloudflareaccess.com` and `:path: /`, with no URI Template
variables. The CONNECT-IP path ignores both, so `ip_proxy.uri_template` does not
apply to these clients.

**Authentication is a TLS client certificate.** No `Proxy-Authorization` is
ever sent, so a listener using `auth.mode = "basic"` refuses these clients with
`407`. Use `auth.mode = "client_cert"` on that listener and enroll each client's public key; see
[Authentication](configuration.md#authentication). To keep serving
standards-compliant clients at the same time, give each mode its own
[listener](configuration.md#listeners) — the mode fixes the TLS
context, so the two cannot share a socket, but they can share a process.

**The HTTP/2 fallback uses a separate deployed wire shape.** usque's `--http2`
mode sends an ordinary CONNECT with `cf-connect-proto: cf-connect-ip`, not an
Extended CONNECT `:protocol`. Its DATAGRAM capsule value contains the raw IP
packet and omits the otherwise mandatory Context ID zero. The server detects
that exact header and mirrors the framing on responses. Standards-based H2
CONNECT-IP remains available at the same time; it uses Extended CONNECT,
`Capsule-Protocol: ?1`, and retains Context ID zero.

Cloudflare's HTTP/3 service does not require clients to observe
`SETTINGS_ENABLE_CONNECT_PROTOCOL`; this server advertises the setting on both
HTTP transports where applicable.

**Addresses come from the client's own configuration, not from
`ADDRESS_ASSIGN`.** These clients send no address-control capsules; the client
learns its tunnel addresses from its config file and configures its interface
from those. Two consequences:

- The address must be pinned per client with `[[clients]].ipv4` / `.ipv6`, and
  the client's configuration must carry the same values. A pool-allocated
  address would leave the two sides disagreeing, and the server would drop every
  client packet as a spoofed source.
- `ADDRESS_ASSIGN` is still sent, and it must agree with the pinned addresses.
  These clients ignore it for interface configuration but do use it to filter
  inbound packets, so an address the client is not expecting causes silent drops
  in the other direction too.

`masque-server enroll-client` generates both sides at once, which is the
reliable way to keep them consistent.

**Keepalive interacts with the idle timeout.** These clients default to a 30s
keepalive period. Keep `server.idle_timeout_secs` above it; the default is 60.

**HTTP/2 fallback is available when the client supports it.** These clients may
carry CONNECT-IP over TCP/H2 instead of QUIC. Point that mode at a listener with
`transport = "http2"`; address assignment, certificate identity, source checks,
and TUN routing are shared with HTTP/3. Prefer QUIC when it is reachable because
TCP loss makes all capsules on the H2 connection wait for retransmission.
