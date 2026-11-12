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
same proxy authentication pipeline. All CONNECT forms accept
`Proxy-Authorization: Basic BASE64(username:password)`.

Standard CONNECT-IP over HTTP/2 and HTTP/3 also accepts
`Authorization: Basic BASE64(username:password)` under
[RFC 9484 §11](https://www.rfc-editor.org/rfc/rfc9484.html#section-11).
CONNECT-IP requests that carry both credential fields receive an empty 404.

The server validates syntax, looks up the username in that listener's account
set, and snapshots only the matching Argon2id hash before scheduling password
verification. Missing, malformed, duplicated, or invalid credentials return the
same empty response as an unsupported request:

```text
:status: 404
content-length: 0
```

The server does not send `Proxy-Authenticate`. Correct credentials must arrive
on the first CONNECT request. Authentication is per request, so one authorized
tunnel does not authorize later streams that omit the header. The legacy
`auth.stealth` field cannot re-enable a proxy authentication challenge.

With a listener's `auth.mode = "client_cert"` there is no per-request step: the client is
identified once, from its TLS client certificate, during the TLS handshake. An
unregistered key never reaches the request path — it is refused with a TLS
`access_denied` alert. See
[Legacy CONNECT-IP format](#legacy-connect-ip-format).

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

A missing, truncated, or out-of-range Quarter Stream ID closes the HTTP/3
connection with `H3_DATAGRAM_ERROR` (`0x33`); the maximum QSID is `2^60 - 1`.
An unknown or truncated Context ID and a legal QSID with no owning tunnel are
dropped without closing the connection.

HTTP/3 request DATA streams also accept DATAGRAM capsules, decoded across frame
boundaries. Replies use QUIC DATAGRAM only after the peer has advertised support;
otherwise they use DATAGRAM capsules on the response stream. This applies to
both CONNECT-UDP and CONNECT-IP. Unknown capsule values are streamed past
without buffering. Oversized DATAGRAM declarations or a truncated capsule at
end-of-stream reset the affected stream with `H3_MESSAGE_ERROR`. A packet too
large for native QUIC DATAGRAM is dropped rather than moved onto the reliable
capsule path. UDP capsule payloads support up to 65,527 bytes; IP capsules obey
the configured TUN MTU.

HTTP/2 has no native HTTP Datagram frame. The client must negotiate Capsule
Protocol with `Capsule-Protocol: ?1`; each request and response DATA stream then
carries RFC 9297 DATAGRAM capsules whose value is Context ID `0` followed by
the UDP payload. Those capsules inherit HTTP/2's reliable, ordered TCP delivery,
so this mode is for compatibility rather than maximum datagram performance.
Capsules are decoded incrementally and oversized declarations are rejected
before their values are buffered. Unknown capsule types are ignored. The same
stream fallback carries CONNECT-IP packets over HTTP/2.

## CONNECT-IP

Standard requests use `:protocol = connect-ip` and match the complete configured
path/query template after authentication. The default full-tunnel URI is
`/.well-known/masque/ip/*/*/`. Decoded `target` and `ipproto` values are validated
according to RFC 9484, including prefix lengths, zero host bits, percent-encoded
IPv6 colons, and decimal protocol numbers from 0 through 255. Malformed scopes
are rejected with `400`; valid non-wildcard scopes are rejected with `501`
because the forwarding path does not yet enforce per-request scope. Neither
failure allocates addresses or installs routes. Failure responses remain empty;
unauthenticated requests receive an empty `404`, without exposing URI validation
results.

The configured `cf-connect-ip` compatibility dialect retains its deployed URI
behavior. See [URI template configuration](configuration.md#connect-ip) for the
supported template forms and the compatibility boundary.

A successful setup assigns addresses and returns `200`, followed by:

- `ADDRESS_ASSIGN` capsules for assigned IPv4 and IPv6 addresses; and
- `ROUTE_ADVERTISEMENT` capsules for reachable prefixes.

Addresses come from the pool, unless the client authenticated with a certificate
whose `[[clients]]` entry pins them. A pinned client receives exactly its pinned
addresses and nothing from the pool. Reconnection may briefly overlap a stale
connection carrying the same enrolled key; the newest tunnel atomically takes
over the return route, while reference-counted leases keep later cleanup from
freeing an address that is still live.

Both transports answer `ADDRESS_REQUEST` with a matching Request ID for every
entry. Requests for an already leased host address, or an unspecified address
of an available family with `/32` or `/128`, confirm that lease. Requests for
other addresses, unavailable families, or delegated prefixes receive the RFC 9484
all-zero `/32` or `/128` rejection. Each reply retains the complete existing
address assignment, and rejections are not repeated in later replies. Client
`ADDRESS_ASSIGN` and `ROUTE_ADVERTISEMENT` capsules never change the server's
leases, routing table, or source-address checks.

Control values are limited to 16 KiB; each IP stream accepts at most 1,024 unique
address Request IDs over its lifetime. Empty requests, zero or reused IDs,
invalid address/prefix fields, truncated controls, and resource-limit violations
reset only the affected stream using the existing generic protocol error.
Control replies share bounded output handling and survive fragmented input,
small receive windows, and a clean request FIN. HTTP/3 retains its shared
64-buffer per-stream and 256-buffer per-connection output ceilings; overflowing
either resets only the requesting stream rather than growing the queue.
Initial unsolicited assignments and context-free HTTP/2 packet framing
remain supported.

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
| `404` | Unsupported request, or missing, invalid, or unverified Basic credentials |
| `429` / `503` | Per-connection or global setup capacity exhausted |
| `501` | Valid CONNECT-IP target or protocol scope is not implemented |
| `502` | DNS, target socket, or upstream TCP setup failed |

Once a tunnel is established, relay errors normally reset that stream rather
than close every tunnel on the HTTP connection.

## Interoperability

Clients must support proxy CONNECT on the selected transport and the relevant
MASQUE extension. Standards-based HTTP/2 CONNECT-UDP and CONNECT-IP require
Extended CONNECT and Capsule Protocol support; an ordinary HTTP proxy client
is sufficient only for standard CONNECT. The legacy CONNECT-IP format below is also supported.
Client configuration syntax is outside these protocols. Test authentication,
target policy, TCP, UDP, and DNS separately when qualifying a peer.

## Legacy CONNECT-IP format

`ip_proxy.connect_protocols` accepts both `connect-ip` and `cf-connect-ip` by
default. For `cf-connect-ip` over HTTP/3, send it as `:protocol` with valid
`:authority` and `:path` fields such as `proxy.example` and `/`. This format
does not use the RFC 9484 URI Template.

For the legacy format over HTTP/2, send a regular CONNECT with the
`cf-connect-proto: cf-connect-ip` field. Its DATAGRAM capsule value is the
raw IP packet. The server uses the same framing in the response. Standard
HTTP/2 CONNECT-IP uses Extended CONNECT, `Capsule-Protocol: ?1`, and includes
Context ID zero.

Authentication is selected per listener. A peer that configures its tunnel
interface out of band needs matching pinned addresses in
`[[clients]].ipv4` and `[[clients]].ipv6`. The server still sends
`ADDRESS_ASSIGN` with the actual lease. Select `transport = "http2"` for
TCP/TLS or `transport = "http3"` for QUIC. The transport selection does not
change source-address checks or host routing.
