# Protocol behavior

## Standards

| Standard | Use |
| --- | --- |
| [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) | QUIC transport and variable-length integers |
| [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) | HTTP/3 request streams |
| [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297) | HTTP Datagrams and Capsule Protocol |
| [RFC 9298](https://www.rfc-editor.org/rfc/rfc9298) | CONNECT-UDP |
| [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484) | CONNECT-IP |
| [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617) | Basic authentication syntax |

The TLS ALPN is HTTP/3 as provided by quiche. QUIC DATAGRAM support and HTTP/3
Extended CONNECT are advertised during connection setup.

## Authentication

With `auth.mode = "basic"` (the default), every CONNECT form passes through the
same proxy authentication pipeline. The client supplies:

```text
Proxy-Authorization: Basic BASE64(username:password)
```

The server validates syntax and username before scheduling Argon2id password
verification. Missing or invalid credentials return:

```text
:status: 407
proxy-authenticate: Basic realm="masque", charset="UTF-8"
```

Authentication is per request, so one authenticated tunnel does not authorize
later streams that omit the header.

With `auth.mode = "client_cert"` there is no per-request step: the client is
identified once, from its TLS client certificate, during the QUIC handshake. An
unregistered key never reaches the request path — it is refused with a TLS
`access_denied` alert. See
[Cloudflare-compatible clients](#cloudflare-compatible-clients).

## Standard CONNECT

The request uses `:method = CONNECT` and places the TCP destination in
`:authority` as `host:port`. It does not use `:protocol`.

After authentication, resolution, and policy checks, the server connects to
the target and returns `200`. HTTP/3 request-body bytes flow to the target and
target bytes flow in the response body. Either side's end-of-stream is relayed
as a half-close when possible.

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

Each HTTP Datagram starts with the request stream's Quarter Stream ID followed
by Context ID `0` and the UDP payload. Unexpected Context IDs are rejected.
Datagrams are not retransmitted by QUIC.

If a client uses Capsule Protocol fallback, DATAGRAM capsules are incrementally
decoded from the request stream. Unknown capsule types are ignored as required
by the Capsule Protocol unless they affect tunnel state.

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

IP packets use HTTP Datagrams with Context ID `0`. Before writing a client
packet to TUN, the server checks the source address against the tunnel's
assignment. Return packets are routed only to the owning tunnel.

CONNECT-IP depends on host routing and firewall configuration; the HTTP
protocol does not configure NAT or upstream routes for the host.

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
than close every tunnel on the QUIC connection.

## Interoperability

Clients must support HTTP/3 proxy CONNECT and the relevant MASQUE extension.
Configuration syntaxes in products such as Surge are client-specific and are
not part of the RFCs. Test authentication, target policy, TCP, UDP, and DNS
separately when qualifying a client.

## Cloudflare-compatible clients

VPN-style MASQUE clients modelled on Cloudflare WARP — for example
[usque](https://github.com/Diniboy1123/usque) and
[mihomo](https://wiki.metacubex.one/config/proxies/masque/) — diverge from
RFC 9484 in ways the server accommodates. Everything below is on by default
except the authentication mode.

**`:protocol` is `cf-connect-ip`.** Cloudflare's endpoint uses that instead of
the registered `connect-ip`, and these clients send only it. Both are in
`ip_proxy.connect_protocols` by default. This is not optional: usque and mihomo
are independent implementations, and both were observed sending byte-identical
requests — `:protocol: cf-connect-ip`, `:authority: cloudflareaccess.com`,
`:path: /` — so a server accepting only `connect-ip` answers `404` to every
client in this family.

**`:authority` and `:path` are fixed.** The request arrives as
`:authority: cloudflareaccess.com` and `:path: /`, with no URI Template
variables. The CONNECT-IP path ignores both, so `ip_proxy.uri_template` does not
apply to these clients.

**Authentication is a TLS client certificate.** No `Proxy-Authorization` is
ever sent, so `auth.mode = "basic"` refuses these clients with `407`. Use
`auth.mode = "client_cert"` and enroll each client's public key; see
[Authentication](configuration.md#authentication).

**Extended CONNECT is not required of the server.** Cloudflare does not
advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL`, and these clients tolerate its
absence. This server advertises it anyway, which is compatible.

**Addresses come from the client's own configuration, not from
`ADDRESS_ASSIGN`.** Cloudflare sends no capsules at all; the client learns its
tunnel addresses from its config file and configures its interface from those.
Two consequences:

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

**HTTP/2 fallback is not supported.** Some of these clients can carry
CONNECT-IP over TCP and HTTP/2 instead of QUIC. This server is HTTP/3 only, so
those clients must use their default QUIC transport.
