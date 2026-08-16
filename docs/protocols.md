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

Every CONNECT form passes through the same proxy authentication pipeline. The
client supplies:

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

The request contains `:protocol = connect-ip` and follows the configured URI
template. A successful setup allocates addresses and returns `200`, followed
by:

- `ADDRESS_ASSIGN` capsules for assigned IPv4 and IPv6 addresses; and
- `ROUTE_ADVERTISEMENT` capsules for reachable prefixes.

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
