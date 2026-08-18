# Configuration

The server reads TOML from `--config` (default `masque.toml`). Missing sections
use defaults, but authentication is deliberately fail-closed: the default
configuration cannot start until credentials are set or authentication is
explicitly disabled.

Start from [`deploy/config/masque.toml`](../deploy/config/masque.toml). That
file is the canonical deployable example and is tested by the release flow.

## CLI

```text
masque-server [OPTIONS]
masque-server hash-password
masque-server --config <PATH> check-config
masque-server enroll-client [OPTIONS] --name <NAME> --endpoint <ADDR:PORT>

  -c, --config <PATH>       Config file [default: masque.toml]
  -l, --listen <ADDR>       Override server.listen_addr
      --cert <PATH>         Override tls.cert_path
      --key <PATH>          Override tls.key_path
  -v, --verbose             Increase verbosity; repeat for trace logging
  -V, --version             Print the server version
```

`check-config` validates authentication, the TLS certificate/key pair, QUIC
settings, client roster, and address pools without binding the UDP listener or
creating a TUN device. It is suitable for upgrade preflight, but cannot detect
runtime conditions such as an occupied port or unavailable kernel device.

`hash-password` reads a password on stdin and prints an Argon2id hash for
`auth.password_hash`. `enroll-client` generates a client key pair for
`auth.mode = "client_cert"`; it reads `tls.cert_path` from `--config`, so pass
the same config the server uses. Both are described under
[Authentication](#authentication).

```text
enroll-client options:
      --name <NAME>         Label for this client, used in the server's logs
      --endpoint <ADDR:PORT>  What clients dial; must be reachable from them
      --ipv4 <ADDR>         Fixed tunnel IPv4, inside ip_proxy.ipv4_pool
      --ipv6 <ADDR>         Fixed tunnel IPv6, inside ip_proxy.ipv6_pool
  -o, --out <PATH>          Write the client JSON here instead of stdout
```

`RUST_LOG` overrides the default tracing filter.

## Server

```toml
[server]
listen_addr = "0.0.0.0:443"
idle_timeout_secs = 60
max_connections = 10000
max_tunnels_per_connection = 100
shards = 1
```

| Key | Meaning |
| --- | --- |
| `listen_addr` | UDP address used for QUIC and HTTP/3 |
| `idle_timeout_secs` | Inactive tunnel lifetime |
| `max_connections` | Per-shard connection cap |
| `max_tunnels_per_connection` | CONNECT streams retained per connection |
| `shards` | Linux event loops/listeners; `0` selects one per available core |

Use one shard until a benchmark shows one event loop is CPU-bound. Memory and
the effective connection capacity increase with the shard count.

`listen_addr` and `shards` describe the single listener this section implies.
A configuration that uses [`[[listeners]]`](#multiple-listeners) names its
sockets there instead, and these two keys are then ignored.

## TLS

```toml
[tls]
cert_path = "/etc/masque/certs/server.crt"
key_path = "/etc/masque/certs/server.key"
```

The certificate must cover the hostname used by clients. The systemd unit runs
as group `masque`; install both files as `root:masque` with mode `0640`.

## Authentication

`auth.mode` selects how clients prove who they are. The two modes are mutually
exclusive *on one socket* — `client_cert` makes the TLS handshake demand a
certificate, so a credential-based client cannot even connect, and vice versa.
To serve both kinds of client, give each mode its own listener; see
[Multiple listeners](#multiple-listeners).

| Key | Meaning |
| --- | --- |
| `enabled` | Master switch. `false` disables authentication whatever `mode` says |
| `mode` | `basic` (default) or `client_cert` |
| `username` | `basic` only |
| `password_hash` | `basic` only; Argon2id PHC string |
| `[[clients]]` | `client_cert` only; the roster of allowed clients |

Choose `basic` for standards-compliant MASQUE clients. Choose `client_cert` for
VPN-style clients modelled on Cloudflare WARP, such as usque and mihomo, which
never send credentials; see
[Cloudflare-compatible clients](protocols.md#cloudflare-compatible-clients).

### `mode = "basic"` (default)

Credentials are checked on every CONNECT request, so one authorized tunnel does
not authorize later streams that omit the header.

```toml
[auth]
enabled = true
mode = "basic"
username = "proxy-user"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."
```

Generate the hash without placing the password in process arguments, which
would expose it to every user on the host through the process list:

```sh
printf '%s' 'a-strong-password' | masque-server hash-password
```

Clients send `Proxy-Authorization: Basic BASE64(user:password)` on each
request. Missing, malformed, duplicated, or wrong credentials receive
`407 Proxy Authentication Required`.

The server refuses to start if `username` is empty or contains `:`, or if
`password_hash` is not a valid Argon2id PHC string.

### `mode = "client_cert"`

Clients authenticate once, with a TLS client certificate, during the QUIC
handshake. Nothing is checked per request: every stream on an established
connection is already authorized. Standard CONNECT and CONNECT-UDP keep working
if their sections are enabled — the mode changes who may connect, not what they
may ask for.

```toml
[auth]
enabled = true
mode = "client_cert"

[[clients]]
name = "laptop"
public_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."
ipv4 = "10.89.0.2"
ipv6 = "fd00:abcd::2"

[[clients]]
name = "phone"
public_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."
ipv4 = "10.89.0.3"
ipv6 = "fd00:abcd::3"
```

| `[[clients]]` key | Meaning |
| --- | --- |
| `name` | Label used in the server's logs. Optional but makes them readable |
| `public_key` | The client's ECDSA P-256 public key: base64 SubjectPublicKeyInfo DER, or a `-----BEGIN PUBLIC KEY-----` block |
| `ipv4` | Fixed CONNECT-IP address, inside `ip_proxy.ipv4_pool` |
| `ipv6` | Fixed CONNECT-IP address, inside `ip_proxy.ipv6_pool` |

#### Enrolling a client

There is no enrollment API to call. The operator generates the key pair and
distributes it:

```sh
masque-server --config masque.toml enroll-client \
    --name laptop --endpoint 203.0.113.9:443 \
    --ipv4 10.89.0.2 --ipv6 fd00:abcd::2 --out client.json
```

This prints three things: the `[[clients]]` block for this file, a JSON
configuration for usque-style clients, and a `proxies:` entry for mihomo-style
clients. The client halves contain the private key — treat the output as a
secret. Generating both spellings matters because the same key is encoded
differently for each: usque takes the server key as PEM and addresses bare,
mihomo takes it as bare base64 and addresses in CIDR form.

The generated mihomo entry uses the active `ip_proxy.tun_mtu` value from the
same server configuration, so a non-default MTU stays consistent on both ends.

`--out` writes the JSON to a file created as a new `0600` file on Unix; an
existing path is never overwritten. Without it the JSON goes to the terminal.

Nothing is written to the server configuration automatically. Append the
`[[clients]]` block yourself, then run `systemctl reload masque` or restart.

## Multiple listeners

`[[listeners]]` gives each socket its own authentication mode, which is what
lets one process serve both kinds of client. It is the whole list of listeners,
not an addition to `[server].listen_addr`: naming any listener here stops the
server deriving one from `[server]`, and `[server].listen_addr` and
`[server].shards` are then ignored.

```toml
[[listeners]]
listen_addr = "0.0.0.0:443"
shards = 1

[listeners.auth]
enabled = true
mode = "basic"
username = "proxy-user"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."

[[listeners]]
listen_addr = "0.0.0.0:4443"
shards = 1

[listeners.auth]
enabled = true
mode = "client_cert"
```

| `[[listeners]]` key | Meaning |
| --- | --- |
| `listen_addr` | Required; there is no default, so a typo cannot silently land on someone else's port |
| `shards` | Event loops for this listener; defaults to `1` |
| `[listeners.auth]` | Optional; omitted means the top-level `[auth]` |

A `[listeners.auth]` table replaces `[auth]` outright rather than merging field
by field, so the username from a Basic `[auth]` does not follow a listener that
switched to `client_cert`.

Everything else stays server-wide: one `[[clients]]` roster, one TUN device, one
CONNECT-IP address pool, one routing table. That is the reason to run two
listeners in one process rather than two processes — two processes would need
two TUN devices and two address pools, and overlapping pools hand the same
tunnel address to two clients.

The server refuses to start when two listeners contend for the same address.
This is not left to the kernel to report: a listener with more than one shard
opens its socket with `SO_REUSEPORT`, so a second listener on that address would
join the load-balancing group and be handed connections meant for the other
authentication mode.

Wildcards count as contention. `0.0.0.0` claims every IPv4 address on its port,
so it conflicts with `127.0.0.1` on that port. `::` is treated as claiming IPv4
as well, because whether it really does is the kernel's `IPV6_V6ONLY` default —
`0` on Linux unless `net.ipv6.bindv6only` says otherwise. Nothing here sets that
option, so `[::]:443` beside `0.0.0.0:443` is refused everywhere rather than
binding on some hosts and failing on others.

Addresses are compared in canonical form, so `[::ffff:127.0.0.1]:443` and
`127.0.0.1:443` are recognised as the same interface rather than passing the
check and then failing to bind — or, under `SO_REUSEPORT`, binding successfully
and leaving one listener shadowing the other's traffic.

`shards = 0` (one per core) is rejected when more than one listener is
configured; give each listener an explicit count. The 32-shard cap applies to
the server's total, not to any one listener. The budget for concurrent password
verification is sized from the Basic listeners' shards alone, so adding a
certificate listener does not widen what unauthenticated callers can demand.

`--listen` overrides `[server].listen_addr`, which this form does not use, so
it is refused rather than silently ignored when `[[listeners]]` is present.

Run `masque-server --config masque.toml check-config` to validate a
multi-listener file before restarting. It prints the resolved listeners, with
the shard counts the server will actually run rather than the ones written down
— `shards = 0` expanded to one per core, and any excess capped:

```
configuration is compatible with masque-server 0.3.0: /etc/masque/masque.toml
listener 0.0.0.0:443 auth=basic shards=1
listener 0.0.0.0:4443 auth=client_cert shards=1
```

The usque JSON schema stores the endpoint IP but not its port, so enrollment
also prints the matching launch argument — `--connect-port 443` for the example
above, `--connect-port 8449` for a server on 8449. Omitting it silently falls
back to the client's default port.

#### How the certificate is checked

Only the public key inside the certificate is compared against the roster. The
certificate itself is a disposable envelope: these clients self-sign a fresh
one per connection with an empty subject and 24-hour validity, so its chain,
name, and dates carry nothing worth verifying.

A key that is not on the roster is refused during the handshake with a TLS
`access_denied` alert, before it can open a stream. The rejected key is logged
in exactly the form you can paste into a `[[clients]]` entry, so enrolling a new
client needs no separate key extraction step.

The **server** certificate must use an ECDSA key, because these clients pin its
public key and reject any other key type. `scripts/gen-certs.sh` produces a
suitable P-256 certificate. Replacing the server certificate invalidates every
client configuration that pinned the old key.

#### Pinned addresses

`ipv4` / `ipv6` bypass the dynamic pool and give that client the same address
every time. This is required for clients that configure their tunnel interface
from their own configuration rather than from the `ADDRESS_ASSIGN` capsule: if
the two sides disagree, traffic is dropped in both directions — inbound as a
spoofed source, outbound by the client's own filtering. Omit them only for
clients that do read `ADDRESS_ASSIGN`.

Pinned addresses are withheld from dynamic allocation for the process lifetime,
so an offline client keeps its address. When a replacement connection arrives
before its stale predecessor times out, the same authenticated identity may
reclaim the addresses immediately and the newest tunnel owns their return
route — a network change does not cost a minute of downtime.

Dynamic allocation begins at network address `+2`; `+1` belongs to the server's
own TUN interface.

#### Revoking a client

Edit the roster and send `SIGHUP`:

```sh
systemctl reload masque            # or: kill -HUP $(pidof masque-server)
```

The server re-reads `[[clients]]` from the same file it was started with,
disconnects any live connection whose entry was removed or changed, and leaves
every other tunnel untouched. A removed client's next attempt is refused at the
handshake like any unenrolled key. Adding an entry works the same way, so a
client can be re-enrolled without a restart either.

Only the roster is reloaded. Listen address, TLS material, pools, and tuning are
fixed at bind time; changing those still needs a restart. A reload that does not
validate — an unparseable key, a pinned address outside the pool, `auth.mode` no
longer `client_cert` — is rejected as a whole and the running roster stays in
force, so a typo cannot lock everyone out.

Editing an existing entry counts as revocation: the client is disconnected and
must reconnect to pick up its new pinned addresses, which are chosen when the
tunnel is set up.

Reload is unavailable when the server was started without a config file, since
there is nothing to re-read.

#### Startup validation

The server refuses to start when:

- `mode = "client_cert"` and no `[[clients]]` entry exists — an empty roster
  admits nobody, which looks exactly like a broken TLS setup;
- a `public_key` is unparseable or is not ECDSA P-256;
- two entries share a `public_key`, or pin the same address;
- a pinned address falls outside its pool, or is the pool's gateway address —
  checked only while `ip_proxy.enabled = true`, since there is no pool to
  validate against otherwise.

`[[clients]]` entries outside this mode are ignored, do not reserve addresses,
and produce a startup warning.

### Disabling authentication

`auth.enabled = false` turns off both modes and logs a warning. This is only
appropriate in an isolated test environment or behind another trusted
authentication boundary.

## QUIC and UDP

```toml
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
```

Important relationships:

- `initial_max_data` must not exceed `max_connection_window`.
- `initial_max_stream_data` must not exceed `max_stream_window`.
- Path-MTU discovery cannot probe beyond `max_datagram_size`; raising only
  `discover_pmtu` has no benefit.
- UDP GSO is opt-in because some virtual egress paths advertise it but drop
  super-packets. Enable it only after an external-path A/B test.
- Supported congestion controllers are `cubic`, `reno`, and `bbr2`. CUBIC is
  the current default because the server's deferred-send behavior penalizes
  BBR2's fine-grained pacing.

Queue depths trade memory and latency for burst tolerance. QUIC DATAGRAM frames
are not retransmitted; a full queue drops traffic.

## TCP policy

```toml
[tcp_proxy]
enabled = true
connect_timeout_secs = 10
allow_targets = ["0.0.0.0/0", "::/0"]
deny_targets = [
  "127.0.0.0/8",
  "10.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "::1/128",
  "fc00::/7",
  "fe80::/10",
]
```

Resolved addresses must match an allow prefix and must not match a deny prefix.
Deny rules take precedence. Keep loopback, link-local, private, metadata, and
management networks denied unless access is intentional.

## UDP policy

```toml
[udp_proxy]
enabled = true
uri_template = "/.well-known/masque/udp/{target_host}/{target_port}/"
allow_targets = ["0.0.0.0/0", "::/0"]
deny_targets = ["127.0.0.0/8", "10.0.0.0/8", "::1/128"]
```

The template must retain `{target_host}` and `{target_port}`. Apply the same
internal-network restrictions used for TCP unless UDP access is intentionally
different.

## CONNECT-IP

```toml
[ip_proxy]
enabled = true
uri_template = "/.well-known/masque/ip/{target}/{ipproto}/"
connect_protocols = ["connect-ip", "cf-connect-ip"]
tun_name = "masque0"
tun_mtu = 1280
tun_offload = true
ipv4_pool = "10.89.0.0/16"
ipv6_pool = "fd00:abcd::/64"
```

`connect_protocols` lists the accepted `:protocol` values. RFC 9484 registers
`connect-ip`; Cloudflare's endpoint uses `cf-connect-ip` and clients built
against it send only that. Both are accepted by default, which costs nothing
because an RFC client never sends the second one. Narrow the list to
`["connect-ip"]` to accept only standards-compliant clients.

CONNECT-IP is Linux-only. Pools must not overlap host, container, VPN, or
upstream networks. The host is responsible for routing, forwarding, firewall,
and optional NAT outside the process. Disable the entire section when full IP
proxying is unnecessary; this also lets you remove `CAP_NET_ADMIN` from the
service.

## Validation and upgrades

The server validates authentication, congestion control, flow-control window
relationships, and platform requirements at startup. Treat a startup error as
a configuration defect rather than weakening validation.

The installer does not overwrite an existing configuration. Compare it with
the example shipped in every new release and add new fields deliberately; all
fields currently have backward-compatible defaults.
