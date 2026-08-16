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

  -c, --config <PATH>       Config file [default: masque.toml]
  -l, --listen <ADDR>       Override server.listen_addr
      --cert <PATH>         Override tls.cert_path
      --key <PATH>          Override tls.key_path
  -v, --verbose             Increase verbosity; repeat for trace logging
```

`RUST_LOG` overrides the default tracing filter.

## Server

```toml
[server]
listen_addr = "0.0.0.0:443"
idle_timeout_secs = 30
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

## TLS

```toml
[tls]
cert_path = "/etc/masque/certs/server.crt"
key_path = "/etc/masque/certs/server.key"
```

The certificate must cover the hostname used by clients. The systemd unit runs
as group `masque`; install both files as `root:masque` with mode `0640`.

## Authentication

```toml
[auth]
enabled = true
username = "proxy-user"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."
```

Generate a hash without placing the password in process arguments:

```sh
printf '%s' 'a-strong-password' | masque-server hash-password
```

Clients send `Proxy-Authorization: Basic ...` on every CONNECT request.
Missing or invalid credentials receive `407 Proxy Authentication Required`.
Set `enabled = false` only in an isolated test environment or behind another
trusted authentication boundary.

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
tun_name = "masque0"
tun_mtu = 1280
tun_offload = true
ipv4_pool = "10.89.0.0/16"
ipv6_pool = "fd00:abcd::/64"
```

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
