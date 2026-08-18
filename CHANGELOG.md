# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) while the project is
pre-1.0.

## Unreleased

## 0.3.0 - 2026-08-18

### Added

- `[[listeners]]` runs several listening sockets from one process, each with
  its own `listen_addr`, `shards`, and authentication mode. This is what allows
  one server to accept both standards-compliant MASQUE clients, which send
  `Proxy-Authorization`, and Cloudflare-style clients, which authenticate with
  a TLS client certificate: `auth.mode` decides which TLS context a socket is
  bound with, so the two modes cannot share a socket. They do share everything
  behind them — one `[[clients]]` roster, one TUN device, one CONNECT-IP
  address pool, one routing table — which two processes could not.
- Startup and `check-config` reject two listeners that contend for one address.
  A listener with more than one shard binds with `SO_REUSEPORT`, so a second
  listener on that address would join the load-balancing group and be handed
  connections meant for the other authentication mode. Wildcards count:
  `0.0.0.0` claims every IPv4 address on its port, and `::` is assumed to claim
  IPv4 as well, since whether it does is the kernel's `IPV6_V6ONLY` default.
  Addresses are compared in canonical form, so an IPv4-mapped spelling such as
  `[::ffff:127.0.0.1]` cannot present itself as a different address from the
  IPv4 one it resolves to, and the error names which conflict it found rather
  than blaming a wildcard that may not be involved. Port `0` is exempt: it asks
  the kernel for whichever port is free, so several listeners may use it.
- `check-config` prints the resolved listeners, their shard counts, and the
  authentication each one demands, so the deployed modes can be read without
  re-deriving them from the TOML. Shard counts are the resolved ones, so
  `shards = 0` reports the per-core count rather than zero.
- The installer offers a `dual` authentication mode that writes a two-listener
  configuration, generating Basic credentials for one port and enrolling the
  first certificate client on the other. On upgrade it reports every mode an
  existing configuration runs, `disabled` included, so a server that
  authenticates on one port and not another cannot read as if it did both.

### Changed

- Shards are numbered across the whole server rather than within a listener,
  and the 32-shard cap now applies to that total. `shards = 0` (one per core)
  is rejected when more than one listener is configured.
- The `[[clients]]` roster and its `SIGHUP` reload follow "any listener uses
  `client_cert`" rather than the single `auth.mode`.
- The concurrent password-verification budget is sized from the shards that
  verify passwords rather than from every shard, so a client-certificate
  listener cannot widen what unauthenticated callers may demand of a Basic one.
- `--listen` is refused against a `[[listeners]]` configuration, which does not
  use `[server].listen_addr`. Silently ignoring it would leave the configured
  listeners bound when the flag was reached for to narrow exposure.
- Configurations without `[[listeners]]` are unchanged: `[server]` and `[auth]`
  still describe one listener, and `[server].listen_addr` and `[server].shards`
  are ignored only when `[[listeners]]` names sockets itself.

## 0.2.0 - 2026-08-18

### Added

- A one-command Linux x86_64 installer that resolves and verifies the latest
  stable GitHub release, offers Basic or TLS client-certificate authentication,
  enrolls the first certificate client, and prints a redacted configuration and
  client setup result. Reusing it for an upgrade preserves the existing TOML
  and TLS files, preflights them with the candidate binary, and rolls back the
  binary, systemd unit, and service state if activation fails.
- `masque-server check-config` validates startup configuration without binding
  a socket or creating a TUN device, allowing safe preflight before replacement.
- Compatibility with VPN-style MASQUE clients modelled on Cloudflare WARP, such
  as usque:
  - `ip_proxy.connect_protocols` accepts Cloudflare's `cf-connect-ip` alongside
    the registered `connect-ip`, both by default.
  - `auth.mode = "client_cert"` authenticates clients by TLS client
    certificate, matched against a `[[clients]]` roster by public key. An
    unregistered key is refused during the handshake with a TLS `access_denied`
    alert.
  - `[[clients]].ipv4` / `.ipv6` pin a client's CONNECT-IP addresses, which
    clients that configure their tunnel interface out of band require. Pinned
    addresses are withheld from dynamic pool allocation.
  - `masque-server enroll-client` generates a client key pair and prints both
    the server's `[[clients]]` block and the client's own configuration,
    replacing the vendor enrollment API for self-hosted setups.
  - Pinned-address leases tolerate an authenticated reconnect overlapping its
    stale predecessor; the newest tunnel takes over the return route.
  - `tests/client_cert_connect_ip.rs` drives a synthetic client imitating this
    family against a real server, covering certificate authentication,
    `cf-connect-ip`, pinned assignment, reconnect overlap, full-MTU datagram
    sizing, and rejection of unenrolled and absent certificates.
  - A documented interop procedure and failure-signature table for qualifying a
    real client on Linux, where packet forwarding can be exercised.
  - `enroll-client` also prints a mihomo-style `proxies:` entry, which needs the
    same key in a different encoding (bare base64 rather than PEM) and addresses
    in CIDR form.
  - `SIGHUP` reloads the `[[clients]]` roster. Revoked clients are disconnected
    and refused at their next handshake, other tunnels are untouched, and a
    roster that fails validation is rejected as a whole so the running one stays
    in force. Previously revoking a client required a restart, which dropped
    every other client's tunnel.

### Fixed

- The Docker build installs `clang` and `libclang-dev`. Without them the
  `boring-sys` bindgen step fails with "Unable to find libclang".
- Roster reload keeps pinned leases bound to the public key that owns them, so
  moving an address between clients cannot create a cross-identity overlap.
- `SIGHUP` cannot switch a running server into `client_cert` mode and validates
  reservations against the IP-proxy state the process bound with rather than
  unrelated edits awaiting restart.
- Generated mihomo configuration uses the configured `ip_proxy.tun_mtu` instead
  of always emitting 1280.

### Changed

- The binary now reports the package version through `masque-server --version`.
- `server.idle_timeout_secs` now defaults to 60 rather than 30, so a tunnel
  whose client uses the common 30s keepalive period does not race its own
  keepalive against the timeout.
- Dynamic CONNECT-IP allocation starts at network address `+2`, leaving `+1`
  exclusively to the server's TUN gateway.
- Client enrollment files are created with mode `0600` on Unix and never
  overwrite an existing path. The endpoint port is printed as usque's required
  `--connect-port` argument because its JSON schema stores only the IP.
- CONNECT-IP sends `200` only after address allocation succeeds, so exhaustion
  and setup failures return a real `503` instead of a successful dead tunnel.

## 0.1.0-rc.11 - 2026-08-16

### Added

- Globally bounded, connection-cancelled Argon2 authentication work.
- Batched target UDP receive and send paths on Linux.
- Config-sized target receive buffers with portable truncation detection.
- Per-connection latency percentiles and batch connection-rate reporting in
  the load generator.
- Standalone repository layout, CI, deployment, security, and contributor
  documentation.

### Changed

- Production binary is consistently named `masque-server`.
- Platform network adapters live under `src/net/`.
- The E2E client lives under `tools/masque-e2e/` and deployment assets under
  `deploy/`.
- The lockfile uses the latest dependency versions compatible with Rust 1.88.
- Development and release builds use Rust 1.97.1, while CI separately verifies
  the declared Rust 1.88 minimum.
- GitHub Actions are pinned to immutable commit SHAs.

## 0.1.0-rc.10 - 2026-08-15

- Scaled packet processing across independent `SO_REUSEPORT` shards.

## 0.1.0-rc.9 - 2026-08-15

- Preserved the first CONNECT-UDP datagram during socket registration.

## 0.1.0-rc.8 - 2026-08-15

- Added standard HTTP/3 CONNECT TCP proxying.

## 0.1.0-rc.7 - 2026-08-15

- Added mandatory-by-default HTTP proxy authentication.

Earlier release candidates established Linux packaging, systemd deployment,
QUIC pacing, and the initial performance test workflow.
