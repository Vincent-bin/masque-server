# MASQUE Server

A high-performance MASQUE proxy server written in Rust. HTTP/3 carries TCP,
UDP, and IP traffic using standard CONNECT, CONNECT-UDP, and CONNECT-IP;
HTTP/2 provides a TCP/TLS compatibility transport for all three when a network
blocks QUIC.

The project is pre-1.0. Protocol behavior, configuration compatibility, and
release packaging are tested, but operators should still validate upgrades in
a staging environment.

## Features

- Standard CONNECT for TCP streams
- CONNECT-UDP ([RFC 9298]) using HTTP Datagrams
- CONNECT-IP ([RFC 9484]) with Linux TUN integration
- HTTP/3 over UDP for performance, plus HTTP/2 Extended CONNECT and the
  Cloudflare/usque CONNECT-IP dialect over TCP/TLS as compatibility fallbacks
- Multiple HTTP Basic accounts per listener with Argon2id password
  verification, or TLS client-certificate authentication against a public-key
  roster
- Multiple listeners in one process, each with its own Basic or client-certificate
  authentication mode while sharing proxy policies, client roster, and TUN state
- CIDR allow and deny policies for TCP and UDP targets
- Adaptive QUIC Retry plus process-wide per-source connection and Basic-auth
  admission limits
- QUIC NAT rebinding and validated client-address migration without dropping
  established HTTP/3 tunnels
- Bounded queues and backpressure across authentication and tunnel I/O
- Linux `recvmmsg`/`sendmmsg`, UDP GRO, optional UDP GSO, and TUN offload
- Multi-core sharding with Linux `SO_REUSEPORT` CID steering
- Optional loopback health/readiness endpoints and low-overhead Prometheus
  metrics, with packaged static alert rules and a Grafana dashboard JSON
- Optional JSON logs plus native systemd readiness and shard-liveness watchdog
- Atomic `SIGHUP` reload of the full TLS certificate chain, Basic account sets,
  and certificate roster without dropping established tunnels; active roster
  updates disconnect only revoked certificate clients
- Read-only `doctor` checks for CONNECT-IP TUN, forwarding, route, firewall,
  and NAT prerequisites without modifying the host
- A packaged client-side `masque-probe` that verifies TLS, authentication,
  CONNECT-TCP, CONNECT-UDP, and optional CONNECT-IP over HTTP/3 or HTTP/2
- Credential-safe client configuration generation and a redacted JSON support
  bundle for reproducible troubleshooting
- Static Linux x86_64 and ARM64 release archives with a systemd installer

## Quick start

Build the server:

```sh
cargo build --release --bin masque-server
```

Each `[[listeners]]` entry chooses `transport = "http3"` (the default and
recommended path) or `transport = "http2"`, and has an explicit
`[listeners.auth]` table. For a `basic` listener, generate an Argon2id password
hash:

```sh
printf '%s' 'replace-this-password' | \
  target/release/masque-server hash-password
```

Copy [`deploy/config/masque.toml`](deploy/config/masque.toml), set the server TLS
certificate and private key, and configure at least one
`[[listeners.auth.users]]` username and password hash, then start the server:

```sh
target/release/masque-server --config ./masque.toml
```

After replacing both TLS files, `systemctl reload masque` makes new HTTP/2 and
HTTP/3 handshakes use them while established connections continue normally.
Invalid or mismatched replacement material is rejected and the previous
identity remains active.

Authentication is fail-closed. In `basic` mode the server refuses to start until
at least one uniquely named account with a valid Argon2id hash is configured.

Alternatively, set `mode = "client_cert"` in `[listeners.auth]` to authenticate
clients during the TLS handshake. Generate each client's P-256 key and
configuration with:

```sh
target/release/masque-server --config ./masque.toml enroll-client \
  --name laptop --endpoint 203.0.113.9:443 \
  --ipv4 10.89.0.2 --ipv6 fd00:abcd::2 --out laptop.json
```

Append the generated `[[clients]]` block to the server configuration, then
reload or restart the service. The generated client configuration contains a
private key and must be handled as a secret. Basic and client-certificate
authentication are mutually exclusive on one socket, because the mode decides
what the TLS handshake demands. To serve both kinds of client, give each mode
its own `[[listeners]]` entry in the same process; see
[Authentication](docs/configuration.md#authentication) and
[Listeners](docs/configuration.md#listeners).

A second listener can be added to a deployed configuration without editing TOML
by hand. This prompts for the HTTP transport, address, authentication mode, and
any credentials, validates the merged file the way `check-config` does,
test-binds the new address, and leaves the file untouched if anything is wrong:

```sh
masque-server --config /etc/masque/masque.toml add-listener
```

Every value, including `--transport http2|http3`, is also available as a flag
for provisioning scripts. See
[Adding a listener](docs/configuration.md#adding-a-listener). A new socket is
bound at startup, so open UDP for HTTP/3 or TCP for HTTP/2, restart the service,
and confirm it came up. A new HTTP/3 Basic listener accepts the same
`--emit-client surge --client-endpoint ... --client-out ...` options shown
below, so its only plaintext credential can be delivered in the same operation.

Basic accounts on an existing listener can be managed without editing TOML or
restarting the server. If the file has only one Basic listener, its address can
be omitted:

```sh
printf '%s\n' 'a-strong-password' | sudo masque-server \
  --config /etc/masque/masque.toml add-user \
  --username phone --password-stdin \
  --emit-client surge --client-endpoint proxy.example.com:8449 \
  --client-out /root/phone-surge.conf
sudo masque-server --config /etc/masque/masque.toml list-users
sudo systemctl reload masque
```

`set-password` and `remove-user` update one account atomically; removing the
last account is refused. Existing scalar `username` / `password_hash` files are
accepted and are migrated to the multi-account form by the first account edit.
See [Basic account management](docs/configuration.md#basic-account-management).

The generated Surge file is created as mode `0600` and contains the plaintext
password. If an account already exists and its password is still known, generate
the same file without changing the server configuration:

```sh
printf '%s' 'a-strong-password' | masque-server client-config surge \
  --endpoint proxy.example.com:8449 --username phone \
  --out /root/phone-surge.conf
```

CONNECT-IP is independent of the authentication mode: it needs Linux host
forwarding because it carries complete IP packets through `masque0`, while
CONNECT and CONNECT-UDP use ordinary userspace sockets. Inspect the host before
qualifying a CONNECT-IP client:

```sh
sudo masque-server --config /etc/masque/masque.toml doctor
```

The command and the server's startup check are read-only. They never change
routing, firewall, sysctl, or NAT state.

Run the packaged probe from the same client network that is failing. It tries
HTTP/3 first and falls back to HTTP/2, then establishes a real upstream TCP
CONNECT and performs a DNS-over-UDP round trip through the proxy:

```sh
printf '%s' 'a-strong-password' | masque-probe proxy.example.com:8449 \
  --username phone --password-stdin
masque-probe proxy.example.com:4443 --client-config laptop.json --connect-ip
```

For a shareable server-side report, create a structured bundle rather than
copying the TOML or logs by hand:

```sh
sudo masque-server --config /etc/masque/masque.toml support-bundle \
  --out /root/masque-support.json
```

The report omits raw configuration, credentials, identities, key material,
environment variables, logs, and traffic details. Review it before sharing.
See [Troubleshooting](docs/troubleshooting.md) for probe options and result
codes.

## One-command Linux install

On Linux x86_64 or ARM64, download, verify, and install the latest stable
release with:

```sh
curl -fsSL https://raw.githubusercontent.com/Vincent-bin/masque-server/main/install-latest.sh | sudo sh
```

For a new configuration the installer prompts for `basic`, `client_cert`, or
`dual` authentication and optional TLS file locations. Basic mode creates the
first account, generates a random password when none is supplied, and can write
a ready-to-import Surge configuration while the plaintext is still available.
Client-certificate mode enrolls the first
client, adds its `[[clients]]` entry, writes its secret JSON as mode `0600`, and
prints the matching usque and mihomo configuration. Dual mode does both, writing
a two-listener configuration that serves credentials on one port and
certificates on another. At the end a fresh installation prints the installed
version, service state, and effective server configuration with the password
hash redacted. It also offers to run the read-only CONNECT-IP host diagnostic;
the installer never configures forwarding, firewall rules, routes, or NAT.

The same command is also the upgrade command. When
`/etc/masque/masque.toml` already exists, the candidate binary checks that
configuration without binding a port or creating a TUN, then upgrades both
binaries, the systemd unit, and versioned monitoring assets. It never rewrites the
TOML or referenced TLS files, and it does not copy the existing configuration
into unattended upgrade logs. An
incompatible configuration aborts before replacement; a failed service restart
restores the prior binaries, unit, monitoring assets, and service state. See
[Deployment](docs/deployment.md#one-command-install) for non-interactive
variables, certificate requirements, and installing a specific release.

## Install a downloaded release on Linux

Release archives contain `masque-server`, `masque-probe`, an example
configuration, a hardened systemd unit, Prometheus rules, a Grafana dashboard,
and an installer. Replace `ARCH` with `x86_64` or `aarch64`:

```sh
tar xzf masque-vVERSION-linux-ARCH.tar.gz
cd masque-vVERSION-linux-ARCH
sudo ./install.sh
```

The monitoring files are optional static assets. Installation does not install
or start Prometheus or Grafana on the server.

The package installer creates an unprivileged `masque` system user, lets new
installations choose either authentication mode, and enables the service. Set
`MASQUE_START_SERVICE=1` to start it immediately; the one-command installer
does this automatically when TLS material is present.

See [Deployment](docs/deployment.md) for certificates, systemd hardening,
upgrades, and diagnostics.

## Documentation

| Document | Contents |
| --- | --- |
| [Architecture](docs/architecture.md) | Runtime components, data flow, sharding, and resource bounds |
| [Configuration](docs/configuration.md) | TOML sections, authentication, policy, and tuning |
| [Deployment](docs/deployment.md) | Linux installation, systemd, certificates, and upgrades |
| [Protocols](docs/protocols.md) | Supported RFCs and CONNECT request behavior |
| [Performance](docs/performance.md) | Benchmark methodology and Linux fast paths |
| [Observability](docs/observability.md) | Health/readiness, metrics, alerts, dashboard, and structured logs |
| [Troubleshooting](docs/troubleshooting.md) | Client probe, redacted support bundle, and failure isolation |
| [Testing](docs/testing.md) | Unit, E2E, benchmark, and release validation |
| [Security](docs/security.md) | Threat model, safe defaults, and operational guidance |

## Repository layout

```text
src/                    Server library and CLI
  capsule/              Capsule Protocol codecs
  net/                  Platform UDP adapters and Linux batch I/O
  tunnel/               TCP, UDP, and IP tunnel implementations
tools/masque-e2e/       E2E client and load generator
tools/masque-probe/     Packaged end-user connectivity diagnostic
tests/e2e/              Docker E2E environment and fixtures
benches/                In-process microbenchmarks
fuzz/                   Scheduled libFuzzer targets for public protocol parsers
deploy/                 Example config, installer, systemd unit, and monitoring assets
docs/                   Operator and contributor documentation
scripts/                Test, benchmark, certificate, and packaging helpers
.github/workflows/      CI and release automation
```

The server remains a single primary crate deliberately. The hot packet path
crosses QUIC, scheduling, and tunnel code, so release builds use fat LTO and a
single codegen unit instead of introducing crate boundaries solely for layout.

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked
cargo test --workspace --locked
cargo bench --bench core
scripts/network-bench.sh
```

The Docker E2E suite requires `/dev/net/tun`, Docker Compose, and permission to
create a container with `NET_ADMIN`:

```sh
scripts/e2e-test.sh
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a change.

## Platform support

Linux is the production target and the only platform supporting CONNECT-IP,
multi-shard HTTP/3 listeners, UDP GSO/GRO, and batched target UDP I/O. HTTP/2
protocol handling is portable, including CONNECT-IP capsule setup, but actual
IP forwarding still needs Linux TUN and host routing. macOS is useful for the
portable HTTP/2 and HTTP/3 paths, but it cannot exercise the Linux syscall,
TUN, and offload paths.

## License

Licensed under the [MIT License](LICENSE).

[RFC 9298]: https://www.rfc-editor.org/rfc/rfc9298
[RFC 9484]: https://www.rfc-editor.org/rfc/rfc9484
