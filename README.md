# MASQUE Server

A high-performance MASQUE proxy server written in Rust. It carries TCP, UDP,
and IP traffic over HTTP/3 using standard CONNECT, CONNECT-UDP, and CONNECT-IP.

The project is pre-1.0. Protocol behavior, configuration compatibility, and
release packaging are tested, but operators should still validate upgrades in
a staging environment.

## Features

- Standard CONNECT for TCP streams
- CONNECT-UDP ([RFC 9298]) using HTTP Datagrams
- CONNECT-IP ([RFC 9484]) with Linux TUN integration
- HTTP Basic authentication with Argon2id password verification, or TLS client
  certificate authentication against a public-key roster
- Multiple listeners in one process, each with its own Basic or client-certificate
  authentication mode while sharing proxy policies, client roster, and TUN state
- CIDR allow and deny policies for TCP and UDP targets
- Bounded queues and backpressure across authentication and tunnel I/O
- Linux `recvmmsg`/`sendmmsg`, UDP GRO, optional UDP GSO, and TUN offload
- Multi-core sharding with `SO_REUSEPORT`
- Optional loopback health/readiness endpoints and low-overhead Prometheus
  metrics, with packaged static alert rules and a Grafana dashboard JSON
- Optional JSON logs plus native systemd readiness and shard-liveness watchdog
- Static Linux x86_64 release archives with a systemd installer

## Quick start

Build the server:

```sh
cargo build --release --bin masque-server
```

Each `[[listeners]]` entry has an explicit `[listeners.auth]` table. For a
`basic` listener, generate an Argon2id password hash:

```sh
printf '%s' 'replace-this-password' | \
  target/release/masque-server hash-password
```

Copy [`deploy/config/masque.toml`](deploy/config/masque.toml), set the server TLS
certificate, private key, username, and password hash, then start the server:

```sh
target/release/masque-server --config ./masque.toml
```

Authentication is fail-closed. In `basic` mode the server refuses to start until
a valid username and Argon2id hash are configured.

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
by hand. This prompts for the address, the authentication mode, and any
credentials, validates the merged file the way `check-config` does, test-binds
the new address, and leaves the file untouched if anything is wrong:

```sh
masque-server --config /etc/masque/masque.toml add-listener
```

Every value is also available as a flag for provisioning scripts. See
[Adding a listener](docs/configuration.md#adding-a-listener). A new socket is
bound at startup, so open its UDP port, restart the service, and confirm it came
up.

## One-command Linux install

On Linux x86_64, download, verify, and install the latest stable release with:

```sh
curl -fsSL https://raw.githubusercontent.com/Vincent-bin/masque-server/main/install-latest.sh | sudo sh
```

For a new configuration the installer prompts for `basic`, `client_cert`, or
`dual` authentication and optional TLS file locations. Basic mode generates a
random password when none is supplied. Client-certificate mode enrolls the first
client, adds its `[[clients]]` entry, writes its secret JSON as mode `0600`, and
prints the matching usque and mihomo configuration. Dual mode does both, writing
a two-listener configuration that serves credentials on one port and
certificates on another. At the end a fresh installation prints the installed
version, service state, and effective server configuration with the password
hash redacted.

The same command is also the upgrade command. When
`/etc/masque/masque.toml` already exists, the candidate binary checks that
configuration without binding a port or creating a TUN, then upgrades the
binary, systemd unit, and versioned monitoring assets. It never rewrites the
TOML or referenced TLS files, and it does not copy the existing configuration
into unattended upgrade logs. An
incompatible configuration aborts before replacement; a failed service restart
restores the prior binary, unit, monitoring assets, and service state. See
[Deployment](docs/deployment.md#one-command-install) for non-interactive
variables, certificate requirements, and installing a specific release.

The 0.3 configuration format is intentionally not compatible with 0.2. Convert
old `[auth]` and `[server]` listener keys into explicit `[[listeners]]` and
`[listeners.auth]` entries before rerunning the installer; it does not migrate
them automatically.

## Install a downloaded release on Linux

Release archives contain the binary, an example configuration, a hardened
systemd unit, Prometheus rules, a Grafana dashboard, and an installer:

```sh
tar xzf masque-vVERSION-linux-x86_64.tar.gz
cd masque-vVERSION-linux-x86_64
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
| [Testing](docs/testing.md) | Unit, E2E, benchmark, and release validation |
| [Security](docs/security.md) | Threat model, safe defaults, and operational guidance |

## Repository layout

```text
src/                    Server library and CLI
  capsule/              Capsule Protocol codecs
  net/                  Platform UDP adapters and Linux batch I/O
  tunnel/               TCP, UDP, and IP tunnel implementations
tools/masque-e2e/       E2E client and load generator
tests/e2e/              Docker E2E environment and fixtures
benches/                In-process microbenchmarks
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
multi-shard listeners, UDP GSO/GRO, and batched target UDP I/O. macOS is useful
for development and portable CONNECT/CONNECT-UDP tests, but it cannot exercise
the Linux syscall and offload paths.

## License

Licensed under the [MIT License](LICENSE).

[RFC 9298]: https://www.rfc-editor.org/rfc/rfc9298
[RFC 9484]: https://www.rfc-editor.org/rfc/rfc9484
