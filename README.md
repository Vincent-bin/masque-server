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
- CIDR allow and deny policies for TCP and UDP targets
- Bounded queues and backpressure across authentication and tunnel I/O
- Linux `recvmmsg`/`sendmmsg`, UDP GRO, optional UDP GSO, and TUN offload
- Multi-core sharding with `SO_REUSEPORT`
- Static Linux x86_64 release archives with a systemd installer

## Quick start

Build the server:

```sh
cargo build --release --bin masque-server
```

Authentication is enabled by default. For the default `basic` mode, generate an
Argon2id password hash:

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

Alternatively, set `auth.mode = "client_cert"` to authenticate clients during
the TLS handshake. Generate each client's P-256 key and configuration with:

```sh
target/release/masque-server --config ./masque.toml enroll-client \
  --name laptop --endpoint 203.0.113.9:443 \
  --ipv4 10.89.0.2 --ipv6 fd00:abcd::2 --out laptop.json
```

Append the generated `[[clients]]` block to the server configuration, then
reload or restart the service. The generated client configuration contains a
private key and must be handled as a secret. Basic and client-certificate
authentication are mutually exclusive within one server instance; see
[Authentication](docs/configuration.md#authentication) for the complete setup.

## Install a release on Linux

Release archives contain the binary, an example configuration, a hardened
systemd unit, and an installer:

```sh
tar xzf masque-vVERSION-linux-x86_64.tar.gz
cd masque-vVERSION-linux-x86_64
sudo ./install.sh
```

The installer creates an unprivileged `masque` system user and enables the
service. It preserves an existing `/etc/masque/masque.toml`. New installations
receive a randomly generated proxy password unless `MASQUE_AUTH_USERNAME` and
`MASQUE_AUTH_PASSWORD` are supplied to the installer.

The installer initially configures Basic authentication. To use TLS client
certificates instead, change `auth.mode` to `client_cert`, remove the Basic
credentials, and enroll the allowed clients as described above.

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
deploy/                 Example config, installer, and systemd unit
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
