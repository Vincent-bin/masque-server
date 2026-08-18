# Testing

## Validation matrix

| Layer | Command | Purpose |
| --- | --- | --- |
| Formatting | `cargo fmt --all --check` | Stable source formatting |
| Static analysis | `cargo clippy --workspace --all-targets --locked -- -D warnings` | Rust correctness and maintainability |
| MSRV | `cargo +1.88.0 check --workspace --locked` | Declared minimum compiler support |
| Unit/integration | `cargo test --workspace --locked` | Codecs, policy, config, scheduling, tunnels |
| Release tests | `cargo test --workspace --release --locked` | Optimized-profile behavior |
| Microbenchmark | `cargo bench --bench core` | Codec, routing, and allocation regressions |
| Network benchmark | `scripts/network-bench.sh` | Local direct-vs-MASQUE throughput and RTT |
| Docker E2E | `scripts/e2e-test.sh` | TCP, UDP, IP/TUN, and container networking |
| Client interop | `cargo test --test client_cert_connect_ip` | Cloudflare-compatible certificate auth, CONNECT-IP setup, and both authentication modes served from one process |
| Config preflight | `cargo test --test check_config` | `check-config` accepts what a server accepts, including multi-listener files |
| Linux package | `scripts/package-linux.sh` | Artifact layout and static binary build |

## Local tests

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo +1.88.0 check --workspace --locked
cargo test --workspace --locked
```

macOS covers portable CONNECT, CONNECT-UDP, authentication, protocol codecs,
and scheduling. It does not validate Linux `recvmmsg`/`sendmmsg`, GSO/GRO,
`SO_REUSEPORT`, TUN offload, capabilities, or systemd.

## Docker E2E

```sh
scripts/e2e-test.sh
```

The script creates development certificates, builds the server and E2E client,
starts an echo target, grants the server container `NET_ADMIN` and TUN access,
runs the suite, and removes the Compose network and volumes.

Failures should retain enough logs for diagnosis but must not print production
credentials or certificates.

## Network benchmark

```sh
scripts/network-bench.sh
```

Run several repetitions and preserve the direct UDP baseline. When changing
batching, readiness, pacing, flow control, or buffers, test both 64-byte and
1200-byte payloads. Use multiple connections for shard tests.

See [Performance](performance.md) for methodology and reporting requirements.

## Linux-specific checks

A release candidate is not complete until an x86_64 Linux host verifies:

1. the musl archive installs and starts through systemd;
2. authentication accepts correct credentials and rejects missing/wrong ones;
3. standard CONNECT and CONNECT-UDP work through a real client;
4. `sendmmsg` and `recvmmsg` appear under traffic;
5. UDP GSO on/off behavior is tested across the external path;
6. single- and multi-shard modes pass concurrent traffic;
7. memory and CPU remain bounded under invalid authentication load; and
8. a real Cloudflare-compatible client passes traffic through a TUN device —
   see [Cloudflare-compatible client interop](#cloudflare-compatible-client-interop).

For target datagram sizing, raise `quic.max_datagram_size` above 2048 in a test
configuration and verify oversized responses are rejected rather than silently
truncated.

## Cloudflare-compatible client interop

`cargo test --test client_cert_connect_ip` covers the handshake, the
`cf-connect-ip` request, pinned address assignment, reconnect overlap, datagram
sizing, and rejection of unenrolled keys — all against a synthetic client that
imitates this family. It runs anywhere.

What it cannot cover is packet forwarding, because that needs a TUN device.
Qualifying a real client therefore needs a Linux host with root. Two clients are
known to interoperate, and testing both is worthwhile because they are
independent implementations of the same protocol:

- [mihomo](https://wiki.metacubex.one/config/proxies/masque/) — ships prebuilt
  binaries, and can be run as a plain local proxy, so it needs neither a
  toolchain nor a TUN device nor root. Start here.
- [usque](https://github.com/Diniboy1123/usque) — the reference client; needs a
  Go toolchain (currently Go ≥ 1.26) and root, since it only runs as a TUN.

`masque-server enroll-client` prints configuration for both. Their field
encodings differ in ways that are easy to get wrong by hand — mihomo wants the
server key as bare base64 and addresses in CIDR form, usque wants PEM and bare
addresses — so use the generated blocks rather than transcribing.

**1. Build the client.** Only needed for usque; mihomo ships binaries.

```sh
git clone https://github.com/Diniboy1123/usque && cd usque && go build .
```

**2. Configure the server.** Use `auth.mode = "client_cert"` on its listener,
and a certificate with an ECDSA key so the client can pin it:

```sh
scripts/gen-certs.sh certs
```

```toml
[tls]
cert_path = "certs/server.crt"
key_path = "certs/server.key"

[[listeners]]
listen_addr = "0.0.0.0:4433"
shards = 1

[listeners.auth]
enabled = true
mode = "client_cert"

[ip_proxy]
enabled = true
ipv4_pool = "10.89.0.0/24"
ipv6_pool = "fd00:abcd::/64"
```

**3. Enroll the client.** Do not hand-write either side; the pinned addresses
must match exactly, and enrollment is what guarantees that:

```sh
masque-server --config masque.toml enroll-client \
    --name interop --endpoint <server-ip>:4433 \
    --ipv4 10.89.0.2 --ipv6 fd00:abcd::2 --out config.json
```

Append the printed `[[clients]]` block to `masque.toml` and start the server.

**4. Let the host forward and translate.** The server moves packets between
QUIC and its TUN device and nothing more; egress is the host's job:

```sh
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.89.0.0/24 -o <wan-if> -j MASQUERADE
```

**5. Connect.** With mihomo, paste the generated `proxies:` block into a config
with a listener and a catch-all rule, then run it unprivileged:

```yaml
mixed-port: 7899
mode: rule
proxies:
  # ... the generated block ...
rules:
  - MATCH,<proxy name>
```

```sh
./mihomo -d <config-dir>          # no root, no TUN
```

With usque, the JSON stores the endpoint IP but not its port, so the port is a
flag — enrollment prints the exact argument:

```sh
sudo ./usque nativetun --config config.json --connect-port 4433
```

**6. Verify.** The most decisive target is the server's own TUN address, because
it exercises the tunnel end to end without depending on the host's egress path
at all. Serve a large file there and pull it through the tunnel, comparing
checksums:

```sh
# on the server, bound to the TUN gateway only
python3 -m http.server 8080 --bind 10.89.0.1

# from the client
curl -x http://127.0.0.1:7899 -o out.bin http://10.89.0.1:8080/blob.bin   # mihomo
curl -o out.bin http://10.89.0.1:8080/blob.bin                            # usque
```

Then an ICMP echo to `10.89.0.1`, both address families, and a full-MTU probe:

```sh
ping -M do -s 1252 -I 10.89.0.2 10.89.0.1   # 1252 + 28 = the 1280-byte MTU
ping -M do -s 1253 -I 10.89.0.2 10.89.0.1   # must fail: proves where the limit is
```

Only then test egress to the internet. Small-packet success with bulk-transfer
failure means MTU, not routing.

### Egress testing needs an uncontended host

Egress is the least reliable thing to test, because it depends on the server
host's own networking rather than on MASQUE. Before concluding the server is at
fault, confirm the packet actually left:

```sh
tcpdump -ni masque0 host <target>   # did the tunnel deliver it?
tcpdump -ni <wan-if> host <target>  # did the host forward it?
```

If it arrives on `masque0` but never leaves the WAN interface, the server did
its job and the host dropped the packet. Three environment traps produce exactly
that, and all three were hit while qualifying this feature:

- **Docker sets the `FORWARD` policy to `DROP`.** Add the tunnel's rules to the
  `DOCKER-USER` chain, which Docker leaves for exactly this and traverses first.
- **A transparent proxy on the server host captures forwarded traffic.** A
  policy-routing setup (`ip rule show` revealing a table for a proxy's own TUN)
  will divert forwarded TCP into the proxy instead of the WAN interface. Such
  setups commonly exempt ICMP explicitly, which produces the confusing signature
  of working pings and hanging TCP. Check `ip rule show` before blaming MASQUE.
- **A published container port hijacks that port for forwarded traffic too.** A
  container publishing `0.0.0.0:80` installs a DNAT rule matching *any* packet
  with that destination port, including tunnel traffic merely passing through, so
  it never reaches the WAN interface. Pick a test port nothing publishes.

### Failure signatures

| Symptom | Cause |
| --- | --- |
| `login failed! Please double-check if your tls key and cert is enrolled` | The client's public key is not in `[[clients]]`. The server logs the key it received in pasteable form. |
| Client reports a different public key than enrollment printed | `config.json` and the `[[clients]]` block came from different runs. Re-enroll. |
| `remote endpoint has a different public key than what we trust in config.json` | `tls.cert_path` changed after enrollment. Re-run enrollment, or pass `--insecure` to skip pinning while testing. |
| HTTP 404 on the CONNECT | `cf-connect-ip` is missing from `ip_proxy.connect_protocols`, or `ip_proxy.enabled = false`. |
| HTTP 407 | The server is in `auth.mode = "basic"`; these clients never send credentials. |
| HTTP 503 | The dynamic address pool is exhausted, or `max_tunnels_per_connection` is reached. A pinned client is unaffected by pool exhaustion — its address is reserved at startup. |
| Tunnel comes up, no traffic passes | Host forwarding or NAT is missing, or the TUN device failed to appear — check the server's startup warnings. |
| In-tunnel traffic works, egress does not | The host's forwarding path, not the server. See [Egress testing needs an uncontended host](#egress-testing-needs-an-uncontended-host). |
| Egress ICMP works but TCP hangs | Almost always a transparent proxy on the server host that exempts ICMP from its policy routing. Check `ip rule show`. |
| Server logs `spoofed source address, dropping` | The client's interface address disagrees with its pinned address. Re-enroll so both sides match. |
| Small packets work, bulk transfers stall | The framed MTU exceeds the datagram budget. Raise `quic.max_datagram_size` or lower the client's MTU; keep the client at 1280 unless both ends were changed together. |
| Tunnel drops roughly every 30s | `server.idle_timeout_secs` is at or below the client's keepalive period. |

## Release checklist

- Update `CHANGELOG.md` and package version.
- Run formatting, Clippy with warnings denied, and release tests.
- Build `x86_64-unknown-linux-musl` with the same command used by CI.
- Extract the archive into a temporary directory and inspect permissions and
  paths.
- Verify `masque-server --help`, `hash-password`, and side-effect-free
  `check-config` from the packaged binary.
- Install on a disposable Linux host and run a client smoke test.
- Tag only the commit that passed these checks.

Tags containing a hyphen are published as GitHub pre-releases.
