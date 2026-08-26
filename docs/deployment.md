# Linux deployment

## Supported release artifact

GitHub Actions builds static `x86_64-unknown-linux-musl` and
`aarch64-unknown-linux-musl` binaries and packages:

```text
bin/masque-server
bin/masque-probe
config/masque.toml
monitoring/prometheus-rules.yml
monitoring/grafana-dashboard.json
systemd/masque.service
install.sh
README.md
```

Verify the archive before extraction:

```sh
sha256sum --check masque-vVERSION-linux-ARCH.tar.gz.sha256
```

## One-command install

On Linux x86_64 or ARM64, the bootstrap installer detects the architecture,
resolves the latest stable GitHub release, downloads its archive and checksum,
verifies SHA-256, and invokes the installer from that archive:

```sh
curl -fsSL https://raw.githubusercontent.com/Vincent-bin/masque-server/main/install-latest.sh | sudo sh
```

Although the script arrives on standard input, interactive answers are read
from `/dev/tty`. A new installation offers three modes:

- `basic` creates the first account, generates a high-entropy password unless
  one is provided, prints the credentials once, and optionally writes a secret
  Surge configuration while the plaintext is available;
- `client_cert` enrolls the first client, appends the generated `[[clients]]`
  entry, writes the usque JSON to a new `0600` file, and prints the mihomo block;
- `dual` does both, writing a
  [two-listener configuration](configuration.md#listeners) that serves
  credentials on one port and certificates on another. The authentication mode
  decides what the TLS handshake demands, so the two cannot share a socket.

Dual mode asks for a second port, defaulting to `4443`, and writes two explicit
`[[listeners]]` entries, each with its own `[listeners.auth]` table.

Client-certificate enrollment needs the server's ECDSA certificate immediately
because the generated client configuration pins its public key, so `client_cert`
and `dual` both require it. Supply the PEM full chain and unencrypted private
key when prompted. Basic mode may defer TLS installation, but the service cannot
start until both files exist.

The final output includes the installed version, authentication mode, service
state, the resolved listeners with the authentication each demands, and the
complete effective TOML with the password hash redacted. It also includes a
generated Basic password or, in `client_cert` and `dual` modes, client private
key material. Treat the terminal output as a secret and do not capture it in a
public provisioning log.

The following environment variables make provisioning non-interactive:

| Variable | Meaning |
| --- | --- |
| `MASQUE_VERSION` | Exact published version/tag instead of the latest stable release |
| `MASQUE_AUTH_MODE` | `basic`, `client_cert`, or `dual` |
| `MASQUE_AUTH_USERNAME` | Basic username; defaults to `masque` |
| `MASQUE_AUTH_PASSWORD` | Basic password; random when omitted |
| `MASQUE_BASIC_CLIENT_ENDPOINT` | Optional public Basic endpoint in `host:port` form; enables Surge configuration generation |
| `MASQUE_BASIC_CLIENT_NAME` | Optional proxy name in the generated Surge configuration |
| `MASQUE_BASIC_CLIENT_CONFIG_OUT` | Absolute secret Surge output path; defaults to `/root/masque-surge.conf` when generation is enabled |
| `MASQUE_LISTEN_PORT` | Public UDP listen port; defaults to `443` |
| `MASQUE_CERT_LISTEN_PORT` | `dual` only; certificate listener port, defaults to `4443` |
| `MASQUE_TLS_CERT` / `MASQUE_TLS_KEY` | Source PEM certificate and key copied into `/etc/masque/certs` |
| `MASQUE_CLIENT_NAME` | First certificate-authenticated client label |
| `MASQUE_CLIENT_ENDPOINT` | Required public server endpoint in `IP:port` form |
| `MASQUE_CLIENT_IPV4` / `MASQUE_CLIENT_IPV6` | Pinned addresses; use `none` to omit one family |
| `MASQUE_CLIENT_CONFIG_OUT` | Absolute secret JSON output path; defaults to `/root/masque-client.json` |
| `MASQUE_START_SERVICE` | `1` to start/restart, `0` to stage only; bootstrap default is `1` |
| `MASQUE_RUN_HOST_DIAGNOSTICS` | `1` to run the read-only CONNECT-IP host check after installation (default), `0` to skip |

For example, a non-interactive client-certificate installation is:

```sh
curl -fsSL https://raw.githubusercontent.com/Vincent-bin/masque-server/main/install-latest.sh | \
  sudo env \
    MASQUE_AUTH_MODE=client_cert \
    MASQUE_TLS_CERT=/root/fullchain.pem \
    MASQUE_TLS_KEY=/root/privkey.pem \
    MASQUE_LISTEN_PORT=8449 \
    MASQUE_CLIENT_NAME=laptop \
    MASQUE_CLIENT_ENDPOINT=203.0.113.9:8449 \
    MASQUE_CLIENT_IPV4=10.89.0.2 \
    MASQUE_CLIENT_IPV6=fd00:abcd::2 \
    MASQUE_CLIENT_CONFIG_OUT=/root/laptop.json \
    sh
```

`MASQUE_VERSION=0.6.0` selects `v0.6.0`. This is also how to install a
prerelease explicitly; automatic resolution deliberately chooses only GitHub's
latest stable release. Authentication, listen, TLS-source, and client
provisioning variables apply only when `/etc/masque/masque.toml` does not yet
exist.

The same one-command installer is safe to reuse for later releases. If the
configuration already exists, the downloaded candidate runs `check-config`
against it before any installed file is replaced. A failed check leaves the
server/probe binaries, systemd unit, monitoring assets, configuration, TLS
files, and running service untouched. On success, both binaries, the packaged systemd unit, Prometheus
rules, and Grafana dashboard are upgraded; the TOML and every TLS path it
references remain unchanged. If the requested service restart then fails, the
installer restores the previous release-managed files, enabled state, and
active state. Upgrade output reports the resolved listener and authentication
summary but does not print the existing configuration contents.

## Install a downloaded archive

```sh
tar xzf masque-vVERSION-linux-ARCH.tar.gz
cd masque-vVERSION-linux-ARCH
sudo ./install.sh
```

To configure Basic credentials non-interactively during a new installation:

```sh
sudo MASQUE_AUTH_USERNAME='proxy-user' \
  MASQUE_AUTH_PASSWORD='replace-this-password' \
  ./install.sh
```

If no password is supplied, the installer creates a random one and displays it
once. Store it immediately in a password manager.

For an interactive new installation, `sudo ./install.sh` asks whether to use
Basic, client-certificate, or dual authentication. The package installer enables but
does not start the service unless `MASQUE_START_SERVICE=1`; the bootstrap above
sets it to `1` by default.

The installer creates:

- `/usr/local/bin/masque-server`;
- `/usr/local/bin/masque-probe`;
- `/etc/masque/masque.toml`;
- `/etc/masque/certs/`;
- `/etc/systemd/system/masque.service`;
- `/usr/local/share/masque-server/monitoring/prometheus-rules.yml`;
- `/usr/local/share/masque-server/monitoring/grafana-dashboard.json`; and
- the unprivileged `masque` user and group.

It preserves every existing configuration and referenced TLS file byte for
byte during an upgrade.

## Certificates

Install the full certificate chain and unencrypted private key:

```sh
sudo install -o root -g masque -m 0640 fullchain.pem \
  /etc/masque/certs/server.crt
sudo install -o root -g masque -m 0640 privkey.pem \
  /etc/masque/certs/server.key
```

After an ACME client has installed **both** renewed files with those ownership
and mode settings, activate them without restarting the service:

```sh
sudo systemctl reload masque
sudo journalctl -u masque -n 20 --no-pager
```

New HTTP/2 and HTTP/3 handshakes use the replacement identity. Established
connections remain up with the identity selected by their original handshake.
The server validates the full chain, private key, and public-key match before
swapping one in-memory snapshot; on failure the journal reports the error and
the previous identity stays active. `systemctl reload` only sends the signal,
so use the journal or `masque_tls_reloads_total` to confirm the outcome.

Put the install of both files and `systemctl reload masque` in the ACME deploy
hook, which runs only after successful renewal. The paths must remain readable
through the unit's filesystem sandbox; `/etc/masque/certs` is recommended.
Replacing file contents or symlink targets is reloadable, but changing the
configured paths requires a restart.

## Network and firewall

Open the socket protocol selected by each listener: `transport = "http3"`
needs inbound UDP, while `transport = "http2"` needs inbound TCP. They may use
the same numeric port because TCP and UDP are separate namespaces. For example,
dual transport on port 8449 needs both UDP/8449 and TCP/8449.

Standard CONNECT and CONNECT-UDP need ordinary outbound TCP/UDP access.
CONNECT-IP additionally needs:

- `/dev/net/tun`;
- IPv4/IPv6 forwarding as appropriate;
- firewall rules for the configured pools; and
- optional NAT when assigned client addresses are not routed upstream.

Avoid broad NAT or forwarding rules until the exact TUN name and address pools
have been verified.

These requirements come from CONNECT-IP, not from Basic versus client
certificate authentication. A certificate-authenticated CONNECT or CONNECT-UDP
client still uses userspace sockets; mihomo/usque-style clients combine client
certificates with `cf-connect-ip`, which is why they need the host path below.

After the service has created its TUN interface, run the read-only diagnostic:

```sh
sudo masque-server --config /etc/masque/masque.toml doctor
```

It checks `/dev/net/tun`, IPv4/IPv6 forwarding, the configured interface and
pool routes, and available iptables/nftables evidence for forwarding and NAT.
Forwarding and TUN are hard prerequisites. Firewall and NAT results are warnings
because a routed prefix or upstream gateway can be valid without a local
MASQUERADE rule. Neither `doctor`, startup, nor the installer changes host
networking. Persist any required rules through the firewall manager already
used by the machine.

## systemd

```sh
sudo systemctl start masque
sudo systemctl status masque --no-pager
sudo journalctl -u masque -f
```

The supplied unit uses `Type=notify`, an unprivileged account, a read-only filesystem view,
restricted kernel access, and only `CAP_NET_BIND_SERVICE` plus
`CAP_NET_ADMIN`. If CONNECT-IP is disabled and the listen port is above 1023,
both capabilities can be removed from a local override.

Check the effective sandbox:

```sh
systemd-analyze security masque.service
```

## Add a listener after installation

The installer writes listeners only for a fresh installation; an upgrade keeps
the existing file untouched. To add one to a deployed server — a second socket
for the authentication mode the first does not serve, for example — use:

```sh
sudo masque-server --config /etc/masque/masque.toml add-listener
sudo systemctl restart masque
```

It prompts for the transport, address, authentication mode, and any credentials,
validates the merged file the way the upgrade preflight does, and test-binds the
new address; anything wrong leaves the file byte for byte unchanged. The file is
replaced atomically with its mode and owner preserved, so the service account
keeps its access. Flags cover every value for unattended use; see
[Adding a listener](configuration.md#adding-a-listener).

Open the new UDP or TCP port in the firewall as appropriate — see
[Network and firewall](#network-and-firewall). A new socket is bound at startup,
so the restart is required; `systemctl reload` only re-reads the TLS identity
and active `[[clients]]` roster.

The bind test describes the moment it ran, so confirm the service after the
restart rather than assuming it:

```sh
sudo systemctl restart masque
systemctl status masque --no-pager
```

If it failed to bind, the journal names the address, and the previous
configuration is one `[[listeners]]` block away — remove the appended block and
restart. Keep the usual configuration backups; this command edits in place and
does not keep a copy.

## Service lifecycle

`systemctl stop` and `systemctl restart` send SIGTERM. The server receives that
signal once and broadcasts the shutdown request to every worker. HTTP/3 sends
GOAWAY and QUIC CONNECTION_CLOSE; HTTP/2 starts an H2 graceful shutdown. Both
drain existing connections for at most five seconds. The packaged unit sets
`TimeoutStopSec=10s`, leaving a second five-second margin before systemd may
escalate to SIGKILL.

systemd considers startup complete only after the process has bound every
proxy listener and the optional observability endpoint and sent `READY=1`.
The packaged unit also sets `WatchdogSec=30s`; pings stop if any shard misses
its five-second liveness window, allowing systemd to restart a wedged process.
Graceful shutdown sends `STOPPING=1` as readiness changes to false.

SIGINT follows the same path for foreground runs. SIGHUP remains distinct: it
atomically reloads the TLS identity, every active Basic account set, and, when
client-certificate authentication is active, the `[[clients]]` roster. It does
not stop the service or disturb established tunnels, except that certificate
roster revocation disconnects the affected client. Manage Basic accounts with
`list-users`, `add-user`, `set-password`, and `remove-user`; see
[Basic account management](configuration.md#basic-account-management).

## Upgrade

For the latest stable release, rerun the bootstrap command:

```sh
curl -fsSL https://raw.githubusercontent.com/Vincent-bin/masque-server/main/install-latest.sh | sudo sh
sudo systemctl status masque --no-pager
```

The candidate first runs the equivalent of:

```sh
masque-server --config /etc/masque/masque.toml check-config
```

This validates the parts of startup that do not need live resources. A file
that no longer satisfies fail-closed authentication, a bad
certificate/key pair, an unsupported HTTP/2 or QUIC setting, or an invalid
client/address pool therefore stops the upgrade before replacement. Edit and validate such a
configuration deliberately; the installer never migrates it automatically.

After a successful upgrade, inspect service status and run a client
connectivity and throughput smoke test. Keep independent backups as part of
normal operations even though the installer performs a temporary transactional
rollback around both binaries, the unit, and packaged monitoring-asset replacement.

For optional health checks, Prometheus scraping, alert rules, and the dashboard
JSON, see [Observability](observability.md). The installer copies those static
assets but never installs or starts Prometheus or Grafana on the server.

## Diagnostics

Start with configuration and host diagnostics, then confirm the listener and
process:

```sh
sudo masque-server --config /etc/masque/masque.toml check-config
sudo masque-server --config /etc/masque/masque.toml doctor
sudo ss -u -l -p | grep masque-server
sudo ss -t -l -p | grep masque-server
systemctl show masque -p MainPID -p ActiveState -p SubState
```

From the affected client network, run `masque-probe` with Basic credentials or
an enrollment JSON. It validates real upstream TCP CONNECT establishment and a
CONNECT-UDP DNS round trip instead of merely checking whether the port opens:

```sh
printf '%s' 'client-password' | masque-probe proxy.example.com:8449 \
  --username client-name --password-stdin
masque-probe proxy.example.com:4443 --client-config client.json --connect-ip
```

Create a private, shareable server report with:

```sh
sudo masque-server --config /etc/masque/masque.toml support-bundle \
  --out /root/masque-support.json
```

The command refuses to overwrite an existing file and excludes raw
configuration, credentials, client identities, key material, environment,
logs, and traffic details. Review it before sharing. See
[Troubleshooting](troubleshooting.md) for the full diagnostic flow.

Inspect UDP batching during a controlled benchmark:

```sh
sudo strace -f -c -e trace=sendmmsg,sendmsg,recvmmsg \
  -p "$(pidof masque-server)"
```

The musl release should show real `sendmmsg` and `recvmmsg` calls. Run tracing
only briefly; it changes timing.

For persistent failures, attach the support bundle and the probe's `--json`
output. Keep any separately requested log excerpt private until it has been
reviewed; never publish certificates, password hashes, credentials, or captured
user traffic.
