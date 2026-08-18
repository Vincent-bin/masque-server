# Linux deployment

## Supported release artifact

GitHub Actions builds a static `x86_64-unknown-linux-musl` binary and packages:

```text
bin/masque-server
config/masque.toml
systemd/masque.service
install.sh
README.md
```

Verify the archive before extraction:

```sh
sha256sum --check masque-vVERSION-linux-x86_64.tar.gz.sha256
```

## One-command install

On Linux x86_64, the bootstrap installer resolves the latest stable GitHub
release, downloads its archive and checksum, verifies SHA-256, and invokes the
installer from that archive:

```sh
curl -fsSL https://raw.githubusercontent.com/Vincent-bin/masque-server/main/install-latest.sh | sudo sh
```

Although the script arrives on standard input, interactive answers are read
from `/dev/tty`. A new installation offers two mutually exclusive modes:

- `basic` generates a high-entropy password unless one is provided and prints
  the credentials once;
- `client_cert` enrolls the first client, appends the generated `[[clients]]`
  entry, writes the usque JSON to a new `0600` file, and prints the mihomo block.

Client-certificate enrollment needs the server's ECDSA certificate immediately
because the generated client configuration pins its public key. Supply the PEM
full chain and unencrypted private key when prompted. Basic mode may defer TLS
installation, but the service cannot start until both files exist.

The final output includes the installed version, authentication mode, service
state, and complete effective TOML with the password hash redacted. It also
includes a generated Basic password or, in `client_cert` mode, client private
key material. Treat the terminal output as a secret and do not capture it in a
public provisioning log.

The following environment variables make provisioning non-interactive:

| Variable | Meaning |
| --- | --- |
| `MASQUE_VERSION` | Exact published version/tag instead of the latest stable release |
| `MASQUE_AUTH_MODE` | `basic` or `client_cert` |
| `MASQUE_AUTH_USERNAME` | Basic username; defaults to `masque` |
| `MASQUE_AUTH_PASSWORD` | Basic password; random when omitted |
| `MASQUE_LISTEN_PORT` | Public UDP listen port; defaults to `443` |
| `MASQUE_TLS_CERT` / `MASQUE_TLS_KEY` | Source PEM certificate and key copied into `/etc/masque/certs` |
| `MASQUE_CLIENT_NAME` | First certificate-authenticated client label |
| `MASQUE_CLIENT_ENDPOINT` | Required public server endpoint in `IP:port` form |
| `MASQUE_CLIENT_IPV4` / `MASQUE_CLIENT_IPV6` | Pinned addresses; use `none` to omit one family |
| `MASQUE_CLIENT_CONFIG_OUT` | Absolute secret JSON output path; defaults to `/root/masque-client.json` |
| `MASQUE_START_SERVICE` | `1` to start/restart, `0` to stage only; bootstrap default is `1` |

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

`MASQUE_VERSION=0.2.0` selects `v0.2.0`. This is also how to install a
prerelease explicitly; automatic resolution deliberately chooses only GitHub's
latest stable release. Authentication, listen, TLS-source, and client
provisioning variables apply only when `/etc/masque/masque.toml` does not yet
exist.

The same one-command installer is safe to reuse for later releases. If the
configuration already exists, the downloaded candidate runs `check-config`
against it before any installed file is replaced. A failed check leaves the
binary, systemd unit, configuration, TLS files, and running service untouched.
On success, only the binary and packaged systemd unit are upgraded; the TOML
and every TLS path it references remain unchanged. If the requested service
restart then fails, the installer restores the previous binary, unit, enabled
state, and active state.

## Install a downloaded archive

```sh
tar xzf masque-vVERSION-linux-x86_64.tar.gz
cd masque-vVERSION-linux-x86_64
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
Basic or client-certificate authentication. The package installer enables but
does not start the service unless `MASQUE_START_SERVICE=1`; the bootstrap above
sets it to `1` by default.

The installer creates:

- `/usr/local/bin/masque-server`;
- `/etc/masque/masque.toml`;
- `/etc/masque/certs/`;
- `/etc/systemd/system/masque.service`; and
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

The service must be restarted after certificate renewal unless an external
unit performs that restart. Validate hostname, validity, and chain before
changing production files.

## Network and firewall

Open the configured UDP port, not TCP. For example, a server listening on 8449
needs inbound UDP/8449.

Standard CONNECT and CONNECT-UDP need ordinary outbound TCP/UDP access.
CONNECT-IP additionally needs:

- `/dev/net/tun`;
- IPv4/IPv6 forwarding as appropriate;
- firewall rules for the configured pools; and
- optional NAT when assigned client addresses are not routed upstream.

Avoid broad NAT or forwarding rules until the exact TUN name and address pools
have been verified.

## systemd

```sh
sudo systemctl start masque
sudo systemctl status masque --no-pager
sudo journalctl -u masque -f
```

The supplied unit uses an unprivileged account, a read-only filesystem view,
restricted kernel access, and only `CAP_NET_BIND_SERVICE` plus
`CAP_NET_ADMIN`. If CONNECT-IP is disabled and the listen port is above 1023,
both capabilities can be removed from a local override.

Check the effective sandbox:

```sh
systemd-analyze security masque.service
```

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

This validates the parts of startup that do not need live resources. A legacy
configuration that no longer satisfies fail-closed authentication, a bad
certificate/key pair, an unsupported QUIC setting, or an invalid client/address
pool therefore stops the upgrade before replacement. Edit and validate such a
configuration deliberately; the installer never migrates it automatically.

After a successful upgrade, inspect service status and run a client
connectivity and throughput smoke test. Keep independent backups as part of
normal operations even though the installer performs a temporary transactional
rollback around the binary and unit replacement.

## Diagnostics

Confirm the listener and process:

```sh
sudo ss -u -l -p | grep masque-server
systemctl show masque -p MainPID -p ActiveState -p SubState
```

Inspect UDP batching during a controlled benchmark:

```sh
sudo strace -f -c -e trace=sendmmsg,sendmsg,recvmmsg \
  -p "$(pidof masque-server)"
```

The musl release should show real `sendmmsg` and `recvmmsg` calls. Run tracing
only briefly; it changes timing.

For persistent failures, collect the version, configuration with secrets
redacted, kernel version, interface offload state, service status, and a short
log excerpt. Never publish certificates, password hashes, credentials, or
captured user traffic.
