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

## Installation

```sh
tar xzf masque-vVERSION-linux-x86_64.tar.gz
cd masque-vVERSION-linux-x86_64
sudo ./install.sh
```

To choose credentials during a new installation:

```sh
sudo MASQUE_AUTH_USERNAME='proxy-user' \
  MASQUE_AUTH_PASSWORD='replace-this-password' \
  ./install.sh
```

If no password is supplied, the installer creates a random one and displays it
once. Store it immediately in a password manager.

The installer creates:

- `/usr/local/bin/masque-server`;
- `/etc/masque/masque.toml`;
- `/etc/masque/certs/`;
- `/etc/systemd/system/masque.service`; and
- the unprivileged `masque` user and group.

It enables but does not start the service.

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

1. Verify and extract the new archive.
2. Save the current binary and configuration using your normal backup system.
3. Run the new `install.sh`; it preserves the existing TOML file.
4. Compare `/etc/masque/masque.toml` with the packaged example.
5. Restart and inspect status and logs.
6. Run a client connectivity and throughput smoke test.

```sh
sudo ./install.sh
sudo systemctl restart masque
sudo systemctl status masque --no-pager
```

The installer may create `/etc/masque/masque.toml.before-auth` when upgrading a
legacy configuration that lacks authentication.

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
