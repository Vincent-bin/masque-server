# Troubleshooting

Separate client-path failures from server-host failures before changing tuning
or firewall rules. `masque-probe` exercises the actual protocol from the client
network; `check-config`, `doctor`, and `support-bundle` inspect the server
without changing it.

## Client-side connectivity probe

Release archives install `/usr/local/bin/masque-probe` beside the server. Copy
that binary to the affected Linux client if necessary, and run it from the same
network and interface as the application that fails.

For Basic authentication, pass the password on stdin so it never appears in
the process list:

```sh
printf '%s' 'client-password' | masque-probe proxy.example.com:8449 \
  --username client-name --password-stdin
```

For client-certificate authentication, use the secret enrollment JSON produced
by `enroll-client`:

```sh
masque-probe proxy.example.com:4443 --client-config client.json --connect-ip
```

The default `--transport auto` tries HTTP/3 first. If UDP/QUIC cannot establish
a session, the report records that failure as a warning and tries HTTP/2 on the
same numeric port. Use `--transport http3` or `--transport http2` to test one
path without fallback. HTTP/3 needs an inbound UDP listener; HTTP/2 needs a TCP
listener.

After the handshake, the default checks perform:

- upstream TCP CONNECT establishment to `example.com:443`;
- CONNECT-UDP to `1.1.1.1:53` with a real DNS query and matching response; and
- CONNECT-IP negotiation/address assignment only when `--connect-ip` is set.

Use `--tcp-target` or `--udp-target` when server policy intentionally blocks the
defaults. `--udp-mode echo` is available for a controlled UDP echo target.
`--skip-tcp` and `--skip-udp` isolate one protocol without treating the skipped
check as a failure.

Public Basic endpoints use the platform CA roots and hostname verification by
default. `--ca-cert` adds a private CA. `--insecure` is only a temporary
diagnostic and is reported as a warning. Enrollment mode always checks the
server public key pinned in the enrollment JSON; `--insecure` cannot disable
that pin.

### Fake-IP DNS and route selection

Some local proxy configurations answer DNS with an address in `198.18.0.0/15`.
The probe reports `DNS_FAKE_IP_DETECTED`; that address may lead back into the
proxy rather than to the server. Retain the hostname for TLS and HTTP while
dialing the real address explicitly:

```sh
masque-probe proxy.example.com:8449 --resolve 203.0.113.9 \
  --username client-name --password-stdin
```

On macOS or Linux, `--interface en0` (replace `en0`) binds the HTTP/3 UDP socket
to a specific interface. It does not affect the HTTP/2 TCP fallback. Combining
`--resolve` and `--interface` is useful when a system proxy changes both DNS and
the default route.

### Machine-readable results

`--json` emits a stable schema with the requested and selected transport, each
check's status/code/detail/duration, and the overall result. Exit status is zero
only when a transport was selected and no check failed. Warnings, including a
successful HTTP/2 fallback, do not fail the run.

```sh
printf '%s' 'client-password' | masque-probe proxy.example.com:8449 \
  --username client-name --password-stdin --json >probe.json
```

Useful result codes include:

| Code | Meaning |
| --- | --- |
| `AUTH_REJECTED` | The server returned 407; select the correct Basic listener and credential |
| `TARGET_POLICY_DENIED` | The configured allow/deny policy rejected the probe target |
| `PROTOCOL_REJECTED` | The listener does not expose the requested CONNECT protocol |
| `TARGET_CONNECT_FAILED` | The proxy was reached, but target connection failed (HTTP 502) |
| `TLS_PIN_MISMATCH` | Enrollment JSON pins a different server key |
| `DNS_FAKE_IP_DETECTED` | Local DNS returned a synthetic address; retry with `--resolve` |
| `RESPONSE_TIMEOUT` | Handshake or tunnel succeeded far enough to wait, but no response arrived |

The detailed code distinguishes DNS, UDP socket, TCP connect, TLS, HTTP/2,
HTTP/3, capsule, and response failures, so retain the complete JSON rather than
copying only the last line.

## Server-side checks

First validate what the process would load, then inspect CONNECT-IP host
prerequisites:

```sh
sudo masque-server --config /etc/masque/masque.toml check-config
sudo masque-server --config /etc/masque/masque.toml doctor
sudo systemctl status masque --no-pager
```

`check-config` parses the TLS identity, credentials, roster, policies, transport
settings, and address pools without binding sockets or creating a TUN. `doctor`
adds read-only TUN, forwarding, route, firewall, and optional NAT evidence. It
does not install a route, modify a sysctl, or change a firewall.

## Server-side support bundle

For a persistent problem, create one attachable report:

```sh
sudo masque-server --config /etc/masque/masque.toml support-bundle \
  --out /root/masque-support.json
```

The command validates the configuration first, creates a new mode-`0600` file,
syncs it, and refuses to overwrite any existing path. The JSON includes:

- server version, operating system, architecture, kernel, and logical CPUs;
- resolved listeners, transport, shard count, authentication kind, and only
  the number of Basic users;
- enabled protocols, policy-rule counts, bounded tuning fields, and
  observability address;
- TLS file existence/size/permissions and certificate validity window;
- read-only CONNECT-IP diagnostic names and result levels (free-form command
  output is excluded); and
- bounded `masque.service` load/active/enabled state when systemd is available.

It deliberately excludes raw configuration, usernames and password hashes,
client labels and assigned addresses, certificate identity/serial, public and
private keys, environment variables, logs, and traffic destinations/counters.
This exclusion is structural rather than a regular-expression pass over secret
text. Still review the resulting JSON before sharing because listener addresses,
TUN names, kernel version, and service state are operational metadata.

Logs are not bundled automatically. If a maintainer asks for a short journal
excerpt, collect and review it separately:

```sh
sudo journalctl -u masque --since '-10 minutes' --no-pager
```

Do not publish credentials, password hashes, enrollment files, TLS keys,
complete production configuration, packet captures, or user traffic.
