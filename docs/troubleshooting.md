# Troubleshooting

Separate client-path failures from server-host failures before changing tuning
or firewall rules. `masque-probe` exercises the actual protocol from the client
network; `check-config`, `doctor`, and `support-bundle` inspect the server
without changing it.

## Evidence workflow for AI-assisted diagnosis

Start with read-only checks and preserve the distinction between an observation,
an inference, and an untested hypothesis. Record the approximate incident time,
affected transport and traffic type, client-side symptom, recent relevant
change, and server/probe versions when known. Use generic host roles in reports.

| Evidence | What it can establish | What it cannot establish |
| --- | --- | --- |
| Fleet `validate` and `status` | Inventory validation and reported service, version, configuration and certificate state | End-to-end traffic or root cause |
| Bounded fleet `diagnose` | Filtered, time-relevant service diagnostics | Complete history or absence of sensitive client/destination metadata |
| Local `check-config` and `status` | Disk validity; `status` also compares loaded configuration when its private live socket is available | External connectivity; loaded state when status says `unknown` |
| Local `doctor` | Read-only evidence of CONNECT-IP host prerequisites | A successful forwarding path or the correctness of all firewall and network state |
| Client-side `masque-probe --json` | Results for the checks actually run from that client path, including selected transport, warning/failure codes and duration | Unselected or skipped transports, every client network, or CONNECT-IP packet forwarding from negotiation alone |
| Local `support-bundle` | Structured snapshot of a valid configuration, service metadata, and diagnostic result levels | Invalid configurations, logs, actual traffic, or end-to-end success |

For a fleet, use the `masque-ops` Skill's `validate`, `status`, and bounded
`diagnose` flow; do not replace it with ad hoc SSH or read private inventory.
For local diagnosis, choose the corresponding local commands below. A support
bundle is produced only after configuration validation succeeds; if validation
fails, record the sanitized validation failure instead of treating the missing
bundle as evidence that the service is healthy.

Run a probe from the affected client network when available. Capture the
requested and selected transport, each relevant check's status and code, and
whether TCP, UDP, or IP checks were skipped. Auto mode may report success after
HTTP/2 fallback even though HTTP/3 failed; use an explicit transport to isolate
each requested path. CONNECT-IP negotiation alone does not verify packet
forwarding. Compare equivalent checks before and after a change, and include
time and scope so unrelated observations are not conflated.

Use a concise sanitized evidence record:

```text
Scope: generic host role, affected transport and traffic type, incident time
Observed: source, check and status/code; relevant version and duration if known
Inference: likely explanation and the evidence supporting it
Not verified: skipped/unavailable checks and alternative explanations
Next check: smallest read-only test that distinguishes those explanations
```

Probe JSON, support bundles, local status output, and even filtered fleet
diagnostics can contain endpoints, listener addresses, aliases, TUN names, or
other private metadata. Keep raw reports private and outside the repository;
extract only the minimum facts into the record. Never share credentials, hashes,
private paths, or raw configuration. Follow [AGENTS.md](../AGENTS.md) before
publishing any diagnostic summary. Do not change configuration or perform a
deployment solely because one signal suggests a cause; use the supported change
workflow and its authorization and verification boundaries.

## Client-side connectivity probe

Install the standalone probe on a Linux or macOS x86_64/ARM64 client; the
installer selects the local architecture and verifies the release SHA-256:

```sh
curl -fsSL https://raw.githubusercontent.com/Vincent-bin/masque-server/main/install-probe.sh | sh
```

Linux server archives also install `/usr/local/bin/masque-probe` beside the
service. Run it from the same network and interface as the application that
fails.

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

- TCP CONNECT to `example.com:443` followed by a verified target TLS handshake;
- CONNECT-UDP to `1.1.1.1:53` with a real DNS query and matching response; and
- when `--connect-ip` is set, address assignment and an IP/UDP DNS round trip to
  `1.1.1.1:53` inside the tunnel (no local TUN or raw-socket privileges needed).

Use `--tcp-target` or `--udp-target` when server policy intentionally blocks the
defaults. `--tcp-mode echo` and `--udp-mode echo` require controlled echo
targets. TCP echo validates a random payload; the default `--tcp-mode tls`
validates the target certificate using platform roots independently of proxy
`--ca-cert` / `--insecure`. An HTTP 200 with no forwarded data now fails.
For CONNECT-IP use `--ip-target IP:PORT` and optionally `--ip-mode echo`.
`--ip-setup-only --connect-ip` explicitly checks negotiation only and reports
`CONNECT_IP_SETUP_ONLY` as a warning. Only `CONNECT_IP_ROUND_TRIP` establishes
packet forwarding to the tested destination. A firewall, ACL or routing issue
can make setup succeed while the packet check fails.
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
| `AUTH_REJECTED` | A legacy or external server returned 407; verify the Basic listener and credential |
| `TCP_RESPONSE_TIMEOUT` / `TCP_RESPONSE_INVALID` | CONNECT opened but target data did not pass validation |
| `TCP_TLS_FAILED` | Target TLS handshake or target certificate validation failed inside CONNECT |
| `CONNECT_IP_RESPONSE_TIMEOUT` / `CONNECT_IP_RESPONSE_INVALID` | CONNECT-IP opened but the inner IP/UDP response did not pass validation |
| `TARGET_POLICY_DENIED` | The configured allow/deny policy rejected the probe target |
| `PROTOCOL_REJECTED` | HTTP 404: verify credentials, endpoint and CONNECT support; this response does not distinguish authentication failure from an unsupported request |
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
