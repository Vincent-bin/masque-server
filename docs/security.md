# Security and hardening

## Threat model

The listeners are expected to receive arbitrary TCP, UDP, TLS, QUIC, HTTP/2,
HTTP/3, CONNECT,
credential, and target data from the internet. A successful client can ask the
server to originate TCP/UDP traffic, and CONNECT-IP clients can exchange raw IP
packets through the host. The principal risks are:

- unauthenticated resource exhaustion;
- password guessing and memory-hard hash amplification;
- disclosure or misdistribution of an enrolled client's private key, which is a
  bearer credential;
- access to loopback, metadata, management, or private networks;
- unbounded buffering under a slow client or target;
- malformed packet or capsule parsing;
- abuse of TUN, forwarding, or Linux capabilities; and
- credential, key, target, or traffic disclosure through logs.

## Authentication

Authentication is enabled and fail-closed by default. Passwords are stored as
Argon2id PHC hashes and compared only after strict Basic-header and username
prechecks.

Argon2 work runs outside shard event loops. Running plus queued verifications
are globally bounded, concurrent hashes are permit-limited, and each
connection has a pending-request cap. A per-source fair-share cap prevents one
address from filling the global queue. Closing a stream or connection cancels
work that has not started and discards results for work already running.
Each Basic listener is also limited to 4,096 configured accounts; adding
accounts does not enlarge any Argon2 concurrency or queue limit.

Give each client or operator a distinct account with a unique, high-entropy
password. Basic credentials are protected by TLS in transit but are reusable
bearer secrets at the HTTP layer. A compromised account can then be rotated or
removed without changing every other client. Account edits become active on
`SIGHUP`; existing tunnels remain, while later CONNECT requests use the new
snapshot.

With a listener's `auth.mode = "client_cert"` the cost profile is different: identity is
established once during the handshake, by public key, so there is no per-request
verification to bound and no password to brute-force. An unenrolled key is
refused with a TLS alert before it can open a stream, which keeps unauthorized
callers off the request path entirely. The trade-off is that authorization is
per connection rather than per request — every stream on an established
connection is already authorized. See
[TLS and credentials](#tls-and-credentials) for what counts as a credential
under that mode.

## Target policy

Default policy blocks common loopback and private ranges, but operators must
adapt it to their environment. Explicitly deny:

- cloud metadata endpoints;
- orchestration and container control planes;
- hypervisor, router, and out-of-band management networks;
- internal DNS, databases, and service meshes not intended for clients; and
- link-local and unique-local ranges where inappropriate.

DNS names are resolved once under a bounded setup deadline. The complete
snapshot must pass CIDR policy, and socket setup consumes that same snapshot
rather than looking the name up again. This closes the policy/connect gap an
attacker-controlled short-TTL name could otherwise use for DNS rebinding.
Mixed allowed and denied answers fail closed.

Disable TCP, UDP, or IP proxy sections that are not required.

## Resource safety

Connection, tunnel, authentication, cross-shard, relay, QUIC DATAGRAM, and TCP
buffer limits prevent application-level unbounded growth. These bounds do not
replace host controls. Apply reasonable systemd limits, provider firewall rate
limits, and monitoring for memory, CPU, file descriptors, authentication
failures, connections, and datagram drops.

HTTP/2 and HTTP/3 share a process-wide live-connection cap per canonical source
IP. HTTP/3 additionally uses authenticated QUIC Retry tokens adaptively: once a
shard reaches the configured threshold, a new source must prove it can receive
at its claimed address before the server allocates connection state. The token
binds the source IP and listener but not the source port, so normal NAT remaps
do not break it. Use `retry_mode = "always"` where spoofed floods are a primary
risk; it costs one extra handshake round trip.

An established HTTP/3 connection may move to a new peer IP or UDP port. quiche
does not report the migration until PATH_CHALLENGE/PATH_RESPONSE proves return
routability. Only then does the server atomically transfer the connection's
per-source admission guard; if the new source is already at its limit, the
connection closes and the original counter remains balanced. Each connection
advertises only one spare CID and retains only a bounded path-challenge queue,
so source-port churn cannot create unbounded routing or validation state.
Multi-shard Linux listeners reserve one of the 16 CID bytes for kernel socket
selection; the other 15 bytes remain keyed or randomly generated, retaining
120 bits of unpredictability. Failure to attach the selector changes only
performance: the bounded userspace ownership map still routes valid packets.

The optional operational endpoint has no authentication and therefore accepts
only loopback addresses. It must stay host-local: use a local collector or a
secure tunnel instead of forwarding `/metrics` to a public interface. Metric
labels exclude usernames, client identities, targets, stream IDs, and
connection IDs.

Do not respond to overload by making queues arbitrarily deep; this can turn
packet loss into seconds of latency and make memory exhaustion easier.

Configuration validation also applies hard ceilings to attacker-controlled
protocol credit: connection and tunnel counts, H2/H3 stream counts, receive
windows, H2 header/send buffers, and both QUIC DATAGRAM queues. This prevents a
mistyped deployment value from silently removing the runtime bounds.
Process-lifetime `*_max` metrics make the actual connection, tunnel, and
authentication high-water marks observable after a burst has ended.

The scheduled Linux pressure test runs the daemon as a separate process and
floods wrong passwords, half-open TLS sockets, excess streams, and DATAGRAM
capsules. It checks authentication and tunnel high-water marks, CPU ticks,
resident-memory growth, and `/proc/<pid>/fd` against the configured ceilings.

`masque-server support-bundle` is deliberately a metadata-only diagnostic. It
does not copy the configuration, logs, environment, usernames, password hashes,
client labels or keys, certificate identities, target addresses, or traffic
data. The generated file is created as mode `0600` and never overwrites an
existing path. It can still reveal operational details such as listener counts,
enabled transports, kernel version, and certificate validity windows, so review
the JSON before sharing it outside the operator team.

## TLS and credentials

- Keep the private key and configuration `root:masque` mode `0640`.
- Do not pass passwords as command-line arguments.
- Do not commit real certificates, hashes, passwords, IPs, or server inventory.
- Avoid trace logging in production except during a short controlled incident.

Install both renewed TLS files before sending `SIGHUP`. The server builds and
validates a complete certificate/key and Basic/certificate-credential
transaction before publishing it; failed reads, malformed PEM, mismatched keys,
duplicate usernames, and invalid password hashes leave the previous snapshots
active. Existing connections pin the snapshot selected during their handshake,
while new handshakes see the replacement. File paths are fixed at startup, so
keep their parent directories and symlink update process writable only by the
operator or ACME service account.

Each successful reload advances the TLS session ID context. Session tickets
from the previous identity or roster therefore cannot bypass certificate
rotation or client revocation: BoringSSL falls back to a full handshake and
issues tickets in the new context.

TLS 1.3 Early Data is unconditionally disabled. CONNECT, CONNECT-UDP, and
CONNECT-IP create externally visible network effects and are not replay-safe;
they are accepted only after the peer's Finished message. Session resumption
still works, but a ticket issued by this server never authorizes 0-RTT. The H3
application gate independently rejects an Early Data state as defense in depth.

The right server certificate depends on the authentication mode, because the
two modes establish server identity in completely different ways.

### With listener `auth.mode = "basic"`

Clients validate the certificate normally. Use one trusted by them and covering
the exact proxy hostname, and renew it before expiry as usual.

### With listener `auth.mode = "client_cert"`

Clients in this family skip chain validation entirely — the SNI they send names
a vendor endpoint rather than this server — and instead pin the leaf public key
they were enrolled with. Chain, hostname, and expiry therefore play no part in
their trust decision.

A self-signed certificate is appropriate here, and is what `scripts/gen-certs.sh`
produces. Pinning trusts exactly one key distributed out of band rather than
every public CA, so the trusted set is smaller than under PKI. A CA-issued
certificate brings no benefit to these clients and introduces a hazard: ACME
renewal rotates the key by default, and a new key invalidates every client's
pin. If you use one anyway, renew with a stable key.

Consequences worth planning for:

- **Replacing the certificate is a flag day.** Every enrolled client pins the
  old key and stops connecting. Re-enroll and redistribute, or renew with the
  same key to preserve the pin.
- **A client's `--insecure`-style flag disables pinning** and exposes it to
  interception. Use it only to diagnose a pin mismatch, never in production.
- **Compromise of the server private key** allows impersonating this server to
  every client, exactly as it would under PKI.

### What is and is not a credential

- `[[clients]]` holds only **public** keys. A leaked server configuration does
  not let anyone connect.
- The **client private key** — in the enrolled JSON or `proxies:` entry — is a
  bearer credential: whoever holds it is that client. With `--out`,
  `enroll-client` writes the JSON as `0600` and refuses to overwrite an existing
  path. Distribute it over a confidential channel and treat the command's
  terminal output, including the mihomo entry, as secret.
- The one-command installer prints its effective configuration with password
  hashes redacted, but it also prints a newly generated Basic password or the
  mihomo client block. Run it only from a private terminal and keep provisioning
  systems from copying that output into shared logs.
- Skipping chain validation does not weaken proof of possession. TLS 1.3 makes
  the client sign the handshake transcript with the certificate's private key,
  and that signature is verified by the TLS stack; the roster check replaces
  only the X.509 trust decision. Knowing a client's public key is therefore not
  enough to impersonate it.
- Roster entries do not expire on their own. Revoke a client by deleting its
  `[[clients]]` entry and sending `SIGHUP`: the server disconnects that
  client's live connections and refuses its next handshake, without restarting
  and without disturbing other tunnels. A reload that fails validation keeps
  the previous TLS identity and roster, so a bad edit cannot lock everyone out.

## Linux privilege

The supplied service runs as an unprivileged user with a hardened filesystem
and capability set. `CAP_NET_BIND_SERVICE` is needed only below port 1024.
`CAP_NET_ADMIN` is needed for CONNECT-IP TUN setup. Remove any capability that
the deployment does not need.

Keep host forwarding and NAT rules narrow to the configured TUN interface and
address pools. The proxy does not manage the host firewall.

`masque-server doctor` only reads sysctls, interface and route state, and
available firewall rules. The daemon's smaller startup check reads only
`/dev/net/tun` and forwarding sysctls; it does not execute firewall utilities.
Neither check enables forwarding or writes routing, firewall, or NAT
configuration. Treat a missing-rule result as evidence to investigate rather
than permission to install a broad ACCEPT or MASQUERADE rule automatically.

## Unsafe and syscall code

The complete production unsafe inventory is intentionally small:

| Module | Unsafe boundary | Invariant checked in review |
| --- | --- | --- |
| `src/net/quic.rs` | socket setup, `recvmmsg`/`sendmmsg`, sockaddr and ancillary-data layouts | Counts are clamped to fixed arrays; raw pointers refer to live per-call storage; address/control lengths are checked before typed reads |
| `src/net/target_udp.rs` | `recvmmsg`/`sendmmsg` and UDP GSO ancillary data | Public batching wrappers are safe; only the private syscall receives raw interior pointers; payload and result counts are clamped |
| `src/server/tls.rs` | two BoringSSL context/connection setters | Pointers come from live safe wrappers; BoringSSL copies bounded context bytes or changes one context flag without retaining ownership |
| `src/config_edit.rs` | terminal attributes, ownership, and advisory file locks | Every descriptor is owned and live; initialized `termios` is restored by an RAII guard |

Linux batching constructs `mmsghdr`, `iovec`, socket-address, and control
message arrays that contain raw pointers. They are rebuilt per syscall, point
only to live storage, and never escape the call. `unsafe_op_in_unsafe_fn` and
Clippy's `undocumented_unsafe_blocks` are denied workspace-wide. The weekly
Linux GNU ASan job directly exercises both packet modules; any layout change
still requires GNU and musl tests plus control-buffer and truncation boundaries.
The development-only E2E and probe tools use a few reviewed `setsockopt` and
`if_nametoindex` calls; the same workspace lint policy applies to them.

## Dependency security

The weekly security workflow uses pinned `cargo-audit` and `cargo-deny`
versions. Known RustSec vulnerabilities fail the audit, while informational
warnings such as an unmaintained transitive crate remain visible. `deny.toml`
restricts licenses and dependency registries/sources while reporting duplicate
transitive versions. Workspace path dependencies are the sole wildcard
exception because they are private code resolved from the same checkout.

## Reporting

Use the private process in [`SECURITY.md`](../SECURITY.md). Public issues are
appropriate only after a fix and disclosure plan are available.
