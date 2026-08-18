# Security and hardening

## Threat model

The listener is expected to receive arbitrary UDP, QUIC, HTTP/3, CONNECT,
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
connection has a pending-request cap. Closing a stream or connection cancels
work that has not started and discards results for work already running.

Use a unique, high-entropy password. Basic credentials are protected by QUIC
TLS in transit but are reusable bearer secrets at the HTTP layer. Rotate them
after suspected client or log compromise.

With `auth.mode = "client_cert"` the cost profile is different: identity is
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

DNS names are evaluated after resolution so a hostname cannot bypass CIDR
policy merely by resolving to a denied address. Rebinding and multi-address
behavior should be retested when resolver logic changes.

Disable TCP, UDP, or IP proxy sections that are not required.

## Resource safety

Connection, tunnel, authentication, cross-shard, relay, QUIC DATAGRAM, and TCP
buffer limits prevent application-level unbounded growth. These bounds do not
replace host controls. Apply reasonable systemd limits, provider firewall rate
limits, and monitoring for memory, CPU, file descriptors, authentication
failures, connections, and datagram drops.

Do not respond to overload by making queues arbitrarily deep; this can turn
packet loss into seconds of latency and make memory exhaustion easier.

## TLS and credentials

- Keep the private key and configuration `root:masque` mode `0640`.
- Do not pass passwords as command-line arguments.
- Do not commit real certificates, hashes, passwords, IPs, or server inventory.
- Avoid trace logging in production except during a short controlled incident.

The right server certificate depends on the authentication mode, because the
two modes establish server identity in completely different ways.

### With `auth.mode = "basic"`

Clients validate the certificate normally. Use one trusted by them and covering
the exact proxy hostname, and renew it before expiry as usual.

### With `auth.mode = "client_cert"`

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
  the previous roster, so a bad edit cannot lock everyone out.

## Linux privilege

The supplied service runs as an unprivileged user with a hardened filesystem
and capability set. `CAP_NET_BIND_SERVICE` is needed only below port 1024.
`CAP_NET_ADMIN` is needed for CONNECT-IP TUN setup. Remove any capability that
the deployment does not need.

Keep host forwarding and NAT rules narrow to the configured TUN interface and
address pools. The proxy does not manage the host firewall.

## Unsafe and syscall code

Linux batching constructs `mmsghdr`, `iovec`, socket-address, and control
message arrays that contain raw pointers. They are rebuilt per syscall, point
only to live storage, are zero-initialized for ABI padding, and never escape
the call. Any change to these layouts requires Linux musl and GNU tests plus
boundary tests for control buffers and datagram truncation.

## Reporting

Use the private process in [`SECURITY.md`](../SECURITY.md). Public issues are
appropriate only after a fix and disclosure plan are available.
