# Security and hardening

## Threat model

The listener is expected to receive arbitrary UDP, QUIC, HTTP/3, CONNECT,
credential, and target data from the internet. A successful client can ask the
server to originate TCP/UDP traffic, and CONNECT-IP clients can exchange raw IP
packets through the host. The principal risks are:

- unauthenticated resource exhaustion;
- password guessing and memory-hard hash amplification;
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

- Use a certificate trusted by clients and covering the exact proxy hostname.
- Keep the private key and configuration `root:masque` mode `0640`.
- Do not pass passwords as command-line arguments.
- Do not commit real certificates, hashes, passwords, IPs, or server inventory.
- Avoid trace logging in production except during a short controlled incident.

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
