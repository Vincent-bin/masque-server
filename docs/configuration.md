# Configuration

The server reads TOML from `--config` (default `masque.toml`). Global sections
may use defaults, but every file must explicitly define at least one
`[[listeners]]` entry and its `[listeners.auth]` table. Authentication is
deliberately fail-closed: a Basic listener cannot start until at least one
valid account is set. Unknown keys are rejected rather than silently ignored.

Start from [`deploy/config/masque.toml`](../deploy/config/masque.toml). That
file is the canonical deployable example and is tested by the release flow.

## CLI

```text
masque-server [OPTIONS]
masque-server hash-password
masque-server client-config surge --endpoint <HOST:PORT> --username <NAME> [OPTIONS]
masque-server --config <PATH> check-config
masque-server --config <PATH> doctor
masque-server --config <PATH> support-bundle --out <PATH>
masque-server --config <PATH> add-listener [OPTIONS]
masque-server --config <PATH> list-users [OPTIONS]
masque-server --config <PATH> add-user --username <NAME> [OPTIONS]
masque-server --config <PATH> set-password --username <NAME> [OPTIONS]
masque-server --config <PATH> remove-user --username <NAME> [OPTIONS]
masque-server enroll-client [OPTIONS] --name <NAME> --endpoint <ADDR:PORT>

  -c, --config <PATH>       Config file [default: masque.toml]
      --cert <PATH>         Override tls.cert_path
      --key <PATH>          Override tls.key_path
      --log-format <FORMAT> Log encoding: text or json [default: text]
  -v, --verbose             Increase verbosity; repeat for trace logging
  -V, --version             Print the server version
```

`check-config` validates authentication, the TLS certificate/key pair, HTTP/2
and QUIC settings, client roster, and address pools without binding a listener
socket or creating a TUN device. It is suitable for upgrade preflight, but
cannot detect runtime conditions such as an occupied port or unavailable
kernel device.

`doctor` first performs the same configuration validation, then inspects the
current CONNECT-IP host environment. Missing Linux TUN or disabled forwarding
is an error. Interface, pool-route, firewall ACCEPT, and SNAT/MASQUERADE checks
are advisory because the service may be stopped and routing may live in
nftables, a network namespace, or an upstream gateway. The command prints what
it could not prove and exits nonzero only for hard prerequisites. It is
read-only and never configures the host.

`support-bundle` runs configuration validation and the same read-only host
inspection, then writes a new mode-`0600` JSON report. It summarizes only typed
operational fields and deliberately excludes the raw TOML, credential values,
client identities and addresses, key material, environment, logs, and traffic
details. See [Troubleshooting](troubleshooting.md#server-side-support-bundle).

`add-listener` appends a `[[listeners]]` block to the configuration file, and is
described under [Adding a listener](#adding-a-listener).

`hash-password` reads a password on stdin and prints an Argon2id hash for a
`listeners.auth.users[].password_hash`. `enroll-client` generates a client key pair for
a listener using `auth.mode = "client_cert"`; it reads `tls.cert_path` from
`--config`, so pass the same config the server uses. Both are described under
[Authentication](#authentication).

```text
enroll-client options:
      --name <NAME>         Label for this client, used in the server's logs
      --endpoint <ADDR:PORT>  What clients dial; must be reachable from them
      --ipv4 <ADDR>         Fixed tunnel IPv4, inside ip_proxy.ipv4_pool
      --ipv6 <ADDR>         Fixed tunnel IPv6, inside ip_proxy.ipv6_pool
  -o, --out <PATH>          Write the client JSON here instead of stdout
```

`RUST_LOG` overrides the default tracing filter. Logs are human-readable by
default; `--log-format json` emits newline-delimited structured JSON.

## Server

```toml
[server]
idle_timeout_secs = 60
max_connections = 10000
max_connections_per_ip = 64
max_pending_auth_per_ip = 8
max_tunnels_per_connection = 100
```

| Key | Meaning |
| --- | --- |
| `idle_timeout_secs` | Inactive tunnel lifetime |
| `max_connections` | Per-HTTP/3-shard or per-HTTP/2-listener connection cap |
| `max_connections_per_ip` | Process-wide live H2 + H3 connections from one source IP |
| `max_pending_auth_per_ip` | Process-wide running + queued Basic/Argon2 checks from one source; `1..256` |
| `max_tunnels_per_connection` | CONNECT streams retained per connection |

This section contains process-wide connection limits only. Socket addresses and
shard counts belong to [`[[listeners]]`](#listeners).

## Observability

The operational HTTP endpoint is disabled by default. Enable it for a
same-host collector with:

```toml
[observability]
listen_addr = "127.0.0.1:9090"
```

Only IPv4/IPv6 loopback addresses are accepted; wildcard and public addresses
fail validation because the endpoint intentionally has no authentication. It
serves `/healthz`, `/readyz`, and Prometheus `/metrics`. `check-config` prints
the resolved address and paths when enabled. See
[Observability](observability.md) for metrics, alerts, and Grafana setup.

## TLS

```toml
[tls]
cert_path = "/etc/masque/certs/server.crt"
key_path = "/etc/masque/certs/server.key"
```

The certificate must cover the hostname used by clients. The systemd unit runs
as group `masque`; install both files as `root:masque` with mode `0640`.

`SIGHUP` re-reads the full certificate chain and unencrypted private key from
the effective paths used at startup. New HTTP/2 and HTTP/3 handshakes use the
new identity; established connections retain the identity from their handshake
and are not interrupted. Both files are parsed and their public keys are
matched before one atomic in-memory swap, so a missing, malformed, or
mismatched replacement leaves the previous identity active.

Successful reloads also advance the TLS session namespace. A ticket issued
before the reload cannot resume across it and falls back to one full handshake,
so a renewed certificate or client-roster revocation takes effect immediately;
tickets issued after the reload remain resumable.

The file contents or symlink targets may change between reloads. Changing
`cert_path`, `key_path`, or CLI path overrides still requires a restart because
the effective startup paths themselves are deliberately fixed.

## Authentication

Each `[listeners.auth]` selects how clients prove who they are on that socket.
The two modes are mutually exclusive *on one socket* — `client_cert` makes the
TLS handshake demand a certificate, so a credential-based client cannot even
connect, and vice versa. To serve both kinds of client, define two listeners.

| Key | Meaning |
| --- | --- |
| `enabled` | Master switch. `false` disables authentication whatever `mode` says |
| `mode` | `basic` (default) or `client_cert` |
| `[[listeners.auth.users]]` | `basic` only; one or more accounts on this socket |
| `users[].username` | Unique Basic username on this listener |
| `users[].password_hash` | Argon2id PHC string |
| `[[clients]]` | `client_cert` only; the roster of allowed clients |

Choose `basic` for standards-compliant MASQUE clients. Choose `client_cert` for
VPN-style clients modelled on Cloudflare WARP, such as usque and mihomo, which
never send credentials; see
[Cloudflare-compatible clients](protocols.md#cloudflare-compatible-clients).

### `mode = "basic"` (default)

Credentials are checked on every CONNECT request, so one authorized tunnel does
not authorize later streams that omit the header.

```toml
[[listeners]]
listen_addr = "0.0.0.0:443"
transport = "http3"
shards = 1

[listeners.auth]
enabled = true
mode = "basic"

[[listeners.auth.users]]
username = "proxy-user"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."

[[listeners.auth.users]]
username = "phone"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."
```

Generate the hash without placing the password in process arguments, which
would expose it to every user on the host through the process list:

```sh
printf '%s' 'a-strong-password' | masque-server hash-password
```

Clients send `Proxy-Authorization: Basic BASE64(user:password)` on each
request. Missing, malformed, duplicated, or wrong credentials receive
`407 Proxy Authentication Required`.

The server accepts at most 4,096 accounts on one listener and refuses to start
if there are no users, usernames are duplicated, a username is empty or
contains `:`, or a hash is not valid Argon2id. Existing single-user `username` /
`password_hash` fields remain accepted for upgrade compatibility, but cannot be
mixed with `[[listeners.auth.users]]`.

#### Basic account management

All accounts on one Basic listener use the same address, port, transport, TLS
identity, and proxy policy. Only their username and password differ. The
management commands preserve comments, validate the complete result, hold the
same advisory edit lock as `add-listener`, and replace the file atomically:

```sh
printf '%s\n' 'phone-password' | sudo masque-server \
  --config /etc/masque/masque.toml add-user \
  --username phone --password-stdin

sudo masque-server --config /etc/masque/masque.toml list-users

printf '%s\n' 'replacement-password' | sudo masque-server \
  --config /etc/masque/masque.toml set-password \
  --username phone --password-stdin

sudo masque-server --config /etc/masque/masque.toml remove-user \
  --username phone
sudo systemctl reload masque
```

When more than one Basic listener exists, select one with
`--listen-addr <ADDR:PORT>`. Add `--transport http2|http3` only when TCP and UDP
listeners share the same numeric address. `add-user` and `set-password` accept
an existing `--password-hash`; `--password-stdin` hashes plaintext without
putting it in process arguments. With neither option, an interactive terminal
prompts securely and unattended use generates a strong password and prints it
once before committing its hash.

The first account edit migrates the legacy scalar pair to repeated user tables.
Duplicate additions and unknown users are rejected without changing the file;
the final account cannot be removed. Send `SIGHUP` after a successful edit.
Future requests on existing HTTP/2 and HTTP/3 connections use the new account
snapshot, while tunnels already authorized continue uninterrupted.

When adding an account, the same command can write the matching Surge proxy
declaration before discarding the plaintext password:

```sh
printf '%s' 'phone-password' | sudo masque-server \
  --config /etc/masque/masque.toml add-user \
  --username phone --password-stdin \
  --emit-client surge --client-endpoint proxy.example.com:8449 \
  --client-name phone --client-out /root/phone-surge.conf
```

`--client-endpoint` is intentionally explicit: a wildcard listener such as
`0.0.0.0:8449` is not an address a remote client can dial. Surge MASQUE uses
HTTP/3, so client output is refused for an HTTP/2 listener. The output is a new
mode-`0600` file and an existing path is never replaced. If `--client-out` is
omitted the secret declaration goes to stdout with a warning.

The server retains only Argon2id hashes, so it cannot export an old account's
password. If the plaintext is known, generate a client file without editing the
account:

```sh
printf '%s' 'phone-password' | masque-server client-config surge \
  --endpoint proxy.example.com:8449 --username phone \
  --out /root/phone-surge.conf
```

### `mode = "client_cert"`

Clients authenticate once, with a TLS client certificate, during the TLS
handshake. Nothing is checked per request: every stream on an established
connection is already authorized. Standard CONNECT and CONNECT-UDP keep working
alongside CONNECT-IP if their sections are enabled — the mode changes who may
connect, not what they may ask for.

```toml
[[listeners]]
listen_addr = "0.0.0.0:443"
transport = "http3"
shards = 1

[listeners.auth]
enabled = true
mode = "client_cert"

[[clients]]
name = "laptop"
public_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."
ipv4 = "10.89.0.2"
ipv6 = "fd00:abcd::2"

[[clients]]
name = "phone"
public_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."
ipv4 = "10.89.0.3"
ipv6 = "fd00:abcd::3"
```

| `[[clients]]` key | Meaning |
| --- | --- |
| `name` | Label used in the server's logs. Optional but makes them readable |
| `public_key` | The client's ECDSA P-256 public key: base64 SubjectPublicKeyInfo DER, or a `-----BEGIN PUBLIC KEY-----` block |
| `ipv4` | Fixed CONNECT-IP address, inside `ip_proxy.ipv4_pool` |
| `ipv6` | Fixed CONNECT-IP address, inside `ip_proxy.ipv6_pool` |

#### Enrolling a client

There is no enrollment API to call. The operator generates the key pair and
distributes it:

```sh
masque-server --config masque.toml enroll-client \
    --name laptop --endpoint 203.0.113.9:443 \
    --ipv4 10.89.0.2 --ipv6 fd00:abcd::2 --out client.json
```

This prints three things: the `[[clients]]` block for this file, a JSON
configuration for usque-style clients, and a `proxies:` entry for mihomo-style
clients. The client halves contain the private key — treat the output as a
secret. Generating both spellings matters because the same key is encoded
differently for each: usque takes the server key as PEM and addresses bare,
mihomo takes it as bare base64 and addresses in CIDR form.

The usque JSON fills both `endpoint_v4` / `endpoint_v6` and the corresponding
`endpoint_h2_v4` / `endpoint_h2_v6` fields with the enrolled server address, so
the same file works with its default HTTP/3 mode and its `--http2` fallback.

The generated mihomo entry uses the active `ip_proxy.tun_mtu` value from the
same server configuration, so a non-default MTU stays consistent on both ends.

`--out` writes the JSON to a file created as a new `0600` file on Unix; an
existing path is never overwritten. Without it the JSON goes to the terminal.

Nothing is written to the server configuration automatically. Append the
`[[clients]]` block yourself, then run `systemctl reload masque` or restart.

## Listeners

`[[listeners]]` is the required, complete list of sockets. Each entry owns its
address, shard count, and authentication mode. There is no top-level `[auth]`
and `[server]` does not contain listener settings.

```toml
[[listeners]]
listen_addr = "0.0.0.0:443"
shards = 1

[listeners.auth]
enabled = true
mode = "basic"

[[listeners.auth.users]]
username = "proxy-user"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."

[[listeners]]
listen_addr = "0.0.0.0:4443"
transport = "http2"
shards = 1

[listeners.auth]
enabled = true
mode = "client_cert"
```

| `[[listeners]]` key | Meaning |
| --- | --- |
| `listen_addr` | Required; there is no default, so a typo cannot silently land on someone else's port |
| `transport` | `http3` (default) binds UDP/QUIC; `http2` binds TCP/TLS |
| `shards` | HTTP/3 event loops; defaults to `1`. HTTP/2 must use exactly `1` |
| `[listeners.auth]` | Required; authentication is always explicit per socket |

Everything else stays server-wide: TLS, HTTP/2 and QUIC settings, TCP/UDP target
policies, connection limits, one `[[clients]]` roster, one TUN device, one
CONNECT-IP address pool, and one routing table. That is the reason to run two
listeners in one process rather than two processes — two processes would need
two TUN devices and two address pools, and overlapping pools hand the same
tunnel address to two clients.

Use one HTTP/3 shard until a benchmark shows one event loop is CPU-bound.
Memory and the effective connection capacity increase with the shard count.
HTTP/2 uses Tokio tasks for its TCP connections and therefore requires
`shards = 1`.

The server refuses to start when two listeners using the same transport contend
for the same address. This is not left to the kernel to report: an HTTP/3
listener with more than one shard opens its UDP socket with `SO_REUSEPORT`, so a
second HTTP/3 listener on that address would join the load-balancing group and
be handed connections meant for the other authentication mode. One HTTP/2 and
one HTTP/3 listener may intentionally use the same numeric IP and port because
they bind independent TCP and UDP sockets.

Wildcards count as contention. `0.0.0.0` claims every IPv4 address on its port,
so it conflicts with `127.0.0.1` on that port. `::` is treated as claiming IPv4
as well, because whether it really does is the kernel's `IPV6_V6ONLY` default —
`0` on Linux unless `net.ipv6.bindv6only` says otherwise. Nothing here sets that
option, so `[::]:443` beside `0.0.0.0:443` is refused everywhere rather than
binding on some hosts and failing on others.

Addresses are compared in canonical form, so `[::ffff:127.0.0.1]:443` and
`127.0.0.1:443` are recognised as the same interface rather than passing the
check and then failing to bind — or, under `SO_REUSEPORT`, binding successfully
and leaving one listener shadowing the other's traffic. The error names which of
the three it found: the same address twice, one address written two ways, or a
wildcard covering another.

Port `0` is exempt. It asks the kernel for whichever port is free, so several
listeners may use it. Every shard of one listener shares the same selected port,
and the live `listening` log lines report that address. `check-config` is
side-effect-free and therefore reports the configured `:0`; no port has been
selected until the server binds.

For HTTP/3, `shards = 0` (one per core) is rejected when more than one listener
is configured; give each listener an explicit count. The 32-shard cap applies
to the total HTTP/3 shard count, not to HTTP/2 connection tasks. The budget for
concurrent password verification is sized from Basic listener workers alone,
so adding a certificate listener does not widen what unauthenticated callers
can demand.

Run `masque-server --config masque.toml check-config` to validate a listener
file before restarting. It prints the resolved listeners, with the shard counts
the server will actually run rather than the ones written down
— `shards = 0` expanded to one per core, and any excess capped:

```
configuration is compatible with masque-server 0.8.0: /etc/masque/masque.toml
listener 0.0.0.0:443 transport=http3 auth=basic shards=1
listener 0.0.0.0:4443 transport=http2 auth=client_cert shards=1
```

The usque JSON schema stores the endpoint IP but not its port, so enrollment
also prints the matching launch argument — `--connect-port 443` for the example
above, `--connect-port 8449` for a server on 8449. Omitting it silently falls
back to the client's default port. Add `--http2` when selecting an HTTP/2
listener.

#### How the certificate is checked

Only the public key inside the certificate is compared against the roster. The
certificate itself is a disposable envelope: these clients self-sign a fresh
one per connection with an empty subject and 24-hour validity, so its chain,
name, and dates carry nothing worth verifying.

A key that is not on the roster is refused during the handshake with a TLS
`access_denied` alert, before it can open a stream. The rejected key is logged
in exactly the form you can paste into a `[[clients]]` entry, so enrolling a new
client needs no separate key extraction step.

The **server** certificate must use an ECDSA key, because these clients pin its
public key and reject any other key type. `scripts/gen-certs.sh` produces a
suitable P-256 certificate. Replacing the server certificate invalidates every
client configuration that pinned the old key.

#### Pinned addresses

`ipv4` / `ipv6` bypass the dynamic pool and give that client the same address
every time. This is required for clients that configure their tunnel interface
from their own configuration rather than from the `ADDRESS_ASSIGN` capsule: if
the two sides disagree, traffic is dropped in both directions — inbound as a
spoofed source, outbound by the client's own filtering. Omit them only for
clients that do read `ADDRESS_ASSIGN`.

Pinned addresses are withheld from dynamic allocation for the process lifetime,
so an offline client keeps its address. When a replacement connection arrives
before its stale predecessor times out, the same authenticated identity may
reclaim the addresses immediately and the newest tunnel owns their return
route — a network change does not cost a minute of downtime.

Dynamic allocation begins at network address `+2`; `+1` belongs to the server's
own TUN interface.

#### Revoking a client

Edit the roster and/or replace both TLS files, then send `SIGHUP`:

```sh
systemctl reload masque            # or: kill -HUP $(pidof masque-server)
```

The server always reloads the certificate chain, private key, and every active
Basic account set. When any listener uses `auth.mode = "client_cert"`, it also
re-reads `[[clients]]` from
the same configuration file, disconnects a live connection whose entry was
removed or changed, and leaves every other tunnel untouched. A removed client's
next attempt is refused at the handshake like any unenrolled key. Adding an
entry works the same way, so a client can be re-enrolled without a restart.

TLS identity and active Basic/certificate credentials form one validated reload
transaction. A malformed certificate, mismatched private key, duplicate Basic
username, invalid password hash, unparseable client key, or invalid pinned
address rejects the whole update and leaves the running snapshots in force.
Listen addresses, transports, authentication modes, pools, and tuning remain
fixed until restart.

Editing an existing entry counts as revocation: the client is disconnected and
must reconnect to pick up its new pinned addresses, which are chosen when the
tunnel is set up.

Reload is unavailable when the server was started without a config file, since
there is nothing to re-read.

#### Startup validation

The server refuses to start when:

- `mode = "client_cert"` and no `[[clients]]` entry exists — an empty roster
  admits nobody, which looks exactly like a broken TLS setup;
- a `public_key` is unparseable or is not ECDSA P-256;
- two entries share a `public_key`, or pin the same address;
- a pinned address falls outside its pool, or is the pool's gateway address —
  checked only while `ip_proxy.enabled = true`, since there is no pool to
  validate against otherwise.

`[[clients]]` entries outside this mode are ignored, do not reserve addresses,
and produce a startup warning.

### Disabling authentication

`listeners.auth.enabled = false` turns off authentication on that listener and
logs a warning. This is only
appropriate in an isolated test environment or behind another trusted
authentication boundary.

### Adding a listener

`add-listener` appends one `[[listeners]]` block to an existing configuration
file. Run without flags it prompts for everything, defaulting to a free port and
to whichever authentication mode the file does not serve yet:

```sh
masque-server --config /etc/masque/masque.toml add-listener
```

```
Transport (http3 | http2) [http2]:
Listen address (ip:port) [0.0.0.0:4443]:
Authentication mode (basic | client_cert) [client_cert]:
```

The shard prompt appears only for HTTP/3; HTTP/2 always uses one listener
worker and schedules connections as Tokio tasks.

A Basic listener also asks for a username and a password. The password is read
without echo and confirmed; leaving it empty generates a strong one and prints
it once. Only the Argon2id hash is written to the file.

Every value can be given as a flag instead, which is also what a provisioning
script must do — prompting requires a terminal, and without one a missing value
is an error rather than a hang:

```sh
printf '%s' 'replace-this-password' | \
  masque-server --config /etc/masque/masque.toml add-listener \
    --transport http2 --listen-addr 0.0.0.0:443 \
    --mode basic --password-stdin --username proxy-user --yes
```

```text
add-listener options:
      --listen-addr <ADDR:PORT>  Address for the new socket
      --transport <TRANSPORT>  http3 | http2 [scripted default: http3]
      --mode <MODE>         basic | client-cert
      --shards <N>          Event loops for this listener [default: 1]
      --username <NAME>     Basic username
      --password-hash <PHC>  Argon2id hash, as printed by hash-password
      --password-stdin      Read the password from stdin and hash it here
      --emit-client surge   Emit the Basic credential in Surge syntax
      --client-endpoint <HOST:PORT>  Public endpoint written to that client config
      --client-name <NAME>  Optional Surge proxy name
      --client-out <PATH>   Create a private client file instead of using stdout
      --disable-auth        Write enabled = false (trusted networks only)
      --no-bind-check       Do not test-bind the new address
      --dry-run             Print the block; leave the file unchanged
  -y, --yes                 Skip the confirmation prompt
```

Combinations that would be ignored are refused rather than dropped:
`--username`, `--password-hash`, and `--password-stdin` apply to `--mode basic`
only, and `--disable-auth` cannot be combined with `--mode`, since a listener
that demands nothing has no mode to record.

The four client-output options have the same safety and file format described
under [Basic account management](#basic-account-management). They apply only to
an authenticated HTTP/3 Basic listener; `--password-hash` cannot produce a
client file because the plaintext is intentionally unrecoverable, and
`--dry-run` cannot promise a two-file result.

A Basic `--dry-run` must be given a password through `--password-stdin` or an
existing hash through `--password-hash`. It never generates a password whose
only recoverable copy would be omitted from the dry-run output.

#### What is checked, and what is not

Before writing, the merged file is parsed and put through the same validation
`check-config` runs — address overlap with an existing listener, credentials,
shard counts, the client roster behind a certificate listener — and the new
address is then bound once to see that nothing else holds it. If any of it
fails, the error says so and the file is left byte for byte as it was.

The bind test exists because `check-config` is side-effect-free and therefore
says nothing about an occupied port, while the server binds every listener at
startup and exits if one fails: a bad address would take down the listeners that
work today at the next restart. It is a probe of the moment it runs, not a
reservation, so **restart the server and confirm it came up**; nothing here can
promise a start that happens minutes later. Use `--no-bind-check` when the
address becomes available only later — a floating address, or a service running
in another network namespace.

The file is replaced atomically, keeping its mode and owner, so a password hash
is never exposed and the service does not lose read access. Comments survive:
the block is appended as text rather than the file being regenerated.

Concurrent `add-listener` edits are refused. One run holds an advisory lock
(`.masque.toml.lock` beside the configuration) so a second one stops
immediately. A final content comparison immediately before replacement also
catches normal editor and script changes that do not honour the lock. No
portable file API can exclude an uncooperative writer racing the final rename,
so configuration-management tools should take the same lock or avoid writing
the file while this command runs.

Two ordering rules follow from the validation being real:

- A `client_cert` listener needs at least one `[[clients]]` entry, because the
  server refuses to start without one. Run
  [`enroll-client`](#enrolling-a-client) and append its `[[clients]]` block
  first.
- A file whose only listener uses `shards = 0` (one per core) has to be given an
  explicit count first; that setting has no meaning once a second listener
  exists.

A new socket is bound at startup, so restart the server afterwards, and open
UDP for an HTTP/3 listener or TCP for an HTTP/2 listener. `SIGHUP` reloads TLS
identity and active Basic/certificate credentials — it never adds, removes, or
rebinds a listener.

## HTTP/2

```toml
[http2]
initial_stream_window = 1048576
initial_connection_window = 16777216
max_concurrent_streams = 128
max_header_list_size = 8192
max_send_buffer_size = 262144
data_frame_budget = 262144
max_datagram_size = 65527
```

These values apply only to listeners with `transport = "http2"`:

| Key | Meaning |
| --- | --- |
| `initial_stream_window` | Initial request-stream receive credit |
| `initial_connection_window` | Initial aggregate receive credit per connection |
| `max_concurrent_streams` | Concurrent request streams advertised per connection |
| `max_header_list_size` | Maximum decoded request header list size |
| `max_send_buffer_size` | Maximum response bytes buffered per stream by the H2 implementation |
| `data_frame_budget` | Connection-level allowance for queued small DATA-frame overhead; `1..16777216`. Packetized CONNECT-IP needs more than h2's generic HTTP default, but raising it increases the memory an abusive connection can consume. |
| `max_datagram_size` | Maximum UDP payload or IP packet carried in one DATAGRAM capsule; `1..65527` |

HTTP/2 CONNECT-UDP and CONNECT-IP DATAGRAM capsules are reliable and ordered
because they travel over TCP. Prefer HTTP/3 for normal operation and use
HTTP/2 where UDP/QUIC is blocked.

## QUIC and UDP

```toml
[quic]
max_datagram_size = 1350
initial_max_streams_bidi = 128
enable_dgram = true
enable_udp_gso = false
enable_udp_gro = true
cc_algorithm = "cubic"
initial_congestion_window_packets = 32
initial_max_data = 16777216
initial_max_stream_data = 4194304
max_connection_window = 25165824
max_stream_window = 16777216
dgram_recv_queue_len = 2048
dgram_send_queue_len = 2048
discover_pmtu = false
retry_mode = "adaptive"
retry_connection_threshold = 64
retry_token_ttl_secs = 30
```

Important relationships:

- `initial_max_data` must not exceed `max_connection_window`.
- `initial_max_stream_data` must not exceed `max_stream_window`.
- Path-MTU discovery cannot probe beyond `max_datagram_size`; raising only
  `discover_pmtu` has no benefit.
- UDP GSO is opt-in because some virtual egress paths advertise it but drop
  super-packets. Enable it only after an external-path A/B test.
- Supported congestion controllers are `cubic`, `reno`, and `bbr2`. CUBIC is
  the current default because the server's deferred-send behavior penalizes
  BBR2's fine-grained pacing.
- `retry_mode = "adaptive"` accepts tokenless Initial packets below
  `retry_connection_threshold`, avoiding an extra low-load round trip. At or
  above the per-shard threshold, the server sends a stateless, authenticated
  Retry token before allocating connection state. `always` validates every
  source address; `off` is appropriate only for trusted networks or controlled
  comparisons. Tokens expire after `retry_token_ttl_secs` (`1..300`), are
  listener-bound, and tolerate source-port changes behind NAT.
  A threshold above `server.max_connections` is valid: the smaller connection
  cap then bounds state before adaptive Retry would activate.

Queue depths trade memory and latency for burst tolerance. QUIC DATAGRAM frames
are not retransmitted; a full queue drops traffic.

## TCP policy

```toml
[tcp_proxy]
enabled = true
connect_timeout_secs = 10
allow_targets = ["0.0.0.0/0", "::/0"]
deny_targets = [
  "127.0.0.0/8",
  "10.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "::1/128",
  "fc00::/7",
  "fe80::/10",
]
```

Resolved addresses must match an allow prefix and must not match a deny prefix.
Deny rules take precedence. Keep loopback, link-local, private, metadata, and
management networks denied unless access is intentional.

## UDP policy

```toml
[udp_proxy]
enabled = true
uri_template = "/.well-known/masque/udp/{target_host}/{target_port}/"
enable_udp_gso = false
allow_targets = ["0.0.0.0/0", "::/0"]
deny_targets = ["127.0.0.0/8", "10.0.0.0/8", "::1/128"]
```

The template must retain `{target_host}` and `{target_port}`. Apply the same
internal-network restrictions used for TCP unless UDP access is intentionally
different. `enable_udp_gso` batches equal-sized large client payloads into
Linux UDP super-packets without first copying them into one contiguous
userspace buffer. Small payloads continue through `sendmmsg`, where segmentation
overhead would outweigh the saved kernel work. It is independent of
`quic.enable_udp_gso`; keep it disabled until the target egress path has passed
a loss and throughput A/B test.

## CONNECT-IP

```toml
[ip_proxy]
enabled = true
uri_template = "/.well-known/masque/ip/{target}/{ipproto}/"
connect_protocols = ["connect-ip", "cf-connect-ip"]
tun_name = "masque0"
tun_mtu = 1280
tun_offload = true
ipv4_pool = "10.89.0.0/16"
ipv6_pool = "fd00:abcd::/64"
```

`connect_protocols` lists the accepted CONNECT-IP protocol identifiers. RFC
9484 registers `connect-ip`; Cloudflare's HTTP/3 endpoint uses
`:protocol = cf-connect-ip`, while its HTTP/2 dialect carries the same value in
`cf-connect-proto`. Both identifiers are accepted by default. Narrow the list
to `["connect-ip"]` to accept only standards-compliant clients.

CONNECT-IP is Linux-only. Pools must not overlap host, container, VPN, or
upstream networks. The host is responsible for routing, forwarding, firewall,
and optional NAT outside the process. Disable the entire section when full IP
proxying is unnecessary; this also lets you remove `CAP_NET_ADMIN` from the
service. This requirement follows the CONNECT-IP protocol, not the listener's
authentication mode: client certificates alone do not require forwarding.

After starting the service, run:

```sh
sudo masque-server --config /etc/masque/masque.toml doctor
```

Startup reads only the hard `/dev/net/tun` and forwarding prerequisites and
reminds the operator to run `doctor`; it deliberately does not execute firewall
utilities from the capability-bearing daemon. A failed startup check is logged
without taking CONNECT and CONNECT-UDP down with optional CONNECT-IP egress.

## Validation and upgrades

The server validates authentication, congestion control, flow-control window
relationships, and platform requirements at startup. Treat a startup error as
a configuration defect rather than weakening validation.

The installer does not overwrite an existing configuration. Compare it with
the example shipped in every new release and add new fields deliberately; all
fields currently have backward-compatible defaults.
