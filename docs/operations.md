# AI-assisted fleet operations

MASQUE Server provides an optional operations layer for repeatable fleet
installation and upgrades. An AI coding agent can interpret an operator's
request through the installable `masque-ops` Skill, but all privileged work is
performed by its deterministic, tested CLI. No model, API key, or AI runtime is
installed on a proxy server.

This is deliberately bounded release operations rather than general configuration
management. It can bootstrap an explicitly described empty host, inspect status,
collect bounded diagnostics, validate an upgrade plan, deploy an exact GitHub
Release, run an external protocol probe, and restore the previously recorded
version. Outside the fresh-install profile, it does not edit configuration,
certificates, users, routes, forwarding, firewall, NAT, or monitoring services.
It targets the paths and service name used by the official Linux installer;
custom installation layouts are intentionally outside its scope.

For choosing between configuration edits, activation, release operations, and
their verification, see [AI-assisted changes](ai-operations.md).

## Install the operations bundle

Python 3.11 or newer and OpenSSH are required on the administration machine.
Linux and macOS can install the Skill, CLI, inventory example, and matching
local probe from the latest stable Release with:

```sh
curl -fsSL https://raw.githubusercontent.com/Vincent-bin/masque-server/main/install-ops.sh | sh
```

The installer verifies the platform-independent operations archive and the
platform-specific probe archive against their Release SHA-256 sidecars before
activation. It installs the Skill at `~/.agents/skills/masque-ops`, the CLI and
probe under `~/.local/bin` for an unprivileged user, and the example under
`~/.config/masque-server`. Re-running it upgrades these release-managed files
without reading or changing private inventory, state, or credentials. Pin an
exact version with:

```sh
curl -fsSL https://raw.githubusercontent.com/Vincent-bin/masque-server/main/install-ops.sh | \
  env MASQUE_VERSION=vX.Y.Z sh
```

Set `MASQUE_OPS_INSTALL_PROBE=0` to skip the probe. A repository checkout also
works through `scripts/masque-ops.py`, and its repo-scoped Skill is discovered
without running this installer.

## New empty host

The AI can install the operations bundle, CLI and probe using the installation
command above. On the administration machine, generate a private inventory for
one empty host instead of editing a template:

```sh
masque-ops init-inventory --ssh-host 203.0.113.10 \
  --auth-mode basic --transport http3 --self-signed
```

Before selecting the options, tell the AI whether a peer is already chosen.
A client name, official documentation, or a configuration example with all
endpoints and secrets removed can help identify the peer's capabilities. The
AI should verify transport, authentication and CONNECT variants, ask about
unknowns, and report what has not been tested. The server and inventory do
not store a client product name or require a particular implementation.

In a terminal, choose an existing SSH key/agent or enter the SSH password
without echo. With `--ssh-password-prompt`, the password is entered privately;
with `--proxy-password-prompt`, the operator can choose the proxy password.
Otherwise the CLI generates a proxy password at bootstrap and keeps it in a
private file. Do not paste either password into an AI conversation. Guided
setup asks for Basic, client-certificate or dual authentication, HTTP/2 or
HTTP/3, and which CONNECT paths to test. Noninteractive setup requires
`--auth-mode` and `--transport` explicitly. With dual authentication, the
two listeners use separate ports, and fresh bootstrap probes both modes.
Subsequent upgrades and rollbacks check the configured primary probe only;
the certificate listener needs a separate probe if both modes must be checked.
`--skip-tcp` and `--skip-udp` affect the probe, not server capabilities;
`--connect-ip` tests negotiation, not forwarding. The inventory and credential
files remain outside the checkout.

The transport-aware fresh installer requires a release that includes this
feature (v0.14.4 or newer); the tool rejects older releases for HTTP/2 setup.
The generated certificate-client enrollment file contains a private key and
must be delivered privately. A configuration example does not prove runtime
compatibility: verify the selected protocol paths after installation.
If an inventory already exists, pass `--add-host` to append a new empty host;
existing entries and the current canary are preserved. Use the JSON result's
host identifier for that host's bootstrap command, without publishing it.

The default self-signed mode creates a certificate on the empty server during
bootstrap and retrieves only its public certificate for the probe. Clients must
install or otherwise trust that certificate. It expires after 365 days; the
tool does not automatically renew it or redistribute a replacement. After installation, use
`masque-ops export-probe-ca --out /private/public-ca.pem` to copy the public
certificate into a new file in a private directory; the command refuses to
copy a private key or overwrite a file. To use an existing domain
certificate instead, pass `--existing-certificate`, the public proxy hostname
as `--endpoint-host`, and `--tls-cert-path` / `--tls-key-path` for the existing
remote PEM files. For a private CA also pass `--ca-cert` for a local trusted CA.
The tool does not issue or renew ACME certificates. For a public certificate,
the operator or an independently authorized certificate workflow can obtain
and renew one with an ACME client, and place the PEM files on the server.
For example, after installing Certbot and pointing the domain at the server,
`certbot certonly --standalone -d proxy.example.com` uses HTTP validation; TCP
port 80 must be reachable and free during issuance and renewal. Configure a
renewal deploy hook to install the renewed chain and key and reload MASQUE;
see [Certbot's user guide](https://eff-certbot.readthedocs.io/en/stable/using.html).

Verify the SSH host key independently before the first connection. AI can then
run `masque-ops validate` and `masque-ops bootstrap` for a latest-stable
preflight. Review its exact version and planned dependency installation; after
authorization, run `masque-ops bootstrap --version vX.Y.Z --apply`. On empty
Debian/Ubuntu or DNF-based hosts, missing installer dependencies are installed
automatically. The tool does not open host or cloud firewalls, configure DNS,
or set up CONNECT-IP forwarding; arrange those separately when required.
Fresh install has no previous version to restore if post-install checks fail.

## Advanced inventory setup

Copy the installed example and protect the private file:

```sh
install -d -m 0700 ~/.config/masque-server ~/.config/masque-server/secrets
install -m 0600 ~/.config/masque-server/fleet.example.toml \
  ~/.config/masque-server/fleet.toml
```

Replace all documentation addresses and endpoints. The default location is
`~/.config/masque-server/fleet.toml`; set `MASQUE_OPS_INVENTORY` or pass
`--inventory` to use another file. The inventory only accepts the official
`Vincent-bin/masque-server` release source and must not contain inline
passwords. Referenced SSH identities, probe passwords, and client enrollment
files are checked separately and must be private regular files rather than
symlinks.

AI agents must not open the inventory or any referenced file. They pass only
the inventory path and a host alias to `masque-ops`; its output omits SSH
addresses, key paths, remote TLS paths, usernames, passwords, and generated
client-file paths. The deterministic CLI is the only component that parses the
private inventory or handles secret bytes.

If it was omitted from the operations install, install the release-matched
probe separately on Linux or macOS x86_64/ARM64:

```sh
curl -fsSL https://raw.githubusercontent.com/Vincent-bin/masque-server/main/install-probe.sh | sh
```

An unprivileged install goes to `~/.local/bin`; root installs to
`/usr/local/bin`. Every archive is verified against its release SHA-256 before
replacement. `masque-ops` also checks `~/.local/bin` when `masque-probe` is not
already in `PATH`.

Verify SSH host fingerprints out of band before placing them in the configured
`known_hosts_file`. The tool enables strict host-key checking and disables
ambient SSH configuration, keyboard-interactive login, forwarding, agent
forwarding, local commands, and shared control sockets. SSH password login is
enabled only when a private password file is explicitly configured; otherwise
the default is noninteractive key or agent authentication.

## Read-only inspection

```sh
masque-ops validate
masque-ops status
masque-ops plan --version vX.Y.Z
masque-ops diagnose edge-a --journal-lines 100
```

`status` checks the installed version, architecture, service state,
configuration validity, certificate expiry, and disk availability. `plan`
also verifies that both the target and current releases have a checksummed
archive for the host architecture; retaining the current artifact is required
for automatic rollback.

Diagnostics never read raw TOML and filter lines that could contain account,
authorization, password, or private-key material. They can still contain
client IP or destination metadata from the journal, so review output before
sharing it. Place `--json` before the subcommand for structured output.

## Set up an external probe

On the administration machine, run:

```sh
masque-ops configure-probe
```

The guided setup selects the only host, or the designated canary in a fleet,
asks for its proxy
hostname and port and authentication method, and tests HTTP/3, TCP CONNECT,
and CONNECT-UDP before saving anything to the inventory. Basic passwords are
entered without terminal echo and saved to a new private file outside the
checkout. Certificate authentication uses an existing private enrollment JSON.
The command refuses to overwrite an existing probe. It changes only local
inventory and does not deploy or change the server. Keep the inventory and
credentials private; do not paste them into chat or a repository.

For automation, pass the endpoint and an existing private credential file:

```sh
masque-ops configure-probe --endpoint proxy.example.com:8449 \
  --username probe-user --password-file /private/probe-password
```

Use `--client-config /private/client.json` instead of the Basic options for
certificate authentication. Use `--no-auth` only for a listener with no
authentication. Specify a host as the positional argument if the inventory
has multiple hosts without exactly one canary. `--transport http2` tests HTTP/2; the
default is HTTP/3 and does not silently fall back. Use `--ca-cert` for a
private CA, and `--resolve` or `--interface` for a known DNS or route issue.
The interface option affects HTTP/3 only. See `configure-probe --help`.

If the test fails, the inventory is unchanged and any newly entered password
file is removed. Check the listener, credentials and network path, then rerun
the command. Default TCP and UDP targets must be allowed by server policy;
CONNECT-IP is optional and now checks an inner IP/UDP round trip. Set
`tcp_mode = "echo"` for a controlled TCP echo target; otherwise TCP validates a
target TLS handshake. IP probes accept `ip_target = "198.51.100.10:9999"` and
`ip_mode = "echo"` for a controlled destination. `ip_setup_only = true` explicitly
limits CONNECT-IP to negotiation and does not verify forwarding. These options
are also available on `configure-probe`. Upgrade the probe binary together with
the operations bundle; an old negotiation-only result cannot satisfy a required
CONNECT-IP forwarding check.

## Deploy and roll back

Mutations require an exact version and the explicit `--apply` gate:

```sh
masque-ops plan --version vX.Y.Z
masque-ops deploy edge-a --version vX.Y.Z --apply
masque-ops rollout --version vX.Y.Z --apply
masque-ops rollback edge-a --apply
```

With one selected host, `rollout` selects it automatically and normally requires
an external `masque-probe`; no canary designation is needed. With multiple
selected hosts, it requires exactly one canary, verifies it first, and then
proceeds sequentially. For a single-host inventory, `deploy` and `rollback`
also select the host automatically. A host is considered upgraded only after systemd is active, the
new binary version matches, the live configuration passes `check-config`, and
its SHA-256 still matches the preflight snapshot, and the optional external
TCP/UDP/IP probe succeeds. A failed host is restored to its prior version when
possible, and the rollout stops without touching later hosts.

## Bootstrap an empty Linux host

For advanced setups, add `[hosts.bootstrap]` to the host's private inventory entry. It describes the
authentication mode, ports, existing remote ACME certificate paths, and local
mode-`0600` destinations for generated credentials. The installed example
shows Basic mode; `client_cert` and `dual` additionally require
`client_endpoint` and `client_config`. Inline passwords are rejected.

First run the non-mutating preflight:

```sh
masque-ops bootstrap edge-new --version vX.Y.Z
```

After explicit approval, the same command performs the install:

```sh
masque-ops bootstrap edge-new --version vX.Y.Z --apply
```

The CLI requires a verified root SSH entry for this one operation. It confirms
that the host is Linux and unconfigured, all required commands and release
assets exist, and the configured remote TLS files are readable. A Basic
password is read or generated only inside the CLI and sent in encrypted SSH
standard input, never in a process argument. Generated Basic and certificate
client files stream directly from SSH into new local files with mode `0600`;
their contents and paths are not emitted. The installer suppresses credential,
client-key, and rendered-configuration output, then the CLI checks systemd,
configuration validity, version, and the optional external probe.

Fresh installation has no previous Release to restore if an external
post-install check fails. The CLI stops and records that state instead of
deleting a potentially working installation. Inspect `status` before retrying.

State and an append-only audit are stored next to `state_path`, with mode
`0600`. They contain host aliases, versions, result categories, timestamps,
configuration hashes, and probe status—not SSH addresses or authentication
material.

## Remote maintenance boundary

Release installation puts a root-owned helper at
`/usr/local/sbin/masque-maintain` and a pinned copy of the verified bootstrap at
`/usr/local/libexec/masque-server/install-latest.sh`. The helper exposes only
`status`, bounded `diagnose`, and an exact-version `upgrade`. Upgrade downloads
from the official repository, verifies the archive SHA-256, serializes changes
with `flock`, validates the existing configuration with the candidate binary,
and relies on the package installer for atomic replacement and service-state
rollback.

This narrow command can be granted to a dedicated SSH account with sudo. See
the Skill's
[`inventory.md`](../.agents/skills/masque-ops/references/inventory.md) for the
sudoers example and probe configuration. A server running an older release
does not yet have the helper; its first transition requires the explicit,
root-only `deploy --bootstrap` path. Remove root SSH from the inventory after
that transition.

## Using the Skill

Codex-compatible agents discover either the installed
`~/.agents/skills/masque-ops/SKILL.md` or the repo-scoped copy automatically
after startup. A typical request is: “Use `$masque-ops` to inspect the fleet and
prepare an upgrade plan for `vX.Y.Z`.” Inspection and planning do not authorize
deployment; ask explicitly to execute the reviewed plan before the agent may
add `--apply`.

The CLI is the supported interface and works without an AI agent. Treat the
Skill as a guarded natural-language runbook, not as an independent source of
privilege or release truth.
