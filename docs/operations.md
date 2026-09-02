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

## Set up an inventory

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
`known_hosts_file`. The tool enables strict host-key checking, disables ambient
SSH configuration, password and keyboard-interactive login, forwarding, agent
forwarding, local commands, and shared control sockets.

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

## Deploy and roll back

Mutations require an exact version and the explicit `--apply` gate:

```sh
masque-ops plan --version vX.Y.Z
masque-ops deploy edge-a --version vX.Y.Z --apply
masque-ops rollout --version vX.Y.Z --apply
masque-ops rollback edge-a --apply
```

`rollout` requires exactly one selected canary and normally requires an
external `masque-probe` for it. It deploys the canary first and then proceeds
sequentially. A host is considered upgraded only after systemd is active, the
new binary version matches, the live configuration passes `check-config`, and
its SHA-256 still matches the preflight snapshot, and the optional external
TCP/UDP/IP probe succeeds. A failed host is restored to its prior version when
possible, and the rollout stops without touching later hosts.

## Bootstrap an empty Linux host

Add `[hosts.bootstrap]` to the host's private inventory entry. It describes the
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
standard input, never in a process argument. Generated Surge and certificate
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
