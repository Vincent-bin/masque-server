# AI-assisted fleet operations

The repository includes an optional operations layer for repeatable MASQUE
fleet installation and upgrades. An AI coding agent can interpret an operator's request through
the repo-scoped `masque-ops` Skill, but all privileged work is performed by the
deterministic, tested `scripts/masque-ops.py` CLI. No model, API key, or AI
runtime is installed on a proxy server.

This is deliberately bounded release operations rather than general configuration
management. It can bootstrap an explicitly described empty host, inspect status,
collect bounded diagnostics, validate an upgrade plan, deploy an exact GitHub
Release, run an external protocol probe, and restore the previously recorded
version. Outside the fresh-install profile, it does not edit configuration,
certificates, users, routes, forwarding, firewall, NAT, or monitoring services.
It targets the paths and service name used by the official Linux installer;
custom installation layouts are intentionally outside its scope.

## Set up an inventory

Python 3.11 or newer and OpenSSH are required on the administration machine.
Copy the example outside the repository and protect it:

```sh
install -d -m 0700 ~/.config/masque-server ~/.config/masque-server/secrets
install -m 0600 deploy/config/fleet.example.toml \
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

Install the release-matched probe on Linux or macOS x86_64/ARM64 with automatic
platform and architecture detection:

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
scripts/masque-ops.py validate
scripts/masque-ops.py status
scripts/masque-ops.py plan --version vX.Y.Z
scripts/masque-ops.py diagnose edge-a --journal-lines 100
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
scripts/masque-ops.py plan --version vX.Y.Z
scripts/masque-ops.py deploy edge-a --version vX.Y.Z --apply
scripts/masque-ops.py rollout --version vX.Y.Z --apply
scripts/masque-ops.py rollback edge-a --apply
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
mode-`0600` destinations for generated credentials. The repository example
shows Basic mode; `client_cert` and `dual` additionally require
`client_endpoint` and `client_config`. Inline passwords are rejected.

First run the non-mutating preflight:

```sh
scripts/masque-ops.py bootstrap edge-new --version vX.Y.Z
```

After explicit approval, the same command performs the install:

```sh
scripts/masque-ops.py bootstrap edge-new --version vX.Y.Z --apply
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
the repo Skill's
[`inventory.md`](../.agents/skills/masque-ops/references/inventory.md) for the
sudoers example and probe configuration. A server running an older release
does not yet have the helper; its first transition requires the explicit,
root-only `deploy --bootstrap` path. Remove root SSH from the inventory after
that transition.

## Using the Skill

Codex-compatible agents discover the repo-scoped
`.agents/skills/masque-ops/SKILL.md` automatically when working in this
repository. A typical request is: “Use `$masque-ops` to inspect the fleet and
prepare an upgrade plan for `vX.Y.Z`.” Inspection and planning do not authorize
deployment; ask explicitly to execute the reviewed plan before the agent may
add `--apply`.

The CLI is the supported interface and works without an AI agent. Treat the
Skill as a guarded natural-language runbook, not as an independent source of
privilege or release truth.
