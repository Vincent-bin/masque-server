---
name: masque-ops
description: Safely bootstrap, inspect, diagnose, deploy, roll out, and roll back a masque-server fleet through the bundled deterministic operations CLI. Use when an operator asks Codex to install an empty MASQUE host, check fleet health, execute a release upgrade, collect bounded diagnostics, or recover a prior version. Do not use for ordinary source-code changes, release creation, or editing remote network and authentication configuration.
---

# MASQUE operations

Operate the fleet through the CLI bundled in this Skill; do not replace its
checks with ad hoc SSH commands. All relative paths below are relative to the
directory containing this `SKILL.md`, whether the Skill came from a checkout or
was installed globally.

## Workflow

1. Resolve `scripts/masque-ops.py` inside this Skill directory and use that exact
   executable for every command. Do not search for another checkout or CLI.
   Use the private inventory path supplied by the operator or the default
   `~/.config/masque-server/fleet.toml`. Never open or print that file; pass its
   path only to the bundled CLI, which owns parsing and secret handling.
2. Read [references/inventory.md](references/inventory.md) when creating or
   validating inventory, SSH, probes, or sudo access. For a first empty host,
   use `init-inventory` to create a private inventory and probe defaults instead
   of asking the operator to write TOML. The CLI can generate a self-signed
   certificate, install missing dependencies, and generate the proxy password
   during an authorized bootstrap. Password entry belongs in a local terminal.
   Confirm the SSH host key out of band and explain self-signed trust and any
   external DNS or firewall prerequisites.
   Before choosing authentication or transport, ask whether the operator has a
   particular peer, its documentation, or a redacted configuration example.
   Use those inputs only to determine protocol and authentication capabilities;
   do not copy private endpoints or credentials into conversation or source.
   If capabilities are unknown, explain the choices and ask the operator to
   select them. Do not claim compatibility from a format example alone.
   Basic authentication failures always return an empty 404. Verify that the
   peer sends credentials on its first request; the server does not issue a
   password challenge. Preserve existing credentials during upgrades. A legacy
   `stealth = false` setting no longer enables 407 responses.
3. Run `validate`, then the read-only `status` command. If validation reports a
   missing local probe and the operator authorized tool installation, run this
   Skill's `scripts/install-probe.sh` with `MASQUE_VERSION` set to the exact
   target version; do not fetch or construct another installer.
   To set up an external probe, use `configure-probe`; it tests the connection
   before updating the private local inventory. The operator can enter a Basic
   password privately at the terminal or supply an existing credential path.
   Do not request passwords or client private keys in the conversation.
4. Before any upgrade, run `plan --version vX.Y.Z`. Before a fresh installation,
   run `bootstrap HOST --version vX.Y.Z` without `--apply`. Report blockers from
   the CLI's sanitized output only.
5. Read [references/runbooks.md](references/runbooks.md) before executing a
   deployment, rollout, rollback, or diagnosis.
6. Use a mutating command only when the operator explicitly authorized that
   mutation. `--apply` is the final execution gate; never infer authorization
   from a request to inspect, review, plan, benchmark, or diagnose.
7. Check `plan`'s required probe count against the intended authentication and
   transport coverage. The private inventory can include up to eight required
   probes through `[hosts.probe]` and `[[hosts.probes]]`; an `auto` transport
   probe does not verify both H2 and H3. Do not read or edit the private inventory
   outside the supported CLI. Report each host's resulting version and health. Stop on a failed canary,
   failed verification, partial rollout, or failed rollback.
8. After a successful Linux HTTP/3 installation or upgrade, mention optional
   QUIC UDP GSO. It defaults off and needs
   on/off testing over the real external path; kernel support and a passing
   connectivity probe do not establish performance or absence of packet loss.
   Target UDP GSO is a separate setting and needs its own CONNECT-UDP test.
   Refer to the [performance guide](https://github.com/Vincent-bin/masque-server/blob/main/docs/performance.md#quic-socket)
   and [configuration guide](https://github.com/Vincent-bin/masque-server/blob/main/docs/configuration.md#quic-and-udp).
   This is advice, not authorization or a supported remote configuration
   operation; do not change settings during a release rollout.

For releases with BBR2 as the QUIC default, fresh configurations use BBR2.
Explicit `quic.cc_algorithm` values remain authoritative; configurations that
omit it adopt the default of the installed version. Before upgrades, explain
this behavior change and assess the path using throughput, latency, and loss.
Changing an existing fleet configuration is outside this CLI's capabilities.

## Safety boundaries

- Use exact release tags for mutations. Do not deploy a branch, commit, local
  binary, draft release, or unverified archive.
- Keep inventory, SSH keys, probe passwords, client enrollment files, state,
  and audit logs outside the Skill or any source checkout and out of responses.
- Do not use shell commands, file readers, or tool output to inspect inventory,
  SSH configuration, keys, probe credentials, or generated client files. The
  operations CLI receives their paths and reads or writes them internally.
- Do not print or read raw server configuration, password contents, client
  private keys, environment variables, or unfiltered journals.
- Do not disable SSH host-key checking, use agent forwarding, or trust a newly
  discovered host key without out-of-band verification.
- Do not edit remote configuration, TLS files, routes, forwarding, firewall,
  NAT, systemd policy, or sudoers as part of a release rollout.
- Use `--bootstrap` only for the one-time migration from a release that lacks
  `masque-maintain`, and only after explicit authorization for root SSH.
- Use the `bootstrap` subcommand only for an unconfigured Linux host with the
  private `[hosts.bootstrap]` profile, and only after explicit authorization.
  It transmits credentials through SSH standard input and never reports them.
- Never continue past a CLI blocker or manually bypass its preflight, external
  probe, architecture, checksum, configuration, or rollback checks.
