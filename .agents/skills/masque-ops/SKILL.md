---
name: masque-ops
description: Safely bootstrap, inspect, diagnose, deploy, roll out, and roll back a masque-server fleet through the repository's deterministic operations CLI. Use when an operator asks Codex to install an empty MASQUE host, check fleet health, execute a release upgrade, collect bounded diagnostics, or recover a prior version. Do not use for ordinary source-code changes, release creation, or editing remote network and authentication configuration.
---

# MASQUE operations

Operate the fleet through `scripts/masque-ops.py`; do not replace its checks with
ad hoc SSH commands.

## Workflow

1. Locate the repository root and private inventory path. Use the path supplied
   by the operator or the default `~/.config/masque-server/fleet.toml`. Never
   open or print that file; pass its path only to `scripts/masque-ops.py`, which
   owns parsing and secret handling.
2. Read [references/inventory.md](references/inventory.md) when creating or
   validating inventory, SSH, probes, or sudo access.
3. Run `validate`, then the read-only `status` command. If validation reports a
   missing local probe and the operator authorized tool installation, run the
   repository's `install-probe.sh` for the exact target version; do not fetch or
   construct another installer.
4. Before any upgrade, run `plan --version vX.Y.Z`. Before a fresh installation,
   run `bootstrap HOST --version vX.Y.Z` without `--apply`. Report blockers from
   the CLI's sanitized output only.
5. Read [references/runbooks.md](references/runbooks.md) before executing a
   deployment, rollout, rollback, or diagnosis.
6. Use a mutating command only when the operator explicitly authorized that
   mutation. `--apply` is the final execution gate; never infer authorization
   from a request to inspect, review, plan, benchmark, or diagnose.
7. Report each host's resulting version and health. Stop on a failed canary,
   failed verification, partial rollout, or failed rollback.

## Safety boundaries

- Use exact release tags for mutations. Do not deploy a branch, commit, local
  binary, draft release, or unverified archive.
- Keep inventory, SSH keys, probe passwords, client enrollment files, state,
  and audit logs outside the repository and out of responses.
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
