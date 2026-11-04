# AI-assisted configuration, changes, and deployment

Use this guide to select the supported interface and evidence for an operator's
request. The agent interprets intent; the project's CLI and tests perform the
checks. A plan, a successful local validation, and a verified live change are
different outcomes and must be reported separately. Keep infrastructure
identifiers and private configuration out of chat and shared artifacts, as
specified in [AGENTS.md](../AGENTS.md).

## Choose the operation

| Request | Supported interface | Activation and verification | Boundary |
| --- | --- | --- | --- |
| Prepare an empty host | Install the documented operations bundle, then use `masque-ops init-inventory` | Generates a private first-host inventory and probe; credentials are entered privately or generated | Verify the SSH host key out of band; DNS, provider firewall and certificate trust still need an appropriate external path |
| Inspect a fleet or plan a release | `masque-ops validate`, `status`, and `plan` | Read-only; review blockers and target version | Does not authorize a mutation or prove client traffic works |
| Bootstrap an empty host | `masque-ops bootstrap` without `--apply`, then the authorized `--apply` operation | Prepare supported missing dependencies and optional self-signed TLS, validate service and configuration, then run the external probe | Only the declared empty-host profile is supported; no previous release exists to restore |
| Deploy or roll back a release | `masque-ops plan`, followed by authorized `deploy`, `rollout`, or `rollback` | Check the recorded result, service, unchanged configuration hash and configured probe; stop on failure | Rollback restores a release, not arbitrary configuration or host network changes |
| Add a local listener | `masque-server add-listener`, with `--dry-run` when applicable | Validate the intended change, then restart and check service and external traffic | The bind check is not a reservation; a listener needs a restart. The command does not keep a backup |
| Manage local Basic accounts | `list-users`, `add-user`, `set-password`, `remove-user` | Validate the resulting configuration, reload credentials and verify intended access and rejection | These commands edit local configuration; a release rollout is not a configuration rollback |
| Change another existing configuration setting | See [Configuration](configuration.md) and [Deployment](deployment.md) | Validate a candidate with `check-config`; activate using the documented reload or restart, then verify | There is no general remote configuration transaction in `masque-ops`; do not invent one or bypass its boundary |
| Diagnose a problem | `masque-ops status` / `diagnose`, local `status`, `doctor`, or `support-bundle` | Use bounded, redacted evidence; verify relevant client paths where possible | Diagnostics and validation cannot establish end-to-end availability on their own |

The local server commands are not remote operations APIs. The `masque-ops`
Skill expressly excludes editing remote network, authentication, TLS, and
configuration files. If an existing remote change cannot be performed through
the supported interface, describe the capability gap and a reviewable plan;
do not fall back to ad hoc SSH or claim the change was applied.

## Work from intent to evidence

1. Identify the requested behavior, scope, affected transport and authentication
   mode, and whether it is a local configuration change, fresh bootstrap, or
   release operation. Resolve missing values without exposing private endpoints,
   credentials, inventories, raw configuration, or fleet aliases in reports.
2. Inspect the applicable documentation and current state through the supported
   read-only interface. For fleet work, follow the installed
   [`masque-ops` Skill](../.agents/skills/masque-ops/SKILL.md), including its
   rules for private inventory, exact release versions, planning, and approval.
3. Prepare a concrete change and verification plan. Identify whether activation
   requires a reload or restart, the expected impact on existing connections,
   required external prerequisites, and how to recover. Keep a protected,
   independently recoverable configuration backup before configuration edits;
   `add-listener` and release rollback do not supply one.
4. Validate before activation. `check-config` validates startup configuration
   without binding sockets or creating a TUN. `add-listener` also attempts a
   bind unless disabled, but that only describes the instant of the check. Its
   `--dry-run` prints a configuration block that may include a credential hash;
   treat output as sensitive and do not copy it into a conversation or artifact.
   Dry-run is not a reservation and does not exercise activation.
5. Apply only the requested and authorized operation using its supported
   interface. For fleet release mutations, follow the Skill's explicit `--apply`
   gate. Stop on a blocker or failed canary; do not skip checks to make progress.
6. Verify the actual outcome: configuration validation, service readiness and
   version where relevant, reload or restart result, and an external probe for
   each requested transport and traffic type when available. Check rejection
   paths when changing authentication. A probe omitted or unable to cover a
   requested path is a coverage gap, not a success.
7. Report only sanitized scope, intended change, applied or planned status,
   verification results, and any unverified behavior or recovery action. Never
   publish host aliases, even if the CLI's sanitized output contains them.

Credential and TLS reloads affect only the documented reloadable state. A new
listener requires a restart; other configuration fields must not be assumed
reloadable. See [configuration reload](configuration.md#listeners) and
[service lifecycle](deployment.md#service-lifecycle).

## Current capability gaps

- There is no guarded fleet-wide transaction for changing existing server
  configuration, users, certificates, firewall, or routes. Remote configuration
  management needs an explicitly designed and tested interface before agents
  can reliably automate it through `masque-ops`.
- Release rollout is sequential and stops on failure. A failed host may be
  restored, but earlier successful hosts are not automatically rolled back as a
  group. Bootstrap has no prior installation to restore.
- An external probe may be optional for individual operations, and a successful
  probe covers only its configured transports and traffic. Record what was
  actually exercised.
- `check-config` is not a live bind, network, firewall, or client-compatibility
  test. A clean result cannot guarantee the service will activate successfully.

See [AI-assisted fleet operations](operations.md),
[Troubleshooting](troubleshooting.md), and [Testing](testing.md) for command
details and environment-specific coverage.

For incident diagnosis, use the
[evidence workflow](troubleshooting.md#evidence-workflow-for-ai-assisted-diagnosis)
to select read-only checks, distinguish observation from inference, and report
unverified paths without exposing raw operational data.
