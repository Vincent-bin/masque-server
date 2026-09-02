# Private fleet inventory

The operations CLI requires Python 3.11 or newer. Resolve paths relative to the
Skill directory and copy `assets/fleet.example.toml` to the private inventory
location:

```sh
install -d -m 0700 ~/.config/masque-server ~/.config/masque-server/secrets
install -m 0600 assets/fleet.example.toml \
  ~/.config/masque-server/fleet.toml
```

Replace every example address and probe endpoint. Keep the inventory, SSH
identity, Basic password file, and client-certificate enrollment JSON owned by
the invoking user with mode `0600`. The CLI rejects symlinked inventory and
secret files, inline passwords, unknown keys, duplicate hosts, and unsupported
release repositories.

An AI agent must pass the inventory path to the CLI without opening the file.
Successful CLI output deliberately omits SSH addresses, identity paths, remote
certificate paths, usernames, passwords, and generated client-file paths.

The CLI targets the official package layout (`masque.service`,
`/etc/masque/masque.toml`, and `/usr/local/bin/masque-server`). These paths are
not inventory options because allowing them to diverge from the fixed remote
helper would make preflight results ambiguous.

Record each SSH host key only after verifying its fingerprint through an
independent channel. Point `known_hosts_file` at that file. Do not turn off
strict host-key verification and do not use an unverified `ssh-keyscan` result
as the trust decision.

## Remote privilege boundary

Release archives install the root-owned `/usr/local/sbin/masque-maintain`
entrypoint. It accepts only:

```text
masque-maintain status
masque-maintain diagnose [1..500]
masque-maintain upgrade vVERSION
```

It cannot edit MASQUE configuration, TLS material, forwarding, routes,
firewall, or NAT. A dedicated SSH user can receive only these commands through
sudo. Validate the policy with `visudo -cf` before installing it; a suitable
policy is:

```sudoers
Cmnd_Alias MASQUE_STATUS = /usr/local/sbin/masque-maintain status
Cmnd_Alias MASQUE_DIAGNOSE = /usr/local/sbin/masque-maintain diagnose, /usr/local/sbin/masque-maintain diagnose [0-9]*
Cmnd_Alias MASQUE_UPGRADE = /usr/local/sbin/masque-maintain upgrade v[0-9]*
masque-deploy ALL=(root) NOPASSWD: MASQUE_STATUS, MASQUE_DIAGNOSE, MASQUE_UPGRADE
```

Set `user = "masque-deploy"` and `sudo = true` in the inventory. The helper
also validates argument count, the diagnostic range, and the complete semantic
version syntax, so the sudo wildcard cannot turn it into an arbitrary command
runner. Ensure the helper and its parent directories remain root-owned and not
writable by the deployment user.

For the initial transition from a release without the helper, temporarily use
an explicit root inventory entry and the CLI's `deploy --bootstrap` flag. This
one-time path sends the Skill's bundled, audited installer over SSH; subsequent
operations should use the dedicated account and omit `--bootstrap`.

For a truly unconfigured host, add a private `[hosts.bootstrap]` table and use
the separate `bootstrap` subcommand. It requires an explicit root SSH entry,
normalized absolute paths to existing remote TLS files, an authentication mode,
and local credential destinations under a private directory. Inline passwords
are not accepted. Basic mode reads an existing mode-`0600` password file or
creates it before connecting; certificate mode retrieves the generated client
configuration directly into a new mode-`0600` file. If the probe uses those
credentials, its paths must match the bootstrap paths exactly. See
`assets/fleet.example.toml` for all fields.

## External probes

A host's optional `[hosts.probe]` runs `masque-probe` on the administration
machine after a deployment. Basic authentication uses `username` plus a
`password_file`; the password file is connected directly to probe stdin and is
never placed in the process arguments or parsed by `masque-ops`. Certificate
authentication uses `client_config`. A rollout requires a canary probe unless
the operator explicitly accepts the weaker `--allow-no-probe` check.
