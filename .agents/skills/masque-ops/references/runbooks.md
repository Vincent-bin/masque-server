# Fleet operation runbooks

Set the private inventory path once for the examples:

```sh
inventory="$HOME/.config/masque-server/fleet.toml"
```

Place global options before the subcommand. Add `--json` when machine-readable
output is useful.

## Inspect and plan

These commands are read-only:

```sh
scripts/masque-ops.py --inventory "$inventory" validate
scripts/masque-ops.py --inventory "$inventory" status
scripts/masque-ops.py --inventory "$inventory" diagnose edge-a --journal-lines 100
scripts/masque-ops.py --inventory "$inventory" plan --version vX.Y.Z
```

Diagnostics are bounded and filter authentication material, but journals can
still contain client or destination metadata. Review them before sharing.

## Deploy one host

Run and inspect `plan` first, then execute only after explicit authorization:

```sh
scripts/masque-ops.py --inventory "$inventory" \
  deploy edge-a --version vX.Y.Z --apply
```

For a pre-operations release that does not yet contain `masque-maintain`, use
the one-time root-only bootstrap after the operator approves it:

```sh
scripts/masque-ops.py --inventory "$inventory" \
  deploy edge-a --version vX.Y.Z --bootstrap --apply
```

The exact target Release must contain the archive and SHA-256 sidecar for the
remote architecture. The currently installed Release must contain them too, so
automatic rollback remains possible. The remote installer checks the existing
configuration with the candidate before replacement and restores the previous
release-managed files if activation fails. Post-deploy verification also
requires the configuration SHA-256 to match its preflight value.

## Install an empty host

Keep the SSH destination, key, verified host-key file, remote TLS paths, and
credential output paths in the private inventory. Do not open that inventory in
an AI session. Validate it, inspect the empty host, and run the bootstrap
preflight without mutation:

```sh
scripts/masque-ops.py --inventory "$inventory" validate
scripts/masque-ops.py --inventory "$inventory" status edge-new
scripts/masque-ops.py --inventory "$inventory" \
  bootstrap edge-new --version vX.Y.Z
```

After the operator explicitly authorizes the fresh installation:

```sh
scripts/masque-ops.py --inventory "$inventory" \
  bootstrap edge-new --version vX.Y.Z --apply
```

The CLI checks Linux architecture, release assets, remote dependencies, absence
of an existing MASQUE install, readable TLS files, local secret destinations,
and the optional probe before changing the host. The Basic password is read or
created in its mode-`0600` local file and sent only over SSH standard input.
Generated Surge or certificate-client configuration streams directly into new
local mode-`0600` files. The model sees only the host alias, status, blockers,
version, and probe result. A fresh host has no prior release to restore, so stop
and inspect status if post-install verification fails.

## Fleet rollout

Select exactly one canary in inventory or with `--canary`. The canary is
upgraded and externally probed before the remaining hosts are changed, one at a
time:

```sh
scripts/masque-ops.py --inventory "$inventory" \
  rollout --version vX.Y.Z --apply
```

On any failure, stop and report which hosts changed and which did not. The
failing host is automatically restored when possible; earlier successful hosts
are not silently rolled back as a group.

## Roll back one host

The local mode-`0600` state file records the previous version after each
successful deployment. Restore it with:

```sh
scripts/masque-ops.py --inventory "$inventory" rollback edge-a --apply
```

Do not edit the state file to force a rollback. If state and the running
version disagree, investigate and recover manually rather than bypassing the
guard.
