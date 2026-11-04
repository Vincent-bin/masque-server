# Infrastructure privacy

- Never disclose real infrastructure IP addresses, hostnames, fleet aliases,
  infrastructure account names, credential paths, or private deployment/probe configuration
  in chat summaries, PR descriptions, issues, comments, release notes, or
  published artifacts. Use generic roles such as "the canary node".
- Use actual endpoints only as necessary operational inputs. Process tool
  output privately and emit sanitized summaries instead of echoing identifiers.
  Sanitized operations-CLI output may still contain private fleet aliases;
  redact those before presenting or publishing it.
- Keep inventories, authentication material, live configuration, and raw host
  diagnostics outside the repository and public build artifacts.
- Before publishing text, inspect it for infrastructure identifiers. When
  correcting a disclosure, check prior public edit revisions as well as the
  current text, and verify removal without printing the original values.
- Synthetic protocol fixtures, loopback addresses, and documentation-only
  example networks may remain where needed to explain or test behavior.

# Development guide

This repository is a Rust MASQUE server. HTTP/3 uses shard-owned QUIC event
loops; HTTP/2 uses asynchronous connection tasks. Begin with
[`docs/architecture.md`](docs/architecture.md) for ownership, source layout,
and invariant references. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) for design
rules and [`docs/testing.md`](docs/testing.md) for change-specific validation.

- Keep queues and buffers bounded; do not block shard loops on DNS, password
  hashing, or target I/O. Preserve TCP backpressure and bounded UDP loss.
- Keep Linux-specific fast paths isolated and preserve portable fallbacks.
  Explain the invariants of every unsafe block.
- Preserve safe configuration upgrade behavior and update example config when
  adding fields. Verify both HTTP transports when touching shared behavior.
- Run `scripts/check.sh quick` for a fast formatting and shell syntax check.
  Before submission, run `scripts/check.sh full` and the applicable additional
  checks in the testing matrix. Report checks that could not run and why.
- For fleet operations use the `masque-ops` Skill and its bundled CLI; source
  changes do not require that Skill. Follow the privacy rules above in all
  reports and artifacts.
- For configuration, activation, and deployment tasks, consult
  [`docs/ai-operations.md`](docs/ai-operations.md). Distinguish planned,
  applied, and externally verified outcomes; report unsupported operations and
  verification gaps rather than bypassing the documented operations boundary.
- For diagnosis, follow the evidence workflow in
  [`docs/troubleshooting.md`](docs/troubleshooting.md). Separate observed check
  results from hypotheses, report skipped checks, and keep raw diagnostics and
  private infrastructure identifiers out of reports.
