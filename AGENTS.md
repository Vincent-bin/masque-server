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
