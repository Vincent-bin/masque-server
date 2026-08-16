## Summary

Describe the behavior change and why it is needed.

## Correctness and resource bounds

Describe queue, buffer, task, connection, tunnel, unsafe-code, and failure-mode
effects. Write “not applicable” where appropriate.

## Validation

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo test --workspace --locked`
- [ ] Relevant E2E tests
- [ ] Before/after benchmark for a hot-path change

## Compatibility

Note configuration, protocol, deployment, and upgrade impact.
