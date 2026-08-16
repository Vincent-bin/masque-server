# Contributing

Contributions are welcome. For substantial protocol, concurrency, or public
configuration changes, open an issue describing the intended behavior and
compatibility impact before implementation.

## Development setup

Install stable Rust, Clang, CMake, and the native tools required by `quiche`.
Then run:

```sh
cargo build --workspace --locked
cargo test --workspace --locked
```

Before submitting a change:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Changes to packet handling, scheduling, buffering, or authentication must also
run the relevant E2E or benchmark command described in
[`docs/testing.md`](docs/testing.md).

## Design rules

- Keep all queues and per-connection buffers bounded.
- Never block a shard event loop with DNS, password hashing, or target I/O.
- Treat QUIC DATAGRAM traffic as lossy; do not add an unbounded retry queue.
- Keep Linux-only syscalls behind `cfg(target_os = "linux")` and provide a
  portable fallback where the feature is not intrinsically Linux-specific.
- Document every `unsafe` block with the lifetime, layout, and descriptor
  invariants that make it sound.
- Add configuration fields compatibly: defaults must preserve a safe upgrade
  path and example configuration must be updated in the same change.

## Pull requests

Keep commits focused and explain:

1. the problem and observable behavior;
2. correctness and resource-bound implications;
3. tests performed; and
4. benchmark results when a hot path changes.

Do not include credentials, private certificates, server addresses, or raw
production logs.
