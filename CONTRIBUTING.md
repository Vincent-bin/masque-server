# Contributing

Contributions are welcome. For substantial protocol, concurrency, or public
configuration changes, open an issue describing the intended behavior and
compatibility impact before implementation.

## Development setup

Install rustup, Clang, CMake, and the native tools required by `quiche`. Rustup
uses the production toolchain pinned in `rust-toolchain.toml`. Then run:

```sh
cargo build --workspace --locked
cargo test --workspace --locked
```

For a quick local check, run `scripts/check.sh quick`. Before submitting a
change, run the shared local and CI checks:

```sh
scripts/check.sh full
```

This requires the pinned Rust toolchain, Rust 1.88.0, Clang, CMake, Python 3,
and ShellCheck. The full check does not replace the platform-specific, E2E,
or performance checks selected by the change matrix in
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
