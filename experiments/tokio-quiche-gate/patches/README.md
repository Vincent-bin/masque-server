# P1 prototype patches

These patches apply to published tokio-quiche **0.23.0** and datagram-socket
**0.8.1**. `manifest.json` pins SHA-256 of every original source file they
modify. `prepare.py` verifies those hashes before patching disposable copies.
The Cargo registry and production dependency graph are never edited.

- `0001-compatibility-prototype.patch`: configurable server CID parsing,
  opt-in preservation of the other stream direction, opt-in unknown/finished
  DATAGRAM input policies, opt-in suppression of per-read progress events,
  and malformed-QSID close-code mapping. It is not a
  complete G1–G8 solution; blocked-body FIN remains a failing probe.
- `0002-musl-msghdr.patch`: initialize the Linux C header with valid zero values
  before assigning iovec fields, including musl's private padding. It does not
  change buffer ownership or pointer lifetimes across the syscall.

The first patch is deliberately limited to feasibility work; it has not been
accepted upstream or adopted by the production server. Any further queue,
admission, Retry, migration or lifecycle patch requires its own regression
evidence and maintenance review before entering the production dependency graph.

Original sources are copyright Cloudflare, Inc. Their BSD-2-Clause conditions
are preserved in [COPYING](COPYING). Published source:

- [tokio-quiche 0.23.0](https://crates.io/crates/tokio-quiche/0.23.0)
- [datagram-socket 0.8.1](https://crates.io/crates/datagram-socket/0.8.1)
