# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) while the project is
pre-1.0.

## Unreleased

### Added

- Globally bounded, connection-cancelled Argon2 authentication work.
- Batched target UDP receive and send paths on Linux.
- Config-sized target receive buffers with portable truncation detection.
- Per-connection latency percentiles and batch connection-rate reporting in
  the load generator.
- Standalone repository layout, CI, deployment, security, and contributor
  documentation.

### Changed

- Production binary is consistently named `masque-server`.
- Platform network adapters live under `src/net/`.
- The E2E client lives under `tools/masque-e2e/` and deployment assets under
  `deploy/`.

## 0.1.0-rc.10 - 2026-08-15

- Scaled packet processing across independent `SO_REUSEPORT` shards.

## 0.1.0-rc.9 - 2026-08-15

- Preserved the first CONNECT-UDP datagram during socket registration.

## 0.1.0-rc.8 - 2026-08-15

- Added standard HTTP/3 CONNECT TCP proxying.

## 0.1.0-rc.7 - 2026-08-15

- Added mandatory-by-default HTTP proxy authentication.

Earlier release candidates established Linux packaging, systemd deployment,
QUIC pacing, and the initial performance test workflow.
