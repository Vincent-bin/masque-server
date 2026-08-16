//! Platform-facing network I/O.
//!
//! Protocol and tunnel modules use these adapters instead of issuing
//! platform syscalls directly. Linux uses batched UDP and offload features;
//! other platforms keep portable Tokio fallbacks.

pub(crate) mod quic;
pub(crate) mod target_udp;
