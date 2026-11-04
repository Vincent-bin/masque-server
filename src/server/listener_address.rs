//! Listener bind-address overlap rules shared by planning and binding.

use std::net::{IpAddr, SocketAddr};

/// Whether binding `wildcard` also claims `other`.
///
/// `::` is treated as covering IPv4 too. Whether it really does is the kernel's
/// `IPV6_V6ONLY` default — `0` on Linux unless `net.ipv6.bindv6only` says
/// otherwise, and the two wildcards were observed to collide on macOS. Nothing
/// here sets that option, so assuming the wider meaning is what keeps the
/// answer from depending on the host: the pair is refused everywhere instead of
/// failing to bind on some hosts and quietly splitting traffic on others.
fn address_covers(wildcard: IpAddr, other: IpAddr) -> bool {
    match wildcard {
        IpAddr::V4(v4) => v4.is_unspecified() && other.is_ipv4(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

/// Reduce an address to the one form two listeners can be compared in.
///
/// `::ffff:127.0.0.1` and `127.0.0.1` name the same interface, so comparing
/// them as written lets a pair through that the kernel then refuses with
/// `EADDRINUSE` — or worse, accepts under `SO_REUSEPORT`, leaving one listener
/// shadowing traffic meant for the other's authentication mode.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// Whether two socket addresses name the same interface after normalising an
/// IPv4-mapped IPv6 spelling.
///
/// A non-zero scope ID is part of a link-local IPv6 interface identity. In
/// particular, `fe80::1%2` and `fe80::1%3` may coexist on two links even though
/// `ip()` alone returns the same address for both. Scope IDs on global addresses
/// and flow information are ignored because they do not distinguish bind
/// targets. A zero link-local scope remains conservative because the kernel may
/// resolve it to the same interface as an explicit one.
fn same_canonical_address(a: SocketAddr, b: SocketAddr) -> bool {
    let (canonical_a, canonical_b) = (canonical_ip(a.ip()), canonical_ip(b.ip()));
    if canonical_a != canonical_b {
        return false;
    }

    match (canonical_a, a, b) {
        (IpAddr::V6(ip), SocketAddr::V6(a), SocketAddr::V6(b)) if ip.is_unicast_link_local() => {
            a.scope_id() == 0 || b.scope_id() == 0 || a.scope_id() == b.scope_id()
        }
        _ => true,
    }
}

/// How two listeners contend for the same packets, if they do.
///
/// Distinguished so the diagnostic can say which of them it is: told that a
/// loopback pair "overlaps because a wildcard claims its family", an operator
/// would go looking for a wildcard that is not there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AddressConflict {
    /// The same address, written the same way.
    Identical,
    /// The same address, written two ways — `127.0.0.1` and `::ffff:127.0.0.1`.
    SameAddress,
    /// One is a wildcard that claims the other.
    WildcardCovers,
}

/// How two listeners would contend, or `None` if they would not.
pub(super) fn listen_address_conflict(a: SocketAddr, b: SocketAddr) -> Option<AddressConflict> {
    if a.port() != b.port() {
        return None;
    }
    // Port 0 has no fixed address to compare yet. Binding resolves it and checks
    // the result against both already-bound and still-planned listeners; this is
    // necessary because SO_REUSEPORT can make the kernel reuse a selected port.
    if a.port() == 0 {
        return None;
    }
    if a == b {
        return Some(AddressConflict::Identical);
    }

    // Canonical form, so an IPv4-mapped spelling cannot present itself as a
    // different address from the IPv4 one it resolves to.
    let (canonical_a, canonical_b) = (canonical_ip(a.ip()), canonical_ip(b.ip()));
    if same_canonical_address(a, b) {
        return Some(AddressConflict::SameAddress);
    }
    if address_covers(canonical_a, canonical_b) || address_covers(canonical_b, canonical_a) {
        return Some(AddressConflict::WildcardCovers);
    }
    None
}
