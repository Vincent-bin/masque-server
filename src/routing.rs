// Routing table for CONNECT-IP tunnels.
//
// Maps client-assigned IP addresses to (connection_id, stream_id) so that
// inbound packets from the TUN device can be forwarded to the correct tunnel.

use std::net::IpAddr;

use crate::fxhash::FxHashMap;

/// Identifies a specific tunnel within a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TunnelOwner {
    /// Opaque identifier for the QUIC connection (index into a connection table).
    pub conn_id: u64,
    /// The HTTP/3 stream ID that owns this tunnel.
    pub stream_id: u64,
}

/// Maps client-assigned IP addresses to tunnel owners.
///
/// Used by the TUN reader to route inbound packets to the correct QUIC
/// connection and stream.
pub struct RoutingTable {
    entries: FxHashMap<IpAddr, TunnelOwner>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self {
            entries: FxHashMap::default(),
        }
    }

    /// Insert a route for an address. Returns the previous owner if the address
    /// was already routed.
    pub fn insert(&mut self, addr: IpAddr, owner: TunnelOwner) -> Option<TunnelOwner> {
        self.entries.insert(addr, owner)
    }

    /// Look up the tunnel owner for a destination IP.
    pub fn lookup(&self, addr: &IpAddr) -> Option<&TunnelOwner> {
        self.entries.get(addr)
    }

    /// Remove a single route. Returns the removed owner if present.
    pub fn remove(&mut self, addr: &IpAddr) -> Option<TunnelOwner> {
        self.entries.remove(addr)
    }

    /// Remove the routes for `addrs`, but only where the current owner matches
    /// `owner`.
    ///
    /// This is the teardown path used by the server: a tunnel already tracks
    /// its own assigned addresses, so removing them by key costs O(addrs)
    /// rather than a full scan of the table. The owner check keeps a stale
    /// teardown from evicting a route that has since been reassigned.
    pub fn remove_owned(&mut self, addrs: &[IpAddr], owner: &TunnelOwner) {
        for addr in addrs {
            if self.entries.get(addr) == Some(owner) {
                self.entries.remove(addr);
            }
        }
    }

    /// Remove all routes owned by a specific tunnel.
    /// Returns the addresses that were removed.
    ///
    /// Scans the whole table; prefer [`RoutingTable::remove_owned`] when the
    /// caller already knows the addresses.
    pub fn remove_by_owner(&mut self, owner: &TunnelOwner) -> Vec<IpAddr> {
        let mut removed = Vec::new();
        self.entries.retain(|addr, o| {
            if o == owner {
                removed.push(*addr);
                false
            } else {
                true
            }
        });
        removed
    }

    /// Remove all routes for a given connection (all streams).
    /// Returns the addresses that were removed.
    pub fn remove_by_connection(&mut self, conn_id: u64) -> Vec<IpAddr> {
        let mut removed = Vec::new();
        self.entries.retain(|addr, o| {
            if o.conn_id == conn_id {
                removed.push(*addr);
                false
            } else {
                true
            }
        });
        removed
    }

    /// Number of active routes.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn owner(conn: u64, stream: u64) -> TunnelOwner {
        TunnelOwner {
            conn_id: conn,
            stream_id: stream,
        }
    }

    // ── Basic operations ────────────────────────────────────────────

    #[test]
    fn new_table_is_empty() {
        let rt = RoutingTable::new();
        assert!(rt.is_empty());
        assert_eq!(rt.len(), 0);
    }

    #[test]
    fn insert_and_lookup() {
        let mut rt = RoutingTable::new();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let o = owner(1, 4);

        assert!(rt.insert(addr, o).is_none());
        assert_eq!(rt.lookup(&addr), Some(&o));
        assert_eq!(rt.len(), 1);
    }

    #[test]
    fn insert_replaces_existing() {
        let mut rt = RoutingTable::new();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let o1 = owner(1, 4);
        let o2 = owner(2, 8);

        rt.insert(addr, o1);
        let prev = rt.insert(addr, o2);
        assert_eq!(prev, Some(o1));
        assert_eq!(rt.lookup(&addr), Some(&o2));
        assert_eq!(rt.len(), 1);
    }

    #[test]
    fn lookup_missing_returns_none() {
        let rt = RoutingTable::new();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99));
        assert!(rt.lookup(&addr).is_none());
    }

    #[test]
    fn remove_existing() {
        let mut rt = RoutingTable::new();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let o = owner(1, 4);

        rt.insert(addr, o);
        let removed = rt.remove(&addr);
        assert_eq!(removed, Some(o));
        assert!(rt.is_empty());
    }

    #[test]
    fn remove_missing_returns_none() {
        let mut rt = RoutingTable::new();
        assert!(rt.remove(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).is_none());
    }

    // ── IPv6 ────────────────────────────────────────────────────────

    #[test]
    fn ipv6_insert_and_lookup() {
        let mut rt = RoutingTable::new();
        let addr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        let o = owner(5, 12);

        rt.insert(addr, o);
        assert_eq!(rt.lookup(&addr), Some(&o));
    }

    #[test]
    fn mixed_v4_v6() {
        let mut rt = RoutingTable::new();
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let v6 = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));

        rt.insert(v4, owner(1, 4));
        rt.insert(v6, owner(1, 8));
        assert_eq!(rt.len(), 2);
        assert_eq!(rt.lookup(&v4).unwrap().stream_id, 4);
        assert_eq!(rt.lookup(&v6).unwrap().stream_id, 8);
    }

    // ── Bulk removal ────────────────────────────────────────────────

    #[test]
    fn remove_by_owner_single() {
        let mut rt = RoutingTable::new();
        let o = owner(1, 4);
        rt.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), o);
        rt.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), o);
        rt.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), owner(2, 4));

        let removed = rt.remove_by_owner(&o);
        assert_eq!(removed.len(), 2);
        assert_eq!(rt.len(), 1);
        // The remaining route belongs to conn 2
        assert_eq!(
            rt.lookup(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)))
                .unwrap()
                .conn_id,
            2
        );
    }

    #[test]
    fn remove_by_owner_no_match() {
        let mut rt = RoutingTable::new();
        rt.insert(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            owner(1, 4),
        );
        let removed = rt.remove_by_owner(&owner(99, 0));
        assert!(removed.is_empty());
        assert_eq!(rt.len(), 1);
    }

    #[test]
    fn remove_by_connection() {
        let mut rt = RoutingTable::new();
        // Two streams on connection 1
        rt.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), owner(1, 4));
        rt.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), owner(1, 8));
        // One stream on connection 2
        rt.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), owner(2, 4));

        let removed = rt.remove_by_connection(1);
        assert_eq!(removed.len(), 2);
        assert_eq!(rt.len(), 1);
    }

    #[test]
    fn remove_owned_removes_only_matching_owner() {
        let mut rt = RoutingTable::new();
        let mine = owner(1, 4);
        let theirs = owner(2, 4);
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let reassigned = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

        rt.insert(a, mine);
        rt.insert(b, mine);
        // Same address, but it now belongs to a different tunnel.
        rt.insert(reassigned, theirs);

        rt.remove_owned(&[a, b, reassigned], &mine);

        assert!(rt.lookup(&a).is_none());
        assert!(rt.lookup(&b).is_none());
        assert_eq!(rt.lookup(&reassigned), Some(&theirs));
    }

    #[test]
    fn remove_owned_ignores_unknown_addresses() {
        let mut rt = RoutingTable::new();
        rt.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), owner(1, 4));
        rt.remove_owned(&[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))], &owner(1, 4));
        assert_eq!(rt.len(), 1);
    }

    #[test]
    fn remove_by_connection_no_match() {
        let mut rt = RoutingTable::new();
        rt.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), owner(1, 4));
        let removed = rt.remove_by_connection(99);
        assert!(removed.is_empty());
        assert_eq!(rt.len(), 1);
    }

    // ── Default trait ───────────────────────────────────────────────

    #[test]
    fn default_is_empty() {
        let rt = RoutingTable::default();
        assert!(rt.is_empty());
    }
}
