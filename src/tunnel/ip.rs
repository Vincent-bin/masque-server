// CONNECT-IP tunnel implementation (RFC 9484).
//
// Each tunnel is assigned IP addresses from a shared pool and relays IP
// packets between the QUIC client and a shared TUN device.

use std::net::IpAddr;
use std::time::Instant;

use crate::datagram::DatagramHeader;

/// State for a single CONNECT-IP tunnel.
pub struct IpTunnel {
    /// The HTTP/3 stream ID this tunnel is bound to.
    pub stream_id: u64,
    /// IP addresses assigned to this client.
    pub assigned_addrs: Vec<IpAddr>,
    /// Timestamp of last packet relayed (either direction).
    pub last_activity: Instant,
    /// Precomputed datagram framing prefix for this stream.
    pub header: DatagramHeader,
}

impl IpTunnel {
    /// Create a tunnel for `stream_id`, which must be a client-initiated
    /// bidirectional stream (divisible by 4).
    pub fn new(stream_id: u64) -> Self {
        Self {
            stream_id,
            assigned_addrs: Vec::new(),
            last_activity: Instant::now(),
            // Stream IDs come from quiche's request streams, which are always
            // client-initiated bidi; fall back to stream 0's framing rather
            // than panicking if that ever changes.
            header: DatagramHeader::new(stream_id)
                .unwrap_or_else(|_| DatagramHeader::new(0).unwrap()),
        }
    }

    /// Check whether a source IP is assigned to this tunnel.
    pub fn owns_address(&self, addr: &IpAddr) -> bool {
        self.assigned_addrs.contains(addr)
    }

    /// Check whether the tunnel has been idle longer than `timeout`.
    pub fn is_idle(&self, timeout: std::time::Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    #[test]
    fn new_sets_stream_id() {
        let t = IpTunnel::new(42);
        assert_eq!(t.stream_id, 42);
    }

    #[test]
    fn new_starts_with_empty_addrs() {
        let t = IpTunnel::new(0);
        assert!(t.assigned_addrs.is_empty());
    }

    #[test]
    fn new_records_recent_activity() {
        let before = Instant::now();
        let t = IpTunnel::new(0);
        assert!(t.last_activity >= before);
    }

    #[test]
    fn owns_address_empty() {
        let t = IpTunnel::new(0);
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(!t.owns_address(&addr));
    }

    #[test]
    fn owns_address_v4_match() {
        let mut t = IpTunnel::new(0);
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        t.assigned_addrs.push(addr);
        assert!(t.owns_address(&addr));
    }

    #[test]
    fn owns_address_v4_no_match() {
        let mut t = IpTunnel::new(0);
        t.assigned_addrs.push(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(!t.owns_address(&other));
    }

    #[test]
    fn owns_address_v6_match() {
        let mut t = IpTunnel::new(0);
        let addr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        t.assigned_addrs.push(addr);
        assert!(t.owns_address(&addr));
    }

    #[test]
    fn owns_address_dual_stack() {
        let mut t = IpTunnel::new(0);
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let v6 = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        t.assigned_addrs.push(v4);
        t.assigned_addrs.push(v6);
        assert!(t.owns_address(&v4));
        assert!(t.owns_address(&v6));
    }

    #[test]
    fn is_idle_fresh_tunnel() {
        let t = IpTunnel::new(0);
        assert!(!t.is_idle(Duration::from_secs(60)));
    }

    #[test]
    fn is_idle_after_timeout() {
        let mut t = IpTunnel::new(0);
        t.last_activity = Instant::now() - Duration::from_secs(120);
        assert!(t.is_idle(Duration::from_secs(60)));
    }
}
