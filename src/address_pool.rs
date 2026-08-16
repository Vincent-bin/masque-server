// IP address pool for CONNECT-IP tunnels.
//
// Allocates individual host addresses from configured CIDR ranges and
// returns them to the pool when tunnels are torn down.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

/// Error from the address pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolError {
    /// No more addresses available in the pool.
    Exhausted,
    /// The requested address is not in the pool's range.
    OutOfRange(IpAddr),
    /// The requested address is already allocated.
    AlreadyAllocated(IpAddr),
    /// Invalid CIDR string.
    InvalidCidr(String),
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolError::Exhausted => write!(f, "address pool exhausted"),
            PoolError::OutOfRange(a) => write!(f, "address {a} out of pool range"),
            PoolError::AlreadyAllocated(a) => write!(f, "address {a} already allocated"),
            PoolError::InvalidCidr(s) => write!(f, "invalid CIDR: {s}"),
        }
    }
}

impl std::error::Error for PoolError {}

/// Manages allocation of IP addresses from CIDR ranges.
pub struct AddressPool {
    v4_net: Option<Ipv4Net>,
    v6_net: Option<Ipv6Net>,
    allocated: HashSet<IpAddr>,
    /// Next candidate for v4 allocation (host part counter).
    v4_next: u32,
    /// Next candidate for v6 allocation (host part counter).
    v6_next: u128,
}

impl AddressPool {
    /// Create a new pool from CIDR strings.
    ///
    /// Either range can be empty to disable that address family.
    pub fn new(v4_cidr: &str, v6_cidr: &str) -> Result<Self, PoolError> {
        let v4_net = if v4_cidr.is_empty() {
            None
        } else {
            Some(
                v4_cidr
                    .parse::<Ipv4Net>()
                    .map_err(|_| PoolError::InvalidCidr(v4_cidr.into()))?,
            )
        };

        let v6_net = if v6_cidr.is_empty() {
            None
        } else {
            Some(
                v6_cidr
                    .parse::<Ipv6Net>()
                    .map_err(|_| PoolError::InvalidCidr(v6_cidr.into()))?,
            )
        };

        Ok(Self {
            v4_net,
            v6_net,
            allocated: HashSet::new(),
            // Start at 1 to skip the network address.
            v4_next: 1,
            v6_next: 1,
        })
    }

    /// Allocate the next available IPv4 address.
    pub fn allocate_v4(&mut self) -> Result<Ipv4Addr, PoolError> {
        let net = self.v4_net.ok_or(PoolError::Exhausted)?;
        let host_mask = !u32::from(net.netmask());
        let net_addr = u32::from(net.network());

        // max_hosts excludes the broadcast address.
        let max_hosts = host_mask; // e.g. /30 -> mask=3, usable host offsets 1..2
        if max_hosts == 0 {
            return Err(PoolError::Exhausted);
        }

        // We'll scan at most (max_hosts - 1) candidates (offsets 1..max_hosts-1).
        let mut checked = 0u64;
        let total_usable = (max_hosts - 1) as u64; // offsets 1 through max_hosts-1

        while checked < total_usable {
            // Wrap around if we've gone past the usable range.
            if self.v4_next >= max_hosts {
                self.v4_next = 1;
            }

            let addr = Ipv4Addr::from(net_addr | self.v4_next);
            self.v4_next += 1;
            checked += 1;

            let ip = IpAddr::V4(addr);
            if !self.allocated.contains(&ip) {
                self.allocated.insert(ip);
                return Ok(addr);
            }
        }

        Err(PoolError::Exhausted)
    }

    /// Allocate the next available IPv6 address.
    pub fn allocate_v6(&mut self) -> Result<Ipv6Addr, PoolError> {
        let net = self.v6_net.ok_or(PoolError::Exhausted)?;
        let prefix_len = net.prefix_len();
        let net_bits = u128::from(net.network());
        let host_mask: u128 = if prefix_len >= 128 {
            0
        } else {
            (1u128 << (128 - prefix_len)) - 1
        };

        if host_mask == 0 {
            return Err(PoolError::Exhausted);
        }

        // For IPv6 we don't reserve a "broadcast", so usable offsets are 1..host_mask.
        let total_usable = host_mask; // offsets 1 through host_mask
        // Cap iteration to avoid spinning on enormous /64 pools.
        let max_iter = total_usable.min(u64::MAX as u128) as u64;
        let mut checked = 0u64;

        while checked < max_iter {
            if self.v6_next > host_mask {
                self.v6_next = 1;
            }

            let addr = Ipv6Addr::from(net_bits | self.v6_next);
            self.v6_next += 1;
            checked += 1;

            let ip = IpAddr::V6(addr);
            if !self.allocated.contains(&ip) {
                self.allocated.insert(ip);
                return Ok(addr);
            }
        }

        Err(PoolError::Exhausted)
    }

    /// Release an address back to the pool.
    pub fn release(&mut self, addr: IpAddr) -> bool {
        self.allocated.remove(&addr)
    }

    /// Release multiple addresses.
    pub fn release_all(&mut self, addrs: &[IpAddr]) {
        for addr in addrs {
            self.allocated.remove(addr);
        }
    }

    /// Number of currently allocated addresses.
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// Check if an address is currently allocated.
    pub fn is_allocated(&self, addr: &IpAddr) -> bool {
        self.allocated.contains(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Construction ──────────────────────────────────────────────────

    #[test]
    fn new_valid_cidrs() {
        let pool = AddressPool::new("10.89.0.0/16", "fd00:abcd::/64").unwrap();
        assert_eq!(pool.allocated_count(), 0);
    }

    #[test]
    fn new_empty_v6() {
        let pool = AddressPool::new("10.89.0.0/24", "").unwrap();
        assert!(pool.v6_net.is_none());
    }

    #[test]
    fn new_empty_v4() {
        let pool = AddressPool::new("", "fd00::/64").unwrap();
        assert!(pool.v4_net.is_none());
    }

    #[test]
    fn new_invalid_cidr() {
        assert!(matches!(
            AddressPool::new("not-a-cidr", ""),
            Err(PoolError::InvalidCidr(_))
        ));
    }

    // ── IPv4 allocation ───────────────────────────────────────────────

    #[test]
    fn allocate_v4_sequential() {
        let mut pool = AddressPool::new("10.89.0.0/24", "").unwrap();
        let a1 = pool.allocate_v4().unwrap();
        let a2 = pool.allocate_v4().unwrap();
        let a3 = pool.allocate_v4().unwrap();

        assert_eq!(a1, Ipv4Addr::new(10, 89, 0, 1));
        assert_eq!(a2, Ipv4Addr::new(10, 89, 0, 2));
        assert_eq!(a3, Ipv4Addr::new(10, 89, 0, 3));
        assert_eq!(pool.allocated_count(), 3);
    }

    #[test]
    fn allocate_v4_exhaustion() {
        // /30 gives 4 addresses: network, 2 hosts, broadcast
        // host_mask = 3, so max_hosts = 3, usable = 1,2
        let mut pool = AddressPool::new("10.0.0.0/30", "").unwrap();
        let _a1 = pool.allocate_v4().unwrap(); // .1
        let _a2 = pool.allocate_v4().unwrap(); // .2
        assert!(matches!(pool.allocate_v4(), Err(PoolError::Exhausted)));
    }

    #[test]
    fn allocate_v4_release_reuse() {
        let mut pool = AddressPool::new("10.0.0.0/30", "").unwrap();
        let a1 = pool.allocate_v4().unwrap();
        let _a2 = pool.allocate_v4().unwrap();
        // Pool is full
        assert!(pool.allocate_v4().is_err());

        // Release a1
        assert!(pool.release(IpAddr::V4(a1)));
        assert_eq!(pool.allocated_count(), 1);

        // Can allocate again — should get a1 back (wraps around)
        let a3 = pool.allocate_v4().unwrap();
        assert_eq!(a3, a1);
    }

    #[test]
    fn allocate_v4_no_pool() {
        let mut pool = AddressPool::new("", "fd00::/64").unwrap();
        assert!(matches!(pool.allocate_v4(), Err(PoolError::Exhausted)));
    }

    // ── IPv6 allocation ───────────────────────────────────────────────

    #[test]
    fn allocate_v6_sequential() {
        let mut pool = AddressPool::new("", "fd00:abcd::/112").unwrap();
        let a1 = pool.allocate_v6().unwrap();
        let a2 = pool.allocate_v6().unwrap();

        assert_eq!(a1, "fd00:abcd::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(a2, "fd00:abcd::2".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn allocate_v6_exhaustion() {
        // /126 gives 4 addresses, usable hosts = 1,2,3
        let mut pool = AddressPool::new("", "fd00::/126").unwrap();
        let _a1 = pool.allocate_v6().unwrap();
        let _a2 = pool.allocate_v6().unwrap();
        let _a3 = pool.allocate_v6().unwrap();
        assert!(matches!(pool.allocate_v6(), Err(PoolError::Exhausted)));
    }

    #[test]
    fn allocate_v6_no_pool() {
        let mut pool = AddressPool::new("10.0.0.0/24", "").unwrap();
        assert!(matches!(pool.allocate_v6(), Err(PoolError::Exhausted)));
    }

    // ── Release ───────────────────────────────────────────────────────

    #[test]
    fn release_unallocated_returns_false() {
        let mut pool = AddressPool::new("10.0.0.0/24", "").unwrap();
        assert!(!pool.release(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99))));
    }

    #[test]
    fn release_all_addresses() {
        let mut pool = AddressPool::new("10.0.0.0/24", "fd00::/112").unwrap();
        let v4 = pool.allocate_v4().unwrap();
        let v6 = pool.allocate_v6().unwrap();
        assert_eq!(pool.allocated_count(), 2);

        pool.release_all(&[IpAddr::V4(v4), IpAddr::V6(v6)]);
        assert_eq!(pool.allocated_count(), 0);
    }

    // ── is_allocated ──────────────────────────────────────────────────

    #[test]
    fn is_allocated_checks() {
        let mut pool = AddressPool::new("10.0.0.0/24", "").unwrap();
        let addr = pool.allocate_v4().unwrap();
        assert!(pool.is_allocated(&IpAddr::V4(addr)));
        assert!(!pool.is_allocated(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99))));
    }

    // ── Larger pool ───────────────────────────────────────────────────

    #[test]
    fn allocate_many_v4() {
        let mut pool = AddressPool::new("10.89.0.0/16", "").unwrap();
        // Allocate 100 addresses
        for i in 1..=100u32 {
            let addr = pool.allocate_v4().unwrap();
            let expected = Ipv4Addr::from(u32::from(Ipv4Addr::new(10, 89, 0, 0)) | i);
            assert_eq!(addr, expected);
        }
        assert_eq!(pool.allocated_count(), 100);
    }
}
