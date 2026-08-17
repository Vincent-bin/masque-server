// IP address pool for CONNECT-IP tunnels.
//
// Allocates individual host addresses from configured CIDR ranges and
// returns them to the pool when tunnels are torn down.

use std::collections::HashMap;
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
    /// The requested address is not pinned to this authenticated identity.
    NotReserved(IpAddr),
    /// Invalid CIDR string.
    InvalidCidr(String),
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolError::Exhausted => write!(f, "address pool exhausted"),
            PoolError::OutOfRange(a) => write!(f, "address {a} out of pool range"),
            PoolError::AlreadyAllocated(a) => write!(f, "address {a} already allocated"),
            PoolError::NotReserved(a) => {
                write!(f, "address {a} is not reserved for this client")
            }
            PoolError::InvalidCidr(s) => write!(f, "invalid CIDR: {s}"),
        }
    }
}

impl std::error::Error for PoolError {}

/// Manages allocation of IP addresses from CIDR ranges.
pub struct AddressPool {
    v4_net: Option<Ipv4Net>,
    v6_net: Option<Ipv6Net>,
    /// Live leases per address.
    ///
    /// Dynamic addresses always have a count of one. A pinned address can have
    /// a short overlap while the same authenticated client reconnects before
    /// its dead QUIC connection times out, so those leases are reference
    /// counted instead of turning a normal reconnect into a minute-long
    /// outage.
    allocated: HashMap<IpAddr, Allocation>,
    /// Addresses pinned to a configured client identity, keyed by its public
    /// key.
    ///
    /// Held for the process lifetime, not just while the client is connected:
    /// otherwise a dynamic client could take the address an offline client is
    /// expected to reappear on, and that client would then be unable to attach.
    reserved: HashMap<IpAddr, Vec<u8>>,
    /// Next candidate for v4 allocation (host part counter).
    v4_next: u32,
    /// Next candidate for v6 allocation (host part counter).
    v6_next: u128,
}

/// One live address lease.
struct Allocation {
    claims: usize,
    /// Public key that owns a pinned lease. Dynamic leases have no owner.
    owner: Option<Vec<u8>>,
}

impl Allocation {
    fn dynamic() -> Self {
        Self {
            claims: 1,
            owner: None,
        }
    }

    fn pinned(owner: &[u8]) -> Self {
        Self {
            claims: 1,
            owner: Some(owner.to_vec()),
        }
    }
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
            allocated: HashMap::new(),
            reserved: HashMap::new(),
            // network+1 belongs to the server's TUN device, so clients start at
            // network+2 in both families.
            v4_next: 2,
            v6_next: 2,
        })
    }

    /// Withhold `addr` from dynamic allocation for the process lifetime.
    ///
    /// Called once per pinned client address at startup. The address must lie
    /// inside the matching pool range, because the TUN device is configured
    /// with that range as its on-link prefix and the server would have no route
    /// back to anything outside it.
    pub fn reserve_static(&mut self, addr: IpAddr, owner: &[u8]) -> Result<(), PoolError> {
        if !self.in_range(&addr) {
            return Err(PoolError::OutOfRange(addr));
        }
        // The gateway address is the pool network plus one, and it belongs to
        // the server's own TUN device.
        if self.is_gateway(&addr) {
            return Err(PoolError::AlreadyAllocated(addr));
        }
        if self.reserved.contains_key(&addr) {
            return Err(PoolError::AlreadyAllocated(addr));
        }
        self.reserved.insert(addr, owner.to_vec());
        Ok(())
    }

    /// Replace the whole set of pinned addresses.
    ///
    /// Every address is validated before anything changes, so a roster that
    /// fails validation leaves the previous reservations intact rather than
    /// half-applied. Live leases live in a separate map and are untouched: an
    /// address dropped here stays held until the tunnel using it goes away.
    pub fn set_static_reservations<K: AsRef<[u8]>>(
        &mut self,
        reservations: impl IntoIterator<Item = (IpAddr, K)>,
    ) -> Result<(), PoolError> {
        let mut next = HashMap::new();
        for (addr, owner) in reservations {
            if !self.in_range(&addr) {
                return Err(PoolError::OutOfRange(addr));
            }
            if self.is_gateway(&addr) {
                return Err(PoolError::AlreadyAllocated(addr));
            }
            if next.insert(addr, owner.as_ref().to_vec()).is_some() {
                return Err(PoolError::AlreadyAllocated(addr));
            }
        }
        self.reserved = next;
        Ok(())
    }

    /// Take a specific address for a tunnel.
    ///
    /// Used for clients pinned to a fixed address. Reserved addresses are
    /// reference counted: a reconnect can overlap its stale predecessor until
    /// the old QUIC idle timeout fires. Duplicate static addresses across
    /// different identities are rejected even while a roster reload is moving
    /// an address from one key to another.
    pub fn claim(&mut self, addr: IpAddr, owner: &[u8]) -> Result<(), PoolError> {
        if !self.in_range(&addr) {
            return Err(PoolError::OutOfRange(addr));
        }
        if self.is_gateway(&addr) {
            return Err(PoolError::AlreadyAllocated(addr));
        }
        if !self
            .reserved
            .get(&addr)
            .is_some_and(|reserved_owner| reserved_owner == owner)
        {
            return Err(PoolError::NotReserved(addr));
        }
        if let Some(allocation) = self.allocated.get_mut(&addr) {
            if allocation.owner.as_deref() != Some(owner) {
                return Err(PoolError::AlreadyAllocated(addr));
            }
            allocation.claims += 1;
            return Ok(());
        }
        self.allocated.insert(addr, Allocation::pinned(owner));
        Ok(())
    }

    /// Whether `addr` falls inside the pool range for its family.
    fn in_range(&self, addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => self.v4_net.is_some_and(|net| net.contains(v4)),
            IpAddr::V6(v6) => self.v6_net.is_some_and(|net| net.contains(v6)),
        }
    }

    /// Whether `addr` is the network-plus-one address assigned to the TUN device.
    fn is_gateway(&self, addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => self
                .v4_net
                .is_some_and(|net| u32::from(net.network()) | 1 == u32::from(*v4)),
            IpAddr::V6(v6) => self
                .v6_net
                .is_some_and(|net| u128::from(net.network()) | 1 == u128::from(*v6)),
        }
    }

    /// Allocate the next available IPv4 address.
    pub fn allocate_v4(&mut self) -> Result<Ipv4Addr, PoolError> {
        let net = self.v4_net.ok_or(PoolError::Exhausted)?;
        let host_mask = !u32::from(net.netmask());
        let net_addr = u32::from(net.network());

        // Offset 0 is the network, 1 is the TUN gateway, and host_mask is the
        // broadcast address. A /30 therefore has one client address: .2.
        let max_hosts = host_mask;
        if max_hosts <= 2 {
            return Err(PoolError::Exhausted);
        }

        // Scan offsets 2 through host_mask-1 at most once.
        let mut checked = 0u64;
        let total_usable = (max_hosts - 2) as u64;

        while checked < total_usable {
            // Wrap around if we've gone past the usable range.
            if self.v4_next >= max_hosts {
                self.v4_next = 2;
            }

            let addr = Ipv4Addr::from(net_addr | self.v4_next);
            self.v4_next += 1;
            checked += 1;

            let ip = IpAddr::V4(addr);
            if !self.allocated.contains_key(&ip) && !self.reserved.contains_key(&ip) {
                self.allocated.insert(ip, Allocation::dynamic());
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

        // Offset 0 is the subnet-router anycast address and 1 belongs to the
        // TUN gateway. IPv6 has no broadcast, so offsets 2..=host_mask remain.
        if host_mask <= 1 {
            return Err(PoolError::Exhausted);
        }

        let total_usable = host_mask - 1;
        // Cap iteration to avoid spinning on enormous /64 pools.
        let max_iter = total_usable.min(u64::MAX as u128) as u64;
        let mut checked = 0u64;

        while checked < max_iter {
            if self.v6_next > host_mask {
                self.v6_next = 2;
            }

            let addr = Ipv6Addr::from(net_bits | self.v6_next);
            self.v6_next = if self.v6_next == host_mask {
                2
            } else {
                self.v6_next + 1
            };
            checked += 1;

            let ip = IpAddr::V6(addr);
            if !self.allocated.contains_key(&ip) && !self.reserved.contains_key(&ip) {
                self.allocated.insert(ip, Allocation::dynamic());
                return Ok(addr);
            }
        }

        Err(PoolError::Exhausted)
    }

    /// Release an address back to the pool.
    pub fn release(&mut self, addr: IpAddr) -> bool {
        let Some(allocation) = self.allocated.get_mut(&addr) else {
            return false;
        };
        if allocation.claims > 1 {
            allocation.claims -= 1;
        } else {
            self.allocated.remove(&addr);
        }
        true
    }

    /// Release multiple addresses.
    pub fn release_all(&mut self, addrs: &[IpAddr]) {
        for addr in addrs {
            self.release(*addr);
        }
    }

    /// Number of currently allocated addresses.
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// Check if an address is currently allocated.
    pub fn is_allocated(&self, addr: &IpAddr) -> bool {
        self.allocated.contains_key(addr)
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

    // ── Pinned addresses ──────────────────────────────────────────────

    #[test]
    fn reserved_addresses_are_skipped_by_dynamic_allocation() {
        let mut pool = AddressPool::new("10.89.0.0/24", "fd00:abcd::/64").unwrap();
        let pinned_v4 = "10.89.0.2".parse().unwrap();
        let pinned_v6 = "fd00:abcd::2".parse().unwrap();
        pool.reserve_static(pinned_v4, b"client").unwrap();
        pool.reserve_static(pinned_v6, b"client").unwrap();

        // Reserving must not consume the address, only withhold it.
        assert_eq!(pool.allocated_count(), 0);

        // The gateway at .1 and the pinned .2 are both skipped.
        assert_eq!(pool.allocate_v4().unwrap(), Ipv4Addr::new(10, 89, 0, 3));
        assert_eq!(pool.allocate_v4().unwrap(), Ipv4Addr::new(10, 89, 0, 4));
        assert_eq!(pool.allocate_v6().unwrap().to_string(), "fd00:abcd::3");
        assert_eq!(pool.allocate_v6().unwrap().to_string(), "fd00:abcd::4");
    }

    #[test]
    fn reserved_address_stays_claimable_by_its_owner() {
        let mut pool = AddressPool::new("10.89.0.0/24", "").unwrap();
        let pinned = "10.89.0.2".parse().unwrap();
        pool.reserve_static(pinned, b"owner").unwrap();

        pool.claim(pinned, b"owner").unwrap();
        assert!(pool.is_allocated(&pinned));

        // A reconnect with the same registered key can overlap the stale
        // connection until its idle timeout fires.
        pool.claim(pinned, b"owner").unwrap();

        // Releasing one of the overlapping tunnels keeps the other lease live.
        assert!(pool.release(pinned));
        assert!(pool.is_allocated(&pinned));
        assert!(pool.release(pinned));
        assert!(!pool.is_allocated(&pinned));

        // Once both tunnels are gone the same pinned address is claimable again.
        pool.claim(pinned, b"owner").unwrap();
    }

    #[test]
    fn reservation_owner_changes_are_isolated_during_reload() {
        let mut pool = AddressPool::new("10.89.0.0/24", "").unwrap();
        let pinned = "10.89.0.2".parse().unwrap();
        pool.reserve_static(pinned, b"old-key").unwrap();
        assert_eq!(
            pool.reserve_static(pinned, b"new-key"),
            Err(PoolError::AlreadyAllocated(pinned))
        );
        assert_eq!(
            pool.claim(pinned, b"new-key"),
            Err(PoolError::NotReserved(pinned))
        );
        pool.claim(pinned, b"old-key").unwrap();

        // A roster reload moves the address to another public key. The new
        // identity cannot overlap the old identity's still-live lease.
        pool.set_static_reservations([(pinned, b"new-key".as_slice())])
            .unwrap();
        assert_eq!(
            pool.claim(pinned, b"new-key"),
            Err(PoolError::AlreadyAllocated(pinned))
        );
        // Nor may the removed identity open another tunnel in the narrow gap
        // between updating reservations and replacing the shared roster.
        assert_eq!(
            pool.claim(pinned, b"old-key"),
            Err(PoolError::NotReserved(pinned))
        );

        pool.release(pinned);
        pool.claim(pinned, b"new-key").unwrap();
    }

    #[test]
    fn reserve_static_rejects_addresses_outside_the_pool() {
        let mut pool = AddressPool::new("10.89.0.0/24", "fd00:abcd::/64").unwrap();
        let outside = "10.90.0.2".parse().unwrap();
        assert_eq!(
            pool.reserve_static(outside, b"owner"),
            Err(PoolError::OutOfRange(outside))
        );

        // Right family, wrong pool.
        let outside_v6 = "fd00:ffff::2".parse().unwrap();
        assert_eq!(
            pool.reserve_static(outside_v6, b"owner"),
            Err(PoolError::OutOfRange(outside_v6))
        );

        // A family the pool does not cover at all.
        let mut v4_only = AddressPool::new("10.89.0.0/24", "").unwrap();
        let v6 = "fd00:abcd::2".parse().unwrap();
        assert_eq!(
            v4_only.reserve_static(v6, b"owner"),
            Err(PoolError::OutOfRange(v6))
        );
    }

    #[test]
    fn reserve_static_rejects_the_tun_gateway() {
        // network+1 is what the server's own TUN device answers on, so handing
        // it to a client would black-hole that client's return traffic.
        let mut pool = AddressPool::new("10.89.0.0/24", "fd00:abcd::/64").unwrap();
        let v4_gw = "10.89.0.1".parse().unwrap();
        let v6_gw = "fd00:abcd::1".parse().unwrap();
        assert_eq!(
            pool.reserve_static(v4_gw, b"owner"),
            Err(PoolError::AlreadyAllocated(v4_gw))
        );
        assert_eq!(
            pool.reserve_static(v6_gw, b"owner"),
            Err(PoolError::AlreadyAllocated(v6_gw))
        );
    }

    #[test]
    fn claim_rejects_addresses_outside_the_pool() {
        let mut pool = AddressPool::new("10.89.0.0/24", "").unwrap();
        let outside = "192.168.1.5".parse().unwrap();
        assert_eq!(
            pool.claim(outside, b"owner"),
            Err(PoolError::OutOfRange(outside))
        );
    }

    #[test]
    fn a_dynamic_address_is_not_claimable_as_a_static_lease() {
        let mut pool = AddressPool::new("10.89.0.0/24", "").unwrap();
        let first = IpAddr::V4(pool.allocate_v4().unwrap());
        assert_eq!(
            pool.claim(first, b"owner"),
            Err(PoolError::NotReserved(first))
        );
    }

    // ── IPv4 allocation ───────────────────────────────────────────────

    #[test]
    fn allocate_v4_sequential() {
        let mut pool = AddressPool::new("10.89.0.0/24", "").unwrap();
        let a1 = pool.allocate_v4().unwrap();
        let a2 = pool.allocate_v4().unwrap();
        let a3 = pool.allocate_v4().unwrap();

        assert_eq!(a1, Ipv4Addr::new(10, 89, 0, 2));
        assert_eq!(a2, Ipv4Addr::new(10, 89, 0, 3));
        assert_eq!(a3, Ipv4Addr::new(10, 89, 0, 4));
        assert_eq!(pool.allocated_count(), 3);
    }

    #[test]
    fn allocate_v4_exhaustion() {
        // /30 gives 4 addresses: network, gateway, one client, broadcast.
        let mut pool = AddressPool::new("10.0.0.0/30", "").unwrap();
        assert_eq!(pool.allocate_v4().unwrap(), Ipv4Addr::new(10, 0, 0, 2));
        assert!(matches!(pool.allocate_v4(), Err(PoolError::Exhausted)));
    }

    #[test]
    fn allocate_v4_release_reuse() {
        let mut pool = AddressPool::new("10.0.0.0/30", "").unwrap();
        let a1 = pool.allocate_v4().unwrap();
        // Pool is full
        assert!(pool.allocate_v4().is_err());

        // Release a1
        assert!(pool.release(IpAddr::V4(a1)));
        assert_eq!(pool.allocated_count(), 0);

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

        assert_eq!(a1, "fd00:abcd::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(a2, "fd00:abcd::3".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn allocate_v6_exhaustion() {
        // /126 gives network, gateway, and two client addresses.
        let mut pool = AddressPool::new("", "fd00::/126").unwrap();
        assert_eq!(
            pool.allocate_v6().unwrap(),
            "fd00::2".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            pool.allocate_v6().unwrap(),
            "fd00::3".parse::<Ipv6Addr>().unwrap()
        );
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
        for i in 2..=101u32 {
            let addr = pool.allocate_v4().unwrap();
            let expected = Ipv4Addr::from(u32::from(Ipv4Addr::new(10, 89, 0, 0)) | i);
            assert_eq!(addr, expected);
        }
        assert_eq!(pool.allocated_count(), 100);
    }
}
