// Target policy filter — allow/deny lists based on CIDR ranges.

use std::net::IpAddr;

use ipnet::IpNet;

/// Policy checker for target addresses.
#[derive(Clone)]
pub struct TargetPolicy {
    allow: Vec<IpNet>,
    deny: Vec<IpNet>,
}

impl TargetPolicy {
    /// Create a policy from string CIDR lists.
    ///
    /// Invalid CIDRs are logged and skipped.
    pub fn new(allow: &[String], deny: &[String]) -> Self {
        Self {
            allow: parse_cidrs(allow),
            deny: parse_cidrs(deny),
        }
    }

    /// Check whether `addr` is allowed by the policy.
    ///
    /// Rules:
    /// 1. If `addr` matches any deny entry → denied.
    /// 2. If `addr` matches any allow entry → allowed.
    /// 3. Otherwise → denied (default-deny).
    pub fn is_allowed(&self, addr: IpAddr) -> bool {
        // Deny takes precedence
        for net in &self.deny {
            if net.contains(&addr) {
                return false;
            }
        }

        // Must match at least one allow entry
        for net in &self.allow {
            if net.contains(&addr) {
                return true;
            }
        }

        false
    }

    /// Check a list of resolved addresses — allowed if at least one is allowed.
    pub fn any_allowed(&self, addrs: &[IpAddr]) -> bool {
        addrs.iter().any(|a| self.is_allowed(*a))
    }

    /// Check a list of resolved addresses — all must be allowed.
    pub fn all_allowed(&self, addrs: &[IpAddr]) -> bool {
        addrs.iter().all(|a| self.is_allowed(*a))
    }
}

fn parse_cidrs(strings: &[String]) -> Vec<IpNet> {
    strings
        .iter()
        .filter_map(|s| {
            s.parse::<IpNet>().ok().or_else(|| {
                tracing::warn!(cidr = %s, "invalid CIDR in policy, skipping");
                None
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn policy(allow: &[&str], deny: &[&str]) -> TargetPolicy {
        TargetPolicy::new(
            &allow.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &deny.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
    }

    // ── Basic allow/deny ──────────────────────────────────────────────

    #[test]
    fn allow_all_deny_none() {
        let p = policy(&["0.0.0.0/0"], &[]);
        assert!(p.is_allowed(Ipv4Addr::new(8, 8, 8, 8).into()));
        assert!(p.is_allowed(Ipv4Addr::new(10, 0, 0, 1).into()));
        assert!(p.is_allowed(Ipv4Addr::LOCALHOST.into()));
    }

    #[test]
    fn deny_takes_precedence() {
        let p = policy(&["0.0.0.0/0"], &["127.0.0.0/8"]);
        assert!(p.is_allowed(Ipv4Addr::new(8, 8, 8, 8).into()));
        assert!(!p.is_allowed(Ipv4Addr::LOCALHOST.into()));
        assert!(!p.is_allowed(Ipv4Addr::new(127, 0, 0, 2).into()));
    }

    #[test]
    fn deny_private_ranges() {
        let p = policy(
            &["0.0.0.0/0"],
            &["127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"],
        );
        assert!(p.is_allowed(Ipv4Addr::new(8, 8, 8, 8).into()));
        assert!(!p.is_allowed(Ipv4Addr::new(10, 1, 2, 3).into()));
        assert!(!p.is_allowed(Ipv4Addr::new(192, 168, 1, 1).into()));
        assert!(!p.is_allowed(Ipv4Addr::new(172, 16, 0, 1).into()));
        assert!(p.is_allowed(Ipv4Addr::new(172, 32, 0, 1).into()));
    }

    #[test]
    fn default_deny_when_no_allow() {
        let p = policy(&[], &[]);
        assert!(!p.is_allowed(Ipv4Addr::new(8, 8, 8, 8).into()));
    }

    #[test]
    fn specific_allow_range() {
        let p = policy(&["203.0.113.0/24"], &[]);
        assert!(p.is_allowed(Ipv4Addr::new(203, 0, 113, 1).into()));
        assert!(p.is_allowed(Ipv4Addr::new(203, 0, 113, 254).into()));
        assert!(!p.is_allowed(Ipv4Addr::new(203, 0, 114, 1).into()));
        assert!(!p.is_allowed(Ipv4Addr::new(8, 8, 8, 8).into()));
    }

    // ── IPv6 ──────────────────────────────────────────────────────────

    #[test]
    fn ipv6_allow_all() {
        let p = policy(&["0.0.0.0/0", "::/0"], &[]);
        assert!(p.is_allowed(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
        ))));
    }

    #[test]
    fn ipv6_deny_loopback() {
        let p = policy(&["::/0"], &["::1/128"]);
        assert!(!p.is_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(p.is_allowed(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
        ))));
    }

    #[test]
    fn ipv4_not_matched_by_ipv6_allow() {
        // IPv4 address should not be allowed by ::/0
        let p = policy(&["::/0"], &[]);
        assert!(!p.is_allowed(Ipv4Addr::new(8, 8, 8, 8).into()));
    }

    // ── any_allowed / all_allowed ─────────────────────────────────────

    #[test]
    fn any_allowed_mixed() {
        let p = policy(&["0.0.0.0/0"], &["10.0.0.0/8"]);
        let addrs = vec![
            IpAddr::from(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::from(Ipv4Addr::new(8, 8, 8, 8)),
        ];
        assert!(p.any_allowed(&addrs));
        assert!(!p.all_allowed(&addrs));
    }

    #[test]
    fn all_allowed_all_pass() {
        let p = policy(&["0.0.0.0/0"], &[]);
        let addrs = vec![
            IpAddr::from(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::from(Ipv4Addr::new(1, 1, 1, 1)),
        ];
        assert!(p.all_allowed(&addrs));
    }

    #[test]
    fn any_allowed_empty_list() {
        let p = policy(&["0.0.0.0/0"], &[]);
        assert!(!p.any_allowed(&[]));
    }

    // ── Invalid CIDR handling ─────────────────────────────────────────

    #[test]
    fn invalid_cidr_skipped() {
        let p = policy(&["not-a-cidr", "0.0.0.0/0"], &["also-bad"]);
        // The valid "0.0.0.0/0" should still work
        assert!(p.is_allowed(Ipv4Addr::new(8, 8, 8, 8).into()));
    }
}
