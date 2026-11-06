// Target policy filter — allow/deny lists based on CIDR ranges.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Context;
use ipnet::IpNet;

use crate::config::TargetRestrictionSection;

#[derive(Debug, Clone, PartialEq)]
pub struct TargetRestrictions {
    allow: Option<Arc<[IpNet]>>,
    deny: Arc<[IpNet]>,
    ports: Option<Arc<[u16]>>,
}

impl TargetRestrictions {
    pub(crate) fn from_section(section: &TargetRestrictionSection) -> anyhow::Result<Self> {
        fn parse_rules(rules: &[String]) -> anyhow::Result<Arc<[IpNet]>> {
            rules
                .iter()
                .map(|rule| {
                    rule.parse::<IpNet>()
                        .map(canonical_net)
                        .with_context(|| format!("invalid target CIDR {rule:?}"))
                })
                .collect()
        }

        let ports = section
            .allow_ports
            .as_ref()
            .map(|ports| {
                anyhow::ensure!(!ports.contains(&0), "allow_ports cannot include port zero");
                let mut ports = ports.clone();
                ports.sort_unstable();
                ports.dedup();
                Ok::<_, anyhow::Error>(Arc::from(ports))
            })
            .transpose()?;
        Ok(Self {
            allow: section
                .allow_targets
                .as_deref()
                .map(parse_rules)
                .transpose()?,
            deny: parse_rules(&section.deny_targets)?,
            ports,
        })
    }
}

/// Policy checker for target addresses.
#[derive(Clone)]
pub struct TargetPolicy {
    allow: Vec<IpNet>,
    deny: Vec<IpNet>,
    restrictions: Option<TargetRestrictions>,
}

impl TargetPolicy {
    /// Create a policy from string CIDR lists.
    ///
    /// Reject the entire policy if any entry is not a valid CIDR. In
    /// particular, silently dropping a deny rule could permit its targets.
    pub fn new(allow: &[String], deny: &[String]) -> anyhow::Result<Self> {
        Ok(Self {
            allow: parse_cidrs(allow, "allow_targets")?,
            deny: parse_cidrs(deny, "deny_targets")?,
            restrictions: None,
        })
    }

    pub(crate) fn with_restrictions(mut self, restrictions: Option<TargetRestrictions>) -> Self {
        self.restrictions = restrictions;
        self
    }

    pub(crate) fn allows_port(&self, port: u16) -> bool {
        self.restrictions
            .as_ref()
            .and_then(|rules| rules.ports.as_ref())
            .is_none_or(|ports| ports.binary_search(&port).is_ok())
    }

    /// Check whether `addr` is allowed by the policy.
    ///
    /// Rules:
    /// 1. If `addr` matches any deny entry → denied.
    /// 2. If `addr` matches any allow entry → allowed.
    /// 3. Otherwise → denied (default-deny).
    pub fn is_allowed(&self, addr: IpAddr) -> bool {
        // The kernel reaches the same IPv4 target for a mapped IPv6 address.
        // Judge both spellings against the IPv4 rules, before an IPv6 wildcard
        // can bypass a deny such as 127.0.0.0/8 or 169.254.0.0/16.
        let addr = addr.to_canonical();
        if let Some(rules) = &self.restrictions
            && (rules.deny.iter().any(|net| net.contains(&addr))
                || rules
                    .allow
                    .as_ref()
                    .is_some_and(|allow| !allow.iter().any(|net| net.contains(&addr))))
        {
            return false;
        }
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

fn parse_cidrs(strings: &[String], field: &str) -> anyhow::Result<Vec<IpNet>> {
    strings
        .iter()
        .enumerate()
        .map(|(index, rule)| {
            rule.parse::<IpNet>()
                .map(canonical_net)
                .with_context(|| format!("{field}[{index}]: invalid target CIDR {rule:?}"))
        })
        .collect()
}

fn canonical_net(net: IpNet) -> IpNet {
    // Preserve explicitly configured mapped CIDRs as aliases of their
    // IPv4 equivalents. Only prefixes wholly inside ::ffff:0:0/96
    // qualify; a broader IPv6 network stays an IPv6 network.
    if let IpNet::V6(v6) = net
        && v6.prefix_len() >= 96
        && let Some(v4) = v6.network().to_ipv4_mapped()
    {
        return IpNet::new(IpAddr::V4(v4), v6.prefix_len() - 96)
            .expect("a mapped IPv6 prefix translates to a valid IPv4 prefix");
    }
    net
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn listener_restrictions_preserve_global_denies_and_match_ports() {
        let restrictions = TargetRestrictions::from_section(&TargetRestrictionSection {
            allow_targets: Some(vec!["192.0.2.0/24".into()]),
            deny_targets: vec!["192.0.2.20/32".into()],
            allow_ports: Some(vec![443]),
        })
        .unwrap();
        let target =
            policy(&["0.0.0.0/0"], &["192.0.2.30/32"]).with_restrictions(Some(restrictions));
        assert!(target.allows_port(443));
        assert!(!target.allows_port(80));
        assert!(target.is_allowed("::ffff:192.0.2.10".parse().unwrap()));
        for addr in ["192.0.2.20", "192.0.2.30", "198.51.100.1"] {
            assert!(!target.is_allowed(addr.parse().unwrap()), "{addr}");
        }
    }

    #[test]
    fn malformed_listener_restrictions_are_rejected() {
        assert!(
            TargetRestrictions::from_section(&TargetRestrictionSection {
                deny_targets: vec!["192.0.2.0/99".into()],
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            TargetRestrictions::from_section(&TargetRestrictionSection {
                allow_ports: Some(vec![0]),
                ..Default::default()
            })
            .is_err()
        );
    }

    fn policy(allow: &[&str], deny: &[&str]) -> TargetPolicy {
        TargetPolicy::new(
            &allow.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &deny.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap()
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
            &[
                "127.0.0.0/8",
                "10.0.0.0/8",
                "192.168.0.0/16",
                "172.16.0.0/12",
            ],
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
        assert!(p.is_allowed(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,))));
    }

    #[test]
    fn ipv6_deny_loopback() {
        let p = policy(&["::/0"], &["::1/128"]);
        assert!(!p.is_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(p.is_allowed(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,))));
    }

    #[test]
    fn ipv4_not_matched_by_ipv6_allow() {
        // IPv4 address should not be allowed by ::/0
        let p = policy(&["::/0"], &[]);
        assert!(!p.is_allowed(Ipv4Addr::new(8, 8, 8, 8).into()));
    }

    #[test]
    fn mapped_ipv6_cannot_bypass_ipv4_target_denials() {
        let p = policy(
            &["0.0.0.0/0", "::/0"],
            &[
                "127.0.0.0/8",
                "10.0.0.0/8",
                "169.254.0.0/16",
                "172.16.0.0/12",
                "192.168.0.0/16",
            ],
        );
        for addr in [
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(10, 1, 2, 3),
            Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
        ] {
            assert!(!p.is_allowed(addr.into()), "{addr}");
            assert!(!p.is_allowed(addr.to_ipv6_mapped().into()), "mapped {addr}");
        }
    }

    #[test]
    fn mapped_ipv6_uses_ipv4_allow_rules() {
        let mapped = "::ffff:192.0.2.10".parse().unwrap();
        assert!(policy(&["192.0.2.0/24"], &[]).is_allowed(mapped));
        assert!(!policy(&["::/0"], &[]).is_allowed(mapped));
        assert!(!policy(&[], &[]).is_allowed(mapped));
    }

    #[test]
    fn explicitly_mapped_cidrs_apply_to_both_target_spellings() {
        for allow in ["::ffff:192.0.2.10/120", "192.0.2.0/24"] {
            for deny in ["::ffff:192.0.2.10/128", "192.0.2.10/32"] {
                let p = policy(&[allow], &[deny]);
                for spelling in ["192.0.2.10", "::ffff:192.0.2.10"] {
                    assert!(!p.is_allowed(spelling.parse().unwrap()), "{allow}, {deny}");
                }
                for spelling in ["192.0.2.11", "::ffff:192.0.2.11"] {
                    assert!(p.is_allowed(spelling.parse().unwrap()), "{allow}, {deny}");
                }
            }
        }
        let p = policy(&["::ffff:0:0/96"], &[]);
        assert!(p.is_allowed("192.0.2.10".parse().unwrap()));
        assert!(!p.is_allowed("2001:db8::1".parse().unwrap()));
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
    fn invalid_cidr_rejects_the_entire_policy() {
        for invalid in [
            "not-a-cidr",
            "192.0.2.0/33",
            "2001:db8::/129",
            "192.0.2.1",
            "",
        ] {
            for field in ["allow_targets", "deny_targets"] {
                let valid = vec!["0.0.0.0/0".into(), "::/0".into()];
                let mixed = vec!["192.0.2.0/24".into(), invalid.into()];
                let result = if field == "allow_targets" {
                    TargetPolicy::new(&mixed, &valid)
                } else {
                    TargetPolicy::new(&valid, &mixed)
                };
                let error = result.err().expect("invalid policy must be rejected");
                let message = error.to_string();
                assert!(message.contains(&format!("{field}[1]")), "{message}");
                assert!(message.contains(&format!("{invalid:?}")), "{message}");
            }
        }
    }
}
