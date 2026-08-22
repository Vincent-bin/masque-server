//! Read-only checks for the Linux host networking CONNECT-IP depends on.
//!
//! The server owns the TUN file descriptor and moves packets between it and
//! MASQUE tunnels. Routing those packets beyond the host remains an operator
//! decision: deployments may use iptables, nftables, UFW, a routed prefix, a
//! network namespace, or something outside the host entirely. The checks here
//! therefore distinguish hard prerequisites from advisory evidence and never
//! mutate the system.

use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;

use crate::config::IpProxySection;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticLevel {
    Ok,
    Info,
    Warning,
    Error,
}

impl DiagnosticLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticCheck {
    pub level: DiagnosticLevel,
    pub name: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostDiagnostics {
    checks: Vec<DiagnosticCheck>,
}

impl HostDiagnostics {
    pub fn checks(&self) -> &[DiagnosticCheck] {
        &self.checks
    }

    pub fn error_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| check.level == DiagnosticLevel::Error)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| check.level == DiagnosticLevel::Warning)
            .count()
    }

    pub fn has_errors(&self) -> bool {
        self.error_count() != 0
    }

    fn push(&mut self, level: DiagnosticLevel, name: &'static str, detail: impl Into<String>) {
        self.checks.push(DiagnosticCheck {
            level,
            name,
            detail: detail.into(),
        });
    }
}

trait HostProbe {
    fn is_linux(&self) -> bool;
    fn exists(&self, path: &Path) -> bool;
    fn read_to_string(&self, path: &Path) -> io::Result<String>;
    fn command_output(&self, program: &str, args: &[&str]) -> io::Result<String>;
}

struct RealHostProbe;

impl HostProbe for RealHostProbe {
    fn is_linux(&self) -> bool {
        cfg!(target_os = "linux")
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        fs::read_to_string(path)
    }

    fn command_output(&self, program: &str, args: &[&str]) -> io::Result<String> {
        let output = Command::new(program).args(args).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::other(format!(
                "{program} exited with {}{}",
                output.status,
                if stderr.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", stderr.trim())
                }
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

/// Inspect the current host without opening a TUN device or changing any
/// forwarding, routing, firewall, or NAT state.
pub fn diagnose_connect_ip(config: &IpProxySection) -> HostDiagnostics {
    diagnose_with(config, &RealHostProbe)
}

/// Check hard prerequisites without executing external programs.
///
/// This is safe to call from the long-running server process. Full route and
/// firewall inspection remains exclusive to [`diagnose_connect_ip`], which an
/// administrator invokes explicitly through `doctor`.
pub fn diagnose_connect_ip_startup(config: &IpProxySection) -> HostDiagnostics {
    diagnose_startup_with(config, &RealHostProbe)
}

fn diagnose_prerequisites_with(config: &IpProxySection, probe: &impl HostProbe) -> HostDiagnostics {
    let mut report = HostDiagnostics::default();
    if !config.enabled {
        report.push(
            DiagnosticLevel::Ok,
            "CONNECT-IP",
            "ip_proxy.enabled = false; host forwarding is not required",
        );
        return report;
    }

    if !probe.is_linux() {
        report.push(
            DiagnosticLevel::Error,
            "platform",
            "CONNECT-IP data forwarding requires Linux TUN support",
        );
        return report;
    }
    report.push(DiagnosticLevel::Ok, "platform", "Linux host detected");

    if probe.exists(Path::new("/dev/net/tun")) {
        report.push(DiagnosticLevel::Ok, "TUN device", "/dev/net/tun is present");
    } else {
        report.push(
            DiagnosticLevel::Error,
            "TUN device",
            "/dev/net/tun is missing; CONNECT-IP cannot create its interface",
        );
    }

    check_forwarding_for_report(
        &mut report,
        probe,
        &config.ipv4_pool,
        Path::new("/proc/sys/net/ipv4/ip_forward"),
        "IPv4 forwarding",
        "net.ipv4.ip_forward",
    );
    check_forwarding_for_report(
        &mut report,
        probe,
        &config.ipv6_pool,
        Path::new("/proc/sys/net/ipv6/conf/all/forwarding"),
        "IPv6 forwarding",
        "net.ipv6.conf.all.forwarding",
    );

    report
}

fn diagnose_startup_with(config: &IpProxySection, probe: &impl HostProbe) -> HostDiagnostics {
    let mut report = diagnose_prerequisites_with(config, probe);
    if config.enabled && probe.is_linux() {
        report.push(
            DiagnosticLevel::Warning,
            "host egress",
            "routing, firewall forwarding, and optional NAT are operator-managed and not verified during service startup; run `masque-server doctor`",
        );
    }
    report
}

fn diagnose_with(config: &IpProxySection, probe: &impl HostProbe) -> HostDiagnostics {
    let mut report = diagnose_prerequisites_with(config, probe);
    if !config.enabled || !probe.is_linux() {
        return report;
    }

    let interface_path = Path::new("/sys/class/net").join(&config.tun_name);
    let interface_present = probe.exists(&interface_path);
    if interface_present {
        report.push(
            DiagnosticLevel::Ok,
            "TUN interface",
            format!("{} is present", config.tun_name),
        );
    } else {
        report.push(
            DiagnosticLevel::Warning,
            "TUN interface",
            format!(
                "{} is not present; this is expected before the service starts, otherwise inspect its startup log",
                config.tun_name
            ),
        );
    }

    if interface_present {
        check_pool_route(
            &mut report,
            probe,
            "IPv4 pool route",
            "-4",
            &config.ipv4_pool,
            &config.tun_name,
        );
        check_pool_route(
            &mut report,
            probe,
            "IPv6 pool route",
            "-6",
            &config.ipv6_pool,
            &config.tun_name,
        );
    }

    let rules = RuleSnapshot::collect(probe);
    check_firewall_and_nat(
        &mut report,
        "IPv4",
        &config.ipv4_pool,
        &config.tun_name,
        pool_likely_needs_nat(&config.ipv4_pool),
        FamilyRules {
            filter: rules.v4_filter.as_deref(),
            nat: rules.v4_nat.as_deref(),
            nft: rules.nft.as_deref(),
        },
    );
    check_firewall_and_nat(
        &mut report,
        "IPv6",
        &config.ipv6_pool,
        &config.tun_name,
        pool_likely_needs_nat(&config.ipv6_pool),
        FamilyRules {
            filter: rules.v6_filter.as_deref(),
            nat: rules.v6_nat.as_deref(),
            nft: rules.nft.as_deref(),
        },
    );

    report.push(
        DiagnosticLevel::Info,
        "ownership",
        "diagnostics are read-only; masque-server never changes host routing, firewall, or NAT",
    );
    report
}

fn check_forwarding_for_report(
    report: &mut HostDiagnostics,
    probe: &impl HostProbe,
    pool: &str,
    path: &Path,
    name: &'static str,
    sysctl: &str,
) {
    if pool.is_empty() {
        report.push(
            DiagnosticLevel::Info,
            name,
            "no address pool is configured for this family",
        );
        return;
    }
    match probe.read_to_string(path) {
        Ok(value) if value.trim() == "1" => {
            report.push(DiagnosticLevel::Ok, name, format!("{sysctl}=1"))
        }
        Ok(value) => report.push(
            DiagnosticLevel::Error,
            name,
            format!(
                "{sysctl}={} but CONNECT-IP needs forwarding for pool {pool}",
                value.trim()
            ),
        ),
        Err(error) => report.push(
            DiagnosticLevel::Error,
            name,
            format!("cannot read {}: {error}", path.display()),
        ),
    }
}

fn check_pool_route(
    report: &mut HostDiagnostics,
    probe: &impl HostProbe,
    name: &'static str,
    family: &str,
    pool: &str,
    tun_name: &str,
) {
    if pool.is_empty() {
        return;
    }
    match probe.command_output("ip", &[family, "route", "show", pool]) {
        Ok(output)
            if output
                .lines()
                .any(|line| line.split_whitespace().any(|v| v == tun_name)) =>
        {
            report.push(
                DiagnosticLevel::Ok,
                name,
                format!("{pool} is routed through {tun_name}"),
            );
        }
        Ok(_) => report.push(
            DiagnosticLevel::Warning,
            name,
            format!("no route for {pool} through {tun_name} was found"),
        ),
        Err(error) => report.push(
            DiagnosticLevel::Warning,
            name,
            format!("could not inspect the route for {pool}: {error}"),
        ),
    }
}

fn check_firewall_and_nat(
    report: &mut HostDiagnostics,
    family: &'static str,
    pool: &str,
    tun_name: &str,
    likely_needs_nat: bool,
    rules: FamilyRules<'_>,
) {
    if pool.is_empty() {
        return;
    }

    let filter = combined_rules(rules.filter, rules.nft);
    let forward_name = if family == "IPv4" {
        "IPv4 firewall forwarding"
    } else {
        "IPv6 firewall forwarding"
    };
    match filter {
        Some(ref text) if has_forward_accept_evidence(text, pool, tun_name) => report.push(
            DiagnosticLevel::Ok,
            forward_name,
            format!("found ACCEPT/policy evidence for {pool} and {tun_name}"),
        ),
        Some(_) => report.push(
            DiagnosticLevel::Warning,
            forward_name,
            format!(
                "no matching ACCEPT rule was found for {pool} on {tun_name}; another firewall or routed policy may still allow it"
            ),
        ),
        None => report.push(
            DiagnosticLevel::Warning,
            forward_name,
            format!("could not inspect {family} firewall rules"),
        ),
    }

    let nat = combined_rules(rules.nat, rules.nft);
    let nat_name = if family == "IPv4" {
        "IPv4 NAT"
    } else {
        "IPv6 NAT"
    };
    match nat {
        Some(ref text) if has_nat_evidence(text, pool) => report.push(
            DiagnosticLevel::Ok,
            nat_name,
            format!("found SNAT/MASQUERADE evidence for {pool}"),
        ),
        Some(_) if likely_needs_nat => report.push(
            DiagnosticLevel::Warning,
            nat_name,
            format!(
                "no SNAT/MASQUERADE rule was found for private pool {pool}; internet egress needs NAT unless another gateway translates it"
            ),
        ),
        Some(_) => report.push(
            DiagnosticLevel::Info,
            nat_name,
            format!("no NAT rule was found for {pool}; this is valid when the pool is routed upstream"),
        ),
        None if likely_needs_nat => report.push(
            DiagnosticLevel::Warning,
            nat_name,
            format!(
                "could not inspect NAT for private pool {pool}; verify SNAT/MASQUERADE or an upstream translator"
            ),
        ),
        None => report.push(
            DiagnosticLevel::Info,
            nat_name,
            format!("could not inspect NAT for routed pool {pool}"),
        ),
    }
}

#[derive(Clone, Copy)]
struct FamilyRules<'a> {
    filter: Option<&'a str>,
    nat: Option<&'a str>,
    nft: Option<&'a str>,
}

struct RuleSnapshot {
    v4_filter: Option<String>,
    v4_nat: Option<String>,
    v6_filter: Option<String>,
    v6_nat: Option<String>,
    nft: Option<String>,
}

impl RuleSnapshot {
    fn collect(probe: &impl HostProbe) -> Self {
        Self {
            v4_filter: probe
                .command_output("iptables-save", &["-t", "filter"])
                .ok(),
            v4_nat: probe.command_output("iptables-save", &["-t", "nat"]).ok(),
            v6_filter: probe
                .command_output("ip6tables-save", &["-t", "filter"])
                .ok(),
            v6_nat: probe.command_output("ip6tables-save", &["-t", "nat"]).ok(),
            // nft may describe rules that are not visible through an iptables
            // compatibility frontend. Collect it once and consider it beside
            // each family-specific table rather than treating either view as
            // authoritative.
            nft: probe.command_output("nft", &["list", "ruleset"]).ok(),
        }
    }
}

fn combined_rules(primary: Option<&str>, nft: Option<&str>) -> Option<String> {
    match (primary, nft) {
        (Some(primary), Some(nft)) => Some(format!("{primary}\n{nft}")),
        (Some(primary), None) => Some(primary.to_owned()),
        (None, Some(nft)) => Some(nft.to_owned()),
        (None, None) => None,
    }
}

fn has_forward_accept_evidence(rules: &str, pool: &str, tun_name: &str) -> bool {
    rules.lines().any(|line| {
        let upper = line.to_ascii_uppercase();
        line.contains(pool)
            && line.contains(tun_name)
            && (upper.contains("ACCEPT") || upper.contains("POLICY ACCEPT"))
    }) || rules.lines().any(|line| {
        let upper = line.to_ascii_uppercase();
        upper.contains(":FORWARD ACCEPT")
            || (upper.contains("HOOK FORWARD") && upper.contains("POLICY ACCEPT"))
    })
}

fn has_nat_evidence(rules: &str, pool: &str) -> bool {
    rules.lines().any(|line| {
        let upper = line.to_ascii_uppercase();
        line.contains(pool) && (upper.contains("MASQUERADE") || upper.contains("SNAT"))
    })
}

fn pool_likely_needs_nat(pool: &str) -> bool {
    if let Ok(network) = pool.parse::<ipnet::Ipv4Net>() {
        let addr = network.network();
        let octets = addr.octets();
        return addr.is_private()
            || addr.is_loopback()
            || addr.is_link_local()
            || octets[0] == 0
            || (octets[0] == 100 && (64..=127).contains(&octets[1]));
    }
    if let Ok(network) = pool.parse::<ipnet::Ipv6Net>() {
        let addr = network.network();
        return addr.is_loopback()
            || addr.is_unspecified()
            || addr.is_unicast_link_local()
            || (addr.segments()[0] & 0xfe00) == 0xfc00;
    }
    false
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::io;
    use std::path::{Path, PathBuf};

    use super::*;

    #[derive(Default)]
    struct FakeProbe {
        linux: bool,
        paths: HashSet<PathBuf>,
        files: HashMap<PathBuf, String>,
        commands: HashMap<String, String>,
    }

    impl FakeProbe {
        fn command_key(program: &str, args: &[&str]) -> String {
            format!("{program}\0{}", args.join("\0"))
        }

        fn add_command(&mut self, program: &str, args: &[&str], output: &str) {
            self.commands
                .insert(Self::command_key(program, args), output.to_owned());
        }
    }

    impl HostProbe for FakeProbe {
        fn is_linux(&self) -> bool {
            self.linux
        }

        fn exists(&self, path: &Path) -> bool {
            self.paths.contains(path)
        }

        fn read_to_string(&self, path: &Path) -> io::Result<String> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing fixture"))
        }

        fn command_output(&self, program: &str, args: &[&str]) -> io::Result<String> {
            self.commands
                .get(&Self::command_key(program, args))
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing fixture"))
        }
    }

    fn ready_probe(config: &IpProxySection) -> FakeProbe {
        let mut probe = FakeProbe {
            linux: true,
            ..FakeProbe::default()
        };
        probe.paths.insert(PathBuf::from("/dev/net/tun"));
        probe
            .paths
            .insert(PathBuf::from("/sys/class/net").join(&config.tun_name));
        probe
            .files
            .insert(PathBuf::from("/proc/sys/net/ipv4/ip_forward"), "1\n".into());
        probe.files.insert(
            PathBuf::from("/proc/sys/net/ipv6/conf/all/forwarding"),
            "1\n".into(),
        );
        probe.add_command(
            "ip",
            &["-4", "route", "show", &config.ipv4_pool],
            &format!("{} dev {} scope link\n", config.ipv4_pool, config.tun_name),
        );
        probe.add_command(
            "ip",
            &["-6", "route", "show", &config.ipv6_pool],
            &format!("{} dev {} metric 256\n", config.ipv6_pool, config.tun_name),
        );
        let filter = format!(
            "-A FORWARD -s {} -i {} -o eth0 -j ACCEPT\n-A FORWARD -s {} -i {} -o eth0 -j ACCEPT\n",
            config.ipv4_pool, config.tun_name, config.ipv6_pool, config.tun_name
        );
        let nat = format!(
            "-A POSTROUTING -s {} -o eth0 -j MASQUERADE\n-A POSTROUTING -s {} -o eth0 -j MASQUERADE\n",
            config.ipv4_pool, config.ipv6_pool
        );
        probe.add_command("iptables-save", &["-t", "filter"], &filter);
        probe.add_command("iptables-save", &["-t", "nat"], &nat);
        probe.add_command("ip6tables-save", &["-t", "filter"], &filter);
        probe.add_command("ip6tables-save", &["-t", "nat"], &nat);
        probe
    }

    #[test]
    fn disabled_connect_ip_needs_no_host_setup() {
        let config = IpProxySection {
            enabled: false,
            ..IpProxySection::default()
        };
        let report = diagnose_with(&config, &FakeProbe::default());
        assert!(!report.has_errors());
        assert_eq!(report.warning_count(), 0);
        assert_eq!(report.checks()[0].name, "CONNECT-IP");
    }

    #[test]
    fn ready_linux_host_has_no_errors_or_warnings() {
        let config = IpProxySection::default();
        let report = diagnose_with(&config, &ready_probe(&config));
        assert!(!report.has_errors(), "{report:#?}");
        assert_eq!(report.warning_count(), 0, "{report:#?}");
    }

    #[test]
    fn nft_only_forwarding_and_nat_evidence_is_recognized() {
        let config = IpProxySection::default();
        let mut probe = ready_probe(&config);
        probe.commands.retain(|key, _| {
            !key.starts_with("iptables-save") && !key.starts_with("ip6tables-save")
        });
        probe.add_command(
            "nft",
            &["list", "ruleset"],
            &format!(
                "iifname \"{}\" ip saddr {} accept\n\
                 iifname \"{}\" ip6 saddr {} accept\n\
                 ip saddr {} masquerade\n\
                 ip6 saddr {} masquerade\n",
                config.tun_name,
                config.ipv4_pool,
                config.tun_name,
                config.ipv6_pool,
                config.ipv4_pool,
                config.ipv6_pool
            ),
        );

        let report = diagnose_with(&config, &probe);
        assert!(!report.has_errors(), "{report:#?}");
        assert_eq!(report.warning_count(), 0, "{report:#?}");
    }

    #[test]
    fn enabled_connect_ip_is_rejected_on_a_non_linux_host() {
        let config = IpProxySection::default();
        let report = diagnose_with(&config, &FakeProbe::default());
        assert_eq!(report.error_count(), 1);
        assert_eq!(report.checks()[0].name, "platform");
    }

    #[test]
    fn startup_check_uses_no_commands_and_points_to_doctor() {
        let config = IpProxySection::default();
        let mut probe = ready_probe(&config);
        probe.commands.clear();
        let report = diagnose_startup_with(&config, &probe);
        assert!(!report.has_errors(), "{report:#?}");
        assert_eq!(report.warning_count(), 1, "{report:#?}");
        assert!(report.checks().iter().any(|check| {
            check.name == "host egress" && check.detail.contains("masque-server doctor")
        }));
    }

    #[test]
    fn missing_forwarding_is_an_error_but_nat_discovery_is_advisory() {
        let config = IpProxySection::default();
        let mut probe = ready_probe(&config);
        probe
            .files
            .insert(PathBuf::from("/proc/sys/net/ipv4/ip_forward"), "0\n".into());
        probe
            .commands
            .remove(&FakeProbe::command_key("iptables-save", &["-t", "nat"]));

        let report = diagnose_with(&config, &probe);
        assert_eq!(report.error_count(), 1, "{report:#?}");
        assert!(report.warning_count() >= 1, "{report:#?}");
        assert!(report.checks().iter().any(|check| {
            check.name == "IPv4 forwarding" && check.level == DiagnosticLevel::Error
        }));
    }

    #[test]
    fn default_private_pools_are_identified_as_nat_candidates() {
        assert!(pool_likely_needs_nat("10.89.0.0/16"));
        assert!(pool_likely_needs_nat("fd00:abcd::/64"));
        assert!(!pool_likely_needs_nat("203.0.113.0/24"));
        assert!(!pool_likely_needs_nat("2001:db8::/64"));
    }
}
