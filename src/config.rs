// Configuration loading — TOML file + CLI overrides.

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Top-level server configuration.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default)]
pub struct ServerConfig {
    pub server: ServerSection,
    pub tls: TlsSection,
    pub quic: QuicSection,
    pub udp_proxy: UdpProxySection,
    pub ip_proxy: IpProxySection,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default)]
pub struct ServerSection {
    pub listen_addr: SocketAddr,
    pub idle_timeout_secs: u64,
    pub max_connections: usize,
    pub max_tunnels_per_connection: usize,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default)]
pub struct TlsSection {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default)]
pub struct QuicSection {
    pub max_datagram_size: usize,
    pub initial_max_streams_bidi: u64,
    pub enable_dgram: bool,
    /// Use UDP segmentation offload for QUIC sends when Linux supports it.
    /// This is opt-in because some virtual NIC egress paths silently drop
    /// otherwise valid GSO super-packets.
    pub enable_udp_gso: bool,
    /// Use UDP generic receive offload for QUIC receives when Linux supports it.
    pub enable_udp_gro: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default)]
pub struct UdpProxySection {
    pub enabled: bool,
    pub uri_template: String,
    pub allow_targets: Vec<String>,
    pub deny_targets: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default)]
pub struct IpProxySection {
    pub enabled: bool,
    pub uri_template: String,
    pub tun_name: String,
    pub tun_mtu: usize,
    pub ipv4_pool: String,
    pub ipv6_pool: String,
}

// ── Defaults ──────────────────────────────────────────────────────────

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server: ServerSection::default(),
            tls: TlsSection::default(),
            quic: QuicSection::default(),
            udp_proxy: UdpProxySection::default(),
            ip_proxy: IpProxySection::default(),
        }
    }
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:443".parse().unwrap(),
            idle_timeout_secs: 30,
            max_connections: 10_000,
            max_tunnels_per_connection: 100,
        }
    }
}

impl Default for TlsSection {
    fn default() -> Self {
        Self {
            cert_path: PathBuf::from("certs/server.crt"),
            key_path: PathBuf::from("certs/server.key"),
        }
    }
}

impl Default for QuicSection {
    fn default() -> Self {
        Self {
            max_datagram_size: 1350,
            initial_max_streams_bidi: 128,
            enable_dgram: true,
            // Some virtual NICs advertise UDP GSO but silently drop the
            // resulting super-packets on their external path. Keep GSO
            // opt-in until an operator has verified the actual egress path.
            enable_udp_gso: false,
            enable_udp_gro: true,
        }
    }
}

impl Default for UdpProxySection {
    fn default() -> Self {
        Self {
            enabled: true,
            uri_template: "/.well-known/masque/udp/{target_host}/{target_port}/"
                .into(),
            allow_targets: vec!["0.0.0.0/0".into()],
            deny_targets: vec![
                "127.0.0.0/8".into(),
                "10.0.0.0/8".into(),
                "::1/128".into(),
            ],
        }
    }
}

impl Default for IpProxySection {
    fn default() -> Self {
        Self {
            enabled: true,
            uri_template: "/.well-known/masque/ip/{target}/{ipproto}/".into(),
            tun_name: "masque0".into(),
            tun_mtu: 1280,
            ipv4_pool: "10.89.0.0/16".into(),
            ipv6_pool: "fd00:abcd::/64".into(),
        }
    }
}

/// Parse a TOML string into a [`ServerConfig`].
pub fn parse_toml(toml_str: &str) -> Result<ServerConfig, toml::de::Error> {
    toml::from_str(toml_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sensible() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.server.listen_addr.port(), 443);
        assert_eq!(cfg.server.idle_timeout_secs, 30);
        assert!(cfg.quic.enable_dgram);
        assert!(!cfg.quic.enable_udp_gso);
        assert!(cfg.quic.enable_udp_gro);
        assert!(cfg.udp_proxy.enabled);
        assert!(cfg.ip_proxy.enabled);
        assert_eq!(cfg.ip_proxy.tun_mtu, 1280);
    }

    #[test]
    fn parse_empty_toml_gives_defaults() {
        let cfg = parse_toml("").unwrap();
        assert_eq!(cfg, ServerConfig::default());
    }

    #[test]
    fn parse_partial_server_section() {
        let toml = r#"
[server]
listen_addr = "127.0.0.1:8443"
idle_timeout_secs = 60
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(
            cfg.server.listen_addr,
            "127.0.0.1:8443".parse().unwrap()
        );
        assert_eq!(cfg.server.idle_timeout_secs, 60);
        // Other fields keep defaults
        assert_eq!(cfg.server.max_connections, 10_000);
    }

    #[test]
    fn parse_tls_section() {
        let toml = r#"
[tls]
cert_path = "/etc/masque/cert.pem"
key_path = "/etc/masque/key.pem"
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.tls.cert_path, PathBuf::from("/etc/masque/cert.pem"));
        assert_eq!(cfg.tls.key_path, PathBuf::from("/etc/masque/key.pem"));
    }

    #[test]
    fn parse_quic_section() {
        let toml = r#"
[quic]
max_datagram_size = 1200
initial_max_streams_bidi = 64
enable_dgram = false
enable_udp_gso = true
enable_udp_gro = false
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.quic.max_datagram_size, 1200);
        assert_eq!(cfg.quic.initial_max_streams_bidi, 64);
        assert!(!cfg.quic.enable_dgram);
        assert!(cfg.quic.enable_udp_gso);
        assert!(!cfg.quic.enable_udp_gro);
    }

    #[test]
    fn parse_udp_proxy_section() {
        let toml = r#"
[udp_proxy]
enabled = false
allow_targets = ["192.168.0.0/16"]
deny_targets = []
"#;
        let cfg = parse_toml(toml).unwrap();
        assert!(!cfg.udp_proxy.enabled);
        assert_eq!(cfg.udp_proxy.allow_targets, vec!["192.168.0.0/16"]);
        assert!(cfg.udp_proxy.deny_targets.is_empty());
    }

    #[test]
    fn parse_ip_proxy_section() {
        let toml = r#"
[ip_proxy]
enabled = false
tun_name = "tun7"
tun_mtu = 1400
ipv4_pool = "172.16.0.0/12"
ipv6_pool = "fd01::/64"
"#;
        let cfg = parse_toml(toml).unwrap();
        assert!(!cfg.ip_proxy.enabled);
        assert_eq!(cfg.ip_proxy.tun_name, "tun7");
        assert_eq!(cfg.ip_proxy.tun_mtu, 1400);
        assert_eq!(cfg.ip_proxy.ipv4_pool, "172.16.0.0/12");
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
[server]
listen_addr = "0.0.0.0:443"
idle_timeout_secs = 30
max_connections = 10000
max_tunnels_per_connection = 100

[tls]
cert_path = "certs/server.crt"
key_path = "certs/server.key"

[quic]
max_datagram_size = 1350
initial_max_streams_bidi = 128
enable_dgram = true

[udp_proxy]
enabled = true
uri_template = "/.well-known/masque/udp/{target_host}/{target_port}/"
allow_targets = ["0.0.0.0/0"]
deny_targets = ["127.0.0.0/8", "10.0.0.0/8", "::1/128"]

[ip_proxy]
enabled = true
uri_template = "/.well-known/masque/ip/{target}/{ipproto}/"
tun_name = "masque0"
tun_mtu = 1280
ipv4_pool = "10.89.0.0/16"
ipv6_pool = "fd00:abcd::/64"
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg, ServerConfig::default());
    }

    #[test]
    fn parse_invalid_listen_addr() {
        let toml = r#"
[server]
listen_addr = "not-an-address"
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn parse_invalid_type() {
        let toml = r#"
[server]
idle_timeout_secs = "not a number"
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn parse_unknown_field_is_ignored() {
        // serde ignores unknown fields by default — good for forward compat.
        let toml = r#"
[server]
unknown_field = 42
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.server.listen_addr.port(), 443); // defaults preserved
    }
}
