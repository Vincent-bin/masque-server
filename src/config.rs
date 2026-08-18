// Configuration loading — TOML file + CLI overrides.

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Top-level server configuration.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct ServerConfig {
    pub server: ServerSection,
    pub tls: TlsSection,
    pub auth: AuthSection,
    pub quic: QuicSection,
    pub tcp_proxy: TcpProxySection,
    pub udp_proxy: UdpProxySection,
    pub ip_proxy: IpProxySection,
    /// Pre-registered clients, identified by their TLS client certificate key.
    ///
    /// Only consulted when `auth.mode = "client_cert"`. Written as repeated
    /// `[[clients]]` tables.
    pub clients: Vec<ClientEntry>,
    /// Every socket this server listens on, written as repeated `[[listeners]]`
    /// tables.
    ///
    /// This is the whole list, not an addition to `[server].listen_addr`: a
    /// configuration that names any listener here stops deriving one from
    /// `[server]`. Leaving it empty keeps the single-listener form, which is
    /// what every configuration written before this existed uses.
    ///
    /// Separate listeners are what allow one process to serve two
    /// authentication modes at once — `auth.mode` fixes the TLS context, so a
    /// Basic listener and a client-certificate listener cannot share a socket.
    pub listeners: Vec<ListenerSection>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default)]
pub struct ServerSection {
    pub listen_addr: SocketAddr,
    pub idle_timeout_secs: u64,
    pub max_connections: usize,
    pub max_tunnels_per_connection: usize,
    /// Independent event loops to run, each with its own `SO_REUSEPORT` socket
    /// and its own share of the connections.
    ///
    /// QUIC's per-packet crypto is what saturates a core, and a connection is
    /// always handled by one loop, so this is what lets a busy server use more
    /// than one core. `0` means one per available core. Linux only.
    pub shards: usize,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default)]
pub struct TlsSection {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// How clients prove who they are.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// RFC 7617 `Proxy-Authorization: Basic`, verified per request.
    #[default]
    Basic,
    /// A TLS client certificate, matched against the `[[clients]]` roster by
    /// public key during the QUIC handshake.
    ///
    /// This is what Cloudflare's WARP MASQUE endpoint does, and what clients
    /// built against it (usque) expect: they never send `Proxy-Authorization`.
    ClientCert,
}

#[derive(Clone, Deserialize, PartialEq)]
#[serde(default)]
pub struct AuthSection {
    /// Master switch. `false` disables authentication whatever `mode` says.
    pub enabled: bool,
    pub mode: AuthMode,
    pub username: String,
    pub password_hash: String,
}

impl std::fmt::Debug for AuthSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSection")
            .field("enabled", &self.enabled)
            .field("mode", &self.mode)
            .field("username", &self.username)
            .field(
                "password_hash",
                &if self.password_hash.is_empty() {
                    ""
                } else {
                    "[REDACTED]"
                },
            )
            .finish()
    }
}

impl AuthSection {
    /// Whether `Proxy-Authorization` is required on every CONNECT request.
    pub fn basic_enabled(&self) -> bool {
        self.enabled && self.mode == AuthMode::Basic
    }

    /// Whether a client certificate is required to complete the handshake.
    pub fn client_cert_enabled(&self) -> bool {
        self.enabled && self.mode == AuthMode::ClientCert
    }
}

/// One listening socket.
///
/// `listen_addr` has no default on purpose: an omitted address would otherwise
/// silently become `0.0.0.0:443` and collide with whichever listener meant to
/// take that port.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ListenerSection {
    pub listen_addr: SocketAddr,
    /// Independent event loops for this listener. See [`ServerSection::shards`].
    #[serde(default = "default_listener_shards")]
    pub shards: usize,
    /// Authentication for this listener. Omitted means the top-level `[auth]`.
    ///
    /// An override replaces `[auth]` outright rather than merging field by
    /// field: half-inherited credentials would be an authentication decision
    /// assembled from two places, which is not something to leave implicit.
    #[serde(default)]
    pub auth: Option<AuthSection>,
}

fn default_listener_shards() -> usize {
    1
}

/// A listener whose authentication has been resolved against the top-level
/// `[auth]` default.
///
/// Distinct from [`ListenerSection`] so the inheritance happens exactly once,
/// where it can be tested, rather than at each place that reads a listener.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedListener {
    pub listen_addr: SocketAddr,
    pub shards: usize,
    pub auth: AuthSection,
}

impl ServerConfig {
    /// Every listener this configuration asks for, in the order it named them.
    ///
    /// An empty `[[listeners]]` desugars to the single listener described by
    /// `[server]` and `[auth]`, so the two configuration forms produce the same
    /// shape and the rest of the server only ever handles a list.
    pub fn resolved_listeners(&self) -> Vec<ResolvedListener> {
        if self.listeners.is_empty() {
            return vec![ResolvedListener {
                listen_addr: self.server.listen_addr,
                shards: self.server.shards,
                auth: self.auth.clone(),
            }];
        }

        self.listeners
            .iter()
            .map(|listener| ResolvedListener {
                listen_addr: listener.listen_addr,
                shards: listener.shards,
                auth: listener.auth.clone().unwrap_or_else(|| self.auth.clone()),
            })
            .collect()
    }
}

/// One pre-registered client.
///
/// This replaces the vendor enrollment API for self-hosted setups: the
/// operator generates a key pair, records its public key here, and hands the
/// private key to the client out of band.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct ClientEntry {
    /// Label used in logs. Optional, but makes the logs readable.
    pub name: String,
    /// The client's ECDSA P-256 public key, as base64 SubjectPublicKeyInfo DER
    /// or a `-----BEGIN PUBLIC KEY-----` PEM block.
    pub public_key: String,
    /// Fixed IPv4 handed to this client's CONNECT-IP tunnels. Must fall inside
    /// `ip_proxy.ipv4_pool`.
    ///
    /// Clients that configure their tunnel interface from a vendor API rather
    /// than from the `ADDRESS_ASSIGN` capsule need the server to assign the
    /// same address every time, otherwise the two disagree and every packet is
    /// dropped as spoofed.
    pub ipv4: Option<String>,
    /// Fixed IPv6, inside `ip_proxy.ipv6_pool`.
    pub ipv6: Option<String>,
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
    /// Congestion control algorithm: `cubic`, `reno`, or `bbr2`.
    pub cc_algorithm: String,
    /// Initial congestion window, in packets.
    pub initial_congestion_window_packets: usize,
    /// Connection-level flow control credit advertised at handshake, in bytes.
    pub initial_max_data: u64,
    /// Per-stream flow control credit advertised at handshake, in bytes.
    ///
    /// This is the window a single CONNECT stream starts with, so it caps
    /// per-stream throughput at `initial_max_stream_data / RTT` until
    /// autotuning grows it toward `max_stream_window`.
    pub initial_max_stream_data: u64,
    /// Ceiling for connection flow-control autotuning, in bytes.
    pub max_connection_window: u64,
    /// Ceiling for per-stream flow-control autotuning, in bytes.
    pub max_stream_window: u64,
    /// QUIC DATAGRAM receive queue depth, in datagrams.
    ///
    /// Datagrams are never retransmitted, so a deeper queue trades added
    /// latency under load for fewer drops during bursts.
    pub dgram_recv_queue_len: usize,
    /// QUIC DATAGRAM send queue depth, in datagrams.
    pub dgram_send_queue_len: usize,
    /// Probe for a larger path MTU than the conservative initial packet size.
    ///
    /// Probes stop at `max_datagram_size`, so this only pays off when that
    /// value is also raised above the path MTU the server would otherwise
    /// assume (for example to 1500 on a network known to carry it).
    pub discover_pmtu: bool,
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
pub struct TcpProxySection {
    pub enabled: bool,
    pub connect_timeout_secs: u64,
    pub allow_targets: Vec<String>,
    pub deny_targets: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default)]
pub struct IpProxySection {
    pub enabled: bool,
    pub uri_template: String,
    /// Accepted `:protocol` values for an Extended CONNECT IP request.
    ///
    /// RFC 9484 registers `connect-ip`. Cloudflare's endpoint uses
    /// `cf-connect-ip` instead, and clients written against it send only that,
    /// so both are accepted by default; an RFC client never sends the latter.
    pub connect_protocols: Vec<String>,
    pub tun_name: String,
    pub tun_mtu: usize,
    /// Open the TUN device with `IFF_VNET_HDR` so the kernel can hand over a
    /// whole GSO aggregate per read and accept one per write (Linux only).
    ///
    /// This changes the wire format on the device fd, so it is all-or-nothing;
    /// the server switches both directions together when the kernel accepts it.
    pub tun_offload: bool,
    pub ipv4_pool: String,
    pub ipv6_pool: String,
}

// ── Defaults ──────────────────────────────────────────────────────────

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:443".parse().unwrap(),
            // Comfortably above the 30s keepalive period MASQUE VPN clients
            // commonly default to, so a tunnel that is merely quiet does not
            // race its own keepalive to the timeout.
            idle_timeout_secs: 60,
            max_connections: 10_000,
            max_tunnels_per_connection: 100,
            // Opt-in: sharding changes how connections are distributed, so an
            // operator should turn it on deliberately after checking their
            // own traffic rather than inheriting it from an upgrade.
            shards: 1,
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

impl Default for AuthSection {
    fn default() -> Self {
        Self {
            // Fail closed in Server::bind until an operator configures
            // credentials or explicitly opts out for a private test setup.
            enabled: true,
            mode: AuthMode::Basic,
            username: String::new(),
            password_hash: String::new(),
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
            // CUBIC, despite BBR2 looking like the better fit for a proxy.
            // `DeferredSend` holds back a single serialized packet per
            // connection, so a pacer that spaces every packet individually —
            // which BBR2 does and quiche's CUBIC pacing largely does not —
            // caps the server at one packet per event-loop wakeup. Measured on
            // loopback CONNECT-UDP at 1200B: CUBIC 127k pkt/s at 75us p50 RTT,
            // BBR2 34k pkt/s at 1228us. Revisit once a pacing-blocked
            // connection can hold a burst rather than one packet.
            cc_algorithm: "cubic".into(),
            initial_congestion_window_packets: 32,
            initial_max_data: 16 * 1024 * 1024,
            initial_max_stream_data: 4 * 1024 * 1024,
            // quiche's own autotuning ceilings, restated so they are visible
            // and tunable alongside the initial windows.
            max_connection_window: 24 * 1024 * 1024,
            max_stream_window: 16 * 1024 * 1024,
            dgram_recv_queue_len: 2048,
            dgram_send_queue_len: 2048,
            discover_pmtu: false,
        }
    }
}

impl Default for UdpProxySection {
    fn default() -> Self {
        Self {
            enabled: true,
            uri_template: "/.well-known/masque/udp/{target_host}/{target_port}/".into(),
            allow_targets: vec!["0.0.0.0/0".into()],
            deny_targets: vec!["127.0.0.0/8".into(), "10.0.0.0/8".into(), "::1/128".into()],
        }
    }
}

impl Default for TcpProxySection {
    fn default() -> Self {
        Self {
            enabled: true,
            connect_timeout_secs: 10,
            allow_targets: vec!["0.0.0.0/0".into(), "::/0".into()],
            deny_targets: vec![
                "127.0.0.0/8".into(),
                "10.0.0.0/8".into(),
                "169.254.0.0/16".into(),
                "172.16.0.0/12".into(),
                "192.168.0.0/16".into(),
                "::1/128".into(),
                "fc00::/7".into(),
                "fe80::/10".into(),
            ],
        }
    }
}

impl Default for IpProxySection {
    fn default() -> Self {
        Self {
            enabled: true,
            uri_template: "/.well-known/masque/ip/{target}/{ipproto}/".into(),
            connect_protocols: vec!["connect-ip".into(), "cf-connect-ip".into()],
            tun_name: "masque0".into(),
            tun_mtu: 1280,
            tun_offload: true,
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
        assert_eq!(cfg.server.idle_timeout_secs, 60);
        assert!(cfg.auth.enabled);
        assert_eq!(cfg.auth.mode, AuthMode::Basic);
        assert!(cfg.auth.basic_enabled());
        assert!(!cfg.auth.client_cert_enabled());
        assert!(cfg.auth.username.is_empty());
        assert!(cfg.auth.password_hash.is_empty());
        assert!(cfg.clients.is_empty());
        assert!(cfg.listeners.is_empty());
        assert!(cfg.quic.enable_dgram);
        assert!(!cfg.quic.enable_udp_gso);
        assert!(cfg.quic.enable_udp_gro);
        assert_eq!(cfg.quic.cc_algorithm, "cubic");
        assert!(cfg.quic.initial_max_stream_data <= cfg.quic.max_stream_window);
        assert!(cfg.quic.initial_max_data <= cfg.quic.max_connection_window);
        assert!(!cfg.quic.discover_pmtu);
        assert!(cfg.tcp_proxy.enabled);
        assert_eq!(cfg.tcp_proxy.connect_timeout_secs, 10);
        assert!(cfg.udp_proxy.enabled);
        assert!(cfg.ip_proxy.enabled);
        assert_eq!(cfg.ip_proxy.tun_mtu, 1280);
        // Cloudflare's non-standard identifier is accepted out of the box; an
        // RFC 9484 client never sends it, so this costs nothing.
        assert_eq!(
            cfg.ip_proxy.connect_protocols,
            vec!["connect-ip", "cf-connect-ip"]
        );
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
        assert_eq!(cfg.server.listen_addr, "127.0.0.1:8443".parse().unwrap());
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
    fn parse_auth_section_and_redact_hash_in_debug_output() {
        let toml = r#"
[auth]
enabled = true
username = "alice"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"
"#;
        let cfg = parse_toml(toml).unwrap();
        assert!(cfg.auth.enabled);
        assert_eq!(cfg.auth.username, "alice");
        assert!(cfg.auth.password_hash.starts_with("$argon2id$"));

        let debug = format!("{cfg:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("$argon2id$"));
    }

    #[test]
    fn parse_client_cert_auth_mode_with_roster() {
        let toml = r#"
[auth]
enabled = true
mode = "client_cert"

[[clients]]
name = "laptop"
public_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdGVzdA=="
ipv4 = "10.89.0.2"
ipv6 = "fd00:abcd::2"

[[clients]]
name = "phone"
public_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb3RoZXI="
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.auth.mode, AuthMode::ClientCert);
        assert!(cfg.auth.client_cert_enabled());
        // The Basic pipeline must stand down, or a client certificate would not
        // be enough on its own.
        assert!(!cfg.auth.basic_enabled());

        assert_eq!(cfg.clients.len(), 2);
        assert_eq!(cfg.clients[0].name, "laptop");
        assert_eq!(cfg.clients[0].ipv4.as_deref(), Some("10.89.0.2"));
        assert_eq!(cfg.clients[0].ipv6.as_deref(), Some("fd00:abcd::2"));
        // A roster entry without fixed addresses falls back to the pool.
        assert_eq!(cfg.clients[1].ipv4, None);
        assert_eq!(cfg.clients[1].ipv6, None);
    }

    #[test]
    fn disabling_auth_overrides_the_mode() {
        let cfg = parse_toml("[auth]\nenabled = false\nmode = \"client_cert\"\n").unwrap();
        assert!(!cfg.auth.client_cert_enabled());
        assert!(!cfg.auth.basic_enabled());
    }

    #[test]
    fn parse_unknown_auth_mode_is_rejected() {
        // A typo here would otherwise silently fall back to Basic and lock out
        // every client certificate.
        assert!(parse_toml("[auth]\nmode = \"mtls\"\n").is_err());
    }

    #[test]
    fn a_configuration_without_listeners_desugars_to_one() {
        let cfg = parse_toml(
            r#"
[server]
listen_addr = "127.0.0.1:8443"
shards = 3

[auth]
mode = "client_cert"
"#,
        )
        .unwrap();

        let listeners = cfg.resolved_listeners();
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].listen_addr, "127.0.0.1:8443".parse().unwrap());
        assert_eq!(listeners[0].shards, 3);
        assert_eq!(listeners[0].auth, cfg.auth);
    }

    #[test]
    fn listeners_replace_the_single_listener_form() {
        let cfg = parse_toml(
            r#"
[server]
listen_addr = "0.0.0.0:443"

[auth]
enabled = true
mode = "basic"
username = "alice"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"

[[listeners]]
listen_addr = "0.0.0.0:8443"

[[listeners]]
listen_addr = "0.0.0.0:4443"
shards = 2

[listeners.auth]
mode = "client_cert"
"#,
        )
        .unwrap();

        let listeners = cfg.resolved_listeners();
        assert_eq!(listeners.len(), 2, "[server].listen_addr must not add one");

        // No override: the top-level [auth] is inherited whole.
        assert_eq!(listeners[0].listen_addr, "0.0.0.0:8443".parse().unwrap());
        assert_eq!(listeners[0].shards, 1, "shards default to one per listener");
        assert!(listeners[0].auth.basic_enabled());
        assert_eq!(listeners[0].auth.username, "alice");

        // An override replaces [auth] rather than merging into it, so the
        // inherited username does not follow the mode across.
        assert_eq!(listeners[1].listen_addr, "0.0.0.0:4443".parse().unwrap());
        assert_eq!(listeners[1].shards, 2);
        assert!(listeners[1].auth.client_cert_enabled());
        assert!(listeners[1].auth.username.is_empty());
    }

    /// The whole point of the list: one process, two authentication modes.
    #[test]
    fn listeners_can_disagree_about_the_authentication_mode() {
        let cfg = parse_toml(
            r#"
[[listeners]]
listen_addr = "0.0.0.0:443"

[listeners.auth]
mode = "basic"
username = "alice"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"

[[listeners]]
listen_addr = "0.0.0.0:4443"

[listeners.auth]
mode = "client_cert"
"#,
        )
        .unwrap();

        let listeners = cfg.resolved_listeners();
        assert!(listeners[0].auth.basic_enabled());
        assert!(!listeners[0].auth.client_cert_enabled());
        assert!(listeners[1].auth.client_cert_enabled());
        assert!(!listeners[1].auth.basic_enabled());
    }

    #[test]
    fn a_listener_without_an_address_is_rejected() {
        // Defaulting this would silently put the listener on 0.0.0.0:443,
        // where it would fight whichever listener meant to take that port.
        assert!(parse_toml("[[listeners]]\nshards = 2\n").is_err());
    }

    #[test]
    fn parse_unknown_listener_auth_mode_is_rejected() {
        let toml = r#"
[[listeners]]
listen_addr = "0.0.0.0:443"

[listeners.auth]
mode = "mtls"
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn listener_password_hashes_are_redacted_in_debug_output() {
        let cfg = parse_toml(
            r#"
[[listeners]]
listen_addr = "0.0.0.0:443"

[listeners.auth]
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"
"#,
        )
        .unwrap();

        // `info!(?cfg, ...)` logs the whole configuration at startup.
        let debug = format!("{cfg:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("$argon2id$"));
    }

    #[test]
    fn parse_custom_connect_protocols() {
        let toml = r#"
[ip_proxy]
connect_protocols = ["connect-ip"]
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.ip_proxy.connect_protocols, vec!["connect-ip"]);
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
        // Tuning knobs absent from the file keep their defaults.
        assert_eq!(cfg.quic.cc_algorithm, "cubic");
        assert_eq!(cfg.quic.dgram_send_queue_len, 2048);
    }

    #[test]
    fn parse_quic_tuning_knobs() {
        let toml = r#"
[quic]
cc_algorithm = "cubic"
initial_congestion_window_packets = 10
initial_max_data = 1000000
initial_max_stream_data = 500000
max_connection_window = 2000000
max_stream_window = 1000000
dgram_recv_queue_len = 512
dgram_send_queue_len = 256
discover_pmtu = true
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg.quic.cc_algorithm, "cubic");
        assert_eq!(cfg.quic.initial_congestion_window_packets, 10);
        assert_eq!(cfg.quic.initial_max_data, 1_000_000);
        assert_eq!(cfg.quic.initial_max_stream_data, 500_000);
        assert_eq!(cfg.quic.max_connection_window, 2_000_000);
        assert_eq!(cfg.quic.max_stream_window, 1_000_000);
        assert_eq!(cfg.quic.dgram_recv_queue_len, 512);
        assert_eq!(cfg.quic.dgram_send_queue_len, 256);
        assert!(cfg.quic.discover_pmtu);
        // Untouched fields still come from the defaults.
        assert_eq!(cfg.quic.max_datagram_size, 1350);
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
    fn parse_tcp_proxy_section() {
        let toml = r#"
[tcp_proxy]
enabled = false
connect_timeout_secs = 3
allow_targets = ["192.168.0.0/16"]
deny_targets = []
"#;
        let cfg = parse_toml(toml).unwrap();
        assert!(!cfg.tcp_proxy.enabled);
        assert_eq!(cfg.tcp_proxy.connect_timeout_secs, 3);
        assert_eq!(cfg.tcp_proxy.allow_targets, vec!["192.168.0.0/16"]);
        assert!(cfg.tcp_proxy.deny_targets.is_empty());
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
idle_timeout_secs = 60
max_connections = 10000
max_tunnels_per_connection = 100

[tls]
cert_path = "certs/server.crt"
key_path = "certs/server.key"

[quic]
max_datagram_size = 1350
initial_max_streams_bidi = 128
enable_dgram = true
cc_algorithm = "cubic"
initial_congestion_window_packets = 32
initial_max_data = 16777216
initial_max_stream_data = 4194304
max_connection_window = 25165824
max_stream_window = 16777216
dgram_recv_queue_len = 2048
dgram_send_queue_len = 2048
discover_pmtu = false

[tcp_proxy]
enabled = true
connect_timeout_secs = 10
allow_targets = ["0.0.0.0/0", "::/0"]
deny_targets = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]

[udp_proxy]
enabled = true
uri_template = "/.well-known/masque/udp/{target_host}/{target_port}/"
allow_targets = ["0.0.0.0/0"]
deny_targets = ["127.0.0.0/8", "10.0.0.0/8", "::1/128"]

[ip_proxy]
enabled = true
uri_template = "/.well-known/masque/ip/{target}/{ipproto}/"
connect_protocols = ["connect-ip", "cf-connect-ip"]
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
