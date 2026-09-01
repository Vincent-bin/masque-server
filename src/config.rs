// Configuration loading — TOML file + CLI overrides.

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Top-level server configuration.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default)]
    pub tls: TlsSection,
    #[serde(default)]
    pub quic: QuicSection,
    #[serde(default)]
    pub http2: Http2Section,
    #[serde(default)]
    pub tcp_proxy: TcpProxySection,
    #[serde(default)]
    pub udp_proxy: UdpProxySection,
    #[serde(default)]
    pub ip_proxy: IpProxySection,
    /// Optional loopback-only HTTP endpoint for health checks and Prometheus.
    #[serde(default)]
    pub observability: ObservabilitySection,
    /// Pre-registered clients, identified by their TLS client certificate key.
    ///
    /// Only consulted when a listener uses `auth.mode = "client_cert"`.
    /// Written as repeated `[[clients]]` tables.
    #[serde(default)]
    pub clients: Vec<ClientEntry>,
    /// Every socket this server listens on, written as repeated `[[listeners]]`
    /// tables.
    ///
    /// Separate listeners are what allow one process to serve two
    /// authentication modes at once — a listener's `auth.mode` fixes its TLS
    /// context, so Basic and client-certificate modes cannot share a socket.
    /// The field intentionally has no serde default: every configuration file
    /// must name at least one listener explicitly.
    pub listeners: Vec<ListenerSection>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ServerSection {
    pub idle_timeout_secs: u64,
    pub max_connections: usize,
    /// Process-wide cap for live HTTP/2 and HTTP/3 connections admitted from
    /// one canonical source IP address.
    pub max_connections_per_ip: usize,
    /// Basic-auth requests from one source that may be running or waiting for
    /// Argon2 verification across every listener and transport.
    pub max_pending_auth_per_ip: usize,
    pub max_tunnels_per_connection: usize,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
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
    /// public key during the TLS handshake.
    ///
    /// This is what Cloudflare's WARP MASQUE endpoint does, and what clients
    /// built against it (usque) expect: they never send `Proxy-Authorization`.
    ClientCert,
}

/// HTTP transport carried by one listener.
///
/// HTTP/3 listens on UDP and remains the default. HTTP/2 listens on TCP/TLS
/// and carries HTTP Datagrams through reliable DATAGRAM capsules.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ListenerTransport {
    #[default]
    Http3,
    Http2,
}

/// When an HTTP/3 listener validates a client's address before allocating
/// connection state.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QuicRetryMode {
    /// Accept tokenless Initial packets until the configured live-state
    /// threshold is reached, then require a valid Retry token.
    #[default]
    Adaptive,
    /// Always allocate immediately. Useful only on a trusted network or for a
    /// controlled latency comparison.
    Off,
    /// Require address validation for every new HTTP/3 connection.
    Always,
}

impl ListenerTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http3 => "http3",
            Self::Http2 => "http2",
        }
    }
}

#[derive(Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AuthSection {
    /// Master switch. `false` disables authentication whatever `mode` says.
    pub enabled: bool,
    pub mode: AuthMode,
    /// Hide Basic authentication failures behind the same empty `404` used
    /// for unsupported HTTP requests instead of advertising a `407` challenge.
    /// Clients must send `Proxy-Authorization` on their first CONNECT.
    pub stealth: bool,
    /// Legacy single-user spelling retained so existing configurations keep
    /// working. New configurations should use repeated
    /// `[[listeners.auth.users]]` tables instead.
    pub username: String,
    /// Legacy companion to [`username`](Self::username).
    pub password_hash: String,
    /// Basic credentials accepted by this listener.
    #[serde(default)]
    pub users: Vec<BasicUser>,
}

/// One Basic-auth principal.
#[derive(Clone, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct BasicUser {
    pub username: String,
    pub password_hash: String,
}

impl std::fmt::Debug for BasicUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicUser")
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

impl std::fmt::Debug for AuthSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSection")
            .field("enabled", &self.enabled)
            .field("mode", &self.mode)
            .field("stealth", &self.stealth)
            .field("username", &self.username)
            .field(
                "password_hash",
                &if self.password_hash.is_empty() {
                    ""
                } else {
                    "[REDACTED]"
                },
            )
            .field("users", &self.users)
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

    /// Whether failed Basic authorization should resemble an ordinary 404.
    pub fn stealth_enabled(&self) -> bool {
        self.basic_enabled() && self.stealth
    }
}

/// One listening socket.
///
/// `listen_addr` has no default on purpose: an omitted address would otherwise
/// silently become `0.0.0.0:443` and collide with whichever listener meant to
/// take that port.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ListenerSection {
    pub listen_addr: SocketAddr,
    /// `http3` binds UDP; `http2` binds TCP/TLS. The default preserves
    /// configurations written before HTTP/2 support was added.
    #[serde(default)]
    pub transport: ListenerTransport,
    /// Independent event loops for this listener. Each shard owns a
    /// `SO_REUSEPORT` socket and a disjoint share of the connections. `0` means
    /// one per available core and is accepted only for a single listener.
    #[serde(default = "default_listener_shards")]
    pub shards: usize,
    /// Optional HTTP/3 packet-size ceiling for this listener. When absent,
    /// `quic.max_datagram_size` remains the process-wide default. A listener
    /// override lets a relay/low-MTU endpoint use 1200 without penalising
    /// ordinary single-hop listeners.
    #[serde(default)]
    pub max_datagram_size: Option<usize>,
    /// Authentication for this listener. Required so a socket's trust boundary
    /// is never inherited from a distant part of the file.
    pub auth: AuthSection,
}

fn default_listener_shards() -> usize {
    1
}

/// A validated listener with `shards = 0` resolved to an explicit count.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedListener {
    pub listen_addr: SocketAddr,
    pub transport: ListenerTransport,
    pub shards: usize,
    pub max_datagram_size: Option<usize>,
    pub auth: AuthSection,
}

impl ResolvedListener {
    pub fn effective_quic_max_datagram_size(&self, default: usize) -> usize {
        self.max_datagram_size.unwrap_or(default)
    }
}

/// One pre-registered client.
///
/// This replaces the vendor enrollment API for self-hosted setups: the
/// operator generates a key pair, records its public key here, and hands the
/// private key to the client out of band.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
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
#[serde(default, deny_unknown_fields)]
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
    /// Stateless address-validation policy for new HTTP/3 connections.
    pub retry_mode: QuicRetryMode,
    /// In adaptive mode, tokenless Initial packets stop allocating state when
    /// this many connections are already live on the receiving shard.
    pub retry_connection_threshold: usize,
    /// Lifetime of an authenticated Retry token.
    pub retry_token_ttl_secs: u64,
}

/// HTTP/2 flow-control and resource limits.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Http2Section {
    /// Receive credit advertised for each request stream.
    pub initial_stream_window: u32,
    /// Receive credit advertised for the whole connection.
    pub initial_connection_window: u32,
    /// Maximum simultaneous streams accepted on one connection.
    pub max_concurrent_streams: u32,
    /// Maximum uncompressed request header list size.
    pub max_header_list_size: u32,
    /// Per-stream response bytes the h2 implementation may buffer.
    pub max_send_buffer_size: usize,
    /// Connection-level allowance for queued small DATA-frame overhead.
    ///
    /// CONNECT-IP clients commonly put one small inner TCP ACK in each DATA
    /// frame. The generic h2 default is intentionally tiny and can mistake a
    /// legitimate packet burst for abusive framing before the tunnel task gets
    /// scheduled to consume it.
    pub data_frame_budget: usize,
    /// Largest UDP payload accepted in a CONNECT-UDP DATAGRAM capsule.
    pub max_datagram_size: usize,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct UdpProxySection {
    pub enabled: bool,
    /// Total deadline for DNS resolution and target socket setup.
    pub connect_timeout_secs: u64,
    pub uri_template: String,
    pub allow_targets: Vec<String>,
    pub deny_targets: Vec<String>,
    /// Use UDP segmentation offload when relaying large client datagrams to
    /// targets on Linux. Kept separate from the outer QUIC socket because the
    /// two egress paths can have different offload support.
    pub enable_udp_gso: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct TcpProxySection {
    pub enabled: bool,
    pub connect_timeout_secs: u64,
    pub allow_targets: Vec<String>,
    pub deny_targets: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
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

/// Operational HTTP endpoint, disabled when `listen_addr` is absent.
///
/// Metrics contain deployment and traffic information and have no
/// authentication layer of their own, so validation permits only a loopback
/// address. Operators can use a local Prometheus agent or an SSH tunnel when a
/// collector does not run on the same host.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ObservabilitySection {
    pub listen_addr: Option<SocketAddr>,
}

// ── Defaults ──────────────────────────────────────────────────────────

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server: ServerSection::default(),
            tls: TlsSection::default(),
            quic: QuicSection::default(),
            http2: Http2Section::default(),
            tcp_proxy: TcpProxySection::default(),
            udp_proxy: UdpProxySection::default(),
            ip_proxy: IpProxySection::default(),
            observability: ObservabilitySection::default(),
            clients: Vec::new(),
            listeners: vec![ListenerSection {
                listen_addr: "0.0.0.0:443".parse().unwrap(),
                transport: ListenerTransport::Http3,
                shards: default_listener_shards(),
                max_datagram_size: None,
                auth: AuthSection::default(),
            }],
        }
    }
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            // Comfortably above the 30s keepalive period MASQUE VPN clients
            // commonly default to, so a tunnel that is merely quiet does not
            // race its own keepalive to the timeout.
            idle_timeout_secs: 60,
            max_connections: 10_000,
            max_connections_per_ip: 64,
            max_pending_auth_per_ip: 8,
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

impl Default for AuthSection {
    fn default() -> Self {
        Self {
            // Fail closed in Server::bind until an operator configures
            // credentials or explicitly opts out for a private test setup.
            enabled: true,
            mode: AuthMode::Basic,
            stealth: false,
            username: String::new(),
            password_hash: String::new(),
            users: Vec::new(),
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
            retry_mode: QuicRetryMode::Adaptive,
            retry_connection_threshold: 64,
            retry_token_ttl_secs: 30,
        }
    }
}

impl Default for Http2Section {
    fn default() -> Self {
        Self {
            initial_stream_window: 1024 * 1024,
            initial_connection_window: 16 * 1024 * 1024,
            max_concurrent_streams: 128,
            max_header_list_size: 8 * 1024,
            max_send_buffer_size: 256 * 1024,
            // Enough for a TLS read containing thousands of packet-sized DATA
            // frames, while retaining h2's connection-level abuse bound.
            data_frame_budget: 256 * 1024,
            // RFC 9298 caps a context-zero UDP payload at 65,527 bytes.
            max_datagram_size: 65_527,
        }
    }
}

impl Default for UdpProxySection {
    fn default() -> Self {
        Self {
            enabled: true,
            connect_timeout_secs: 10,
            uri_template: "/.well-known/masque/udp/{target_host}/{target_port}/".into(),
            allow_targets: vec!["0.0.0.0/0".into()],
            deny_targets: vec!["127.0.0.0/8".into(), "10.0.0.0/8".into(), "::1/128".into()],
            enable_udp_gso: false,
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

    const DISABLED_LISTENER: &str = r#"
[[listeners]]
listen_addr = "127.0.0.1:8443"

[listeners.auth]
enabled = false
"#;

    fn parse_with_listener(toml: &str) -> ServerConfig {
        parse_toml(&format!("{toml}\n{DISABLED_LISTENER}")).unwrap()
    }

    #[test]
    fn defaults_are_sensible() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.server.idle_timeout_secs, 60);
        assert!(cfg.clients.is_empty());
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(cfg.listeners[0].listen_addr.port(), 443);
        assert_eq!(cfg.listeners[0].transport, ListenerTransport::Http3);
        assert_eq!(cfg.listeners[0].shards, 1);
        assert!(cfg.listeners[0].auth.basic_enabled());
        assert!(!cfg.listeners[0].auth.client_cert_enabled());
        assert!(cfg.listeners[0].auth.username.is_empty());
        assert!(cfg.listeners[0].auth.password_hash.is_empty());
        assert!(cfg.quic.enable_dgram);
        assert!(!cfg.quic.enable_udp_gso);
        assert!(cfg.quic.enable_udp_gro);
        assert_eq!(cfg.quic.cc_algorithm, "cubic");
        assert!(cfg.quic.initial_max_stream_data <= cfg.quic.max_stream_window);
        assert!(cfg.quic.initial_max_data <= cfg.quic.max_connection_window);
        assert!(!cfg.quic.discover_pmtu);
        assert_eq!(cfg.http2.data_frame_budget, 256 * 1024);
        assert!(cfg.tcp_proxy.enabled);
        assert_eq!(cfg.tcp_proxy.connect_timeout_secs, 10);
        assert!(cfg.udp_proxy.enabled);
        assert_eq!(cfg.udp_proxy.connect_timeout_secs, 10);
        assert!(cfg.ip_proxy.enabled);
        assert_eq!(cfg.ip_proxy.tun_mtu, 1280);
        assert_eq!(cfg.observability.listen_addr, None);
        // Cloudflare's non-standard identifier is accepted out of the box; an
        // RFC 9484 client never sends it, so this costs nothing.
        assert_eq!(
            cfg.ip_proxy.connect_protocols,
            vec!["connect-ip", "cf-connect-ip"]
        );
    }

    #[test]
    fn configuration_file_requires_listeners() {
        let error = parse_toml("").unwrap_err().to_string();
        assert!(error.contains("listeners"), "unexpected error: {error}");
    }

    #[test]
    fn parse_partial_server_section() {
        let cfg = parse_with_listener(
            r#"
[server]
idle_timeout_secs = 75
"#,
        );
        assert_eq!(cfg.server.idle_timeout_secs, 75);
        // Other fields keep defaults
        assert_eq!(cfg.server.max_connections, 10_000);
        assert_eq!(cfg.server.max_connections_per_ip, 64);
        assert_eq!(cfg.server.max_pending_auth_per_ip, 8);
    }

    #[test]
    fn parse_tls_section() {
        let cfg = parse_with_listener(
            r#"
[tls]
cert_path = "/etc/masque/cert.pem"
key_path = "/etc/masque/key.pem"
"#,
        );
        assert_eq!(cfg.tls.cert_path, PathBuf::from("/etc/masque/cert.pem"));
        assert_eq!(cfg.tls.key_path, PathBuf::from("/etc/masque/key.pem"));
    }

    #[test]
    fn parse_quic_retry_policy() {
        let cfg = parse_with_listener(
            r#"
[quic]
retry_mode = "always"
retry_connection_threshold = 128
retry_token_ttl_secs = 15
"#,
        );
        assert_eq!(cfg.quic.retry_mode, QuicRetryMode::Always);
        assert_eq!(cfg.quic.retry_connection_threshold, 128);
        assert_eq!(cfg.quic.retry_token_ttl_secs, 15);
    }

    #[test]
    fn parse_observability_section() {
        let cfg = parse_with_listener(
            r#"
[observability]
listen_addr = "127.0.0.1:9090"
"#,
        );
        assert_eq!(
            cfg.observability.listen_addr,
            Some("127.0.0.1:9090".parse().unwrap())
        );
    }

    #[test]
    fn parse_listener_auth_and_redact_hash_in_debug_output() {
        let toml = r#"
[[listeners]]
listen_addr = "127.0.0.1:8443"

[listeners.auth]
enabled = true
username = "alice"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"
"#;
        let cfg = parse_toml(toml).unwrap();
        let auth = &cfg.listeners[0].auth;
        assert!(auth.enabled);
        assert_eq!(auth.username, "alice");
        assert!(auth.password_hash.starts_with("$argon2id$"));

        let debug = format!("{cfg:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("$argon2id$"));
    }

    #[test]
    fn parse_multiple_basic_users_and_redact_every_hash() {
        let toml = r#"
[[listeners]]
listen_addr = "127.0.0.1:8443"

[listeners.auth]
enabled = true
mode = "basic"

[[listeners.auth.users]]
username = "alice"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$YWxpY2U$aGFzaDE"

[[listeners.auth.users]]
username = "bob"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$Ym9i$aGFzaDI"
"#;
        let cfg = parse_toml(toml).unwrap();
        let auth = &cfg.listeners[0].auth;
        assert!(auth.username.is_empty());
        assert!(auth.password_hash.is_empty());
        assert_eq!(auth.users.len(), 2);
        assert_eq!(auth.users[0].username, "alice");
        assert_eq!(auth.users[1].username, "bob");

        let debug = format!("{cfg:?}");
        assert_eq!(debug.matches("[REDACTED]").count(), 2);
        assert!(!debug.contains("$argon2id$"));
    }

    #[test]
    fn parse_client_cert_auth_mode_with_roster() {
        let toml = r#"
[[listeners]]
listen_addr = "127.0.0.1:8443"

[listeners.auth]
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
        let auth = &cfg.listeners[0].auth;
        assert_eq!(auth.mode, AuthMode::ClientCert);
        assert!(auth.client_cert_enabled());
        // The Basic pipeline must stand down, or a client certificate would not
        // be enough on its own.
        assert!(!auth.basic_enabled());

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
        let cfg = parse_toml(
            "[[listeners]]\nlisten_addr = \"127.0.0.1:8443\"\n\
             [listeners.auth]\nenabled = false\nmode = \"client_cert\"\n",
        )
        .unwrap();
        assert!(!cfg.listeners[0].auth.client_cert_enabled());
        assert!(!cfg.listeners[0].auth.basic_enabled());
    }

    #[test]
    fn parse_unknown_auth_mode_is_rejected() {
        // A typo here would otherwise silently fall back to Basic and lock out
        // every client certificate.
        assert!(
            parse_toml(
                "[[listeners]]\nlisten_addr = \"127.0.0.1:8443\"\n\
                 [listeners.auth]\nmode = \"mtls\"\n"
            )
            .is_err()
        );
    }

    #[test]
    fn listeners_are_explicit_and_can_use_different_authentication_modes() {
        let cfg = parse_toml(
            r#"
[[listeners]]
listen_addr = "0.0.0.0:8443"

[listeners.auth]
enabled = true
mode = "basic"
username = "alice"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"

[[listeners]]
listen_addr = "0.0.0.0:4443"
shards = 2

[listeners.auth]
mode = "client_cert"
"#,
        )
        .unwrap();

        assert_eq!(cfg.listeners.len(), 2);
        assert_eq!(cfg.listeners[0].shards, 1, "shards default to one");
        assert!(cfg.listeners[0].auth.basic_enabled());
        assert_eq!(cfg.listeners[0].auth.username, "alice");
        assert_eq!(cfg.listeners[1].shards, 2);
        assert!(cfg.listeners[1].auth.client_cert_enabled());
        assert!(!cfg.listeners[1].auth.basic_enabled());
    }

    #[test]
    fn http3_listener_can_override_the_global_datagram_size() {
        let cfg = parse_toml(
            r#"
[quic]
max_datagram_size = 1350

[[listeners]]
listen_addr = "0.0.0.0:8443"
max_datagram_size = 1200

[listeners.auth]
enabled = false

[[listeners]]
listen_addr = "0.0.0.0:8444"

[listeners.auth]
enabled = false
"#,
        )
        .unwrap();

        assert_eq!(cfg.quic.max_datagram_size, 1350);
        assert_eq!(cfg.listeners[0].max_datagram_size, Some(1200));
        assert_eq!(cfg.listeners[1].max_datagram_size, None);
    }

    #[test]
    fn parses_http2_listener_and_tuning() {
        let cfg = parse_toml(
            r#"
[http2]
initial_stream_window = 2097152
initial_connection_window = 33554432
max_concurrent_streams = 64
max_header_list_size = 4096
max_send_buffer_size = 131072
data_frame_budget = 524288
max_datagram_size = 4096

[[listeners]]
listen_addr = "127.0.0.1:8443"
transport = "http2"

[listeners.auth]
enabled = false
"#,
        )
        .unwrap();

        assert_eq!(cfg.listeners[0].transport, ListenerTransport::Http2);
        assert_eq!(cfg.listeners[0].shards, 1);
        assert_eq!(cfg.http2.initial_stream_window, 2 * 1024 * 1024);
        assert_eq!(cfg.http2.initial_connection_window, 32 * 1024 * 1024);
        assert_eq!(cfg.http2.max_concurrent_streams, 64);
        assert_eq!(cfg.http2.max_header_list_size, 4096);
        assert_eq!(cfg.http2.max_send_buffer_size, 128 * 1024);
        assert_eq!(cfg.http2.data_frame_budget, 512 * 1024);
        assert_eq!(cfg.http2.max_datagram_size, 4096);
    }

    #[test]
    fn a_listener_requires_an_address_and_authentication() {
        assert!(
            parse_toml("[[listeners]]\nshards = 2\n[listeners.auth]\nenabled = false\n").is_err()
        );
        assert!(parse_toml("[[listeners]]\nlisten_addr = \"127.0.0.1:443\"\n").is_err());
    }

    #[test]
    fn legacy_single_listener_fields_are_rejected() {
        let top_level_auth = format!("[auth]\nenabled = false\n{DISABLED_LISTENER}");
        assert!(parse_toml(&top_level_auth).is_err());

        let server_listener =
            format!("[server]\nlisten_addr = \"127.0.0.1:443\"\nshards = 1\n{DISABLED_LISTENER}");
        assert!(parse_toml(&server_listener).is_err());
    }

    #[test]
    fn parse_custom_connect_protocols() {
        let cfg = parse_with_listener(
            r#"
[ip_proxy]
connect_protocols = ["connect-ip"]
"#,
        );
        assert_eq!(cfg.ip_proxy.connect_protocols, vec!["connect-ip"]);
    }

    #[test]
    fn parse_quic_section() {
        let cfg = parse_with_listener(
            r#"
[quic]
max_datagram_size = 1200
initial_max_streams_bidi = 64
enable_dgram = false
enable_udp_gso = true
enable_udp_gro = false
"#,
        );
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
        let cfg = parse_with_listener(
            r#"
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
"#,
        );
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
        let cfg = parse_with_listener(
            r#"
[udp_proxy]
enabled = false
connect_timeout_secs = 7
allow_targets = ["192.168.0.0/16"]
deny_targets = []
enable_udp_gso = true
"#,
        );
        assert!(!cfg.udp_proxy.enabled);
        assert_eq!(cfg.udp_proxy.connect_timeout_secs, 7);
        assert_eq!(cfg.udp_proxy.allow_targets, vec!["192.168.0.0/16"]);
        assert!(cfg.udp_proxy.deny_targets.is_empty());
        assert!(cfg.udp_proxy.enable_udp_gso);
    }

    #[test]
    fn parse_tcp_proxy_section() {
        let cfg = parse_with_listener(
            r#"
[tcp_proxy]
enabled = false
connect_timeout_secs = 3
allow_targets = ["192.168.0.0/16"]
deny_targets = []
"#,
        );
        assert!(!cfg.tcp_proxy.enabled);
        assert_eq!(cfg.tcp_proxy.connect_timeout_secs, 3);
        assert_eq!(cfg.tcp_proxy.allow_targets, vec!["192.168.0.0/16"]);
        assert!(cfg.tcp_proxy.deny_targets.is_empty());
    }

    #[test]
    fn parse_ip_proxy_section() {
        let cfg = parse_with_listener(
            r#"
[ip_proxy]
enabled = false
tun_name = "tun7"
tun_mtu = 1400
ipv4_pool = "172.16.0.0/12"
ipv6_pool = "fd01::/64"
"#,
        );
        assert!(!cfg.ip_proxy.enabled);
        assert_eq!(cfg.ip_proxy.tun_name, "tun7");
        assert_eq!(cfg.ip_proxy.tun_mtu, 1400);
        assert_eq!(cfg.ip_proxy.ipv4_pool, "172.16.0.0/12");
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
[server]
idle_timeout_secs = 60
max_connections = 10000
max_connections_per_ip = 64
max_pending_auth_per_ip = 8
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
retry_mode = "adaptive"
retry_connection_threshold = 64
retry_token_ttl_secs = 30

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

[[listeners]]
listen_addr = "0.0.0.0:443"
shards = 1

[listeners.auth]
enabled = true
mode = "basic"
username = ""
password_hash = ""
"#;
        let cfg = parse_toml(toml).unwrap();
        assert_eq!(cfg, ServerConfig::default());
    }

    #[test]
    fn parse_invalid_listen_addr() {
        let toml = r#"
[[listeners]]
listen_addr = "not-an-address"

[listeners.auth]
enabled = false
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn parse_invalid_type() {
        let toml = format!(
            r#"
[server]
idle_timeout_secs = "not a number"
{DISABLED_LISTENER}
"#
        );
        assert!(parse_toml(&toml).is_err());
    }

    #[test]
    fn parse_unknown_field_is_rejected() {
        let toml = format!(
            r#"
[server]
unknown_field = 42
{DISABLED_LISTENER}
"#
        );
        assert!(parse_toml(&toml).is_err());
    }
}
