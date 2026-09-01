//! Shareable, credential-free diagnostics for support requests.
//!
//! The bundle is assembled from typed configuration fields. It never copies
//! the source TOML, logs, environment variables, usernames, password hashes,
//! client labels, or public/private key material, which makes accidental
//! disclosure much harder than trying to redact arbitrary text afterwards.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use boring::x509::X509;
use serde::Serialize;

use crate::config::{ListenerTransport, ResolvedListener, ServerConfig};
use crate::host;

#[derive(Debug, Serialize)]
pub struct SupportBundle {
    schema_version: u8,
    generated_at_unix_seconds: u64,
    application: ApplicationSummary,
    host: HostSummary,
    configuration: ConfigurationSummary,
    tls: TlsSummary,
    connect_ip_diagnostics: Vec<DiagnosticSummary>,
    systemd: SystemdSummary,
    privacy: PrivacySummary,
}

#[derive(Debug, Serialize)]
struct ApplicationSummary {
    name: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct HostSummary {
    os: &'static str,
    architecture: &'static str,
    kernel_release: Option<String>,
    logical_cpus: Option<usize>,
}

#[derive(Debug, Serialize)]
struct ConfigurationSummary {
    valid: bool,
    config_file: FileSummary,
    listeners: Vec<ListenerSummary>,
    registered_client_count: usize,
    server: ServerLimitsSummary,
    protocols: ProtocolSummary,
    quic: QuicSummary,
    http2: Http2Summary,
    observability_listen_addr: Option<String>,
}

#[derive(Debug, Serialize)]
struct FileSummary {
    exists: bool,
    regular_file: bool,
    size_bytes: Option<u64>,
    #[cfg(unix)]
    mode: Option<String>,
    #[cfg(unix)]
    group_or_other_writable: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ListenerSummary {
    listen_addr: String,
    transport: &'static str,
    shards: usize,
    max_datagram_size: Option<usize>,
    authentication: &'static str,
    stealth: bool,
    basic_user_count: usize,
}

#[derive(Debug, Serialize)]
struct ServerLimitsSummary {
    idle_timeout_secs: u64,
    max_connections: usize,
    max_connections_per_ip: usize,
    max_pending_auth_per_ip: usize,
    max_tunnels_per_connection: usize,
}

#[derive(Debug, Serialize)]
struct ProtocolSummary {
    connect_tcp_enabled: bool,
    connect_udp_enabled: bool,
    connect_ip_enabled: bool,
    tcp_connect_timeout_secs: u64,
    udp_connect_timeout_secs: u64,
    tcp_allow_rule_count: usize,
    tcp_deny_rule_count: usize,
    udp_allow_rule_count: usize,
    udp_deny_rule_count: usize,
    tun_name: Option<String>,
    tun_mtu: Option<usize>,
    tun_offload: Option<bool>,
}

#[derive(Debug, Serialize)]
struct QuicSummary {
    max_datagram_size: usize,
    congestion_controller: String,
    udp_gso: bool,
    udp_gro: bool,
    path_mtu_discovery: bool,
    datagram_receive_queue: usize,
    datagram_send_queue: usize,
}

#[derive(Debug, Serialize)]
struct Http2Summary {
    initial_stream_window: u32,
    initial_connection_window: u32,
    max_concurrent_streams: u32,
    max_datagram_size: usize,
}

#[derive(Debug, Serialize)]
struct TlsSummary {
    certificate_file: FileSummary,
    private_key_file: FileSummary,
    certificate_not_before: Option<String>,
    certificate_not_after: Option<String>,
}

#[derive(Debug, Serialize)]
struct DiagnosticSummary {
    level: &'static str,
    name: &'static str,
}

#[derive(Debug, Default, Serialize)]
struct SystemdSummary {
    available: bool,
    load_state: Option<String>,
    active_state: Option<String>,
    sub_state: Option<String>,
    unit_file_state: Option<String>,
}

#[derive(Debug, Serialize)]
struct PrivacySummary {
    excluded: [&'static str; 8],
}

/// Collect a support report from already parsed and validated configuration.
pub fn collect(
    config_path: &Path,
    config: &ServerConfig,
    listeners: &[ResolvedListener],
) -> SupportBundle {
    let generated_at_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let certificate = read_certificate_window(&config.tls.cert_path);
    let connect_ip_diagnostics = host::diagnose_connect_ip(&config.ip_proxy)
        .checks()
        .iter()
        .map(|check| DiagnosticSummary {
            level: check.level.label(),
            name: check.name,
        })
        .collect();

    SupportBundle {
        schema_version: 1,
        generated_at_unix_seconds,
        application: ApplicationSummary {
            name: "masque-server",
            version: env!("CARGO_PKG_VERSION"),
        },
        host: HostSummary {
            os: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
            kernel_release: command_line("uname", &["-r"]),
            logical_cpus: std::thread::available_parallelism().ok().map(usize::from),
        },
        configuration: ConfigurationSummary {
            valid: true,
            config_file: file_summary(config_path),
            listeners: listeners
                .iter()
                .map(|listener| ListenerSummary {
                    listen_addr: listener.listen_addr.to_string(),
                    transport: listener.transport.as_str(),
                    shards: listener.shards,
                    max_datagram_size: (listener.transport == ListenerTransport::Http3).then(
                        || listener.effective_quic_max_datagram_size(config.quic.max_datagram_size),
                    ),
                    authentication: auth_label(&listener.auth),
                    stealth: listener.auth.stealth_enabled(),
                    basic_user_count: basic_user_count(&listener.auth),
                })
                .collect(),
            registered_client_count: config.clients.len(),
            server: ServerLimitsSummary {
                idle_timeout_secs: config.server.idle_timeout_secs,
                max_connections: config.server.max_connections,
                max_connections_per_ip: config.server.max_connections_per_ip,
                max_pending_auth_per_ip: config.server.max_pending_auth_per_ip,
                max_tunnels_per_connection: config.server.max_tunnels_per_connection,
            },
            protocols: ProtocolSummary {
                connect_tcp_enabled: config.tcp_proxy.enabled,
                connect_udp_enabled: config.udp_proxy.enabled,
                connect_ip_enabled: config.ip_proxy.enabled,
                tcp_connect_timeout_secs: config.tcp_proxy.connect_timeout_secs,
                udp_connect_timeout_secs: config.udp_proxy.connect_timeout_secs,
                tcp_allow_rule_count: config.tcp_proxy.allow_targets.len(),
                tcp_deny_rule_count: config.tcp_proxy.deny_targets.len(),
                udp_allow_rule_count: config.udp_proxy.allow_targets.len(),
                udp_deny_rule_count: config.udp_proxy.deny_targets.len(),
                tun_name: config
                    .ip_proxy
                    .enabled
                    .then(|| config.ip_proxy.tun_name.clone()),
                tun_mtu: config.ip_proxy.enabled.then_some(config.ip_proxy.tun_mtu),
                tun_offload: config
                    .ip_proxy
                    .enabled
                    .then_some(config.ip_proxy.tun_offload),
            },
            quic: QuicSummary {
                max_datagram_size: config.quic.max_datagram_size,
                congestion_controller: config.quic.cc_algorithm.clone(),
                udp_gso: config.quic.enable_udp_gso,
                udp_gro: config.quic.enable_udp_gro,
                path_mtu_discovery: config.quic.discover_pmtu,
                datagram_receive_queue: config.quic.dgram_recv_queue_len,
                datagram_send_queue: config.quic.dgram_send_queue_len,
            },
            http2: Http2Summary {
                initial_stream_window: config.http2.initial_stream_window,
                initial_connection_window: config.http2.initial_connection_window,
                max_concurrent_streams: config.http2.max_concurrent_streams,
                max_datagram_size: config.http2.max_datagram_size,
            },
            observability_listen_addr: config
                .observability
                .listen_addr
                .map(|address| address.to_string()),
        },
        tls: TlsSummary {
            certificate_file: file_summary(&config.tls.cert_path),
            private_key_file: file_summary(&config.tls.key_path),
            certificate_not_before: certificate
                .as_ref()
                .map(|cert| cert.not_before().to_string()),
            certificate_not_after: certificate
                .as_ref()
                .map(|cert| cert.not_after().to_string()),
        },
        connect_ip_diagnostics,
        systemd: systemd_summary(),
        privacy: PrivacySummary {
            excluded: [
                "raw configuration",
                "usernames and password hashes",
                "client names and assigned addresses",
                "certificate subjects and serial numbers",
                "public and private key material",
                "environment variables",
                "logs",
                "traffic destinations and counters",
            ],
        },
    }
}

/// Serialize a support report using a stable, human-readable JSON layout.
pub fn to_json(bundle: &SupportBundle) -> anyhow::Result<String> {
    let mut json =
        serde_json::to_string_pretty(bundle).context("failed to serialize support bundle")?;
    json.push('\n');
    Ok(json)
}

/// Create a private support report without replacing an existing path.
pub fn write(path: &Path, bundle: &SupportBundle) -> anyhow::Result<()> {
    let json = to_json(bundle)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).with_context(|| {
        format!(
            "failed to create {} (refusing to overwrite an existing path)",
            path.display()
        )
    })?;
    file.write_all(json.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", path.display()))
}

fn auth_label(auth: &crate::config::AuthSection) -> &'static str {
    if auth.client_cert_enabled() {
        "client_cert"
    } else if auth.basic_enabled() {
        "basic"
    } else {
        "disabled"
    }
}

fn basic_user_count(auth: &crate::config::AuthSection) -> usize {
    if !auth.basic_enabled() {
        0
    } else if auth.users.is_empty() {
        usize::from(!auth.username.is_empty())
    } else {
        auth.users.len()
    }
}

fn read_certificate_window(path: &Path) -> Option<X509> {
    let pem = fs::read(path).ok()?;
    X509::stack_from_pem(&pem).ok()?.into_iter().next()
}

fn file_summary(path: &Path) -> FileSummary {
    let metadata = fs::metadata(path).ok();
    #[cfg(unix)]
    let mode = metadata.as_ref().map(|metadata| {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o7777
    });
    FileSummary {
        exists: metadata.is_some(),
        regular_file: metadata.as_ref().is_some_and(std::fs::Metadata::is_file),
        size_bytes: metadata.as_ref().map(std::fs::Metadata::len),
        #[cfg(unix)]
        mode: mode.map(|mode| format!("{mode:04o}")),
        #[cfg(unix)]
        group_or_other_writable: mode.map(|mode| mode & 0o022 != 0),
    }
}

fn command_line(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn systemd_summary() -> SystemdSummary {
    let output = Command::new("systemctl")
        .args([
            "show",
            "masque.service",
            "--no-pager",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=UnitFileState",
        ])
        .output();
    let Ok(output) = output else {
        return SystemdSummary::default();
    };
    if !output.status.success() {
        return SystemdSummary::default();
    }
    let mut summary = SystemdSummary {
        available: true,
        ..SystemdSummary::default()
    };
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = (!value.is_empty()).then(|| value.to_owned());
        match key {
            "LoadState" => summary.load_state = value,
            "ActiveState" => summary.active_state = value,
            "SubState" => summary.sub_state = value,
            "UnitFileState" => summary.unit_file_state = value,
            _ => {}
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthMode, BasicUser, ListenerTransport};

    #[test]
    fn serialized_bundle_never_contains_credentials_or_roster_identity() {
        let mut config = ServerConfig::default();
        config.ip_proxy.enabled = false;
        config.clients.push(crate::config::ClientEntry {
            name: "PRIVATE-CLIENT-LABEL".into(),
            public_key: "PRIVATE-PUBLIC-KEY".into(),
            ipv4: Some("10.89.0.99".into()),
            ipv6: None,
        });
        config.listeners[0].auth.enabled = true;
        config.listeners[0].auth.mode = AuthMode::Basic;
        config.listeners[0].auth.username.clear();
        config.listeners[0].auth.password_hash.clear();
        config.listeners[0].auth.users = vec![BasicUser {
            username: "PRIVATE-USERNAME".into(),
            password_hash: "PRIVATE-PASSWORD-HASH".into(),
        }];
        let listeners = vec![ResolvedListener {
            listen_addr: config.listeners[0].listen_addr,
            transport: ListenerTransport::Http3,
            shards: 1,
            max_datagram_size: None,
            auth: config.listeners[0].auth.clone(),
        }];

        let json = to_json(&collect(
            Path::new("/path/that/does/not/embed/the/config/name"),
            &config,
            &listeners,
        ))
        .unwrap();
        for secret in [
            "PRIVATE-CLIENT-LABEL",
            "PRIVATE-PUBLIC-KEY",
            "PRIVATE-USERNAME",
            "PRIVATE-PASSWORD-HASH",
            "10.89.0.99",
        ] {
            assert!(!json.contains(secret), "bundle leaked {secret}");
        }
        assert!(json.contains("\"basic_user_count\": 1"));
        assert!(json.contains("\"stealth\": false"));
        assert!(json.contains("\"registered_client_count\": 1"));
    }
}
