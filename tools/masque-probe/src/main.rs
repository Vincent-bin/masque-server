mod credentials;
mod endpoint;
mod http2;
mod http3;
mod identity;
mod protocol;
mod report;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};

use credentials::{BasicCredentials, Credentials};
use endpoint::Authority;
use identity::ClientIdentity;
use report::{CheckResult, ProbeFailure, ProbeReport};

#[derive(Parser)]
#[command(
    name = "masque-probe",
    version,
    about = "Diagnose a MASQUE endpoint from the client network"
)]
struct Cli {
    /// Public endpoint in host:port form, for example proxy.example.com:8449.
    endpoint: String,

    /// HTTP transport to test. Auto tries HTTP/3 first, then HTTP/2 on the same port.
    #[arg(long, value_enum, default_value_t = Transport::Auto)]
    transport: Transport,

    /// TLS DNS name. Defaults to the endpoint hostname for Basic auth and to
    /// the usque-compatible SNI for a certificate enrollment.
    #[arg(long)]
    server_name: Option<String>,

    /// Connect to this IP while retaining the endpoint hostname for TLS and HTTP.
    /// Useful when a local proxy returns synthetic DNS addresses.
    #[arg(long)]
    resolve: Option<std::net::IpAddr>,

    /// Bind the HTTP/3 UDP socket to this network interface (for example en0).
    #[arg(long)]
    interface: Option<String>,

    /// Basic username. The password is deliberately never accepted as an argument.
    #[arg(long, requires = "password_stdin", conflicts_with = "client_config")]
    username: Option<String>,

    /// Read the Basic password from stdin.
    #[arg(long, requires = "username", conflicts_with = "client_config")]
    password_stdin: bool,

    /// Enrollment JSON containing private_key and endpoint_pub_key.
    #[arg(long, conflicts_with_all = ["username", "password_stdin", "insecure", "ca_cert"])]
    client_config: Option<PathBuf>,

    /// TCP target used to verify standard CONNECT.
    #[arg(long, default_value = "example.com:443", conflicts_with = "skip_tcp")]
    tcp_target: String,

    /// Skip the standard CONNECT target check.
    #[arg(long)]
    skip_tcp: bool,

    /// DNS server used to verify CONNECT-UDP with a real query.
    #[arg(long, default_value = "1.1.1.1:53", conflicts_with = "skip_udp")]
    udp_target: String,

    /// UDP validation payload: a DNS query, or a byte-for-byte echo payload.
    #[arg(long, value_enum, default_value_t = UdpMode::Dns)]
    udp_mode: UdpMode,

    /// Skip the CONNECT-UDP target check.
    #[arg(long)]
    skip_udp: bool,

    /// Also check CONNECT-IP negotiation and address assignment.
    #[arg(long)]
    connect_ip: bool,

    /// Per-stage timeout in seconds.
    #[arg(
        long,
        default_value_t = 8,
        value_parser = clap::value_parser!(u64).range(1..=60)
    )]
    timeout: u64,

    /// Trust this PEM CA file in addition to the platform roots.
    #[arg(long, conflicts_with = "insecure")]
    ca_cert: Option<PathBuf>,

    /// Disable public CA and hostname verification. Never disables enrollment-key pinning.
    #[arg(long)]
    insecure: bool,

    /// Emit one stable JSON report instead of human-readable output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Transport {
    Auto,
    Http3,
    Http2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum UdpMode {
    Dns,
    Echo,
}

impl Transport {
    fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Http3 => "http3",
            Self::Http2 => "http2",
        }
    }
}

enum ActiveSession {
    Http3(Box<http3::Session>),
    Http2(http2::Session),
}

impl ActiveSession {
    fn probe_tcp(
        &mut self,
        target: &Authority,
        credentials: &Credentials,
    ) -> Result<String, ProbeFailure> {
        match self {
            Self::Http3(session) => session.probe_tcp(target, credentials),
            Self::Http2(session) => session.probe_tcp(target, credentials),
        }
    }

    fn probe_udp(
        &mut self,
        target: &Authority,
        credentials: &Credentials,
        udp_mode: UdpMode,
    ) -> Result<String, ProbeFailure> {
        match self {
            Self::Http3(session) => {
                session.probe_udp(target, credentials, udp_mode == UdpMode::Dns)
            }
            Self::Http2(session) => {
                session.probe_udp(target, credentials, udp_mode == UdpMode::Dns)
            }
        }
    }

    fn probe_connect_ip(&mut self, credentials: &Credentials) -> Result<String, ProbeFailure> {
        match self {
            Self::Http3(session) => session.probe_connect_ip(credentials),
            Self::Http2(session) => session.probe_connect_ip(credentials),
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let mut report = run_probe(&cli);
    report.finish();

    if cli.json {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("failed to serialize probe report: {error}");
                std::process::exit(2);
            }
        }
    } else {
        report.print_human();
    }
    if !report.success {
        std::process::exit(1);
    }
}

fn run_probe(cli: &Cli) -> ProbeReport {
    let mut report = ProbeReport::new(cli.endpoint.clone(), cli.transport.as_str());
    let endpoint = match Authority::parse(&cli.endpoint, "MASQUE endpoint") {
        Ok(endpoint) => endpoint,
        Err(failure) => {
            report
                .checks
                .push(CheckResult::fail("endpoint", failure, Instant::now()));
            return report;
        }
    };

    let credentials_started = Instant::now();
    let credentials = match load_credentials(cli) {
        Ok(credentials) => credentials,
        Err(failure) => {
            report.checks.push(CheckResult::fail(
                "credentials",
                failure,
                credentials_started,
            ));
            return report;
        }
    };
    report.checks.push(CheckResult::pass(
        "credentials",
        "CREDENTIALS_READY",
        format!("authentication mode: {}", credentials.label()),
        credentials_started,
    ));

    let server_name = cli.server_name.clone().unwrap_or_else(|| {
        if credentials.client_identity().is_some() {
            "consumer-masque.cloudflareclient.com".into()
        } else {
            endpoint.host.clone()
        }
    });
    if credentials.client_identity().is_none()
        && let Err(failure) = endpoint::validate_server_name(&server_name)
    {
        report.checks.push(CheckResult::fail(
            "tls_server_name",
            failure,
            Instant::now(),
        ));
        return report;
    }

    if cli.insecure {
        report.checks.push(CheckResult::warning(
            "tls_verification",
            "TLS_VERIFICATION_DISABLED",
            "certificate-chain and hostname verification are disabled for this probe",
            Instant::now(),
        ));
    }

    let dns_started = Instant::now();
    let addresses = match cli.resolve {
        Some(address) => {
            let address = std::net::SocketAddr::new(address, endpoint.port);
            report.checks.push(CheckResult::pass(
                "dns",
                "DNS_BYPASSED",
                format!(
                    "using {address} from --resolve while retaining {}",
                    endpoint.host
                ),
                dns_started,
            ));
            vec![address]
        }
        None => match endpoint.resolve() {
            Ok(addresses) => {
                let detail = format!(
                    "{} resolved to {}",
                    endpoint.host,
                    addresses
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                if addresses
                    .iter()
                    .any(|address| is_benchmarking_ip(address.ip()))
                {
                    report.checks.push(CheckResult::warning(
                    "dns",
                    "DNS_FAKE_IP_DETECTED",
                    format!(
                        "{detail}; 198.18.0.0/15 is commonly used by fake-IP DNS, use --resolve with the real server IP if direct probing fails"
                    ),
                    dns_started,
                ));
                } else {
                    report.checks.push(CheckResult::pass(
                        "dns",
                        "DNS_RESOLVED",
                        detail,
                        dns_started,
                    ));
                }
                addresses
            }
            Err(failure) => {
                report
                    .checks
                    .push(CheckResult::fail("dns", failure, dns_started));
                return report;
            }
        },
    };

    let timeout = Duration::from_secs(cli.timeout);
    let mut session = match connect_transport(
        cli,
        &endpoint,
        &addresses,
        &server_name,
        &credentials,
        timeout,
        &mut report,
    ) {
        Some(session) => session,
        None => return report,
    };

    if cli.skip_tcp {
        report.checks.push(CheckResult::skipped(
            "connect_tcp",
            "disabled by --skip-tcp",
        ));
    } else {
        run_target_check(
            "connect_tcp",
            &cli.tcp_target,
            &credentials,
            &mut report,
            |target, credentials| session.probe_tcp(target, credentials),
        );
    }

    if cli.skip_udp {
        report.checks.push(CheckResult::skipped(
            "connect_udp",
            "disabled by --skip-udp",
        ));
    } else {
        run_target_check(
            "connect_udp",
            &cli.udp_target,
            &credentials,
            &mut report,
            |target, credentials| session.probe_udp(target, credentials, cli.udp_mode),
        );
    }

    if cli.connect_ip {
        let started = Instant::now();
        match session.probe_connect_ip(&credentials) {
            Ok(detail) => report.checks.push(CheckResult::pass(
                "connect_ip",
                "CONNECT_IP_READY",
                detail,
                started,
            )),
            Err(failure) => report
                .checks
                .push(CheckResult::fail("connect_ip", failure, started)),
        }
    } else {
        report.checks.push(CheckResult::skipped(
            "connect_ip",
            "not requested; pass --connect-ip to check negotiation",
        ));
    }

    report
}

fn load_credentials(cli: &Cli) -> Result<Credentials, ProbeFailure> {
    if let Some(path) = &cli.client_config {
        return ClientIdentity::from_enrollment(path).map(Credentials::ClientCertificate);
    }
    if let Some(username) = &cli.username {
        return BasicCredentials::from_stdin(username.clone()).map(Credentials::Basic);
    }
    Ok(Credentials::None)
}

#[allow(clippy::too_many_arguments)]
fn connect_transport(
    cli: &Cli,
    endpoint: &Authority,
    addresses: &[std::net::SocketAddr],
    server_name: &str,
    credentials: &Credentials,
    timeout: Duration,
    report: &mut ProbeReport,
) -> Option<ActiveSession> {
    if matches!(cli.transport, Transport::Auto | Transport::Http3) {
        let started = Instant::now();
        match http3::Session::connect(
            addresses,
            endpoint,
            server_name,
            credentials,
            cli.insecure,
            cli.ca_cert.as_deref(),
            cli.interface.as_deref(),
            timeout,
        ) {
            Ok((session, peer)) => {
                report.selected_transport = Some("http3".into());
                report.checks.push(CheckResult::pass(
                    "http3_handshake",
                    "HTTP3_READY",
                    format!(
                        "QUIC, TLS, h3 ALPN, Extended CONNECT and HTTP Datagrams ready via {peer}"
                    ),
                    started,
                ));
                return Some(ActiveSession::Http3(Box::new(session)));
            }
            Err(failure) if cli.transport == Transport::Auto => {
                report.checks.push(CheckResult::warning(
                    "http3_handshake",
                    failure.code,
                    format!("{}; trying HTTP/2 fallback", failure.detail),
                    started,
                ));
            }
            Err(failure) => {
                report
                    .checks
                    .push(CheckResult::fail("http3_handshake", failure, started));
                return None;
            }
        }
    }

    let started = Instant::now();
    match http2::Session::connect(
        addresses,
        endpoint,
        server_name,
        credentials,
        cli.insecure,
        cli.ca_cert.as_deref(),
        timeout,
    ) {
        Ok((session, peer)) => {
            report.selected_transport = Some("http2".into());
            report.checks.push(CheckResult::pass(
                "http2_handshake",
                "HTTP2_READY",
                format!("TCP, TLS, h2 ALPN and Extended CONNECT ready via {peer}"),
                started,
            ));
            Some(ActiveSession::Http2(session))
        }
        Err(failure) => {
            report
                .checks
                .push(CheckResult::fail("http2_handshake", failure, started));
            None
        }
    }
}

fn is_benchmarking_ip(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(address) => {
            let octets = address.octets();
            octets[0] == 198 && matches!(octets[1], 18 | 19)
        }
        std::net::IpAddr::V6(_) => false,
    }
}

fn run_target_check(
    name: &str,
    value: &str,
    credentials: &Credentials,
    report: &mut ProbeReport,
    mut run: impl FnMut(&Authority, &Credentials) -> Result<String, ProbeFailure>,
) {
    let started = Instant::now();
    let target = match Authority::parse(value, "probe target") {
        Ok(target) => target,
        Err(failure) => {
            report
                .checks
                .push(CheckResult::fail(name, failure, started));
            return;
        }
    };
    match run(&target, credentials) {
        Ok(detail) => report
            .checks
            .push(CheckResult::pass(name, "ROUND_TRIP_OK", detail, started)),
        Err(failure) => report
            .checks
            .push(CheckResult::fail(name, failure, started)),
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn default_targets_are_public_and_well_formed() {
        let cli = Cli::parse_from(["masque-probe", "proxy.example:443"]);
        assert!(Authority::parse(&cli.tcp_target, "target").is_ok());
        assert!(Authority::parse(&cli.udp_target, "target").is_ok());
        assert_eq!(cli.transport, Transport::Auto);
    }

    #[test]
    fn recognizes_the_rfc_2544_range_used_by_fake_ip_dns() {
        assert!(is_benchmarking_ip("198.18.0.1".parse().unwrap()));
        assert!(is_benchmarking_ip("198.19.255.254".parse().unwrap()));
        assert!(!is_benchmarking_ip("198.20.0.1".parse().unwrap()));
    }
}
