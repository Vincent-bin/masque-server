use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::ec::{EcGroup, EcKey};
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::pkey::PKey;
use boring::x509::{X509Builder, X509NameBuilder};
use masque::config::{AuthMode, BasicUser, ClientEntry, ListenerTransport, ServerConfig};
use masque::server::Server;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, UdpSocket};

struct TempTls {
    directory: PathBuf,
    cert: PathBuf,
    key: PathBuf,
}

impl TempTls {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "masque-probe-it-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let cert = directory.join("server.crt");
        let key = directory.join("server.key");

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key_pair = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "localhost").unwrap();
        let name = name.build();
        let mut certificate = X509Builder::new().unwrap();
        certificate.set_version(2).unwrap();
        certificate
            .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        certificate.set_pubkey(&key_pair).unwrap();
        certificate
            .sign(&key_pair, MessageDigest::sha256())
            .unwrap();
        std::fs::write(&cert, certificate.build().to_pem().unwrap()).unwrap();
        std::fs::write(
            &key,
            key_pair.ec_key().unwrap().private_key_to_pem().unwrap(),
        )
        .unwrap();

        Self {
            directory,
            cert,
            key,
        }
    }
}

impl Drop for TempTls {
    fn drop(&mut self) {
        std::fs::remove_file(&self.cert).ok();
        std::fs::remove_file(&self.key).ok();
        std::fs::remove_dir(&self.directory).ok();
    }
}

async fn spawn_echo() -> (
    SocketAddr,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(address).await.unwrap();

    let tcp_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = tcp.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                loop {
                    let Ok(length) = stream.read(&mut buffer).await else {
                        return;
                    };
                    if length == 0 || stream.write_all(&buffer[..length]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    let udp_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 65_535];
        loop {
            let Ok((length, peer)) = udp.recv_from(&mut buffer).await else {
                return;
            };
            if udp.send_to(&buffer[..length], peer).await.is_err() {
                return;
            }
        }
    });
    (address, tcp_task, udp_task)
}

async fn spawn_server(
    tls: &TempTls,
    transport: ListenerTransport,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    spawn_server_with_udp_policy(tls, transport, true).await
}

async fn spawn_server_with_udp_policy(
    tls: &TempTls,
    transport: ListenerTransport,
    allow_loopback_udp: bool,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let mut config = ServerConfig::default();
    config.tls.cert_path = tls.cert.clone();
    config.tls.key_path = tls.key.clone();
    config.listeners[0].listen_addr = "127.0.0.1:0".parse().unwrap();
    config.listeners[0].transport = transport;
    config.listeners[0].auth.username.clear();
    config.listeners[0].auth.password_hash.clear();
    config.listeners[0].auth.users = vec![BasicUser {
        username: "probe-user".into(),
        password_hash: masque::auth::hash_password(b"probe-password").unwrap(),
    }];
    config.tcp_proxy.enabled = true;
    config.tcp_proxy.allow_targets = vec!["127.0.0.0/8".into()];
    config.tcp_proxy.deny_targets.clear();
    config.udp_proxy.enabled = true;
    if allow_loopback_udp {
        config.udp_proxy.allow_targets = vec!["127.0.0.0/8".into()];
        config.udp_proxy.deny_targets.clear();
    } else {
        config.udp_proxy.allow_targets = vec!["0.0.0.0/0".into()];
        config.udp_proxy.deny_targets = vec!["127.0.0.0/8".into()];
    }
    // Exercise CONNECT-IP negotiation without creating a host network device.
    config.ip_proxy.enabled = true;
    config.ip_proxy.require_tun = false;
    config.ip_proxy.tun_name = "invalid/tun/name".into();

    let mut server = Server::bind(config).await.unwrap();
    let address = server.listen_addrs()[0];
    let task = tokio::spawn(async move {
        server.run().await.unwrap();
    });
    (address, task)
}

async fn spawn_certificate_server(
    tls: &TempTls,
    transport: ListenerTransport,
    public_key: String,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let mut config = ServerConfig::default();
    config.tls.cert_path = tls.cert.clone();
    config.tls.key_path = tls.key.clone();
    config.listeners[0].listen_addr = "127.0.0.1:0".parse().unwrap();
    config.listeners[0].transport = transport;
    config.listeners[0].auth.mode = AuthMode::ClientCert;
    config.listeners[0].auth.username.clear();
    config.listeners[0].auth.password_hash.clear();
    config.listeners[0].auth.users.clear();
    config.clients = vec![ClientEntry {
        name: "probe-client".into(),
        public_key,
        ipv4: None,
        ipv6: None,
    }];
    config.tcp_proxy.enabled = true;
    config.tcp_proxy.allow_targets = vec!["127.0.0.0/8".into()];
    config.tcp_proxy.deny_targets.clear();
    config.udp_proxy.enabled = true;
    config.udp_proxy.allow_targets = vec!["127.0.0.0/8".into()];
    config.udp_proxy.deny_targets.clear();
    // Exercise CONNECT-IP negotiation without creating a host network device.
    config.ip_proxy.enabled = true;
    config.ip_proxy.require_tun = false;
    config.ip_proxy.tun_name = "invalid/tun/name".into();

    let mut server = Server::bind(config).await.unwrap();
    let address = server.listen_addrs()[0];
    let task = tokio::spawn(async move {
        server.run().await.unwrap();
    });
    (address, task)
}

fn run_probe(endpoint: SocketAddr, target: SocketAddr, transport: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_masque-probe"))
        .args([
            &endpoint.to_string(),
            "--transport",
            transport,
            "--username",
            "probe-user",
            "--password-stdin",
            "--insecure",
            "--tcp-mode",
            "echo",
            "--tcp-target",
            &target.to_string(),
            "--udp-target",
            &target.to_string(),
            "--udp-mode",
            "echo",
            "--connect-ip",
            "--ip-setup-only",
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"probe-password")
        .unwrap();
    child.wait_with_output().unwrap()
}

fn assert_probe_passed(output: std::process::Output, transport: &str) {
    assert!(
        output.status.success(),
        "probe failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], true);
    assert_eq!(report["selected_transport"], transport);
    let checks = report["checks"].as_array().unwrap();
    for name in ["connect_tcp", "connect_udp", "connect_ip"] {
        let check = checks.iter().find(|check| check["name"] == name).unwrap();
        assert_eq!(
            check["status"],
            if name == "connect_ip" {
                "warning"
            } else {
                "pass"
            }
        );
        if name == "connect_ip" {
            assert_eq!(check["code"], "CONNECT_IP_SETUP_ONLY");
            assert!(
                check["detail"]
                    .as_str()
                    .unwrap()
                    .starts_with("CONNECT-IP assigned 2 address(es);")
            );
        }
    }
}

fn run_certificate_probe(
    endpoint: SocketAddr,
    target: SocketAddr,
    transport: &str,
    client_config: &Path,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_masque-probe"))
        .args([
            &endpoint.to_string(),
            "--transport",
            transport,
            "--client-config",
            client_config.to_str().unwrap(),
            "--tcp-mode",
            "echo",
            "--tcp-target",
            &target.to_string(),
            "--udp-target",
            &target.to_string(),
            "--udp-mode",
            "echo",
            "--connect-ip",
            "--ip-setup-only",
            "--json",
        ])
        .output()
        .unwrap()
}

async fn check_basic_probe(transport: &str, configured: ListenerTransport) {
    let tls = TempTls::new();
    let (target, tcp_echo, udp_echo) = spawn_echo().await;
    let (endpoint, server) = spawn_server(&tls, configured).await;
    let output = tokio::task::block_in_place(|| run_probe(endpoint, target, transport));
    assert_probe_passed(output, transport);

    server.abort();
    tcp_echo.abort();
    udp_echo.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn released_probe_checks_basic_http2_end_to_end() {
    check_basic_probe("http2", ListenerTransport::Http2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn released_probe_checks_basic_http3_end_to_end() {
    check_basic_probe("http3", ListenerTransport::Http3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http3_udp_policy_failure_is_returned_instead_of_an_early_200() {
    let tls = TempTls::new();
    let (target, tcp_echo, udp_echo) = spawn_echo().await;
    let (endpoint, server) =
        spawn_server_with_udp_policy(&tls, ListenerTransport::Http3, false).await;

    let output = tokio::task::block_in_place(|| run_probe(endpoint, target, "http3"));
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let udp = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["name"] == "connect_udp")
        .unwrap();
    assert_eq!(udp["status"], "fail");
    assert_eq!(udp["code"], "TARGET_POLICY_DENIED");
    assert!(udp["detail"].as_str().unwrap().contains("HTTP 403"));

    server.abort();
    tcp_echo.abort();
    udp_echo.abort();
}

async fn check_certificate_probe(transport: &str, configured: ListenerTransport) {
    let tls = TempTls::new();
    let pair = masque::enroll::generate_client_key().unwrap();
    let server_key = masque::enroll::server_public_key_pem(&tls.cert).unwrap();
    let enrollment_path = tls.directory.join("client.json");
    let enrollment = masque::enroll::client_config_json(
        &pair.private_key_b64,
        &server_key,
        Ipv4Addr::LOCALHOST.into(),
        None,
        None,
    );
    std::fs::write(&enrollment_path, enrollment).unwrap();
    let (target, tcp_echo, udp_echo) = spawn_echo().await;

    let (endpoint, server) =
        spawn_certificate_server(&tls, configured, pair.public_key_b64.clone()).await;
    let output = tokio::task::block_in_place(|| {
        run_certificate_probe(endpoint, target, transport, &enrollment_path)
    });
    assert_probe_passed(output, transport);

    server.abort();
    tcp_echo.abort();
    udp_echo.abort();
    std::fs::remove_file(enrollment_path).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn released_probe_checks_certificate_http2_end_to_end() {
    check_certificate_probe("http2", ListenerTransport::Http2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn released_probe_checks_certificate_http3_end_to_end() {
    check_certificate_probe("http3", ListenerTransport::Http3).await;
}

fn run_payload_probe(
    endpoint: SocketAddr,
    transport: &str,
    options: &[String],
) -> serde_json::Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_masque-probe"))
        .args([
            &endpoint.to_string(),
            "--transport",
            transport,
            "--username",
            "probe-user",
            "--password-stdin",
            "--insecure",
            "--json",
            "--timeout",
            // Authentication and CONNECT setup share the runner with other
            // tests. Give them enough time to reach the payload stage under
            // CI load; the tested silent payload must still time out.
            "5",
        ])
        .args(options)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"probe-password")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    serde_json::from_slice(&output.stdout).expect("probe must return a structured failure")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accepted_connect_without_matching_payload_fails_on_both_transports() {
    for transport in [ListenerTransport::Http2, ListenerTransport::Http3] {
        let tls = TempTls::new();
        let (endpoint, server) = spawn_server(&tls, transport).await;
        for silent in [false, true] {
            let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let address = target.local_addr().unwrap();
            let origin = tokio::spawn(async move {
                let (mut stream, _) = target.accept().await.unwrap();
                let mut request = [0; 128];
                let received = stream.read(&mut request).await.unwrap();
                assert!(received > 0, "must send real payload after CONNECT 200");
                if silent {
                    // Stay silent longer than the probe's per-stage deadline.
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                } else {
                    stream.write_all(b"not-the-request").await.unwrap();
                }
            });
            let options = vec![
                "--skip-udp".into(),
                "--tcp-target".into(),
                address.to_string(),
                "--tcp-mode".into(),
                "echo".into(),
            ];
            let report = tokio::task::spawn_blocking(move || {
                run_payload_probe(endpoint, transport.as_str(), &options)
            })
            .await
            .unwrap();
            assert_eq!(report["success"], false);
            let check = report["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|check| check["name"] == "connect_tcp")
                .unwrap();
            assert_eq!(check["status"], "fail");
            assert_eq!(
                check["code"],
                if silent {
                    "TCP_RESPONSE_TIMEOUT"
                } else {
                    "TCP_RESPONSE_INVALID"
                },
                "transport={transport:?}, silent={silent}"
            );
            origin.abort();
        }
        server.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ip_assignment_without_forwarding_is_not_success_on_either_transport() {
    for transport in [ListenerTransport::Http2, ListenerTransport::Http3] {
        let tls = TempTls::new();
        let (endpoint, server) = spawn_server(&tls, transport).await;
        let options = [
            "--skip-tcp",
            "--skip-udp",
            "--connect-ip",
            "--ip-target",
            "198.51.100.1:9999",
            "--ip-mode",
            "echo",
        ]
        .map(String::from);
        let report = tokio::task::spawn_blocking(move || {
            run_payload_probe(endpoint, transport.as_str(), &options)
        })
        .await
        .unwrap();
        assert_eq!(report["success"], false);
        let check = report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["name"] == "connect_ip")
            .unwrap();
        assert_eq!(check["status"], "fail");
        assert_eq!(
            check["code"], "CONNECT_IP_RESPONSE_TIMEOUT",
            "transport={transport:?}"
        );
        server.abort();
    }
}
