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
    config.ip_proxy.enabled = false;

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
    config.ip_proxy.enabled = false;

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
            "--tcp-target",
            &target.to_string(),
            "--udp-target",
            &target.to_string(),
            "--udp-mode",
            "echo",
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
    for name in ["connect_tcp", "connect_udp"] {
        let check = checks.iter().find(|check| check["name"] == name).unwrap();
        assert_eq!(check["status"], "pass");
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
            "--tcp-target",
            &target.to_string(),
            "--udp-target",
            &target.to_string(),
            "--udp-mode",
            "echo",
            "--json",
        ])
        .output()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn released_probe_checks_basic_http2_and_http3_end_to_end() {
    let tls = TempTls::new();
    let (target, tcp_echo, udp_echo) = spawn_echo().await;

    for (transport, configured) in [
        ("http3", ListenerTransport::Http3),
        ("http2", ListenerTransport::Http2),
    ] {
        let (endpoint, server) = spawn_server(&tls, configured).await;
        let output = tokio::task::block_in_place(|| run_probe(endpoint, target, transport));
        assert_probe_passed(output, transport);
        server.abort();
    }

    tcp_echo.abort();
    udp_echo.abort();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn released_probe_checks_certificate_http2_and_http3_end_to_end() {
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

    for (transport, configured) in [
        ("http3", ListenerTransport::Http3),
        ("http2", ListenerTransport::Http2),
    ] {
        let (endpoint, server) =
            spawn_certificate_server(&tls, configured, pair.public_key_b64.clone()).await;
        let output = tokio::task::block_in_place(|| {
            run_certificate_probe(endpoint, target, transport, &enrollment_path)
        });
        assert_probe_passed(output, transport);
        server.abort();
    }

    tcp_echo.abort();
    udp_echo.abort();
    std::fs::remove_file(enrollment_path).unwrap();
}
