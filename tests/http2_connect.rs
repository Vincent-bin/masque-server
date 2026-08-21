//! End-to-end coverage for the HTTP/2 compatibility transport.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::ec::{EcGroup, EcKey};
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::pkey::{PKey, Private};
use boring::ssl::{SslConnector, SslFiletype, SslMethod, SslVerifyMode};
use boring::x509::{X509Builder, X509NameBuilder};
use bytes::Bytes;
use http::{Method, Request, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use masque::capsule::decoder::CapsuleDecoder;
use masque::capsule::{CapsuleFrame, IpAddress, encoder};
use masque::config::{AuthMode, ClientEntry, ListenerTransport, ServerConfig};
use masque::server::Server;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TestFiles {
    directory: PathBuf,
    cert: PathBuf,
    key: PathBuf,
}

impl TestFiles {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "masque-http2-test-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();

        let key = p256_key();
        let cert = self_signed(&key);
        let cert_path = directory.join("server.crt");
        let key_path = directory.join("server.key");
        std::fs::write(&cert_path, cert.to_pem().unwrap()).unwrap();
        std::fs::write(&key_path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        Self {
            directory,
            cert: cert_path,
            key: key_path,
        }
    }
}

impl Drop for TestFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn p256_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn self_signed(key: &PKey<Private>) -> boring::x509::X509 {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();

    let mut cert = X509Builder::new().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.sign(key, MessageDigest::sha256()).unwrap();
    cert.build()
}

fn http2_config(files: &TestFiles) -> ServerConfig {
    let mut config = ServerConfig::default();
    config.tls.cert_path = files.cert.clone();
    config.tls.key_path = files.key.clone();
    config.listeners[0].listen_addr = "127.0.0.1:0".parse().unwrap();
    config.listeners[0].transport = ListenerTransport::Http2;
    config.listeners[0].auth.enabled = false;
    config.ip_proxy.enabled = false;
    config.tcp_proxy.allow_targets = vec!["127.0.0.0/8".into()];
    config.tcp_proxy.deny_targets.clear();
    config.udp_proxy.allow_targets = vec!["127.0.0.0/8".into()];
    config.udp_proxy.deny_targets.clear();
    config
}

async fn spawn_http2_server(
    files: &TestFiles,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    spawn_http2_config(http2_config(files)).await
}

async fn spawn_http2_config(
    config: ServerConfig,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let mut server = Server::bind(config).await.unwrap();
    let addr = server.listen_addrs()[0];
    let task = tokio::spawn(async move {
        server.run().await.unwrap();
    });
    (addr, task)
}

async fn connect_h2(
    addr: std::net::SocketAddr,
) -> (
    h2::client::SendRequest<Bytes>,
    tokio::task::JoinHandle<Result<(), h2::Error>>,
) {
    connect_h2_with_identity(addr, None).await
}

async fn connect_h2_with_identity(
    addr: std::net::SocketAddr,
    identity: Option<(&Path, &Path)>,
) -> (
    h2::client::SendRequest<Bytes>,
    tokio::task::JoinHandle<Result<(), h2::Error>>,
) {
    let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
    connector.set_verify(SslVerifyMode::NONE);
    connector.set_alpn_protos(b"\x02h2").unwrap();
    if let Some((cert, key)) = identity {
        connector
            .set_certificate_chain_file(cert)
            .expect("client certificate is valid PEM");
        connector
            .set_private_key_file(key, SslFiletype::PEM)
            .expect("client private key is valid PEM");
        connector.check_private_key().unwrap();
    }
    let tls = tokio_boring::connect(
        connector.build().configure().unwrap(),
        "localhost",
        TcpStream::connect(addr).await.unwrap(),
    )
    .await
    .unwrap();
    let (client, connection) = h2::client::handshake(tls).await.unwrap();
    let driver = tokio::spawn(connection);
    (client.ready().await.unwrap(), driver)
}

fn connect_request(target: std::net::SocketAddr) -> Request<()> {
    let uri = http::Uri::builder()
        .authority(target.to_string())
        .build()
        .unwrap();
    Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .body(())
        .unwrap()
}

fn connect_ip_request(protocol: &'static str) -> Request<()> {
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri("https://localhost/.well-known/masque/ip/*/*/")
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap();
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static(protocol));
    request
}

fn cloudflare_h2_connect_ip_request() -> Request<()> {
    let uri = http::Uri::builder()
        .authority("cloudflareaccess.com:443")
        .build()
        .unwrap();
    Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .header("cf-connect-proto", "cf-connect-ip")
        .header("pq-enabled", "false")
        .body(())
        .unwrap()
}

async fn read_connect_ip_setup(
    response: http::Response<h2::RecvStream>,
) -> (Vec<CapsuleFrame>, h2::RecvStream) {
    assert_eq!(response.status(), StatusCode::OK);

    let mut response_body = response.into_body();
    let mut decoder = CapsuleDecoder::new();
    let mut frames = Vec::new();
    while frames.len() < 2 {
        let data = tokio::time::timeout(Duration::from_secs(2), response_body.data())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        response_body
            .flow_control()
            .release_capacity(data.len())
            .unwrap();
        frames.extend(decoder.decode(&data).unwrap());
    }
    (frames, response_body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standard_connect_relays_bytes_over_http2() {
    let files = TestFiles::new();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut buf = [0_u8; 64];
        let read = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..read]).await.unwrap();
    });

    let (server_addr, server_task) = spawn_http2_server(&files).await;
    let (mut client, driver) = connect_h2(server_addr).await;
    let request = connect_request(target_addr);
    let (response, mut request_body) = client.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    request_body
        .send_data(Bytes::from_static(b"hello over h2"), true)
        .unwrap();
    let mut response_body = response.into_body();
    let echoed = tokio::time::timeout(Duration::from_secs(2), response_body.data())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(&echoed[..], b"hello over h2");
    response_body
        .flow_control()
        .release_capacity(echoed.len())
        .unwrap();

    target_task.await.unwrap();
    server_task.abort();
    driver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn basic_auth_challenges_missing_credentials_and_accepts_valid_credentials() {
    let files = TestFiles::new();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        stream.write_all(&byte).await.unwrap();
    });

    let mut config = http2_config(&files);
    config.listeners[0].auth.enabled = true;
    config.listeners[0].auth.mode = AuthMode::Basic;
    config.listeners[0].auth.username = "alice".into();
    config.listeners[0].auth.password_hash = masque::auth::hash_password(b"secret").unwrap();
    let (server_addr, server_task) = spawn_http2_config(config).await;
    let (mut client, driver) = connect_h2(server_addr).await;

    let (response, _) = client
        .send_request(connect_request(target_addr), true)
        .unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    assert_eq!(
        response.headers()["proxy-authenticate"],
        "Basic realm=\"masque\", charset=\"UTF-8\""
    );

    client = client.ready().await.unwrap();
    let mut request = connect_request(target_addr);
    request.headers_mut().insert(
        "proxy-authorization",
        "Basic YWxpY2U6c2VjcmV0".parse().unwrap(),
    );
    let (response, mut request_body) = client.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    request_body
        .send_data(Bytes::from_static(b"x"), true)
        .unwrap();
    let mut response_body = response.into_body();
    let echoed = tokio::time::timeout(Duration::from_secs(2), response_body.data())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(&echoed[..], b"x");
    response_body
        .flow_control()
        .release_capacity(echoed.len())
        .unwrap();

    target_task.await.unwrap();
    server_task.abort();
    driver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_certificate_authenticates_http2_connection() {
    let files = TestFiles::new();
    let client_key = p256_key();
    let client_cert = self_signed(&client_key);
    let client_cert_path = files.directory.join("client.crt");
    let client_key_path = files.directory.join("client.key");
    std::fs::write(&client_cert_path, client_cert.to_pem().unwrap()).unwrap();
    std::fs::write(
        &client_key_path,
        client_key.private_key_to_pem_pkcs8().unwrap(),
    )
    .unwrap();

    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        stream.write_all(&byte).await.unwrap();
    });

    let mut config = http2_config(&files);
    config.listeners[0].auth.enabled = true;
    config.listeners[0].auth.mode = AuthMode::ClientCert;
    config.clients = vec![ClientEntry {
        name: "h2-client".into(),
        public_key: STANDARD.encode(client_key.public_key_to_der().unwrap()),
        ipv4: None,
        ipv6: None,
    }];
    let (server_addr, server_task) = spawn_http2_config(config).await;
    let (mut client, driver) =
        connect_h2_with_identity(server_addr, Some((&client_cert_path, &client_key_path))).await;

    let (response, mut request_body) = client
        .send_request(connect_request(target_addr), false)
        .unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    request_body
        .send_data(Bytes::from_static(b"c"), true)
        .unwrap();
    let mut response_body = response.into_body();
    let echoed = tokio::time::timeout(Duration::from_secs(2), response_body.data())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(&echoed[..], b"c");
    response_body
        .flow_control()
        .release_capacity(echoed.len())
        .unwrap();

    target_task.await.unwrap();
    server_task.abort();
    driver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_udp_relays_datagram_capsules_over_http2() {
    let files = TestFiles::new();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let target_task = tokio::spawn(async move {
        let mut buf = [0_u8; 256];
        let (read, peer) = target.recv_from(&mut buf).await.unwrap();
        target.send_to(&buf[..read], peer).await.unwrap();
    });

    let (server_addr, server_task) = spawn_http2_server(&files).await;
    let (mut client, driver) = connect_h2(server_addr).await;
    let uri = format!(
        "https://localhost/.well-known/masque/udp/{}/{}/",
        target_addr.ip(),
        target_addr.port()
    );
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap();
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("connect-udp"));
    let (response, mut request_body) = client.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["capsule-protocol"], "?1");

    let mut capsule = Vec::new();
    encoder::encode_datagram_context_zero(b"udp over h2", &mut capsule);
    request_body.send_data(Bytes::from(capsule), false).unwrap();

    let mut response_body = response.into_body();
    let data = tokio::time::timeout(Duration::from_secs(2), response_body.data())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    response_body
        .flow_control()
        .release_capacity(data.len())
        .unwrap();
    let frames = CapsuleDecoder::new().decode(&data).unwrap();
    assert_eq!(
        frames,
        vec![CapsuleFrame::Datagram(
            [vec![0], b"udp over h2".to_vec()].concat()
        )]
    );

    request_body.send_data(Bytes::new(), true).unwrap();
    target_task.await.unwrap();
    server_task.abort();
    driver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_ip_assigns_addresses_and_routes_over_http2_capsules() {
    let files = TestFiles::new();
    let mut config = http2_config(&files);
    config.ip_proxy.enabled = true;
    let (server_addr, server_task) = spawn_http2_config(config).await;
    let (mut client, driver) = connect_h2(server_addr).await;

    // Exercise the identifier used by Cloudflare-compatible clients; the
    // registered `connect-ip` identifier is covered by request unit tests.
    let request = connect_ip_request("cf-connect-ip");
    let (response, mut request_body) = client.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.headers()["capsule-protocol"], "?1");
    let (frames, _response_body) = read_connect_ip_setup(response).await;

    let CapsuleFrame::AddressAssign(addresses) = &frames[0] else {
        panic!("first setup capsule was not ADDRESS_ASSIGN");
    };
    assert!(
        addresses
            .iter()
            .any(|address| matches!(address.ip, IpAddress::V4(_)))
    );
    assert!(
        addresses
            .iter()
            .any(|address| matches!(address.ip, IpAddress::V6(_)))
    );
    let CapsuleFrame::RouteAdvertisement(routes) = &frames[1] else {
        panic!("second setup capsule was not ROUTE_ADVERTISEMENT");
    };
    assert_eq!(routes.len(), 2);

    request_body.send_data(Bytes::new(), true).unwrap();
    server_task.abort();
    driver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_certificate_pins_http2_connect_ip_addresses() {
    let files = TestFiles::new();
    let client_key = p256_key();
    let client_cert = self_signed(&client_key);
    let client_cert_path = files.directory.join("ip-client.crt");
    let client_key_path = files.directory.join("ip-client.key");
    std::fs::write(&client_cert_path, client_cert.to_pem().unwrap()).unwrap();
    std::fs::write(
        &client_key_path,
        client_key.private_key_to_pem_pkcs8().unwrap(),
    )
    .unwrap();

    let ipv4: std::net::Ipv4Addr = "10.89.0.44".parse().unwrap();
    let ipv6: std::net::Ipv6Addr = "fd00:abcd::44".parse().unwrap();
    let mut config = http2_config(&files);
    config.ip_proxy.enabled = true;
    config.listeners[0].auth.enabled = true;
    config.listeners[0].auth.mode = AuthMode::ClientCert;
    config.clients = vec![ClientEntry {
        name: "h2-ip-client".into(),
        public_key: STANDARD.encode(client_key.public_key_to_der().unwrap()),
        ipv4: Some(ipv4.to_string()),
        ipv6: Some(ipv6.to_string()),
    }];

    let (server_addr, server_task) = spawn_http2_config(config).await;
    let (mut client, driver) =
        connect_h2_with_identity(server_addr, Some((&client_cert_path, &client_key_path))).await;
    let (response, mut request_body) = client
        .send_request(cloudflare_h2_connect_ip_request(), false)
        .unwrap();
    let response = response.await.unwrap();
    assert!(!response.headers().contains_key("capsule-protocol"));
    let (frames, mut response_body) = read_connect_ip_setup(response).await;
    let CapsuleFrame::AddressAssign(addresses) = &frames[0] else {
        panic!("first setup capsule was not ADDRESS_ASSIGN");
    };
    assert!(
        addresses
            .iter()
            .any(|address| address.ip == IpAddress::V4(ipv4))
    );
    assert!(
        addresses
            .iter()
            .any(|address| address.ip == IpAddress::V6(ipv6))
    );
    assert_eq!(addresses.len(), 2);

    // usque's HTTP/2 dialect removes Context ID zero from the DATAGRAM capsule
    // value. A standard-mode decoder would reject this one-byte payload before
    // the stream can close cleanly.
    let mut legacy_capsule = Vec::new();
    encoder::encode_datagram(&[0x45], &mut legacy_capsule);
    // Packetized CONNECT-IP legitimately produces many small DATA frames (TCP
    // ACK packets are a common example). Send enough in one burst to exceed
    // h2's generic HTTP framing budget and prove the transport-specific budget
    // remains effective. The one-byte payload is intentionally not a complete
    // IP packet; the server consumes and drops it after decoding the capsule.
    for _ in 0..512 {
        request_body
            .send_data(Bytes::copy_from_slice(&legacy_capsule), false)
            .unwrap();
    }
    request_body.send_data(Bytes::new(), true).unwrap();
    let end = tokio::time::timeout(Duration::from_secs(2), response_body.data())
        .await
        .unwrap();
    if let Some(data) = end {
        assert!(data.unwrap().is_empty());
        let end = tokio::time::timeout(Duration::from_secs(2), response_body.data())
            .await
            .unwrap();
        assert!(end.is_none(), "legacy CONNECT-IP stream was reset");
    }
    server_task.abort();
    driver.abort();
}
