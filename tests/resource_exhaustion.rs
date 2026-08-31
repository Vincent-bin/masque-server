//! Scheduled Linux pressure verification for externally reachable resource
//! limits.
//!
//! The server runs as a child process so `/proc` measurements include only the
//! service, not the load generator. The test is ignored in the fast suite and
//! executed explicitly by scheduled verification (also under ASan).

#![cfg(target_os = "linux")]

use std::future::poll_fn;
use std::net::{SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::ec::{EcGroup, EcKey};
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::pkey::{PKey, Private};
use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
use boring::x509::{X509Builder, X509NameBuilder};
use bytes::{Buf as _, Bytes};
use http::{Method, Request, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;

use masque::capsule::encoder;

const MAX_CONNECTIONS_PER_IP: usize = 8;
const MAX_PENDING_AUTH_PER_IP: u64 = 2;
const MAX_TUNNELS_PER_CONNECTION: usize = 4;
const BAD_PASSWORD_ATTEMPTS: usize = 64;
const STREAM_ATTEMPTS: usize = 128;
const DATAGRAMS_PER_TUNNEL: usize = 4_096;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "masque-resource-pressure-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ChildServer(Child);

impl ChildServer {
    fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for ChildServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn p256_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn write_identity(dir: &Path) -> (PathBuf, PathBuf) {
    let key = p256_key();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    let mut cert = X509Builder::new().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();

    let cert_path = dir.join("server.crt");
    let key_path = dir.join("server.key");
    std::fs::write(&cert_path, cert.build().to_pem().unwrap()).unwrap();
    std::fs::write(&key_path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    (cert_path, key_path)
}

fn unused_tcp_addr(excluded: &[u16]) -> SocketAddr {
    loop {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        if !excluded.contains(&addr.port()) {
            return addr;
        }
    }
}

fn write_config(
    dir: &Path,
    cert: &Path,
    key: &Path,
    basic_addr: SocketAddr,
    open_addr: SocketAddr,
    observability_addr: SocketAddr,
) -> PathBuf {
    let password_hash = masque::auth::hash_password(b"correct-password").unwrap();
    let config = format!(
        r#"[server]
idle_timeout_secs = 60
max_connections = 16
max_connections_per_ip = {MAX_CONNECTIONS_PER_IP}
max_pending_auth_per_ip = {MAX_PENDING_AUTH_PER_IP}
max_tunnels_per_connection = {MAX_TUNNELS_PER_CONNECTION}

[tls]
cert_path = {cert:?}
key_path = {key:?}

[tcp_proxy]
enabled = true
allow_targets = ["127.0.0.0/8"]
deny_targets = []

[udp_proxy]
enabled = true
allow_targets = ["127.0.0.0/8"]
deny_targets = []

[ip_proxy]
enabled = false

[observability]
listen_addr = "{observability_addr}"

[[listeners]]
listen_addr = "{basic_addr}"
transport = "http2"
shards = 1

[listeners.auth]
enabled = true
mode = "basic"

[[listeners.auth.users]]
username = "alice"
password_hash = {password_hash:?}

[[listeners]]
listen_addr = "{open_addr}"
transport = "http2"
shards = 1

[listeners.auth]
enabled = false
mode = "basic"
"#,
        cert = cert.display().to_string(),
        key = key.display().to_string(),
    );
    let path = dir.join("masque.toml");
    std::fs::write(&path, config).unwrap();
    path
}

async fn http_get(addr: SocketAddr, path: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr).await?;
    stream
        .write_all(format!("GET {path} HTTP/1.0\r\n\r\n").as_bytes())
        .await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let body = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .map(|offset| &response[offset + 4..])
        .unwrap_or_default();
    Ok(String::from_utf8_lossy(body).into_owned())
}

async fn wait_ready(child: &mut Child, addr: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("pressure-test server exited during startup: {status}");
        }
        if http_get(addr, "/readyz")
            .await
            .is_ok_and(|body| body == "ready\n")
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "pressure-test server did not become ready"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn metric_sum(metrics: &str, name: &str, required_labels: &[&str]) -> u64 {
    metrics
        .lines()
        .filter(|line| {
            (line.starts_with(&format!("{name}{{")) || line.starts_with(&format!("{name} ")))
                && required_labels.iter().all(|label| line.contains(label))
        })
        .filter_map(|line| line.split_ascii_whitespace().nth(1))
        .map(|value| value.parse::<u64>().unwrap())
        .sum()
}

fn process_fd_count(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .count()
}

fn process_rss_bytes(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let kib = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.split_ascii_whitespace().next())
        .unwrap()
        .parse::<u64>()
        .unwrap();
    kib * 1024
}

fn process_cpu_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let after_command = stat.rsplit_once(") ").unwrap().1;
    let fields: Vec<&str> = after_command.split_ascii_whitespace().collect();
    // `fields[0]` is process state (field 3); utime/stime are fields 14/15.
    fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
}

fn clock_ticks_per_second() -> u64 {
    let output = Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .expect("getconf CLK_TCK is available on Linux");
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

async fn connect_h2(
    addr: SocketAddr,
) -> (
    h2::client::SendRequest<Bytes>,
    tokio::task::JoinHandle<Result<(), h2::Error>>,
) {
    let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
    connector.set_verify(SslVerifyMode::NONE);
    connector.set_alpn_protos(b"\x02h2").unwrap();
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

fn bad_password_request() -> Request<()> {
    let credentials = STANDARD.encode(b"alice:wrong-password");
    Request::builder()
        .method(Method::CONNECT)
        .uri("127.0.0.1:9")
        .header("proxy-authorization", format!("Basic {credentials}"))
        .body(())
        .unwrap()
}

fn connect_udp_request(target: SocketAddr) -> Request<()> {
    let uri = format!(
        "https://localhost/.well-known/masque/udp/{}/{}/",
        target.ip(),
        target.port()
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
    request
}

async fn send_repeated_capsules(mut stream: h2::SendStream<Bytes>, capsule: Bytes, count: usize) {
    for _ in 0..count {
        let mut remaining = capsule.clone();
        while remaining.has_remaining() {
            stream.reserve_capacity(remaining.remaining());
            let capacity = tokio::time::timeout(
                Duration::from_secs(5),
                poll_fn(|cx| stream.poll_capacity(cx)),
            )
            .await
            .expect("HTTP/2 flow control stalled")
            .expect("CONNECT-UDP stream closed")
            .expect("HTTP/2 flow control failed");
            let chunk = remaining.split_to(capacity.min(remaining.remaining()));
            stream.send_data(chunk, false).unwrap();
        }
    }
    stream.send_data(Bytes::new(), true).unwrap();
}

async fn wait_for_metric_zero(addr: SocketAddr, name: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let metrics = http_get(addr, "/metrics").await.unwrap();
        if metric_sum(&metrics, name, &[]) == 0 {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{name} did not return to zero"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "scheduled Linux resource pressure verification"]
async fn hostile_inputs_stay_inside_cpu_memory_and_fd_bounds() {
    let directory = TempDir::new();
    let (cert, key) = write_identity(directory.path());
    let basic_addr = unused_tcp_addr(&[]);
    let open_addr = unused_tcp_addr(&[basic_addr.port()]);
    let observability_addr = unused_tcp_addr(&[basic_addr.port(), open_addr.port()]);
    let config = write_config(
        directory.path(),
        &cert,
        &key,
        basic_addr,
        open_addr,
        observability_addr,
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_masque-server"))
        .arg("--config")
        .arg(config)
        .env("RUST_LOG", "error")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_ready(&mut child, observability_addr).await;
    let server = ChildServer(child);
    let pid = server.pid();
    let baseline_fds = process_fd_count(pid);
    let baseline_rss = process_rss_bytes(pid);
    let mut peak_fds = baseline_fds;
    let mut peak_rss = baseline_rss;

    // Raw TCP peers that never send a ClientHello occupy a bounded number of
    // handshake tasks and descriptors; excess sockets are accepted then
    // dropped immediately by source admission.
    let half_open: Vec<_> = (0..64)
        .filter_map(|_| StdTcpStream::connect(basic_addr).ok())
        .collect();
    assert!(half_open.len() >= MAX_CONNECTIONS_PER_IP);
    tokio::time::sleep(Duration::from_millis(250)).await;
    peak_fds = peak_fds.max(process_fd_count(pid));
    peak_rss = peak_rss.max(process_rss_bytes(pid));
    let metrics = http_get(observability_addr, "/metrics").await.unwrap();
    let basic_label = format!("listener=\"{basic_addr}\"");
    assert!(
        metric_sum(&metrics, "masque_connections_active_max", &[&basic_label])
            <= MAX_CONNECTIONS_PER_IP as u64
    );
    assert!(
        metric_sum(
            &metrics,
            "masque_connections_rejected_total",
            &[&basic_label]
        ) > 0,
        "half-open excess was not load-shed"
    );
    drop(half_open);
    wait_for_metric_zero(observability_addr, "masque_connections_active").await;

    // All requests are launched together. Per-source admission permits only
    // two Argon2 jobs; the rest must fail fast instead of becoming a CPU and
    // memory backlog.
    let (client, driver) = connect_h2(basic_addr).await;
    let cpu_before = process_cpu_ticks(pid);
    let mut attempts = JoinSet::new();
    for _ in 0..BAD_PASSWORD_ATTEMPTS {
        let sender = client.clone();
        attempts.spawn(async move {
            let mut sender = sender.ready().await.unwrap();
            let (response, _) = sender.send_request(bad_password_request(), true).unwrap();
            tokio::time::timeout(Duration::from_secs(10), response)
                .await
                .unwrap()
                .unwrap()
                .status()
        });
    }
    let mut unauthorized = 0;
    let mut overloaded = 0;
    while let Some(result) = attempts.join_next().await {
        match result.unwrap() {
            StatusCode::PROXY_AUTHENTICATION_REQUIRED => unauthorized += 1,
            StatusCode::SERVICE_UNAVAILABLE => overloaded += 1,
            status => panic!("unexpected bad-password response {status}"),
        }
        peak_fds = peak_fds.max(process_fd_count(pid));
        peak_rss = peak_rss.max(process_rss_bytes(pid));
    }
    assert!(unauthorized > 0 && overloaded > 0);
    let cpu_ticks = process_cpu_ticks(pid) - cpu_before;
    assert!(
        cpu_ticks <= clock_ticks_per_second() * 5,
        "bad-password flood consumed {cpu_ticks} CPU ticks"
    );
    let metrics = http_get(observability_addr, "/metrics").await.unwrap();
    assert!(
        metric_sum(&metrics, "masque_auth_pending_max", &[&basic_label]) <= MAX_PENDING_AUTH_PER_IP
    );
    assert!(
        metric_sum(&metrics, "masque_auth_running_max", &[&basic_label]) <= MAX_PENDING_AUTH_PER_IP
    );
    assert!(
        metric_sum(
            &metrics,
            "masque_auth_attempts_total",
            &[&basic_label, "result=\"overloaded\""]
        ) > 0
    );
    drop(client);
    driver.abort();
    wait_for_metric_zero(observability_addr, "masque_connections_active").await;

    // Open far more streams than the tunnel cap, keep every admitted tunnel
    // alive, then push thousands of DATAGRAM capsules through each one.
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let target_drain = tokio::spawn(async move {
        let mut buf = [0_u8; 2048];
        while target.recv_from(&mut buf).await.is_ok() {}
    });
    let (open_client, open_driver) = connect_h2(open_addr).await;
    let mut requests = Vec::with_capacity(STREAM_ATTEMPTS);
    for _ in 0..STREAM_ATTEMPTS {
        let mut sender = open_client.clone().ready().await.unwrap();
        requests.push(
            sender
                .send_request(connect_udp_request(target_addr), false)
                .unwrap(),
        );
    }
    let mut tunnels = Vec::new();
    for (response, request_body) in requests {
        let response = tokio::time::timeout(Duration::from_secs(10), response)
            .await
            .unwrap()
            .unwrap();
        match response.status() {
            StatusCode::OK => tunnels.push(request_body),
            StatusCode::SERVICE_UNAVAILABLE => {}
            status => panic!("unexpected stream-flood response {status}"),
        }
    }
    assert_eq!(tunnels.len(), MAX_TUNNELS_PER_CONNECTION);
    peak_fds = peak_fds.max(process_fd_count(pid));
    peak_rss = peak_rss.max(process_rss_bytes(pid));
    let open_label = format!("listener=\"{open_addr}\"");
    let metrics = http_get(observability_addr, "/metrics").await.unwrap();
    assert_eq!(
        metric_sum(
            &metrics,
            "masque_tunnels_active_max",
            &[&open_label, "protocol=\"udp\""]
        ),
        MAX_TUNNELS_PER_CONNECTION as u64
    );

    let mut capsule = Vec::new();
    encoder::encode_datagram_context_zero(&[0x5a; 256], &mut capsule);
    let capsule = Bytes::from(capsule);
    let mut senders = JoinSet::new();
    for tunnel in tunnels {
        let capsule = capsule.clone();
        senders.spawn(send_repeated_capsules(
            tunnel,
            capsule,
            DATAGRAMS_PER_TUNNEL,
        ));
    }
    while let Some(result) = senders.join_next().await {
        result.unwrap();
        peak_fds = peak_fds.max(process_fd_count(pid));
        peak_rss = peak_rss.max(process_rss_bytes(pid));
    }
    drop(open_client);
    open_driver.abort();
    target_drain.abort();
    wait_for_metric_zero(observability_addr, "masque_connections_active").await;

    // Descriptor usage is explained entirely by the source-connection and
    // per-connection tunnel caps, plus fixed listeners/runtime descriptors.
    let fd_budget = baseline_fds + MAX_CONNECTIONS_PER_IP + MAX_TUNNELS_PER_CONNECTION + 8;
    assert!(
        peak_fds <= fd_budget,
        "server FD peak {peak_fds} exceeded baseline {baseline_fds} + bounded budget"
    );

    // Two Argon2id verifications account for roughly 38 MiB. Leave generous
    // room for allocator and ASan quarantine overhead while still detecting a
    // queued-hash or unbounded-frame regression. CI may raise this explicit
    // delta for a sanitizer runtime without weakening the structural gauges.
    let rss_delta_limit_mib = std::env::var("MASQUE_RESOURCE_RSS_DELTA_MIB")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(256);
    let rss_delta = peak_rss.saturating_sub(baseline_rss);
    assert!(
        rss_delta <= rss_delta_limit_mib * 1024 * 1024,
        "server RSS grew from {baseline_rss} to {peak_rss} bytes"
    );

    eprintln!(
        "resource-pressure summary: bad-password unauthorized={unauthorized} overloaded={overloaded} cpu_ticks={cpu_ticks}; fd baseline={baseline_fds} peak={peak_fds} limit={fd_budget}; RSS baseline={baseline_rss} peak={peak_rss} delta={rss_delta} limit={} bytes; admitted_tunnels={MAX_TUNNELS_PER_CONNECTION} datagrams_per_tunnel={DATAGRAMS_PER_TUNNEL}",
        rss_delta_limit_mib * 1024 * 1024
    );
}
