//! End-to-end coverage for the Cloudflare-compatible CONNECT-IP path.
//!
//! These tests drive a real QUIC client against a real server, because the
//! parts that were most likely to be wrong are the parts unit tests cannot
//! reach: whether BoringSSL actually asks for a client certificate when the
//! chain is unverifiable, and whether a request shaped the way Cloudflare's
//! clients shape it survives quiche's HTTP/3 layer.
//!
//! The client is deliberately built to mimic that family of clients rather than
//! an RFC 9484 one: a self-signed certificate with an empty subject, serial 0,
//! and 24 hours of validity; `:protocol: cf-connect-ip`; a hardcoded authority;
//! and `:path: /`.

#[cfg(target_os = "linux")]
use std::io::{Read as _, Write as _};
#[cfg(target_os = "linux")]
use std::net::TcpStream;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::ec::{EcGroup, EcKey};
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::pkey::{PKey, Private};
use boring::x509::{X509, X509Builder, X509NameBuilder};
use quiche::h3::NameValue as _;

use masque::capsule::decoder::{CapsuleDecoder, DecodeError};
use masque::capsule::{CapsuleFrame, IpAddress};
use masque::config::{
    AuthMode, AuthSection, ClientEntry, ListenerSection, ListenerTransport, QuicRetryMode,
    ServerConfig,
};
use masque::datagram::DatagramHeader;
use masque::server::Server;

const MAX_DATAGRAM_SIZE: usize = 1350;
const CLIENT_IPV4: &str = "10.89.0.2";
const CLIENT_IPV6: &str = "fd00:abcd::2";

/// QUIC maps a TLS alert to `CRYPTO_ERROR` (0x100) plus the alert number.
/// Alert 49 is `access_denied`.
const ACCESS_DENIED_CRYPTO_ERROR: u64 = 0x100 + 49;
#[cfg(target_os = "linux")]
const MIGRATION_SOURCE_LIMIT_ERROR: u64 = 0x0101;

/// The tunnel MTU these clients use, matching `ip_proxy.tun_mtu`.
const TUN_MTU: usize = 1280;

/// Connection ID length this client uses, matching what these clients set.
/// It is also QUIC's maximum, which makes it the tightest case for datagram
/// sizing.
const CLIENT_CONN_ID_LEN: usize = quiche::MAX_CONN_ID_LEN;

/// Connection ID length the server issues (`server::CONN_ID_LEN`).
const SERVER_CONN_ID_LEN: usize = 16;

// ── Key and certificate material ─────────────────────────────────────

fn p256_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn public_key_b64(key: &PKey<Private>) -> String {
    STANDARD.encode(key.public_key_to_der().unwrap())
}

/// A self-signed certificate. `subject` empty reproduces what these clients
/// present: no distinguished name at all, so only the key identifies them.
fn self_signed(key: &PKey<Private>, subject: Option<&str>) -> X509 {
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&BigNum::from_u32(0).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    if let Some(cn) = subject {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
    }
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    builder.set_pubkey(key).unwrap();
    builder.sign(key, MessageDigest::sha256()).unwrap();
    builder.build()
}

/// Write a key pair out as the PEM files quiche loads.
fn write_pem(dir: &Path, stem: &str, key: &PKey<Private>, cert: &X509) -> (PathBuf, PathBuf) {
    let cert_path = dir.join(format!("{stem}.crt"));
    let key_path = dir.join(format!("{stem}.key"));
    std::fs::write(&cert_path, cert.to_pem().unwrap()).unwrap();
    // SEC1 ("EC PRIVATE KEY"), which is what BoringSSL expects here.
    std::fs::write(
        &key_path,
        key.ec_key().unwrap().private_key_to_pem().unwrap(),
    )
    .unwrap();
    (cert_path, key_path)
}

/// A scratch directory removed when the test ends.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "masque-it-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

// ── Server under test ────────────────────────────────────────────────

/// The loopback address that asks the kernel for whichever port is free.
///
/// Servers under test bind this and report back what they got, rather than
/// picking a port in advance. Reserving one and releasing it leaves a window in
/// which a parallel test can take it, and the whole point of a probe socket is
/// that it must be closed before the server can have the port.
fn ephemeral_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

fn server_config(
    cert: PathBuf,
    key: PathBuf,
    listen_addr: SocketAddr,
    clients: Vec<ClientEntry>,
) -> ServerConfig {
    let mut config = ServerConfig::default();
    config.tls.cert_path = cert;
    config.tls.key_path = key;
    config.listeners[0].listen_addr = listen_addr;
    config.listeners[0].shards = 1;
    config.listeners[0].auth.enabled = true;
    config.listeners[0].auth.mode = AuthMode::ClientCert;
    config.clients = clients;
    // The tunnels under test are CONNECT-IP only, and the TCP and UDP paths
    // would otherwise resolve and dial real targets.
    config.tcp_proxy.enabled = false;
    config.udp_proxy.enabled = false;
    config
}

/// Run a server on its own runtime thread and return the addresses it bound.
///
/// The thread is detached: the runtime is dropped when the process exits, and
/// the OS reclaims the ports.
///
/// Waiting for the real addresses rather than sleeping is what makes a
/// `127.0.0.1:0` listener usable: the port is never held by anything but the
/// server, so no parallel test can take it in between, and a caller cannot
/// start talking to a socket that is not up yet.
fn spawn_server(config: ServerConfig) -> Vec<SocketAddr> {
    spawn_server_with_observability(config).0
}

fn spawn_server_with_observability(config: ServerConfig) -> (Vec<SocketAddr>, Option<SocketAddr>) {
    let (bound_tx, bound_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            match Server::bind(config).await {
                Ok(mut server) => {
                    // A failed send means the test gave up; run anyway and let
                    // the detached thread die with the process.
                    let _ = bound_tx.send((server.listen_addrs(), server.observability_addr()));
                    let _ = server.run().await;
                }
                Err(e) => panic!("server failed to bind: {e:#}"),
            }
        });
    });

    bound_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("server did not report its listen addresses")
}

#[cfg(target_os = "linux")]
fn scrape_metrics(addr: SocketAddr) -> String {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[cfg(target_os = "linux")]
fn metric_total(rendered: &str, name: &str) -> u64 {
    rendered
        .lines()
        .filter(|line| line.starts_with(name))
        .filter_map(|line| line.rsplit_once(' '))
        .filter_map(|(_, value)| value.parse::<u64>().ok())
        .sum()
}

// ── Client ───────────────────────────────────────────────────────────

struct Client {
    socket: UdpSocket,
    quic: quiche::Connection,
    h3: Option<quiche::h3::Connection>,
}

impl Client {
    /// Connect with a client certificate, the way these clients authenticate.
    ///
    /// `verify_peer(false)` mirrors them too: the SNI they send does not match
    /// the endpoint, so they skip chain validation and pin the server's public
    /// key instead.
    fn connect(peer: SocketAddr, cert: &Path, key: &Path) -> anyhow::Result<Self> {
        Self::connect_with(peer, Some((cert, key)))
    }

    /// Connect without a client certificate, the way a standards-compliant
    /// MASQUE client that authenticates with `Proxy-Authorization` does.
    fn connect_anonymous(peer: SocketAddr) -> anyhow::Result<Self> {
        Self::connect_with(peer, None)
    }

    #[cfg(target_os = "linux")]
    fn connect_from(
        peer: SocketAddr,
        cert: &Path,
        key: &Path,
        source_ip: std::net::IpAddr,
    ) -> anyhow::Result<Self> {
        Self::connect_with_session_from(peer, Some((cert, key)), None, false, source_ip)
    }

    fn connect_with(peer: SocketAddr, identity: Option<(&Path, &Path)>) -> anyhow::Result<Self> {
        Self::connect_with_session(peer, identity, None, false)
    }

    /// Build a resuming client that is willing to send Early Data if the
    /// server's ticket permits it. Production tickets must never do so.
    fn connect_with_session(
        peer: SocketAddr,
        identity: Option<(&Path, &Path)>,
        session: Option<&[u8]>,
        enable_early_data: bool,
    ) -> anyhow::Result<Self> {
        Self::connect_with_session_from(
            peer,
            identity,
            session,
            enable_early_data,
            "127.0.0.1".parse().unwrap(),
        )
    }

    fn connect_with_session_from(
        peer: SocketAddr,
        identity: Option<(&Path, &Path)>,
        session: Option<&[u8]>,
        enable_early_data: bool,
        source_ip: std::net::IpAddr,
    ) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind(SocketAddr::new(source_ip, 0))?;
        socket.connect(peer)?;
        socket.set_read_timeout(Some(Duration::from_millis(50)))?;
        let local = socket.local_addr()?;

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        config.verify_peer(false);
        if let Some((cert, key)) = identity {
            config.load_cert_chain_from_pem_file(cert.to_str().unwrap())?;
            config.load_priv_key_from_pem_file(key.to_str().unwrap())?;
        }
        config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
        config.set_max_idle_timeout(10_000);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(1_048_576);
        config.set_initial_max_stream_data_bidi_local(262_144);
        config.set_initial_max_stream_data_bidi_remote(262_144);
        config.set_initial_max_stream_data_uni(262_144);
        config.set_initial_max_streams_bidi(16);
        config.set_initial_max_streams_uni(16);
        config.set_active_connection_id_limit(2);
        config.set_disable_active_migration(false);
        config.enable_dgram(true, 256, 256);
        if enable_early_data {
            config.enable_early_data();
        }

        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut scid)
            .map_err(|_| anyhow::anyhow!("RNG failed"))?;

        // The SNI these clients send names the vendor's endpoint rather than
        // this server, which is exactly why they cannot verify the chain.
        let mut quic = quiche::connect(
            Some("consumer-masque.cloudflareclient.com"),
            &quiche::ConnectionId::from_ref(&scid),
            local,
            peer,
            &mut config,
        )?;
        if let Some(session) = session {
            // This is still before the connection has emitted or received a
            // packet, as required by quiche::Connection::set_session().
            quic.set_session(session)?;
        }

        Ok(Self {
            socket,
            quic,
            h3: None,
        })
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        let mut out = [0u8; MAX_DATAGRAM_SIZE];
        loop {
            match self.quic.send(&mut out) {
                Ok((len, _)) => {
                    self.socket.send(&out[..len])?;
                }
                Err(quiche::Error::Done) => return Ok(()),
                Err(e) => anyhow::bail!("QUIC send: {e}"),
            }
        }
    }

    fn recv_once(&mut self) -> anyhow::Result<()> {
        let mut buf = [0u8; 65535];
        let len = match self.socket.recv(&mut buf) {
            Ok(len) => len,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        let info = quiche::RecvInfo {
            from: self.socket.peer_addr()?,
            to: self.socket.local_addr()?,
        };
        match self.quic.recv(&mut buf[..len], info) {
            Ok(_) | Err(quiche::Error::Done) => Ok(()),
            Err(e) => anyhow::bail!("QUIC recv: {e}"),
        }
    }

    fn drive(&mut self) -> anyhow::Result<()> {
        self.flush()?;
        self.recv_once()?;
        self.flush()
    }

    /// Give the server a spare destination CID before moving to another
    /// socket. Active migration requires both endpoints to have supplied one.
    fn publish_spare_connection_id(&mut self) -> anyhow::Result<()> {
        while self.quic.scids_left() > 0 {
            let mut random = [0u8; CLIENT_CONN_ID_LEN + 16];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random)
                .map_err(|_| anyhow::anyhow!("RNG failed"))?;
            let id = quiche::ConnectionId::from_ref(&random[..CLIENT_CONN_ID_LEN]);
            let reset_token = u128::from_be_bytes(
                random[CLIENT_CONN_ID_LEN..]
                    .try_into()
                    .expect("reset token is 16 bytes"),
            );
            self.quic.new_scid(&id, reset_token, false)?;
        }
        self.flush()
    }

    /// Replace the connected UDP socket while retaining this QUIC and H3
    /// connection, then wait for the replacement path to validate.
    fn migrate_source(&mut self, timeout: Duration) -> anyhow::Result<(SocketAddr, SocketAddr)> {
        self.migrate_source_from("127.0.0.1".parse().unwrap(), timeout)
    }

    fn migrate_source_from(
        &mut self,
        source_ip: std::net::IpAddr,
        timeout: Duration,
    ) -> anyhow::Result<(SocketAddr, SocketAddr)> {
        self.publish_spare_connection_id()?;
        let old_local = self.socket.local_addr()?;
        let peer = self.socket.peer_addr()?;
        let replacement = UdpSocket::bind(SocketAddr::new(source_ip, 0))?;
        replacement.connect(peer)?;
        replacement.set_read_timeout(Some(Duration::from_millis(50)))?;
        let new_local = replacement.local_addr()?;
        anyhow::ensure!(
            old_local != new_local,
            "replacement socket reused the old address"
        );

        let deadline = Instant::now() + timeout;
        loop {
            match self.quic.migrate_source(new_local) {
                Ok(_) => {
                    // `migrate_source()` selects the new path. Explicitly
                    // probe the server side and send a non-probing PING so the
                    // server also observes peer migration and validates us.
                    self.quic.probe_path(new_local, peer)?;
                    self.quic.send_ack_eliciting()?;
                    break;
                }
                Err(quiche::Error::OutOfIdentifiers) if Instant::now() < deadline => {
                    // The server publishes its spare CID immediately after the
                    // handshake; receive until that NEW_CONNECTION_ID arrives.
                    self.drive()?;
                }
                Err(error) => anyhow::bail!("cannot start QUIC migration: {error}"),
            }
        }

        self.socket = replacement;
        while Instant::now() < deadline {
            self.drive()?;
            if self.quic.is_path_validated(new_local, peer) == Ok(true) {
                return Ok((old_local, new_local));
            }
            if self.quic.is_closed() {
                anyhow::bail!("connection closed during migration");
            }
        }
        anyhow::bail!("replacement QUIC path did not validate within {timeout:?}")
    }

    fn handshake(&mut self, timeout: Duration) -> anyhow::Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            self.drive()?;
            if self.quic.is_established() {
                return Ok(());
            }
            if self.quic.is_closed() {
                anyhow::bail!("connection closed during handshake");
            }
        }
        anyhow::bail!("handshake timed out")
    }

    /// Receive the post-handshake session ticket and serialized QUIC transport
    /// parameters needed to attempt a real resumed connection.
    fn session(&mut self, timeout: Duration) -> anyhow::Result<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            self.drive()?;
            if let Some(session) = self.quic.session() {
                return Ok(session.to_vec());
            }
        }
        anyhow::bail!("server did not issue a session ticket within {timeout:?}")
    }

    fn peer_certificate_der(&self) -> Vec<u8> {
        self.quic
            .peer_cert()
            .expect("server did not present a certificate")
            .to_vec()
    }

    /// Drive until the peer tears the connection down, or give up.
    ///
    /// A rejected client cannot be detected at `is_established()`: under TLS
    /// 1.3 the server sends its own Finished before it has seen the client's
    /// certificate, so the client reaches "established" and only then receives
    /// the alert. What matters is that the connection does not survive.
    fn wait_for_close(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.quic.is_closed() || self.quic.peer_error().is_some() {
                return true;
            }
            if self.drive().is_err() {
                return true;
            }
        }
        false
    }

    fn init_h3(&mut self) -> anyhow::Result<()> {
        let mut config = quiche::h3::Config::new()?;
        config.enable_extended_connect(true);
        self.h3 = Some(quiche::h3::Connection::with_transport(
            &mut self.quic,
            &config,
        )?);
        Ok(())
    }

    /// Send the CONNECT-IP request exactly as Cloudflare's clients send it.
    fn send_connect_ip(&mut self, protocol: &str) -> anyhow::Result<u64> {
        self.send_connect_ip_with_credentials(protocol, None)
    }

    /// The same request, optionally carrying `Proxy-Authorization`.
    fn send_connect_ip_with_credentials(
        &mut self,
        protocol: &str,
        credentials: Option<&str>,
    ) -> anyhow::Result<u64> {
        let mut headers = vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", protocol.as_bytes()),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"cloudflareaccess.com"),
            quiche::h3::Header::new(b":path", b"/"),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
            // These clients send an empty User-Agent, which has to survive
            // QPACK and the server's header scan.
            quiche::h3::Header::new(b"user-agent", b""),
        ];
        if let Some(credentials) = credentials {
            headers.push(quiche::h3::Header::new(
                b"proxy-authorization",
                credentials.as_bytes(),
            ));
        }

        let h3 = self.h3.as_mut().unwrap();
        let stream_id = h3.send_request(&mut self.quic, &headers, false)?;
        self.flush()?;
        Ok(stream_id)
    }

    /// Wait for the response status on `stream_id`.
    fn response_status(&mut self, stream_id: u64, timeout: Duration) -> anyhow::Result<u16> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            loop {
                let h3 = self.h3.as_mut().unwrap();
                match h3.poll(&mut self.quic) {
                    Ok((sid, quiche::h3::Event::Headers { list, .. })) if sid == stream_id => {
                        for header in &list {
                            if header.name() == b":status" {
                                let status = std::str::from_utf8(header.value())?;
                                return Ok(status.parse()?);
                            }
                        }
                        anyhow::bail!("response had no :status");
                    }
                    Ok(_) => continue,
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => anyhow::bail!("H3 poll: {e}"),
                }
            }
            self.drive()?;
        }
        anyhow::bail!("no response within {timeout:?}")
    }

    /// Collect capsules from the response body until `wanted` of them arrive.
    fn capsules(&mut self, stream_id: u64, wanted: usize, timeout: Duration) -> Vec<CapsuleFrame> {
        let deadline = Instant::now() + timeout;
        let mut decoder = CapsuleDecoder::new();
        let mut frames = Vec::new();
        let mut buf = [0u8; 4096];

        while Instant::now() < deadline && frames.len() < wanted {
            loop {
                let h3 = self.h3.as_mut().unwrap();
                match h3.poll(&mut self.quic) {
                    Ok(_) => continue,
                    Err(quiche::h3::Error::Done) => break,
                    Err(_) => break,
                }
            }
            loop {
                let h3 = self.h3.as_mut().unwrap();
                match h3.recv_body(&mut self.quic, stream_id, &mut buf) {
                    Ok(len) => match decoder.decode(&buf[..len]) {
                        Ok(mut decoded) => frames.append(&mut decoded),
                        Err(DecodeError::Incomplete) => {}
                        Err(e) => panic!("capsule decode failed: {e:?}"),
                    },
                    Err(_) => break,
                }
            }
            let _ = self.drive();
        }

        frames
    }
}

// ── Fixtures ─────────────────────────────────────────────────────────

/// A running server plus everything a client needs to reach it.
struct Fixture {
    _dir: TempDir,
    peer: SocketAddr,
    client_cert: PathBuf,
    client_key: PathBuf,
    stranger_cert: PathBuf,
    stranger_key: PathBuf,
}

/// Start a server that knows one client, pinned to fixed addresses, and mint a
/// second unregistered key pair to test rejection with.
fn fixture_with_retry(tag: &str, retry_mode: QuicRetryMode) -> Fixture {
    let dir = TempDir::new(tag);

    let server_key = p256_key();
    let (cert_path, key_path) = write_pem(
        dir.path(),
        "server",
        &server_key,
        &self_signed(&server_key, Some("masque-server")),
    );

    let client_key = p256_key();
    let (client_cert, client_key_path) = write_pem(
        dir.path(),
        "client",
        &client_key,
        &self_signed(&client_key, None),
    );

    let stranger_key = p256_key();
    let (stranger_cert, stranger_key_path) = write_pem(
        dir.path(),
        "stranger",
        &stranger_key,
        &self_signed(&stranger_key, None),
    );

    let mut config = server_config(
        cert_path,
        key_path,
        ephemeral_addr(),
        vec![ClientEntry {
            name: "laptop".into(),
            public_key: public_key_b64(&client_key),
            ipv4: Some(CLIENT_IPV4.into()),
            ipv6: Some(CLIENT_IPV6.into()),
        }],
    );
    config.quic.retry_mode = retry_mode;
    let peer = spawn_server(config)[0];

    Fixture {
        _dir: dir,
        peer,
        client_cert,
        client_key: client_key_path,
        stranger_cert,
        stranger_key: stranger_key_path,
    }
}

fn fixture(tag: &str) -> Fixture {
    fixture_with_retry(tag, QuicRetryMode::Adaptive)
}

// ── Multi-listener fixture ───────────────────────────────────────────

const BASIC_USERNAME: &str = "alice";
const BASIC_PASSWORD: &str = "correct horse battery staple";

/// A server running both authentication modes at once, on two ports.
struct DualFixture {
    _dir: TempDir,
    basic_peer: SocketAddr,
    cert_peer: SocketAddr,
    client_cert: PathBuf,
    client_key: PathBuf,
    /// A ready-made `Proxy-Authorization` value for the Basic listener.
    credentials: String,
}

/// Start one process listening on two ports: Basic on the first,
/// client-certificate on the second.
///
/// `auth.mode` fixes the TLS context when a socket is bound, so this is the
/// only shape in which one process can serve both.
fn dual_fixture(tag: &str) -> DualFixture {
    let dir = TempDir::new(tag);

    let server_key = p256_key();
    let (cert_path, key_path) = write_pem(
        dir.path(),
        "server",
        &server_key,
        &self_signed(&server_key, Some("masque-server")),
    );

    let client_key = p256_key();
    let (client_cert, client_key_path) = write_pem(
        dir.path(),
        "client",
        &client_key,
        &self_signed(&client_key, None),
    );

    let mut config = ServerConfig::default();
    config.tls.cert_path = cert_path;
    config.tls.key_path = key_path;
    // Only CONNECT-IP is under test here; the other forms would dial real
    // targets.
    config.tcp_proxy.enabled = false;
    config.udp_proxy.enabled = false;
    // Both on port 0: the server asks the kernel for distinct free ports and
    // reports which. They do not count as contending before bind, because
    // neither has a port yet; startup detects and retries a reuseport collision.
    config.listeners = vec![
        ListenerSection {
            listen_addr: ephemeral_addr(),
            transport: ListenerTransport::Http3,
            shards: 1,
            auth: AuthSection {
                enabled: true,
                mode: AuthMode::Basic,
                username: BASIC_USERNAME.into(),
                password_hash: masque::auth::hash_password(BASIC_PASSWORD.as_bytes()).unwrap(),
                users: Vec::new(),
            },
        },
        ListenerSection {
            listen_addr: ephemeral_addr(),
            transport: ListenerTransport::Http3,
            shards: 1,
            auth: AuthSection {
                enabled: true,
                mode: AuthMode::ClientCert,
                username: String::new(),
                password_hash: String::new(),
                users: Vec::new(),
            },
        },
    ];
    config.clients = vec![ClientEntry {
        name: "laptop".into(),
        public_key: public_key_b64(&client_key),
        ipv4: Some(CLIENT_IPV4.into()),
        ipv6: Some(CLIENT_IPV6.into()),
    }];

    // One shard each, in configuration order.
    let bound = spawn_server(config);
    assert_eq!(bound.len(), 2, "one shard per listener");

    DualFixture {
        _dir: dir,
        basic_peer: bound[0],
        cert_peer: bound[1],
        client_cert,
        client_key: client_key_path,
        credentials: format!(
            "Basic {}",
            STANDARD.encode(format!("{BASIC_USERNAME}:{BASIC_PASSWORD}"))
        ),
    }
}

// ── Roster reload fixture ────────────────────────────────────────────

/// Render a server configuration file with the given roster entries.
///
/// The listen address is `127.0.0.1:0`; the server reports the port it took.
/// Only the roster is reloaded, so rewriting this file leaves the bound socket
/// alone and the port stays valid across a reload.
fn server_config_file(cert: &Path, key: &Path, clients: &[(&str, &str)]) -> String {
    let mut text = format!(
        "[tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\n\n\
         [tcp_proxy]\nenabled = false\n\n[udp_proxy]\nenabled = false\n\n\
         [ip_proxy]\nenabled = true\nipv4_pool = \"10.89.0.0/24\"\n\
         ipv6_pool = \"fd00:abcd::/64\"\n\n\
         [[listeners]]\nlisten_addr = \"127.0.0.1:0\"\nshards = 1\n\n\
         [listeners.auth]\nenabled = true\nmode = \"client_cert\"\n",
        cert.display(),
        key.display()
    );
    for (name, public_key) in clients {
        text.push_str(&format!(
            "\n[[clients]]\nname = \"{name}\"\npublic_key = \"{public_key}\"\n"
        ));
    }
    text
}

/// Start a reloadable server and return the addresses it bound.
///
/// Separate from [`spawn_server`] because these tests need the `SIGHUP` handler,
/// which `run` installs after `bind` returns — so the caller still has to give
/// it a moment before raising one.
fn spawn_reloadable_server(config: ServerConfig, reload_path: PathBuf) -> Vec<SocketAddr> {
    let (bound_tx, bound_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let mut server = Server::bind_with_reload(config, Some(reload_path))
                .await
                .expect("server failed to bind");
            let _ = bound_tx.send(server.listen_addrs());
            let _ = server.run().await;
        });
    });

    let bound = bound_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("server did not report its listen addresses");
    // Bound is not the same as ready to reload: `run` installs the SIGHUP
    // handler, and a signal raised before that would be the default action.
    std::thread::sleep(Duration::from_millis(600));
    bound
}

/// Ask this process to reload, the way an operator would.
fn raise_sighup() {
    let status = std::process::Command::new("kill")
        .args(["-HUP", &std::process::id().to_string()])
        .status()
        .expect("failed to send SIGHUP");
    assert!(status.success(), "kill -HUP failed");
}

// ── Tests ────────────────────────────────────────────────────────────

/// Resolving `:0` once per shard would turn each shard into a different
/// listener. The first socket must select the port and every later socket in
/// that listener must join the exact same reuseport group. Separate listeners
/// must still receive separate ports.
#[cfg(target_os = "linux")]
#[test]
fn ephemeral_multi_shard_listeners_share_only_their_own_port() {
    let dir = TempDir::new("ephemeral-shards");
    let server_key = p256_key();
    let (cert_path, key_path) = write_pem(
        dir.path(),
        "server",
        &server_key,
        &self_signed(&server_key, Some("masque-server")),
    );

    let mut config = ServerConfig::default();
    config.tls.cert_path = cert_path;
    config.tls.key_path = key_path;
    config.tcp_proxy.enabled = false;
    config.udp_proxy.enabled = false;
    config.ip_proxy.enabled = false;
    config.listeners = vec![
        ListenerSection {
            listen_addr: ephemeral_addr(),
            transport: ListenerTransport::Http3,
            shards: 2,
            auth: AuthSection {
                enabled: false,
                ..Default::default()
            },
        },
        ListenerSection {
            listen_addr: ephemeral_addr(),
            transport: ListenerTransport::Http3,
            shards: 2,
            auth: AuthSection {
                enabled: false,
                ..Default::default()
            },
        },
    ];

    let bound = spawn_server(config);
    assert_eq!(bound.len(), 4);
    assert_ne!(bound[0].port(), 0);
    assert_eq!(
        bound[0], bound[1],
        "one listener's shards must share a port"
    );
    assert_eq!(
        bound[2], bound[3],
        "one listener's shards must share a port"
    );
    assert_ne!(
        bound[0], bound[2],
        "separate listeners must not join one reuseport group"
    );
}

/// Revoking a client must drop the tunnel it already holds, without restarting
/// the server and without disturbing anyone else.
///
/// Removing an entry only from future handshakes would leave the revoked client
/// connected for as long as it cared to stay, which is not revocation at all.
#[test]
fn revoked_client_is_disconnected_on_reload_while_others_keep_running() {
    let dir = TempDir::new("revoke");

    let server_key = p256_key();
    let (cert_path, key_path) = write_pem(
        dir.path(),
        "server",
        &server_key,
        &self_signed(&server_key, Some("masque-server")),
    );

    let doomed_key = p256_key();
    let (doomed_cert, doomed_key_path) = write_pem(
        dir.path(),
        "doomed",
        &doomed_key,
        &self_signed(&doomed_key, None),
    );
    let keeper_key = p256_key();
    let (keeper_cert, keeper_key_path) = write_pem(
        dir.path(),
        "keeper",
        &keeper_key,
        &self_signed(&keeper_key, None),
    );

    let config_path = dir.path().join("masque.toml");
    std::fs::write(
        &config_path,
        server_config_file(
            &cert_path,
            &key_path,
            &[
                ("doomed", &public_key_b64(&doomed_key)),
                ("keeper", &public_key_b64(&keeper_key)),
            ],
        ),
    )
    .unwrap();

    let config =
        masque::config::parse_toml(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    let peer = spawn_reloadable_server(config, config_path.clone())[0];

    let mut doomed = Client::connect(peer, &doomed_cert, &doomed_key_path).unwrap();
    doomed.handshake(Duration::from_secs(5)).unwrap();
    doomed.init_h3().unwrap();
    let doomed_stream = doomed.send_connect_ip("cf-connect-ip").unwrap();
    assert_eq!(
        doomed
            .response_status(doomed_stream, Duration::from_secs(5))
            .unwrap(),
        200
    );

    let mut keeper = Client::connect(peer, &keeper_cert, &keeper_key_path).unwrap();
    keeper.handshake(Duration::from_secs(5)).unwrap();
    keeper.init_h3().unwrap();
    let keeper_stream = keeper.send_connect_ip("cf-connect-ip").unwrap();
    assert_eq!(
        keeper
            .response_status(keeper_stream, Duration::from_secs(5))
            .unwrap(),
        200
    );

    // Revoke one client and reload.
    std::fs::write(
        &config_path,
        server_config_file(
            &cert_path,
            &key_path,
            &[("keeper", &public_key_b64(&keeper_key))],
        ),
    )
    .unwrap();
    raise_sighup();

    assert!(
        doomed.wait_for_close(Duration::from_secs(10)),
        "a revoked client must lose the tunnel it already holds"
    );

    // The other client must be untouched: revocation is targeted, not a
    // restart in disguise.
    assert!(
        !keeper.wait_for_close(Duration::from_secs(2)),
        "revoking one client must not disturb the others"
    );
    assert!(!keeper.quic.is_closed());
}

/// A reload that does not validate must leave the running roster in force
/// rather than locking everyone out.
#[test]
fn a_broken_reload_keeps_the_previous_roster() {
    let dir = TempDir::new("badreload");

    let server_key = p256_key();
    let (cert_path, key_path) = write_pem(
        dir.path(),
        "server",
        &server_key,
        &self_signed(&server_key, Some("masque-server")),
    );
    let client_key = p256_key();
    let (client_cert, client_key_path) = write_pem(
        dir.path(),
        "client",
        &client_key,
        &self_signed(&client_key, None),
    );

    let config_path = dir.path().join("masque.toml");
    let good = server_config_file(
        &cert_path,
        &key_path,
        &[("laptop", &public_key_b64(&client_key))],
    );
    std::fs::write(&config_path, &good).unwrap();

    let config = masque::config::parse_toml(&good).unwrap();
    let peer = spawn_reloadable_server(config, config_path.clone())[0];

    let mut client = Client::connect(peer, &client_cert, &client_key_path).unwrap();
    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();
    let stream = client.send_connect_ip("cf-connect-ip").unwrap();
    assert_eq!(
        client
            .response_status(stream, Duration::from_secs(5))
            .unwrap(),
        200
    );

    // An unparseable public key: the roster must be rejected as a whole.
    std::fs::write(
        &config_path,
        server_config_file(&cert_path, &key_path, &[("laptop", "!!not base64!!")]),
    )
    .unwrap();
    raise_sighup();

    assert!(
        !client.wait_for_close(Duration::from_secs(3)),
        "a rejected reload must not disconnect an authorized client"
    );

    // And a client presenting the still-valid key is still admitted.
    let mut second = Client::connect(peer, &client_cert, &client_key_path).unwrap();
    second.handshake(Duration::from_secs(5)).unwrap();
    second.init_h3().unwrap();
    let stream = second.send_connect_ip("cf-connect-ip").unwrap();
    assert_eq!(
        second
            .response_status(stream, Duration::from_secs(5))
            .unwrap(),
        200,
        "the previous roster must still be in force after a failed reload"
    );
}

/// SIGHUP replaces the server identity used by future QUIC handshakes without
/// rebuilding the UDP listener or disturbing an established connection. A bad
/// follow-up key must leave the last complete identity in force.
#[test]
fn http3_tls_identity_reloads_without_dropping_existing_connections() {
    let dir = TempDir::new("tls-reload-h3");

    let original_key = p256_key();
    let original_cert = self_signed(&original_key, Some("masque-server-original"));
    let (cert_path, key_path) = write_pem(dir.path(), "server", &original_key, &original_cert);
    let client_key = p256_key();
    let (client_cert, client_key_path) = write_pem(
        dir.path(),
        "client",
        &client_key,
        &self_signed(&client_key, None),
    );

    let config_path = dir.path().join("masque.toml");
    let config_text = server_config_file(
        &cert_path,
        &key_path,
        &[("laptop", &public_key_b64(&client_key))],
    );
    std::fs::write(&config_path, &config_text).unwrap();
    let config = masque::config::parse_toml(&config_text).unwrap();
    let peer = spawn_reloadable_server(config, config_path)[0];

    let mut established = Client::connect(peer, &client_cert, &client_key_path).unwrap();
    established.handshake(Duration::from_secs(5)).unwrap();
    assert_eq!(
        established.peer_certificate_der(),
        original_cert.to_der().unwrap()
    );
    established.init_h3().unwrap();

    let replacement_key = p256_key();
    let replacement_cert = self_signed(&replacement_key, Some("masque-server-replacement"));
    std::fs::write(&cert_path, replacement_cert.to_pem().unwrap()).unwrap();
    std::fs::write(
        &key_path,
        replacement_key
            .ec_key()
            .unwrap()
            .private_key_to_pem()
            .unwrap(),
    )
    .unwrap();
    raise_sighup();

    let replacement_der = replacement_cert.to_der().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut candidate = Client::connect(peer, &client_cert, &client_key_path).unwrap();
        candidate.handshake(Duration::from_secs(2)).unwrap();
        if candidate.peer_certificate_der() == replacement_der {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "new HTTP/3 handshakes did not pick up the replacement certificate"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // The connection negotiated under the old certificate remains usable.
    let stream = established.send_connect_ip("cf-connect-ip").unwrap();
    assert_eq!(
        established
            .response_status(stream, Duration::from_secs(5))
            .unwrap(),
        200
    );
    assert!(!established.quic.is_closed());

    // A partial ACME deployment (new certificate with an unrelated key) is
    // rejected as a pair; future handshakes keep using the previous snapshot.
    let mismatched_key = p256_key();
    std::fs::write(
        &key_path,
        mismatched_key
            .ec_key()
            .unwrap()
            .private_key_to_pem()
            .unwrap(),
    )
    .unwrap();
    raise_sighup();
    std::thread::sleep(Duration::from_millis(600));

    let mut after_failure = Client::connect(peer, &client_cert, &client_key_path).unwrap();
    after_failure.handshake(Duration::from_secs(5)).unwrap();
    assert_eq!(
        after_failure.peer_certificate_der(),
        replacement_der,
        "a rejected reload must keep the previous complete TLS identity"
    );
}

/// The whole point of the exercise: a client that authenticates with a
/// certificate and asks for `cf-connect-ip` gets a working tunnel, assigned the
/// addresses its roster entry pins it to.
#[test]
fn quic_retry_always_completes_a_real_handshake() {
    let fixture = fixture_with_retry("retry", QuicRetryMode::Always);
    let mut client =
        Client::connect(fixture.peer, &fixture.client_cert, &fixture.client_key).unwrap();

    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();
    let stream_id = client.send_connect_ip("connect-ip").unwrap();
    assert_eq!(
        client
            .response_status(stream_id, Duration::from_secs(5))
            .unwrap(),
        200
    );
}

/// A real ticket issued by the production TLS context must not allow the
/// resuming client to construct HTTP/3 before the full handshake. Because
/// CONNECT, CONNECT-UDP, and CONNECT-IP all enter through that same H3 layer,
/// this prevents every tunnel kind from executing as replayable Early Data.
#[test]
fn session_tickets_never_enable_zero_rtt_connect_requests() {
    let fixture = fixture("no-zero-rtt");
    let identity = Some((fixture.client_cert.as_path(), fixture.client_key.as_path()));

    let mut first = Client::connect_with_session(fixture.peer, identity, None, true).unwrap();
    first.handshake(Duration::from_secs(5)).unwrap();
    let session = first.session(Duration::from_secs(5)).unwrap();

    let mut resumed =
        Client::connect_with_session(fixture.peer, identity, Some(&session), true).unwrap();
    // Emit the resumed Initial. If the ticket advertised 0-RTT, quiche would
    // now report Early Data and permit H3 request headers to be serialized.
    resumed.flush().unwrap();
    assert!(
        !resumed.quic.is_in_early_data(),
        "the server's session ticket unexpectedly authorized Early Data"
    );
    assert!(
        resumed.init_h3().is_err(),
        "HTTP/3 became usable before the full handshake"
    );

    // Disabling Early Data must not disable ordinary session resumption or
    // requests after the handshake.
    resumed.handshake(Duration::from_secs(5)).unwrap();
    resumed.init_h3().unwrap();
    let stream_id = resumed.send_connect_ip("connect-ip").unwrap();
    assert_eq!(
        resumed
            .response_status(stream_id, Duration::from_secs(5))
            .unwrap(),
        200
    );
}

#[test]
fn registered_client_gets_its_pinned_addresses_over_cf_connect_ip() {
    let fixture = fixture("happy");
    let mut client =
        Client::connect(fixture.peer, &fixture.client_cert, &fixture.client_key).unwrap();

    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();

    let stream_id = client.send_connect_ip("cf-connect-ip").unwrap();
    let status = client
        .response_status(stream_id, Duration::from_secs(5))
        .unwrap();
    assert_eq!(status, 200, "cf-connect-ip must be accepted");

    let capsules = client.capsules(stream_id, 2, Duration::from_secs(5));
    let assigned = capsules
        .iter()
        .find_map(|frame| match frame {
            CapsuleFrame::AddressAssign(addrs) => Some(addrs),
            _ => None,
        })
        .expect("server must send ADDRESS_ASSIGN");

    // Pinned, not pool-allocated: a client that configures its interface out of
    // band only works if the server hands back the same addresses every time.
    let addresses: Vec<IpAddress> = assigned.iter().map(|a| a.ip.clone()).collect();
    assert!(
        addresses.contains(&IpAddress::V4(CLIENT_IPV4.parse::<Ipv4Addr>().unwrap())),
        "expected the pinned IPv4, got {addresses:?}"
    );
    assert!(
        addresses.contains(&IpAddress::V6(CLIENT_IPV6.parse::<Ipv6Addr>().unwrap())),
        "expected the pinned IPv6, got {addresses:?}"
    );

    // The default route tells the client it may send everything through here.
    assert!(
        capsules
            .iter()
            .any(|frame| matches!(frame, CapsuleFrame::RouteAdvertisement(_))),
        "expected ROUTE_ADVERTISEMENT, got {capsules:?}"
    );
}

/// One process, two listeners, two authentication modes.
///
/// `auth.mode` decides which TLS context a shard builds, and that is settled
/// when its socket is bound — so a Cloudflare-style client and a
/// standards-compliant one cannot share a listener. They can share a process,
/// and this is the test that says so.
///
/// It also pins the reason for sharing one: the address pool is per server, not
/// per listener, so the two clients cannot be handed the same tunnel address.
#[test]
fn two_listeners_serve_both_authentication_modes_from_one_process() {
    let fixture = dual_fixture("dual");

    // The certificate listener: authenticated during the handshake, pinned
    // addresses from the roster.
    let mut cert_client =
        Client::connect(fixture.cert_peer, &fixture.client_cert, &fixture.client_key).unwrap();
    cert_client.handshake(Duration::from_secs(5)).unwrap();
    cert_client.init_h3().unwrap();

    let stream_id = cert_client.send_connect_ip("cf-connect-ip").unwrap();
    assert_eq!(
        cert_client
            .response_status(stream_id, Duration::from_secs(5))
            .unwrap(),
        200,
        "the certificate listener must accept the enrolled client"
    );
    let cert_addresses = assigned_addresses(&mut cert_client, stream_id);
    assert!(
        cert_addresses.contains(&IpAddress::V4(CLIENT_IPV4.parse::<Ipv4Addr>().unwrap())),
        "expected the pinned IPv4, got {cert_addresses:?}"
    );

    // The Basic listener, at the same time, in the same process: no client
    // certificate at all, credentials on the request instead.
    let mut basic_client = Client::connect_anonymous(fixture.basic_peer).unwrap();
    basic_client.handshake(Duration::from_secs(5)).unwrap();
    basic_client.init_h3().unwrap();

    let stream_id = basic_client
        .send_connect_ip_with_credentials("connect-ip", Some(&fixture.credentials))
        .unwrap();
    assert_eq!(
        basic_client
            .response_status(stream_id, Duration::from_secs(5))
            .unwrap(),
        200,
        "the Basic listener must accept correct credentials"
    );
    let basic_addresses = assigned_addresses(&mut basic_client, stream_id);
    assert!(
        !basic_addresses.is_empty(),
        "the Basic listener must assign an address from the pool"
    );

    // One pool behind both listeners. Two processes could not do this: each
    // would allocate from its own copy and hand out the same addresses.
    for address in &basic_addresses {
        assert!(
            !cert_addresses.contains(address),
            "listeners handed out the same address {address:?}; the pool is not shared"
        );
    }
}

/// Each listener enforces its own mode and only its own.
#[test]
fn a_listener_enforces_only_its_own_authentication_mode() {
    let fixture = dual_fixture("dual-refuse");

    // Basic listener, no credentials: refused at the request, not the
    // handshake, because this listener never asks for a certificate.
    let mut client = Client::connect_anonymous(fixture.basic_peer).unwrap();
    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();
    let stream_id = client.send_connect_ip("connect-ip").unwrap();
    assert_eq!(
        client
            .response_status(stream_id, Duration::from_secs(5))
            .unwrap(),
        407,
        "the Basic listener must still demand credentials"
    );

    // Certificate listener, same anonymous client: refused during the
    // handshake, before it can open a stream.
    let mut client = Client::connect_anonymous(fixture.cert_peer).unwrap();
    let _ = client.handshake(Duration::from_secs(5));
    assert!(
        client.wait_for_close(Duration::from_secs(5)),
        "the certificate listener must not serve a client without a certificate"
    );

    // And credentials are no substitute for a certificate on that listener.
    let mut client = Client::connect_anonymous(fixture.cert_peer).unwrap();
    let _ = client.handshake(Duration::from_secs(5));
    assert!(
        client.wait_for_close(Duration::from_secs(5)),
        "Basic credentials must not open the certificate listener"
    );
}

/// Collect the addresses the server assigned on `stream_id`.
fn assigned_addresses(client: &mut Client, stream_id: u64) -> Vec<IpAddress> {
    client
        .capsules(stream_id, 2, Duration::from_secs(5))
        .iter()
        .find_map(|frame| match frame {
            CapsuleFrame::AddressAssign(addrs) => {
                Some(addrs.iter().map(|a| a.ip.clone()).collect())
            }
            _ => None,
        })
        .expect("server must send ADDRESS_ASSIGN")
}

/// The registered `connect-ip` spelling has to keep working: accepting
/// Cloudflare's identifier must not come at the cost of RFC 9484 clients.
#[test]
fn registered_client_may_also_use_the_rfc_protocol_identifier() {
    let fixture = fixture("rfc");
    let mut client =
        Client::connect(fixture.peer, &fixture.client_cert, &fixture.client_key).unwrap();

    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();

    let stream_id = client.send_connect_ip("connect-ip").unwrap();
    assert_eq!(
        client
            .response_status(stream_id, Duration::from_secs(5))
            .unwrap(),
        200
    );
}

/// A full-MTU IP packet must fit into a single QUIC DATAGRAM.
///
/// These clients run a 1280-byte tunnel MTU and disable path-MTU discovery, so
/// they will emit 1280-byte packets from the first moment. If the framed packet
/// does not fit, pings and handshakes still work while bulk traffic silently
/// disappears — the hardest possible failure mode to attribute.
///
/// The margin is tighter than it looks: QUIC subtracts the peer's connection ID
/// from every packet's payload budget, and these clients use a 20-byte
/// connection ID, which is the largest QUIC allows.
#[test]
fn a_full_mtu_ip_packet_fits_in_one_datagram() {
    let fixture = fixture("mtu");
    let mut client =
        Client::connect(fixture.peer, &fixture.client_cert, &fixture.client_key).unwrap();

    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();
    let stream_id = client.send_connect_ip("cf-connect-ip").unwrap();
    assert_eq!(
        client
            .response_status(stream_id, Duration::from_secs(5))
            .unwrap(),
        200
    );

    // Frame a packet the size of the configured tunnel MTU, the way the client
    // would: quarter stream ID, context ID 0, then the raw IP packet.
    let packet = vec![0x45u8; TUN_MTU];
    let framed = DatagramHeader::new(stream_id).unwrap().encode(&packet);
    assert!(framed.len() > TUN_MTU, "framing must add the header");

    let writable = client
        .quic
        .dgram_max_writable_len()
        .expect("server must advertise DATAGRAM support");

    // The client's own budget is measured against the server's 16-byte
    // connection ID, while the server's return path is measured against this
    // client's 20-byte one. Requiring the difference as headroom means the
    // assertion covers both directions, not just the roomier one.
    let return_path_headroom = CLIENT_CONN_ID_LEN - SERVER_CONN_ID_LEN;
    assert!(
        writable >= framed.len() + return_path_headroom,
        "a {TUN_MTU}-byte packet frames to {} bytes but only {writable} are writable \
         ({return_path_headroom} of which the tighter return path needs); raise \
         quic.max_datagram_size or lower ip_proxy.tun_mtu",
        framed.len()
    );

    // Budget arithmetic is one thing; quiche actually accepting the write is
    // the behaviour that matters.
    client
        .quic
        .dgram_send(&framed)
        .expect("a full-MTU packet must be sendable as one datagram");
    client.flush().unwrap();
}

/// Changing the client's UDP source port must preserve both the QUIC/H3
/// connection and an already-open CONNECT stream. This is the common NAT
/// rebinding form of connection migration and exercises the spare CID that the
/// server publishes after the handshake.
#[test]
fn client_source_port_migrates_without_reconnecting() {
    let fixture = fixture("migration");
    let mut client =
        Client::connect(fixture.peer, &fixture.client_cert, &fixture.client_key).unwrap();

    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();
    let existing_stream = client.send_connect_ip("connect-ip").unwrap();
    assert_eq!(
        client
            .response_status(existing_stream, Duration::from_secs(5))
            .unwrap(),
        200
    );

    let (old_local, new_local) = client.migrate_source(Duration::from_secs(5)).unwrap();
    assert_eq!(old_local.ip(), new_local.ip());
    assert_ne!(old_local.port(), new_local.port());

    // Response-body state belonging to the pre-migration stream survives.
    let capsules = client.capsules(existing_stream, 2, Duration::from_secs(5));
    assert!(
        capsules
            .iter()
            .any(|frame| matches!(frame, CapsuleFrame::AddressAssign(_))),
        "the pre-migration CONNECT stream stopped making progress"
    );

    // A new stream on the same H3 connection works without another TLS or
    // client-certificate handshake.
    let later_stream = client.send_connect_ip("connect-ip").unwrap();
    assert_eq!(
        client
            .response_status(later_stream, Duration::from_secs(5))
            .unwrap(),
        200
    );
    assert!(!client.quic.is_closed());
}

/// A validated address change, not only a NAT port remap, keeps the same
/// authenticated HTTP/3 connection alive. The loopback /8 gives the test two
/// routable local addresses without depending on an external interface.
#[cfg(target_os = "linux")]
#[test]
fn client_source_ip_migrates_without_reconnecting() {
    let fixture = fixture("migration-ip");
    let mut client =
        Client::connect(fixture.peer, &fixture.client_cert, &fixture.client_key).unwrap();

    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();
    let first_stream = client.send_connect_ip("connect-ip").unwrap();
    assert_eq!(
        client
            .response_status(first_stream, Duration::from_secs(5))
            .unwrap(),
        200
    );

    let (old_local, new_local) = client
        .migrate_source_from("127.0.0.2".parse().unwrap(), Duration::from_secs(5))
        .unwrap();
    assert_ne!(old_local.ip(), new_local.ip());

    let later_stream = client.send_connect_ip("connect-ip").unwrap();
    assert_eq!(
        client
            .response_status(later_stream, Duration::from_secs(5))
            .unwrap(),
        200
    );
    assert!(!client.quic.is_closed());
}

/// Linux steers every server-issued destination CID to its owning reuseport
/// socket. Source-port migration must therefore stay on the connection's
/// shard instead of paying the userspace cross-shard forwarding cost.
#[cfg(target_os = "linux")]
#[test]
fn migrated_connections_stay_on_reuseport_owner() {
    let dir = TempDir::new("migration-shards");
    let server_key = p256_key();
    let (server_cert, server_key_path) = write_pem(
        dir.path(),
        "server",
        &server_key,
        &self_signed(&server_key, Some("masque-server")),
    );
    let client_key = p256_key();
    let (client_cert, client_key_path) = write_pem(
        dir.path(),
        "client",
        &client_key,
        &self_signed(&client_key, None),
    );
    let mut config = server_config(
        server_cert,
        server_key_path,
        ephemeral_addr(),
        vec![ClientEntry {
            name: "migrating-client".into(),
            public_key: public_key_b64(&client_key),
            ipv4: None,
            ipv6: None,
        }],
    );
    config.listeners[0].shards = 4;
    config.observability.listen_addr = Some(ephemeral_addr());
    let (listeners, observability) = spawn_server_with_observability(config);
    assert_eq!(listeners.len(), 4);
    let peer = listeners[0];
    let observability = observability.expect("metrics listener must be bound");

    for _ in 0..8 {
        let mut client = Client::connect(peer, &client_cert, &client_key_path).unwrap();
        client.handshake(Duration::from_secs(5)).unwrap();
        client.migrate_source(Duration::from_secs(5)).unwrap();
        assert!(!client.quic.is_closed());
    }

    let metrics = scrape_metrics(observability);
    assert!(
        metrics.lines().any(|line| {
            line.starts_with("masque_quic_path_events_total{")
                && line.contains("event=\"peer_migrated\"")
                && line
                    .rsplit_once(' ')
                    .and_then(|(_, value)| value.parse::<u64>().ok())
                    .is_some_and(|value| value >= 8)
        }),
        "all eight migrations should be observable as completed peer migrations"
    );
    assert_eq!(
        metric_total(&metrics, "masque_quic_cross_shard_forwarded_packets_total{"),
        0,
        "CID steering should keep migrated packets on their owning shard"
    );
}

/// A validated path cannot use migration to bypass the live-connection cap of
/// its new source. The old admission remains balanced and the already-admitted
/// connection at the destination source is unaffected.
#[cfg(target_os = "linux")]
#[test]
fn migration_to_a_full_source_is_closed() {
    let dir = TempDir::new("migration-source-limit");
    let server_key = p256_key();
    let (server_cert, server_key_path) = write_pem(
        dir.path(),
        "server",
        &server_key,
        &self_signed(&server_key, Some("masque-server")),
    );
    let client_key = p256_key();
    let (client_cert, client_key_path) = write_pem(
        dir.path(),
        "client",
        &client_key,
        &self_signed(&client_key, None),
    );
    let mut config = server_config(
        server_cert,
        server_key_path,
        ephemeral_addr(),
        vec![ClientEntry {
            name: "limited-client".into(),
            public_key: public_key_b64(&client_key),
            ipv4: None,
            ipv6: None,
        }],
    );
    config.server.max_connections_per_ip = 1;
    let peer = spawn_server(config)[0];

    let occupied_source = "127.0.0.2".parse().unwrap();
    let mut occupied =
        Client::connect_from(peer, &client_cert, &client_key_path, occupied_source).unwrap();
    occupied.handshake(Duration::from_secs(5)).unwrap();

    let mut migrating = Client::connect(peer, &client_cert, &client_key_path).unwrap();
    migrating.handshake(Duration::from_secs(5)).unwrap();
    let _ = migrating.migrate_source_from(occupied_source, Duration::from_secs(2));
    assert!(
        migrating.wait_for_close(Duration::from_secs(5)),
        "migration into a full source budget remained open"
    );
    assert_eq!(
        migrating
            .quic
            .peer_error()
            .map(|error| (error.is_app, error.error_code)),
        Some((true, MIGRATION_SOURCE_LIMIT_ERROR))
    );

    occupied.drive().unwrap();
    assert!(!occupied.quic.is_closed());
}

/// A network change often makes the replacement QUIC connection arrive before
/// the dead one reaches its idle timeout. Because both connections prove
/// possession of the same enrolled key, the replacement must be allowed to
/// take over the pinned return route immediately rather than waiting up to a
/// minute for the stale lease to disappear.
#[test]
fn registered_client_can_reconnect_while_the_old_tunnel_is_still_present() {
    let fixture = fixture("reconnect");

    let mut old = Client::connect(fixture.peer, &fixture.client_cert, &fixture.client_key).unwrap();
    old.handshake(Duration::from_secs(5)).unwrap();
    old.init_h3().unwrap();
    let old_stream = old.send_connect_ip("cf-connect-ip").unwrap();
    assert_eq!(
        old.response_status(old_stream, Duration::from_secs(5))
            .unwrap(),
        200
    );

    // Keep `old` alive while a second connection using the same enrolled key
    // claims exactly the same fixed addresses.
    let mut replacement =
        Client::connect(fixture.peer, &fixture.client_cert, &fixture.client_key).unwrap();
    replacement.handshake(Duration::from_secs(5)).unwrap();
    replacement.init_h3().unwrap();
    let stream_id = replacement.send_connect_ip("cf-connect-ip").unwrap();
    assert_eq!(
        replacement
            .response_status(stream_id, Duration::from_secs(5))
            .unwrap(),
        200
    );

    let capsules = replacement.capsules(stream_id, 2, Duration::from_secs(5));
    let assigned = capsules
        .iter()
        .find_map(|frame| match frame {
            CapsuleFrame::AddressAssign(addrs) => Some(addrs),
            _ => None,
        })
        .expect("replacement tunnel must receive its fixed addresses");
    assert!(
        assigned
            .iter()
            .any(|addr| { addr.ip == IpAddress::V4(CLIENT_IPV4.parse::<Ipv4Addr>().unwrap()) })
    );

    // Prevent an over-eager optimizer from ending the old connection's lifetime
    // before the replacement has completed.
    assert!(!old.quic.is_closed());
}

/// Address exhaustion must be decided before the success response. The old
/// ordering sent 200 first and then attempted an impossible second 503 header
/// block, leaving the caller with a successful but unusable tunnel.
#[test]
fn exhausted_address_pool_returns_503_instead_of_an_early_200() {
    let dir = TempDir::new("exhausted");

    let server_key = p256_key();
    let (server_cert, server_key_path) = write_pem(
        dir.path(),
        "server",
        &server_key,
        &self_signed(&server_key, Some("masque-server")),
    );

    let first_key = p256_key();
    let (first_cert, first_key_path) = write_pem(
        dir.path(),
        "first",
        &first_key,
        &self_signed(&first_key, None),
    );
    let second_key = p256_key();
    let (second_cert, second_key_path) = write_pem(
        dir.path(),
        "second",
        &second_key,
        &self_signed(&second_key, None),
    );

    let mut config = server_config(
        server_cert,
        server_key_path,
        ephemeral_addr(),
        vec![
            ClientEntry {
                name: "first".into(),
                public_key: public_key_b64(&first_key),
                ipv4: None,
                ipv6: None,
            },
            ClientEntry {
                name: "second".into(),
                public_key: public_key_b64(&second_key),
                ipv4: None,
                ipv6: None,
            },
        ],
    );
    // network=.0, TUN gateway=.1, and the sole client address=.2.
    config.ip_proxy.ipv4_pool = "10.89.0.0/30".into();
    config.ip_proxy.ipv6_pool.clear();
    let peer = spawn_server(config)[0];

    let mut first = Client::connect(peer, &first_cert, &first_key_path).unwrap();
    first.handshake(Duration::from_secs(5)).unwrap();
    first.init_h3().unwrap();
    let first_stream = first.send_connect_ip("cf-connect-ip").unwrap();
    assert_eq!(
        first
            .response_status(first_stream, Duration::from_secs(5))
            .unwrap(),
        200
    );
    let capsules = first.capsules(first_stream, 2, Duration::from_secs(5));
    let assigned = capsules
        .iter()
        .find_map(|frame| match frame {
            CapsuleFrame::AddressAssign(addrs) => Some(addrs),
            _ => None,
        })
        .unwrap();
    assert!(
        assigned
            .iter()
            .any(|addr| { addr.ip == IpAddress::V4("10.89.0.2".parse::<Ipv4Addr>().unwrap()) })
    );

    let mut second = Client::connect(peer, &second_cert, &second_key_path).unwrap();
    second.handshake(Duration::from_secs(5)).unwrap();
    second.init_h3().unwrap();
    let second_stream = second.send_connect_ip("cf-connect-ip").unwrap();
    assert_eq!(
        second
            .response_status(second_stream, Duration::from_secs(5))
            .unwrap(),
        503
    );

    assert!(!first.quic.is_closed());
}

/// An unregistered key must never get a tunnel. The rejection lands as a TLS
/// alert, so the connection is torn down rather than answering the request.
#[test]
fn unregistered_client_certificate_is_refused() {
    let fixture = fixture("stranger");
    let mut client =
        Client::connect(fixture.peer, &fixture.stranger_cert, &fixture.stranger_key).unwrap();

    // The handshake may reach "established" locally before the alert arrives,
    // so its result is not the thing under test.
    let _ = client.handshake(Duration::from_secs(2));
    assert!(
        client.wait_for_close(Duration::from_secs(5)),
        "a key outside the roster must not keep a usable connection"
    );

    // The rejection has to come from TLS, not from the server's own
    // belt-and-braces check after the handshake: only a TLS alert stops the
    // client before it can open a stream, and only `access_denied` tells the
    // operator their key is not enrolled rather than that TLS itself is broken.
    assert_eq!(
        client.quic.peer_error().map(|e| (e.is_app, e.error_code)),
        Some((false, ACCESS_DENIED_CRYPTO_ERROR)),
        "expected a CRYPTO_ERROR carrying TLS alert access_denied"
    );
}

/// A client that offers no certificate at all must be refused too — the
/// `FAIL_IF_NO_PEER_CERT` half of the verify mode. Without it, omitting the
/// certificate would skip the verify callback entirely and reach the request
/// path with no identity.
#[test]
fn client_without_a_certificate_is_refused() {
    let fixture = fixture("nocert");

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(fixture.peer).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let local = socket.local_addr().unwrap();

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.verify_peer(false);
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();
    config.set_max_idle_timeout(10_000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(1_048_576);
    config.set_initial_max_stream_data_bidi_local(262_144);
    config.set_initial_max_streams_bidi(16);

    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut scid).unwrap();
    let quic = quiche::connect(
        Some("consumer-masque.cloudflareclient.com"),
        &quiche::ConnectionId::from_ref(&scid),
        local,
        fixture.peer,
        &mut config,
    )
    .unwrap();

    let mut client = Client {
        socket,
        quic,
        h3: None,
    };
    let _ = client.handshake(Duration::from_secs(2));
    assert!(
        client.wait_for_close(Duration::from_secs(5)),
        "a client with no certificate must not keep a usable connection"
    );
}
