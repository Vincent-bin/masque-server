use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use masque::capsule::decoder::CapsuleDecoder;
use masque::capsule::CapsuleFrame;
use quiche::h3::NameValue;
use ring::rand::SecureRandom;
use tracing::{error, info, warn};

const MAX_DATAGRAM_SIZE: usize = 1350;
const BUF_SIZE: usize = 65535;

struct InFlight {
    sent_at: HashMap<u64, Instant>,
    order: VecDeque<(u64, Instant)>,
}

impl InFlight {
    fn with_capacity(window: usize) -> Self {
        Self {
            sent_at: HashMap::with_capacity(window * 2),
            order: VecDeque::with_capacity(window * 2),
        }
    }

    fn insert(&mut self, sequence: u64, sent_at: Instant) {
        self.sent_at.insert(sequence, sent_at);
        self.order.push_back((sequence, sent_at));
    }

    fn remove(&mut self, sequence: &u64) -> bool {
        self.sent_at.remove(sequence).is_some()
    }

    fn expire(&mut self, now: Instant, expiry: Duration) -> u64 {
        let mut expired = 0;

        while let Some(&(sequence, sent_at)) = self.order.front() {
            if now.saturating_duration_since(sent_at) < expiry {
                break;
            }
            self.order.pop_front();
            if self.sent_at.remove(&sequence).is_some() {
                expired += 1;
            }
        }

        expired
    }

    fn len(&self) -> usize {
        self.sent_at.len()
    }

    fn is_empty(&self) -> bool {
        self.sent_at.is_empty()
    }
}

// ---------------------------------------------------------------------------
// QUIC + H3 test client
// ---------------------------------------------------------------------------

struct Client {
    socket: UdpSocket,
    quic: quiche::Connection,
    h3: Option<quiche::h3::Connection>,
    peer: SocketAddr,
    local: SocketAddr,
}

impl Client {
    fn connect(server_addr: &str) -> Result<Self> {
        let peer: SocketAddr = server_addr.parse().context("parse server addr")?;

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(peer)?;
        let local = socket.local_addr()?;

        let mut scid_buf = [0u8; quiche::MAX_CONN_ID_LEN];
        ring::rand::SystemRandom::new()
            .fill(&mut scid_buf)
            .map_err(|_| anyhow::anyhow!("RNG failed"))?;
        let scid = quiche::ConnectionId::from_ref(&scid_buf);

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        config.verify_peer(false);
        config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
        config.set_max_idle_timeout(30_000);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(128);
        config.set_initial_max_streams_uni(100);
        config.enable_pacing(true);
        config.enable_dgram(true, 1000, 1000);

        let quic = quiche::connect(Some("server"), &scid, local, peer, &mut config)?;

        Ok(Client {
            socket,
            quic,
            h3: None,
            peer,
            local,
        })
    }

    /// Send all pending QUIC packets to the network.
    fn flush(&mut self) -> Result<()> {
        let mut out = [0u8; MAX_DATAGRAM_SIZE];
        loop {
            match self.quic.send(&mut out) {
                Ok((len, send_info)) => {
                    let delay = send_info.at.saturating_duration_since(Instant::now());
                    if !delay.is_zero() {
                        std::thread::sleep(delay);
                    }
                    self.socket.send(&out[..len])?;
                }
                Err(quiche::Error::Done) => return Ok(()),
                Err(e) => bail!("QUIC send: {e}"),
            }
        }
    }

    /// Receive one packet from the network and feed it to QUIC.
    fn recv_once(&mut self) -> Result<bool> {
        let timeout = self
            .quic
            .timeout()
            .unwrap_or(Duration::from_millis(50))
            .max(Duration::from_millis(1));
        self.socket.set_read_timeout(Some(timeout))?;

        let mut buf = [0u8; BUF_SIZE];
        match self.socket.recv(&mut buf) {
            Ok(len) => {
                let info = quiche::RecvInfo {
                    from: self.peer,
                    to: self.local,
                };
                match self.quic.recv(&mut buf[..len], info) {
                    Ok(_) | Err(quiche::Error::Done) => {}
                    Err(e) => bail!("QUIC recv: {e}"),
                }
                Ok(true)
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                self.quic.on_timeout();
                Ok(false)
            }
            Err(e) => bail!("socket recv: {e}"),
        }
    }

    /// One round of flush → recv → flush.
    fn drive(&mut self) -> Result<()> {
        self.flush()?;
        self.recv_once()?;
        self.flush()?;
        Ok(())
    }

    /// Complete the QUIC handshake.
    fn handshake(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            self.flush()?;
            if self.quic.is_established() {
                return Ok(());
            }
            if Instant::now() > deadline {
                bail!("handshake timeout");
            }
            self.recv_once()?;
        }
    }

    /// Create the HTTP/3 layer on top of the QUIC connection.
    fn init_h3(&mut self) -> Result<()> {
        let mut h3_config = quiche::h3::Config::new()?;
        h3_config.enable_extended_connect(true);
        let h3 = quiche::h3::Connection::with_transport(&mut self.quic, &h3_config)?;
        self.h3 = Some(h3);
        self.wait_for_server_capabilities(Duration::from_secs(5))
    }

    /// Wait until the server SETTINGS advertise the capabilities required by
    /// a standards-compliant CONNECT-UDP client such as Surge.
    fn wait_for_server_capabilities(&mut self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let capabilities_ready = {
                let h3 = self.h3.as_ref().context("H3 not initialised")?;
                h3.extended_connect_enabled_by_peer() && h3.dgram_enabled_by_peer(&self.quic)
            };
            if capabilities_ready {
                return Ok(());
            }

            {
                let h3 = self.h3.as_mut().context("H3 not initialised")?;
                loop {
                    match h3.poll(&mut self.quic) {
                        Ok(_) => continue,
                        Err(quiche::h3::Error::Done) => break,
                        Err(error) => {
                            bail!("H3 poll while waiting for SETTINGS: {error}")
                        }
                    }
                }
            }

            if Instant::now() > deadline {
                bail!("server did not advertise Extended CONNECT and HTTP Datagram support");
            }
            self.drive()?;
        }
    }

    /// Send an HTTP/3 request; returns the stream ID.
    fn send_request(&mut self, headers: &[quiche::h3::Header], fin: bool) -> Result<u64> {
        let h3 = self.h3.as_mut().context("H3 not initialised")?;
        let stream_id = h3.send_request(&mut self.quic, headers, fin)?;
        self.flush()?;
        Ok(stream_id)
    }

    /// Queue request headers and a small body before flushing QUIC. This
    /// exercises servers that receive HEADERS and DATA in the same packet.
    fn send_request_with_body(
        &mut self,
        headers: &[quiche::h3::Header],
        body: &[u8],
        fin: bool,
    ) -> Result<u64> {
        let h3 = self.h3.as_mut().context("H3 not initialised")?;
        let stream_id = h3.send_request(&mut self.quic, headers, false)?;
        let written = h3.send_body(&mut self.quic, stream_id, body, fin)?;
        if written != body.len() {
            bail!("short early CONNECT body write: {written}/{}", body.len());
        }
        self.flush()?;
        Ok(stream_id)
    }

    /// Send an entire HTTP/3 request body, retrying partial and blocked writes.
    fn send_body_all(&mut self, stream_id: u64, body: &[u8], fin: bool) -> Result<()> {
        let mut offset = 0;
        while offset < body.len() {
            let result = {
                let h3 = self.h3.as_mut().context("H3 not initialised")?;
                h3.send_body(&mut self.quic, stream_id, &body[offset..], fin)
            };
            match result {
                Ok(0) | Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {
                    self.drive()?;
                }
                Ok(written) => {
                    offset += written;
                    self.flush()?;
                }
                Err(error) => bail!("send CONNECT body: {error}"),
            }
        }

        if body.is_empty() && fin {
            loop {
                let result = {
                    let h3 = self.h3.as_mut().context("H3 not initialised")?;
                    h3.send_body(&mut self.quic, stream_id, b"", true)
                };
                match result {
                    Ok(_) => break,
                    Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {
                        self.drive()?;
                    }
                    Err(error) => bail!("finish CONNECT body: {error}"),
                }
            }
        }
        self.flush()
    }

    fn recv_body_bytes(
        &mut self,
        stream_id: u64,
        expected_len: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        let mut received = Vec::with_capacity(expected_len);
        let mut buffer = [0_u8; BUF_SIZE];

        while received.len() < expected_len {
            {
                let h3 = self.h3.as_mut().context("H3 not initialised")?;
                loop {
                    match h3.poll(&mut self.quic) {
                        Ok((sid, quiche::h3::Event::Data)) if sid == stream_id => {}
                        Ok((sid, quiche::h3::Event::Finished)) if sid == stream_id => {
                            if received.len() < expected_len {
                                bail!(
                                    "CONNECT response finished after {} of {expected_len} bytes",
                                    received.len()
                                );
                            }
                        }
                        Ok(_) => continue,
                        Err(quiche::h3::Error::Done) => break,
                        Err(error) => {
                            bail!("H3 poll for CONNECT body: {error}")
                        }
                    }
                }

                loop {
                    match h3.recv_body(&mut self.quic, stream_id, &mut buffer) {
                        Ok(len) => received.extend_from_slice(&buffer[..len]),
                        Err(quiche::h3::Error::Done) => break,
                        Err(error) => bail!("receive CONNECT body: {error}"),
                    }
                }
            }

            if received.len() >= expected_len {
                break;
            }
            if Instant::now() > deadline {
                bail!(
                    "CONNECT response timeout after {} of {expected_len} bytes",
                    received.len()
                );
            }
            self.drive()?;
        }
        Ok(received)
    }

    /// Poll until we get response headers for any stream, return (stream_id, status).
    fn poll_response(&mut self, timeout: Duration) -> Result<(u64, u16)> {
        let (stream_id, status, _) = self.poll_response_headers(timeout)?;
        Ok((stream_id, status))
    }

    fn poll_response_headers(
        &mut self,
        timeout: Duration,
    ) -> Result<(u64, u16, Vec<quiche::h3::Header>)> {
        let deadline = Instant::now() + timeout;
        loop {
            let h3 = self.h3.as_mut().context("H3 not initialised")?;
            loop {
                match h3.poll(&mut self.quic) {
                    Ok((sid, quiche::h3::Event::Headers { list, .. })) => {
                        let status = list
                            .iter()
                            .find(|h| h.name() == b":status")
                            .map(|h| String::from_utf8_lossy(h.value()).parse::<u16>())
                            .transpose()
                            .map_err(|e| anyhow::anyhow!("bad :status: {e}"))?
                            .context("missing :status")?;
                        return Ok((sid, status, list));
                    }
                    Ok(_) => continue,
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => bail!("H3 poll: {e}"),
                }
            }

            if Instant::now() > deadline {
                bail!("response timeout");
            }
            self.drive()?;
        }
    }

    /// Send a QUIC DATAGRAM carrying an HTTP Datagram for the given stream.
    fn send_dgram(&mut self, stream_id: u64, payload: &[u8]) -> Result<()> {
        let encoded = masque::datagram::encode_payload(stream_id, payload)
            .map_err(|e| anyhow::anyhow!("encode dgram: {e}"))?;
        self.quic.dgram_send(&encoded)?;
        self.flush()?;
        Ok(())
    }

    /// Drive the connection and collect capsules from the H3 body stream.
    fn recv_capsules(&mut self, stream_id: u64, timeout: Duration) -> Result<Vec<CapsuleFrame>> {
        let deadline = Instant::now() + timeout;
        let mut decoder = CapsuleDecoder::new();
        let mut frames = Vec::new();
        let mut body_buf = [0u8; BUF_SIZE];

        while Instant::now() < deadline {
            // Poll + recv_body in a single scope to avoid borrow conflicts.
            let mut got_data = true;
            while got_data {
                got_data = false;
                let h3 = self.h3.as_mut().context("H3 not initialised")?;
                match h3.poll(&mut self.quic) {
                    Ok((sid, quiche::h3::Event::Data)) if sid == stream_id => {
                        got_data = true;
                    }
                    Ok(_) => {
                        got_data = true;
                        continue;
                    }
                    Err(quiche::h3::Error::Done) => {}
                    Err(e) => bail!("H3 poll: {e}"),
                }

                // Drain all available body data.
                loop {
                    let h3 = self.h3.as_mut().unwrap();
                    match h3.recv_body(&mut self.quic, stream_id, &mut body_buf) {
                        Ok(len) => match decoder.decode(&body_buf[..len]) {
                            Ok(mut capsules) => frames.append(&mut capsules),
                            Err(masque::capsule::decoder::DecodeError::Incomplete) => {}
                            Err(e) => bail!("capsule decode: {e:?}"),
                        },
                        Err(quiche::h3::Error::Done) => break,
                        Err(e) => bail!("recv_body: {e}"),
                    }
                }
            }

            if !frames.is_empty() {
                return Ok(frames);
            }
            self.drive()?;
        }

        if frames.is_empty() {
            bail!("capsule timeout — no capsules received");
        }
        Ok(frames)
    }

    /// Wait for a QUIC DATAGRAM and decode it as an HTTP Datagram.
    fn recv_dgram(&mut self, timeout: Duration) -> Result<masque::datagram::HttpDatagram> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut buf = [0u8; BUF_SIZE];
            match self.quic.dgram_recv(&mut buf) {
                Ok(len) => {
                    return masque::datagram::decode(&buf[..len])
                        .map_err(|e| anyhow::anyhow!("decode dgram: {e}"));
                }
                Err(quiche::Error::Done) => {}
                Err(e) => bail!("dgram recv: {e}"),
            }

            if Instant::now() > deadline {
                bail!("datagram timeout");
            }
            self.drive()?;
        }
    }

    /// Saturate one CONNECT-UDP tunnel with a bounded number of in-flight
    /// echo requests. Returns (sent packets, received packets, expired packets).
    fn run_echo_throughput(
        &mut self,
        stream_id: u64,
        payload_size: usize,
        duration: Duration,
        window: usize,
        expiry: Duration,
    ) -> Result<(u64, u64, u64)> {
        if payload_size < 8 {
            bail!("benchmark payload must be at least 8 bytes");
        }

        self.socket.set_nonblocking(true)?;
        let started = Instant::now();
        let deadline = started + duration;
        let drain_deadline = deadline + expiry;
        let mut payload = vec![0x5a; payload_size];
        let mut encoded = Vec::with_capacity(payload_size + 16);
        let mut packet_buf = [0u8; BUF_SIZE];
        let mut dgram_buf = [0u8; BUF_SIZE];
        let mut in_flight = InFlight::with_capacity(window);
        let mut next_sequence = 0_u64;
        let mut sent = 0_u64;
        let mut received = 0_u64;
        let mut expired = 0_u64;

        while Instant::now() < drain_deadline {
            let now = Instant::now();
            expired += in_flight.expire(now, expiry);

            let mut made_progress = false;
            while now < deadline && in_flight.len() < window {
                payload[..8].copy_from_slice(&next_sequence.to_be_bytes());
                masque::datagram::encode_payload_into(stream_id, &payload, &mut encoded)
                    .map_err(|e| anyhow::anyhow!("encode datagram: {e}"))?;

                match self.quic.dgram_send(&encoded) {
                    Ok(()) => {
                        in_flight.insert(next_sequence, now);
                        next_sequence += 1;
                        sent += 1;
                        made_progress = true;
                    }
                    Err(quiche::Error::Done) => break,
                    Err(e) => bail!("dgram send: {e}"),
                }
            }

            self.flush()?;

            loop {
                match self.socket.recv(&mut packet_buf) {
                    Ok(len) => {
                        let info = quiche::RecvInfo {
                            from: self.peer,
                            to: self.local,
                        };
                        match self.quic.recv(&mut packet_buf[..len], info) {
                            Ok(_) | Err(quiche::Error::Done) => {}
                            Err(e) => bail!("QUIC recv: {e}"),
                        }
                        made_progress = true;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        break;
                    }
                    Err(e) => bail!("socket recv: {e}"),
                }
            }

            loop {
                let len = match self.quic.dgram_recv(&mut dgram_buf) {
                    Ok(len) => len,
                    Err(quiche::Error::Done) => break,
                    Err(e) => bail!("dgram recv: {e}"),
                };
                let dgram = masque::datagram::decode_ref(&dgram_buf[..len])
                    .map_err(|e| anyhow::anyhow!("decode dgram: {e}"))?;
                if dgram.stream_id != stream_id || dgram.payload.len() < 8 {
                    continue;
                }
                let sequence = u64::from_be_bytes(dgram.payload[..8].try_into().unwrap());
                if in_flight.remove(&sequence) {
                    received += 1;
                }
                made_progress = true;
            }

            if now >= deadline && in_flight.is_empty() {
                break;
            }
            if !made_progress {
                std::thread::yield_now();
            }
        }

        expired += in_flight.len() as u64;
        self.socket.set_nonblocking(false)?;
        Ok((sent, received, expired))
    }
}

fn connect_echo_socket(echo_addr: &str) -> Result<UdpSocket> {
    let peer: SocketAddr = echo_addr.parse().context("parse echo server addr")?;
    let bind_addr = if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.connect(peer)?;
    Ok(socket)
}

fn run_echo_server(bind_addr: &str) -> Result<()> {
    let tcp_listener = TcpListener::bind(bind_addr)
        .with_context(|| format!("bind TCP echo server at {bind_addr}"))?;
    std::thread::spawn(move || {
        for stream in tcp_listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    std::thread::spawn(move || {
                        let mut buffer = [0_u8; BUF_SIZE];
                        loop {
                            match stream.read(&mut buffer) {
                                Ok(0) => return,
                                Ok(len) => {
                                    if stream.write_all(&buffer[..len]).is_err() {
                                        return;
                                    }
                                }
                                Err(_) => return,
                            }
                        }
                    });
                }
                Err(_) => return,
            }
        }
    });

    let socket = UdpSocket::bind(bind_addr)
        .with_context(|| format!("bind UDP echo server at {bind_addr}"))?;
    let mut buf = [0u8; BUF_SIZE];

    loop {
        let (len, peer) = socket.recv_from(&mut buf)?;
        let sent = socket.send_to(&buf[..len], peer)?;
        if sent != len {
            bail!("short UDP echo send: {sent}/{len}");
        }
    }
}

/// Exercise the same echo process without MASQUE/QUIC so the benchmark can
/// distinguish proxy overhead from the load generator and echo-server ceiling.
fn run_direct_echo_throughput(
    echo_addr: &str,
    payload_size: usize,
    duration: Duration,
    window: usize,
    expiry: Duration,
) -> Result<(u64, u64, u64)> {
    let socket = connect_echo_socket(echo_addr)?;
    socket.set_nonblocking(true)?;

    let started = Instant::now();
    let deadline = started + duration;
    let drain_deadline = deadline + expiry;
    let mut payload = vec![0x5a; payload_size];
    let mut recv_buf = [0u8; BUF_SIZE];
    let mut in_flight = InFlight::with_capacity(window);
    let mut next_sequence = 0_u64;
    let mut sent = 0_u64;
    let mut received = 0_u64;
    let mut expired = 0_u64;

    while Instant::now() < drain_deadline {
        let now = Instant::now();
        expired += in_flight.expire(now, expiry);

        let mut made_progress = false;
        while now < deadline && in_flight.len() < window {
            payload[..8].copy_from_slice(&next_sequence.to_be_bytes());
            match socket.send(&payload) {
                Ok(len) if len == payload.len() => {
                    in_flight.insert(next_sequence, now);
                    next_sequence += 1;
                    sent += 1;
                    made_progress = true;
                }
                Ok(len) => bail!("short UDP send: {len}/{}", payload.len()),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            }
        }

        loop {
            match socket.recv(&mut recv_buf) {
                Ok(len) => {
                    if len >= 8 {
                        let sequence = u64::from_be_bytes(recv_buf[..8].try_into().unwrap());
                        if in_flight.remove(&sequence) {
                            received += 1;
                        }
                    }
                    made_progress = true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            }
        }

        if now >= deadline && in_flight.is_empty() {
            break;
        }
        if !made_progress {
            std::thread::yield_now();
        }
    }

    expired += in_flight.len() as u64;
    Ok((sent, received, expired))
}

// ---------------------------------------------------------------------------
// Server readiness check
// ---------------------------------------------------------------------------

fn wait_for_server(server_addr: &str) -> Result<()> {
    let mut delay = Duration::from_millis(250);

    for attempt in 1..=20 {
        info!(attempt, "checking server readiness…");
        match Client::connect(server_addr).and_then(|mut c| {
            c.handshake()?;
            c.init_h3()?;
            Ok(())
        }) {
            Ok(()) => {
                info!("server ready");
                return Ok(());
            }
            Err(e) => {
                warn!(attempt, %e, "not ready, retrying");
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_secs(5));
            }
        }
    }
    bail!("server not ready after 20 attempts")
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn append_proxy_authorization(headers: &mut Vec<quiche::h3::Header>) -> Result<()> {
    let username = std::env::var_os("MASQUE_USERNAME");
    let password = std::env::var_os("MASQUE_PASSWORD");
    let (username, password) = match (username, password) {
        (None, None) => return Ok(()),
        (Some(username), Some(password)) => (username, password),
        _ => bail!("MASQUE_USERNAME and MASQUE_PASSWORD must be set together"),
    };

    let username = username
        .into_string()
        .map_err(|_| anyhow::anyhow!("MASQUE_USERNAME is not valid UTF-8"))?;
    let password = password
        .into_string()
        .map_err(|_| anyhow::anyhow!("MASQUE_PASSWORD is not valid UTF-8"))?;
    if username.is_empty() || username.contains(':') || username.chars().any(char::is_control) {
        bail!("MASQUE_USERNAME must be non-empty and contain no ':' or control characters");
    }
    if password.is_empty() || password.chars().any(char::is_control) {
        bail!("MASQUE_PASSWORD must be non-empty and contain no control characters");
    }

    let user_pass = format!("{username}:{password}");
    let value = format!("Basic {}", STANDARD.encode(user_pass));
    headers.push(quiche::h3::Header::new(
        b"proxy-authorization",
        value.as_bytes(),
    ));
    Ok(())
}

fn connect_udp_headers_without_auth(
    server_addr: &str,
    target_host: &str,
    target_port: &str,
) -> Vec<quiche::h3::Header> {
    let path = format!("/.well-known/masque/udp/{target_host}/{target_port}/");
    vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"connect-udp"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", server_addr.as_bytes()),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
    ]
}

fn connect_udp_headers(
    server_addr: &str,
    target_host: &str,
    target_port: &str,
) -> Result<Vec<quiche::h3::Header>> {
    let mut headers = connect_udp_headers_without_auth(server_addr, target_host, target_port);
    append_proxy_authorization(&mut headers)?;
    Ok(headers)
}

fn connect_tcp_headers_without_auth(target_authority: &str) -> Vec<quiche::h3::Header> {
    vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":authority", target_authority.as_bytes()),
    ]
}

fn connect_tcp_headers(target_authority: &str) -> Result<Vec<quiche::h3::Header>> {
    let mut headers = connect_tcp_headers_without_auth(target_authority);
    append_proxy_authorization(&mut headers)?;
    Ok(headers)
}

fn connect_udp_tunnel(server_addr: &str, echo_addr: &str) -> Result<(Client, u64)> {
    let mut client = Client::connect(server_addr)?;
    client.handshake()?;
    client.init_h3()?;
    let (echo_host, echo_port) = echo_addr.rsplit_once(':').context("bad ECHO_SERVER_ADDR")?;
    let headers = connect_udp_headers(server_addr, echo_host, echo_port)?;
    let stream_id = client.send_request(&headers, false)?;
    let (_, status) = client.poll_response(Duration::from_secs(5))?;
    if status != 200 {
        bail!("expected 200, got {status}");
    }
    std::thread::sleep(Duration::from_millis(100));
    Ok((client, stream_id))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn test_server_capabilities(server_addr: &str, _echo_addr: &str) -> Result<()> {
    let mut client = Client::connect(server_addr)?;
    client.handshake()?;
    client.init_h3()?;
    info!("Extended CONNECT and HTTP Datagram SETTINGS advertised");
    Ok(())
}

fn test_standard_connect_happy_path(server_addr: &str, echo_addr: &str) -> Result<()> {
    let mut client = Client::connect(server_addr)?;
    client.handshake()?;
    client.init_h3()?;

    let headers = connect_tcp_headers(echo_addr)?;
    let stream_id = client.send_request(&headers, false)?;
    let (response_stream_id, status) = client.poll_response(Duration::from_secs(5))?;
    if response_stream_id != stream_id || status != 200 {
        bail!(
            "expected stream {stream_id} status 200, got stream {response_stream_id} status {status}"
        );
    }

    let payload = b"standard HTTP/3 CONNECT echo test";
    client.send_body_all(stream_id, payload, true)?;
    let echoed = client.recv_body_bytes(stream_id, payload.len(), Duration::from_secs(5))?;
    if echoed != payload {
        bail!("standard CONNECT payload mismatch");
    }
    info!("standard CONNECT TCP round-trip OK");
    Ok(())
}

fn test_standard_connect_early_body(server_addr: &str, echo_addr: &str) -> Result<()> {
    let mut client = Client::connect(server_addr)?;
    client.handshake()?;
    client.init_h3()?;

    let headers = connect_tcp_headers(echo_addr)?;
    let payload = b"CONNECT headers and body in one QUIC flight";
    let stream_id = client.send_request_with_body(&headers, payload, true)?;
    let (_, status) = client.poll_response(Duration::from_secs(5))?;
    if status != 200 {
        bail!("expected 200 for early CONNECT body, got {status}");
    }
    let echoed = client.recv_body_bytes(
        stream_id,
        payload.len(),
        Duration::from_secs(5),
    )?;
    if echoed != payload {
        bail!("early standard CONNECT payload mismatch");
    }
    Ok(())
}

fn test_standard_connect_auth_required(server_addr: &str, echo_addr: &str) -> Result<()> {
    let mut client = Client::connect(server_addr)?;
    client.handshake()?;
    client.init_h3()?;

    let headers = connect_tcp_headers_without_auth(echo_addr);
    client.send_request(&headers, false)?;
    let (_, status, response_headers) = client.poll_response_headers(Duration::from_secs(5))?;
    if status != 407 {
        bail!("expected 407 for unauthenticated standard CONNECT, got {status}");
    }
    if !response_headers
        .iter()
        .any(|header| header.name() == b"proxy-authenticate")
    {
        bail!("standard CONNECT 407 missing Proxy-Authenticate");
    }
    Ok(())
}

fn test_connect_udp_happy_path(server_addr: &str, echo_addr: &str) -> Result<()> {
    let mut client = Client::connect(server_addr)?;
    client.handshake()?;
    client.init_h3()?;

    // Split echo address into host:port
    let (echo_host, echo_port) = echo_addr.rsplit_once(':').context("bad ECHO_SERVER_ADDR")?;

    let headers = connect_udp_headers(server_addr, echo_host, echo_port)?;
    let stream_id = client.send_request(&headers, false)?;

    let (_sid, status) = client.poll_response(Duration::from_secs(5))?;
    if status != 200 {
        bail!("expected 200, got {status}");
    }

    // Give the server a moment to set up the UDP tunnel socket.
    std::thread::sleep(Duration::from_millis(100));

    // Send a datagram through the tunnel and verify echo.
    let payload = b"hello masque e2e";
    client.send_dgram(stream_id, payload)?;

    let dgram = client.recv_dgram(Duration::from_secs(5))?;
    if dgram.payload != payload {
        bail!(
            "payload mismatch: {:?} vs {:?}",
            dgram.payload,
            payload.to_vec()
        );
    }

    info!("datagram round-trip OK");
    Ok(())
}

fn test_proxy_auth_required(server_addr: &str, echo_addr: &str) -> Result<()> {
    let mut client = Client::connect(server_addr)?;
    client.handshake()?;
    client.init_h3()?;

    let (echo_host, echo_port) = echo_addr.rsplit_once(':').context("bad ECHO_SERVER_ADDR")?;
    let headers = connect_udp_headers_without_auth(server_addr, echo_host, echo_port);
    client.send_request(&headers, false)?;

    let (_, status, response_headers) = client.poll_response_headers(Duration::from_secs(5))?;
    if status != 407 {
        bail!("expected 407, got {status}");
    }

    let challenge = response_headers
        .iter()
        .find(|header| header.name() == b"proxy-authenticate")
        .context("407 response missing Proxy-Authenticate")?;
    if challenge.value() != b"Basic realm=\"masque\", charset=\"UTF-8\"" {
        bail!(
            "unexpected Proxy-Authenticate challenge: {}",
            String::from_utf8_lossy(challenge.value())
        );
    }

    info!("unauthenticated CONNECT-UDP correctly rejected with 407");
    Ok(())
}

fn benchmark_connect_udp(server_addr: &str, echo_addr: &str) -> Result<()> {
    let duration_secs = std::env::var("MASQUE_BENCH_DURATION_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5);
    let window = std::env::var("MASQUE_BENCH_WINDOW")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(256);
    let latency_samples = std::env::var("MASQUE_BENCH_RTT_SAMPLES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50);
    let expiry_ms = std::env::var("MASQUE_BENCH_EXPIRY_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1_000);

    if duration_secs == 0 || window == 0 || latency_samples == 0 || expiry_ms == 0 {
        bail!("benchmark duration, window, RTT samples, and expiry must be non-zero");
    }

    let expiry = Duration::from_millis(expiry_ms);
    println!(
        "CONNECT-UDP benchmark: {duration_secs}s per payload, window {window}, expiry {expiry_ms}ms"
    );

    println!("Direct UDP echo baseline:");
    let direct_socket = connect_echo_socket(echo_addr)?;
    direct_socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    let latency_payload = vec![0x3c; 64];
    let mut response = [0u8; BUF_SIZE];
    let mut direct_latencies = Vec::with_capacity(latency_samples);
    for _ in 0..latency_samples {
        let started = Instant::now();
        direct_socket.send(&latency_payload)?;
        let len = direct_socket.recv(&mut response)?;
        if response[..len] != latency_payload {
            bail!("direct UDP latency probe payload mismatch");
        }
        direct_latencies.push(started.elapsed().as_secs_f64() * 1e6);
    }
    direct_latencies.sort_by(f64::total_cmp);
    let percentile = |values: &[f64], p: f64| values[((values.len() - 1) as f64 * p) as usize];
    println!(
        "  RTT 64B ({latency_samples} samples): p50 {:.1} us, p95 {:.1} us, p99 {:.1} us",
        percentile(&direct_latencies, 0.50),
        percentile(&direct_latencies, 0.95),
        percentile(&direct_latencies, 0.99),
    );

    let duration = Duration::from_secs(duration_secs);
    for payload_size in [64, 1_200] {
        let (sent, received, expired) =
            run_direct_echo_throughput(echo_addr, payload_size, duration, window, expiry)?;
        let seconds = duration.as_secs_f64();
        let tx_pps = sent as f64 / seconds;
        let rx_pps = received as f64 / seconds;
        let goodput_gbps = received as f64 * payload_size as f64 * 8.0 / seconds / 1e9;
        let response_shortfall = (sent - received) as f64 * 100.0 / sent.max(1) as f64;
        println!(
            "  Throughput {payload_size:>4}B: tx {tx_pps:>10.0} pkt/s, echo {rx_pps:>10.0} pkt/s, app goodput {goodput_gbps:.3} Gbit/s, interval shortfall {response_shortfall:.2}% ({expired} expired)"
        );
    }

    println!("MASQUE CONNECT-UDP:");
    let (mut client, stream_id) = connect_udp_tunnel(server_addr, echo_addr)?;

    let mut latencies = Vec::with_capacity(latency_samples);
    for _ in 0..latency_samples {
        let started = Instant::now();
        client.send_dgram(stream_id, &latency_payload)?;
        let response = client.recv_dgram(Duration::from_secs(2))?;
        if response.payload != latency_payload {
            bail!("latency probe payload mismatch");
        }
        latencies.push(started.elapsed().as_secs_f64() * 1e6);
    }
    latencies.sort_by(f64::total_cmp);
    println!(
        "  RTT 64B ({latency_samples} samples): p50 {:.1} us, p95 {:.1} us, p99 {:.1} us",
        percentile(&latencies, 0.50),
        percentile(&latencies, 0.95),
        percentile(&latencies, 0.99),
    );

    drop(client);

    for payload_size in [64, 1_200] {
        let (mut client, stream_id) = connect_udp_tunnel(server_addr, echo_addr)?;
        let (sent, received, expired) =
            client.run_echo_throughput(stream_id, payload_size, duration, window, expiry)?;
        let seconds = duration.as_secs_f64();
        let tx_pps = sent as f64 / seconds;
        let rx_pps = received as f64 / seconds;
        let goodput_gbps = received as f64 * payload_size as f64 * 8.0 / seconds / 1e9;
        let relay_gbps = goodput_gbps * 2.0;
        let response_shortfall = if sent == 0 {
            0.0
        } else {
            (sent - received) as f64 * 100.0 / sent as f64
        };
        println!(
            "  Throughput {payload_size:>4}B: tx {tx_pps:>10.0} pkt/s, echo {rx_pps:>10.0} pkt/s, app goodput {goodput_gbps:.3} Gbit/s, bidirectional relay {relay_gbps:.3} Gbit/s, interval shortfall {response_shortfall:.2}% ({expired} expired)"
        );
    }
    Ok(())
}

fn test_connect_udp_policy_deny(server_addr: &str, _echo_addr: &str) -> Result<()> {
    let mut client = Client::connect(server_addr)?;
    client.handshake()?;
    client.init_h3()?;

    let headers = connect_udp_headers(server_addr, "127.0.0.1", "53")?;
    let _stream_id = client.send_request(&headers, false)?;

    let (_sid, status) = client.poll_response(Duration::from_secs(5))?;
    if status != 403 {
        bail!("expected 403, got {status}");
    }
    Ok(())
}

fn test_connect_udp_bad_uri(server_addr: &str, _echo_addr: &str) -> Result<()> {
    let mut client = Client::connect(server_addr)?;
    client.handshake()?;
    client.init_h3()?;

    let mut headers = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"connect-udp"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", server_addr.as_bytes()),
        quiche::h3::Header::new(b":path", b"/bad/path"),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
    ];
    append_proxy_authorization(&mut headers)?;
    let _stream_id = client.send_request(&headers, false)?;

    let (_sid, status) = client.poll_response(Duration::from_secs(5))?;
    if status != 400 {
        bail!("expected 400, got {status}");
    }
    Ok(())
}

fn test_non_connect_404(server_addr: &str, _echo_addr: &str) -> Result<()> {
    let mut client = Client::connect(server_addr)?;
    client.handshake()?;
    client.init_h3()?;

    let headers = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", server_addr.as_bytes()),
        quiche::h3::Header::new(b":path", b"/"),
    ];
    let _stream_id = client.send_request(&headers, true)?;

    let (_sid, status) = client.poll_response(Duration::from_secs(5))?;
    if status != 404 {
        bail!("expected 404, got {status}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CONNECT-IP helpers
// ---------------------------------------------------------------------------

fn connect_ip_headers(server_addr: &str) -> Result<Vec<quiche::h3::Header>> {
    let mut headers = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"connect-ip"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", server_addr.as_bytes()),
        quiche::h3::Header::new(b":path", b"/.well-known/masque/ip/"),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
    ];
    append_proxy_authorization(&mut headers)?;
    Ok(headers)
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        // Skip the checksum field at bytes 10-11.
        if i == 10 {
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a minimal IPv4/UDP packet.
fn build_udp_in_ipv4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len: u16 = 8 + payload.len() as u16;
    let total_len: u16 = 20 + udp_len;

    // IPv4 header (20 bytes, no options).
    let mut pkt = vec![0u8; 20];
    pkt[0] = 0x45; // version=4, IHL=5
    pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = 17; // protocol = UDP
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let cksum = ipv4_checksum(&pkt);
    pkt[10..12].copy_from_slice(&cksum.to_be_bytes());

    // UDP header (8 bytes).
    pkt.extend_from_slice(&sport.to_be_bytes());
    pkt.extend_from_slice(&dport.to_be_bytes());
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&[0, 0]); // checksum = 0 (optional for IPv4)

    // Payload.
    pkt.extend_from_slice(payload);
    pkt
}

// ---------------------------------------------------------------------------
// CONNECT-IP tests
// ---------------------------------------------------------------------------

fn test_connect_ip_handshake(server_addr: &str, _echo_addr: &str) -> Result<()> {
    let mut client = Client::connect(server_addr)?;
    client.handshake()?;
    client.init_h3()?;

    let headers = connect_ip_headers(server_addr)?;
    let stream_id = client.send_request(&headers, false)?;

    let (_sid, status) = client.poll_response(Duration::from_secs(5))?;
    if status != 200 {
        bail!("expected 200, got {status}");
    }

    // Read capsules (ADDRESS_ASSIGN + ROUTE_ADVERTISEMENT).
    let capsules = client.recv_capsules(stream_id, Duration::from_secs(5))?;

    let mut got_addr_assign = false;
    let mut got_route_adv = false;

    for frame in &capsules {
        match frame {
            CapsuleFrame::AddressAssign(addrs) => {
                got_addr_assign = true;
                // Must have at least one IPv4 address from 10.89.x.x pool.
                let has_v4 = addrs.iter().any(|a| {
                    matches!(&a.ip, masque::capsule::IpAddress::V4(v4) if v4.octets()[0] == 10 && v4.octets()[1] == 89)
                });
                if !has_v4 {
                    bail!("ADDRESS_ASSIGN missing IPv4 from 10.89.x.x pool: {addrs:?}");
                }
                info!("ADDRESS_ASSIGN OK: {addrs:?}");
            }
            CapsuleFrame::RouteAdvertisement(routes) => {
                got_route_adv = true;
                if routes.is_empty() {
                    bail!("ROUTE_ADVERTISEMENT has no routes");
                }
                info!("ROUTE_ADVERTISEMENT OK: {} routes", routes.len());
            }
            other => {
                info!("unexpected capsule: {other:?}");
            }
        }
    }

    if !got_addr_assign {
        bail!("missing ADDRESS_ASSIGN capsule");
    }
    if !got_route_adv {
        bail!("missing ROUTE_ADVERTISEMENT capsule");
    }

    Ok(())
}

fn test_connect_ip_round_trip(server_addr: &str, echo_addr: &str) -> Result<()> {
    let mut client = Client::connect(server_addr)?;
    client.handshake()?;
    client.init_h3()?;

    let headers = connect_ip_headers(server_addr)?;
    let stream_id = client.send_request(&headers, false)?;

    let (_sid, status) = client.poll_response(Duration::from_secs(5))?;
    if status != 200 {
        bail!("expected 200, got {status}");
    }

    // Read capsules to get the assigned IPv4 address.
    let capsules = client.recv_capsules(stream_id, Duration::from_secs(5))?;

    let assigned_v4 = capsules
        .iter()
        .find_map(|f| match f {
            CapsuleFrame::AddressAssign(addrs) => addrs.iter().find_map(|a| match &a.ip {
                masque::capsule::IpAddress::V4(v4) => Some(*v4),
                _ => None,
            }),
            _ => None,
        })
        .context("no IPv4 assigned")?;

    info!(%assigned_v4, "assigned address");

    // Parse echo server address.
    let (echo_host, echo_port) = echo_addr.rsplit_once(':').context("bad ECHO_SERVER_ADDR")?;
    let echo_ip: Ipv4Addr = echo_host.parse().context("parse echo host")?;
    let echo_port: u16 = echo_port.parse().context("parse echo port")?;

    // Build a UDP-in-IPv4 packet and send as QUIC DATAGRAM.
    let payload = b"connect-ip echo test";
    let ip_pkt = build_udp_in_ipv4(assigned_v4, echo_ip, 12345, echo_port, payload);

    // context_id=0 means raw IP packet in CONNECT-IP datagrams.
    client.send_dgram(stream_id, &ip_pkt)?;

    // Receive the response datagram.
    let dgram = client.recv_dgram(Duration::from_secs(5))?;

    // The response payload is an IP packet; parse the UDP payload out of it.
    let resp = &dgram.payload;
    if resp.len() < 28 {
        bail!("response IP packet too short: {} bytes", resp.len());
    }

    let ihl = ((resp[0] & 0x0f) as usize) * 4;
    if resp.len() < ihl + 8 {
        bail!("response too short for UDP header");
    }

    // Verify destination IP is our assigned address.
    let dst_ip = Ipv4Addr::new(resp[16], resp[17], resp[18], resp[19]);
    if dst_ip != assigned_v4 {
        bail!("response dst {dst_ip} != assigned {assigned_v4}");
    }

    // Extract UDP payload.
    let udp_data_offset = ihl + 8;
    let resp_payload = &resp[udp_data_offset..];
    if resp_payload != payload {
        bail!(
            "payload mismatch: {:?} vs {:?}",
            resp_payload,
            payload.to_vec()
        );
    }

    info!("CONNECT-IP round-trip OK");
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "masque_e2e=info".parse().unwrap()),
        )
        .init();

    if let Ok(bind_addr) = std::env::var("MASQUE_ECHO_SERVER_ADDR") {
        if let Err(e) = run_echo_server(&bind_addr) {
            error!(%e, "UDP echo server failed");
            std::process::exit(1);
        }
        return;
    }

    let server_addr =
        std::env::var("MASQUE_SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:4433".into());
    let echo_addr = std::env::var("ECHO_SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:9999".into());

    info!(%server_addr, %echo_addr, "MASQUE E2E test suite");

    if let Err(e) = wait_for_server(&server_addr) {
        error!(%e, "server not ready");
        std::process::exit(1);
    }

    if std::env::var_os("MASQUE_AUTH_CHECK").is_some() {
        if let Err(e) = test_proxy_auth_required(&server_addr, &echo_addr) {
            error!(%e, "proxy authentication check failed");
            std::process::exit(1);
        }
        return;
    }

    if std::env::var_os("MASQUE_TCP_CHECK").is_some() {
        for (name, test) in [
            (
                "server_capabilities",
                test_server_capabilities as fn(&str, &str) -> Result<()>,
            ),
            (
                "standard_connect_auth_required",
                test_standard_connect_auth_required,
            ),
            (
                "standard_connect_happy_path",
                test_standard_connect_happy_path,
            ),
            (
                "standard_connect_early_body",
                test_standard_connect_early_body,
            ),
        ] {
            if let Err(error) = test(&server_addr, &echo_addr) {
                error!(%error, "{name} failed");
                std::process::exit(1);
            }
        }
        info!("MASQUE TCP compatibility checks passed");
        return;
    }

    if std::env::var_os("MASQUE_BENCH").is_some() {
        if let Err(e) = benchmark_connect_udp(&server_addr, &echo_addr) {
            error!(%e, "network benchmark failed");
            std::process::exit(1);
        }
        return;
    }

    let tests: &[(&str, fn(&str, &str) -> Result<()>)] = &[
        ("server_capabilities", test_server_capabilities),
        (
            "standard_connect_auth_required",
            test_standard_connect_auth_required,
        ),
        (
            "standard_connect_happy_path",
            test_standard_connect_happy_path,
        ),
        (
            "standard_connect_early_body",
            test_standard_connect_early_body,
        ),
        ("proxy_auth_required", test_proxy_auth_required),
        ("connect_udp_happy_path", test_connect_udp_happy_path),
        ("connect_udp_policy_deny", test_connect_udp_policy_deny),
        ("connect_udp_bad_uri", test_connect_udp_bad_uri),
        ("non_connect_404", test_non_connect_404),
        ("connect_ip_handshake", test_connect_ip_handshake),
        ("connect_ip_round_trip", test_connect_ip_round_trip),
    ];

    let mut passed = 0u32;
    let mut failed = 0u32;

    for (name, test_fn) in tests {
        info!("--- {name} ---");
        match test_fn(&server_addr, &echo_addr) {
            Ok(()) => {
                info!("{name}: PASS");
                passed += 1;
            }
            Err(e) => {
                error!("{name}: FAIL — {e:#}");
                failed += 1;
            }
        }
    }

    info!("{passed} passed, {failed} failed");
    if failed > 0 {
        std::process::exit(1);
    }
}
