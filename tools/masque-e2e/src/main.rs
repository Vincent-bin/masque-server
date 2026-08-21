use std::collections::{HashMap, VecDeque};
#[cfg(target_os = "macos")]
use std::ffi::CString;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::AsRawFd;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use masque::capsule::CapsuleFrame;
use masque::capsule::decoder::CapsuleDecoder;
use quiche::h3::NameValue;
use ring::rand::SecureRandom;
use tracing::{error, info, warn};

const MAX_DATAGRAM_SIZE: usize = 1350;
const BUF_SIZE: usize = 65535;
const MAX_HTTP_RESPONSE_HEADER_SIZE: usize = 64 * 1024;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const CLIENT_UDP_RECEIVE_BUFFER_SIZE: libc::c_int = 4 * 1024 * 1024;

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tune_udp_receive_buffer(socket: &UdpSocket) {
    // Default UDP receive buffers are small on both macOS and Linux. A bulk
    // download can fill one between scheduler wakeups, making the benchmark
    // report client-side kernel drops as QUIC/server performance. The kernel
    // may clamp this request to its configured maximum; that is still better
    // than silently retaining the much smaller default.
    // SAFETY: the file descriptor and option pointer remain valid throughout
    // the call, and SO_RCVBUF expects a `c_int` value.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&CLIENT_UDP_RECEIVE_BUFFER_SIZE as *const libc::c_int).cast(),
            std::mem::size_of_val(&CLIENT_UDP_RECEIVE_BUFFER_SIZE) as libc::socklen_t,
        )
    };
    if result != 0 {
        warn!(
            error = %std::io::Error::last_os_error(),
            "could not enlarge client UDP receive buffer"
        );
    }
}

#[cfg(target_os = "macos")]
fn bind_udp_socket_to_requested_interface(socket: &UdpSocket) -> Result<()> {
    let Some(interface) = std::env::var_os("MASQUE_INTERFACE") else {
        return Ok(());
    };
    let interface = interface
        .into_string()
        .map_err(|_| anyhow::anyhow!("MASQUE_INTERFACE is not valid UTF-8"))?;
    let interface_name =
        CString::new(interface.as_str()).context("MASQUE_INTERFACE contains an embedded NUL")?;

    // SAFETY: `interface_name` is a live, NUL-terminated C string.
    let interface_index = unsafe { libc::if_nametoindex(interface_name.as_ptr()) };
    if interface_index == 0 {
        bail!("network interface {interface:?} does not exist");
    }

    // macOS routes sockets through a utun default route even when the intended
    // proxy egress is the physical NIC. IP_BOUND_IF gives the benchmark client
    // the same underlay path as a proxy application's own outbound socket.
    // SAFETY: the file descriptor and pointer are valid for the duration of the
    // call, and the option value has the `c_uint` type expected by IP_BOUND_IF.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_BOUND_IF,
            (&interface_index as *const libc::c_uint).cast(),
            std::mem::size_of_val(&interface_index) as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("bind UDP socket to interface {interface}"));
    }

    info!(%interface, interface_index, "bound client socket to interface");
    Ok(())
}

#[derive(Debug)]
struct HttpDownloadResponse {
    header: Vec<u8>,
    header_complete: bool,
    status: Option<u16>,
    content_length: Option<u64>,
    body_bytes: u64,
    first_body_at: Option<Instant>,
}

impl HttpDownloadResponse {
    fn new() -> Self {
        Self {
            header: Vec::with_capacity(4096),
            header_complete: false,
            status: None,
            content_length: None,
            body_bytes: 0,
            first_body_at: None,
        }
    }

    fn ingest(&mut self, data: &[u8], now: Instant) -> Result<()> {
        if self.header_complete {
            self.record_body(data.len(), now);
            return Ok(());
        }

        self.header.extend_from_slice(data);
        let Some(header_end) = self
            .header
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|offset| offset + 4)
        else {
            if self.header.len() > MAX_HTTP_RESPONSE_HEADER_SIZE {
                bail!("HTTP response header exceeded {MAX_HTTP_RESPONSE_HEADER_SIZE} bytes");
            }
            return Ok(());
        };

        if header_end > MAX_HTTP_RESPONSE_HEADER_SIZE {
            bail!("HTTP response header exceeded {MAX_HTTP_RESPONSE_HEADER_SIZE} bytes");
        }

        let header_text = std::str::from_utf8(&self.header[..header_end])
            .context("HTTP response header is not UTF-8")?;
        let mut lines = header_text.split("\r\n");
        let status_line = lines.next().context("missing HTTP status line")?;
        let status = status_line
            .split_ascii_whitespace()
            .nth(1)
            .context("missing HTTP status code")?
            .parse::<u16>()
            .context("invalid HTTP status code")?;

        let mut content_length = None;
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case("content-length") {
                content_length = Some(
                    value
                        .trim()
                        .parse::<u64>()
                        .context("invalid HTTP Content-Length")?,
                );
            }
        }

        self.status = Some(status);
        self.content_length = content_length;
        self.header_complete = true;

        let body_in_buffer = self.header.len() - header_end;
        self.header.truncate(header_end);
        self.record_body(body_in_buffer, now);
        Ok(())
    }

    fn record_body(&mut self, len: usize, now: Instant) {
        if len == 0 {
            return;
        }
        self.first_body_at.get_or_insert(now);
        self.body_bytes += len as u64;
    }

    fn expected_body_bytes(&self, configured: Option<u64>) -> Option<u64> {
        configured.or(self.content_length)
    }
}

#[derive(Debug)]
struct TcpDownloadResult {
    response: HttpDownloadResponse,
    finished_at: Instant,
    stream_finished: bool,
}

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
    /// Honour quiche's pacing deadlines by sleeping before each send.
    ///
    /// The load generator keeps this enabled too: bypassing pacing creates
    /// unrealistic bursts and can make a real network path look slower.
    pace: bool,
}

impl Client {
    fn connect(server_addr: &str) -> Result<Self> {
        let peer: SocketAddr = server_addr.parse().context("parse server addr")?;

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        tune_udp_receive_buffer(&socket);
        #[cfg(target_os = "macos")]
        {
            bind_udp_socket_to_requested_interface(&socket)?;
        }
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
        // A 1 MiB receive window caps a 140 ms path at roughly 60 Mbit/s until
        // autotuning catches up. Match the production server's window ceilings
        // so this client measures CONNECT throughput rather than its own flow
        // control configuration.
        config.set_initial_max_data(25_165_824);
        config.set_initial_max_stream_data_bidi_local(16_777_216);
        config.set_initial_max_stream_data_bidi_remote(4_194_304);
        config.set_initial_max_stream_data_uni(4_194_304);
        config.set_max_connection_window(25_165_824);
        config.set_max_stream_window(16_777_216);
        config.set_initial_max_streams_bidi(128);
        config.set_initial_max_streams_uni(100);
        config.enable_pacing(true);
        config.enable_dgram(true, 1000, 1000);

        let server_name = std::env::var("MASQUE_SERVER_NAME").unwrap_or_else(|_| "server".into());
        let quic = quiche::connect(Some(&server_name), &scid, local, peer, &mut config)?;

        Ok(Client {
            socket,
            quic,
            h3: None,
            peer,
            local,
            pace: true,
        })
    }

    /// Send all pending QUIC packets to the network.
    fn flush(&mut self) -> Result<()> {
        let mut out = [0u8; MAX_DATAGRAM_SIZE];
        loop {
            match self.quic.send(&mut out) {
                Ok((len, send_info)) => {
                    if self.pace {
                        let delay = send_info.at.saturating_duration_since(Instant::now());
                        if !delay.is_zero() {
                            std::thread::sleep(delay);
                        }
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

    /// Receive a large byte stream through a standard HTTP/3 CONNECT tunnel.
    ///
    /// The payload inside the tunnel is an HTTP/1.1 response. Headers are
    /// parsed incrementally and excluded from the goodput figure. The socket is
    /// drained until it would block on every loop iteration, avoiding the
    /// one-packet-per-wakeup behavior that made older benchmarks latency-bound.
    fn run_tcp_download(
        &mut self,
        stream_id: u64,
        configured_body_bytes: Option<u64>,
        timeout: Duration,
    ) -> Result<TcpDownloadResult> {
        self.socket.set_nonblocking(true)?;

        let deadline = Instant::now() + timeout;
        let mut packet_buf = [0_u8; BUF_SIZE];
        let mut body_buf = [0_u8; BUF_SIZE];
        let mut response = HttpDownloadResponse::new();
        let mut stream_finished = false;

        loop {
            let mut made_progress = false;

            self.flush()?;

            // Drain a bounded burst from the UDP socket. The bound prevents a
            // permanently busy socket from starving HTTP/3 body consumption
            // and the resulting flow-control updates.
            for _ in 0..2048 {
                match self.socket.recv(&mut packet_buf) {
                    Ok(len) => {
                        let info = quiche::RecvInfo {
                            from: self.peer,
                            to: self.local,
                        };
                        match self.quic.recv(&mut packet_buf[..len], info) {
                            Ok(_) | Err(quiche::Error::Done) => {}
                            Err(error) => bail!("QUIC receive during TCP download: {error}"),
                        }
                        made_progress = true;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error.into()),
                }
            }

            {
                let h3 = self.h3.as_mut().context("H3 not initialised")?;
                loop {
                    match h3.poll(&mut self.quic) {
                        Ok((sid, quiche::h3::Event::Data)) if sid == stream_id => loop {
                            match h3.recv_body(&mut self.quic, stream_id, &mut body_buf) {
                                Ok(len) => {
                                    response.ingest(&body_buf[..len], Instant::now())?;
                                    made_progress = true;
                                }
                                Err(quiche::h3::Error::Done) => break,
                                Err(error) => bail!("receive CONNECT download body: {error}"),
                            }
                        },
                        Ok((sid, quiche::h3::Event::Finished)) if sid == stream_id => {
                            stream_finished = true;
                            made_progress = true;
                        }
                        Ok((sid, quiche::h3::Event::Reset(code))) if sid == stream_id => {
                            bail!("CONNECT download stream reset with code {code}");
                        }
                        Ok(_) => {
                            made_progress = true;
                        }
                        Err(quiche::h3::Error::Done) => break,
                        Err(error) => bail!("poll CONNECT download stream: {error}"),
                    }
                }
            }

            self.flush()?;

            if let Some(expected) = response.expected_body_bytes(configured_body_bytes) {
                if response.body_bytes > expected {
                    bail!(
                        "received {} HTTP body bytes, expected {expected}",
                        response.body_bytes
                    );
                }
                if response.body_bytes == expected {
                    break;
                }
            }

            if stream_finished {
                break;
            }
            if Instant::now() >= deadline {
                bail!(
                    "CONNECT download timed out after receiving {} body bytes",
                    response.body_bytes
                );
            }

            if !made_progress {
                if self.quic.timeout().is_some_and(|timeout| timeout.is_zero()) {
                    self.quic.on_timeout();
                } else {
                    std::thread::yield_now();
                }
            }
        }

        self.socket.set_nonblocking(false)?;

        if !response.header_complete {
            bail!("CONNECT tunnel closed before a complete HTTP response header arrived");
        }
        if response.status != Some(200) {
            bail!("HTTP origin returned status {:?}", response.status);
        }
        if let Some(expected) = response.expected_body_bytes(configured_body_bytes)
            && response.body_bytes != expected
        {
            bail!(
                "CONNECT download finished after {} of {expected} body bytes",
                response.body_bytes
            );
        }

        Ok(TcpDownloadResult {
            response,
            finished_at: Instant::now(),
            stream_finished,
        })
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
    let echoed = client.recv_body_bytes(stream_id, payload.len(), Duration::from_secs(5))?;
    if echoed != payload {
        bail!("early standard CONNECT payload mismatch");
    }
    Ok(())
}

fn benchmark_direct_tcp_download(
    target: &str,
    path: &str,
    configured_body_bytes: Option<u64>,
    timeout: Duration,
) -> Result<(TcpDownloadResult, Instant, Instant, Instant)> {
    let sample_started = Instant::now();
    let mut stream = TcpStream::connect(target)
        .with_context(|| format!("connect directly to TCP origin {target}"))?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let connected_at = Instant::now();

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {target}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    );
    let request_started = Instant::now();
    stream.write_all(request.as_bytes())?;

    let mut response = HttpDownloadResponse::new();
    let mut buffer = [0_u8; BUF_SIZE];
    let mut stream_finished = false;
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => {
                stream_finished = true;
                break;
            }
            Ok(len) => response.ingest(&buffer[..len], Instant::now())?,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                bail!(
                    "direct TCP download timed out after receiving {} body bytes",
                    response.body_bytes
                );
            }
            Err(error) => return Err(error.into()),
        }

        if let Some(expected) = response.expected_body_bytes(configured_body_bytes) {
            if response.body_bytes > expected {
                bail!(
                    "direct TCP download received {} body bytes, expected {expected}",
                    response.body_bytes
                );
            }
            if response.body_bytes == expected {
                break;
            }
        }
    }

    if !response.header_complete {
        bail!("direct TCP origin closed before a complete HTTP response header arrived");
    }
    if response.status != Some(200) {
        bail!("direct TCP origin returned status {:?}", response.status);
    }
    if let (Some(configured), Some(advertised)) = (configured_body_bytes, response.content_length)
        && configured != advertised
    {
        bail!(
            "configured body size {configured} differs from direct origin Content-Length {advertised}"
        );
    }
    if let Some(expected) = response.expected_body_bytes(configured_body_bytes)
        && response.body_bytes != expected
    {
        bail!(
            "direct TCP download finished after {} of {expected} body bytes",
            response.body_bytes
        );
    }

    let finished_at = Instant::now();
    Ok((
        TcpDownloadResult {
            response,
            finished_at,
            stream_finished,
        },
        sample_started,
        connected_at,
        request_started,
    ))
}

fn benchmark_standard_connect_download(server_addr: &str) -> Result<()> {
    let target = std::env::var("MASQUE_TCP_TARGET")
        .context("MASQUE_TCP_TARGET must be set to origin-host:port")?;
    let path = std::env::var("MASQUE_TCP_PATH").unwrap_or_else(|_| "/masque-bench.bin".into());
    let configured_body_bytes = std::env::var("MASQUE_TCP_DOWNLOAD_BYTES")
        .ok()
        .map(|value| {
            value
                .parse::<u64>()
                .context("MASQUE_TCP_DOWNLOAD_BYTES must be an integer")
        })
        .transpose()?;
    let timeout_secs = std::env::var("MASQUE_TCP_TIMEOUT_SECS")
        .unwrap_or_else(|_| "120".into())
        .parse::<u64>()
        .context("MASQUE_TCP_TIMEOUT_SECS must be an integer")?;
    let repeats = std::env::var("MASQUE_TCP_DOWNLOAD_REPEATS")
        .unwrap_or_else(|_| "1".into())
        .parse::<u32>()
        .context("MASQUE_TCP_DOWNLOAD_REPEATS must be an integer")?;
    let direct_baseline = std::env::var_os("MASQUE_TCP_DIRECT_BASELINE").is_some();

    if target.is_empty()
        || target
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        bail!("MASQUE_TCP_TARGET contains invalid characters");
    }
    if !path.starts_with('/') || path.chars().any(char::is_control) {
        bail!("MASQUE_TCP_PATH must be an absolute path without control characters");
    }
    if configured_body_bytes == Some(0) || timeout_secs == 0 || repeats == 0 {
        bail!("download size, timeout, and repeat count must be non-zero");
    }
    if repeats > 16 {
        bail!("MASQUE_TCP_DOWNLOAD_REPEATS must not exceed 16");
    }

    let connection_started = Instant::now();
    let mut client = Client::connect(server_addr)?;
    client.handshake()?;
    client.init_h3()?;
    let quic_setup = Instant::now().saturating_duration_since(connection_started);
    let mut direct_transfer_rates = Vec::with_capacity(repeats as usize);
    let mut masque_transfer_rates = Vec::with_capacity(repeats as usize);

    for sample in 1..=repeats {
        if direct_baseline {
            let (direct, direct_started, connected_at, request_started) =
                benchmark_direct_tcp_download(
                    &target,
                    &path,
                    configured_body_bytes,
                    Duration::from_secs(timeout_secs),
                )?;
            let first_body_at = direct
                .response
                .first_body_at
                .context("direct HTTP response contained no body")?;
            let body_bytes = direct.response.body_bytes;
            let connect_elapsed = connected_at.saturating_duration_since(direct_started);
            let ttfb = first_body_at.saturating_duration_since(request_started);
            let request_elapsed = direct
                .finished_at
                .saturating_duration_since(request_started);
            let transfer_elapsed = direct.finished_at.saturating_duration_since(first_body_at);
            let sample_elapsed = direct.finished_at.saturating_duration_since(direct_started);
            let mbps = |elapsed: Duration| -> f64 {
                if elapsed.is_zero() {
                    return 0.0;
                }
                body_bytes as f64 * 8.0 / elapsed.as_secs_f64() / 1_000_000.0
            };
            let request_mbps = mbps(request_elapsed);
            let transfer_mbps = mbps(transfer_elapsed);
            let sample_mbps = mbps(sample_elapsed);
            direct_transfer_rates.push(transfer_mbps);
            println!(
                "DIRECT_TCP_DOWNLOAD_RESULT sample={sample} body_bytes={body_bytes} \
connect_ms={:.3} ttfb_ms={:.3} request_ms={:.3} transfer_ms={:.3} sample_ms={:.3} \
request_mbps={:.3} transfer_mbps={:.3} sample_mbps={:.3} stream_finished={}",
                connect_elapsed.as_secs_f64() * 1000.0,
                ttfb.as_secs_f64() * 1000.0,
                request_elapsed.as_secs_f64() * 1000.0,
                transfer_elapsed.as_secs_f64() * 1000.0,
                sample_elapsed.as_secs_f64() * 1000.0,
                request_mbps,
                transfer_mbps,
                sample_mbps,
                direct.stream_finished,
            );
        }

        let sample_started = Instant::now();
        let stats_before = client.quic.stats();
        let counters_before = (
            stats_before.recv,
            stats_before.recv_bytes,
            stats_before.lost,
            stats_before.lost_bytes,
            stats_before.data_blocked_recv_count,
            stats_before.stream_data_blocked_recv_count,
        );

        let headers = connect_tcp_headers(&target)?;
        let stream_id = client.send_request(&headers, false)?;
        let (response_stream_id, status) = client.poll_response(Duration::from_secs(10))?;
        if response_stream_id != stream_id || status != 200 {
            bail!(
                "expected CONNECT stream {stream_id} status 200, got stream {response_stream_id} status {status}"
            );
        }
        let connect_finished = Instant::now();

        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {target}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
        );
        let request_started = Instant::now();
        client.send_body_all(stream_id, request.as_bytes(), true)?;
        let result = client.run_tcp_download(
            stream_id,
            configured_body_bytes,
            Duration::from_secs(timeout_secs),
        )?;

        if let (Some(configured), Some(advertised)) =
            (configured_body_bytes, result.response.content_length)
            && configured != advertised
        {
            bail!(
                "configured body size {configured} differs from origin Content-Length {advertised}"
            );
        }

        let first_body_at = result
            .response
            .first_body_at
            .context("HTTP response contained no body")?;
        let body_bytes = result.response.body_bytes;
        let connect_elapsed = connect_finished.saturating_duration_since(sample_started);
        let ttfb = first_body_at.saturating_duration_since(request_started);
        let request_elapsed = result
            .finished_at
            .saturating_duration_since(request_started);
        let transfer_elapsed = result.finished_at.saturating_duration_since(first_body_at);
        let sample_elapsed = result.finished_at.saturating_duration_since(sample_started);

        let mbps = |elapsed: Duration| -> f64 {
            if elapsed.is_zero() {
                return 0.0;
            }
            body_bytes as f64 * 8.0 / elapsed.as_secs_f64() / 1_000_000.0
        };
        let request_mbps = mbps(request_elapsed);
        let transfer_mbps = mbps(transfer_elapsed);
        let sample_mbps = mbps(sample_elapsed);
        masque_transfer_rates.push(transfer_mbps);

        let stats = client.quic.stats();
        let path_stats = client.quic.path_stats().find(|path| path.active);
        let (rtt_ms, client_cwnd, pmtu, client_delivery_rate_mbps) = path_stats
            .map(|path| {
                (
                    path.rtt.as_secs_f64() * 1000.0,
                    path.cwnd,
                    path.pmtu,
                    path.delivery_rate as f64 * 8.0 / 1_000_000.0,
                )
            })
            .unwrap_or((0.0, 0, 0, 0.0));

        println!(
            "TCP_DOWNLOAD_RESULT sample={sample} body_bytes={body_bytes} quic_setup_ms={:.3} \
connect_ms={:.3} ttfb_ms={:.3} request_ms={:.3} transfer_ms={:.3} sample_ms={:.3} \
request_mbps={:.3} transfer_mbps={:.3} sample_mbps={:.3} rtt_ms={rtt_ms:.3} \
client_cwnd={client_cwnd} pmtu={pmtu} \
client_delivery_rate_mbps={client_delivery_rate_mbps:.3} recv_packets={} \
recv_wire_bytes={} client_lost_packets={} client_lost_bytes={} \
data_blocked_received={} stream_blocked_received={} stream_finished={}",
            quic_setup.as_secs_f64() * 1000.0,
            connect_elapsed.as_secs_f64() * 1000.0,
            ttfb.as_secs_f64() * 1000.0,
            request_elapsed.as_secs_f64() * 1000.0,
            transfer_elapsed.as_secs_f64() * 1000.0,
            sample_elapsed.as_secs_f64() * 1000.0,
            request_mbps,
            transfer_mbps,
            sample_mbps,
            stats.recv.saturating_sub(counters_before.0),
            stats.recv_bytes.saturating_sub(counters_before.1),
            stats.lost.saturating_sub(counters_before.2),
            stats.lost_bytes.saturating_sub(counters_before.3),
            stats
                .data_blocked_recv_count
                .saturating_sub(counters_before.4),
            stats
                .stream_data_blocked_recv_count
                .saturating_sub(counters_before.5),
            result.stream_finished,
        );
    }

    let masque_median = median(&mut masque_transfer_rates)
        .expect("at least one MASQUE TCP download sample was required");
    if let Some(direct_median) = median(&mut direct_transfer_rates) {
        println!(
            "TCP_DOWNLOAD_SUMMARY samples={repeats} direct_transfer_mbps_median={direct_median:.3} \
masque_transfer_mbps_median={masque_median:.3} direct_ratio_pct={:.2}",
            masque_median * 100.0 / direct_median,
        );
    } else {
        println!(
            "TCP_DOWNLOAD_SUMMARY samples={repeats} masque_transfer_mbps_median={masque_median:.3}"
        );
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

/// Saturating multi-connection load generator.
///
/// The single-connection benchmark cannot show anything about how work is
/// spread across cores: one QUIC connection is handled by one event loop no
/// matter how the server is built. This drives many independent connections,
/// each from its own socket and therefore its own 4-tuple, which is what a
/// connection-sharded server needs in order to use more than one core.
fn load_test(server_addr: &str, echo_addr: &str) -> Result<()> {
    const MAX_LOAD_CONNECTIONS: usize = 1_024;
    const MAX_LOAD_DURATION_SECS: usize = 3_600;
    const MAX_LOAD_WINDOW: usize = 1_000;
    const MAX_LOAD_EXPIRY_MS: usize = 60_000;

    let conns = env_usize("MASQUE_LOAD_CONNS", 32)?;
    let duration_secs = env_usize("MASQUE_LOAD_DURATION_SECS", 10)?;
    let payload_size = env_usize("MASQUE_LOAD_PAYLOAD", 1200)?;
    let window = env_usize("MASQUE_LOAD_WINDOW", 16)?;
    let expiry_ms = env_usize("MASQUE_LOAD_EXPIRY_MS", 1_000)?;

    if conns == 0 || duration_secs == 0 || window == 0 || expiry_ms == 0 {
        bail!("load connections, duration, window, and expiry must be non-zero");
    }
    if payload_size < 8 {
        bail!("MASQUE_LOAD_PAYLOAD must be at least 8 bytes");
    }
    if conns > MAX_LOAD_CONNECTIONS {
        bail!("MASQUE_LOAD_CONNS must not exceed {MAX_LOAD_CONNECTIONS}");
    }
    if duration_secs > MAX_LOAD_DURATION_SECS {
        bail!("MASQUE_LOAD_DURATION_SECS must not exceed {MAX_LOAD_DURATION_SECS}");
    }
    if window > MAX_LOAD_WINDOW {
        bail!(
            "MASQUE_LOAD_WINDOW must not exceed the QUIC DATAGRAM queue size ({MAX_LOAD_WINDOW})"
        );
    }
    if expiry_ms > MAX_LOAD_EXPIRY_MS {
        bail!("MASQUE_LOAD_EXPIRY_MS must not exceed {MAX_LOAD_EXPIRY_MS}");
    }
    if payload_size > MAX_DATAGRAM_SIZE {
        bail!("MASQUE_LOAD_PAYLOAD must not exceed {MAX_DATAGRAM_SIZE}");
    }

    println!(
        "Load test: {conns} connections, {duration_secs}s, {payload_size}B payload, \
         window {window}/conn, expiry {expiry_ms}ms"
    );

    #[derive(Debug)]
    struct WorkerStats {
        setup: Duration,
        sent: u64,
        received: u64,
        expired: u64,
    }

    #[derive(Debug)]
    enum WorkerOutcome {
        Finished(WorkerStats),
        SetupFailed(String),
        RuntimeFailed { setup: Duration, error: String },
    }

    let ready = Arc::new(Barrier::new(conns + 1));
    let start = Arc::new(Barrier::new(conns + 1));
    let duration = Duration::from_secs(duration_secs as u64);
    let expiry = Duration::from_millis(expiry_ms as u64);

    // Include thread creation in the time until the whole concurrent batch is
    // ready. Individual connection latency is measured inside each worker.
    let setup_batch_started = Instant::now();
    let mut workers = Vec::with_capacity(conns);
    for _ in 0..conns {
        let server_addr = server_addr.to_string();
        let echo_addr = echo_addr.to_string();
        let ready = Arc::clone(&ready);
        let start = Arc::clone(&start);

        workers.push(std::thread::spawn(move || {
            // Establish the tunnel before the barrier so every connection is
            // pushing traffic during the same measurement window.
            let setup_started = Instant::now();
            let tunnel = connect_udp_tunnel(&server_addr, &echo_addr);
            let setup = setup_started.elapsed();

            // A failed setup still participates in both barriers, otherwise
            // every successful worker and the coordinator would wait forever.
            ready.wait();
            start.wait();

            let (mut client, stream_id) = match tunnel {
                Ok(tunnel) => tunnel,
                Err(error) => return WorkerOutcome::SetupFailed(format!("{error:#}")),
            };

            // Reuse the exact saturating loop used by the trusted
            // single-connection benchmark. Keeping one packet engine avoids
            // a second implementation silently changing pacing, draining, or
            // expiry semantics.
            match client.run_echo_throughput(stream_id, payload_size, duration, window, expiry) {
                Ok((sent, received, expired)) => WorkerOutcome::Finished(WorkerStats {
                    setup,
                    sent,
                    received,
                    expired,
                }),
                Err(error) => WorkerOutcome::RuntimeFailed {
                    setup,
                    error: format!("{error:#}"),
                },
            }
        }));
    }

    ready.wait();
    let setup_batch = setup_batch_started.elapsed();
    start.wait();

    let mut setup_latencies = Vec::with_capacity(conns);
    let mut sent = 0u64;
    let mut received = 0u64;
    let mut expired = 0u64;
    let mut setup_failures = 0u64;
    let mut runtime_failures = 0u64;
    for worker in workers {
        match worker.join() {
            Ok(WorkerOutcome::Finished(stats)) => {
                setup_latencies.push(stats.setup.as_secs_f64() * 1e3);
                sent += stats.sent;
                received += stats.received;
                expired += stats.expired;
            }
            Ok(WorkerOutcome::SetupFailed(error)) => {
                setup_failures += 1;
                warn!(%error, "load connection setup failed");
            }
            Ok(WorkerOutcome::RuntimeFailed { setup, error }) => {
                setup_latencies.push(setup.as_secs_f64() * 1e3);
                runtime_failures += 1;
                warn!(%error, "load worker stopped early");
            }
            Err(_) => {
                runtime_failures += 1;
                warn!("load worker panicked");
            }
        }
    }

    // Only workers that returned a measured setup duration definitely
    // established a tunnel. A panic is not assumed to have happened after
    // setup, so it cannot inflate this count.
    let established = setup_latencies.len() as u64;
    let elapsed = duration.as_secs_f64();
    let tx_pps = sent as f64 / elapsed;
    let rx_pps = received as f64 / elapsed;
    let goodput = rx_pps * payload_size as f64 * 8.0 / 1e9;
    let response_shortfall = sent.saturating_sub(received);
    let response_shortfall_pct = response_shortfall as f64 * 100.0 / sent.max(1) as f64;

    println!(
        "  connections established: {established}/{conns} in {:.0} ms ({:.1} conn/s)",
        setup_batch.as_secs_f64() * 1e3,
        established as f64 / setup_batch.as_secs_f64().max(f64::EPSILON)
    );
    if !setup_latencies.is_empty() {
        setup_latencies.sort_by(f64::total_cmp);
        let average = setup_latencies.iter().sum::<f64>() / setup_latencies.len() as f64;
        let percentile = |p: f64| percentile_nearest_rank(&setup_latencies, p).unwrap();
        println!(
            "  per-connection setup: avg {average:.1} ms   p50 {:.1} ms   p95 {:.1} ms   p99 {:.1} ms",
            percentile(0.50),
            percentile(0.95),
            percentile(0.99)
        );
    }
    println!(
        "  tx {:>10.0} pkt/s   echo {:>10.0} pkt/s   app goodput {:.3} Gbit/s   \
         bidirectional relay {:.3} Gbit/s   response shortfall {response_shortfall_pct:.2}% \
         ({expired} expired)",
        tx_pps,
        rx_pps,
        goodput,
        goodput * 2.0
    );
    println!(
        "LOAD_RESULT connections={conns} established={established} duration_secs={duration_secs} \
payload_bytes={payload_size} window={window} expiry_ms={expiry_ms} tx_packets={sent} \
rx_packets={received} \
tx_pps={tx_pps:.3} rx_pps={rx_pps:.3} app_goodput_gbps={goodput:.6} \
bidirectional_relay_gbps={:.6} response_shortfall_pct={response_shortfall_pct:.6} \
expired_packets={expired} \
setup_failures={setup_failures} runtime_failures={runtime_failures}",
        goodput * 2.0
    );
    if established == 0 {
        bail!("no load connections were established");
    }
    if setup_failures != 0 || runtime_failures != 0 {
        bail!(
            "load test had {setup_failures} setup failure(s) and {runtime_failures} runtime failure(s)"
        );
    }
    Ok(())
}

fn env_usize(name: &str, default: usize) -> Result<usize> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<usize>()
            .with_context(|| format!("{name} must be a non-negative integer")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => bail!("{name} is not valid UTF-8"),
    }
}

fn percentile_nearest_rank(sorted: &[f64], percentile: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }

    let rank = (percentile.clamp(0.0, 1.0) * sorted.len() as f64).ceil() as usize;
    Some(sorted[rank.clamp(1, sorted.len()) - 1])
}

fn median(values: &mut [f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len() & 1 == 0 {
        Some((values[middle - 1] + values[middle]) / 2.0)
    } else {
        Some(values[middle])
    }
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

    if std::env::var_os("MASQUE_TCP_DOWNLOAD").is_some() {
        if let Err(e) = benchmark_standard_connect_download(&server_addr) {
            error!(%e, "standard CONNECT download benchmark failed");
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

    if std::env::var_os("MASQUE_LOAD").is_some() {
        if let Err(e) = load_test(&server_addr, &echo_addr) {
            error!(%e, "load test failed");
            std::process::exit(1);
        }
        return;
    }

    if std::env::var_os("MASQUE_BENCH").is_some() {
        if let Err(e) = benchmark_connect_udp(&server_addr, &echo_addr) {
            error!(%e, "network benchmark failed");
            std::process::exit(1);
        }
        return;
    }

    type E2eTest = fn(&str, &str) -> Result<()>;
    let tests: &[(&str, E2eTest)] = &[
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_tcp_download_counts_body_without_http_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let origin = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let read = stream.read(&mut request).unwrap();
            assert!(request[..read].starts_with(b"GET /blob HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\npayload")
                .unwrap();
        });

        let (result, started, connected, request_started) = benchmark_direct_tcp_download(
            &addr.to_string(),
            "/blob",
            Some(7),
            Duration::from_secs(2),
        )
        .unwrap();

        origin.join().unwrap();
        assert_eq!(result.response.status, Some(200));
        assert_eq!(result.response.content_length, Some(7));
        assert_eq!(result.response.body_bytes, 7);
        assert!(connected >= started);
        assert!(request_started >= connected);
        assert!(result.finished_at >= request_started);
    }

    #[test]
    fn median_handles_odd_even_and_empty_samples() {
        assert_eq!(median(&mut []), None);
        assert_eq!(median(&mut [3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(&mut [4.0, 1.0, 3.0, 2.0]), Some(2.5));
    }

    #[test]
    fn nearest_rank_percentiles_handle_small_samples() {
        assert_eq!(percentile_nearest_rank(&[], 0.95), None);
        assert_eq!(percentile_nearest_rank(&[10.0], 0.95), Some(10.0));
        assert_eq!(percentile_nearest_rank(&[10.0, 20.0], 0.50), Some(10.0));
        assert_eq!(percentile_nearest_rank(&[10.0, 20.0], 0.95), Some(20.0));
        assert_eq!(
            percentile_nearest_rank(&[10.0, 20.0, 30.0, 40.0], 0.75),
            Some(30.0)
        );
    }
}
