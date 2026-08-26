use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

use boring::ssl::{SslContextBuilder, SslMethod};
use masque::capsule::CapsuleFrame;
use masque::capsule::decoder::{CapsuleDecoder, DecodeError};
use quiche::h3::NameValue as _;
use ring::rand::SecureRandom as _;

use crate::credentials::Credentials;
use crate::endpoint::{Authority, encode_path_segment};
use crate::protocol::{ensure_success_status, udp_probe_payload, validate_udp_probe_response};
use crate::report::ProbeFailure;

const MAX_DATAGRAM_SIZE: usize = 65_535;

pub struct Session {
    socket: UdpSocket,
    quic: quiche::Connection,
    h3: quiche::h3::Connection,
    peer: SocketAddr,
    local: SocketAddr,
    authority: String,
    timeout: Duration,
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    pub fn connect(
        addresses: &[SocketAddr],
        endpoint: &Authority,
        server_name: &str,
        credentials: &Credentials,
        insecure: bool,
        ca_cert: Option<&Path>,
        interface: Option<&str>,
        timeout: Duration,
    ) -> Result<(Self, SocketAddr), ProbeFailure> {
        let mut failures = Vec::new();
        for &peer in addresses {
            match Self::connect_one(
                peer,
                endpoint,
                server_name,
                credentials,
                insecure,
                ca_cert,
                interface,
                timeout,
            ) {
                Ok(session) => return Ok((session, peer)),
                Err(failure) => failures.push(format!("{peer}: {}", failure.detail)),
            }
        }
        Err(ProbeFailure::new(
            "HTTP3_HANDSHAKE_FAILED",
            format!("all resolved addresses failed: {}", failures.join("; ")),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn connect_one(
        peer: SocketAddr,
        endpoint: &Authority,
        server_name: &str,
        credentials: &Credentials,
        insecure: bool,
        ca_cert: Option<&Path>,
        interface: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, ProbeFailure> {
        let bind = if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).map_err(|error| {
            ProbeFailure::new("UDP_SOCKET_ERROR", format!("bind {bind}: {error}"))
        })?;
        if let Some(interface) = interface {
            bind_socket_to_interface(&socket, peer, interface)?;
        }
        socket.connect(peer).map_err(|error| {
            ProbeFailure::new(
                "UDP_SOCKET_ERROR",
                format!("connect UDP to {peer}: {error}"),
            )
        })?;
        let local = socket.local_addr().map_err(|error| {
            ProbeFailure::new(
                "UDP_SOCKET_ERROR",
                format!("read local UDP address: {error}"),
            )
        })?;

        let mut config = build_config(credentials, insecure, ca_cert)?;
        let mut scid = [0_u8; quiche::MAX_CONN_ID_LEN];
        ring::rand::SystemRandom::new()
            .fill(&mut scid)
            .map_err(|_| ProbeFailure::new("RNG_ERROR", "system random generator failed"))?;
        let connection_id = quiche::ConnectionId::from_ref(&scid);
        let quic = quiche::connect(Some(server_name), &connection_id, local, peer, &mut config)
            .map_err(|error| {
                ProbeFailure::new("QUIC_ERROR", format!("create QUIC connection: {error}"))
            })?;

        let mut pending = PendingSession {
            socket,
            quic,
            peer,
            local,
            timeout,
        };
        pending.handshake()?;

        if let Some(identity) = credentials.client_identity() {
            let peer_certificate = pending.quic.peer_cert().ok_or_else(|| {
                ProbeFailure::new("TLS_PIN_MISMATCH", "server sent no leaf certificate")
            })?;
            identity.verify_peer_certificate(peer_certificate)?;
        }

        let mut h3_config = quiche::h3::Config::new().map_err(|error| {
            ProbeFailure::new("HTTP3_ERROR", format!("create HTTP/3 config: {error}"))
        })?;
        h3_config.enable_extended_connect(true);
        let h3 = quiche::h3::Connection::with_transport(&mut pending.quic, &h3_config)
            .map_err(|error| ProbeFailure::new("HTTP3_ERROR", format!("start HTTP/3: {error}")))?;
        let mut session = Self {
            socket: pending.socket,
            quic: pending.quic,
            h3,
            peer,
            local,
            authority: endpoint.original.clone(),
            timeout,
        };
        session.wait_for_capabilities()?;
        Ok(session)
    }

    pub fn probe_tcp(
        &mut self,
        target: &Authority,
        credentials: &Credentials,
    ) -> Result<String, ProbeFailure> {
        let mut headers = vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":authority", target.original.as_bytes()),
        ];
        append_auth(&mut headers, credentials);
        let stream = self.send_request(&headers)?;
        let status = self.poll_status(stream)?;
        ensure_success_status(status, &target.original)?;
        Ok(format!("CONNECT to {} returned HTTP 200", target.original))
    }

    pub fn probe_udp(
        &mut self,
        target: &Authority,
        credentials: &Credentials,
        dns: bool,
    ) -> Result<String, ProbeFailure> {
        let path = format!(
            "/.well-known/masque/udp/{}/{}/",
            encode_path_segment(&target.host),
            target.port
        );
        let mut headers = vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"connect-udp"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", self.authority.as_bytes()),
            quiche::h3::Header::new(b":path", path.as_bytes()),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        ];
        append_auth(&mut headers, credentials);
        let stream = self.send_request(&headers)?;
        let status = self.poll_status(stream)?;
        ensure_success_status(status, &target.original)?;

        let request = udp_probe_payload(dns);
        let datagram = masque::datagram::encode_payload(stream, &request).map_err(|error| {
            ProbeFailure::new(
                "HTTP_DATAGRAM_ERROR",
                format!("encode DNS datagram: {error}"),
            )
        })?;
        self.quic.dgram_send(&datagram).map_err(|error| {
            ProbeFailure::new(
                "HTTP_DATAGRAM_ERROR",
                format!("queue DNS datagram: {error}"),
            )
        })?;
        self.flush()?;
        let response = self.recv_datagram(stream)?;
        validate_udp_probe_response(&response, &request, dns)?;
        Ok(format!(
            "CONNECT-UDP to {} returned a matching {} response",
            target.original,
            if dns { "DNS" } else { "echo" }
        ))
    }

    pub fn probe_connect_ip(&mut self, credentials: &Credentials) -> Result<String, ProbeFailure> {
        let mut headers = vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"connect-ip"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", self.authority.as_bytes()),
            quiche::h3::Header::new(b":path", b"/.well-known/masque/ip/"),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        ];
        append_auth(&mut headers, credentials);
        let stream = self.send_request(&headers)?;
        let status = self.poll_status(stream)?;
        ensure_success_status(status, "CONNECT-IP")?;
        let frames = self.recv_capsules(stream)?;
        let assigned = frames.iter().find_map(|frame| match frame {
            CapsuleFrame::AddressAssign(addresses) if !addresses.is_empty() => Some(addresses),
            _ => None,
        });
        let Some(addresses) = assigned else {
            return Err(ProbeFailure::new(
                "CONNECT_IP_NO_ADDRESS",
                "CONNECT-IP returned 200 but no ADDRESS_ASSIGN capsule",
            ));
        };
        Ok(format!(
            "CONNECT-IP assigned {} address(es); run server-side doctor to verify forwarding/NAT",
            addresses.len()
        ))
    }

    fn wait_for_capabilities(&mut self) -> Result<(), ProbeFailure> {
        let deadline = Instant::now() + self.timeout;
        loop {
            if self.h3.extended_connect_enabled_by_peer()
                && self.h3.dgram_enabled_by_peer(&self.quic)
            {
                return Ok(());
            }
            self.poll_events(None)?;
            if Instant::now() >= deadline {
                return Err(ProbeFailure::new(
                    "HTTP3_SETTINGS_MISSING",
                    "server did not advertise Extended CONNECT and HTTP Datagrams",
                ));
            }
            self.drive(deadline)?;
        }
    }

    fn send_request(&mut self, headers: &[quiche::h3::Header]) -> Result<u64, ProbeFailure> {
        let stream = self
            .h3
            .send_request(&mut self.quic, headers, false)
            .map_err(|error| {
                ProbeFailure::new("HTTP3_REQUEST_ERROR", format!("send CONNECT: {error}"))
            })?;
        self.flush()?;
        Ok(stream)
    }

    fn poll_status(&mut self, expected_stream: u64) -> Result<u16, ProbeFailure> {
        let deadline = Instant::now() + self.timeout;
        loop {
            if let Some(status) = self.poll_events(Some(expected_stream))? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(ProbeFailure::new(
                    "RESPONSE_TIMEOUT",
                    "timed out waiting for CONNECT response headers",
                ));
            }
            self.drive(deadline)?;
        }
    }

    fn poll_events(&mut self, expected_stream: Option<u64>) -> Result<Option<u16>, ProbeFailure> {
        loop {
            match self.h3.poll(&mut self.quic) {
                Ok((stream, quiche::h3::Event::Headers { list, .. }))
                    if expected_stream.is_none_or(|expected| expected == stream) =>
                {
                    let status = list
                        .iter()
                        .find(|header| header.name() == b":status")
                        .ok_or_else(|| {
                            ProbeFailure::new(
                                "HTTP3_PROTOCOL_ERROR",
                                "response has no :status header",
                            )
                        })?;
                    let value = std::str::from_utf8(status.value())
                        .ok()
                        .and_then(|value| value.parse::<u16>().ok())
                        .ok_or_else(|| {
                            ProbeFailure::new(
                                "HTTP3_PROTOCOL_ERROR",
                                "response has an invalid :status header",
                            )
                        })?;
                    return Ok(Some(value));
                }
                Ok(_) => continue,
                Err(quiche::h3::Error::Done) => return Ok(None),
                Err(error) => {
                    return Err(ProbeFailure::new(
                        "HTTP3_PROTOCOL_ERROR",
                        format!("poll HTTP/3: {error}"),
                    ));
                }
            }
        }
    }

    fn recv_datagram(&mut self, expected_stream: u64) -> Result<Vec<u8>, ProbeFailure> {
        let deadline = Instant::now() + self.timeout;
        loop {
            let mut buffer = [0_u8; MAX_DATAGRAM_SIZE];
            match self.quic.dgram_recv(&mut buffer) {
                Ok(length) => {
                    let datagram =
                        masque::datagram::decode(&buffer[..length]).map_err(|error| {
                            ProbeFailure::new(
                                "HTTP_DATAGRAM_ERROR",
                                format!("decode response datagram: {error}"),
                            )
                        })?;
                    if datagram.stream_id == expected_stream && datagram.context_id == 0 {
                        return Ok(datagram.payload);
                    }
                }
                Err(quiche::Error::Done) => {}
                Err(error) => {
                    return Err(ProbeFailure::new(
                        "HTTP_DATAGRAM_ERROR",
                        format!("receive response datagram: {error}"),
                    ));
                }
            }
            if Instant::now() >= deadline {
                return Err(ProbeFailure::new(
                    "UDP_RESPONSE_TIMEOUT",
                    "CONNECT-UDP opened, but no DNS response datagram arrived",
                ));
            }
            self.drive(deadline)?;
        }
    }

    fn recv_capsules(&mut self, stream: u64) -> Result<Vec<CapsuleFrame>, ProbeFailure> {
        let deadline = Instant::now() + self.timeout;
        let mut decoder = CapsuleDecoder::new();
        let mut frames = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            self.poll_events(None)?;
            loop {
                match self.h3.recv_body(&mut self.quic, stream, &mut buffer) {
                    Ok(length) => match decoder.decode(&buffer[..length]) {
                        Ok(mut decoded) => frames.append(&mut decoded),
                        Err(DecodeError::Incomplete) => {}
                        Err(error) => {
                            return Err(ProbeFailure::new(
                                "CAPSULE_ERROR",
                                format!("decode CONNECT-IP capsule: {error:?}"),
                            ));
                        }
                    },
                    Err(quiche::h3::Error::Done) => break,
                    Err(error) => {
                        return Err(ProbeFailure::new(
                            "CAPSULE_ERROR",
                            format!("read CONNECT-IP capsule: {error}"),
                        ));
                    }
                }
            }
            if frames
                .iter()
                .any(|frame| matches!(frame, CapsuleFrame::AddressAssign(_)))
            {
                return Ok(frames);
            }
            if Instant::now() >= deadline {
                return Err(ProbeFailure::new(
                    "CAPSULE_TIMEOUT",
                    "timed out waiting for CONNECT-IP ADDRESS_ASSIGN",
                ));
            }
            self.drive(deadline)?;
        }
    }

    fn flush(&mut self) -> Result<(), ProbeFailure> {
        let mut output = [0_u8; MAX_DATAGRAM_SIZE];
        loop {
            match self.quic.send(&mut output) {
                Ok((length, info)) => {
                    let delay = info.at.saturating_duration_since(Instant::now());
                    if !delay.is_zero() {
                        std::thread::sleep(delay.min(Duration::from_millis(10)));
                    }
                    self.socket.send(&output[..length]).map_err(|error| {
                        ProbeFailure::new("UDP_SEND_ERROR", format!("send QUIC packet: {error}"))
                    })?;
                }
                Err(quiche::Error::Done) => return Ok(()),
                Err(error) => {
                    return Err(ProbeFailure::new(
                        "QUIC_ERROR",
                        format!("serialize QUIC packet: {error}"),
                    ));
                }
            }
        }
    }

    fn drive(&mut self, deadline: Instant) -> Result<(), ProbeFailure> {
        self.flush()?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = self
            .quic
            .timeout()
            .unwrap_or(Duration::from_millis(50))
            .min(remaining)
            .max(Duration::from_millis(1));
        self.socket
            .set_read_timeout(Some(timeout))
            .map_err(|error| {
                ProbeFailure::new("UDP_SOCKET_ERROR", format!("set receive timeout: {error}"))
            })?;
        let mut input = [0_u8; MAX_DATAGRAM_SIZE];
        match self.socket.recv(&mut input) {
            Ok(length) => {
                let info = quiche::RecvInfo {
                    from: self.peer,
                    to: self.local,
                };
                match self.quic.recv(&mut input[..length], info) {
                    Ok(_) | Err(quiche::Error::Done) => {}
                    Err(error) => {
                        return Err(ProbeFailure::new(
                            "QUIC_ERROR",
                            format!("parse QUIC packet: {error}"),
                        ));
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                self.quic.on_timeout();
            }
            Err(error) => {
                return Err(ProbeFailure::new(
                    "UDP_RECEIVE_ERROR",
                    format!("receive QUIC packet: {error}"),
                ));
            }
        }
        if self.quic.is_closed() {
            return Err(ProbeFailure::new(
                "QUIC_CONNECTION_CLOSED",
                quic_close_detail(&self.quic),
            ));
        }
        self.flush()
    }
}

#[cfg(target_os = "macos")]
fn bind_socket_to_interface(
    socket: &UdpSocket,
    peer: SocketAddr,
    interface: &str,
) -> Result<(), ProbeFailure> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd as _;

    let interface = CString::new(interface).map_err(|_| {
        ProbeFailure::new(
            "INVALID_INTERFACE",
            "interface name contains an embedded NUL",
        )
    })?;
    // SAFETY: `interface` is live and NUL terminated for the duration of the call.
    let index = unsafe { libc::if_nametoindex(interface.as_ptr()) };
    if index == 0 {
        return Err(ProbeFailure::new(
            "INVALID_INTERFACE",
            "network interface does not exist",
        ));
    }
    let (level, option) = if peer.is_ipv4() {
        (libc::IPPROTO_IP, libc::IP_BOUND_IF)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
    };
    // SAFETY: the socket fd and pointer to the `c_uint` option are valid.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&index as *const libc::c_uint).cast(),
            std::mem::size_of_val(&index) as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(ProbeFailure::new(
            "INTERFACE_BIND_FAILED",
            format!(
                "could not bind UDP socket to interface {:?}: {}",
                interface,
                std::io::Error::last_os_error()
            ),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_socket_to_interface(
    socket: &UdpSocket,
    _peer: SocketAddr,
    interface: &str,
) -> Result<(), ProbeFailure> {
    use std::os::fd::AsRawFd as _;

    if interface.is_empty() || interface.as_bytes().contains(&0) {
        return Err(ProbeFailure::new(
            "INVALID_INTERFACE",
            "interface name is empty or contains an embedded NUL",
        ));
    }
    let mut name = interface.as_bytes().to_vec();
    name.push(0);
    // SAFETY: the socket fd and interface byte string are valid for this call.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.len() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(ProbeFailure::new(
            "INTERFACE_BIND_FAILED",
            format!(
                "could not bind UDP socket to interface {interface:?}: {}; this may require CAP_NET_RAW/root",
                std::io::Error::last_os_error()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn bind_socket_to_interface(
    _socket: &UdpSocket,
    _peer: SocketAddr,
    _interface: &str,
) -> Result<(), ProbeFailure> {
    Err(ProbeFailure::new(
        "INTERFACE_UNSUPPORTED",
        "--interface is supported only on Linux and macOS",
    ))
}

struct PendingSession {
    socket: UdpSocket,
    quic: quiche::Connection,
    peer: SocketAddr,
    local: SocketAddr,
    timeout: Duration,
}

impl PendingSession {
    fn handshake(&mut self) -> Result<(), ProbeFailure> {
        let deadline = Instant::now() + self.timeout;
        let mut output = [0_u8; MAX_DATAGRAM_SIZE];
        let mut input = [0_u8; MAX_DATAGRAM_SIZE];
        loop {
            loop {
                match self.quic.send(&mut output) {
                    Ok((length, _)) => {
                        self.socket.send(&output[..length]).map_err(|error| {
                            ProbeFailure::new(
                                "UDP_SEND_ERROR",
                                format!("send QUIC handshake: {error}"),
                            )
                        })?;
                    }
                    Err(quiche::Error::Done) => break,
                    Err(error) => {
                        return Err(ProbeFailure::new(
                            "QUIC_ERROR",
                            format!("serialize QUIC handshake: {error}"),
                        ));
                    }
                }
            }
            if self.quic.is_established() {
                return Ok(());
            }
            if self.quic.is_closed() {
                return Err(ProbeFailure::new(
                    "TLS_OR_QUIC_REJECTED",
                    quic_close_detail(&self.quic),
                ));
            }
            if Instant::now() >= deadline {
                return Err(ProbeFailure::new(
                    "UDP_BLOCKED_OR_TIMEOUT",
                    "QUIC handshake timed out; UDP may be blocked or the server may not be listening",
                ));
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            let timeout = self
                .quic
                .timeout()
                .unwrap_or(Duration::from_millis(50))
                .min(remaining)
                .max(Duration::from_millis(1));
            self.socket
                .set_read_timeout(Some(timeout))
                .map_err(|error| {
                    ProbeFailure::new("UDP_SOCKET_ERROR", format!("set receive timeout: {error}"))
                })?;
            match self.socket.recv(&mut input) {
                Ok(length) => {
                    let info = quiche::RecvInfo {
                        from: self.peer,
                        to: self.local,
                    };
                    match self.quic.recv(&mut input[..length], info) {
                        Ok(_) | Err(quiche::Error::Done) => {}
                        Err(error) => {
                            return Err(ProbeFailure::new(
                                "QUIC_ERROR",
                                format!("parse QUIC handshake: {error}"),
                            ));
                        }
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    self.quic.on_timeout();
                }
                Err(error) => {
                    return Err(ProbeFailure::new(
                        "UDP_RECEIVE_ERROR",
                        format!("receive QUIC handshake: {error}"),
                    ));
                }
            }
        }
    }
}

fn build_config(
    credentials: &Credentials,
    insecure: bool,
    ca_cert: Option<&Path>,
) -> Result<quiche::Config, ProbeFailure> {
    let mut config = if let Some(identity) = credentials.client_identity() {
        let mut builder = SslContextBuilder::new(SslMethod::tls()).map_err(|error| {
            ProbeFailure::new("TLS_CONFIG_ERROR", format!("create TLS context: {error}"))
        })?;
        identity.configure_context(&mut builder)?;
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder).map_err(
            |error| ProbeFailure::new("TLS_CONFIG_ERROR", format!("create QUIC config: {error}")),
        )?
    } else {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|error| {
            ProbeFailure::new("TLS_CONFIG_ERROR", format!("create QUIC config: {error}"))
        })?;
        config.verify_peer(!insecure);
        if let Some(path) = ca_cert {
            let path = path.to_str().ok_or_else(|| {
                ProbeFailure::new("TLS_CONFIG_ERROR", "--ca-cert path is not valid UTF-8")
            })?;
            config
                .load_verify_locations_from_file(path)
                .map_err(|error| {
                    ProbeFailure::new(
                        "TLS_CONFIG_ERROR",
                        format!("load CA certificate {path}: {error}"),
                    )
                })?;
        }
        config
    };

    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|error| ProbeFailure::new("HTTP3_ERROR", error.to_string()))?;
    config.set_max_idle_timeout(15_000);
    config.set_max_recv_udp_payload_size(1350);
    config.set_max_send_udp_payload_size(1350);
    config.set_initial_max_data(4 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_local(1024 * 1024);
    config.set_initial_max_stream_data_bidi_remote(1024 * 1024);
    config.set_initial_max_stream_data_uni(256 * 1024);
    config.set_initial_max_streams_bidi(16);
    config.set_initial_max_streams_uni(16);
    config.enable_dgram(true, 128, 128);
    Ok(config)
}

fn append_auth(headers: &mut Vec<quiche::h3::Header>, credentials: &Credentials) {
    if let Some(value) = credentials.authorization() {
        headers.push(quiche::h3::Header::new(
            b"proxy-authorization",
            value.as_bytes(),
        ));
    }
}

fn quic_close_detail(connection: &quiche::Connection) -> String {
    if let Some(error) = connection.peer_error() {
        return format!(
            "peer closed QUIC (application={}, code={}, reason={})",
            error.is_app,
            error.error_code,
            String::from_utf8_lossy(&error.reason)
        );
    }
    if let Some(error) = connection.local_error() {
        return format!(
            "local QUIC close (application={}, code={}, reason={})",
            error.is_app,
            error.error_code,
            String::from_utf8_lossy(&error.reason)
        );
    }
    "QUIC connection closed without an error reason".into()
}
