use std::future::poll_fn;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use bytes::{Buf as _, Bytes};
use h2::client::SendRequest;
use http::{Method, Request};
use masque::capsule::CapsuleFrame;
use masque::capsule::decoder::{CapsuleDecoder, DecodeError};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

use crate::credentials::Credentials;
use crate::endpoint::{Authority, encode_path_segment};
use crate::protocol::{ensure_success_status, udp_probe_payload, validate_udp_probe_response};
use crate::report::ProbeFailure;

const INITIAL_STREAM_WINDOW: u32 = 4 * 1024 * 1024;
const INITIAL_CONNECTION_WINDOW: u32 = 8 * 1024 * 1024;

pub struct Session {
    runtime: Runtime,
    connection: Connection,
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
        timeout: Duration,
    ) -> Result<(Self, SocketAddr), ProbeFailure> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|error| {
                ProbeFailure::new("HTTP2_RUNTIME_ERROR", format!("create runtime: {error}"))
            })?;
        let (connection, peer) = runtime.block_on(Connection::connect(
            addresses,
            endpoint,
            server_name,
            credentials,
            insecure,
            ca_cert,
            timeout,
        ))?;
        Ok((
            Self {
                runtime,
                connection,
            },
            peer,
        ))
    }

    pub fn probe_tcp(
        &mut self,
        target: &Authority,
        credentials: &Credentials,
    ) -> Result<String, ProbeFailure> {
        let Self {
            runtime,
            connection,
        } = self;
        runtime.block_on(connection.probe_tcp(target, credentials))
    }

    pub fn probe_udp(
        &mut self,
        target: &Authority,
        credentials: &Credentials,
        dns: bool,
    ) -> Result<String, ProbeFailure> {
        let Self {
            runtime,
            connection,
        } = self;
        runtime.block_on(connection.probe_udp(target, credentials, dns))
    }

    pub fn probe_connect_ip(&mut self, credentials: &Credentials) -> Result<String, ProbeFailure> {
        let Self {
            runtime,
            connection,
        } = self;
        runtime.block_on(connection.probe_connect_ip(credentials))
    }
}

struct Connection {
    sender: SendRequest<Bytes>,
    driver: JoinHandle<Result<(), h2::Error>>,
    authority: String,
    timeout: Duration,
}

impl Connection {
    #[allow(clippy::too_many_arguments)]
    async fn connect(
        addresses: &[SocketAddr],
        endpoint: &Authority,
        server_name: &str,
        credentials: &Credentials,
        insecure: bool,
        ca_cert: Option<&Path>,
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
                timeout,
            )
            .await
            {
                Ok(connection) => return Ok((connection, peer)),
                Err(failure) => failures.push(format!("{peer}: {}", failure.detail)),
            }
        }
        Err(ProbeFailure::new(
            "HTTP2_HANDSHAKE_FAILED",
            format!("all resolved addresses failed: {}", failures.join("; ")),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_one(
        peer: SocketAddr,
        endpoint: &Authority,
        server_name: &str,
        credentials: &Credentials,
        insecure: bool,
        ca_cert: Option<&Path>,
        timeout: Duration,
    ) -> Result<Self, ProbeFailure> {
        let tcp = tokio::time::timeout(timeout, TcpStream::connect(peer))
            .await
            .map_err(|_| {
                ProbeFailure::new(
                    "TCP_BLOCKED_OR_TIMEOUT",
                    format!("TCP connection to {peer} timed out"),
                )
            })?
            .map_err(|error| {
                ProbeFailure::new(
                    "TCP_CONNECT_ERROR",
                    format!("TCP connection to {peer} failed: {error}"),
                )
            })?;
        tcp.set_nodelay(true).map_err(|error| {
            ProbeFailure::new("TCP_CONNECT_ERROR", format!("set TCP_NODELAY: {error}"))
        })?;

        let mut connector =
            boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls_client()).map_err(
                |error| {
                    ProbeFailure::new("TLS_CONFIG_ERROR", format!("create TLS connector: {error}"))
                },
            )?;
        connector
            .set_alpn_protos(b"\x02h2")
            .map_err(|error| ProbeFailure::new("TLS_CONFIG_ERROR", error.to_string()))?;
        if let Some(identity) = credentials.client_identity() {
            identity.configure_context(&mut connector)?;
        } else {
            connector.set_verify(if insecure {
                boring::ssl::SslVerifyMode::NONE
            } else {
                boring::ssl::SslVerifyMode::PEER
            });
            if let Some(path) = ca_cert {
                connector.set_ca_file(path).map_err(|error| {
                    ProbeFailure::new(
                        "TLS_CONFIG_ERROR",
                        format!("load CA certificate {}: {error}", path.display()),
                    )
                })?;
            }
        }
        let configuration = connector.build().configure().map_err(|error| {
            ProbeFailure::new("TLS_CONFIG_ERROR", format!("configure TLS: {error}"))
        })?;
        let tls = tokio::time::timeout(
            timeout,
            tokio_boring::connect(configuration, server_name, tcp),
        )
        .await
        .map_err(|_| {
            ProbeFailure::new(
                "TLS_HANDSHAKE_TIMEOUT",
                format!("TLS handshake with {peer} timed out"),
            )
        })?
        .map_err(|error| {
            ProbeFailure::new(
                "TLS_HANDSHAKE_FAILED",
                format!("TLS handshake with {peer} failed: {error}"),
            )
        })?;
        if tls.ssl().selected_alpn_protocol() != Some(b"h2") {
            return Err(ProbeFailure::new(
                "HTTP2_ALPN_MISSING",
                "server did not negotiate the h2 ALPN",
            ));
        }
        if let Some(identity) = credentials.client_identity() {
            let certificate = tls.ssl().peer_certificate().ok_or_else(|| {
                ProbeFailure::new("TLS_PIN_MISMATCH", "server sent no leaf certificate")
            })?;
            let der = certificate.to_der().map_err(|error| {
                ProbeFailure::new(
                    "TLS_PIN_MISMATCH",
                    format!("encode server certificate: {error}"),
                )
            })?;
            identity.verify_peer_certificate(&der)?;
        }

        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(INITIAL_STREAM_WINDOW)
            .initial_connection_window_size(INITIAL_CONNECTION_WINDOW)
            .max_send_buffer_size(1024 * 1024)
            .data_frame_budget(64 * 1024);
        let (sender, h2_connection) = builder.handshake(tls).await.map_err(|error| {
            ProbeFailure::new(
                "HTTP2_HANDSHAKE_FAILED",
                format!("start HTTP/2 connection: {error}"),
            )
        })?;
        let driver = tokio::spawn(h2_connection);
        let sender = sender.ready().await.map_err(|error| {
            ProbeFailure::new(
                "HTTP2_HANDSHAKE_FAILED",
                format!("HTTP/2 sender not ready: {error}"),
            )
        })?;
        let deadline = tokio::time::Instant::now() + timeout;
        while !sender.is_extended_connect_protocol_enabled() {
            if driver.is_finished() {
                return Err(ProbeFailure::new(
                    "HTTP2_SETTINGS_MISSING",
                    "HTTP/2 connection ended before server SETTINGS arrived",
                ));
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(ProbeFailure::new(
                    "HTTP2_SETTINGS_MISSING",
                    "server did not advertise Extended CONNECT",
                ));
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        Ok(Self {
            sender,
            driver,
            authority: endpoint.original.clone(),
            timeout,
        })
    }

    async fn ready_sender(&self) -> Result<SendRequest<Bytes>, ProbeFailure> {
        self.sender.clone().ready().await.map_err(|error| {
            ProbeFailure::new(
                "HTTP2_CONNECTION_CLOSED",
                format!("HTTP/2 connection is not ready: {error}"),
            )
        })
    }

    async fn probe_tcp(
        &mut self,
        target: &Authority,
        credentials: &Credentials,
    ) -> Result<String, ProbeFailure> {
        let uri = http::Uri::builder()
            .authority(target.original.as_str())
            .build()
            .map_err(|error| {
                ProbeFailure::new(
                    "INVALID_TARGET",
                    format!("build CONNECT authority: {error}"),
                )
            })?;
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .body(())
            .map_err(|error| ProbeFailure::new("HTTP2_REQUEST_ERROR", error.to_string()))?;
        append_auth(&mut request, credentials)?;
        let mut sender = self.ready_sender().await?;
        let (response, _) = sender.send_request(request, false).map_err(|error| {
            ProbeFailure::new("HTTP2_REQUEST_ERROR", format!("send CONNECT: {error}"))
        })?;
        let response = response_with_timeout(response, self.timeout).await?;
        ensure_success_status(response.status().as_u16(), &target.original)?;
        Ok(format!("CONNECT to {} returned HTTP 200", target.original))
    }

    async fn probe_udp(
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
        let uri = format!("https://{}{}", self.authority, path)
            .parse::<http::Uri>()
            .map_err(|error| {
                ProbeFailure::new("INVALID_TARGET", format!("build CONNECT-UDP URI: {error}"))
            })?;
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .header("capsule-protocol", "?1")
            .body(())
            .map_err(|error| ProbeFailure::new("HTTP2_REQUEST_ERROR", error.to_string()))?;
        request
            .extensions_mut()
            .insert(h2::ext::Protocol::from_static("connect-udp"));
        append_auth(&mut request, credentials)?;
        let mut sender = self.ready_sender().await?;
        let (response, mut request_body) =
            sender.send_request(request, false).map_err(|error| {
                ProbeFailure::new("HTTP2_REQUEST_ERROR", format!("send CONNECT-UDP: {error}"))
            })?;
        let response = response_with_timeout(response, self.timeout).await?;
        ensure_success_status(response.status().as_u16(), &target.original)?;
        if response.headers().get("capsule-protocol") != Some(&http::HeaderValue::from_static("?1"))
        {
            return Err(ProbeFailure::new(
                "CAPSULE_PROTOCOL_MISSING",
                "CONNECT-UDP response omitted Capsule-Protocol: ?1",
            ));
        }
        let mut response_body = response.into_body();
        let request = udp_probe_payload(dns);
        let mut capsule = Vec::with_capacity(request.len() + 16);
        masque::capsule::encoder::encode_datagram_context_zero(&request, &mut capsule);
        send_data_all(&mut request_body, Bytes::from(capsule), false).await?;
        let payload = recv_datagram_payload(&mut response_body, self.timeout).await?;
        validate_udp_probe_response(&payload, &request, dns)?;
        Ok(format!(
            "CONNECT-UDP to {} returned a matching {} response",
            target.original,
            if dns { "DNS" } else { "echo" }
        ))
    }

    async fn probe_connect_ip(
        &mut self,
        credentials: &Credentials,
    ) -> Result<String, ProbeFailure> {
        let uri = format!("https://{}/.well-known/masque/ip/", self.authority)
            .parse::<http::Uri>()
            .map_err(|error| {
                ProbeFailure::new("INVALID_ENDPOINT", format!("build CONNECT-IP URI: {error}"))
            })?;
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .header("capsule-protocol", "?1")
            .body(())
            .map_err(|error| ProbeFailure::new("HTTP2_REQUEST_ERROR", error.to_string()))?;
        request
            .extensions_mut()
            .insert(h2::ext::Protocol::from_static("connect-ip"));
        append_auth(&mut request, credentials)?;
        let mut sender = self.ready_sender().await?;
        let (response, _) = sender.send_request(request, false).map_err(|error| {
            ProbeFailure::new("HTTP2_REQUEST_ERROR", format!("send CONNECT-IP: {error}"))
        })?;
        let response = response_with_timeout(response, self.timeout).await?;
        ensure_success_status(response.status().as_u16(), "CONNECT-IP")?;
        let addresses = recv_assigned_addresses(response.into_body(), self.timeout).await?;
        Ok(format!(
            "CONNECT-IP assigned {addresses} address(es); run server-side doctor to verify forwarding/NAT"
        ))
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

fn append_auth(request: &mut Request<()>, credentials: &Credentials) -> Result<(), ProbeFailure> {
    if let Some(value) = credentials.authorization() {
        let value = http::HeaderValue::from_str(&value).map_err(|error| {
            ProbeFailure::new(
                "INVALID_CREDENTIALS",
                format!("build Proxy-Authorization header: {error}"),
            )
        })?;
        request
            .headers_mut()
            .insert(http::header::PROXY_AUTHORIZATION, value);
    }
    Ok(())
}

async fn response_with_timeout(
    response: h2::client::ResponseFuture,
    timeout: Duration,
) -> Result<http::Response<h2::RecvStream>, ProbeFailure> {
    tokio::time::timeout(timeout, response)
        .await
        .map_err(|_| ProbeFailure::new("RESPONSE_TIMEOUT", "CONNECT response timed out"))?
        .map_err(|error| {
            ProbeFailure::new(
                "HTTP2_RESPONSE_ERROR",
                format!("CONNECT response failed: {error}"),
            )
        })
}

async fn send_data_all(
    stream: &mut h2::SendStream<Bytes>,
    mut data: Bytes,
    end_stream: bool,
) -> Result<(), ProbeFailure> {
    while data.has_remaining() {
        stream.reserve_capacity(data.remaining());
        let capacity = poll_fn(|context| stream.poll_capacity(context))
            .await
            .ok_or_else(|| {
                ProbeFailure::new(
                    "HTTP2_STREAM_CLOSED",
                    "request stream closed while waiting for flow-control capacity",
                )
            })?
            .map_err(|error| {
                ProbeFailure::new("HTTP2_STREAM_CLOSED", format!("flow control: {error}"))
            })?;
        let length = capacity.min(data.remaining());
        let chunk = data.split_to(length);
        stream
            .send_data(chunk, end_stream && data.is_empty())
            .map_err(|error| {
                ProbeFailure::new("HTTP2_STREAM_CLOSED", format!("send capsule: {error}"))
            })?;
    }
    Ok(())
}

async fn recv_datagram_payload(
    stream: &mut h2::RecvStream,
    timeout: Duration,
) -> Result<Vec<u8>, ProbeFailure> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut decoder = CapsuleDecoder::new();
    loop {
        let chunk = tokio::time::timeout_at(deadline, stream.data())
            .await
            .map_err(|_| {
                ProbeFailure::new(
                    "UDP_RESPONSE_TIMEOUT",
                    "CONNECT-UDP opened, but no DNS response capsule arrived",
                )
            })?
            .ok_or_else(|| {
                ProbeFailure::new(
                    "HTTP2_STREAM_CLOSED",
                    "CONNECT-UDP response stream ended before a DNS response",
                )
            })?
            .map_err(|error| {
                ProbeFailure::new("HTTP2_STREAM_CLOSED", format!("read capsule: {error}"))
            })?;
        stream
            .flow_control()
            .release_capacity(chunk.len())
            .map_err(|error| ProbeFailure::new("HTTP2_FLOW_CONTROL_ERROR", error.to_string()))?;
        let frames = match decoder.decode(&chunk) {
            Ok(frames) => frames,
            Err(DecodeError::Incomplete) => continue,
            Err(error) => {
                return Err(ProbeFailure::new(
                    "CAPSULE_ERROR",
                    format!("decode DATAGRAM capsule: {error:?}"),
                ));
            }
        };
        for frame in frames {
            let CapsuleFrame::Datagram(value) = frame else {
                continue;
            };
            let (context, length) = masque::varint::decode(&value).map_err(|_| {
                ProbeFailure::new("CAPSULE_ERROR", "DATAGRAM capsule has no Context ID")
            })?;
            if context == 0 {
                return Ok(value[length..].to_vec());
            }
        }
    }
}

async fn recv_assigned_addresses(
    mut stream: h2::RecvStream,
    timeout: Duration,
) -> Result<usize, ProbeFailure> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut decoder = CapsuleDecoder::new();
    loop {
        let chunk = tokio::time::timeout_at(deadline, stream.data())
            .await
            .map_err(|_| {
                ProbeFailure::new(
                    "CAPSULE_TIMEOUT",
                    "timed out waiting for CONNECT-IP ADDRESS_ASSIGN",
                )
            })?
            .ok_or_else(|| {
                ProbeFailure::new(
                    "HTTP2_STREAM_CLOSED",
                    "CONNECT-IP stream ended before ADDRESS_ASSIGN",
                )
            })?
            .map_err(|error| {
                ProbeFailure::new("HTTP2_STREAM_CLOSED", format!("read capsule: {error}"))
            })?;
        stream
            .flow_control()
            .release_capacity(chunk.len())
            .map_err(|error| ProbeFailure::new("HTTP2_FLOW_CONTROL_ERROR", error.to_string()))?;
        let frames = match decoder.decode(&chunk) {
            Ok(frames) => frames,
            Err(DecodeError::Incomplete) => continue,
            Err(error) => {
                return Err(ProbeFailure::new(
                    "CAPSULE_ERROR",
                    format!("decode CONNECT-IP capsule: {error:?}"),
                ));
            }
        };
        for frame in frames {
            if let CapsuleFrame::AddressAssign(addresses) = frame
                && !addresses.is_empty()
            {
                return Ok(addresses.len());
            }
        }
    }
}
