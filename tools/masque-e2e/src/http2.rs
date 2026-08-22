//! HTTP/2 client paths used by the transport-parity benchmark.
//!
//! The production server treats HTTP/2 as a compatibility transport, but its
//! performance still needs to be measured with the same targets, payloads,
//! windows, and result fields as HTTP/3. Keeping this client in the existing
//! E2E binary ensures both transports share all benchmark configuration and
//! direct baselines.

use std::future::poll_fn;
use std::net::SocketAddr;
use std::task::Poll;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use bytes::{Buf as _, Bytes};
use h2::client::SendRequest;
use http::{Method, Request, StatusCode};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

use masque::capsule::decoder::{CapsuleDecoder, DecodeError};
use masque::capsule::{CapsuleFrame, encoder};

use super::{
    HttpDownloadResponse, InFlight, TcpDownloadResult, UdpBenchConfig,
    benchmark_direct_tcp_download, median, print_udp_result, proxy_authorization_value,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const H2_INITIAL_CONNECTION_WINDOW: u32 = 25_165_824;
const H2_INITIAL_STREAM_WINDOW: u32 = 16_777_216;
const H2_SEND_BUFFER: usize = 16_777_216;
const H2_DATA_FRAME_BUDGET: usize = 256 * 1024;
const UDP_CAPSULE_BATCH_BYTES: usize = 64 * 1024;

fn runtime() -> Result<Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("build HTTP/2 benchmark runtime")
}

struct Connection {
    sender: SendRequest<Bytes>,
    driver: JoinHandle<Result<(), h2::Error>>,
}

impl Connection {
    async fn connect(server_addr: &str) -> Result<Self> {
        let peer: SocketAddr = server_addr.parse().context("parse HTTP/2 server address")?;
        let tcp = TcpStream::connect(peer)
            .await
            .with_context(|| format!("connect HTTP/2 TCP socket to {peer}"))?;
        tcp.set_nodelay(true)?;

        let mut connector =
            boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls_client())
                .context("create HTTP/2 TLS connector")?;
        connector.set_verify(boring::ssl::SslVerifyMode::NONE);
        connector.set_alpn_protos(b"\x02h2")?;
        let server_name = std::env::var("MASQUE_SERVER_NAME").unwrap_or_else(|_| "server".into());
        let tls = tokio_boring::connect(connector.build().configure()?, &server_name, tcp)
            .await
            .with_context(|| format!("complete HTTP/2 TLS handshake with {peer}"))?;
        if tls.ssl().selected_alpn_protocol() != Some(b"h2") {
            bail!("server did not negotiate h2 ALPN");
        }

        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(H2_INITIAL_STREAM_WINDOW)
            .initial_connection_window_size(H2_INITIAL_CONNECTION_WINDOW)
            .max_send_buffer_size(H2_SEND_BUFFER)
            .data_frame_budget(H2_DATA_FRAME_BUDGET);
        let (sender, connection) = builder.handshake(tls).await?;
        let driver = tokio::spawn(connection);
        let sender = sender.ready().await?;
        let settings_deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
        while !sender.is_extended_connect_protocol_enabled() {
            if driver.is_finished() {
                bail!("HTTP/2 connection ended before server SETTINGS arrived");
            }
            if tokio::time::Instant::now() >= settings_deadline {
                bail!("server did not advertise HTTP/2 Extended CONNECT");
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Ok(Self { sender, driver })
    }

    async fn ready_sender(&self) -> Result<SendRequest<Bytes>> {
        self.sender.clone().ready().await.map_err(Into::into)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

fn add_auth(request: &mut Request<()>) -> Result<()> {
    if let Some(value) = proxy_authorization_value()? {
        request.headers_mut().insert(
            http::header::PROXY_AUTHORIZATION,
            value.parse().context("build Proxy-Authorization header")?,
        );
    }
    Ok(())
}

fn tcp_request(target: &str, authenticated: bool) -> Result<Request<()>> {
    let uri = http::Uri::builder()
        .authority(target)
        .build()
        .context("build HTTP/2 CONNECT authority")?;
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .body(())?;
    if authenticated {
        add_auth(&mut request)?;
    }
    Ok(request)
}

fn udp_request(server_addr: &str, target: SocketAddr, authenticated: bool) -> Result<Request<()>> {
    let uri = format!(
        "https://{server_addr}/.well-known/masque/udp/{}/{}/",
        target.ip(),
        target.port()
    );
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .header("capsule-protocol", "?1")
        .body(())?;
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("connect-udp"));
    if authenticated {
        add_auth(&mut request)?;
    }
    Ok(request)
}

async fn response_with_timeout(
    response: h2::client::ResponseFuture,
) -> Result<http::Response<h2::RecvStream>> {
    tokio::time::timeout(CONNECT_TIMEOUT, response)
        .await
        .context("HTTP/2 CONNECT response timeout")?
        .context("HTTP/2 CONNECT response failed")
}

async fn send_data_all(
    send: &mut h2::SendStream<Bytes>,
    mut data: Bytes,
    end_stream: bool,
) -> Result<()> {
    if data.is_empty() {
        send.send_data(data, end_stream)?;
        return Ok(());
    }

    while data.has_remaining() {
        send.reserve_capacity(data.remaining());
        let capacity = poll_fn(|cx| send.poll_capacity(cx))
            .await
            .context("HTTP/2 request stream closed while waiting for flow-control capacity")??;
        let take = capacity.min(data.remaining());
        let chunk = data.split_to(take);
        let finished = end_stream && data.is_empty();
        send.send_data(chunk, finished)?;
    }
    Ok(())
}

pub(super) fn wait_for_server(server_addr: &str) -> Result<()> {
    runtime()?.block_on(async {
        let connection = Connection::connect(server_addr).await?;
        let sender = connection.ready_sender().await?;
        if !sender.is_extended_connect_protocol_enabled() {
            bail!("server did not advertise HTTP/2 Extended CONNECT");
        }
        Ok(())
    })
}

pub(super) fn test_auth_required(server_addr: &str, echo_addr: &str) -> Result<()> {
    runtime()?.block_on(async {
        let connection = Connection::connect(server_addr).await?;
        let mut sender = connection.ready_sender().await?;
        let (response, _) = sender.send_request(
            udp_request(
                server_addr,
                echo_addr.parse().context("parse UDP echo address")?,
                false,
            )?,
            false,
        )?;
        let response = response_with_timeout(response).await?;
        if response.status() != StatusCode::PROXY_AUTHENTICATION_REQUIRED {
            bail!(
                "expected HTTP/2 CONNECT-UDP status 407, got {}",
                response.status()
            );
        }
        if response.headers().get("proxy-authenticate")
            != Some(&http::HeaderValue::from_static(
                "Basic realm=\"masque\", charset=\"UTF-8\"",
            ))
        {
            bail!("HTTP/2 407 response has no expected Proxy-Authenticate challenge");
        }
        Ok(())
    })
}

pub(super) fn test_tcp(server_addr: &str, echo_addr: &str) -> Result<()> {
    runtime()?.block_on(async {
        let connection = Connection::connect(server_addr).await?;
        let mut sender = connection.ready_sender().await?;
        let (response, mut request_body) =
            sender.send_request(tcp_request(echo_addr, true)?, false)?;
        let response = response_with_timeout(response).await?;
        if response.status() != StatusCode::OK {
            bail!(
                "expected HTTP/2 CONNECT status 200, got {}",
                response.status()
            );
        }

        let payload = Bytes::from_static(b"standard HTTP/2 CONNECT echo test");
        send_data_all(&mut request_body, payload.clone(), true).await?;
        let mut response_body = response.into_body();
        let mut echoed = Vec::with_capacity(payload.len());
        while echoed.len() < payload.len() {
            let chunk = tokio::time::timeout(CONNECT_TIMEOUT, response_body.data())
                .await
                .context("HTTP/2 CONNECT echo timeout")?
                .context("HTTP/2 CONNECT response ended early")??;
            response_body.flow_control().release_capacity(chunk.len())?;
            echoed.extend_from_slice(&chunk);
        }
        if echoed != payload {
            bail!("HTTP/2 CONNECT echo payload mismatch");
        }
        Ok(())
    })
}

struct UdpTunnel {
    _connection: Connection,
    request_body: h2::SendStream<Bytes>,
    response_body: h2::RecvStream,
    decoder: CapsuleDecoder,
}

impl UdpTunnel {
    async fn connect(server_addr: &str, echo_addr: &str) -> Result<Self> {
        let connection = Connection::connect(server_addr).await?;
        let mut sender = connection.ready_sender().await?;
        if !sender.is_extended_connect_protocol_enabled() {
            bail!("server did not advertise HTTP/2 Extended CONNECT");
        }
        let target = echo_addr.parse().context("parse UDP echo address")?;
        let (response, request_body) =
            sender.send_request(udp_request(server_addr, target, true)?, false)?;
        let response = response_with_timeout(response).await?;
        if response.status() != StatusCode::OK {
            bail!(
                "expected HTTP/2 CONNECT-UDP status 200, got {}",
                response.status()
            );
        }
        if response.headers().get("capsule-protocol") != Some(&http::HeaderValue::from_static("?1"))
        {
            bail!("HTTP/2 CONNECT-UDP response omitted Capsule-Protocol");
        }
        Ok(Self {
            _connection: connection,
            request_body,
            response_body: response.into_body(),
            decoder: CapsuleDecoder::new(),
        })
    }

    async fn send_payload(&mut self, payload: &[u8]) -> Result<()> {
        let mut capsule = Vec::with_capacity(payload.len() + 16);
        encoder::encode_datagram_context_zero(payload, &mut capsule);
        send_data_all(&mut self.request_body, Bytes::from(capsule), false).await
    }

    fn decode_chunk(&mut self, chunk: &Bytes, payloads: &mut Vec<Vec<u8>>) -> Result<()> {
        let frames = match self.decoder.decode(chunk) {
            Ok(frames) => frames,
            Err(DecodeError::Incomplete) => Vec::new(),
            Err(error) => bail!("decode HTTP/2 DATAGRAM capsule: {error:?}"),
        };
        for frame in frames {
            let CapsuleFrame::Datagram(value) = frame else {
                continue;
            };
            let (context_id, context_len) = masque::varint::decode(&value)
                .map_err(|_| anyhow::anyhow!("HTTP/2 DATAGRAM capsule has no Context ID"))?;
            if context_id == 0 {
                payloads.push(value[context_len..].to_vec());
            }
        }
        Ok(())
    }

    async fn recv_payload(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let chunk = tokio::time::timeout_at(deadline, self.response_body.data())
                .await
                .context("HTTP/2 DATAGRAM capsule timeout")?
                .context("HTTP/2 CONNECT-UDP response ended")??;
            self.response_body
                .flow_control()
                .release_capacity(chunk.len())?;
            let mut payloads = Vec::new();
            self.decode_chunk(&chunk, &mut payloads)?;
            if let Some(payload) = payloads.into_iter().next() {
                return Ok(payload);
            }
        }
    }

    async fn poll_data_now(&mut self) -> Poll<Option<Result<Bytes, h2::Error>>> {
        poll_fn(|cx| Poll::Ready(self.response_body.poll_data(cx))).await
    }

    fn consume_chunk(
        &mut self,
        chunk: Bytes,
        in_flight: &mut InFlight,
        received: &mut u64,
    ) -> Result<()> {
        self.response_body
            .flow_control()
            .release_capacity(chunk.len())?;
        let mut payloads = Vec::new();
        self.decode_chunk(&chunk, &mut payloads)?;
        for payload in payloads {
            if payload.len() < 8 {
                continue;
            }
            let sequence = u64::from_be_bytes(payload[..8].try_into().unwrap());
            if in_flight.remove(&sequence) {
                *received += 1;
            }
        }
        Ok(())
    }

    async fn run_echo_throughput(
        &mut self,
        payload_size: usize,
        duration: Duration,
        window: usize,
        expiry: Duration,
    ) -> Result<(u64, u64, u64)> {
        if payload_size < 8 {
            bail!("benchmark payload must be at least 8 bytes");
        }

        let started = Instant::now();
        let deadline = started + duration;
        let drain_deadline = deadline + expiry;
        let mut payload = vec![0x5a; payload_size];
        let mut in_flight = InFlight::with_capacity(window);
        let mut next_sequence = 0_u64;
        let mut sent = 0_u64;
        let mut received = 0_u64;
        let mut expired = 0_u64;

        while Instant::now() < drain_deadline {
            let now = Instant::now();
            expired += in_flight.expire(now, expiry);
            let mut made_progress = false;

            if now < deadline && in_flight.len() < window {
                let available = window - in_flight.len();
                let mut capsule_batch = Vec::with_capacity(
                    UDP_CAPSULE_BATCH_BYTES.min(available.saturating_mul(payload_size + 16)),
                );
                let mut sequences = Vec::with_capacity(available);
                while sequences.len() < available {
                    payload[..8].copy_from_slice(&next_sequence.to_be_bytes());
                    let before = capsule_batch.len();
                    encoder::encode_datagram_context_zero(&payload, &mut capsule_batch);
                    if before != 0 && capsule_batch.len() > UDP_CAPSULE_BATCH_BYTES {
                        capsule_batch.truncate(before);
                        break;
                    }
                    sequences.push(next_sequence);
                    next_sequence += 1;
                }
                send_data_all(&mut self.request_body, Bytes::from(capsule_batch), false).await?;
                let sent_at = Instant::now();
                for sequence in sequences {
                    in_flight.insert(sequence, sent_at);
                    sent += 1;
                }
                made_progress = true;
            }

            loop {
                match self.poll_data_now().await {
                    Poll::Ready(Some(Ok(chunk))) => {
                        self.consume_chunk(chunk, &mut in_flight, &mut received)?;
                        made_progress = true;
                    }
                    Poll::Ready(Some(Err(error))) => return Err(error.into()),
                    Poll::Ready(None) => {
                        if in_flight.is_empty() && now >= deadline {
                            break;
                        }
                        bail!("HTTP/2 CONNECT-UDP response ended during benchmark");
                    }
                    Poll::Pending => break,
                }
            }

            if now >= deadline && in_flight.is_empty() {
                break;
            }
            if !made_progress {
                match tokio::time::timeout(Duration::from_millis(1), self.response_body.data())
                    .await
                {
                    Ok(Some(Ok(chunk))) => {
                        self.consume_chunk(chunk, &mut in_flight, &mut received)?;
                    }
                    Ok(Some(Err(error))) => return Err(error.into()),
                    Ok(None) => bail!("HTTP/2 CONNECT-UDP response ended during benchmark"),
                    Err(_) => {}
                }
            }
        }

        expired += in_flight.len() as u64;
        Ok((sent, received, expired))
    }
}

pub(super) fn test_udp(server_addr: &str, echo_addr: &str) -> Result<()> {
    runtime()?.block_on(async {
        let mut tunnel = UdpTunnel::connect(server_addr, echo_addr).await?;
        let payload = b"HTTP/2 CONNECT-UDP echo test";
        tunnel.send_payload(payload).await?;
        let echoed = tunnel.recv_payload(CONNECT_TIMEOUT).await?;
        if echoed != payload {
            bail!("HTTP/2 CONNECT-UDP echo payload mismatch");
        }
        Ok(())
    })
}

pub(super) fn benchmark_udp(
    server_addr: &str,
    echo_addr: &str,
    config: UdpBenchConfig,
) -> Result<()> {
    runtime()?.block_on(async {
        println!("MASQUE CONNECT-UDP (transport=http2):");
        let setup_started = Instant::now();
        let mut tunnel = UdpTunnel::connect(server_addr, echo_addr).await?;
        let setup = setup_started.elapsed();

        let latency_payload = vec![0x3c; 64];
        let mut latencies = Vec::with_capacity(config.latency_samples);
        for _ in 0..config.latency_samples {
            let started = Instant::now();
            tunnel.send_payload(&latency_payload).await?;
            let response = tunnel.recv_payload(Duration::from_secs(2)).await?;
            if response != latency_payload {
                bail!("HTTP/2 latency probe payload mismatch");
            }
            latencies.push(started.elapsed().as_secs_f64() * 1e6);
        }
        latencies.sort_by(f64::total_cmp);
        let percentile = |p: f64| super::percentile_nearest_rank(&latencies, p).unwrap();
        println!(
            "  setup {:.3} ms; RTT 64B ({} samples): p50 {:.1} us, p95 {:.1} us, p99 {:.1} us",
            setup.as_secs_f64() * 1e3,
            config.latency_samples,
            percentile(0.50),
            percentile(0.95),
            percentile(0.99),
        );

        drop(tunnel);
        for payload_size in [64, 1_200] {
            let mut tunnel = UdpTunnel::connect(server_addr, echo_addr).await?;
            let (sent, received, expired) = tunnel
                .run_echo_throughput(payload_size, config.duration, config.window, config.expiry)
                .await?;
            print_udp_result(
                "http2",
                "masque",
                payload_size,
                config.duration,
                sent,
                received,
                expired,
            );
        }
        Ok(())
    })
}

async fn run_tcp_download(
    connection: &Connection,
    target: &str,
    path: &str,
    configured_body_bytes: Option<u64>,
    timeout: Duration,
) -> Result<(TcpDownloadResult, Instant, Instant)> {
    let mut sender = connection.ready_sender().await?;
    let (response, mut request_body) = sender.send_request(tcp_request(target, true)?, false)?;
    let response = response_with_timeout(response).await?;
    if response.status() != StatusCode::OK {
        bail!(
            "expected HTTP/2 CONNECT status 200, got {}",
            response.status()
        );
    }
    let connected_at = Instant::now();

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {target}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    );
    let request_started = Instant::now();
    send_data_all(&mut request_body, Bytes::from(request), true).await?;
    let mut response_body = response.into_body();
    let deadline = tokio::time::Instant::now() + timeout;
    let mut parsed = HttpDownloadResponse::new();
    let mut stream_finished = false;
    loop {
        let chunk = tokio::time::timeout_at(deadline, response_body.data())
            .await
            .with_context(|| {
                format!(
                    "HTTP/2 CONNECT download timed out after {} body bytes",
                    parsed.body_bytes
                )
            })?;
        match chunk {
            Some(Ok(chunk)) => {
                response_body.flow_control().release_capacity(chunk.len())?;
                parsed.ingest(&chunk, Instant::now())?;
            }
            Some(Err(error)) => return Err(error.into()),
            None => {
                stream_finished = true;
                break;
            }
        }

        if let Some(expected) = parsed.expected_body_bytes(configured_body_bytes) {
            if parsed.body_bytes > expected {
                bail!(
                    "HTTP/2 CONNECT received {} HTTP body bytes, expected {expected}",
                    parsed.body_bytes
                );
            }
            if parsed.body_bytes == expected {
                break;
            }
        }
    }

    if !parsed.header_complete || parsed.status != Some(200) {
        bail!("HTTP/2 CONNECT origin returned an incomplete or unsuccessful response");
    }
    if let Some(expected) = parsed.expected_body_bytes(configured_body_bytes)
        && parsed.body_bytes != expected
    {
        bail!(
            "HTTP/2 CONNECT download finished after {} of {expected} body bytes",
            parsed.body_bytes
        );
    }
    Ok((
        TcpDownloadResult {
            response: parsed,
            finished_at: Instant::now(),
            stream_finished,
        },
        connected_at,
        request_started,
    ))
}

pub(super) fn benchmark_tcp_download(server_addr: &str) -> Result<()> {
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
    if configured_body_bytes == Some(0) || timeout_secs == 0 || repeats == 0 || repeats > 16 {
        bail!("download size and timeout must be non-zero; repeats must be between 1 and 16");
    }

    let runtime = runtime()?;
    let setup_started = Instant::now();
    let connection = runtime.block_on(Connection::connect(server_addr))?;
    let transport_setup = setup_started.elapsed();
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
            let mbps = |elapsed: Duration| {
                body_bytes as f64 * 8.0 / elapsed.as_secs_f64().max(f64::EPSILON) / 1_000_000.0
            };
            let transfer_mbps = mbps(transfer_elapsed);
            direct_transfer_rates.push(transfer_mbps);
            println!(
                "DIRECT_TCP_DOWNLOAD_RESULT transport=http2 sample={sample} body_bytes={body_bytes} connect_ms={:.3} ttfb_ms={:.3} request_ms={:.3} transfer_ms={:.3} sample_ms={:.3} request_mbps={:.3} transfer_mbps={transfer_mbps:.3} sample_mbps={:.3} stream_finished={}",
                connect_elapsed.as_secs_f64() * 1e3,
                ttfb.as_secs_f64() * 1e3,
                request_elapsed.as_secs_f64() * 1e3,
                transfer_elapsed.as_secs_f64() * 1e3,
                sample_elapsed.as_secs_f64() * 1e3,
                mbps(request_elapsed),
                mbps(sample_elapsed),
                direct.stream_finished,
            );
        }

        let sample_started = Instant::now();
        let (result, connected_at, request_started) = runtime.block_on(run_tcp_download(
            &connection,
            &target,
            &path,
            configured_body_bytes,
            Duration::from_secs(timeout_secs),
        ))?;
        let first_body_at = result
            .response
            .first_body_at
            .context("HTTP/2 origin response contained no body")?;
        let body_bytes = result.response.body_bytes;
        let connect_elapsed = connected_at.saturating_duration_since(sample_started);
        let ttfb = first_body_at.saturating_duration_since(request_started);
        let request_elapsed = result
            .finished_at
            .saturating_duration_since(request_started);
        let transfer_elapsed = result.finished_at.saturating_duration_since(first_body_at);
        let sample_elapsed = result.finished_at.saturating_duration_since(sample_started);
        let mbps = |elapsed: Duration| {
            body_bytes as f64 * 8.0 / elapsed.as_secs_f64().max(f64::EPSILON) / 1_000_000.0
        };
        let transfer_mbps = mbps(transfer_elapsed);
        masque_transfer_rates.push(transfer_mbps);
        println!(
            "TCP_DOWNLOAD_RESULT transport=http2 sample={sample} body_bytes={body_bytes} transport_setup_ms={:.3} connect_ms={:.3} ttfb_ms={:.3} request_ms={:.3} transfer_ms={:.3} sample_ms={:.3} request_mbps={:.3} transfer_mbps={transfer_mbps:.3} sample_mbps={:.3} stream_finished={}",
            transport_setup.as_secs_f64() * 1e3,
            connect_elapsed.as_secs_f64() * 1e3,
            ttfb.as_secs_f64() * 1e3,
            request_elapsed.as_secs_f64() * 1e3,
            transfer_elapsed.as_secs_f64() * 1e3,
            sample_elapsed.as_secs_f64() * 1e3,
            mbps(request_elapsed),
            mbps(sample_elapsed),
            result.stream_finished,
        );
    }

    let masque_median = median(&mut masque_transfer_rates).expect("at least one sample");
    if let Some(direct_median) = median(&mut direct_transfer_rates) {
        println!(
            "TCP_DOWNLOAD_SUMMARY transport=http2 samples={repeats} direct_transfer_mbps_median={direct_median:.3} masque_transfer_mbps_median={masque_median:.3} direct_ratio_pct={:.2}",
            masque_median * 100.0 / direct_median,
        );
    } else {
        println!(
            "TCP_DOWNLOAD_SUMMARY transport=http2 samples={repeats} masque_transfer_mbps_median={masque_median:.3}"
        );
    }
    Ok(())
}
