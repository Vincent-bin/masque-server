//! MASQUE over HTTP/2.
//!
//! HTTP/2 is a compatibility transport for networks where UDP/QUIC is
//! unavailable. Standard CONNECT streams carry bytes directly in DATA frames;
//! CONNECT-UDP and CONNECT-IP streams carry DATAGRAM capsules. Both RFC 9484
//! Extended CONNECT and Cloudflare's deployed H2 CONNECT-IP dialect are
//! accepted. HTTP/3 remains the preferred transport because HTTP/2 makes
//! datagrams reliable and ordered.

use std::future::{pending, poll_fn};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use boring::ssl::{AlpnError, SslAcceptor, SslFiletype, SslMethod, select_next_proto};
use bytes::{Buf as _, Bytes};
use h2::Reason;
use h2::SendStream;
use h2::server::SendResponse;
use http::header::{HeaderName, HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION};
use http::{Request, Response, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use super::request::{ConnectRequest, classify_connect_request};
use super::{
    Http2TunRoute, MAX_EPHEMERAL_BIND_ATTEMPTS, MAX_PENDING_AUTH_PER_CONNECTION, Shared,
    allocate_pool_addresses, claim_static_addresses, encode_ip_setup_capsules,
    listen_address_conflict,
};
use crate::auth::{AuthPrecheck, BasicAuthenticator};
use crate::capsule::decoder::CapsuleDecoder;
use crate::capsule::{CapsuleFrame, encoder};
use crate::client_identity::{ClientIdentity, SharedRoster, configure_client_cert_verification};
use crate::config::{ResolvedListener, ServerConfig};
use crate::ip_packet;
use crate::metrics::{Metrics, ShardMetrics};
use crate::policy::TargetPolicy;
use crate::routing::TunnelOwner;
use crate::tun::TunSendBatch;
use crate::tunnel::tcp::{TcpSetupFailure, resolve_and_connect};
use crate::uri::{self, TcpTarget, UdpTarget};
use crate::varint;

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
const TCP_READ_CHUNK_SIZE: usize = 64 * 1024;
const MAX_UDP_PAYLOAD: usize = 65_527;
const MAX_HTTP2_TUN_QUEUE_PACKETS: usize = 256;
const IP_RESPONSE_BATCH_SIZE: usize = 64 * 1024;
const MAX_IP_CONTROL_CAPSULE_SIZE: usize = 64 * 1024;
const CAPSULE_PROTOCOL: HeaderName = HeaderName::from_static("capsule-protocol");
const CF_CONNECT_PROTO: HeaderName = HeaderName::from_static("cf-connect-proto");

/// A bound TCP/TLS listener and the immutable state shared by its connections.
pub(super) struct Http2Listener {
    listener: TcpListener,
    listen_addr: SocketAddr,
    acceptor: Arc<SslAcceptor>,
    config: Arc<ServerConfig>,
    shared: Arc<Shared>,
    auth: Option<Arc<BasicAuthenticator>>,
    client_certs: Option<Arc<SharedRoster>>,
    tcp_policy: TargetPolicy,
    udp_policy: TargetPolicy,
    metrics: Arc<ShardMetrics>,
    connection_slots: Arc<Semaphore>,
}

impl Http2Listener {
    /// Bind one TCP listener, retrying a colliding ephemeral assignment before
    /// the rest of the configured listeners are opened.
    pub(super) async fn bind(
        config: Arc<ServerConfig>,
        shared: Arc<Shared>,
        listener: ResolvedListener,
        process_metrics: Arc<Metrics>,
        auth_label: &'static str,
        unavailable: &[SocketAddr],
    ) -> anyhow::Result<Self> {
        let acceptor = Arc::new(build_acceptor(
            &config,
            listener
                .auth
                .client_cert_enabled()
                .then(|| Arc::clone(&shared.clients)),
        )?);

        let (socket, listen_addr) = bind_tcp_listener(listener.listen_addr, unavailable).await?;
        let metrics = process_metrics
            .register_listener(listen_addr, "http2", auth_label, 1, false, false)
            .into_iter()
            .next()
            .expect("one metrics owner was requested for the HTTP/2 listener");
        let auth = listener
            .auth
            .basic_enabled()
            .then(|| {
                BasicAuthenticator::new(&listener.auth.username, &listener.auth.password_hash)
                    .map(Arc::new)
            })
            .transpose()?;
        let client_certs = listener
            .auth
            .client_cert_enabled()
            .then(|| Arc::clone(&shared.clients));

        info!(addr = %listen_addr, transport = "http2", "listening");
        Ok(Self {
            listener: socket,
            listen_addr,
            acceptor,
            tcp_policy: TargetPolicy::new(
                &config.tcp_proxy.allow_targets,
                &config.tcp_proxy.deny_targets,
            ),
            udp_policy: TargetPolicy::new(
                &config.udp_proxy.allow_targets,
                &config.udp_proxy.deny_targets,
            ),
            connection_slots: Arc::new(Semaphore::new(config.server.max_connections)),
            config,
            shared,
            auth,
            client_certs,
            metrics,
        })
    }

    pub(super) fn local_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Accept TCP connections until shutdown, then give established H2
    /// connections a bounded interval to finish their streams.
    pub(super) async fn run(self, mut shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
        let mut connections = JoinSet::new();
        let connection_shutdown = shutdown.clone();
        let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown.wait_for(|requested| *requested) => break,
                _ = heartbeat.tick() => {
                    self.metrics.record_heartbeat(
                        self.shared.metrics.elapsed_millis(),
                        Duration::ZERO,
                    );
                }
                joined = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = joined {
                        warn!(%error, "HTTP/2 connection task panicked");
                    }
                }
                accepted = self.listener.accept() => {
                    let (stream, peer) = accepted
                        .with_context(|| format!("HTTP/2 listener {} accept failed", self.listen_addr))?;
                    let connection_slot = match Arc::clone(&self.connection_slots).try_acquire_owned() {
                        Ok(slot) => slot,
                        Err(_) => {
                            self.metrics.connection_rejected_limit();
                            warn!(%peer, "HTTP/2 connection limit reached");
                            continue;
                        }
                    };

                    let context = ConnectionContext {
                        acceptor: Arc::clone(&self.acceptor),
                        config: Arc::clone(&self.config),
                        shared: Arc::clone(&self.shared),
                        auth: self.auth.as_ref().map(Arc::clone),
                        client_certs: self.client_certs.as_ref().map(Arc::clone),
                        tcp_policy: self.tcp_policy.clone(),
                        udp_policy: self.udp_policy.clone(),
                        metrics: Arc::clone(&self.metrics),
                    };
                    connections.spawn(serve_connection(
                        stream,
                        peer,
                        context,
                        connection_shutdown.clone(),
                        connection_slot,
                    ));
                }
            }
        }

        info!(addr = %self.listen_addr, connections = connections.len(), "HTTP/2 listener draining");
        let drain = async {
            while let Some(joined) = connections.join_next().await {
                if let Err(error) = joined {
                    warn!(%error, "HTTP/2 connection task panicked during drain");
                }
            }
        };
        if tokio::time::timeout(DRAIN_TIMEOUT, drain).await.is_err() {
            connections.abort_all();
            self.shared.metrics.record_forced_shutdown();
            while connections.join_next().await.is_some() {}
        }
        Ok(())
    }
}

#[derive(Clone)]
struct ConnectionContext {
    acceptor: Arc<SslAcceptor>,
    config: Arc<ServerConfig>,
    shared: Arc<Shared>,
    auth: Option<Arc<BasicAuthenticator>>,
    client_certs: Option<Arc<SharedRoster>>,
    tcp_policy: TargetPolicy,
    udp_policy: TargetPolicy,
    metrics: Arc<ShardMetrics>,
}

/// Validate and build the TLS context used by an H2 listener.
pub(super) fn build_acceptor(
    config: &ServerConfig,
    client_certs: Option<Arc<SharedRoster>>,
) -> anyhow::Result<SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
        .context("failed to create HTTP/2 TLS context")?;
    builder
        .set_certificate_chain_file(&config.tls.cert_path)
        .with_context(|| {
            format!(
                "failed to load tls.cert_path {}",
                config.tls.cert_path.display()
            )
        })?;
    builder
        .set_private_key_file(&config.tls.key_path, SslFiletype::PEM)
        .with_context(|| {
            format!(
                "failed to load tls.key_path {}",
                config.tls.key_path.display()
            )
        })?;
    builder.check_private_key().with_context(|| {
        format!(
            "tls.key_path {} does not match tls.cert_path {}",
            config.tls.key_path.display(),
            config.tls.cert_path.display()
        )
    })?;
    builder.set_alpn_select_callback(|_, client| {
        select_next_proto(b"\x02h2", client).ok_or(AlpnError::NOACK)
    });
    if let Some(roster) = client_certs {
        configure_client_cert_verification(&mut builder, roster);
    }
    Ok(builder.build())
}

async fn bind_tcp_listener(
    requested: SocketAddr,
    unavailable: &[SocketAddr],
) -> anyhow::Result<(TcpListener, SocketAddr)> {
    for attempt in 1..=MAX_EPHEMERAL_BIND_ATTEMPTS {
        let listener = TcpListener::bind(requested)
            .await
            .with_context(|| format!("failed to bind HTTP/2 listener {requested}"))?;
        let bound = listener.local_addr()?;
        if requested.port() != 0 {
            return Ok((listener, bound));
        }

        if let Some(existing) = unavailable
            .iter()
            .copied()
            .find(|existing| listen_address_conflict(bound, *existing).is_some())
        {
            if attempt == MAX_EPHEMERAL_BIND_ATTEMPTS {
                anyhow::bail!(
                    "HTTP/2 listener {requested} repeatedly received an ephemeral address that \
                     overlaps listener {existing}"
                );
            }
            debug!(%requested, assigned = %bound, %existing, attempt, "retrying HTTP/2 ephemeral bind");
            continue;
        }
        return Ok((listener, bound));
    }
    unreachable!("bounded ephemeral bind loop returns or reports its last collision")
}

async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    context: ConnectionContext,
    mut shutdown: watch::Receiver<bool>,
    _connection_slot: OwnedSemaphorePermit,
) {
    let _connection_metrics = ConnectionMetricsGuard::new(Arc::clone(&context.metrics));
    let tls = match tokio::time::timeout(
        TLS_HANDSHAKE_TIMEOUT,
        tokio_boring::accept(&context.acceptor, stream),
    )
    .await
    {
        Ok(Ok(tls)) => tls,
        Ok(Err(error)) => {
            debug!(%peer, %error, "HTTP/2 TLS handshake failed");
            return;
        }
        Err(_) => {
            debug!(%peer, "HTTP/2 TLS handshake timed out");
            return;
        }
    };

    if tls.ssl().selected_alpn_protocol() != Some(b"h2") {
        warn!(%peer, "HTTP/2 TLS connection negotiated no h2 ALPN");
        return;
    }

    let (authenticated_identity, mut applied_roster_generation) =
        if let Some(roster) = &context.client_certs {
            let identity = tls
                .ssl()
                .peer_certificate()
                .and_then(|cert| cert.to_der().ok())
                .and_then(|der| identify_current_client(roster, &der));
            let Some((identity, generation)) = identity else {
                context.metrics.record_auth_failure();
                warn!(%peer, "closing HTTP/2 connection with no current client identity");
                return;
            };
            context.metrics.record_auth_success();
            info!(%peer, client = %identity.name, "HTTP/2 client authenticated by certificate");
            (Some(identity), generation)
        } else {
            (None, 0)
        };

    let h2 = &context.config.http2;
    let mut builder = h2::server::Builder::new();
    builder
        .enable_connect_protocol()
        .initial_window_size(h2.initial_stream_window)
        .initial_connection_window_size(h2.initial_connection_window)
        .max_concurrent_streams(h2.max_concurrent_streams)
        .max_header_list_size(h2.max_header_list_size)
        .max_send_buffer_size(h2.max_send_buffer_size)
        .data_frame_budget(h2.data_frame_budget);

    let mut connection = match builder.handshake(tls).await {
        Ok(connection) => connection,
        Err(error) => {
            debug!(%peer, %error, "HTTP/2 handshake failed");
            return;
        }
    };
    info!(%peer, "HTTP/2 connection established");
    let connection_index = context
        .shared
        .next_conn_index
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let tunnel_slots = Arc::new(Semaphore::new(
        context.config.server.max_tunnels_per_connection,
    ));
    let auth_slots = Arc::new(Semaphore::new(MAX_PENDING_AUTH_PER_CONNECTION));
    let mut requests = JoinSet::new();
    let mut draining = false;
    let mut drain_deadline = None;
    let mut roster_sweep = tokio::time::interval_at(
        tokio::time::Instant::now() + HEARTBEAT_INTERVAL,
        HEARTBEAT_INTERVAL,
    );
    roster_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = shutdown.wait_for(|requested| *requested), if !draining => {
                draining = true;
                drain_deadline = Some(tokio::time::Instant::now() + DRAIN_TIMEOUT);
                connection.graceful_shutdown();
            }
            _ = roster_sweep.tick(), if authenticated_identity.is_some() => {
                let roster = context
                    .client_certs
                    .as_ref()
                    .expect("an authenticated identity has a roster");
                let generation = roster.generation();
                if generation != applied_roster_generation {
                    applied_roster_generation = generation;
                    let identity = authenticated_identity
                        .as_deref()
                        .expect("guarded by authenticated_identity.is_some()");
                    if !roster.load().still_authorizes(identity) {
                        info!(%peer, client = %identity.name, "disconnecting HTTP/2 client removed from the roster");
                        connection.abrupt_shutdown(Reason::NO_ERROR);
                        requests.abort_all();
                        break;
                    }
                }
            }
            _ = async {
                match drain_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => pending::<()>().await,
                }
            } => {
                connection.abrupt_shutdown(Reason::NO_ERROR);
                requests.abort_all();
                break;
            }
            joined = requests.join_next(), if !requests.is_empty() => {
                if let Some(Err(error)) = joined {
                    warn!(%peer, %error, "HTTP/2 request task panicked");
                }
            }
            accepted = connection.accept() => {
                match accepted {
                    Some(Ok((request, respond))) if !draining => {
                        requests.spawn(handle_request(
                            request,
                            respond,
                            context.clone(),
                            connection_index,
                            authenticated_identity.as_ref().map(Arc::clone),
                            Arc::clone(&tunnel_slots),
                            Arc::clone(&auth_slots),
                        ));
                    }
                    Some(Ok((_request, mut respond))) => {
                        let _ = send_error(&mut respond, StatusCode::SERVICE_UNAVAILABLE);
                    }
                    Some(Err(error)) => {
                        debug!(%peer, %error, "HTTP/2 connection error");
                        break;
                    }
                    None => break,
                }
            }
        }
    }

    requests.abort_all();
    while requests.join_next().await.is_some() {}
    debug!(%peer, "HTTP/2 connection closed");
}

/// Resolve a certificate against one stable roster generation.
///
/// A SIGHUP can replace the roster between any two reads. Retrying when its
/// generation changes prevents a connection from retaining an identity from
/// the old roster while recording the new generation as already enforced.
fn identify_current_client(
    roster: &SharedRoster,
    cert_der: &[u8],
) -> Option<(Arc<ClientIdentity>, u64)> {
    loop {
        let before = roster.generation();
        let identity = roster.load().identify(cert_der);
        let after = roster.generation();
        if before == after {
            return identity.ok().map(|identity| (identity, after));
        }
    }
}

enum RequestKind {
    Tcp(TcpTarget),
    Udp(UdpTarget),
    Ip(IpCapsuleMode),
}

/// CONNECT-IP has two HTTP/2 wire shapes in active use.
///
/// RFC 9484 uses Extended CONNECT and keeps Context ID zero in each DATAGRAM
/// capsule. Cloudflare's TCP fallback predates that shape: it uses a regular
/// CONNECT plus `cf-connect-proto`, and removes the zero byte from capsule
/// values. usque intentionally mirrors the latter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IpCapsuleMode {
    Standard,
    Cloudflare,
}

impl IpCapsuleMode {
    fn decode_packet(self, payload: &[u8]) -> anyhow::Result<Option<&[u8]>> {
        match self {
            Self::Cloudflare => Ok(Some(payload)),
            Self::Standard => {
                let (context_id, context_len) = varint::decode(payload)
                    .map_err(|_| anyhow::anyhow!("DATAGRAM capsule has no Context ID"))?;
                if context_id == 0 {
                    Ok(Some(&payload[context_len..]))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn encode_packet(self, packet: &[u8], output: &mut Vec<u8>) {
        match self {
            Self::Standard => encoder::encode_datagram_context_zero(packet, output),
            Self::Cloudflare => encoder::encode_datagram(packet, output),
        }
    }
}

async fn handle_request(
    request: Request<h2::RecvStream>,
    mut respond: SendResponse<Bytes>,
    context: ConnectionContext,
    connection_index: u64,
    authenticated_identity: Option<Arc<ClientIdentity>>,
    tunnel_slots: Arc<Semaphore>,
    auth_slots: Arc<Semaphore>,
) {
    let stream_id = respond.stream_id().as_u32();
    let protocol = request
        .extensions()
        .get::<h2::ext::Protocol>()
        .map(|protocol| protocol.as_str().to_owned());
    let mut cloudflare_protocols = request.headers().get_all(&CF_CONNECT_PROTO).iter();
    let cloudflare_protocol = cloudflare_protocols.next().map(HeaderValue::as_bytes);
    let duplicate_cloudflare_protocol = cloudflare_protocols.next().is_some();
    let cloudflare_capsules = protocol.is_none() && cloudflare_protocol == Some(b"cf-connect-ip");
    let effective_protocol = if cloudflare_capsules {
        "cf-connect-ip"
    } else {
        protocol.as_deref().unwrap_or("")
    };

    let authority = request
        .uri()
        .authority()
        .map_or("", |authority| authority.as_str());
    let Some(connect) = classify_connect_request(
        request.method().as_str().as_bytes(),
        effective_protocol.as_bytes(),
        authority.as_bytes(),
        request.uri().path().as_bytes(),
        &context.config,
    ) else {
        let _ = send_error(&mut respond, StatusCode::NOT_FOUND);
        return;
    };

    if let Some(auth) = &context.auth {
        let mut values = request.headers().get_all(PROXY_AUTHORIZATION).iter();
        let first = values.next().map(HeaderValue::as_bytes);
        if values.next().is_some() {
            let _ = send_proxy_auth_required(&mut respond);
            return;
        }
        let password = match auth.precheck(first) {
            AuthPrecheck::Rejected => {
                let _ = send_proxy_auth_required(&mut respond);
                return;
            }
            AuthPrecheck::NeedsVerify(password) => password,
        };
        let auth_slot = match auth_slots.try_acquire_owned() {
            Ok(slot) => slot,
            Err(_) => {
                context.metrics.record_auth_overloaded();
                let _ = send_error(&mut respond, StatusCode::SERVICE_UNAVAILABLE);
                return;
            }
        };
        let verification = verify_password(
            Arc::clone(auth),
            password,
            Arc::clone(&context.shared.auth_queue_slots),
            Arc::clone(&context.shared.auth_permits),
            Arc::clone(&context.metrics),
            auth_slot,
        );
        tokio::pin!(verification);
        let authorized = tokio::select! {
            result = &mut verification => result,
            _ = poll_fn(|cx| respond.poll_reset(cx)) => return,
        };
        match authorized {
            AuthResult::Authorized => {}
            AuthResult::Rejected => {
                let _ = send_proxy_auth_required(&mut respond);
                return;
            }
            AuthResult::Overloaded => {
                let _ = send_error(&mut respond, StatusCode::SERVICE_UNAVAILABLE);
                return;
            }
        }
    }

    // Match HTTP/3's ordering: a recognized proxy request authenticates before
    // target parsing or transport-specific validation. This keeps malformed
    // requests from using status differences to bypass the 407 boundary.
    let kind = match prepare_request(
        &request,
        connect,
        &context.config,
        cloudflare_capsules,
        duplicate_cloudflare_protocol,
    ) {
        Ok(kind) => kind,
        Err(status) => {
            let _ = send_error(&mut respond, status);
            return;
        }
    };

    let tunnel_slot = match tunnel_slots.try_acquire_owned() {
        Ok(slot) => slot,
        Err(_) => {
            let _ = send_error(&mut respond, StatusCode::SERVICE_UNAVAILABLE);
            return;
        }
    };
    let (_parts, body) = request.into_parts();

    let result = match kind {
        RequestKind::Tcp(target) => {
            serve_tcp_tunnel(stream_id, target, body, respond, context, tunnel_slot).await
        }
        RequestKind::Udp(target) => {
            serve_udp_tunnel(stream_id, target, body, respond, context, tunnel_slot).await
        }
        RequestKind::Ip(capsule_mode) => {
            serve_ip_tunnel(
                connection_index,
                stream_id,
                body,
                respond,
                context,
                authenticated_identity,
                capsule_mode,
                tunnel_slot,
            )
            .await
        }
    };
    if let Err(error) = result {
        debug!(stream_id, %error, "HTTP/2 tunnel closed with an error");
    }
}

fn prepare_request(
    request: &Request<h2::RecvStream>,
    connect: ConnectRequest,
    config: &ServerConfig,
    cloudflare_capsules: bool,
    duplicate_cloudflare_protocol: bool,
) -> Result<RequestKind, StatusCode> {
    match connect {
        ConnectRequest::Tcp { authority } => uri::parse_connect_authority(&authority)
            .map(RequestKind::Tcp)
            .map_err(|_| StatusCode::BAD_REQUEST),
        ConnectRequest::Udp { path } => {
            if !uses_capsule_protocol(request) {
                return Err(StatusCode::BAD_REQUEST);
            }
            uri::parse_udp_path(&path, &config.udp_proxy.uri_template)
                .map(RequestKind::Udp)
                .map_err(|_| StatusCode::BAD_REQUEST)
        }
        ConnectRequest::Ip => {
            if cloudflare_capsules {
                if duplicate_cloudflare_protocol {
                    return Err(StatusCode::BAD_REQUEST);
                }
                return Ok(RequestKind::Ip(IpCapsuleMode::Cloudflare));
            }
            if !uses_capsule_protocol(request) {
                return Err(StatusCode::BAD_REQUEST);
            }
            Ok(RequestKind::Ip(IpCapsuleMode::Standard))
        }
    }
}

/// HTTP/2 Extended CONNECT has no native datagram frame, so both datagram
/// protocols require the Capsule Protocol on a fully formed absolute URI.
fn uses_capsule_protocol(request: &Request<h2::RecvStream>) -> bool {
    request.uri().scheme().is_some()
        && request.uri().authority().is_some()
        && !request.uri().path().is_empty()
        && request.headers().get_all(&CAPSULE_PROTOCOL).iter().count() == 1
        && request.headers().get(&CAPSULE_PROTOCOL) == Some(&HeaderValue::from_static("?1"))
}

enum AuthResult {
    Authorized,
    Rejected,
    Overloaded,
}

async fn verify_password(
    auth: Arc<BasicAuthenticator>,
    password: Zeroizing<Vec<u8>>,
    queue_slots: Arc<Semaphore>,
    permits: Arc<Semaphore>,
    metrics: Arc<ShardMetrics>,
    _connection_slot: OwnedSemaphorePermit,
) -> AuthResult {
    let queue_slot = match queue_slots.try_acquire_owned() {
        Ok(slot) => slot,
        Err(_) => {
            metrics.record_auth_overloaded();
            return AuthResult::Overloaded;
        }
    };
    let pending = metrics.auth_pending_guard();
    let permit = match permits.acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => return AuthResult::Rejected,
    };
    drop(pending);
    let running = metrics.auth_running_guard();
    let completion_metrics = Arc::clone(&metrics);
    match tokio::task::spawn_blocking(move || {
        let _queue_slot = queue_slot;
        let _permit = permit;
        let _running = running;
        let authorized = auth.verify(&password);
        if authorized {
            completion_metrics.record_auth_success();
        } else {
            completion_metrics.record_auth_failure();
        }
        authorized
    })
    .await
    {
        Ok(true) => AuthResult::Authorized,
        Ok(false) | Err(_) => AuthResult::Rejected,
    }
}

async fn serve_tcp_tunnel(
    stream_id: u32,
    target: TcpTarget,
    mut body: h2::RecvStream,
    mut respond: SendResponse<Bytes>,
    context: ConnectionContext,
    _tunnel_slot: OwnedSemaphorePermit,
) -> anyhow::Result<()> {
    let (stream, target_addr) = match resolve_and_connect(
        target,
        &context.tcp_policy,
        Duration::from_secs(context.config.tcp_proxy.connect_timeout_secs),
    )
    .await
    {
        Ok(connected) => connected,
        Err(TcpSetupFailure { status, reason }) => {
            warn!(stream_id, %reason, "HTTP/2 TCP target setup failed");
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
            send_error(&mut respond, status)?;
            return Ok(());
        }
    };

    let response = Response::builder().status(StatusCode::OK).body(())?;
    let mut send = respond.send_response(response, false)?;
    info!(stream_id, %target_addr, transport = "http2", "TCP tunnel established");
    let _metrics = TunnelMetricsGuard::new(Arc::clone(&context.metrics), 0);
    let activity = Arc::new(Activity::new());
    let (mut target_read, mut target_write) = stream.into_split();

    let client_to_target = async {
        while let Some(chunk) = body.data().await {
            let chunk = chunk?;
            target_write.write_all(&chunk).await?;
            body.flow_control().release_capacity(chunk.len())?;
            activity.touch();
        }
        target_write.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };
    let target_to_client = async {
        let mut buf = vec![0_u8; TCP_READ_CHUNK_SIZE];
        loop {
            let read = target_read.read(&mut buf).await?;
            if read == 0 {
                send_h2_data(&mut send, Bytes::new(), true).await?;
                return Ok::<_, anyhow::Error>(());
            }
            activity.touch();
            send_h2_data(&mut send, Bytes::copy_from_slice(&buf[..read]), false).await?;
        }
    };

    let relay = async { tokio::try_join!(client_to_target, target_to_client).map(|_| ()) };
    tokio::select! {
        result = relay => result?,
        _ = wait_until_idle(Arc::clone(&activity), Duration::from_secs(context.config.server.idle_timeout_secs)) => {
            send.send_reset(Reason::CANCEL);
        }
    }
    Ok(())
}

async fn serve_udp_tunnel(
    stream_id: u32,
    target: UdpTarget,
    mut body: h2::RecvStream,
    mut respond: SendResponse<Bytes>,
    context: ConnectionContext,
    _tunnel_slot: OwnedSemaphorePermit,
) -> anyhow::Result<()> {
    let addrs: Vec<SocketAddr> =
        match tokio::net::lookup_host((target.host.as_str(), target.port)).await {
            Ok(addrs) => addrs.collect(),
            Err(error) => {
                warn!(stream_id, %error, "HTTP/2 UDP target DNS resolution failed");
                send_error(&mut respond, StatusCode::BAD_GATEWAY)?;
                return Ok(());
            }
        };
    if addrs.is_empty() {
        send_error(&mut respond, StatusCode::BAD_GATEWAY)?;
        return Ok(());
    }
    if !context
        .udp_policy
        .all_allowed(&addrs.iter().map(|addr| addr.ip()).collect::<Vec<_>>())
    {
        send_error(&mut respond, StatusCode::FORBIDDEN)?;
        return Ok(());
    }
    let target_addr = addrs[0];
    let socket = match UdpSocket::bind(if target_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await
    {
        Ok(socket) => socket,
        Err(error) => {
            warn!(stream_id, %error, "HTTP/2 UDP socket bind failed");
            send_error(&mut respond, StatusCode::BAD_GATEWAY)?;
            return Ok(());
        }
    };
    if let Err(error) = socket.connect(target_addr).await {
        warn!(stream_id, %error, "HTTP/2 UDP target connect failed");
        send_error(&mut respond, StatusCode::BAD_GATEWAY)?;
        return Ok(());
    }

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CAPSULE_PROTOCOL, "?1")
        .body(())?;
    let mut send = respond.send_response(response, false)?;
    info!(stream_id, %target_addr, transport = "http2", "UDP tunnel established");
    let _metrics = TunnelMetricsGuard::new(Arc::clone(&context.metrics), 1);
    let activity = Arc::new(Activity::new());
    let max_payload = context.config.http2.max_datagram_size.min(MAX_UDP_PAYLOAD);
    // One extra byte admits the context ID zero before the UDP payload.
    let mut decoder = CapsuleDecoder::with_max_capsule_size(max_payload + 1);

    let client_to_target = async {
        while let Some(chunk) = body.data().await {
            let chunk = chunk?;
            let frames = decoder.decode(&chunk)?;
            body.flow_control().release_capacity(chunk.len())?;
            for frame in frames {
                let CapsuleFrame::Datagram(payload) = frame else {
                    continue;
                };
                let (context_id, context_len) = varint::decode(&payload)
                    .map_err(|_| anyhow::anyhow!("DATAGRAM capsule has no Context ID"))?;
                if context_id != 0 {
                    continue;
                }
                let udp_payload = &payload[context_len..];
                if udp_payload.len() > max_payload {
                    anyhow::bail!("UDP payload exceeds configured HTTP/2 datagram limit");
                }
                let written = socket.send(udp_payload).await?;
                if written != udp_payload.len() {
                    anyhow::bail!("target UDP socket accepted a partial datagram");
                }
                activity.touch();
            }
        }
        if decoder.buffered() != 0 {
            anyhow::bail!("request ended with a truncated DATAGRAM capsule");
        }
        Ok::<_, anyhow::Error>(())
    };

    let target_to_client = async {
        // One extra byte detects a datagram larger than the configured limit;
        // never forward a silently truncated prefix.
        let mut recv = vec![0_u8; max_payload + 1];
        let mut capsule = Vec::with_capacity(max_payload + 16);
        loop {
            let read = socket.recv(&mut recv).await?;
            if read > max_payload {
                debug!(
                    stream_id,
                    read, max_payload, "dropping oversized HTTP/2 target datagram"
                );
                continue;
            }
            activity.touch();
            // The HTTP Datagram payload begins with Context ID zero.
            capsule.clear();
            encoder::encode_datagram_context_zero(&recv[..read], &mut capsule);
            send_h2_data(&mut send, Bytes::copy_from_slice(&capsule), false).await?;
        }
    };

    // RFC 9298 recommends not expiring UDP mappings in less than two minutes.
    let idle_timeout =
        Duration::from_secs(context.config.server.idle_timeout_secs).max(Duration::from_secs(120));
    enum Completion {
        Client(anyhow::Result<()>),
        Target(anyhow::Result<()>),
        Idle,
    }
    let completion = tokio::select! {
        result = client_to_target => Completion::Client(result),
        result = target_to_client => Completion::Target(result),
        _ = wait_until_idle(Arc::clone(&activity), idle_timeout) => Completion::Idle,
    };
    match completion {
        Completion::Client(Ok(())) => {
            send_h2_data(&mut send, Bytes::new(), true).await?;
        }
        Completion::Client(Err(error)) | Completion::Target(Err(error)) => {
            send.send_reset(Reason::PROTOCOL_ERROR);
            return Err(error);
        }
        Completion::Target(Ok(())) => unreachable!("target receive loop never completes cleanly"),
        Completion::Idle => send.send_reset(Reason::CANCEL),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn serve_ip_tunnel(
    connection_index: u64,
    stream_id: u32,
    mut body: h2::RecvStream,
    mut respond: SendResponse<Bytes>,
    context: ConnectionContext,
    authenticated_identity: Option<Arc<ClientIdentity>>,
    capsule_mode: IpCapsuleMode,
    _tunnel_slot: OwnedSemaphorePermit,
) -> anyhow::Result<()> {
    let stream_id = u64::from(stream_id);
    let pinned = authenticated_identity
        .as_deref()
        .filter(|identity| identity.has_static_addresses());
    let addresses = match pinned {
        Some(identity) => match claim_static_addresses(&context.shared, identity) {
            Ok(addresses) => addresses,
            Err(error) => {
                warn!(
                    stream_id,
                    client = %identity.name,
                    %error,
                    "cannot attach HTTP/2 IP tunnel to fixed addresses"
                );
                send_error(&mut respond, StatusCode::SERVICE_UNAVAILABLE)?;
                return Ok(());
            }
        },
        None => allocate_pool_addresses(&context.shared),
    };
    if addresses.is_empty() {
        warn!(stream_id, "address pool exhausted for HTTP/2 IP tunnel");
        send_error(&mut respond, StatusCode::SERVICE_UNAVAILABLE)?;
        return Ok(());
    }

    let owner = TunnelOwner {
        conn_id: connection_index,
        stream_id,
    };
    let max_ip_packet = context
        .config
        .ip_proxy
        .tun_mtu
        .min(context.config.http2.max_datagram_size);
    // Bound queued TUN data by the H2 stream's configured send-buffer budget,
    // not by a fixed packet count that could become tens of megabytes at a
    // jumbo MTU. One slot is retained even when one packet exceeds the budget.
    let return_queue_capacity = (context.config.http2.max_send_buffer_size / max_ip_packet.max(1))
        .clamp(1, MAX_HTTP2_TUN_QUEUE_PACKETS);
    let (return_sender, mut return_packets) = mpsc::channel(return_queue_capacity);
    context
        .shared
        .http2_tun_routes
        .write()
        .expect("HTTP/2 TUN routes poisoned")
        .insert(
            owner,
            Http2TunRoute {
                sender: return_sender,
                metrics: Arc::clone(&context.metrics),
            },
        );
    {
        let mut routes = context
            .shared
            .routing_table
            .write()
            .expect("routing table poisoned");
        for address in &addresses {
            routes.insert(*address, owner);
            info!(
                stream_id,
                addr = %address,
                pinned = pinned.is_some(),
                transport = "http2",
                "assigned address to IP tunnel"
            );
        }
    }
    let _lease = Http2IpLease {
        shared: Arc::clone(&context.shared),
        owner,
        addresses: addresses.clone(),
    };

    let mut response = Response::builder().status(StatusCode::OK);
    if capsule_mode == IpCapsuleMode::Standard {
        response = response.header(CAPSULE_PROTOCOL, "?1");
    }
    let response = response.body(())?;
    let mut send = respond.send_response(response, false)?;
    send_h2_data(
        &mut send,
        Bytes::from(encode_ip_setup_capsules(&addresses)),
        false,
    )
    .await?;

    info!(
        stream_id,
        transport = "http2",
        capsule_mode = ?capsule_mode,
        "CONNECT-IP tunnel established"
    );
    let _metrics = TunnelMetricsGuard::new(Arc::clone(&context.metrics), 2);
    let activity = Arc::new(Activity::new());
    let idle = wait_until_idle(
        Arc::clone(&activity),
        Duration::from_secs(context.config.server.idle_timeout_secs),
    );
    tokio::pin!(idle);

    let context_bytes = usize::from(capsule_mode == IpCapsuleMode::Standard);
    let mut decoder = CapsuleDecoder::with_max_capsule_size(
        MAX_IP_CONTROL_CAPSULE_SIZE.max(max_ip_packet.saturating_add(context_bytes)),
    );
    let mut tun_send = TunSendBatch::new();
    let mut response_capsules = Vec::with_capacity(IP_RESPONSE_BATCH_SIZE);

    enum Completion {
        ClientClosed,
        Idle,
    }

    // Keep the two directions independent. In particular, waiting for response
    // flow-control credit must not stop us from consuming request DATA frames:
    // Cloudflare-style clients put each inner TCP ACK in a small DATA frame,
    // and h2 deliberately closes a connection when too many unconsumed small
    // frames accumulate. A single select loop whose return-path arm awaited
    // `send_h2_data` could therefore reset an otherwise healthy bulk transfer.
    let client_to_tun = async {
        loop {
            let Some(chunk) = body.data().await else {
                if decoder.buffered() != 0 {
                    anyhow::bail!("request ended with a truncated CONNECT-IP capsule");
                }
                return Ok::<_, anyhow::Error>(());
            };
            let chunk = chunk?;
            let frames = decoder.decode(&chunk)?;
            body.flow_control().release_capacity(chunk.len())?;

            for frame in frames {
                let CapsuleFrame::Datagram(payload) = frame else {
                    // ADDRESS_* and ROUTE_ADVERTISEMENT are valid on this
                    // stream but do not alter the server's local lease or
                    // source-spoofing boundary.
                    continue;
                };
                let Some(packet) = capsule_mode.decode_packet(&payload)? else {
                    continue;
                };
                if packet.len() > max_ip_packet {
                    debug!(
                        stream_id,
                        packet_len = packet.len(),
                        max_ip_packet,
                        "dropping oversized HTTP/2 IP packet"
                    );
                    continue;
                }
                let source = match ip_packet::src_addr(packet) {
                    Ok(source) => source,
                    Err(error) => {
                        debug!(stream_id, %error, "invalid IP header in HTTP/2 client packet");
                        continue;
                    }
                };
                if !addresses.contains(&source) {
                    debug!(stream_id, %source, "spoofed HTTP/2 source address, dropping");
                    continue;
                }

                activity.touch();
                if let Some(tun) = &context.shared.tun {
                    if tun_send.is_full() {
                        tun.send_batch(&mut tun_send).await?;
                    }
                    tun_send.push(packet);
                }
            }
            if let Some(tun) = &context.shared.tun
                && !tun_send.is_empty()
            {
                tun.send_batch(&mut tun_send).await?;
            }
        }
    };

    let tun_to_client = async {
        loop {
            let Some(packet) = return_packets.recv().await else {
                anyhow::bail!("HTTP/2 TUN return path closed");
            };
            response_capsules.clear();
            if packet.len() <= max_ip_packet {
                capsule_mode.encode_packet(&packet, &mut response_capsules);
            }
            while response_capsules.len() < IP_RESPONSE_BATCH_SIZE {
                let packet = match return_packets.try_recv() {
                    Ok(packet) => packet,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        anyhow::bail!("HTTP/2 TUN return path closed");
                    }
                };
                if packet.len() <= max_ip_packet {
                    capsule_mode.encode_packet(&packet, &mut response_capsules);
                }
            }
            if response_capsules.is_empty() {
                continue;
            }
            activity.touch();
            send_h2_data(&mut send, Bytes::copy_from_slice(&response_capsules), false).await?;
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    };

    let relay = {
        tokio::pin!(client_to_tun);
        tokio::pin!(tun_to_client);
        tokio::select! {
            result = &mut client_to_tun => result.map(|()| Completion::ClientClosed),
            result = &mut tun_to_client => result.map(|()| Completion::ClientClosed),
            _ = &mut idle => Ok(Completion::Idle),
        }
    };

    match relay {
        Ok(Completion::ClientClosed) => send_h2_data(&mut send, Bytes::new(), true).await?,
        Ok(Completion::Idle) => send.send_reset(Reason::CANCEL),
        Err(error) => {
            send.send_reset(Reason::PROTOCOL_ERROR);
            return Err(error);
        }
    }
    Ok(())
}

/// Synchronous cleanup makes task cancellation safe: aborting an H2 stream
/// immediately removes its return route and releases every address lease.
struct Http2IpLease {
    shared: Arc<Shared>,
    owner: TunnelOwner,
    addresses: Vec<IpAddr>,
}

impl Drop for Http2IpLease {
    fn drop(&mut self) {
        self.shared
            .http2_tun_routes
            .write()
            .expect("HTTP/2 TUN routes poisoned")
            .remove(&self.owner);
        self.shared
            .routing_table
            .write()
            .expect("routing table poisoned")
            .remove_owned(&self.addresses, &self.owner);
        self.shared
            .address_pool
            .lock()
            .expect("address pool poisoned")
            .release_all(&self.addresses);
        info!(
            stream_id = self.owner.stream_id,
            transport = "http2",
            "CONNECT-IP tunnel closed"
        );
    }
}

async fn send_h2_data(
    send: &mut SendStream<Bytes>,
    mut data: Bytes,
    end_stream: bool,
) -> Result<(), h2::Error> {
    if data.is_empty() {
        return send.send_data(data, end_stream);
    }

    while data.has_remaining() {
        send.reserve_capacity(data.remaining());
        let capacity = poll_fn(|cx| send.poll_capacity(cx))
            .await
            .ok_or_else(|| h2::Error::from(Reason::STREAM_CLOSED))??;
        let take = capacity.min(data.remaining());
        let chunk = data.split_to(take);
        let finished = end_stream && data.is_empty();
        send.send_data(chunk, finished)?;
    }
    Ok(())
}

fn send_error(respond: &mut SendResponse<Bytes>, status: StatusCode) -> Result<(), h2::Error> {
    let response = Response::builder()
        .status(status)
        .body(())
        .expect("status-only response is valid");
    respond.send_response(response, true).map(|_| ())
}

fn send_proxy_auth_required(respond: &mut SendResponse<Bytes>) -> Result<(), h2::Error> {
    let response = Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header(
            PROXY_AUTHENTICATE,
            "Basic realm=\"masque\", charset=\"UTF-8\"",
        )
        .body(())
        .expect("static proxy-authenticate response is valid");
    respond.send_response(response, true).map(|_| ())
}

struct Activity {
    started: Instant,
    last_millis: std::sync::atomic::AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            last_millis: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        use std::sync::atomic::Ordering;
        let elapsed = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        self.last_millis.store(elapsed, Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        use std::sync::atomic::Ordering;
        let last = self.last_millis.load(Ordering::Relaxed);
        let now = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        Duration::from_millis(now.saturating_sub(last))
    }
}

async fn wait_until_idle(activity: Arc<Activity>, timeout: Duration) {
    let check_interval = timeout.min(Duration::from_secs(1));
    loop {
        tokio::time::sleep(check_interval).await;
        if activity.idle_for() >= timeout {
            return;
        }
    }
}

struct ConnectionMetricsGuard {
    metrics: Arc<ShardMetrics>,
}

impl ConnectionMetricsGuard {
    fn new(metrics: Arc<ShardMetrics>) -> Self {
        metrics.connection_opened();
        Self { metrics }
    }
}

impl Drop for ConnectionMetricsGuard {
    fn drop(&mut self) {
        self.metrics.connection_closed();
    }
}

struct TunnelMetricsGuard {
    metrics: Arc<ShardMetrics>,
    protocol_index: usize,
}

impl TunnelMetricsGuard {
    fn new(metrics: Arc<ShardMetrics>, protocol_index: usize) -> Self {
        metrics.tunnel_opened(protocol_index);
        Self {
            metrics,
            protocol_index,
        }
    }
}

impl Drop for TunnelMetricsGuard {
    fn drop(&mut self) {
        self.metrics.tunnel_closed(self.protocol_index);
    }
}

#[cfg(test)]
mod tests {
    use super::IpCapsuleMode;
    use crate::capsule::CapsuleFrame;
    use crate::capsule::decoder::CapsuleDecoder;

    #[test]
    fn standard_ip_capsule_keeps_context_id_zero() {
        let mut encoded = Vec::new();
        IpCapsuleMode::Standard.encode_packet(b"packet", &mut encoded);

        let frames = CapsuleDecoder::new().decode(&encoded).unwrap();
        assert_eq!(
            frames,
            vec![CapsuleFrame::Datagram(
                [vec![0], b"packet".to_vec()].concat()
            )]
        );
        assert_eq!(
            IpCapsuleMode::Standard.decode_packet(&[0, b'p']).unwrap(),
            Some(&b"p"[..])
        );
    }

    #[test]
    fn cloudflare_ip_capsule_omits_context_id_zero() {
        let mut encoded = Vec::new();
        IpCapsuleMode::Cloudflare.encode_packet(b"packet", &mut encoded);

        let frames = CapsuleDecoder::new().decode(&encoded).unwrap();
        assert_eq!(frames, vec![CapsuleFrame::Datagram(b"packet".to_vec())]);
        assert_eq!(
            IpCapsuleMode::Cloudflare.decode_packet(b"packet").unwrap(),
            Some(&b"packet"[..])
        );
    }

    #[test]
    fn standard_ip_capsule_ignores_unknown_context() {
        assert_eq!(
            IpCapsuleMode::Standard.decode_packet(&[1, 42]).unwrap(),
            None
        );
    }
}
