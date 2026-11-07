//! TLS/H2 connection lifecycle and request dispatch.

use std::future::pending;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use bytes::Bytes;
use h2::Reason;
use h2::server::SendResponse;
use http::{Request, StatusCode};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use super::super::MAX_PENDING_AUTH_PER_CONNECTION;
use super::auth::{self, Authorization};
use super::request::{self as request_handling, RequestKind};
use super::support::{ConnectionMetricsGuard, send_error};
use super::{
    ConnectionContext, DRAIN_TIMEOUT, HANDSHAKE_TIMEOUT, HEARTBEAT_INTERVAL, ip, tcp, udp,
};
use crate::admission::SourceAdmission;
use crate::client_identity::ClientIdentity;

pub(super) async fn serve(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    context: ConnectionContext,
    mut shutdown: watch::Receiver<bool>,
    _connection_slot: OwnedSemaphorePermit,
    _source_admission: SourceAdmission,
) {
    let _connection_metrics = ConnectionMetricsGuard::new(Arc::clone(&context.metrics));
    // H2 flow-control updates and small DATAGRAM capsules should not wait
    // behind an unacknowledged TCP segment.
    if let Err(error) = stream.set_nodelay(true) {
        debug!(%peer, %error, "failed to disable Nagle on HTTP/2 connection");
    }
    let tls = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
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
                .and_then(|der| auth::identify_current_client(roster, &der));
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

    let mut connection = match tokio::time::timeout(HANDSHAKE_TIMEOUT, builder.handshake(tls)).await
    {
        Ok(Ok(connection)) => connection,
        Ok(Err(error)) => {
            debug!(%peer, %error, "HTTP/2 handshake failed");
            return;
        }
        Err(_) => {
            debug!(%peer, "HTTP/2 handshake timed out");
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
    let idle_timeout = Duration::from_secs(context.config.server.idle_timeout_secs);
    // Only a connection without request tasks is idle. Tunnel tasks enforce
    // their own protocol-specific inactivity rules; a connection-age timer
    // would cut off healthy long-lived tunnels (including quiet UDP tunnels).
    // An unrepresentably distant deadline is effectively disabled, rather
    // than panicking on a very large configured duration.
    let established = tokio::time::Instant::now();
    let mut idle_deadline = established.checked_add(idle_timeout);
    let first_auth = context
        .auth
        .as_ref()
        .and_then(|_| established.checked_add(idle_timeout.max(Duration::from_secs(1))))
        .map(|deadline| {
            Arc::new(FirstAuth {
                deadline,
                verified: AtomicBool::new(false),
            })
        });
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
            _ = async {
                match idle_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => pending::<()>().await,
                }
            }, if !draining && requests.is_empty() => {
                debug!(%peer, "idle HTTP/2 connection timed out");
                draining = true;
                drain_deadline = Some(tokio::time::Instant::now() + DRAIN_TIMEOUT);
                // No application tasks remain. Flush a final GOAWAY without
                // needing a PING acknowledgement from an idle or hostile peer.
                // Keep polling below, but bound even a blocked transport flush.
                connection.abrupt_shutdown(Reason::NO_ERROR);
            }
            _ = async {
                match first_auth.as_deref().filter(|auth| !auth.verified.load(Ordering::Acquire)) {
                    Some(auth) => tokio::time::sleep_until(auth.deadline).await,
                    None => pending::<()>().await,
                }
            }, if !draining => {
                // A request task may have authenticated since the timer was armed.
                if first_auth.as_deref().is_some_and(|auth| !auth.verified.load(Ordering::Acquire)) {
                    debug!(%peer, "HTTP/2 first authentication timed out");
                    draining = true;
                    drain_deadline = Some(tokio::time::Instant::now() + DRAIN_TIMEOUT);
                    connection.abrupt_shutdown(Reason::NO_ERROR);
                    requests.abort_all();
                }
            }
            joined = requests.join_next(), if !requests.is_empty() => {
                if let Some(Err(error)) = joined {
                    warn!(%peer, %error, "HTTP/2 request task panicked");
                }
                if requests.is_empty() {
                    idle_deadline = tokio::time::Instant::now().checked_add(idle_timeout);
                }
            }
            accepted = connection.accept() => {
                match accepted {
                    Some(Ok((request, respond))) if !draining => {
                        idle_deadline = None;
                        requests.spawn(handle_request(
                            request,
                            respond,
                            context.clone(),
                            connection_index,
                            authenticated_identity.as_ref().map(Arc::clone),
                            RequestAdmission {
                                tunnel_slots: Arc::clone(&tunnel_slots),
                                auth_slots: Arc::clone(&auth_slots),
                                source_ip: peer.ip(),
                                first_auth: first_auth.clone(),
                            },
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

/// A fixed deadline shared by the connection and its request tasks.
struct FirstAuth {
    deadline: tokio::time::Instant,
    verified: AtomicBool,
}

struct RequestAdmission {
    tunnel_slots: Arc<Semaphore>,
    auth_slots: Arc<Semaphore>,
    source_ip: std::net::IpAddr,
    first_auth: Option<Arc<FirstAuth>>,
}

async fn handle_request(
    request: Request<h2::RecvStream>,
    mut respond: SendResponse<Bytes>,
    context: ConnectionContext,
    connection_index: u64,
    authenticated_identity: Option<Arc<ClientIdentity>>,
    admission: RequestAdmission,
) {
    let stream_id = respond.stream_id().as_u32();
    let Some(recognized) = request_handling::recognize(&request, &context.config) else {
        let _ = send_error(&mut respond, StatusCode::NOT_FOUND);
        return;
    };

    if matches!(
        auth::authorize_request(
            &request,
            &mut respond,
            &context,
            admission.auth_slots,
            admission.source_ip,
        )
        .await,
        Authorization::ResponseSent
    ) {
        return;
    }

    if let Some(auth) = &admission.first_auth
        && !auth.verified.load(Ordering::Acquire)
    {
        if tokio::time::Instant::now() >= auth.deadline {
            return;
        }
        auth.verified.store(true, Ordering::Release);
    }

    // Match HTTP/3's ordering: a recognized proxy request authenticates before
    // target parsing or transport-specific validation. This keeps malformed
    // requests from using status differences to bypass the authentication boundary.
    let kind = match request_handling::prepare(&request, recognized, &context.config) {
        Ok(kind) => kind,
        Err(status) => {
            let _ = send_error(&mut respond, status);
            return;
        }
    };

    let tunnel_slot = match admission.tunnel_slots.try_acquire_owned() {
        Ok(slot) => slot,
        Err(_) => {
            let _ = send_error(&mut respond, StatusCode::SERVICE_UNAVAILABLE);
            return;
        }
    };
    let (_parts, body) = request.into_parts();

    let result = match kind {
        RequestKind::Tcp(target) => {
            tcp::serve(stream_id, target, body, respond, context, tunnel_slot).await
        }
        RequestKind::Udp(target) => {
            udp::serve(stream_id, target, body, respond, context, tunnel_slot).await
        }
        RequestKind::Ip(capsule_mode) => {
            ip::serve(
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
