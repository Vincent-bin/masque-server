//! MASQUE over HTTP/2.
//!
//! HTTP/2 is a compatibility transport for networks where UDP/QUIC is
//! unavailable. Standard CONNECT streams carry bytes directly in DATA frames;
//! CONNECT-UDP and CONNECT-IP streams carry DATAGRAM capsules. Both RFC 9484
//! Extended CONNECT and Cloudflare's deployed H2 CONNECT-IP dialect are
//! accepted. HTTP/3 remains the preferred transport because HTTP/2 makes
//! datagrams reliable and ordered.

mod auth;
mod connection;
mod ip;
mod request;
mod support;
mod tcp;
mod udp;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use boring::ssl::{AlpnError, SslAcceptor, SslMethod, select_next_proto};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use super::{MAX_EPHEMERAL_BIND_ATTEMPTS, Shared, listen_address_conflict, tls};
use crate::auth::SharedBasicAuthenticator;
use crate::client_identity::{SharedRoster, configure_client_cert_verification};
use crate::config::{ResolvedListener, ServerConfig};
use crate::metrics::{Metrics, ShardMetrics};
use crate::policy::TargetPolicy;

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);

/// A bound TCP/TLS listener and the immutable state shared by its connections.
pub(super) struct Http2Listener {
    listener: TcpListener,
    listen_addr: SocketAddr,
    acceptor: Arc<SslAcceptor>,
    config: Arc<ServerConfig>,
    shared: Arc<Shared>,
    auth: Option<Arc<SharedBasicAuthenticator>>,
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
        auth: Option<Arc<SharedBasicAuthenticator>>,
        process_metrics: Arc<Metrics>,
        auth_label: &'static str,
        unavailable: &[SocketAddr],
    ) -> anyhow::Result<Self> {
        let acceptor = Arc::new(build_acceptor(
            listener
                .auth
                .client_cert_enabled()
                .then(|| Arc::clone(&shared.clients)),
            Arc::clone(&shared.tls),
        )?);

        let (socket, listen_addr) = bind_tcp_listener(listener.listen_addr, unavailable).await?;
        let metrics = process_metrics
            .register_listener(listen_addr, "http2", auth_label, 1, false, false)
            .into_iter()
            .next()
            .expect("one metrics owner was requested for the HTTP/2 listener");
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
                    let source_admission = match self.shared.source_admissions.try_acquire(peer.ip()) {
                        Some(admission) => admission,
                        None => {
                            self.metrics.connection_rejected_source_limit();
                            warn!(%peer, "HTTP/2 source connection limit reached");
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
                    connections.spawn(connection::serve(
                        stream,
                        peer,
                        context,
                        connection_shutdown.clone(),
                        connection_slot,
                        source_admission,
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
    auth: Option<Arc<SharedBasicAuthenticator>>,
    client_certs: Option<Arc<SharedRoster>>,
    tcp_policy: TargetPolicy,
    udp_policy: TargetPolicy,
    metrics: Arc<ShardMetrics>,
}

/// Validate and build the TLS context used by an H2 listener.
pub(super) fn build_acceptor(
    client_certs: Option<Arc<SharedRoster>>,
    tls_identity: Arc<tls::SharedTlsIdentity>,
) -> anyhow::Result<SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
        .context("failed to create HTTP/2 TLS context")?;
    tls::configure_dynamic_identity(&mut builder, tls_identity);
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
