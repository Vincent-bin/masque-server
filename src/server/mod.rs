// QUIC listener and connection accept loop.

mod authentication;
pub(crate) mod capsules;
mod http2;
mod listener_address;
mod request;
mod retry;
mod shard_datagrams;
mod shard_lifecycle;
mod shard_output;
mod shard_packets;
mod shard_tunnels;
mod tls;
mod validation;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use std::sync::{Mutex, RwLock};

use anyhow::Context as _;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use self::authentication::AuthOutcome;
use self::listener_address::{AddressConflict, listen_address_conflict};
use self::request::{ConnectRequest, PendingAuth, PendingConnectSetups, RequestContext};
pub use self::validation::validate_config;
use self::validation::{
    ValidatedServerConfig, active_client_registry, any_client_cert_listener, basic_shard_count,
    listener_auth_label, validate_server_config,
};
#[cfg(test)]
use self::validation::{is_loopback, plan_listeners};
use crate::address_pool::{AddressPool, PoolError};
use crate::admission::SourceAdmissionLimiter;
use crate::auth::{BasicAuthenticator, SharedBasicAuthenticator};
use crate::capsule;
use crate::capsule::{AssignedAddress, CapsuleFrame, IpAddress, IpAddressRange};
use crate::client_identity::{
    ClientIdentity, ClientRegistry, SharedRoster, configure_client_cert_verification,
};
use crate::config::{AuthSection, ListenerTransport, ResolvedListener, ServerConfig, TlsSection};
use crate::connection::{AwaitingAuth, ClientConnection, EarlyUdpDatagramResult};
use crate::datagram;
use crate::fxhash::FxHashMap;
use crate::ip_packet;
use crate::metrics::{Metrics, ShardMetrics};
use crate::net::quic::{
    MAX_BATCH_PACKETS, MAX_DATAGRAM_SIZE, QuicUdpSocket, RecvPacketBatch, SendPacketBatch,
};
#[cfg(target_os = "linux")]
use crate::net::target_udp;
use crate::net::target_udp::TargetRecvBatch;
use crate::observability::ObservabilityServer;
use crate::policy::TargetPolicy;
use crate::routing::{RoutingTable, TunnelOwner};
use crate::scheduler::{DirtySet, TimerQueue};
use crate::systemd;
use crate::tun::{self, TunManager, TunRecvBatch, TunSendBatch};
use crate::tunnel::ip::IpTunnel;
use crate::tunnel::resolver::ResolverBudget;
use crate::tunnel::tcp::{PendingTcpTunnel, TcpRelayEvent, TcpTunnel, spawn_tcp_connect};
use crate::tunnel::udp::{PendingUdpTunnel, UdpSetupResult, UdpTunnel, spawn_udp_setup};

/// Unique connection ID length.
const CONN_ID_LEN: usize = 16;

/// Bounded queue used by per-tunnel receive tasks to wake the main loop.
///
/// Counted in batches, so the datagram bound is this times
/// [`MAX_UDP_RECV_BATCH`].
const UDP_RESPONSE_QUEUE_CAPACITY: usize = 256;

/// Completed UDP target setups waiting for their owning shard. The live
/// pending-tunnel maps provide the per-connection bound; this queue prevents a
/// burst across many connections from growing shard memory without limit.
const UDP_SETUP_QUEUE_CAPACITY: usize = 256;

/// TCP readers wait for the main loop to acknowledge each chunk, so this
/// queue bounds both wakeups and response memory across all tunnels.
const TCP_RELAY_QUEUE_CAPACITY: usize = 1024;

/// Drain already-ready target TCP events before driving HTTP/3.
///
/// A target reader can stay four 64 KiB chunks ahead of the shard. Handling
/// only the event returned by `select!` forced one complete event-loop and
/// QUIC-drive round per chunk even when the other three were already queued.
/// These bounds amortize those wakeups without allowing a busy set of TCP
/// tunnels to starve the QUIC socket indefinitely.
const MAX_TCP_RELAY_EVENTS_PER_ROUND: usize = 64;
const MAX_TCP_RELAY_BYTES_PER_ROUND: usize = 4 * 1024 * 1024;

/// Drain a bounded batch of already-buffered QUIC packets per readiness wakeup.
const MAX_QUIC_RECV_BATCH: usize = MAX_BATCH_PACKETS;

/// Bound on TUN packets handled per readiness wakeup, so a busy TUN device
/// cannot starve the QUIC socket. One offloaded read already yields a whole
/// GSO aggregate, so this is the size of a single batched read.
const MAX_TUN_RECV_BATCH: usize = tun::TUN_BATCH_SIZE;

/// Upper bound on shards, so a machine with a very high core count does not
/// fan out into more event loops than the listen sockets can usefully feed.
///
/// Applied to the server's total, not to one listener's share of it.
const MAX_SHARDS: usize = 32;

/// Queue depth for packets handed between shards.
const SHARD_FORWARD_QUEUE_CAPACITY: usize = 1024;

/// Keep one active and one spare connection ID. Sequential migrations can
/// replenish the spare after retirement without letting CID routing state
/// grow with attacker-controlled path churn.
const ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;

/// Bound unacknowledged PATH_CHALLENGEs retained by quiche per connection.
const PATH_CHALLENGE_RECV_QUEUE_LEN: usize = 3;

/// Private application error used when an otherwise valid peer migration
/// would exceed the process-wide connection cap for its new source address.
const MIGRATION_SOURCE_LIMIT_ERROR: u64 = 0x0101;

/// Queue depth for completed credential verifications.
const AUTH_RESULT_QUEUE_CAPACITY: usize = 256;

/// Global bound on credential verifications that are running or waiting.
///
/// The per-connection limit prevents one QUIC connection from monopolising
/// this queue. This second bound prevents many short-lived connections from
/// leaving an unbounded number of Argon2 jobs behind.
const MAX_PENDING_AUTH_GLOBAL: usize = 256;

/// CONNECT requests one connection may have awaiting verification.
///
/// Waiting costs only the parsed request, so this exists to bound how much a
/// single caller can queue rather than to ration the verification itself —
/// that is what `Shared::auth_permits` does.
const MAX_PENDING_AUTH_PER_CONNECTION: usize = 16;

/// Configuration ceilings that keep one hostile connection, or one mistaken
/// configuration edit, from turning protocol credit into unbounded memory.
/// Defaults remain far below these values; the ceilings leave room for large
/// deployments while making the worst case auditable.
const MAX_CONFIGURED_CONNECTIONS: usize = 1_000_000;
const MAX_CONFIGURED_CONNECTIONS_PER_IP: usize = 65_536;
const MAX_TUNNELS_PER_CONNECTION: usize = 4_096;
const MAX_QUIC_STREAMS_BIDI: u64 = 4_096;
const MAX_QUIC_DATAGRAM_QUEUE_LEN: usize = 4_096;
const MAX_QUIC_CONNECTION_WINDOW: u64 = 1024 * 1024 * 1024;
const MAX_QUIC_STREAM_WINDOW: u64 = 256 * 1024 * 1024;
const MAX_HTTP2_CONCURRENT_STREAMS: u32 = 4_096;
const MAX_HTTP2_STREAM_WINDOW: u32 = 16 * 1024 * 1024;
const MAX_HTTP2_CONNECTION_WINDOW: u32 = 64 * 1024 * 1024;
const MAX_HTTP2_HEADER_LIST_SIZE: u32 = 1024 * 1024;
const MAX_HTTP2_SEND_BUFFER_SIZE: usize = 16 * 1024 * 1024;

/// How many fresh kernel-selected ports to try when an ephemeral listener
/// happens to overlap another listener.
///
/// `SO_REUSEPORT` makes such an overlap legal at the kernel boundary, so the
/// server has to detect it itself or two authentication modes can accidentally
/// join one load-balancing group. A collision is rare; a bounded retry keeps a
/// pathological host configuration from turning startup into an infinite loop.
const MAX_EPHEMERAL_BIND_ATTEMPTS: usize = 32;

/// Concurrent password verifications allowed across all shards.
///
/// Each one costs roughly 19 MiB and tens of milliseconds of CPU, so this caps
/// both the memory and the CPU an unauthenticated caller can demand. Two per
/// shard keeps every shard able to make progress, but never more than one per
/// core: hashing moved off the event loop still competes with it for CPU, and
/// oversubscribing just trades a stall for scheduler thrash.
///
/// `shards` counts only the shards that verify passwords. A client-certificate
/// listener never reaches this path — its shards hold no `BasicAuthenticator` —
/// so counting them would let a large certificate deployment raise the budget
/// that exists to ration what unauthenticated callers can demand of a small
/// Basic one.
fn auth_concurrency(basic_shards: usize) -> usize {
    let cores = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    // Never zero: with no Basic listener nothing acquires a permit, but a
    // semaphore that cannot be acquired would turn any future caller into a
    // hang rather than a rejection.
    (basic_shards * 2).clamp(1, cores.max(2))
}

/// How often idle tunnels are swept. Tunnels close after `idle_timeout_secs`,
/// so this is a background chore rather than something that belongs on the
/// packet path.
const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// A batch of framed target responses for one UDP tunnel.
///
/// Batching keeps a busy tunnel from costing one channel send and one event
/// loop wakeup per datagram.
struct UdpResponse {
    connection_index: u64,
    stream_id: u64,
    datagrams: Vec<Vec<u8>>,
}

/// Return path for one CONNECT-IP stream carried by HTTP/2.
///
/// HTTP/3 connections live inside shards and can be addressed through
/// `index_shard`. HTTP/2 streams are independent Tokio tasks, so the shared
/// TUN reader hands their packets to a bounded channel instead.
#[derive(Clone)]
struct Http2TunRoute {
    sender: mpsc::Sender<Vec<u8>>,
    metrics: Arc<ShardMetrics>,
}

/// Top-level MASQUE server.
///
/// Runs one event loop per shard. A listener's shards each bind its address
/// with `SO_REUSEPORT` and own a disjoint set of connections, so QUIC's
/// per-packet crypto — which is what saturates a core — spreads across them.
/// The kernel hashes each 4-tuple to a shard, and the rare packet that lands on
/// the wrong one (a client that changed address) is handed to its owner rather
/// than dropped.
///
/// A server may have several listeners, which is what lets one process serve
/// more than one authentication mode: each listener's `auth.mode` decides which
/// TLS verification policy a shard builds, and that policy is fixed once its
/// socket is bound. The server certificate selected by new handshakes remains
/// reloadable.
/// Shards are numbered across the whole server, so everything shared between
/// them — the address pool, routing table, TUN device, and cross-shard queues —
/// stays single and needs no knowledge of which listener a shard serves.
pub struct Server {
    shards: Vec<Shard>,
    http2_listeners: Vec<http2::Http2Listener>,
    /// Bound worker addresses in configuration order. HTTP/3 repeats an
    /// address once per shard, preserving the public method's original shape.
    listen_addrs: Vec<SocketAddr>,
    shared: Arc<Shared>,
    metrics: Arc<Metrics>,
    observability: Option<ObservabilityServer>,
}

/// Capture only the startup state that a configuration reload may use.
fn config_reload_settings(
    config: &ServerConfig,
    config_path: Option<std::path::PathBuf>,
) -> Option<ConfigReload> {
    config_path.map(|path| ConfigReload {
        path,
        tls: config.tls.clone(),
        client_cert_enabled: any_client_cert_listener(config),
        ip_proxy_enabled: config.ip_proxy.enabled,
        listeners: config
            .listeners
            .iter()
            .map(|listener| ReloadListener {
                listen_addr: listener.listen_addr,
                transport: listener.transport,
                auth: ReloadAuthKind::from(&listener.auth),
                stealth: listener.auth.stealth_enabled(),
            })
            .collect(),
    })
}

/// Open the UDP socket for one shard with the listener's transport settings.
async fn open_quic_socket(
    config: &ServerConfig,
    listen_addr: SocketAddr,
    reuseport_shards: usize,
    max_datagram_size: usize,
) -> anyhow::Result<QuicUdpSocket> {
    QuicUdpSocket::bind_shared(
        listen_addr,
        max_datagram_size,
        config.quic.enable_udp_gso,
        config.quic.enable_udp_gro,
        reuseport_shards,
    )
    .await
    .with_context(|| format!("failed to bind listener {listen_addr}"))
}

/// Bind the first shard of a listener and resolve an ephemeral port, if any.
///
/// A multi-shard socket sets `SO_REUSEPORT` before binding. Linux may therefore
/// choose an ephemeral port that is already held by another reuseport group,
/// including a later fixed listener from this configuration. Detect that before
/// the remaining shards join the group and ask the kernel for another port.
async fn bind_first_listener_socket(
    config: &ServerConfig,
    requested: SocketAddr,
    reuseport_shards: usize,
    max_datagram_size: usize,
    unavailable: &[SocketAddr],
) -> anyhow::Result<(QuicUdpSocket, SocketAddr)> {
    for attempt in 1..=MAX_EPHEMERAL_BIND_ATTEMPTS {
        let socket =
            open_quic_socket(config, requested, reuseport_shards, max_datagram_size).await?;
        let bound = socket.local_addr()?;

        if requested.port() != 0 {
            return Ok((socket, bound));
        }

        if let Some(existing) = unavailable
            .iter()
            .copied()
            .find(|existing| listen_address_conflict(bound, *existing).is_some())
        {
            if attempt == MAX_EPHEMERAL_BIND_ATTEMPTS {
                anyhow::bail!(
                    "listener {requested} was repeatedly assigned an ephemeral address that \
                     overlaps listener {existing}; tried {MAX_EPHEMERAL_BIND_ATTEMPTS} ports"
                );
            }
            debug!(
                %requested,
                assigned = %bound,
                conflicts_with = %existing,
                attempt,
                "ephemeral listener address overlaps another listener; retrying"
            );
            continue;
        }

        return Ok((socket, bound));
    }

    unreachable!("the bounded ephemeral-port loop either returns or reports its last conflict")
}

impl Server {
    /// Create a new server bound to the configured address.
    pub async fn bind(config: ServerConfig) -> anyhow::Result<Self> {
        Self::bind_with_reload(config, None).await
    }

    /// Bind, and allow `SIGHUP` to re-read TLS material and active Basic/
    /// certificate credentials from `config_path`.
    ///
    /// Revoking a client otherwise costs a restart, which drops every other
    /// client's tunnel to remove one.
    pub async fn bind_with_reload(
        config: ServerConfig,
        config_path: Option<std::path::PathBuf>,
    ) -> anyhow::Result<Self> {
        let ValidatedServerConfig {
            clients,
            tls,
            listeners,
            total_shards,
            address_pool,
        } = validate_server_config(&config)?;

        let basic_shards = basic_shard_count(&listeners);
        let basic_auth = listeners
            .iter()
            .map(|plan| {
                plan.listener
                    .auth
                    .basic_enabled()
                    .then(|| {
                        BasicAuthenticator::from_section(&plan.listener.auth)
                            .map(SharedBasicAuthenticator::new)
                            .map(Arc::new)
                    })
                    .transpose()
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let config = Arc::new(config);
        let metrics = Arc::new(Metrics::new(config.observability.listen_addr.is_some()));

        let tun = build_tun(&config)?;

        let mut key_bytes = [0u8; 64];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut key_bytes)
            .map_err(|_| anyhow::anyhow!("failed to seed connection admission keys"))?;

        // Every shard needs a handle to every other shard's inboxes, so the
        // channels are made before the shards that read them. Shards are
        // numbered across the whole server rather than within a listener, so a
        // packet or a TUN packet reaches its owner without anyone having to
        // know which listener that owner belongs to.
        let mut forward_tx = Vec::with_capacity(total_shards);
        let mut forward_rx = Vec::with_capacity(total_shards);
        let mut forward_slots = Vec::with_capacity(total_shards);
        let mut tun_tx = Vec::with_capacity(total_shards);
        let mut tun_rx = Vec::with_capacity(total_shards);
        for _ in 0..total_shards {
            let (tx, rx) = mpsc::channel(SHARD_FORWARD_QUEUE_CAPACITY);
            forward_tx.push(tx);
            forward_rx.push(rx);
            forward_slots.push(Arc::new(Semaphore::new(SHARD_FORWARD_QUEUE_CAPACITY)));
            let (tx, rx) = mpsc::channel(SHARD_FORWARD_QUEUE_CAPACITY);
            tun_tx.push(tx);
            tun_rx.push(rx);
        }

        // Listener authentication modes stay fixed because changing whether a
        // socket requests client certificates changes its trust boundary.
        // Capture that startup state while still allowing the shared server
        // identity and an already-active client roster to be replaced.
        let config_reload = config_reload_settings(&config, config_path);

        let shared = Arc::new(Shared {
            resolver: ResolverBudget::default(),
            address_pool: Mutex::new(address_pool),
            routing_table: RwLock::new(RoutingTable::new()),
            cid_shard: RwLock::new(FxHashMap::default()),
            index_shard: RwLock::new(FxHashMap::default()),
            http2_tun_routes: RwLock::new(FxHashMap::default()),
            next_conn_index: AtomicU64::new(0),
            conn_id_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key_bytes[..32]),
            retry_tokens: retry::RetryTokenCodec::new(
                ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key_bytes[32..]),
                Duration::from_secs(config.quic.retry_token_ttl_secs),
            ),
            source_admissions: SourceAdmissionLimiter::new(config.server.max_connections_per_ip),
            auth_source_admissions: SourceAdmissionLimiter::new(
                config.server.max_pending_auth_per_ip,
            ),
            tun,
            forward_tx,
            forward_slots,
            tun_tx,
            auth_permits: Arc::new(Semaphore::new(auth_concurrency(basic_shards))),
            auth_queue_slots: Arc::new(Semaphore::new(MAX_PENDING_AUTH_GLOBAL)),
            basic_auth,
            clients: Arc::new(SharedRoster::new(clients)),
            tls,
            config_reload,
            metrics: Arc::clone(&metrics),
            shard_metrics: RwLock::new(Vec::with_capacity(total_shards)),
        });

        let mut shards = Vec::with_capacity(total_shards);
        let mut http2_listeners = Vec::new();
        let mut listen_addrs = Vec::with_capacity(total_shards + listeners.len());
        let mut inboxes = forward_rx.into_iter().zip(tun_rx);
        // Ephemeral listeners must avoid not only sockets that are already up,
        // but fixed listeners that have not been reached yet. Otherwise an
        // early `:0` listener can take a later port and, under SO_REUSEPORT,
        // silently join the other authentication mode's group.
        let mut unavailable_http3_addrs: Vec<SocketAddr> = listeners
            .iter()
            .filter(|plan| plan.listener.transport == ListenerTransport::Http3)
            .map(|plan| plan.listener.listen_addr)
            .filter(|addr| addr.port() != 0)
            .collect();
        let mut unavailable_http2_addrs: Vec<SocketAddr> = listeners
            .iter()
            .filter(|plan| plan.listener.transport == ListenerTransport::Http2)
            .map(|plan| plan.listener.listen_addr)
            .filter(|addr| addr.port() != 0)
            .collect();

        for (listener_index, mut plan) in listeners.into_iter().enumerate() {
            let listener_auth = shared.basic_auth[listener_index].as_ref().map(Arc::clone);
            if plan.listener.transport == ListenerTransport::Http2 {
                let listener = http2::Http2Listener::bind(
                    Arc::clone(&config),
                    Arc::clone(&shared),
                    plan.listener.clone(),
                    listener_auth,
                    Arc::clone(&metrics),
                    listener_auth_label(&plan.listener),
                    &unavailable_http2_addrs,
                )
                .await?;
                unavailable_http2_addrs.push(listener.local_addr());
                listen_addrs.push(listener.local_addr());
                http2_listeners.push(listener);
                continue;
            }

            // Bind `:0` only once, then use the assigned address for every
            // remaining shard. Asking the kernel for `:0` independently would
            // split one logical listener across unrelated ports.
            let (first_socket, bound_addr) = bind_first_listener_socket(
                &config,
                plan.listener.listen_addr,
                plan.listener.shards,
                plan.listener
                    .effective_quic_max_datagram_size(config.quic.max_datagram_size),
                &unavailable_http3_addrs,
            )
            .await?;
            plan.listener.listen_addr = bound_addr;
            unavailable_http3_addrs.push(bound_addr);
            listen_addrs.extend(std::iter::repeat_n(bound_addr, plan.listener.shards));
            let listener_metrics = metrics.register_listener(
                bound_addr,
                plan.listener.transport.as_str(),
                listener_auth_label(&plan.listener),
                plan.listener.shards,
                first_socket.udp_gso_enabled(),
                first_socket.udp_gro_enabled(),
            );
            shared
                .shard_metrics
                .write()
                .expect("shard metrics list poisoned")
                .extend(listener_metrics.iter().cloned());

            let (forward_rx, tun_rx) = inboxes
                .next()
                .expect("one inbox pair was created per planned shard");
            shards.push(Shard::from_socket(
                shards.len(),
                0,
                Arc::clone(&shared),
                Arc::clone(&config),
                plan.listener.clone(),
                listener_auth.as_ref().map(Arc::clone),
                first_socket,
                Arc::clone(&listener_metrics[0]),
                forward_rx,
                tun_rx,
            )?);

            for (listener_shard_index, shard_metrics) in listener_metrics.iter().enumerate().skip(1)
            {
                let (forward_rx, tun_rx) = inboxes
                    .next()
                    .expect("one inbox pair was created per planned shard");
                shards.push(
                    Shard::bind(
                        shards.len(),
                        listener_shard_index,
                        Arc::clone(&shared),
                        Arc::clone(&config),
                        plan.listener.clone(),
                        listener_auth.as_ref().map(Arc::clone),
                        Arc::clone(shard_metrics),
                        forward_rx,
                        tun_rx,
                    )
                    .await?,
                );
            }
        }

        let observability = match config.observability.listen_addr {
            Some(addr) => Some(ObservabilityServer::bind(addr, Arc::clone(&metrics)).await?),
            None => None,
        };

        info!(
            http3_shards = total_shards,
            http2_listeners = http2_listeners.len(),
            "server ready"
        );
        Ok(Self {
            shards,
            http2_listeners,
            listen_addrs,
            shared,
            metrics,
            observability,
        })
    }

    /// The address every shard actually bound, in shard order.
    ///
    /// A listener configured on port `0` takes whichever port the kernel had
    /// free. This is the programmatic way to learn it; the live `listening` log
    /// reports it too. Shards of one listener share an address and repeat here.
    pub fn listen_addrs(&self) -> Vec<SocketAddr> {
        self.listen_addrs.clone()
    }

    /// Bound observability address, including a kernel-selected test port.
    pub fn observability_addr(&self) -> Option<SocketAddr> {
        self.observability
            .as_ref()
            .and_then(|server| server.local_addr().ok())
    }

    /// Reload TLS material and active Basic/certificate credentials whenever
    /// `SIGHUP` arrives.
    ///
    /// One task owns the transaction for the whole server. The new certificate
    /// pair and roster are fully parsed before either shared snapshot changes;
    /// new handshakes then pick up the TLS generation immediately, while
    /// established connections retain the identity they negotiated.
    #[cfg(unix)]
    fn spawn_config_reloader(shared: Arc<Shared>) {
        if shared.config_reload.is_none() {
            return;
        }

        tokio::spawn(async move {
            let mut sighup =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                    Ok(signal) => signal,
                    Err(e) => {
                        warn!(%e, "cannot listen for SIGHUP; configuration reload is unavailable");
                        return;
                    }
                };

            while sighup.recv().await.is_some() {
                let reloads_roster = shared
                    .config_reload
                    .as_ref()
                    .is_some_and(|reload| reload.client_cert_enabled);
                match reload_configuration(&shared) {
                    Ok(outcome) => {
                        shared.metrics.record_tls_reload(true);
                        if reloads_roster {
                            shared.metrics.record_roster_reload(true);
                        }
                        if outcome.roster.is_some() || outcome.basic.is_some() {
                            let (roster_generation, clients) = outcome.roster.unwrap_or((0, 0));
                            let (basic_listeners, basic_users) = outcome.basic.unwrap_or((0, 0));
                            info!(
                                tls_generation = outcome.tls_generation,
                                roster_generation,
                                clients,
                                basic_listeners,
                                basic_users,
                                "TLS identity and authentication state reloaded"
                            );
                        } else {
                            info!(
                                tls_generation = outcome.tls_generation,
                                "TLS identity reloaded"
                            );
                        }
                    }
                    Err(e) => {
                        shared.metrics.record_tls_reload(false);
                        if reloads_roster {
                            shared.metrics.record_roster_reload(false);
                        }
                        warn!(
                            error = %format!("{e:#}"),
                            "configuration reload failed, keeping the previous TLS identity and authentication state"
                        )
                    }
                }
            }
        });
    }

    #[cfg(not(unix))]
    fn spawn_config_reloader(_shared: Arc<Shared>) {}

    /// Run every shard until they all stop.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let watchdog_timeout =
            systemd::watchdog_timeout().context("invalid systemd watchdog environment")?;
        Self::spawn_config_reloader(Arc::clone(&self.shared));

        // Install one process-wide signal listener before any shard starts.
        // Every shard receives the same latched watch value, so one SIGINT or
        // SIGTERM starts every drain even if a shard was not polling its event
        // loop at the instant the signal arrived.
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let shutdown_listener = spawn_shutdown_notifier(shutdown_tx.clone())
            .context("failed to install shutdown signal handlers")?;
        debug!("shutdown signal handlers installed");

        let observability_task = self.observability.take().map(ObservabilityServer::spawn);
        self.metrics.set_ready(true);
        let watchdog_task = watchdog_timeout.map(|timeout| {
            spawn_systemd_watchdog(timeout, Arc::clone(&self.metrics), shutdown_rx.clone())
        });
        if let Err(error) = systemd::notify("READY=1\nSTATUS=Ready to serve MASQUE traffic") {
            self.metrics.begin_shutdown();
            shutdown_listener.abort();
            if let Some(task) = observability_task {
                task.abort();
            }
            if let Some(task) = watchdog_task {
                task.abort();
            }
            return Err(error).context("failed to notify systemd that the server is ready");
        }

        // Readiness becomes false as soon as draining starts, while /healthz
        // and /metrics remain available until every shard has stopped.
        let mut readiness_shutdown = shutdown_rx.clone();
        let readiness_metrics = Arc::clone(&self.metrics);
        let readiness_task = tokio::spawn(async move {
            if readiness_shutdown
                .wait_for(|requested| *requested)
                .await
                .is_ok()
                && readiness_metrics.begin_shutdown()
                && let Err(error) = systemd::notify("STOPPING=1\nSTATUS=Draining connections")
            {
                warn!(%error, "failed to notify systemd that the server is stopping");
            }
        });

        // Preserve the hot-path shape used by the common one-listener,
        // one-shard HTTP/3 deployment. Running that shard on the caller avoids
        // an otherwise unnecessary Tokio task boundary and keeps HTTP/2 support
        // from perturbing existing throughput.
        if self.http2_listeners.is_empty() && self.shards.len() == 1 {
            let outcome = self.shards[0].run(shutdown_rx).await;
            if self.metrics.begin_shutdown()
                && let Err(error) = systemd::notify("STOPPING=1\nSTATUS=Stopping")
            {
                warn!(%error, "failed to notify systemd that the server is stopping");
            }
            let _ = shutdown_tx.send(true);
            shutdown_listener.abort();
            readiness_task.abort();
            if let Some(task) = observability_task {
                task.abort();
            }
            if let Some(task) = watchdog_task {
                task.abort();
            }
            return outcome;
        }

        let mut tasks = tokio::task::JoinSet::new();
        if self.shards.is_empty() && self.shared.tun.is_some() {
            let shared = Arc::clone(&self.shared);
            let shutdown_rx = shutdown_rx.clone();
            tasks.spawn(async move {
                let result = run_http2_tun_dispatcher(shared, shutdown_rx).await;
                ("HTTP/2 TUN dispatcher".to_string(), result)
            });
        }
        for mut shard in self.shards.drain(..) {
            let shutdown_rx = shutdown_rx.clone();
            tasks.spawn(async move {
                let index = shard.index;
                let result = shard.run(shutdown_rx).await;
                (format!("HTTP/3 shard {index}"), result)
            });
        }
        for listener in self.http2_listeners.drain(..) {
            let shutdown_rx = shutdown_rx.clone();
            let addr = listener.local_addr();
            tasks.spawn(async move {
                let result = listener.run(shutdown_rx).await;
                (format!("HTTP/2 listener {addr}"), result)
            });
        }

        let mut outcome = Ok(());
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((worker, Err(error))) => {
                    error!(%worker, %error, "proxy worker exited with an error");
                    if outcome.is_ok() {
                        outcome = Err(error);
                    }
                    if !*shutdown_tx.borrow() {
                        warn!(%worker, "draining remaining workers after an unexpected exit");
                        let _ = shutdown_tx.send(true);
                    }
                }
                Ok((_, Ok(()))) => {}
                Err(error) => {
                    error!(%error, "proxy worker task panicked");
                    if outcome.is_ok() {
                        outcome = Err(anyhow::anyhow!("proxy worker task panicked: {error}"));
                    }
                    if !*shutdown_tx.borrow() {
                        warn!("draining remaining workers after an unexpected exit");
                        let _ = shutdown_tx.send(true);
                    }
                }
            }
        }
        if self.metrics.begin_shutdown()
            && let Err(error) = systemd::notify("STOPPING=1\nSTATUS=Stopping")
        {
            warn!(%error, "failed to notify systemd that the server is stopping");
        }
        let _ = shutdown_tx.send(true);
        shutdown_listener.abort();
        readiness_task.abort();
        if let Some(task) = observability_task {
            task.abort();
        }
        if let Some(task) = watchdog_task {
            task.abort();
        }
        outcome
    }
}

/// Ping systemd only while every proxy worker is making progress. If one worker
/// stops completing its once-per-second heartbeat, readiness fails and pings
/// are withheld so `WatchdogSec` can restart the process.
fn spawn_systemd_watchdog(
    timeout: Duration,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let interval = systemd::watchdog_ping_interval(timeout);
    info!(
        timeout_secs = timeout.as_secs_f64(),
        ping_interval_secs = interval.as_secs_f64(),
        "systemd watchdog enabled"
    );

    tokio::spawn(async move {
        let start = tokio::time::Instant::now() + interval;
        let mut ticker = tokio::time::interval_at(start, interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut withheld = false;

        loop {
            tokio::select! {
                result = shutdown.wait_for(|requested| *requested) => {
                    let _ = result;
                    return;
                }
                _ = ticker.tick() => {
                    if !metrics.is_ready() {
                        if !withheld {
                            warn!("withholding systemd watchdog ping because a shard is stale");
                            withheld = true;
                        }
                        continue;
                    }

                    withheld = false;
                    match systemd::notify("WATCHDOG=1") {
                        Ok(true) => {}
                        Ok(false) => warn!("WATCHDOG_USEC is set but NOTIFY_SOCKET is absent"),
                        Err(error) => warn!(%error, "failed to ping systemd watchdog"),
                    }
                }
            }
        }
    })
}

/// Register one listener for the process shutdown signals and latch the result
/// into a watch channel shared by every shard.
///
/// Keeping the task alive after the first signal means a second signal is not
/// silently swallowed while the bounded drain is still in progress. systemd
/// will still enforce `TimeoutStopSec` and send SIGKILL if that bound is ever
/// exceeded.
#[cfg(unix)]
fn spawn_shutdown_notifier(
    shutdown_tx: watch::Sender<bool>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    Ok(tokio::spawn(async move {
        let mut requested = false;
        loop {
            let signal = tokio::select! {
                _ = sigint.recv() => "SIGINT",
                _ = sigterm.recv() => "SIGTERM",
            };

            if requested {
                warn!(
                    signal,
                    "additional shutdown signal received; drain already in progress"
                );
                continue;
            }

            requested = true;
            info!(signal, "shutdown signal received, draining shards");
            if shutdown_tx.send(true).is_err() {
                return;
            }
        }
    }))
}

#[cfg(not(unix))]
fn spawn_shutdown_notifier(
    shutdown_tx: watch::Sender<bool>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    Ok(tokio::spawn(async move {
        let mut requested = false;
        loop {
            if let Err(error) = tokio::signal::ctrl_c().await {
                error!(%error, "cannot listen for Ctrl-C; shutting down safely");
                let _ = shutdown_tx.send(true);
                return;
            }

            if requested {
                warn!("additional Ctrl-C received; drain already in progress");
                continue;
            }

            requested = true;
            info!(
                signal = "Ctrl-C",
                "shutdown signal received, draining shards"
            );
            if shutdown_tx.send(true).is_err() {
                return;
            }
        }
    }))
}

/// Resolve the configured shard count, where 0 means "one per core".
fn resolve_shard_count(configured: usize) -> usize {
    if configured > 0 {
        return configured.min(MAX_SHARDS);
    }
    if !cfg!(target_os = "linux") {
        return 1;
    }
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .min(MAX_SHARDS)
}

struct ReloadOutcome {
    tls_generation: u64,
    roster: Option<(u64, usize)>,
    basic: Option<(usize, usize)>,
}

/// Re-read and atomically install reloadable configuration state.
///
/// The effective startup certificate paths are read again, which covers ACME
/// replacing files or symlink targets. Listener addresses, authentication
/// modes, pools, and protocol tuning remain fixed until restart. Basic
/// credentials and an active client-certificate roster are prepared in the
/// same transaction. Every fallible step finishes before a shared snapshot
/// changes.
fn reload_configuration(shared: &Shared) -> anyhow::Result<ReloadOutcome> {
    let Some(reload) = shared.config_reload.as_ref() else {
        anyhow::bail!("no configuration file to reload");
    };

    let text = std::fs::read_to_string(&reload.path)
        .with_context(|| format!("failed to read {}", reload.path.display()))?;
    let config = crate::config::parse_toml(&text)
        .with_context(|| format!("failed to parse {}", reload.path.display()))?;

    if config.listeners.len() != reload.listeners.len() {
        anyhow::bail!(
            "refusing to reload: listener count changed from {} to {}; adding or removing a \
             listener requires a restart",
            reload.listeners.len(),
            config.listeners.len()
        );
    }
    let mut basic_auth = Vec::with_capacity(config.listeners.len());
    for (index, (startup, current)) in reload
        .listeners
        .iter()
        .zip(config.listeners.iter())
        .enumerate()
    {
        let current_auth = ReloadAuthKind::from(&current.auth);
        if startup.listen_addr != current.listen_addr
            || startup.transport != current.transport
            || startup.auth != current_auth
            || startup.stealth != current.auth.stealth_enabled()
        {
            anyhow::bail!(
                "refusing to reload listener {}: address, transport, order, authentication \
                 mode, or stealth setting changed; restart the service to apply trust-boundary \
                 changes",
                index + 1
            );
        }
        basic_auth.push(
            (startup.auth == ReloadAuthKind::Basic)
                .then(|| {
                    BasicAuthenticator::from_section(&current.auth)
                        .with_context(|| format!("listener {} Basic credentials", index + 1))
                })
                .transpose()?,
        );
    }
    let tls_identity =
        tls::TlsIdentity::load(&reload.tls).context("failed to load replacement TLS identity")?;

    let registry = if reload.client_cert_enabled {
        let any_client_cert = any_client_cert_listener(&config);
        if !any_client_cert {
            anyhow::bail!(
                "refusing to reload: no listener uses auth.mode = \"client_cert\" any more, \
                 which cannot be changed without a restart"
            );
        }
        Some(active_client_registry(&config, any_client_cert)?)
    } else {
        None
    };

    // Reservations are the final fallible operation and replace themselves
    // transactionally. Once this succeeds, both shared snapshot swaps below
    // are infallible.
    if reload.ip_proxy_enabled
        && let Some(registry) = &registry
    {
        shared
            .address_pool
            .lock()
            .expect("address pool poisoned")
            .set_static_reservations(registry.static_reservations())
            .map_err(|e| {
                anyhow::anyhow!(
                    "refusing to reload: a pinned client address cannot be reserved ({e})"
                )
            })?;
    }

    let mut basic_listener_count = 0;
    let mut basic_user_count = 0;
    for (replacement, target) in basic_auth.into_iter().zip(&shared.basic_auth) {
        match (replacement, target) {
            (Some(replacement), Some(target)) => {
                basic_listener_count += 1;
                basic_user_count += target.replace(replacement);
            }
            (None, None) => {}
            _ => unreachable!("startup Basic-auth slots match the captured reload plan"),
        }
    }
    let basic = (basic_listener_count > 0).then_some((basic_listener_count, basic_user_count));

    let roster = registry.map(|registry| {
        let count = registry.len();
        (shared.clients.replace(registry), count)
    });
    let tls_generation = shared.tls.replace(tls_identity);
    Ok(ReloadOutcome {
        tls_generation,
        roster,
        basic,
    })
}

/// Take every address pinned to `identity`, or none of them.
///
/// All or nothing: a client configured for dual stack that came up with only
/// half its addresses would silently lose one family, which is harder to
/// diagnose than a refused tunnel.
fn claim_static_addresses(
    shared: &Shared,
    identity: &ClientIdentity,
) -> Result<Vec<IpAddr>, PoolError> {
    let mut pool = shared.address_pool.lock().expect("address pool poisoned");
    let mut claimed = Vec::new();

    for addr in identity.static_addresses() {
        if let Err(e) = pool.claim(addr, &identity.key) {
            pool.release_all(&claimed);
            return Err(e);
        }
        claimed.push(addr);
    }

    Ok(claimed)
}

/// Take one address per configured family from the dynamic pool.
///
/// A family whose pool is absent or exhausted is skipped: a v4-only pool should
/// still produce a working v4 tunnel.
fn allocate_pool_addresses(shared: &Shared) -> Vec<IpAddr> {
    let mut pool = shared.address_pool.lock().expect("address pool poisoned");
    let mut addresses = Vec::with_capacity(2);

    if let Ok(v4) = pool.allocate_v4() {
        addresses.push(IpAddr::V4(v4));
    }
    if let Ok(v6) = pool.allocate_v6() {
        addresses.push(IpAddr::V6(v6));
    }

    addresses
}

/// Encode the address and default-route capsules shared by HTTP/2 and HTTP/3
/// CONNECT-IP setup.
fn encode_ip_setup_capsules(addresses: &[IpAddr]) -> Vec<u8> {
    let assigned = addresses
        .iter()
        .map(|ip| match *ip {
            IpAddr::V4(ip) => AssignedAddress {
                request_id: 0,
                ip: IpAddress::V4(ip),
                prefix_len: 32,
            },
            IpAddr::V6(ip) => AssignedAddress {
                request_id: 0,
                ip: IpAddress::V6(ip),
                prefix_len: 128,
            },
        })
        .collect();

    let mut capsules = Vec::new();
    capsule::encoder::encode(&CapsuleFrame::AddressAssign(assigned), &mut capsules);
    capsule::encoder::encode(
        &CapsuleFrame::RouteAdvertisement(vec![
            IpAddressRange {
                start: IpAddress::V4(std::net::Ipv4Addr::UNSPECIFIED),
                end: IpAddress::V4(std::net::Ipv4Addr::BROADCAST),
                ip_protocol: 0,
            },
            IpAddressRange {
                start: IpAddress::V6(std::net::Ipv6Addr::UNSPECIFIED),
                end: IpAddress::V6(std::net::Ipv6Addr::new(
                    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
                )),
                ip_protocol: 0,
            },
        ]),
        &mut capsules,
    );
    capsules
}

/// Build the complete QUIC configuration used by both preflight validation and
/// live shards.
fn build_quic_config(
    config: &ServerConfig,
    max_datagram_size: usize,
    client_certs: Option<Arc<SharedRoster>>,
    tls_identity: Arc<tls::SharedTlsIdentity>,
) -> anyhow::Result<quiche::Config> {
    // quiche's file-loading API fixes one identity into the context. Building
    // the context directly lets the ClientHello callback select the current
    // shared identity for every new connection while existing QUIC state keeps
    // the identity it already negotiated.
    let mut builder = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls())
        .map_err(|e| anyhow::anyhow!("failed to create TLS context: {e}"))?;
    // CONNECT, CONNECT-UDP, and CONNECT-IP all create externally observable
    // side effects and therefore must never be accepted as replayable 0-RTT
    // data. Keep resumption, but lock Early Data off explicitly rather than
    // relying on quiche's current default.
    tls::disable_early_data(&mut builder);
    tls::configure_dynamic_identity(&mut builder, tls_identity);
    if let Some(roster) = client_certs {
        // quiche's normal peer verification cannot express the self-signed,
        // public-key roster, so install the
        // same custom verifier HTTP/2 uses.
        configure_client_cert_verification(&mut builder, roster);
    }
    let mut quic_config =
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder)
            .map_err(|e| anyhow::anyhow!("failed to build QUIC config: {e}"))?;

    quic_config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;

    let idle_timeout_ms = config
        .server
        .idle_timeout_secs
        .checked_mul(1000)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "server.idle_timeout_secs ({}) is too large",
                config.server.idle_timeout_secs
            )
        })?;

    // Transport parameters.
    quic_config.set_max_idle_timeout(idle_timeout_ms);
    quic_config.set_max_recv_udp_payload_size(max_datagram_size);
    quic_config.set_max_send_udp_payload_size(max_datagram_size);
    quic_config.set_initial_max_data(config.quic.initial_max_data);
    quic_config.set_initial_max_stream_data_bidi_local(config.quic.initial_max_stream_data);
    quic_config.set_initial_max_stream_data_bidi_remote(config.quic.initial_max_stream_data);
    quic_config.set_initial_max_stream_data_uni(config.quic.initial_max_stream_data);
    quic_config.set_initial_max_streams_bidi(config.quic.initial_max_streams_bidi);
    quic_config.set_initial_max_streams_uni(100);
    quic_config.set_max_connection_window(config.quic.max_connection_window);
    quic_config.set_max_stream_window(config.quic.max_stream_window);
    // Keep peer-address migration an explicit, tested part of the transport
    // contract rather than inheriting whatever a future quiche default does.
    // One spare CID is enough for a client to validate a replacement path;
    // retired IDs are replenished while the connection is alive.
    quic_config.set_disable_active_migration(false);
    quic_config.set_active_connection_id_limit(ACTIVE_CONNECTION_ID_LIMIT);
    quic_config.set_disable_dcid_reuse(false);
    quic_config.set_path_challenge_recv_max_queue_len(PATH_CHALLENGE_RECV_QUEUE_LEN);
    quic_config.enable_pacing(true);
    quic_config.discover_pmtu(config.quic.discover_pmtu);

    quic_config
        .set_cc_algorithm_name(&config.quic.cc_algorithm)
        .map_err(|_| {
            anyhow::anyhow!(
                "unknown quic.cc_algorithm {:?} (expected cubic, reno, or bbr2)",
                config.quic.cc_algorithm
            )
        })?;
    quic_config
        .set_initial_congestion_window_packets(config.quic.initial_congestion_window_packets);

    if config.quic.enable_dgram {
        quic_config.enable_dgram(
            true,
            config.quic.dgram_recv_queue_len,
            config.quic.dgram_send_queue_len,
        );
    }

    Ok(quic_config)
}

fn build_h3_config() -> anyhow::Result<quiche::h3::Config> {
    let mut h3_config = quiche::h3::Config::new()?;
    h3_config.set_max_field_section_size(8192);
    h3_config.enable_extended_connect(true);
    Ok(h3_config)
}

/// Create the TUN device if the IP proxy is enabled.
fn build_tun(config: &ServerConfig) -> anyhow::Result<Option<TunManager>> {
    if !config.ip_proxy.enabled {
        return Ok(None);
    }

    // Parse pool CIDRs to get the gateway address (network + 1) that we assign
    // to the TUN device itself.
    let (v4_gw, v4_prefix) = if !config.ip_proxy.ipv4_pool.is_empty() {
        let net: ipnet::Ipv4Net = config
            .ip_proxy
            .ipv4_pool
            .parse()
            .map_err(|e| anyhow::anyhow!("bad v4 pool: {e}"))?;
        let gw_bits = u32::from(net.network()) | 1;
        (Some(std::net::Ipv4Addr::from(gw_bits)), net.prefix_len())
    } else {
        (None, 0)
    };

    let (v6_gw, v6_prefix) = if !config.ip_proxy.ipv6_pool.is_empty() {
        let net: ipnet::Ipv6Net = config
            .ip_proxy
            .ipv6_pool
            .parse()
            .map_err(|e| anyhow::anyhow!("bad v6 pool: {e}"))?;
        let gw_bits = u128::from(net.network()) | 1;
        (Some(std::net::Ipv6Addr::from(gw_bits)), net.prefix_len())
    } else {
        (None, 0)
    };

    match TunManager::new(
        &config.ip_proxy.tun_name,
        config.ip_proxy.tun_mtu as u16,
        v4_gw,
        v4_prefix,
        v6_gw,
        v6_prefix,
        config.ip_proxy.tun_offload,
    ) {
        Ok(tun) => Ok(Some(tun)),
        Err(e) => {
            warn!(%e, "failed to create TUN device — CONNECT-IP will be unavailable");
            Ok(None)
        }
    }
}

/// Own the shared TUN read side when a process has HTTP/2 listeners but no
/// HTTP/3 shard. In a mixed deployment HTTP/3 shard zero already performs this
/// job and dispatches HTTP/2-owned packets through `relay_http2_tun_packet`.
async fn run_http2_tun_dispatcher(
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let tun = shared
        .tun
        .as_ref()
        .expect("HTTP/2 TUN dispatcher requires a configured device");
    let device = tun.device();
    let mut batch = TunRecvBatch::new(tun.mtu());

    loop {
        let received = tokio::select! {
            result = shutdown.wait_for(|requested| *requested) => {
                let _ = result;
                return Ok(());
            }
            result = tun::recv_batch(&device, &mut batch) => result,
        };

        let segments = match received {
            Ok(segments) => segments,
            Err(error) => {
                error!(%error, "HTTP/2 TUN receive failed");
                continue;
            }
        };
        for index in 0..segments.min(MAX_TUN_RECV_BATCH) {
            let Some(packet) = batch.packet(index) else {
                break;
            };
            let destination = match ip_packet::dst_addr(packet) {
                Ok(destination) => destination,
                Err(error) => {
                    debug!(%error, "invalid IP header from TUN");
                    continue;
                }
            };
            let owner = shared
                .routing_table
                .read()
                .expect("routing table poisoned")
                .lookup(&destination)
                .copied();
            if let Some(owner) = owner {
                shared.relay_http2_tun_packet(owner, packet);
            }
        }
    }
}

/// Wait for the target socket to be readable, then drain a batch of datagrams.
async fn recv_target_batch(
    socket: &UdpSocket,
    batch: &mut TargetRecvBatch,
) -> std::io::Result<usize> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        use tokio::io::Interest;

        socket
            .async_io(Interest::READABLE, || {
                target_udp::recv_mmsg(socket.as_raw_fd(), batch)
            })
            .await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let len = socket.recv(batch.first_mut()).await?;
        batch.set_single(len);
        Ok(1)
    }
}

/// A QUIC packet that arrived on the wrong shard's socket.
struct ForwardedPacket {
    data: Vec<u8>,
    from: SocketAddr,
}

/// A receive batch handed to the shard that owns its connection IDs.
///
/// `_slots` accounts every packet rather than every channel item, preserving
/// the original queue's memory bound after packets are coalesced into batches.
struct ForwardedPacketBatch {
    packets: Vec<ForwardedPacket>,
    bytes: usize,
    _slots: OwnedSemaphorePermit,
}

#[derive(Default)]
struct PendingForwardBatch {
    packets: Vec<ForwardedPacket>,
    bytes: usize,
}

impl PendingForwardBatch {
    fn push(&mut self, packet: &[u8], from: SocketAddr) {
        self.bytes += packet.len();
        self.packets.push(ForwardedPacket {
            data: packet.to_vec(),
            from,
        });
    }
}

struct PacketOutput<'a> {
    stateless: &'a mut [u8],
    stateless_batch: &'a mut SendPacketBatch,
    stateless_retries: &'a mut usize,
    forward_batches: &'a mut [PendingForwardBatch],
}

/// Immutable facts that govern SIGHUP reloads.
struct ConfigReload {
    path: std::path::PathBuf,
    /// Effective startup paths. ACME may replace their contents or symlink
    /// targets, but changing the paths themselves still needs a restart so CLI
    /// overrides cannot silently disappear on reload.
    tls: TlsSection,
    /// Whether the bound TLS context actually requests client certificates.
    client_cert_enabled: bool,
    /// The IP proxy state this process actually bound with. The value in a
    /// subsequently edited file is intentionally ignored until restart.
    ip_proxy_enabled: bool,
    /// Listener identity and trust boundary captured before sockets are bound.
    /// Basic credentials may change in place; address, transport, order, and
    /// authentication mode still require a restart.
    listeners: Vec<ReloadListener>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReloadAuthKind {
    Disabled,
    Basic,
    ClientCert,
}

impl From<&AuthSection> for ReloadAuthKind {
    fn from(auth: &AuthSection) -> Self {
        if auth.basic_enabled() {
            Self::Basic
        } else if auth.client_cert_enabled() {
            Self::ClientCert
        } else {
            Self::Disabled
        }
    }
}

struct ReloadListener {
    listen_addr: SocketAddr,
    transport: ListenerTransport,
    auth: ReloadAuthKind,
    stealth: bool,
}

/// State every shard shares.
///
/// None of it is on the per-packet path: the pool and routing table are touched
/// only when a CONNECT-IP tunnel opens or closes or when a TUN packet needs an
/// owner, and the ownership maps only when a connection is created or
/// destroyed, or one of its connection IDs is published or retired.
struct Shared {
    resolver: ResolverBudget,
    address_pool: Mutex<AddressPool>,
    routing_table: RwLock<RoutingTable>,
    /// Which shard owns each server-issued connection ID. Consulted when a
    /// packet lands on a shard that does not know the connection, which is what
    /// a client migrating to a new address looks like.
    cid_shard: RwLock<FxHashMap<quiche::ConnectionId<'static>, usize>>,
    /// Which shard owns each connection index, for routing TUN packets.
    index_shard: RwLock<FxHashMap<u64, usize>>,
    /// Bounded return path for CONNECT-IP streams owned by HTTP/2 tasks.
    ///
    /// An owner is present in exactly one of `index_shard` or this map. That
    /// keeps the common HTTP/3 lookup unchanged while allowing the one shared
    /// TUN reader to dispatch packets across transports.
    http2_tun_routes: RwLock<FxHashMap<TunnelOwner, Http2TunRoute>>,
    /// Monotonically increasing connection index used as the conn_id in
    /// TunnelOwner (since quiche ConnectionId is not easily hashable).
    ///
    /// Indices are never reused — and are unique across shards — so a route
    /// left behind by a torn-down tunnel can never resolve to a later
    /// connection.
    next_conn_index: AtomicU64,
    /// Key for deriving a server connection ID from a client's DCID.
    ///
    /// Generated per-process, so a client cannot precompute which server
    /// connection ID — or which hash bucket — its DCID will map to.
    conn_id_key: ring::hmac::Key,
    /// Authenticated address-validation tokens shared by every QUIC shard.
    retry_tokens: retry::RetryTokenCodec,
    /// Process-wide connection budget keyed by canonical source IP.
    source_admissions: SourceAdmissionLimiter,
    /// Fair-share bound for queued or running Basic credential checks.
    auth_source_admissions: SourceAdmissionLimiter,
    /// Shared TUN device for CONNECT-IP tunnels (None if IP proxy disabled).
    tun: Option<TunManager>,
    /// Inbox per shard for packets forwarded after a migration.
    forward_tx: Vec<mpsc::Sender<ForwardedPacketBatch>>,
    /// Packet-count permits for each forward inbox. Batching changes the
    /// number of channel items but must not increase queued packet memory.
    forward_slots: Vec<Arc<Semaphore>>,
    /// Inbox per shard for TUN packets belonging to its connections.
    tun_tx: Vec<mpsc::Sender<Vec<u8>>>,
    /// Bounds how many password verifications run at once.
    ///
    /// Argon2id is memory-hard on purpose, so unbounded concurrency would let
    /// unauthenticated requests turn into hundreds of megabytes and cores of
    /// work. The old inline check bounded this at one per shard by blocking
    /// the event loop; this keeps a bound without the stall.
    ///
    /// Sized from the shards that verify passwords, so adding a
    /// client-certificate listener does not widen what a Basic one will accept.
    auth_permits: Arc<Semaphore>,
    /// Bounds both queued and running password verifications across all shards.
    auth_queue_slots: Arc<Semaphore>,
    /// One atomically replaceable Basic credential set per configured
    /// listener. Non-Basic listeners keep an empty slot so configuration order
    /// remains a stable reload key.
    basic_auth: Vec<Option<Arc<SharedBasicAuthenticator>>>,
    /// Pre-registered client identities, shared by every shard's TLS context.
    ///
    /// Replaceable at runtime so a client can be revoked without restarting
    /// the process and dropping every other client's tunnel.
    clients: Arc<SharedRoster>,
    /// Parsed certificate chain and private key selected by new TLS handshakes.
    /// Existing connections pin the identity they started with.
    tls: Arc<tls::SharedTlsIdentity>,
    /// Present when the server started from a config file. Captured startup
    /// state keeps reload limited to TLS material and already-active
    /// authentication modes.
    config_reload: Option<ConfigReload>,
    /// Process-wide counters and readiness state.
    metrics: Arc<Metrics>,
    /// Metric owner for each global shard index. Read only on a queue-drop
    /// path so a cross-listener handoff is attributed to its destination.
    shard_metrics: RwLock<Vec<Arc<ShardMetrics>>>,
}

impl Shared {
    fn record_shard_queue_drop(&self, shard: usize, packets: usize) {
        if let Some(metrics) = self
            .shard_metrics
            .read()
            .expect("shard metrics list poisoned")
            .get(shard)
        {
            metrics.record_shard_queue_drop(packets);
        }
    }

    fn record_cross_shard_forward(&self, shard: usize, packets: usize, bytes: usize) {
        if let Some(metrics) = self
            .shard_metrics
            .read()
            .expect("shard metrics list poisoned")
            .get(shard)
        {
            metrics.record_cross_shard_forward(packets, bytes);
        }
    }

    fn record_tun_queue_drop(&self, shard: usize) {
        if let Some(metrics) = self
            .shard_metrics
            .read()
            .expect("shard metrics list poisoned")
            .get(shard)
        {
            metrics.record_tun_queue_drop();
        }
    }

    /// Hand one TUN packet to an HTTP/2 CONNECT-IP task without waiting for
    /// stream flow control. Returns false when `owner` belongs to HTTP/3 (or
    /// has already disappeared), so the shard can continue its normal path.
    fn relay_http2_tun_packet(&self, owner: TunnelOwner, packet: &[u8]) -> bool {
        let route = self
            .http2_tun_routes
            .read()
            .expect("HTTP/2 TUN routes poisoned")
            .get(&owner)
            .cloned();
        let Some(route) = route else {
            return false;
        };

        match route.sender.try_reserve() {
            Ok(permit) => permit.send(packet.to_vec()),
            Err(_) => {
                route.metrics.record_tun_queue_drop();
                debug!(
                    conn_id = owner.conn_id,
                    stream_id = owner.stream_id,
                    "HTTP/2 TUN queue full, dropping packet"
                );
            }
        }
        true
    }
}

/// One shard: an independent event loop over its own share of connections.
struct Shard {
    index: usize,
    /// Listener-local socket index encoded into server CIDs on a reuseport
    /// listener. `None` keeps all 128 CID bits random for a single shard.
    reuseport_index: Option<u8>,
    shared: Arc<Shared>,
    /// Counters owned by this shard and aggregated per listener while scraping.
    metrics: Arc<ShardMetrics>,
    socket: QuicUdpSocket,
    quic_config: quiche::Config,
    h3_config: quiche::h3::Config,
    connections: FxHashMap<quiche::ConnectionId<'static>, ClientConnection>,
    /// Additional server-issued CIDs mapped back to the stable connection-map
    /// key. The initial CID stays on the one-lookup hot path above.
    connection_id_aliases: FxHashMap<quiche::ConnectionId<'static>, quiche::ConnectionId<'static>>,
    auth: Option<Arc<SharedBasicAuthenticator>>,
    /// Whether failed Basic authorization uses the ordinary empty 404.
    stealth_auth: bool,
    /// Set when clients authenticate with a certificate instead of credentials.
    ///
    /// The TLS context already refuses unregistered keys, so this exists to
    /// attach the resolved identity to the connection and as a second check
    /// that no connection slips through without one.
    client_certs: Option<Arc<SharedRoster>>,
    tcp_policy: TargetPolicy,
    udp_policy: TargetPolicy,
    /// Effective QUIC packet ceiling for this listener. This is copied out of
    /// the resolved listener so the datagram hot path does not repeatedly
    /// consult an optional override.
    max_datagram_size: usize,
    config: Arc<ServerConfig>,
    /// Reverse index for routing TUN packets without scanning every connection.
    conn_by_index: FxHashMap<u64, quiche::ConnectionId<'static>>,
    udp_response_tx: mpsc::Sender<UdpResponse>,
    udp_response_rx: mpsc::Receiver<UdpResponse>,
    udp_setup_tx: mpsc::Sender<UdpSetupResult>,
    udp_setup_rx: mpsc::Receiver<UdpSetupResult>,
    tcp_event_tx: mpsc::Sender<TcpRelayEvent>,
    tcp_event_rx: mpsc::Receiver<TcpRelayEvent>,
    forward_rx: mpsc::Receiver<ForwardedPacketBatch>,
    tun_rx: mpsc::Receiver<Vec<u8>>,
    auth_tx: mpsc::Sender<AuthOutcome>,
    auth_rx: mpsc::Receiver<AuthOutcome>,
    /// Connections with work pending in the current event-loop round.
    dirty: DirtySet,
    /// Connections ordered by their next QUIC or pacing deadline.
    timers: TimerQueue,
}

impl Shard {
    /// Build one shard and bind its socket.
    #[allow(clippy::too_many_arguments)]
    async fn bind(
        index: usize,
        listener_shard_index: usize,
        shared: Arc<Shared>,
        config: Arc<ServerConfig>,
        listener: ResolvedListener,
        auth: Option<Arc<SharedBasicAuthenticator>>,
        metrics: Arc<ShardMetrics>,
        forward_rx: mpsc::Receiver<ForwardedPacketBatch>,
        tun_rx: mpsc::Receiver<Vec<u8>>,
    ) -> anyhow::Result<Self> {
        let max_datagram_size =
            listener.effective_quic_max_datagram_size(config.quic.max_datagram_size);
        let socket = open_quic_socket(
            &config,
            listener.listen_addr,
            listener.shards,
            max_datagram_size,
        )
        .await?;
        Self::from_socket(
            index,
            listener_shard_index,
            shared,
            config,
            listener,
            auth,
            socket,
            metrics,
            forward_rx,
            tun_rx,
        )
    }

    /// Build one shard around a socket that has already been bound.
    ///
    /// The first shard takes this path because an ephemeral listener has to
    /// inspect the kernel-selected port before the rest of its reuseport group
    /// is opened.
    #[allow(clippy::too_many_arguments)]
    fn from_socket(
        index: usize,
        listener_shard_index: usize,
        shared: Arc<Shared>,
        config: Arc<ServerConfig>,
        listener: ResolvedListener,
        auth: Option<Arc<SharedBasicAuthenticator>>,
        socket: QuicUdpSocket,
        metrics: Arc<ShardMetrics>,
        forward_rx: mpsc::Receiver<ForwardedPacketBatch>,
        tun_rx: mpsc::Receiver<Vec<u8>>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            listener_shard_index < listener.shards,
            "listener shard index {listener_shard_index} is outside {} shards",
            listener.shards
        );
        let reuseport_index = if listener.shards > 1 {
            Some(u8::try_from(listener_shard_index).context("listener shard index exceeds u8")?)
        } else {
            None
        };
        let bound_addr = socket.local_addr()?;
        let max_datagram_size =
            listener.effective_quic_max_datagram_size(config.quic.max_datagram_size);
        metrics.set_udp_offload_state(socket.udp_gso_enabled(), socket.udp_gro_enabled());
        info!(
            shard = index,
            listener_shard = listener_shard_index,
            addr = %bound_addr,
            udp_gso = socket.udp_gso_enabled(),
            udp_gro = socket.udp_gro_enabled(),
            max_datagram_size,
            reuseport_cid_steering = socket.reuseport_cid_steering_enabled(),
            "listening"
        );

        let client_certs = if listener.auth.client_cert_enabled() {
            Some(Arc::clone(&shared.clients))
        } else {
            None
        };
        let stealth_auth = listener.auth.stealth_enabled();

        let quic_config = build_quic_config(
            &config,
            max_datagram_size,
            client_certs.as_ref().map(Arc::clone),
            Arc::clone(&shared.tls),
        )?;
        let h3_config = build_h3_config()?;

        let tcp_policy = TargetPolicy::new(
            &config.tcp_proxy.allow_targets,
            &config.tcp_proxy.deny_targets,
        )
        .with_restrictions(listener.tcp_targets);

        let udp_policy = TargetPolicy::new(
            &config.udp_proxy.allow_targets,
            &config.udp_proxy.deny_targets,
        )
        .with_restrictions(listener.udp_targets);

        let (udp_response_tx, udp_response_rx) = mpsc::channel(UDP_RESPONSE_QUEUE_CAPACITY);
        let (udp_setup_tx, udp_setup_rx) = mpsc::channel(UDP_SETUP_QUEUE_CAPACITY);
        let (tcp_event_tx, tcp_event_rx) = mpsc::channel(TCP_RELAY_QUEUE_CAPACITY);
        let (auth_tx, auth_rx) = mpsc::channel(AUTH_RESULT_QUEUE_CAPACITY);

        Ok(Self {
            index,
            reuseport_index,
            shared,
            metrics,
            socket,
            quic_config,
            h3_config,
            connections: FxHashMap::default(),
            connection_id_aliases: FxHashMap::default(),
            auth,
            stealth_auth,
            client_certs,
            tcp_policy,
            udp_policy,
            max_datagram_size,
            config,
            conn_by_index: FxHashMap::default(),
            udp_response_tx,
            udp_response_rx,
            udp_setup_tx,
            udp_setup_rx,
            tcp_event_tx,
            tcp_event_rx,
            forward_rx,
            tun_rx,
            auth_tx,
            auth_rx,
            dirty: DirtySet::default(),
            timers: TimerQueue::default(),
        })
    }

    /// Run the server event loop.
    pub async fn run(&mut self, mut shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
        let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut dgram_buf = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut tun_recv = TunRecvBatch::new(self.config.ip_proxy.tun_mtu);
        let mut tun_send = TunSendBatch::new();
        let mut recv_batch = RecvPacketBatch::new(MAX_QUIC_RECV_BATCH);
        let mut send_batch = SendPacketBatch::new();
        let mut stateless_out = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut stateless_batch = SendPacketBatch::new();
        let mut forward_batches: Vec<PendingForwardBatch> = (0..self.shared.forward_tx.len())
            .map(|_| PendingForwardBatch::default())
            .collect();
        // One shard reads the shared TUN device and hands each packet to the
        // connection that owns its address. Shard 0 is an arbitrary but stable
        // choice; nothing here depends on which listener that shard serves.
        let tun_device = if self.index == 0 {
            self.shared.tun.as_ref().map(TunManager::device)
        } else {
            None
        };

        let local_addr = self.socket.local_addr()?;
        let idle_timeout = Duration::from_secs(self.config.server.idle_timeout_secs);

        let mut shutting_down = false;
        let mut drain_deadline: Option<Instant> = None;
        const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
        let mut next_idle_sweep = Instant::now() + IDLE_SWEEP_INTERVAL;
        self.metrics
            .record_heartbeat(self.shared.metrics.elapsed_millis(), Duration::ZERO);
        // The roster generation this shard has already enforced.
        let mut applied_roster_generation = self.shared.clients.generation();
        // The connections serviced in the current round. Held across
        // iterations so its allocation is reused.
        let mut serviced: Vec<u64> = Vec::new();

        loop {
            self.dirty.end_round();
            serviced.clear();
            stateless_batch.clear();
            for batch in &mut forward_batches {
                debug_assert!(batch.packets.is_empty());
                debug_assert_eq!(batch.bytes, 0);
            }
            let mut stateless_retries = 0usize;

            // Wake for the earliest connection deadline rather than scanning
            // every connection for it. The idle sweep and, during shutdown, the
            // drain deadline bound how long the loop can sit idle.
            let now = Instant::now();
            let mut next_wakeup = next_idle_sweep.saturating_duration_since(now);
            if let Some(deadline) = self.timers.next_deadline() {
                next_wakeup = next_wakeup.min(deadline.saturating_duration_since(now));
            }
            if let Some(deadline) = drain_deadline {
                next_wakeup = next_wakeup.min(deadline.saturating_duration_since(now));
            }
            let timeout = Some(next_wakeup);

            // Wait for a packet, signal, or timeout.
            enum Event {
                PacketBatch(std::io::Result<usize>),
                TargetDatagram(Option<UdpResponse>),
                /// DNS and socket setup completed for one CONNECT-UDP stream.
                UdpSetup(Option<UdpSetupResult>),
                TcpRelay(Option<TcpRelayEvent>),
                TunPacket(std::io::Result<usize>),
                /// A QUIC packet another shard received for one of ours.
                Forwarded(Option<ForwardedPacketBatch>),
                /// A TUN packet another shard read for one of our tunnels.
                TunInbound(Option<Vec<u8>>),
                /// Credentials finished verifying off the event loop.
                AuthDone(Option<AuthOutcome>),
                Shutdown,
                Timeout,
            }

            let event = if let Some(timeout) = timeout {
                tokio::select! {
                    _ = shutdown.wait_for(|requested| *requested), if !shutting_down => {
                        Event::Shutdown
                    }
                    response = self.udp_response_rx.recv(), if !shutting_down => {
                        Event::TargetDatagram(response)
                    }
                    result = self.udp_setup_rx.recv(), if !shutting_down => {
                        Event::UdpSetup(result)
                    }
                    response = self.tcp_event_rx.recv(), if !shutting_down => {
                        Event::TcpRelay(response)
                    }
                    result = async {
                        let device = tun_device
                            .as_ref()
                            .expect("TUN select branch requires a device");
                        tun::recv_batch(device, &mut tun_recv).await
                    }, if tun_device.is_some() && !shutting_down => {
                        Event::TunPacket(result)
                    }
                    packet = self.forward_rx.recv(), if !shutting_down => {
                        Event::Forwarded(packet)
                    }
                    packet = self.tun_rx.recv(), if !shutting_down => {
                        Event::TunInbound(packet)
                    }
                    outcome = self.auth_rx.recv(), if !shutting_down => {
                        Event::AuthDone(outcome)
                    }
                    result = tokio::time::timeout(
                        timeout, self.socket.recv_batch(&mut recv_batch)
                    ) => match result {
                        Ok(r) => Event::PacketBatch(r),
                        Err(_) => Event::Timeout,
                    },
                }
            } else {
                Event::PacketBatch(self.socket.recv_batch(&mut recv_batch).await)
            };

            match event {
                Event::Shutdown => {
                    info!(
                        shard = self.index,
                        connections = self.connections.len(),
                        "shard draining connections"
                    );
                    shutting_down = true;
                    drain_deadline = Some(Instant::now() + DRAIN_TIMEOUT);

                    // Every connection has a CONNECTION_CLOSE to emit, so this
                    // is the one point where the whole table is legitimately
                    // dirty.
                    for client in self.connections.values_mut() {
                        if let Some(h3) = &mut client.h3 {
                            h3.send_goaway(&mut client.quic, 0).ok();
                        }
                        client.quic.close(true, 0x0, b"server shutting down").ok();
                        self.dirty.mark(client.index);
                    }
                }
                Event::PacketBatch(Ok(received)) => {
                    let mut packet_count = 0usize;
                    let mut byte_count = 0usize;
                    let mut packet_output = PacketOutput {
                        stateless: &mut stateless_out,
                        stateless_batch: &mut stateless_batch,
                        stateless_retries: &mut stateless_retries,
                        forward_batches: &mut forward_batches,
                    };
                    recv_batch.for_each_packet_mut(received, |packet, from| {
                        packet_count += 1;
                        byte_count += packet.len();
                        if !shutting_down {
                            self.handle_packet(packet, from, local_addr, &mut packet_output);
                            return;
                        }

                        // During shutdown, still feed packets to quiche so it
                        // can send CONNECTION_CLOSE frames.
                        if let Ok(hdr) = quiche::Header::from_slice(packet, CONN_ID_LEN) {
                            let key = if let Some((id, client)) =
                                self.connections.get_key_value(&hdr.dcid)
                                && client.primary_connection_id_active()
                            {
                                Some(id.clone())
                            } else {
                                self.connection_id_aliases.get(&hdr.dcid).cloned()
                            };
                            let Some(key) = key else {
                                return;
                            };
                            let Some(client) = self.connections.get_mut(&key) else {
                                return;
                            };
                            let recv_info = quiche::RecvInfo {
                                from,
                                to: local_addr,
                            };
                            client.quic.recv(packet, recv_info).ok();
                            let index = client.index;
                            self.dirty.mark(index);
                        }
                    });
                    self.metrics.record_receive_batch(packet_count, byte_count);
                }
                Event::PacketBatch(Err(e)) => {
                    error!(%e, "socket recv error");
                }
                Event::TargetDatagram(Some(response)) => {
                    self.relay_target_datagrams(response);
                }
                Event::TargetDatagram(None) => {}
                Event::UdpSetup(Some(result)) => {
                    self.handle_udp_setup_result(result);
                }
                Event::UdpSetup(None) => {}
                Event::TcpRelay(Some(event)) => {
                    self.handle_tcp_event_batch(event);
                }
                Event::TcpRelay(None) => {}
                Event::TunPacket(Ok(segments)) => {
                    // One offloaded read already carries a whole aggregate, so
                    // the segments it split into are the batch.
                    for index in 0..segments.min(MAX_TUN_RECV_BATCH) {
                        let Some(packet) = tun_recv.packet(index) else {
                            break;
                        };
                        if !self.relay_tun_packet(packet) {
                            break;
                        }
                    }
                }
                Event::TunPacket(Err(e)) => {
                    error!(%e, "TUN recv error");
                }
                Event::Forwarded(Some(mut batch)) => {
                    debug_assert_eq!(
                        batch.bytes,
                        batch
                            .packets
                            .iter()
                            .map(|packet| packet.data.len())
                            .sum::<usize>()
                    );
                    let mut packet_output = PacketOutput {
                        stateless: &mut stateless_out,
                        stateless_batch: &mut stateless_batch,
                        stateless_retries: &mut stateless_retries,
                        forward_batches: &mut forward_batches,
                    };
                    for packet in &mut batch.packets {
                        self.handle_packet(
                            &mut packet.data,
                            packet.from,
                            local_addr,
                            &mut packet_output,
                        );
                    }
                }
                Event::Forwarded(None) => {}
                Event::TunInbound(Some(packet)) => {
                    self.relay_tun_packet(&packet);
                }
                Event::TunInbound(None) => {}
                Event::AuthDone(Some(outcome)) => {
                    self.handle_auth_result(outcome);
                }
                Event::AuthDone(None) => {}
                Event::Timeout => {}
            }

            self.flush_forward_batches(&mut forward_batches);

            if !stateless_batch.is_empty() {
                let udp_gso_before_send = self.socket.udp_gso_enabled();
                match self.socket.send_batch(&stateless_batch).await {
                    Ok(()) => {
                        self.metrics.record_send_batch(
                            stateless_batch.packet_count(),
                            stateless_batch.byte_count(),
                        );
                        self.metrics.record_quic_retries_sent(stateless_retries);
                    }
                    Err(error) => warn!(%error, "stateless QUIC response send failed"),
                }
                if udp_gso_before_send && !self.socket.udp_gso_enabled() {
                    self.metrics.disable_udp_gso();
                }
            }

            // A connection whose deadline has arrived needs driving even if
            // nothing arrived for it.
            self.expire_connection_timers(Instant::now());
            self.dirty.take_into(&mut serviced);

            // Process QUIC DATAGRAMs → forward to target UDP/TUN.
            if !shutting_down {
                self.retry_tcp_connect_responses(&serviced);
                self.retry_udp_connect_responses(&serviced);
                self.retry_ip_connect_responses(&serviced);
                self.flush_tcp_responses(&serviced);
                self.read_capsule_bodies(&serviced);
                self.relay_client_datagrams(&serviced, &mut dgram_buf, &mut tun_send)
                    .await;
                self.finish_capsule_bodies(&serviced);
                // Flush whatever the relay staged for the TUN device.
                if let Some(tun) = &self.shared.tun
                    && !tun_send.is_empty()
                    && let Err(e) = tun.send_batch(&mut tun_send).await
                {
                    debug!(%e, "TUN batch write failed");
                }
            }

            // Sweeping every iteration would walk every connection and every
            // tunnel per packet batch; once a second is plenty for a timeout
            // measured in seconds. The deadline rolls forward even while
            // shutting down, when the sweep itself is skipped — otherwise it
            // stays in the past and pins the wakeup above to zero.
            let now = Instant::now();
            if now >= next_idle_sweep {
                let event_loop_lag = now.saturating_duration_since(next_idle_sweep);
                self.metrics
                    .record_heartbeat(self.shared.metrics.elapsed_millis(), event_loop_lag);
                next_idle_sweep = now + IDLE_SWEEP_INTERVAL;
                if !shutting_down {
                    // Cheap in the common case: one atomic read, and a scan
                    // only when the roster actually changed.
                    let generation = self.shared.clients.generation();
                    if generation != applied_roster_generation {
                        applied_roster_generation = generation;
                        self.enforce_roster();
                    }
                    self.cleanup_idle_tunnels(idle_timeout);
                    // The sweep writes to the connections it closes tunnels on,
                    // so pick up any it just marked.
                    self.dirty.take_into(&mut serviced);
                }
            }

            // Drive the connections with work pending: handle timers, send
            // pending data, and reschedule their next wakeup.
            self.drive_connections(&serviced, &mut out, &mut send_batch)
                .await;

            // Reap closed connections. A connection can only reach the closed
            // state by being driven, so only the ones just serviced can have
            // entered it.
            for index in &serviced {
                let Some(id) = self.conn_by_index.get(index) else {
                    continue;
                };
                if !self.connections.get(id).is_some_and(|c| c.quic.is_closed()) {
                    continue;
                }
                let id = id.clone();

                if let Some(client) = self.connections.remove(&id) {
                    info!(?id, "connection closed");
                    for tunnel in client.ip_tunnels.values() {
                        self.shared
                            .address_pool
                            .lock()
                            .expect("address pool poisoned")
                            .release_all(&tunnel.assigned_addrs);
                        // Remove by key rather than scanning the whole routing
                        // table once per tunnel.
                        self.shared
                            .routing_table
                            .write()
                            .expect("routing table poisoned")
                            .remove_owned(
                                &tunnel.assigned_addrs,
                                &TunnelOwner {
                                    conn_id: client.index,
                                    stream_id: tunnel.stream_id,
                                },
                            );
                    }
                    self.conn_by_index.remove(&client.index);
                    let mut cid_routes = self
                        .shared
                        .cid_shard
                        .write()
                        .expect("cid ownership poisoned");
                    for connection_id in client.connection_ids() {
                        cid_routes.remove(connection_id);
                        self.connection_id_aliases.remove(connection_id);
                    }
                    drop(cid_routes);
                    self.shared
                        .index_shard
                        .write()
                        .expect("index ownership poisoned")
                        .remove(&client.index);
                }
            }

            // During shutdown, exit once all connections are drained or
            // the drain deadline is reached.
            if shutting_down {
                if self.connections.is_empty() {
                    info!(shard = self.index, "all connections drained, exiting");
                    return Ok(());
                }
                if let Some(deadline) = drain_deadline
                    && Instant::now() >= deadline
                {
                    warn!(
                        remaining = self.connections.len(),
                        "drain timeout reached, forcing exit"
                    );
                    self.shared.metrics.record_forced_shutdown();
                    // Release all remaining IP tunnel resources.
                    for client in self.connections.values() {
                        for tunnel in client.ip_tunnels.values() {
                            self.shared
                                .address_pool
                                .lock()
                                .expect("address pool poisoned")
                                .release_all(&tunnel.assigned_addrs);
                        }
                    }
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{
        AuthMode, AuthSection, ClientEntry, ListenerSection, ListenerTransport, ServerConfig,
    };

    fn invalid_roster_entry() -> ClientEntry {
        ClientEntry {
            name: "unused".into(),
            public_key: "not-a-public-key".into(),
            ipv4: Some("not-an-ip".into()),
            ipv6: None,
        }
    }

    /// A default configuration that listens on the given listeners.
    fn config_with(listeners: Vec<ListenerSection>) -> ServerConfig {
        ServerConfig {
            listeners,
            ..Default::default()
        }
    }

    /// A listener with the given address and authentication mode.
    fn listener(addr: &str, mode: AuthMode) -> ListenerSection {
        ListenerSection {
            listen_addr: addr.parse().unwrap(),
            transport: ListenerTransport::Http3,
            shards: 1,
            max_datagram_size: None,
            tcp_targets: None,
            udp_targets: None,
            auth: AuthSection {
                enabled: true,
                mode,
                stealth: false,
                // Enough to satisfy `BasicAuthenticator`; the hash is only
                // parsed when a request actually arrives.
                username: "alice".into(),
                password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into(),
                users: Vec::new(),
            },
        }
    }

    #[test]
    fn roster_is_not_parsed_outside_client_certificate_mode() {
        let mut config = ServerConfig::default();
        config.clients.push(invalid_roster_entry());
        assert!(
            super::active_client_registry(&config, false)
                .unwrap()
                .is_empty()
        );

        config.listeners[0].auth.enabled = false;
        config.listeners[0].auth.mode = AuthMode::ClientCert;
        assert!(!super::any_client_cert_listener(&config));
        assert!(
            super::active_client_registry(&config, false)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn active_client_certificate_roster_is_fail_closed() {
        let mut config = ServerConfig::default();
        config.listeners[0].auth.mode = AuthMode::ClientCert;
        assert!(super::active_client_registry(&config, true).is_err());

        config.clients.push(invalid_roster_entry());
        assert!(super::active_client_registry(&config, true).is_err());
    }

    #[test]
    fn stealth_auth_requires_an_enabled_basic_listener() {
        let mut config = ServerConfig::default();
        config.listeners[0].auth.enabled = false;
        config.listeners[0].auth.stealth = true;

        let error = match super::validate_server_config(&config) {
            Ok(_) => panic!("stealth authentication was accepted without Basic auth"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("auth.stealth requires enabled Basic authentication"),
            "unexpected diagnostic: {error:#}"
        );
    }

    /// The roster belongs to the server, so one certificate listener among
    /// several is enough to make it load — and to keep reload available.
    #[test]
    fn one_certificate_listener_is_enough_to_activate_the_roster() {
        let mut config = config_with(vec![
            listener("0.0.0.0:443", AuthMode::Basic),
            listener("0.0.0.0:4443", AuthMode::ClientCert),
        ]);
        assert!(super::any_client_cert_listener(&config));

        // Fail closed for the whole server: the certificate listener has no
        // roster to admit anyone from.
        assert!(super::active_client_registry(&config, true).is_err());

        config.listeners = vec![listener("0.0.0.0:443", AuthMode::Basic)];
        assert!(!super::any_client_cert_listener(&config));
    }

    #[test]
    fn configuration_reload_uses_tls_auth_and_ip_proxy_state_from_startup() {
        let path = std::path::PathBuf::from("masque.toml");
        let mut config = ServerConfig::default();

        // Basic mode still consumes HUP safely (the systemd unit always exposes
        // ExecReload), but the captured startup bit prevents an edited file from
        // pretending the already-bound TLS context switched modes.
        let reload = super::config_reload_settings(&config, Some(path.clone())).unwrap();
        assert!(!reload.client_cert_enabled);
        assert_eq!(reload.tls, config.tls);
        assert!(!reload.listeners[0].stealth);

        config.listeners[0].auth.stealth = true;
        let reload = super::config_reload_settings(&config, Some(path.clone())).unwrap();
        assert!(reload.listeners[0].stealth);
        config.listeners[0].auth.stealth = false;

        config.listeners[0].auth.mode = AuthMode::ClientCert;
        config.ip_proxy.enabled = false;
        let reload = super::config_reload_settings(&config, Some(path.clone())).unwrap();
        assert_eq!(reload.path, path);
        assert!(reload.client_cert_enabled);
        assert!(!reload.ip_proxy_enabled);

        // A certificate listener reached only through [[listeners]] must enable
        // reload too, or revoking a client would cost a restart.
        let config = config_with(vec![
            listener("0.0.0.0:443", AuthMode::Basic),
            listener("0.0.0.0:4443", AuthMode::ClientCert),
        ]);
        let reload = super::config_reload_settings(&config, Some(path.clone())).unwrap();
        assert!(reload.client_cert_enabled);

        // Programmatic servers have no source file to re-read.
        assert!(super::config_reload_settings(&config, None).is_none());
    }

    // ── Listener planning ────────────────────────────────────────────

    #[test]
    fn a_configuration_without_listeners_is_rejected() {
        let mut config = ServerConfig::default();
        config.listeners.clear();
        assert!(super::plan_listeners(&config).is_err());
    }

    #[test]
    fn observability_is_restricted_to_loopback() {
        for allowed in ["127.0.0.1:9090", "[::1]:9090", "[::ffff:127.0.0.1]:9090"] {
            assert!(super::is_loopback(
                allowed.parse::<std::net::SocketAddr>().unwrap().ip()
            ));
        }
        for denied in ["0.0.0.0:9090", "192.0.2.1:9090", "[::]:9090"] {
            assert!(!super::is_loopback(
                denied.parse::<std::net::SocketAddr>().unwrap().ip()
            ));
        }

        let mut config = ServerConfig::default();
        config.observability.listen_addr = Some("0.0.0.0:9090".parse().unwrap());
        let error = match super::validate_server_config(&config) {
            Ok(_) => panic!("a public observability address must be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("must use a loopback address"), "{error}");
    }

    #[test]
    fn admission_limits_and_retry_settings_are_bounded() {
        let mut config = ServerConfig::default();

        config.server.max_connections_per_ip = 0;
        let error = match super::validate_server_config(&config) {
            Ok(_) => panic!("zero per-source connection limit must be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("max_connections_per_ip"));
        config.server.max_connections_per_ip = 64;

        config.server.max_pending_auth_per_ip = super::MAX_PENDING_AUTH_GLOBAL + 1;
        let error = match super::validate_server_config(&config) {
            Ok(_) => panic!("oversized per-source auth limit must be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("max_pending_auth_per_ip"));
        config.server.max_pending_auth_per_ip = 8;

        config.quic.retry_connection_threshold = 0;
        let error = match super::validate_server_config(&config) {
            Ok(_) => panic!("zero Retry threshold must be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("retry_connection_threshold"));
        config.quic.retry_connection_threshold = 64;

        config.quic.retry_token_ttl_secs = 301;
        let error = match super::validate_server_config(&config) {
            Ok(_) => panic!("oversized Retry token lifetime must be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("retry_token_ttl_secs"));
    }

    #[test]
    fn attacker_controlled_protocol_credit_has_configuration_ceilings() {
        let mut config = ServerConfig::default();
        config.listeners[0].auth.enabled = false;
        let error = |config: &ServerConfig| match super::validate_server_config(config) {
            Ok(_) => panic!("oversized resource configuration must be rejected"),
            Err(error) => error.to_string(),
        };

        config.server.max_connections = super::MAX_CONFIGURED_CONNECTIONS + 1;
        let message = error(&config);
        assert!(message.contains("max_connections"), "{message}");
        config.server.max_connections = 10_000;

        config.server.max_tunnels_per_connection = super::MAX_TUNNELS_PER_CONNECTION + 1;
        let message = error(&config);
        assert!(message.contains("max_tunnels_per_connection"), "{message}");
        config.server.max_tunnels_per_connection = 100;

        config.quic.initial_max_streams_bidi = super::MAX_QUIC_STREAMS_BIDI + 1;
        let message = error(&config);
        assert!(message.contains("initial_max_streams_bidi"), "{message}");
        config.quic.initial_max_streams_bidi = 128;

        config.quic.dgram_recv_queue_len = super::MAX_QUIC_DATAGRAM_QUEUE_LEN + 1;
        let message = error(&config);
        assert!(message.contains("dgram_recv_queue_len"), "{message}");
        config.quic.dgram_recv_queue_len = 2_048;

        config.quic.max_connection_window = super::MAX_QUIC_CONNECTION_WINDOW + 1;
        let message = error(&config);
        assert!(message.contains("max_connection_window"), "{message}");
        config.quic.max_connection_window = 24 * 1024 * 1024;

        config.http2.max_concurrent_streams = super::MAX_HTTP2_CONCURRENT_STREAMS + 1;
        let message = error(&config);
        assert!(message.contains("max_concurrent_streams"), "{message}");
        config.http2.max_concurrent_streams = 128;

        config.http2.initial_connection_window = super::MAX_HTTP2_CONNECTION_WINDOW + 1;
        let message = error(&config);
        assert!(message.contains("initial_connection_window"), "{message}");
    }

    #[test]
    fn target_setup_timeouts_are_bounded() {
        let mut config = ServerConfig::default();

        config.tcp_proxy.connect_timeout_secs = 0;
        let error = match super::validate_server_config(&config) {
            Ok(_) => panic!("zero TCP setup timeout must be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("tcp_proxy.connect_timeout_secs"));

        config.tcp_proxy.connect_timeout_secs = 10;
        config.udp_proxy.connect_timeout_secs = 301;
        let error = match super::validate_server_config(&config) {
            Ok(_) => panic!("oversized UDP setup timeout must be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("udp_proxy.connect_timeout_secs"));
    }

    /// Planning keeps the listener-specific trust boundary separate from the
    /// process-wide proxy, QUIC, TLS, and connection settings.
    #[test]
    fn a_plan_resolves_each_listener_independently() {
        let config = config_with(vec![
            listener("127.0.0.1:8443", AuthMode::Basic),
            listener("127.0.0.1:8444", AuthMode::ClientCert),
        ]);

        let plans = super::plan_listeners(&config).unwrap();
        assert_eq!(plans.len(), 2);
        for plan in &plans {
            assert_eq!(plan.listener.shards, 1);
        }
        assert!(plans[0].listener.auth.basic_enabled());
        assert!(plans[1].listener.auth.client_cert_enabled());
        assert_eq!(
            plans[1].listener.listen_addr,
            "127.0.0.1:8444".parse::<std::net::SocketAddr>().unwrap()
        );
    }

    #[test]
    fn listener_datagram_size_overrides_only_its_http3_socket() {
        let mut relay = listener("127.0.0.1:8443", AuthMode::Basic);
        relay.max_datagram_size = Some(1200);
        let direct = listener("127.0.0.1:8444", AuthMode::Basic);
        let config = config_with(vec![relay, direct]);

        let plans = super::plan_listeners(&config).unwrap();
        assert_eq!(
            plans[0]
                .listener
                .effective_quic_max_datagram_size(config.quic.max_datagram_size),
            1200
        );
        assert_eq!(
            plans[1]
                .listener
                .effective_quic_max_datagram_size(config.quic.max_datagram_size),
            1350
        );
    }

    #[test]
    fn listener_datagram_size_is_bounded_and_http3_only() {
        for invalid in [
            quiche::MIN_CLIENT_INITIAL_LEN - 1,
            super::MAX_DATAGRAM_SIZE + 1,
        ] {
            let mut http3 = listener("127.0.0.1:8443", AuthMode::Basic);
            http3.auth.enabled = false;
            http3.max_datagram_size = Some(invalid);
            let error = match super::validate_server_config(&config_with(vec![http3])) {
                Ok(_) => panic!("invalid listener datagram size was accepted"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains("max_datagram_size"), "{error}");
        }

        let mut http2 = listener("127.0.0.1:8443", AuthMode::Basic);
        http2.auth.enabled = false;
        http2.transport = ListenerTransport::Http2;
        http2.max_datagram_size = Some(1200);
        let error = match super::validate_server_config(&config_with(vec![http2])) {
            Ok(_) => panic!("HTTP/2 listener accepted a QUIC-only override"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("HTTP/3-only"), "{error}");
    }

    /// Not just a bind failure: a multi-shard listener uses SO_REUSEPORT, so a
    /// second listener on its address would join that load-balancing group and
    /// be handed connections meant for a different authentication mode.
    #[test]
    fn two_listeners_cannot_share_an_address() {
        let config = config_with(vec![
            listener("0.0.0.0:443", AuthMode::Basic),
            listener("0.0.0.0:443", AuthMode::ClientCert),
        ]);
        assert!(super::plan_listeners(&config).is_err());
    }

    #[test]
    fn http2_and_http3_may_share_a_numeric_address() {
        let mut http3 = listener("127.0.0.1:8443", AuthMode::Basic);
        http3.transport = ListenerTransport::Http3;
        let mut http2 = listener("127.0.0.1:8443", AuthMode::Basic);
        http2.transport = ListenerTransport::Http2;
        let config = config_with(vec![http3, http2]);

        assert!(super::plan_listeners(&config).is_ok());
    }

    #[test]
    fn http2_listener_rejects_quic_sharding() {
        let mut http2 = listener("127.0.0.1:8443", AuthMode::Basic);
        http2.transport = ListenerTransport::Http2;
        http2.shards = 2;
        let config = config_with(vec![http2]);

        let error = match super::plan_listeners(&config) {
            Ok(_) => panic!("HTTP/2 sharding should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("HTTP/2 listener"));
    }

    /// A wildcard claims every address of its family on its port, so an
    /// overlapping pair must be refused rather than left to fail at bind time.
    #[test]
    fn wildcard_listeners_cannot_overlap_a_specific_address() {
        let config = config_with(vec![
            listener("0.0.0.0:443", AuthMode::Basic),
            listener("127.0.0.1:443", AuthMode::ClientCert),
        ]);
        assert!(super::plan_listeners(&config).is_err());
    }

    /// `::` may claim IPv4 too, depending on `IPV6_V6ONLY`, which nothing here
    /// sets. Refusing the pair everywhere beats binding on some hosts and
    /// failing on others.
    #[test]
    fn the_ipv6_wildcard_is_assumed_to_claim_ipv4() {
        let config = config_with(vec![
            listener("[::]:443", AuthMode::Basic),
            listener("0.0.0.0:443", AuthMode::ClientCert),
        ]);
        assert!(super::plan_listeners(&config).is_err());

        // Nothing wider than it needs to be: distinct ports, distinct specific
        // addresses, and a v6 loopback beside the v4 wildcard all still stand.
        for pair in [
            ["0.0.0.0:443", "0.0.0.0:4443"],
            ["127.0.0.1:443", "127.0.0.2:443"],
            ["[::1]:443", "0.0.0.0:443"],
        ] {
            let config = config_with(vec![
                listener(pair[0], AuthMode::Basic),
                listener(pair[1], AuthMode::ClientCert),
            ]);
            assert!(
                super::plan_listeners(&config).is_ok(),
                "{pair:?} do not contend for the same packets"
            );
        }
    }

    /// `::ffff:127.0.0.1` is `127.0.0.1`. Comparing the two spellings as
    /// written let the pair through, and the kernel then either refused to bind
    /// or — with SO_REUSEPORT — accepted both and let one listener shadow the
    /// other's traffic.
    #[test]
    fn ipv4_mapped_addresses_are_compared_as_ipv4() {
        for pair in [
            ["127.0.0.1:443", "[::ffff:127.0.0.1]:443"],
            // The mapped wildcard is still the IPv4 wildcard.
            ["[::ffff:0.0.0.0]:443", "127.0.0.1:443"],
            ["[::ffff:127.0.0.1]:443", "0.0.0.0:443"],
        ] {
            let config = config_with(vec![
                listener(pair[0], AuthMode::Basic),
                listener(pair[1], AuthMode::ClientCert),
            ]);
            assert!(
                super::plan_listeners(&config).is_err(),
                "{pair:?} name the same interface"
            );
        }

        // A genuine IPv6 address that merely looks similar is still distinct.
        let config = config_with(vec![
            listener("127.0.0.1:443", AuthMode::Basic),
            listener("[::1]:443", AuthMode::ClientCert),
        ]);
        assert!(super::plan_listeners(&config).is_ok());
    }

    /// A link-local IPv6 scope selects the interface. Dropping it during
    /// canonicalisation would reject two valid listeners as one address.
    #[test]
    fn native_ipv6_scope_ids_remain_distinct() {
        let config = config_with(vec![
            listener("[fe80::1%2]:443", AuthMode::Basic),
            listener("[fe80::1%3]:443", AuthMode::ClientCert),
        ]);
        assert!(super::plan_listeners(&config).is_ok());

        let same_scope = config_with(vec![
            listener("[fe80::1%2]:443", AuthMode::Basic),
            listener("[fe80::1%2]:443", AuthMode::ClientCert),
        ]);
        assert!(super::plan_listeners(&same_scope).is_err());

        // The kernel ignores a zone on a non-link-local address, so spelling a
        // loopback address with two scopes must not bypass the conflict check.
        let scoped_loopback = config_with(vec![
            listener("[::1%2]:443", AuthMode::Basic),
            listener("[::1%3]:443", AuthMode::ClientCert),
        ]);
        assert!(super::plan_listeners(&scoped_loopback).is_err());
    }

    /// Port 0 has no fixed value until bind. Planning permits several such
    /// listeners; startup resolves each one and prevents reuseport collisions.
    #[test]
    fn listeners_may_both_ask_for_an_ephemeral_port() {
        let config = config_with(vec![
            listener("127.0.0.1:0", AuthMode::Basic),
            listener("127.0.0.1:0", AuthMode::ClientCert),
        ]);
        assert!(super::plan_listeners(&config).is_ok());
    }

    /// The diagnostic has to name the conflict it found. Told that a loopback
    /// pair overlaps "because a wildcard claims its family", an operator would
    /// go looking for a wildcard that is not there.
    #[test]
    fn an_address_conflict_is_described_by_its_kind() {
        let cases = [
            (
                "0.0.0.0:443",
                "0.0.0.0:443",
                "two listeners are configured for",
            ),
            (
                "127.0.0.1:443",
                "[::ffff:127.0.0.1]:443",
                "are the same address written two ways",
            ),
            (
                "0.0.0.0:443",
                "127.0.0.1:443",
                "overlap; a wildcard address",
            ),
        ];

        for (first, second, expected) in cases {
            let config = config_with(vec![
                listener(first, AuthMode::Basic),
                listener(second, AuthMode::ClientCert),
            ]);
            let error = match super::plan_listeners(&config) {
                Ok(_) => panic!("{first} and {second} contend and must be refused"),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains(expected),
                "{first} vs {second}: expected {expected:?}, got {error:?}"
            );
        }
    }

    #[test]
    fn automatic_sharding_is_rejected_for_multiple_listeners() {
        let mut config = ServerConfig::default();
        let mut listeners = vec![
            listener("0.0.0.0:443", AuthMode::Basic),
            listener("0.0.0.0:4443", AuthMode::ClientCert),
        ];
        listeners[0].shards = 0;
        config.listeners = listeners;
        assert!(super::plan_listeners(&config).is_err());

        // A lone listener still gets to ask for one per core.
        config.listeners.truncate(1);
        assert!(super::plan_listeners(&config).is_ok());
    }

    #[test]
    fn the_shard_cap_applies_to_the_server_total() {
        let mut config = ServerConfig::default();
        let mut first = listener("0.0.0.0:443", AuthMode::Basic);
        let mut second = listener("0.0.0.0:4443", AuthMode::Basic);
        first.shards = super::MAX_SHARDS;
        second.shards = 1;
        config.listeners = vec![first, second];

        // Each listener is under the cap on its own; together they are not.
        assert!(super::plan_listeners(&config).is_err());
    }

    /// The default algorithm name is only validated when a server starts, and
    /// a quiche rename would turn that into a startup failure in production.
    #[test]
    fn default_cc_algorithm_is_known_to_quiche() {
        let defaults = ServerConfig::default();
        let mut quic_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        quic_config
            .set_cc_algorithm_name(&defaults.quic.cc_algorithm)
            .expect("default cc_algorithm must be accepted by quiche");
    }

    /// The flow-control ceilings must leave autotuning somewhere to grow, or
    /// `Server::bind` rejects its own defaults.
    #[test]
    fn default_flow_control_windows_are_consistent() {
        let quic = ServerConfig::default().quic;
        assert!(quic.max_connection_window >= quic.initial_max_data);
        assert!(quic.max_stream_window >= quic.initial_max_stream_data);
    }

    /// Sharding stays opt-in: it changes how connections are distributed, so
    /// an upgrade must not silently switch a server over to it.
    #[test]
    fn sharding_is_off_by_default() {
        assert_eq!(ServerConfig::default().listeners[0].shards, 1);
        assert_eq!(super::resolve_shard_count(1), 1);
    }

    #[test]
    fn explicit_shard_count_is_capped() {
        assert_eq!(super::resolve_shard_count(4), 4);
        assert_eq!(
            super::resolve_shard_count(usize::MAX),
            super::MAX_SHARDS,
            "a huge configured value must not fan out without bound"
        );
    }

    /// `0` means "one per core", and must still land inside the cap.
    /// Hashing is bounded so it cannot monopolise the machine, but never so
    /// tight that a shard has no slot at all.
    #[test]
    fn auth_concurrency_is_bounded_by_cores_and_shards() {
        let cores = std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1)
            .max(2);
        for shards in [1_usize, 2, 4, 32] {
            let permits = super::auth_concurrency(shards);
            assert!(permits >= 1, "every shard needs to make progress");
            assert!(
                permits <= cores,
                "shards={shards}: {permits} verifications would oversubscribe {cores} cores"
            );
            assert!(permits <= shards * 2);
        }

        // No Basic listener means nothing acquires a permit, but a semaphore
        // that can never be acquired would hang a future caller.
        assert_eq!(super::auth_concurrency(0), 1);
    }

    /// The verification budget rations what unauthenticated callers can demand
    /// of the Basic listeners. A certificate listener never reaches that path,
    /// so its shards must not widen the budget.
    #[test]
    fn certificate_shards_do_not_enlarge_the_verification_budget() {
        // One shard each: multi-shard listeners need SO_REUSEPORT, so a larger
        // certificate listener cannot be planned off Linux. One is enough — the
        // point is that certificate shards are not counted at all.
        let config = config_with(vec![
            listener("0.0.0.0:443", AuthMode::Basic),
            listener("0.0.0.0:4443", AuthMode::ClientCert),
        ]);
        let plans = super::plan_listeners(&config).unwrap();

        let total_shards: usize = plans.iter().map(|plan| plan.listener.shards).sum();
        assert_eq!(total_shards, 2);
        assert_eq!(super::basic_shard_count(&plans), 1);

        // The Basic listener gets the budget one Basic shard gets, whatever the
        // certificate listener contributes to the server's size.
        assert_eq!(super::auth_concurrency(super::basic_shard_count(&plans)), 2);

        // And a server with no Basic listener rations nothing away, but still
        // hands out a permit rather than a semaphore that cannot be acquired.
        let certs_only = config_with(vec![listener("0.0.0.0:4443", AuthMode::ClientCert)]);
        let plans = super::plan_listeners(&certs_only).unwrap();
        assert_eq!(super::basic_shard_count(&plans), 0);
        assert_eq!(super::auth_concurrency(0), 1);
    }

    #[test]
    fn automatic_shard_count_is_within_bounds() {
        let shards = super::resolve_shard_count(0);
        assert!(shards >= 1);
        assert!(shards <= super::MAX_SHARDS);
        if !cfg!(target_os = "linux") {
            assert_eq!(shards, 1, "sharding needs SO_REUSEPORT, so Linux only");
        }
    }
}
