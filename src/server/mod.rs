// QUIC listener and connection accept loop.

mod authentication;
mod request;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use std::sync::{Mutex, RwLock};

use tokio::sync::Semaphore;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use self::authentication::AuthOutcome;
use self::request::{PendingAuth, PendingConnectSetups, RequestContext};
use crate::address_pool::AddressPool;
use crate::auth::BasicAuthenticator;
use crate::capsule;
use crate::capsule::{AssignedAddress, CapsuleFrame, IpAddress, IpAddressRange};
use crate::config::ServerConfig;
use crate::connection::{AwaitingAuth, ClientConnection};
use crate::datagram::{self, DatagramHeader};
use crate::fxhash::FxHashMap;
use crate::ip_packet;
use crate::net::quic::{
    MAX_BATCH_PACKETS, MAX_DATAGRAM_SIZE, QuicUdpSocket, RecvPacketBatch, SendPacketBatch,
};
#[cfg(target_os = "linux")]
use crate::net::target_udp;
use crate::net::target_udp::TargetRecvBatch;
use crate::policy::TargetPolicy;
use crate::routing::{RoutingTable, TunnelOwner};
use crate::scheduler::{DirtySet, TimerQueue};
use crate::tun::{self, TunManager, TunRecvBatch, TunSendBatch};
use crate::tunnel::ip::IpTunnel;
use crate::tunnel::tcp::{PendingTcpTunnel, TcpRelayEvent, TcpTunnel, spawn_tcp_connect};
use crate::tunnel::udp::UdpTunnel;

/// Unique connection ID length.
const CONN_ID_LEN: usize = 16;

/// Bounded queue used by per-tunnel receive tasks to wake the main loop.
///
/// Counted in batches, so the datagram bound is this times
/// [`MAX_UDP_RECV_BATCH`].
const UDP_RESPONSE_QUEUE_CAPACITY: usize = 256;

/// TCP readers wait for the main loop to acknowledge each chunk, so this
/// queue bounds both wakeups and response memory across all tunnels.
const TCP_RELAY_QUEUE_CAPACITY: usize = 1024;

/// Drain a bounded batch of already-buffered QUIC packets per readiness wakeup.
const MAX_QUIC_RECV_BATCH: usize = MAX_BATCH_PACKETS;

/// Bound on TUN packets handled per readiness wakeup, so a busy TUN device
/// cannot starve the QUIC socket. One offloaded read already yields a whole
/// GSO aggregate, so this is the size of a single batched read.
const MAX_TUN_RECV_BATCH: usize = tun::TUN_BATCH_SIZE;

/// Upper bound on shards, so a machine with a very high core count does not
/// fan out into more event loops than the listen socket can usefully feed.
const MAX_SHARDS: usize = 32;

/// Queue depth for packets handed between shards.
const SHARD_FORWARD_QUEUE_CAPACITY: usize = 1024;

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

/// Concurrent password verifications allowed across all shards.
///
/// Each one costs roughly 19 MiB and tens of milliseconds of CPU, so this caps
/// both the memory and the CPU an unauthenticated caller can demand. Two per
/// shard keeps every shard able to make progress, but never more than one per
/// core: hashing moved off the event loop still competes with it for CPU, and
/// oversubscribing just trades a stall for scheduler thrash.
fn auth_concurrency(shards: usize) -> usize {
    let cores = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    (shards * 2).min(cores.max(2))
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

/// Top-level MASQUE server.
///
/// Runs one event loop per shard. Each shard binds the listen address with
/// `SO_REUSEPORT` and owns a disjoint set of connections, so QUIC's per-packet
/// crypto — which is what saturates a core — spreads across them. The kernel
/// hashes each 4-tuple to a shard, and the rare packet that lands on the wrong
/// one (a client that changed address) is handed to its owner rather than
/// dropped.
pub struct Server {
    shards: Vec<Shard>,
}

impl Server {
    /// Create a new server bound to the configured address.
    pub async fn bind(config: ServerConfig) -> anyhow::Result<Self> {
        if config.auth.enabled {
            // Surface a bad credential configuration once, before any shard
            // binds the listen port.
            BasicAuthenticator::new(&config.auth.username, &config.auth.password_hash)?;
        } else {
            warn!("proxy authentication is disabled");
        }

        // Flow-control autotuning only ever grows a window toward its ceiling,
        // so a ceiling below the advertised initial credit is a config mistake
        // rather than something to silently honour. Check before binding, so a
        // misconfigured server never briefly takes the listen port.
        if config.quic.max_connection_window < config.quic.initial_max_data {
            anyhow::bail!(
                "quic.max_connection_window ({}) must be at least quic.initial_max_data ({})",
                config.quic.max_connection_window,
                config.quic.initial_max_data
            );
        }
        if config.quic.max_stream_window < config.quic.initial_max_stream_data {
            anyhow::bail!(
                "quic.max_stream_window ({}) must be at least \
                 quic.initial_max_stream_data ({})",
                config.quic.max_stream_window,
                config.quic.initial_max_stream_data
            );
        }

        let shard_count = resolve_shard_count(config.server.shards);
        // Sharing one address needs SO_REUSEPORT, which only Linux provides in
        // the load-balancing form this depends on.
        let reuseport = shard_count > 1;
        if reuseport && !cfg!(target_os = "linux") {
            anyhow::bail!(
                "server.shards = {shard_count} needs SO_REUSEPORT, which is only \
                 supported on Linux; set server.shards = 1"
            );
        }

        let address_pool = AddressPool::new(&config.ip_proxy.ipv4_pool, &config.ip_proxy.ipv6_pool)
            .map_err(|e| anyhow::anyhow!("address pool: {e}"))?;

        let tun = build_tun(&config)?;

        let mut key_bytes = [0u8; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut key_bytes)
            .map_err(|_| anyhow::anyhow!("failed to seed connection ID key"))?;

        // Every shard needs a handle to every other shard's inboxes, so the
        // channels are made before the shards that read them.
        let mut forward_tx = Vec::with_capacity(shard_count);
        let mut forward_rx = Vec::with_capacity(shard_count);
        let mut tun_tx = Vec::with_capacity(shard_count);
        let mut tun_rx = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            let (tx, rx) = mpsc::channel(SHARD_FORWARD_QUEUE_CAPACITY);
            forward_tx.push(tx);
            forward_rx.push(rx);
            let (tx, rx) = mpsc::channel(SHARD_FORWARD_QUEUE_CAPACITY);
            tun_tx.push(tx);
            tun_rx.push(rx);
        }

        let shared = Arc::new(Shared {
            address_pool: Mutex::new(address_pool),
            routing_table: RwLock::new(RoutingTable::new()),
            cid_shard: RwLock::new(FxHashMap::default()),
            index_shard: RwLock::new(FxHashMap::default()),
            next_conn_index: AtomicU64::new(0),
            conn_id_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key_bytes),
            tun,
            forward_tx,
            tun_tx,
            auth_permits: Arc::new(Semaphore::new(auth_concurrency(shard_count))),
            auth_queue_slots: Arc::new(Semaphore::new(MAX_PENDING_AUTH_GLOBAL)),
        });

        let mut shards = Vec::with_capacity(shard_count);
        for (index, (forward_rx, tun_rx)) in forward_rx.into_iter().zip(tun_rx).enumerate() {
            shards.push(
                Shard::bind(
                    index,
                    Arc::clone(&shared),
                    config.clone(),
                    reuseport,
                    forward_rx,
                    tun_rx,
                )
                .await?,
            );
        }

        info!(shards = shard_count, "server ready");
        Ok(Self { shards })
    }

    /// Run every shard until they all stop.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        // A single shard keeps the current behaviour of running on the caller's
        // task, which keeps the common case free of a spawn and a join.
        if self.shards.len() == 1 {
            return self.shards[0].run().await;
        }

        let mut tasks = tokio::task::JoinSet::new();
        for mut shard in self.shards.drain(..) {
            tasks.spawn(async move {
                let index = shard.index;
                let result = shard.run().await;
                (index, result)
            });
        }

        let mut outcome = Ok(());
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((index, Err(error))) => {
                    error!(shard = index, %error, "shard exited with an error");
                    if outcome.is_ok() {
                        outcome = Err(error);
                    }
                }
                Ok((_, Ok(()))) => {}
                Err(error) => {
                    error!(%error, "shard task panicked");
                    if outcome.is_ok() {
                        outcome = Err(anyhow::anyhow!("shard task panicked: {error}"));
                    }
                }
            }
        }
        outcome
    }
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
                // SAFETY: The socket is live, connected, and nonblocking for
                // the duration of this readiness callback.
                unsafe { target_udp::recv_mmsg(socket.as_raw_fd(), batch) }
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

/// State every shard shares.
///
/// None of it is on the per-packet path: the pool and routing table are touched
/// only when a CONNECT-IP tunnel opens or closes or when a TUN packet needs an
/// owner, and the ownership maps only when a connection is created, destroyed,
/// or has migrated to a different shard's socket.
struct Shared {
    address_pool: Mutex<AddressPool>,
    routing_table: RwLock<RoutingTable>,
    /// Which shard owns each server-issued connection ID. Consulted when a
    /// packet lands on a shard that does not know the connection, which is what
    /// a client migrating to a new address looks like.
    cid_shard: RwLock<FxHashMap<quiche::ConnectionId<'static>, usize>>,
    /// Which shard owns each connection index, for routing TUN packets.
    index_shard: RwLock<FxHashMap<u64, usize>>,
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
    /// Shared TUN device for CONNECT-IP tunnels (None if IP proxy disabled).
    tun: Option<TunManager>,
    /// Inbox per shard for packets forwarded after a migration.
    forward_tx: Vec<mpsc::Sender<ForwardedPacket>>,
    /// Inbox per shard for TUN packets belonging to its connections.
    tun_tx: Vec<mpsc::Sender<Vec<u8>>>,
    /// Bounds how many password verifications run at once.
    ///
    /// Argon2id is memory-hard on purpose, so unbounded concurrency would let
    /// unauthenticated requests turn into hundreds of megabytes and cores of
    /// work. The old inline check bounded this at one per shard by blocking
    /// the event loop; this keeps a bound without the stall.
    auth_permits: Arc<Semaphore>,
    /// Bounds both queued and running password verifications across all shards.
    auth_queue_slots: Arc<Semaphore>,
}

/// One shard: an independent event loop over its own share of connections.
struct Shard {
    index: usize,
    shared: Arc<Shared>,
    socket: QuicUdpSocket,
    quic_config: quiche::Config,
    h3_config: quiche::h3::Config,
    connections: FxHashMap<quiche::ConnectionId<'static>, ClientConnection>,
    auth: Option<Arc<BasicAuthenticator>>,
    tcp_policy: TargetPolicy,
    udp_policy: TargetPolicy,
    config: ServerConfig,
    /// Reverse index for routing TUN packets without scanning every connection.
    conn_by_index: FxHashMap<u64, quiche::ConnectionId<'static>>,
    udp_response_tx: mpsc::Sender<UdpResponse>,
    udp_response_rx: mpsc::Receiver<UdpResponse>,
    tcp_event_tx: mpsc::Sender<TcpRelayEvent>,
    tcp_event_rx: mpsc::Receiver<TcpRelayEvent>,
    forward_rx: mpsc::Receiver<ForwardedPacket>,
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
        shared: Arc<Shared>,
        config: ServerConfig,
        reuseport: bool,
        forward_rx: mpsc::Receiver<ForwardedPacket>,
        tun_rx: mpsc::Receiver<Vec<u8>>,
    ) -> anyhow::Result<Self> {
        let auth = if config.auth.enabled {
            Some(BasicAuthenticator::new(
                &config.auth.username,
                &config.auth.password_hash,
            )?)
        } else {
            None
        };

        let socket = QuicUdpSocket::bind_shared(
            config.server.listen_addr,
            config.quic.max_datagram_size,
            config.quic.enable_udp_gso,
            config.quic.enable_udp_gro,
            reuseport,
        )
        .await?;
        info!(
            shard = index,
            addr = %config.server.listen_addr,
            udp_gso = socket.udp_gso_enabled(),
            udp_gro = socket.udp_gro_enabled(),
            "listening"
        );

        let mut quic_config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

        // TLS
        quic_config.load_cert_chain_from_pem_file(config.tls.cert_path.to_str().unwrap_or(""))?;
        quic_config.load_priv_key_from_pem_file(config.tls.key_path.to_str().unwrap_or(""))?;

        quic_config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;

        // Transport parameters
        quic_config.set_max_idle_timeout(config.server.idle_timeout_secs * 1000);
        quic_config.set_max_recv_udp_payload_size(config.quic.max_datagram_size);
        quic_config.set_max_send_udp_payload_size(config.quic.max_datagram_size);
        quic_config.set_initial_max_data(config.quic.initial_max_data);
        quic_config.set_initial_max_stream_data_bidi_local(config.quic.initial_max_stream_data);
        quic_config.set_initial_max_stream_data_bidi_remote(config.quic.initial_max_stream_data);
        quic_config.set_initial_max_stream_data_uni(config.quic.initial_max_stream_data);
        quic_config.set_initial_max_streams_bidi(config.quic.initial_max_streams_bidi);
        quic_config.set_initial_max_streams_uni(100);
        quic_config.set_max_connection_window(config.quic.max_connection_window);
        quic_config.set_max_stream_window(config.quic.max_stream_window);
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

        // DATAGRAM extension
        if config.quic.enable_dgram {
            quic_config.enable_dgram(
                true,
                config.quic.dgram_recv_queue_len,
                config.quic.dgram_send_queue_len,
            );
        }

        let mut h3_config = quiche::h3::Config::new()?;
        h3_config.set_max_field_section_size(8192);
        h3_config.enable_extended_connect(true);

        let tcp_policy = TargetPolicy::new(
            &config.tcp_proxy.allow_targets,
            &config.tcp_proxy.deny_targets,
        );

        let udp_policy = TargetPolicy::new(
            &config.udp_proxy.allow_targets,
            &config.udp_proxy.deny_targets,
        );

        let (udp_response_tx, udp_response_rx) = mpsc::channel(UDP_RESPONSE_QUEUE_CAPACITY);
        let (tcp_event_tx, tcp_event_rx) = mpsc::channel(TCP_RELAY_QUEUE_CAPACITY);
        let (auth_tx, auth_rx) = mpsc::channel(AUTH_RESULT_QUEUE_CAPACITY);

        Ok(Self {
            index,
            shared,
            socket,
            quic_config,
            h3_config,
            connections: FxHashMap::default(),
            auth: auth.map(Arc::new),
            tcp_policy,
            udp_policy,
            config,
            conn_by_index: FxHashMap::default(),
            udp_response_tx,
            udp_response_rx,
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
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut dgram_buf = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut tun_recv = TunRecvBatch::new(self.config.ip_proxy.tun_mtu);
        let mut tun_send = TunSendBatch::new();
        let mut recv_batch = RecvPacketBatch::new(MAX_QUIC_RECV_BATCH);
        let mut send_batch = SendPacketBatch::new();
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
        // The connections serviced in the current round. Held across
        // iterations so its allocation is reused.
        let mut serviced: Vec<u64> = Vec::new();

        loop {
            self.dirty.end_round();
            serviced.clear();

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
                TcpRelay(Option<TcpRelayEvent>),
                TunPacket(std::io::Result<usize>),
                /// A QUIC packet another shard received for one of ours.
                Forwarded(Option<ForwardedPacket>),
                /// A TUN packet another shard read for one of our tunnels.
                TunInbound(Option<Vec<u8>>),
                /// Credentials finished verifying off the event loop.
                AuthDone(Option<AuthOutcome>),
                Shutdown,
                Timeout,
            }

            let event = if let Some(timeout) = timeout {
                tokio::select! {
                    _ = tokio::signal::ctrl_c(), if !shutting_down => {
                        Event::Shutdown
                    }
                    response = self.udp_response_rx.recv(), if !shutting_down => {
                        Event::TargetDatagram(response)
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
                    info!("shutdown signal received, draining connections...");
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
                    recv_batch.for_each_packet_mut(received, |packet, from| {
                        if !shutting_down {
                            self.handle_packet(packet, from, local_addr);
                            return;
                        }

                        // During shutdown, still feed packets to quiche so it
                        // can send CONNECTION_CLOSE frames.
                        if let Ok(hdr) = quiche::Header::from_slice(packet, CONN_ID_LEN)
                            && let Some(client) = self.connections.get_mut(&hdr.dcid)
                        {
                            let recv_info = quiche::RecvInfo {
                                from,
                                to: local_addr,
                            };
                            client.quic.recv(packet, recv_info).ok();
                            let index = client.index;
                            self.dirty.mark(index);
                        }
                    });
                }
                Event::PacketBatch(Err(e)) => {
                    error!(%e, "socket recv error");
                }
                Event::TargetDatagram(Some(response)) => {
                    self.relay_target_datagrams(response);
                }
                Event::TargetDatagram(None) => {}
                Event::TcpRelay(Some(event)) => {
                    self.handle_tcp_event(event);
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
                Event::Forwarded(Some(mut packet)) => {
                    self.handle_packet(&mut packet.data, packet.from, local_addr);
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

            // A connection whose deadline has arrived needs driving even if
            // nothing arrived for it.
            self.expire_connection_timers(Instant::now());
            self.dirty.take_into(&mut serviced);

            // Process QUIC DATAGRAMs → forward to target UDP/TUN.
            if !shutting_down {
                self.flush_tcp_responses(&serviced);
                self.relay_client_datagrams(&serviced, &mut dgram_buf, &mut tun_send)
                    .await;
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
                next_idle_sweep = now + IDLE_SWEEP_INTERVAL;
                if !shutting_down {
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
                    self.shared
                        .cid_shard
                        .write()
                        .expect("cid ownership poisoned")
                        .remove(&id);
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
                    info!("all connections drained, exiting");
                    return Ok(());
                }
                if let Some(deadline) = drain_deadline
                    && Instant::now() >= deadline
                {
                    warn!(
                        remaining = self.connections.len(),
                        "drain timeout reached, forcing exit"
                    );
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

    /// Mark every connection whose deadline has arrived as needing servicing.
    ///
    /// A deadline that moved later leaves its earlier entry in the queue, so an
    /// entry only counts when it still matches the deadline the connection
    /// holds. Anything else is a superseded entry and is dropped.
    fn expire_connection_timers(&mut self, now: Instant) {
        let connections = &mut self.connections;
        let conn_by_index = &self.conn_by_index;
        let dirty = &mut self.dirty;

        self.timers.expire(now, |index, at| {
            let Some(conn_id) = conn_by_index.get(&index) else {
                return;
            };
            let Some(client) = connections.get_mut(conn_id) else {
                return;
            };
            if client.scheduled_deadline != Some(at) {
                return;
            }
            // Cleared so `reschedule` always queues a fresh entry for whatever
            // deadline the connection has after being driven.
            client.scheduled_deadline = None;
            dirty.mark(index);
        });
    }

    /// Queue this connection's next wakeup, if it changed.
    ///
    /// An unchanged deadline already has a live entry in the queue, so leaving
    /// it alone keeps the queue from growing once per drive on idle-ish
    /// connections.
    fn reschedule(client: &mut ClientConnection, timers: &mut TimerQueue, now: Instant) {
        let deadline = client.next_deadline(now);
        if client.scheduled_deadline == deadline {
            return;
        }
        client.scheduled_deadline = deadline;
        if let Some(at) = deadline {
            timers.schedule(client.index, at);
        }
    }

    /// Process an incoming UDP packet (QUIC).
    fn handle_packet(&mut self, buf: &mut [u8], from: SocketAddr, local: SocketAddr) {
        let hdr = match quiche::Header::from_slice(buf, CONN_ID_LEN) {
            Ok(v) => v,
            Err(e) => {
                debug!(%e, "failed to parse QUIC header");
                return;
            }
        };

        // Established packets carry the server-issued CID and take this fast
        // path. Deriving a CID requires HMAC-SHA256, so only do that for a new
        // Initial or for packets that still carry the original destination ID.
        let key = if let Some((conn_id, _)) = self.connections.get_key_value(&hdr.dcid) {
            conn_id.clone()
        } else {
            let conn_id = ring::hmac::sign(&self.shared.conn_id_key, &hdr.dcid);
            let conn_id = quiche::ConnectionId::from_vec(conn_id.as_ref()[..CONN_ID_LEN].to_vec());

            if !self.connections.contains_key(&conn_id) {
                if hdr.ty != quiche::Type::Initial {
                    // The kernel steers by 4-tuple, so a client that changed
                    // address can land here instead of on its owner. Hand the
                    // packet over rather than dropping the connection.
                    let owner = self
                        .shared
                        .cid_shard
                        .read()
                        .expect("cid ownership poisoned")
                        .get(&conn_id)
                        .copied();
                    match owner {
                        Some(shard) if shard != self.index => {
                            let forwarded = ForwardedPacket {
                                data: buf.to_vec(),
                                from,
                            };
                            // Dropping under pressure is what the network
                            // would have done; QUIC will retransmit.
                            if self.shared.forward_tx[shard].try_send(forwarded).is_err() {
                                debug!(shard, "shard forward queue full, dropping packet");
                            }
                        }
                        _ => debug!("non-initial packet for unknown connection"),
                    }
                    return;
                }

                // Enforce max_connections limit.
                if self.connections.len() >= self.config.server.max_connections {
                    warn!("max connections reached, rejecting new connection");
                    return;
                }

                let scid = quiche::ConnectionId::from_vec(conn_id.as_ref().to_vec());

                let quic = match quiche::accept(&scid, None, local, from, &mut self.quic_config) {
                    Ok(c) => c,
                    Err(e) => {
                        error!(%e, "failed to accept connection");
                        return;
                    }
                };

                info!(shard = self.index, ?scid, %from, "new connection");

                let conn_idx = self.shared.next_conn_index.fetch_add(1, Ordering::Relaxed);
                self.conn_by_index.insert(conn_idx, scid.clone());
                // Publish ownership so another shard can hand back a packet
                // that reaches it after this client migrates, and so TUN
                // packets can find this connection.
                self.shared
                    .cid_shard
                    .write()
                    .expect("cid ownership poisoned")
                    .insert(scid.clone(), self.index);
                self.shared
                    .index_shard
                    .write()
                    .expect("index ownership poisoned")
                    .insert(conn_idx, self.index);

                let client = ClientConnection::new(quic, conn_idx);
                self.connections.insert(scid, client);
            }

            conn_id
        };

        let client = self.connections.get_mut(&key).unwrap();
        let conn_idx = client.index;
        // Anything quiche does with this packet — ACKs, stream data, timer
        // changes — needs a following drive, so the connection is dirty from
        // here regardless of which path below it takes.
        self.dirty.mark(conn_idx);

        // Feed the packet to quiche.
        let recv_info = quiche::RecvInfo { from, to: local };

        if let Err(e) = client.quic.recv(buf, recv_info) {
            debug!(%e, "quiche recv error");
            return;
        }

        // Upgrade to HTTP/3 once QUIC handshake completes.
        if client.h3.is_none() && client.quic.is_established() {
            match quiche::h3::Connection::with_transport(&mut client.quic, &self.h3_config) {
                Ok(h3) => {
                    client.h3 = Some(h3);
                    debug!("HTTP/3 connection established");
                }
                Err(e) => {
                    warn!(%e, "failed to create HTTP/3 connection");
                }
            }
        }

        // Collect pending tunnel setups so we can do async I/O outside
        // the borrow of h3.
        let mut pending_setups = PendingConnectSetups::default();
        let mut closed_ip_streams: Vec<u64> = Vec::new();
        let mut failed_tcp_streams: Vec<u64> = Vec::new();
        let mut pending_auth: Vec<PendingAuth> = Vec::new();

        // Process HTTP/3 events.
        if let Some(h3) = &mut client.h3 {
            loop {
                match h3.poll(&mut client.quic) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        let tcp_setup_count = pending_setups.tcp.len();
                        let request_context = RequestContext {
                            config: &self.config,
                            auth: self.auth.as_deref(),
                            udp_policy: &self.udp_policy,
                        };
                        if let Some(pending) = Self::handle_request(
                            h3,
                            &mut client.quic,
                            stream_id,
                            &list,
                            &request_context,
                            &mut pending_setups,
                        ) {
                            if client.awaiting_auth.len() >= MAX_PENDING_AUTH_PER_CONNECTION {
                                warn!(
                                    stream_id,
                                    "too many CONNECT requests awaiting authorization"
                                );
                                Self::send_error_response(h3, &mut client.quic, stream_id, 503);
                            } else {
                                client.awaiting_auth.insert(stream_id, AwaitingAuth::new());
                                pending_auth.push(pending);
                            }
                        }
                        if pending_setups.tcp.len() > tcp_setup_count {
                            debug_assert_eq!(pending_setups.tcp.len(), tcp_setup_count + 1);
                            debug_assert_eq!(pending_setups.tcp.last().unwrap().0, stream_id);
                            client
                                .pending_tcp_tunnels
                                .insert(stream_id, PendingTcpTunnel::staging(stream_id));
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        // Unread until the CONNECT is authorized, so a caller
                        // that never authenticates buffers nothing here.
                        if client.awaiting_auth.contains_key(&stream_id) {
                            continue;
                        }
                        if !Self::relay_tcp_request_body(
                            h3,
                            &mut client.quic,
                            stream_id,
                            &mut client.pending_tcp_tunnels,
                            &mut client.tcp_tunnels,
                        ) {
                            failed_tcp_streams.push(stream_id);
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Finished)) => {
                        if let Some(finished) = client.awaiting_auth.get_mut(&stream_id) {
                            finished.client_finished = true;
                        }
                        if let Some(tunnel) = client.pending_tcp_tunnels.get_mut(&stream_id) {
                            tunnel.client_finished = true;
                            tunnel.last_activity = Instant::now();
                        }
                        if let Some(tunnel) = client.tcp_tunnels.get_mut(&stream_id) {
                            tunnel.finish_client();
                        }
                        // Stream closed by client — remove tunnel if any.
                        if client.udp_tunnels.remove(&stream_id).is_some() {
                            info!(stream_id, "UDP tunnel closed by client");
                        }
                        if client.ip_tunnels.contains_key(&stream_id) {
                            closed_ip_streams.push(stream_id);
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Reset { .. })) => {
                        // A late verification result for this stream is moot.
                        client.awaiting_auth.remove(&stream_id);
                        if client.pending_tcp_tunnels.remove(&stream_id).is_some() {
                            info!(stream_id, "pending TCP tunnel reset by client");
                        }
                        if client.tcp_tunnels.remove(&stream_id).is_some() {
                            info!(stream_id, "TCP tunnel reset by client");
                        }
                        if client.udp_tunnels.remove(&stream_id).is_some() {
                            info!(stream_id, "UDP tunnel reset by client");
                        }
                        if client.ip_tunnels.contains_key(&stream_id) {
                            closed_ip_streams.push(stream_id);
                        }
                    }
                    Ok((_stream_id, quiche::h3::Event::PriorityUpdate)) => {}
                    Ok((_stream_id, quiche::h3::Event::GoAway)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => {
                        error!(%e, "HTTP/3 error");
                        break;
                    }
                }
            }
        }

        for stream_id in failed_tcp_streams {
            warn!(
                stream_id,
                "closing TCP tunnel after request-body backpressure failure"
            );
            Self::reset_tcp_stream(client, stream_id);
        }

        // Clean up closed IP tunnels: release addresses, remove routes.
        for stream_id in closed_ip_streams {
            Self::teardown_ip_tunnel(&self.shared, client, stream_id, conn_idx);
        }

        self.apply_connect_setups(conn_idx, pending_setups);
        self.spawn_auth_verifications(conn_idx, pending_auth);
    }

    /// Apply the tunnel setups a batch of CONNECT requests produced.
    ///
    /// Split out of `handle_packet` because a request whose credentials are
    /// verified off the event loop arrives here later, through
    /// `handle_auth_result`, rather than in the same pass as its headers.
    fn apply_connect_setups(&mut self, conn_idx: u64, pending: PendingConnectSetups) {
        if pending.is_empty() {
            return;
        }
        let PendingConnectSetups {
            tcp: pending_tcp_setups,
            udp: pending_udp_setups,
            ip: pending_ip_setups,
        } = pending;
        let Some(conn_id) = self.conn_by_index.get(&conn_idx).cloned() else {
            return;
        };
        let Some(client) = self.connections.get_mut(&conn_id) else {
            return;
        };
        let max_tunnels = self.config.server.max_tunnels_per_connection;

        for (stream_id, target) in pending_tcp_setups {
            if !client.pending_tcp_tunnels.contains_key(&stream_id) {
                continue;
            }
            if client.tunnel_count() > max_tunnels {
                warn!(
                    stream_id,
                    total_tunnels = client.tunnel_count(),
                    "tunnel limit reached, rejecting TCP tunnel"
                );
                if let Some(h3) = &mut client.h3 {
                    Self::send_error_response(h3, &mut client.quic, stream_id, 503);
                }
                client.pending_tcp_tunnels.remove(&stream_id);
                continue;
            }

            let connect_task = spawn_tcp_connect(
                conn_idx,
                stream_id,
                target,
                self.tcp_policy.clone(),
                Duration::from_secs(self.config.tcp_proxy.connect_timeout_secs),
                self.tcp_event_tx.clone(),
            );
            if let Some(pending) = client.pending_tcp_tunnels.get_mut(&stream_id) {
                pending.start_connect(connect_task);
            }
        }

        let udp_response_tx = if pending_udp_setups.is_empty() {
            None
        } else {
            Some(self.udp_response_tx.clone())
        };
        // The listener itself cannot receive a larger UDP datagram than this,
        // so matching that effective QUIC limit keeps target responses intact
        // without allowing a bad configuration to allocate unbounded buffers
        // per tunnel.
        let target_datagram_size = self
            .config
            .quic
            .max_datagram_size
            .clamp(1, MAX_DATAGRAM_SIZE);
        for (stream_id, target) in pending_udp_setups {
            if client.tunnel_count() >= max_tunnels {
                warn!(
                    stream_id,
                    total_tunnels = client.tunnel_count(),
                    "tunnel limit reached, rejecting"
                );
                if let Some(h3) = &mut client.h3 {
                    Self::send_error_response(h3, &mut client.quic, stream_id, 503);
                }
                continue;
            }

            // Frame the datagram header once per tunnel, rather than re-running
            // the varint encoder for every relayed packet.
            let header = match DatagramHeader::new(stream_id) {
                Ok(h) => h,
                Err(e) => {
                    warn!(stream_id, %e, "cannot frame datagrams for stream");
                    if let Some(h3) = &mut client.h3 {
                        Self::send_error_response(h3, &mut client.quic, stream_id, 400);
                    }
                    continue;
                }
            };

            match target.resolve() {
                Ok(addrs) => {
                    // Use the first resolved address.
                    let addr = addrs[0];
                    // We can't await here (not async fn), so create the
                    // UdpTunnel synchronously using std::net, then convert.
                    match std::net::UdpSocket::bind(if addr.is_ipv4() {
                        "0.0.0.0:0"
                    } else {
                        "[::]:0"
                    }) {
                        Ok(std_sock) => {
                            if let Err(e) = std_sock.connect(addr) {
                                warn!(stream_id, %e, "UDP connect failed");
                                if let Some(h3) = &mut client.h3 {
                                    Self::send_error_response(h3, &mut client.quic, stream_id, 502);
                                }
                                continue;
                            }
                            if let Err(e) = std_sock.set_nonblocking(true) {
                                warn!(stream_id, %e, "UDP nonblocking setup failed");
                                if let Some(h3) = &mut client.h3 {
                                    Self::send_error_response(h3, &mut client.quic, stream_id, 502);
                                }
                                continue;
                            }
                            let recv_std = match std_sock.try_clone() {
                                Ok(socket) => socket,
                                Err(e) => {
                                    warn!(stream_id, %e, "UDP socket clone failed");
                                    if let Some(h3) = &mut client.h3 {
                                        Self::send_error_response(
                                            h3,
                                            &mut client.quic,
                                            stream_id,
                                            502,
                                        );
                                    }
                                    continue;
                                }
                            };
                            match UdpSocket::from_std(recv_std) {
                                Ok(tok_sock) => {
                                    let socket = Arc::new(tok_sock);
                                    let recv_socket = Arc::clone(&socket);
                                    let response_tx = udp_response_tx.as_ref().unwrap().clone();
                                    let recv_task = tokio::spawn(async move {
                                        // One `recvmmsg` per readiness instead
                                        // of a `recvfrom` per datagram, and one
                                        // channel send — so a burst costs one
                                        // syscall and one wakeup of the loop.
                                        let mut batch = TargetRecvBatch::new(target_datagram_size);
                                        loop {
                                            let received =
                                                match recv_target_batch(&recv_socket, &mut batch)
                                                    .await
                                                {
                                                    Ok(received) => received,
                                                    Err(e) => {
                                                        debug!(
                                                            stream_id,
                                                            %e,
                                                            "target recv failed"
                                                        );
                                                        break;
                                                    }
                                                };

                                            let datagrams: Vec<Vec<u8>> = batch
                                                .datagrams(received)
                                                .map(|payload| header.encode(payload))
                                                .collect();
                                            if datagrams.is_empty() {
                                                continue;
                                            }

                                            let response = UdpResponse {
                                                connection_index: conn_idx,
                                                stream_id,
                                                datagrams,
                                            };
                                            if response_tx.send(response).await.is_err() {
                                                break;
                                            }
                                        }
                                    });
                                    let tunnel = UdpTunnel::from_socket(
                                        stream_id, addr, std_sock, socket, recv_task,
                                    );
                                    info!(
                                        stream_id,
                                        target = %addr,
                                        "UDP tunnel established"
                                    );
                                    client.udp_tunnels.insert(stream_id, tunnel);
                                }
                                Err(e) => {
                                    warn!(stream_id, %e, "tokio socket convert failed");
                                    if let Some(h3) = &mut client.h3 {
                                        Self::send_error_response(
                                            h3,
                                            &mut client.quic,
                                            stream_id,
                                            502,
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!(stream_id, %e, "UDP bind failed");
                            if let Some(h3) = &mut client.h3 {
                                Self::send_error_response(h3, &mut client.quic, stream_id, 502);
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(stream_id, %e, "DNS resolution failed");
                    if let Some(h3) = &mut client.h3 {
                        Self::send_error_response(h3, &mut client.quic, stream_id, 502);
                    }
                }
            }
        }

        // Handle pending CONNECT-IP tunnel setups: allocate addresses,
        // register routes, send capsules.
        for stream_id in pending_ip_setups {
            if client.tunnel_count() >= max_tunnels {
                warn!(
                    stream_id,
                    total_tunnels = client.tunnel_count(),
                    "tunnel limit reached, rejecting IP tunnel"
                );
                if let Some(h3) = &mut client.h3 {
                    Self::send_error_response(h3, &mut client.quic, stream_id, 503);
                }
                continue;
            }
            Self::setup_ip_tunnel(&self.shared, client, stream_id, conn_idx);
        }
    }

    /// Allocate addresses, register routes, send capsules for a new IP tunnel.
    fn setup_ip_tunnel(
        shared: &Shared,
        client: &mut ClientConnection,
        stream_id: u64,
        conn_idx: u64,
    ) {
        let mut tunnel = IpTunnel::new(stream_id);

        // Allocate an IPv4 address if the pool has one.
        let (v4_result, v6_result) = {
            let mut address_pool = shared.address_pool.lock().expect("address pool poisoned");
            (address_pool.allocate_v4(), address_pool.allocate_v6())
        };

        if v4_result.is_err() && v6_result.is_err() {
            warn!(stream_id, "address pool exhausted for IP tunnel");
            if let Some(h3) = &mut client.h3 {
                Self::send_error_response(h3, &mut client.quic, stream_id, 503);
            }
            return;
        }

        let mut assigned = Vec::new();

        if let Ok(v4_addr) = v4_result {
            let ip = IpAddr::V4(v4_addr);
            tunnel.assigned_addrs.push(ip);
            shared
                .routing_table
                .write()
                .expect("routing table poisoned")
                .insert(
                    ip,
                    TunnelOwner {
                        conn_id: conn_idx,
                        stream_id,
                    },
                );
            assigned.push(AssignedAddress {
                request_id: 0,
                ip: IpAddress::V4(v4_addr),
                prefix_len: 32,
            });
            info!(stream_id, addr = %v4_addr, "assigned IPv4 to IP tunnel");
        }

        if let Ok(v6_addr) = v6_result {
            let ip = IpAddr::V6(v6_addr);
            tunnel.assigned_addrs.push(ip);
            shared
                .routing_table
                .write()
                .expect("routing table poisoned")
                .insert(
                    ip,
                    TunnelOwner {
                        conn_id: conn_idx,
                        stream_id,
                    },
                );
            assigned.push(AssignedAddress {
                request_id: 0,
                ip: IpAddress::V6(v6_addr),
                prefix_len: 128,
            });
            info!(stream_id, addr = %v6_addr, "assigned IPv6 to IP tunnel");
        }

        // Send ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT back to back: one buffer,
        // one send_body call. The route advertisement is a default route, so
        // the client knows it can send all traffic through this tunnel.
        let mut capsules = Vec::new();
        capsule::encoder::encode(&CapsuleFrame::AddressAssign(assigned), &mut capsules);
        capsule::encoder::encode(
            &CapsuleFrame::RouteAdvertisement(vec![
                IpAddressRange {
                    start: IpAddress::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                    end: IpAddress::V4(std::net::Ipv4Addr::new(255, 255, 255, 255)),
                    ip_protocol: 0, // all protocols
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

        if let Some(h3) = &mut client.h3
            && let Err(e) = h3.send_body(&mut client.quic, stream_id, &capsules, false)
        {
            warn!(stream_id, %e, "failed to send CONNECT-IP capsules");
        }

        client.ip_tunnels.insert(stream_id, tunnel);
        info!(stream_id, "CONNECT-IP tunnel established");
    }

    /// Release addresses and remove routes for a closing IP tunnel.
    fn teardown_ip_tunnel(
        shared: &Shared,
        client: &mut ClientConnection,
        stream_id: u64,
        conn_idx: u64,
    ) {
        if let Some(tunnel) = client.ip_tunnels.remove(&stream_id) {
            info!(stream_id, "IP tunnel closed");

            // Release addresses back to the pool.
            shared
                .address_pool
                .lock()
                .expect("address pool poisoned")
                .release_all(&tunnel.assigned_addrs);

            // Remove this tunnel's routes by key — the tunnel knows exactly
            // which addresses it holds, so there is no need to scan the table.
            shared
                .routing_table
                .write()
                .expect("routing table poisoned")
                .remove_owned(
                    &tunnel.assigned_addrs,
                    &TunnelOwner {
                        conn_id: conn_idx,
                        stream_id,
                    },
                );
        }
    }

    /// Drain HTTP/3 request-body data for a standard CONNECT stream and queue
    /// it for the target TCP writer. Returning false asks the caller to reset
    /// the tunnel because its bounded buffer was exhausted or closed.
    fn relay_tcp_request_body(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        pending_tunnels: &mut FxHashMap<u64, PendingTcpTunnel>,
        tunnels: &mut FxHashMap<u64, TcpTunnel>,
    ) -> bool {
        if !pending_tunnels.contains_key(&stream_id) && !tunnels.contains_key(&stream_id) {
            debug!(stream_id, "H3 data event for a non-TCP tunnel");
            return true;
        }

        let mut body = [0_u8; 16 * 1024];
        loop {
            let len = match h3.recv_body(quic, stream_id, &mut body) {
                Ok(len) => len,
                Err(quiche::h3::Error::Done) => return true,
                Err(error) => {
                    warn!(stream_id, %error, "failed to receive CONNECT body");
                    return false;
                }
            };
            if len == 0 {
                continue;
            }

            if let Some(tunnel) = tunnels.get_mut(&stream_id) {
                if !tunnel.queue_client_data(body[..len].to_vec()) {
                    warn!(stream_id, "TCP client-to-target buffer exhausted");
                    return false;
                }
                continue;
            }
            if let Some(tunnel) = pending_tunnels.get_mut(&stream_id)
                && !tunnel.buffer_client_data(body[..len].to_vec())
            {
                warn!(stream_id, "pending TCP tunnel buffer exhausted");
                return false;
            }
        }
    }

    /// Apply an event generated by an asynchronous target TCP task.
    fn handle_tcp_event(&mut self, event: TcpRelayEvent) {
        let (connection_index, stream_id) = match &event {
            TcpRelayEvent::ConnectResult {
                connection_index,
                stream_id,
                ..
            }
            | TcpRelayEvent::Data {
                connection_index,
                stream_id,
                ..
            }
            | TcpRelayEvent::Eof {
                connection_index,
                stream_id,
            }
            | TcpRelayEvent::Error {
                connection_index,
                stream_id,
                ..
            } => (*connection_index, *stream_id),
        };

        let Some(conn_id) = self.conn_by_index.get(&connection_index).cloned() else {
            return;
        };
        let Some(client) = self.connections.get_mut(&conn_id) else {
            return;
        };
        // Every arm below writes to the connection — a response, body bytes, or
        // a stream reset — so all of them need a following drive.
        self.dirty.mark(connection_index);

        match event {
            TcpRelayEvent::ConnectResult { result, .. } => {
                let Some(mut pending) = client.pending_tcp_tunnels.remove(&stream_id) else {
                    return;
                };

                match result {
                    Ok((stream, target_addr)) => {
                        let Some(h3) = client.h3.as_mut() else {
                            return;
                        };
                        let headers = [quiche::h3::Header::new(b":status", b"200")];
                        if let Err(error) =
                            h3.send_response(&mut client.quic, stream_id, &headers, false)
                        {
                            warn!(
                                stream_id,
                                %error,
                                "failed to send standard CONNECT response"
                            );
                            Self::reset_tcp_stream(client, stream_id);
                            return;
                        }

                        let early_data = std::mem::take(&mut pending.early_data);
                        let client_finished = pending.client_finished;
                        drop(pending);

                        let mut tunnel = TcpTunnel::from_stream(
                            connection_index,
                            stream_id,
                            target_addr,
                            stream,
                            self.tcp_event_tx.clone(),
                        );
                        for data in early_data {
                            if !tunnel.queue_client_data(data) {
                                warn!(stream_id, "failed to transfer early CONNECT body");
                                Self::reset_tcp_stream(client, stream_id);
                                return;
                            }
                        }
                        if client_finished {
                            tunnel.finish_client();
                        }
                        client.tcp_tunnels.insert(stream_id, tunnel);
                        info!(
                            stream_id,
                            target = %target_addr,
                            "TCP tunnel established"
                        );
                    }
                    Err(failure) => {
                        warn!(
                            stream_id,
                            status = failure.status,
                            reason = %failure.reason,
                            "TCP tunnel setup failed"
                        );
                        if let Some(h3) = client.h3.as_mut() {
                            Self::send_error_response(
                                h3,
                                &mut client.quic,
                                stream_id,
                                failure.status,
                            );
                        }
                    }
                }
            }
            TcpRelayEvent::Data { data, .. } => {
                let accepted = client
                    .tcp_tunnels
                    .get_mut(&stream_id)
                    .is_some_and(|tunnel| tunnel.queue_response(data));
                if !accepted && client.tcp_tunnels.contains_key(&stream_id) {
                    warn!(stream_id, "TCP response chunk after the response closed");
                    Self::reset_tcp_stream(client, stream_id);
                }
            }
            TcpRelayEvent::Eof { .. } => {
                if let Some(tunnel) = client.tcp_tunnels.get_mut(&stream_id) {
                    tunnel.upstream_finished = true;
                    tunnel.last_activity = Instant::now();
                }
            }
            TcpRelayEvent::Error { reason, .. } => {
                if client.tcp_tunnels.contains_key(&stream_id) {
                    warn!(stream_id, %reason, "TCP relay failed");
                    Self::reset_tcp_stream(client, stream_id);
                }
            }
        }
    }

    /// Move target TCP response bytes into HTTP/3 with partial-write support.
    ///
    /// A blocked stream unblocks only when the peer grants more flow-control
    /// credit, which arrives as a packet and marks the connection dirty again,
    /// so visiting just `dirty` cannot strand a pending response.
    fn flush_tcp_responses(&mut self, dirty: &[u64]) {
        for index in dirty {
            let Some(conn_id) = self.conn_by_index.get(index) else {
                continue;
            };
            let Some(client) = self.connections.get_mut(conn_id) else {
                continue;
            };
            if client.tcp_tunnels.is_empty() {
                continue;
            }

            let mut failed = Vec::new();
            let mut completed = Vec::new();

            {
                let Some(h3) = client.h3.as_mut() else {
                    continue;
                };

                for (stream_id, tunnel) in &mut client.tcp_tunnels {
                    // Drain as many queued chunks as HTTP/3 will take. Each
                    // write releases that many bytes of the reader's budget, so
                    // the reader keeps running ahead instead of waiting for a
                    // round trip through this loop.
                    while let Some(response) = tunnel.front_response() {
                        let remaining = &response.data[response.offset..];
                        match h3.send_body(&mut client.quic, *stream_id, remaining, false) {
                            Ok(0) => break,
                            Ok(written) => tunnel.advance_response(written),
                            Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {
                                break;
                            }
                            Err(error) => {
                                warn!(
                                    stream_id,
                                    %error,
                                    "failed to send CONNECT response body"
                                );
                                failed.push(*stream_id);
                                break;
                            }
                        }
                    }

                    if !failed.contains(stream_id)
                        && !tunnel.has_pending_response()
                        && tunnel.upstream_finished
                        && !tunnel.response_finished
                    {
                        match h3.send_body(&mut client.quic, *stream_id, b"", true) {
                            Ok(_) => tunnel.response_finished = true,
                            Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {}
                            Err(error) => {
                                warn!(
                                    stream_id,
                                    %error,
                                    "failed to finish CONNECT response body"
                                );
                                failed.push(*stream_id);
                            }
                        }
                    }

                    if tunnel.is_complete() {
                        completed.push(*stream_id);
                    }
                }
            }

            failed.sort_unstable();
            failed.dedup();
            for stream_id in failed {
                Self::reset_tcp_stream(client, stream_id);
            }
            for stream_id in completed {
                if client.tcp_tunnels.remove(&stream_id).is_some() {
                    info!(stream_id, "TCP tunnel closed cleanly");
                }
            }
        }
    }

    fn reset_tcp_stream(client: &mut ClientConnection, stream_id: u64) {
        client.pending_tcp_tunnels.remove(&stream_id);
        client.tcp_tunnels.remove(&stream_id);
        let error = quiche::h3::WireErrorCode::ConnectError as u64;
        client
            .quic
            .stream_shutdown(stream_id, quiche::Shutdown::Read, error)
            .ok();
        client
            .quic
            .stream_shutdown(stream_id, quiche::Shutdown::Write, error)
            .ok();
    }

    /// Relay QUIC DATAGRAMs from clients to target UDP sockets and TUN device.
    ///
    /// A connection only has datagrams to hand over after receiving a packet,
    /// which is exactly what puts it in `dirty`.
    async fn relay_client_datagrams(
        &mut self,
        dirty: &[u64],
        dgram_buf: &mut [u8],
        tun_send: &mut TunSendBatch,
    ) {
        // Which tunnels have datagrams waiting to be written, so the flush at
        // the end of each connection does not have to scan all of them.
        let mut staged_udp_tunnels: Vec<u64> = Vec::new();

        for index in dirty {
            let Some(conn_id) = self.conn_by_index.get(index) else {
                continue;
            };
            let Some(client) = self.connections.get_mut(conn_id) else {
                continue;
            };

            staged_udp_tunnels.clear();

            loop {
                let len = match client.quic.dgram_recv(dgram_buf) {
                    Ok(len) => len,
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        debug!(%e, "dgram_recv error");
                        break;
                    }
                };

                let dgram = match datagram::decode_ref(&dgram_buf[..len]) {
                    Ok(d) => d,
                    Err(e) => {
                        debug!(%e, "malformed datagram");
                        continue;
                    }
                };

                // Only handle context_id=0 (raw payload)
                if dgram.context_id != 0 {
                    debug!(
                        context_id = dgram.context_id,
                        "ignoring non-zero context_id"
                    );
                    continue;
                }

                // Check UDP tunnels first. Datagrams are staged and written
                // as a batch once the connection's queue is drained, so a
                // client burst costs one syscall rather than one per datagram.
                if let Some(tunnel) = client.udp_tunnels.get_mut(&dgram.stream_id) {
                    if !staged_udp_tunnels.contains(&dgram.stream_id) {
                        staged_udp_tunnels.push(dgram.stream_id);
                    }
                    // A full stage is written straight away so a long burst
                    // does not grow the staging buffer without bound.
                    if tunnel.stage_to_target(dgram.payload)
                        && let Err(e) = tunnel.flush_to_target()
                    {
                        debug!(
                            stream_id = dgram.stream_id,
                            %e,
                            "send to target failed"
                        );
                    }
                    continue;
                }

                // Check IP tunnels — validate source and forward to TUN.
                if let Some(tunnel) = client.ip_tunnels.get_mut(&dgram.stream_id) {
                    // Validate source address.
                    match ip_packet::src_addr(dgram.payload) {
                        Ok(src) => {
                            if !tunnel.owns_address(&src) {
                                debug!(
                                    stream_id = dgram.stream_id,
                                    %src,
                                    "spoofed source address, dropping"
                                );
                                continue;
                            }
                        }
                        Err(e) => {
                            debug!(
                                stream_id = dgram.stream_id,
                                %e,
                                "invalid IP header in client packet"
                            );
                            continue;
                        }
                    }

                    tunnel.last_activity = std::time::Instant::now();

                    // Stage for the TUN device rather than writing each packet
                    // on its own, so the offload path can coalesce them into
                    // one write instead of a syscall per packet.
                    if let Some(tun) = &self.shared.tun {
                        if tun_send.is_full()
                            && let Err(e) = tun.send_batch(tun_send).await
                        {
                            debug!(%e, "TUN batch write failed");
                        }
                        tun_send.push(dgram.payload);
                    }
                    continue;
                }

                debug!(stream_id = dgram.stream_id, "datagram for unknown tunnel");
            }

            // The queue is drained, so whatever is still staged is a complete
            // burst and can go out in one syscall per tunnel.
            for stream_id in &staged_udp_tunnels {
                let Some(tunnel) = client.udp_tunnels.get_mut(stream_id) else {
                    continue;
                };
                if !tunnel.has_staged() {
                    continue;
                }
                if let Err(e) = tunnel.flush_to_target() {
                    debug!(stream_id, %e, "send to target failed");
                }
            }
        }
    }

    /// Forward queued target responses and drain the receive queue in a batch.
    fn relay_target_datagrams(&mut self, first: UdpResponse) {
        let mut response = Some(first);

        while let Some(batch) = response {
            let mut queue_full = false;
            if let Some(conn_id) = self.conn_by_index.get(&batch.connection_index)
                && let Some(client) = self.connections.get_mut(conn_id)
                && let Some(tunnel) = client.udp_tunnels.get_mut(&batch.stream_id)
            {
                tunnel.last_activity = Instant::now();
                self.dirty.mark(batch.connection_index);

                for datagram in batch.datagrams {
                    if queue_full {
                        // The rest of the batch would only be dropped by
                        // quiche anyway.
                        break;
                    }
                    match client.quic.dgram_send_buf(datagram) {
                        Ok(()) => {}
                        // The send queue is full: stop draining and let the
                        // flush at the end of the loop make room.
                        Err(quiche::Error::Done) => queue_full = true,
                        // Oversized, or datagrams disabled. Dropping this one
                        // says nothing about the next, so keep draining.
                        Err(e) => {
                            debug!(
                                stream_id = batch.stream_id,
                                %e,
                                "dgram_send failed"
                            );
                        }
                    }
                }
            }

            if queue_full {
                break;
            }
            response = self.udp_response_rx.try_recv().ok();
        }
    }

    /// Route one TUN packet. Returns false when the QUIC DATAGRAM queue is full.
    fn relay_tun_packet(&mut self, pkt: &[u8]) -> bool {
        // Extract destination IP from the packet header.
        let dst = match ip_packet::dst_addr(pkt) {
            Ok(addr) => addr,
            Err(e) => {
                debug!(%e, "invalid IP header from TUN");
                return true;
            }
        };

        // Look up the tunnel owner in the routing table.
        let owner = {
            let routing_table = self
                .shared
                .routing_table
                .read()
                .expect("routing table poisoned");
            match routing_table.lookup(&dst) {
                Some(owner) => *owner,
                None => return true,
            }
        };

        // Only one shard reads the device, so most packets belong to a
        // connection owned elsewhere and have to be handed over.
        let owner_shard = self
            .shared
            .index_shard
            .read()
            .expect("index ownership poisoned")
            .get(&owner.conn_id)
            .copied();
        if let Some(shard) = owner_shard
            && shard != self.index
        {
            if self.shared.tun_tx[shard].try_send(pkt.to_vec()).is_err() {
                debug!(shard, "shard TUN queue full, dropping packet");
            }
            return true;
        }

        let conn_id = match self.conn_by_index.get(&owner.conn_id) {
            Some(conn_id) => conn_id,
            None => {
                debug!(conn_id = owner.conn_id, "TUN packet for unknown connection");
                return true;
            }
        };

        let client = match self.connections.get_mut(conn_id) {
            Some(client) => client,
            None => return true,
        };

        // Update tunnel activity and send DATAGRAM to client.
        if let Some(tunnel) = client.ip_tunnels.get_mut(&owner.stream_id) {
            // Check for backpressure before framing, so a full queue costs no
            // allocation.
            if client.quic.is_dgram_send_queue_full() {
                return false;
            }

            tunnel.last_activity = Instant::now();
            self.dirty.mark(owner.conn_id);

            match client.quic.dgram_send_buf(tunnel.header.encode(pkt)) {
                Ok(()) => {}
                Err(quiche::Error::Done) => return false,
                // Oversized, or datagrams disabled — dropping this packet says
                // nothing about the next one, so keep draining the device.
                Err(e) => {
                    debug!(
                        stream_id = owner.stream_id,
                        %e,
                        "dgram_send for TUN packet failed"
                    );
                }
            }
        }

        true
    }

    /// Close tunnels that have been idle too long.
    fn cleanup_idle_tunnels(&mut self, timeout: Duration) {
        // Collect idle IP tunnel info so we can clean up after the loop.
        let mut idle_ip_tunnels: Vec<(quiche::ConnectionId<'static>, u64, u64)> = Vec::new();
        let dirty = &mut self.dirty;

        for (conn_id, client) in &mut self.connections {
            // Borrow the fields separately so the tunnel maps can be walked
            // while still writing to the same connection's H3 stream.
            let ClientConnection {
                quic,
                h3,
                pending_tcp_tunnels,
                tcp_tunnels,
                udp_tunnels,
                ip_tunnels,
                index,
                awaiting_auth: _,
                deferred_send: _,
                scheduled_deadline: _,
            } = client;

            // Closing a tunnel writes a response or a FIN to the connection,
            // so it has to be driven afterwards to put those on the wire.
            let mut wrote = false;

            // Pending connects are bounded by their connect timeout, but the
            // idle sweep is also a final guard if a resolver stalls.
            pending_tcp_tunnels.retain(|stream_id, tunnel| {
                if !tunnel.is_idle(timeout) {
                    return true;
                }
                info!(stream_id, "closing idle pending TCP tunnel");
                if let Some(h3) = h3.as_mut() {
                    Self::send_error_response(h3, quic, *stream_id, 504);
                    wrote = true;
                }
                false
            });

            tcp_tunnels.retain(|stream_id, tunnel| {
                if !tunnel.is_idle(timeout) {
                    return true;
                }
                info!(stream_id, "closing idle TCP tunnel");
                if let Some(h3) = h3.as_mut() {
                    h3.send_body(quic, *stream_id, b"", true).ok();
                    wrote = true;
                }
                false
            });

            // UDP tunnels: dropping the tunnel aborts its receive task.
            udp_tunnels.retain(|stream_id, tunnel| {
                if !tunnel.is_idle(timeout) {
                    return true;
                }
                info!(stream_id, "closing idle UDP tunnel");
                if let Some(h3) = h3.as_mut() {
                    h3.send_body(quic, *stream_id, b"", true).ok();
                    wrote = true;
                }
                false
            });

            // IP tunnels also need pool and route cleanup, which needs
            // `&mut self`, so only signal the close here and tear down below.
            for (stream_id, tunnel) in ip_tunnels.iter() {
                if !tunnel.is_idle(timeout) {
                    continue;
                }
                info!(stream_id, "closing idle IP tunnel");
                if let Some(h3) = h3.as_mut() {
                    h3.send_body(quic, *stream_id, b"", true).ok();
                    wrote = true;
                }
                idle_ip_tunnels.push((conn_id.clone(), *stream_id, *index));
            }

            if wrote {
                dirty.mark(*index);
            }
        }

        // Now tear down idle IP tunnels (needs &mut self fields).
        for (conn_id, stream_id, conn_idx) in idle_ip_tunnels {
            if let Some(client) = self.connections.get_mut(&conn_id) {
                Self::teardown_ip_tunnel(&self.shared, client, stream_id, conn_idx);
            }
        }
    }

    /// Send an RFC 7617 Basic proxy-authentication challenge.
    fn send_proxy_auth_required(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
    ) {
        let headers = [
            quiche::h3::Header::new(b":status", b"407"),
            quiche::h3::Header::new(
                b"proxy-authenticate",
                b"Basic realm=\"masque\", charset=\"UTF-8\"",
            ),
            quiche::h3::Header::new(b"content-length", b"0"),
        ];

        if let Err(e) = h3.send_response(quic, stream_id, &headers, true) {
            warn!(stream_id, %e, "failed to send proxy authentication challenge");
        }
    }

    /// Send an HTTP error response.
    fn send_error_response(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        status: u16,
    ) {
        // Every status we send is three digits, so format it without a
        // heap-allocated String.
        let status_buf = [
            b'0' + (status / 100 % 10) as u8,
            b'0' + (status / 10 % 10) as u8,
            b'0' + (status % 10) as u8,
        ];

        let headers = [
            quiche::h3::Header::new(b":status", &status_buf),
            quiche::h3::Header::new(b"content-length", b"0"),
        ];

        if let Err(e) = h3.send_response(quic, stream_id, &headers, true) {
            warn!(stream_id, %e, "failed to send response");
        }
    }

    /// Drive the connections with work pending: handle timers, flush outgoing
    /// packets, and queue each one's next wakeup.
    async fn drive_connections(
        &mut self,
        dirty: &[u64],
        out: &mut [u8],
        batch: &mut SendPacketBatch,
    ) {
        let socket = &mut self.socket;
        let connections = &mut self.connections;
        let conn_by_index = &self.conn_by_index;
        let timers = &mut self.timers;

        for index in dirty {
            let Some(conn_id) = conn_by_index.get(index) else {
                continue;
            };
            let Some(client) = connections.get_mut(conn_id) else {
                continue;
            };

            client.quic.on_timeout();

            // Build at most one congestion-control send quantum at a time.
            // Linux can collapse equal-sized packets into one GSO aggregate;
            // remaining messages are still emitted by one sendmmsg syscall.
            loop {
                batch.clear();
                let max_packet_size = client.quic.max_send_udp_payload_size();
                let send_quantum = client
                    .quic
                    .send_quantum()
                    .max(max_packet_size)
                    .min(MAX_DATAGRAM_SIZE);
                let mut generated_bytes = 0;
                let mut quiche_done = false;
                let mut pacing_blocked = false;

                // `quiche::Connection::send()` serializes and accounts a
                // packet before returning its desired release time. Resume a
                // packet retained by the previous loop only once that time is
                // reached.
                if let Some(deadline) = client.deferred_send.deadline() {
                    let now = Instant::now();
                    if deadline > now {
                        break;
                    }
                    if let Some((packet, send_info)) = client.deferred_send.take_if_due(now) {
                        generated_bytes += packet.len();
                        batch.push(packet, send_info, socket.udp_gso_enabled(), send_quantum);
                    }
                }

                while batch.packet_count() < MAX_BATCH_PACKETS && generated_bytes < send_quantum {
                    let (write, send_info) = match client.quic.send(out) {
                        Ok(v) => v,
                        Err(quiche::Error::Done) => {
                            quiche_done = true;
                            break;
                        }
                        Err(e) => {
                            error!(%e, "quiche send error");
                            client.quic.close(false, 0x1, b"send error").ok();
                            quiche_done = true;
                            break;
                        }
                    };

                    // Respect quiche's pacing decision. Keep one serialized
                    // future packet per connection and let the outer event
                    // loop wake exactly at its release time, instead of
                    // sleeping here and blocking unrelated connections.
                    if send_info.at > Instant::now() {
                        client.deferred_send.schedule(&out[..write], send_info);
                        pacing_blocked = true;
                        break;
                    }

                    batch.push(
                        &out[..write],
                        send_info,
                        socket.udp_gso_enabled(),
                        send_quantum,
                    );
                    generated_bytes += write;
                }

                if batch.is_empty() {
                    break;
                }

                if let Err(e) = socket.send_batch(batch).await {
                    warn!(%e, "socket send error");
                }

                if quiche_done || pacing_blocked {
                    break;
                }
            }

            // quiche's timer moves on nearly every recv and send, so the
            // connection's next wakeup is only knowable once it is fully
            // driven.
            Self::reschedule(client, timers, Instant::now());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::ServerConfig;

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
        assert_eq!(ServerConfig::default().server.shards, 1);
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
