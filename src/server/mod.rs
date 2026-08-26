// QUIC listener and connection accept loop.

mod authentication;
mod http2;
mod request;
mod retry;
mod tls;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use std::sync::{Mutex, RwLock};

use anyhow::Context as _;
use tokio::sync::{Semaphore, watch};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use self::authentication::AuthOutcome;
use self::request::{PendingAuth, PendingConnectSetups, RequestContext};
use crate::address_pool::{AddressPool, PoolError};
use crate::admission::SourceAdmissionLimiter;
use crate::auth::{BasicAuthenticator, SharedBasicAuthenticator};
use crate::capsule;
use crate::capsule::{AssignedAddress, CapsuleFrame, IpAddress, IpAddressRange};
use crate::client_identity::{
    ClientIdentity, ClientRegistry, SharedRoster, configure_client_cert_verification,
};
use crate::config::{AuthSection, ListenerTransport, ResolvedListener, ServerConfig, TlsSection};
use crate::connection::{AwaitingAuth, ClientConnection};
use crate::datagram::{self, DatagramHeader};
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

/// Configuration state prepared without opening sockets or creating a TUN
/// device.
///
/// Keeping this as the single startup-validation path means `check-config`
/// and a real server start reject the same authentication, TLS, QUIC, and
/// address-pool mistakes.
struct ValidatedServerConfig {
    clients: ClientRegistry,
    tls: Arc<tls::SharedTlsIdentity>,
    listeners: Vec<ListenerPlan>,
    total_shards: usize,
    address_pool: AddressPool,
}

/// One listener after its shard count has been resolved.
struct ListenerPlan {
    listener: ResolvedListener,
}

/// Whether any listener authenticates with a client certificate.
///
/// The roster, and the reload that replaces it, belong to the server rather
/// than to a listener, so both are governed by this rather than by one
/// listener's mode.
fn any_client_cert_listener(config: &ServerConfig) -> bool {
    config
        .listeners
        .iter()
        .any(|listener| listener.auth.client_cert_enabled())
}

fn listener_auth_label(listener: &ResolvedListener) -> &'static str {
    if listener.auth.client_cert_enabled() {
        "client_cert"
    } else if listener.auth.basic_enabled() {
        "basic"
    } else {
        "disabled"
    }
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or_else(|| ip.is_loopback(), |ip| ip.is_loopback()),
    }
}

/// Shards that verify passwords, which is what the verification budget rations.
///
/// A client-certificate listener's shards hold no `BasicAuthenticator` and
/// never reach that path, so counting them would let a large certificate
/// deployment widen what unauthenticated callers can demand of a small Basic
/// one.
fn basic_shard_count(listeners: &[ListenerPlan]) -> usize {
    listeners
        .iter()
        .filter(|plan| plan.listener.auth.basic_enabled())
        .map(|plan| plan.listener.shards)
        .sum()
}

/// Whether binding `wildcard` also claims `other`.
///
/// `::` is treated as covering IPv4 too. Whether it really does is the kernel's
/// `IPV6_V6ONLY` default — `0` on Linux unless `net.ipv6.bindv6only` says
/// otherwise, and the two wildcards were observed to collide on macOS. Nothing
/// here sets that option, so assuming the wider meaning is what keeps the
/// answer from depending on the host: the pair is refused everywhere instead of
/// failing to bind on some hosts and quietly splitting traffic on others.
fn address_covers(wildcard: IpAddr, other: IpAddr) -> bool {
    match wildcard {
        IpAddr::V4(v4) => v4.is_unspecified() && other.is_ipv4(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

/// Reduce an address to the one form two listeners can be compared in.
///
/// `::ffff:127.0.0.1` and `127.0.0.1` name the same interface, so comparing
/// them as written lets a pair through that the kernel then refuses with
/// `EADDRINUSE` — or worse, accepts under `SO_REUSEPORT`, leaving one listener
/// shadowing traffic meant for the other's authentication mode.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// Whether two socket addresses name the same interface after normalising an
/// IPv4-mapped IPv6 spelling.
///
/// A non-zero scope ID is part of a link-local IPv6 interface identity. In
/// particular, `fe80::1%2` and `fe80::1%3` may coexist on two links even though
/// `ip()` alone returns the same address for both. Scope IDs on global addresses
/// and flow information are ignored because they do not distinguish bind
/// targets. A zero link-local scope remains conservative because the kernel may
/// resolve it to the same interface as an explicit one.
fn same_canonical_address(a: SocketAddr, b: SocketAddr) -> bool {
    let (canonical_a, canonical_b) = (canonical_ip(a.ip()), canonical_ip(b.ip()));
    if canonical_a != canonical_b {
        return false;
    }

    match (canonical_a, a, b) {
        (IpAddr::V6(ip), SocketAddr::V6(a), SocketAddr::V6(b)) if ip.is_unicast_link_local() => {
            a.scope_id() == 0 || b.scope_id() == 0 || a.scope_id() == b.scope_id()
        }
        _ => true,
    }
}

/// How two listeners contend for the same packets, if they do.
///
/// Distinguished so the diagnostic can say which of them it is: told that a
/// loopback pair "overlaps because a wildcard claims its family", an operator
/// would go looking for a wildcard that is not there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressConflict {
    /// The same address, written the same way.
    Identical,
    /// The same address, written two ways — `127.0.0.1` and `::ffff:127.0.0.1`.
    SameAddress,
    /// One is a wildcard that claims the other.
    WildcardCovers,
}

/// How two listeners would contend, or `None` if they would not.
fn listen_address_conflict(a: SocketAddr, b: SocketAddr) -> Option<AddressConflict> {
    if a.port() != b.port() {
        return None;
    }
    // Port 0 has no fixed address to compare yet. Binding resolves it and checks
    // the result against both already-bound and still-planned listeners; this is
    // necessary because SO_REUSEPORT can make the kernel reuse a selected port.
    if a.port() == 0 {
        return None;
    }
    if a == b {
        return Some(AddressConflict::Identical);
    }

    // Canonical form, so an IPv4-mapped spelling cannot present itself as a
    // different address from the IPv4 one it resolves to.
    let (canonical_a, canonical_b) = (canonical_ip(a.ip()), canonical_ip(b.ip()));
    if same_canonical_address(a, b) {
        return Some(AddressConflict::SameAddress);
    }
    if address_covers(canonical_a, canonical_b) || address_covers(canonical_b, canonical_a) {
        return Some(AddressConflict::WildcardCovers);
    }
    None
}

/// Expand the configured listeners into one plan each, rejecting the
/// combinations that cannot be served.
fn plan_listeners(config: &ServerConfig) -> anyhow::Result<Vec<ListenerPlan>> {
    if config.listeners.is_empty() {
        anyhow::bail!("at least one [[listeners]] entry is required");
    }

    let mut plans: Vec<ListenerPlan> = Vec::with_capacity(config.listeners.len());
    let mut total_shards = 0usize;

    for listener in &config.listeners {
        // Two listeners over one address is not merely a bind failure to let
        // the kernel report. A listener with more than one shard opens its
        // socket with SO_REUSEPORT, so a second listener on the same address
        // would join that load-balancing group and the kernel would hand it
        // connections meant for a different authentication mode.
        //
        // Wildcards count: `0.0.0.0` claims every IPv4 address on its port, and
        // `::` claims everything on its port. An overlapping pair is refused
        // rather than left to fail at bind time with an EADDRINUSE that says
        // nothing about which two listeners disagreed.
        let conflict = plans.iter().find_map(|plan| {
            if plan.listener.transport != listener.transport {
                return None;
            }
            let existing = plan.listener.listen_addr;
            listen_address_conflict(existing, listener.listen_addr)
                .map(|conflict| (existing, conflict))
        });
        if let Some((existing, conflict)) = conflict {
            let new = listener.listen_addr;
            match conflict {
                AddressConflict::Identical => anyhow::bail!(
                    "two listeners are configured for {existing}; \
                     each listener needs its own address"
                ),
                AddressConflict::SameAddress => anyhow::bail!(
                    "listeners {existing} and {new} are the same address written two ways; \
                     each listener needs its own address"
                ),
                AddressConflict::WildcardCovers => anyhow::bail!(
                    "listeners {existing} and {new} overlap; a wildcard address claims every \
                     address of its family on that port, and :: may claim IPv4 as well"
                ),
            }
        }

        // "One per core" has no single answer once the cores are shared between
        // listeners, and quietly giving every listener a full set would
        // oversubscribe the machine by the number of listeners.
        if listener.transport == ListenerTransport::Http2 && listener.shards != 1 {
            anyhow::bail!(
                "HTTP/2 listener {} must use shards = 1; one Tokio accept loop already \
                 dispatches its TCP connections across the runtime",
                listener.listen_addr
            );
        }

        if listener.transport == ListenerTransport::Http3
            && listener.shards == 0
            && config.listeners.len() > 1
        {
            anyhow::bail!(
                "listener {} uses shards = 0 (one per core), which has no meaning \
                 alongside other listeners; give each listener an explicit count",
                listener.listen_addr
            );
        }

        let shards = if listener.transport == ListenerTransport::Http3 {
            resolve_shard_count(listener.shards)
        } else {
            1
        };
        // Sharing one address needs SO_REUSEPORT, which only Linux provides in
        // the load-balancing form this depends on.
        if listener.transport == ListenerTransport::Http3
            && shards > 1
            && !cfg!(target_os = "linux")
        {
            anyhow::bail!(
                "listener {} asks for {shards} shards, which needs SO_REUSEPORT; \
                 that is Linux only, so set shards = 1",
                listener.listen_addr
            );
        }

        if listener.transport == ListenerTransport::Http3 {
            total_shards += shards;
        }
        plans.push(ListenerPlan {
            listener: ResolvedListener {
                listen_addr: listener.listen_addr,
                transport: listener.transport,
                shards,
                auth: listener.auth.clone(),
            },
        });
    }

    // Every shard costs two cross-shard queues in each direction and a slice of
    // the shared verification budget, so the cap is on the total rather than on
    // any one listener's share of it.
    if total_shards > MAX_SHARDS {
        anyhow::bail!(
            "{} listeners ask for {total_shards} shards in total, more than the \
             {MAX_SHARDS} this server runs",
            plans.len()
        );
    }

    Ok(plans)
}

/// Build only the roster selected by the active authentication mode.
///
/// Keeping this decision separate from binding makes the "ignored outside
/// client_cert" contract testable without opening sockets or loading TLS keys.
fn active_client_registry(
    config: &ServerConfig,
    any_client_cert: bool,
) -> anyhow::Result<ClientRegistry> {
    if !any_client_cert {
        return Ok(ClientRegistry::default());
    }

    let clients = ClientRegistry::from_config(&config.clients)?;
    if clients.is_empty() {
        anyhow::bail!(
            "listener auth.mode = \"client_cert\" needs at least one [[clients]] entry; \
             run `masque-server enroll-client` to create one"
        );
    }
    Ok(clients)
}

/// Validate everything in a server configuration that does not require a
/// live listener or a TUN device.
///
/// This is intentionally side-effect-free so installers can qualify an
/// existing configuration with a candidate binary before replacing the
/// running version. Runtime-only failures such as an occupied UDP port or a
/// missing kernel TUN device are still reported when the server starts.
/// Returns the listeners the server would actually run, with their shard counts
/// resolved — `shards = 0` expanded to one per core and the cap applied — so a
/// caller reports what will run rather than what was asked for.
pub fn validate_config(config: &ServerConfig) -> anyhow::Result<Vec<ResolvedListener>> {
    let validated = validate_server_config(config)?;
    Ok(validated
        .listeners
        .iter()
        .map(|plan| plan.listener.clone())
        .collect())
}

fn validate_server_config(config: &ServerConfig) -> anyhow::Result<ValidatedServerConfig> {
    let listeners = plan_listeners(config)?;
    let any_client_cert = any_client_cert_listener(config);

    if config.server.max_connections == 0 {
        anyhow::bail!("server.max_connections must be at least 1");
    }
    if config.server.max_connections_per_ip == 0 {
        anyhow::bail!("server.max_connections_per_ip must be at least 1");
    }
    if !(1..=MAX_PENDING_AUTH_GLOBAL).contains(&config.server.max_pending_auth_per_ip) {
        anyhow::bail!(
            "server.max_pending_auth_per_ip ({}) must be between 1 and {}",
            config.server.max_pending_auth_per_ip,
            MAX_PENDING_AUTH_GLOBAL
        );
    }
    if config.server.max_tunnels_per_connection == 0 {
        anyhow::bail!("server.max_tunnels_per_connection must be at least 1");
    }
    if config.quic.retry_connection_threshold == 0 {
        anyhow::bail!("quic.retry_connection_threshold must be at least 1");
    }
    if !(1..=300).contains(&config.quic.retry_token_ttl_secs) {
        anyhow::bail!(
            "quic.retry_token_ttl_secs ({}) must be between 1 and 300",
            config.quic.retry_token_ttl_secs
        );
    }

    if let Some(addr) = config.observability.listen_addr
        && !is_loopback(addr.ip())
    {
        anyhow::bail!(
            "observability.listen_addr ({addr}) must use a loopback address; \
             run Prometheus locally or forward the endpoint securely"
        );
    }

    // Surface a bad credential or active roster configuration first. A roster
    // outside client-cert mode is deliberately not parsed or allowed to
    // reserve pool addresses: the configuration contract says it is ignored.
    let clients = active_client_registry(config, any_client_cert)?;
    if any_client_cert {
        info!(
            clients = clients.len(),
            "client certificate authentication enabled"
        );
    } else if !config.clients.is_empty() {
        warn!(
            "[[clients]] entries are ignored unless a listener has auth.mode = \
             \"client_cert\" and auth.enabled = true"
        );
    }

    // Credentials are per listener, so a mistake in the second one has to name
    // the listener it came from or it cannot be found in a multi-listener file.
    for plan in &listeners {
        let addr = plan.listener.listen_addr;
        if plan.listener.auth.basic_enabled() {
            BasicAuthenticator::from_section(&plan.listener.auth)
                .with_context(|| format!("listener {addr}"))?;
        } else if !plan.listener.auth.client_cert_enabled() {
            warn!(%addr, "proxy authentication is disabled on this listener");
        }
    }

    // Flow-control autotuning only ever grows a window toward its ceiling, so
    // a ceiling below the advertised initial credit is a config mistake.
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

    if !(quiche::MIN_CLIENT_INITIAL_LEN..=MAX_DATAGRAM_SIZE)
        .contains(&config.quic.max_datagram_size)
    {
        anyhow::bail!(
            "quic.max_datagram_size ({}) must be between {} and {} bytes",
            config.quic.max_datagram_size,
            quiche::MIN_CLIENT_INITIAL_LEN,
            MAX_DATAGRAM_SIZE
        );
    }

    const MAX_HTTP2_WINDOW: u32 = (1_u32 << 31) - 1;
    if !(1..=MAX_HTTP2_WINDOW).contains(&config.http2.initial_stream_window) {
        anyhow::bail!(
            "http2.initial_stream_window ({}) must be between 1 and {MAX_HTTP2_WINDOW}",
            config.http2.initial_stream_window
        );
    }
    if !(1..=MAX_HTTP2_WINDOW).contains(&config.http2.initial_connection_window) {
        anyhow::bail!(
            "http2.initial_connection_window ({}) must be between 1 and {MAX_HTTP2_WINDOW}",
            config.http2.initial_connection_window
        );
    }
    if config.http2.max_concurrent_streams == 0 {
        anyhow::bail!("http2.max_concurrent_streams must be at least 1");
    }
    if config.http2.max_header_list_size == 0 {
        anyhow::bail!("http2.max_header_list_size must be at least 1");
    }
    if config.http2.max_send_buffer_size == 0
        || config.http2.max_send_buffer_size > u32::MAX as usize
    {
        anyhow::bail!(
            "http2.max_send_buffer_size ({}) must be between 1 and {}",
            config.http2.max_send_buffer_size,
            u32::MAX
        );
    }
    const MAX_HTTP2_DATA_FRAME_BUDGET: usize = 16 * 1024 * 1024;
    if !(1..=MAX_HTTP2_DATA_FRAME_BUDGET).contains(&config.http2.data_frame_budget) {
        anyhow::bail!(
            "http2.data_frame_budget ({}) must be between 1 and \
             {MAX_HTTP2_DATA_FRAME_BUDGET}",
            config.http2.data_frame_budget
        );
    }
    if !(1..=65_527).contains(&config.http2.max_datagram_size) {
        anyhow::bail!(
            "http2.max_datagram_size ({}) must be between 1 and 65527 bytes",
            config.http2.max_datagram_size
        );
    }

    if config.ip_proxy.enabled && !(1..=u16::MAX as usize).contains(&config.ip_proxy.tun_mtu) {
        anyhow::bail!(
            "ip_proxy.tun_mtu ({}) must be between 1 and {}",
            config.ip_proxy.tun_mtu,
            u16::MAX
        );
    }

    let mut address_pool = AddressPool::new(&config.ip_proxy.ipv4_pool, &config.ip_proxy.ipv6_pool)
        .map_err(|e| anyhow::anyhow!("address pool: {e}"))?;

    // Withhold every pinned address from dynamic allocation up front, so a
    // client that connects while a pinned peer is offline cannot take it.
    if config.ip_proxy.enabled {
        for (addr, owner) in clients.static_reservations() {
            address_pool.reserve_static(addr, owner).map_err(|e| {
                anyhow::anyhow!(
                    "client address {addr} cannot be reserved ({e}); pinned addresses \
                     must lie inside ip_proxy.ipv4_pool / ipv6_pool and must not be the \
                     pool's gateway address"
                )
            })?;
        }
    }

    // Build and discard the protocol configurations. This loads and matches
    // the certificate/key pair and exercises the same quiche setters a shard
    // will use, but has no network or device side effects.
    //
    // Once per listener rather than once per server: the authentication mode
    // decides which of two TLS contexts is built, so validating one listener's
    // would say nothing about another's.
    let tls = Arc::new(tls::SharedTlsIdentity::new(tls::TlsIdentity::load(
        &config.tls,
    )?));
    for plan in &listeners {
        let client_certs = plan
            .listener
            .auth
            .client_cert_enabled()
            .then(|| Arc::new(SharedRoster::new(clients.clone())));
        match plan.listener.transport {
            ListenerTransport::Http3 => {
                build_quic_config(config, client_certs, Arc::clone(&tls))
                    .with_context(|| format!("listener {}", plan.listener.listen_addr))?;
            }
            ListenerTransport::Http2 => {
                http2::build_acceptor(client_certs, Arc::clone(&tls))
                    .with_context(|| format!("listener {}", plan.listener.listen_addr))?;
            }
        }
    }
    if listeners
        .iter()
        .any(|plan| plan.listener.transport == ListenerTransport::Http3)
    {
        build_h3_config()?;
    }

    let total_shards = listeners
        .iter()
        .filter(|plan| plan.listener.transport == ListenerTransport::Http3)
        .map(|plan| plan.listener.shards)
        .sum();
    Ok(ValidatedServerConfig {
        clients,
        tls,
        listeners,
        total_shards,
        address_pool,
    })
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
            })
            .collect(),
    })
}

/// Open the UDP socket for one shard with the listener's transport settings.
async fn open_quic_socket(
    config: &ServerConfig,
    listen_addr: SocketAddr,
    reuseport: bool,
) -> anyhow::Result<QuicUdpSocket> {
    QuicUdpSocket::bind_shared(
        listen_addr,
        config.quic.max_datagram_size,
        config.quic.enable_udp_gso,
        config.quic.enable_udp_gro,
        reuseport,
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
    reuseport: bool,
    unavailable: &[SocketAddr],
) -> anyhow::Result<(QuicUdpSocket, SocketAddr)> {
    for attempt in 1..=MAX_EPHEMERAL_BIND_ATTEMPTS {
        let socket = open_quic_socket(config, requested, reuseport).await?;
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
        let mut tun_tx = Vec::with_capacity(total_shards);
        let mut tun_rx = Vec::with_capacity(total_shards);
        for _ in 0..total_shards {
            let (tx, rx) = mpsc::channel(SHARD_FORWARD_QUEUE_CAPACITY);
            forward_tx.push(tx);
            forward_rx.push(rx);
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

            // SO_REUSEPORT is what lets one listener's shards share an address.
            // A single-shard listener must not set it, or a later listener that
            // was misconfigured onto the same address could join its group.
            let reuseport = plan.listener.shards > 1;

            // Bind `:0` only once, then use the assigned address for every
            // remaining shard. Asking the kernel for `:0` independently would
            // split one logical listener across unrelated ports.
            let (first_socket, bound_addr) = bind_first_listener_socket(
                &config,
                plan.listener.listen_addr,
                reuseport,
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
                Arc::clone(&shared),
                Arc::clone(&config),
                plan.listener.clone(),
                listener_auth.as_ref().map(Arc::clone),
                first_socket,
                Arc::clone(&listener_metrics[0]),
                forward_rx,
                tun_rx,
            )?);

            for shard_metrics in listener_metrics.iter().skip(1) {
                let (forward_rx, tun_rx) = inboxes
                    .next()
                    .expect("one inbox pair was created per planned shard");
                shards.push(
                    Shard::bind(
                        shards.len(),
                        Arc::clone(&shared),
                        Arc::clone(&config),
                        plan.listener.clone(),
                        listener_auth.as_ref().map(Arc::clone),
                        reuseport,
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
        {
            anyhow::bail!(
                "refusing to reload listener {}: address, transport, order, or authentication \
                 mode changed; restart the service to apply trust-boundary changes",
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
    client_certs: Option<Arc<SharedRoster>>,
    tls_identity: Arc<tls::SharedTlsIdentity>,
) -> anyhow::Result<quiche::Config> {
    // quiche's file-loading API fixes one identity into the context. Building
    // the context directly lets the ClientHello callback select the current
    // shared identity for every new connection while existing QUIC state keeps
    // the identity it already negotiated.
    let mut builder = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls())
        .map_err(|e| anyhow::anyhow!("failed to create TLS context: {e}"))?;
    tls::configure_dynamic_identity(&mut builder, tls_identity);
    if let Some(roster) = client_certs {
        // quiche's normal peer verification cannot express the self-signed,
        // public-key roster used by usque-compatible clients, so install the
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
    forward_tx: Vec<mpsc::Sender<ForwardedPacket>>,
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
    fn record_shard_queue_drop(&self, shard: usize) {
        if let Some(metrics) = self
            .shard_metrics
            .read()
            .expect("shard metrics list poisoned")
            .get(shard)
        {
            metrics.record_shard_queue_drop();
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
    shared: Arc<Shared>,
    /// Counters owned by this shard and aggregated per listener while scraping.
    metrics: Arc<ShardMetrics>,
    socket: QuicUdpSocket,
    quic_config: quiche::Config,
    h3_config: quiche::h3::Config,
    connections: FxHashMap<quiche::ConnectionId<'static>, ClientConnection>,
    auth: Option<Arc<SharedBasicAuthenticator>>,
    /// Set when clients authenticate with a certificate instead of credentials.
    ///
    /// The TLS context already refuses unregistered keys, so this exists to
    /// attach the resolved identity to the connection and as a second check
    /// that no connection slips through without one.
    client_certs: Option<Arc<SharedRoster>>,
    tcp_policy: TargetPolicy,
    udp_policy: TargetPolicy,
    config: Arc<ServerConfig>,
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
        config: Arc<ServerConfig>,
        listener: ResolvedListener,
        auth: Option<Arc<SharedBasicAuthenticator>>,
        reuseport: bool,
        metrics: Arc<ShardMetrics>,
        forward_rx: mpsc::Receiver<ForwardedPacket>,
        tun_rx: mpsc::Receiver<Vec<u8>>,
    ) -> anyhow::Result<Self> {
        let socket = open_quic_socket(&config, listener.listen_addr, reuseport).await?;
        Self::from_socket(
            index, shared, config, listener, auth, socket, metrics, forward_rx, tun_rx,
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
        shared: Arc<Shared>,
        config: Arc<ServerConfig>,
        listener: ResolvedListener,
        auth: Option<Arc<SharedBasicAuthenticator>>,
        socket: QuicUdpSocket,
        metrics: Arc<ShardMetrics>,
        forward_rx: mpsc::Receiver<ForwardedPacket>,
        tun_rx: mpsc::Receiver<Vec<u8>>,
    ) -> anyhow::Result<Self> {
        let bound_addr = socket.local_addr()?;
        metrics.set_udp_offload_state(socket.udp_gso_enabled(), socket.udp_gro_enabled());
        info!(
            shard = index,
            addr = %bound_addr,
            udp_gso = socket.udp_gso_enabled(),
            udp_gro = socket.udp_gro_enabled(),
            "listening"
        );

        let client_certs = if listener.auth.client_cert_enabled() {
            Some(Arc::clone(&shared.clients))
        } else {
            None
        };

        let quic_config = build_quic_config(
            &config,
            client_certs.as_ref().map(Arc::clone),
            Arc::clone(&shared.tls),
        )?;
        let h3_config = build_h3_config()?;

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
            metrics,
            socket,
            quic_config,
            h3_config,
            connections: FxHashMap::default(),
            auth,
            client_certs,
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
    pub async fn run(&mut self, mut shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
        let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut dgram_buf = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut tun_recv = TunRecvBatch::new(self.config.ip_proxy.tun_mtu);
        let mut tun_send = TunSendBatch::new();
        let mut recv_batch = RecvPacketBatch::new(MAX_QUIC_RECV_BATCH);
        let mut send_batch = SendPacketBatch::new();
        let mut stateless_out = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut stateless_batch = SendPacketBatch::new();
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
                    _ = shutdown.wait_for(|requested| *requested), if !shutting_down => {
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
                    recv_batch.for_each_packet_mut(received, |packet, from| {
                        packet_count += 1;
                        byte_count += packet.len();
                        if !shutting_down {
                            self.handle_packet(
                                packet,
                                from,
                                local_addr,
                                &mut stateless_out,
                                &mut stateless_batch,
                                &mut stateless_retries,
                            );
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
                    self.metrics.record_receive_batch(packet_count, byte_count);
                }
                Event::PacketBatch(Err(e)) => {
                    error!(%e, "socket recv error");
                }
                Event::TargetDatagram(Some(response)) => {
                    self.relay_target_datagrams(response);
                }
                Event::TargetDatagram(None) => {}
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
                Event::Forwarded(Some(mut packet)) => {
                    self.handle_packet(
                        &mut packet.data,
                        packet.from,
                        local_addr,
                        &mut stateless_out,
                        &mut stateless_batch,
                        &mut stateless_retries,
                    );
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

    fn derive_connection_id(
        &self,
        destination: &quiche::ConnectionId<'_>,
    ) -> quiche::ConnectionId<'static> {
        let signed = ring::hmac::sign(&self.shared.conn_id_key, destination);
        quiche::ConnectionId::from_vec(signed.as_ref()[..CONN_ID_LEN].to_vec())
    }

    fn forward_packet(&self, shard: usize, packet: &[u8], from: SocketAddr) {
        let forwarded = ForwardedPacket {
            data: packet.to_vec(),
            from,
        };
        // Dropping under pressure is what the network would have done; QUIC
        // retransmits without making this unbounded cross-shard state.
        if self.shared.forward_tx[shard].try_send(forwarded).is_err() {
            self.shared.record_shard_queue_drop(shard);
            debug!(shard, "shard forward queue full, dropping packet");
        }
    }

    fn queue_stateless_packet(
        &self,
        packet: &[u8],
        from: SocketAddr,
        to: SocketAddr,
        batch: &mut SendPacketBatch,
    ) {
        batch.push(
            packet,
            quiche::SendInfo {
                from,
                to,
                at: Instant::now(),
            },
            self.socket.udp_gso_enabled(),
            MAX_DATAGRAM_SIZE,
        );
    }

    /// Process an incoming UDP packet (QUIC).
    fn handle_packet(
        &mut self,
        buf: &mut [u8],
        from: SocketAddr,
        local: SocketAddr,
        stateless_out: &mut [u8],
        stateless_batch: &mut SendPacketBatch,
        stateless_retries: &mut usize,
    ) {
        let hdr = match quiche::Header::from_slice(buf, CONN_ID_LEN) {
            Ok(v) => v,
            Err(e) => {
                debug!(%e, "failed to parse QUIC header");
                return;
            }
        };

        // Established packets carry the server-issued CID and take this fast
        // path without hashing. If migration made the packet land on another
        // SO_REUSEPORT shard, the shared ownership map names the right inbox.
        let key = if let Some((conn_id, _)) = self.connections.get_key_value(&hdr.dcid) {
            conn_id.clone()
        } else {
            let direct_owner = self
                .shared
                .cid_shard
                .read()
                .expect("cid ownership poisoned")
                .get(&hdr.dcid)
                .copied();
            if let Some(owner) = direct_owner {
                if owner != self.index {
                    self.forward_packet(owner, buf, from);
                } else {
                    debug!("connection ownership published without local state");
                }
                return;
            }

            if hdr.ty != quiche::Type::Initial {
                debug!("non-initial packet for unknown connection");
                return;
            }

            // A client Initial datagram is required to be at least 1200 bytes.
            // Reject a short spoofed packet before emitting Version
            // Negotiation or Retry, preserving QUIC's amplification bound.
            if buf.len() < quiche::MIN_CLIENT_INITIAL_LEN {
                debug!(bytes = buf.len(), "dropping undersized QUIC Initial");
                return;
            }

            if !quiche::version_is_supported(hdr.version) {
                match quiche::negotiate_version(&hdr.scid, &hdr.dcid, stateless_out) {
                    Ok(written) => self.queue_stateless_packet(
                        &stateless_out[..written],
                        local,
                        from,
                        stateless_batch,
                    ),
                    Err(error) => debug!(%error, "failed to build QUIC version negotiation"),
                }
                return;
            }

            // A retransmitted first Initial still carries the client's
            // original destination CID. Find the state created for its first
            // copy before deciding this is a new connection.
            let derived = self.derive_connection_id(&hdr.dcid);
            if self.connections.contains_key(&derived) {
                derived
            } else {
                let derived_owner = self
                    .shared
                    .cid_shard
                    .read()
                    .expect("cid ownership poisoned")
                    .get(&derived)
                    .copied();
                if let Some(owner) = derived_owner {
                    if owner != self.index {
                        self.forward_packet(owner, buf, from);
                    } else {
                        debug!("derived connection ownership published without local state");
                    }
                    return;
                }

                let token = hdr.token.as_deref().unwrap_or_default();
                let retry_required = retry::retry_required(
                    self.config.quic.retry_mode,
                    self.connections.len(),
                    self.config.quic.retry_connection_threshold,
                );

                if token.is_empty() && retry_required {
                    let retry_token = self.shared.retry_tokens.mint(from, local, &hdr.dcid);
                    match quiche::retry(
                        &hdr.scid,
                        &hdr.dcid,
                        &derived,
                        &retry_token,
                        hdr.version,
                        stateless_out,
                    ) {
                        Ok(written) => {
                            self.queue_stateless_packet(
                                &stateless_out[..written],
                                local,
                                from,
                                stateless_batch,
                            );
                            *stateless_retries += 1;
                        }
                        Err(error) => debug!(%error, "failed to build QUIC Retry"),
                    }
                    return;
                }

                let (scid, odcid) = if token.is_empty()
                    || self.config.quic.retry_mode == crate::config::QuicRetryMode::Off
                {
                    (derived, None)
                } else {
                    let Some(odcid) = self.shared.retry_tokens.validate(from, local, token) else {
                        self.metrics.record_quic_retry_invalid();
                        debug!(%from, "invalid or expired QUIC Retry token");
                        return;
                    };
                    let expected = self.derive_connection_id(&odcid);
                    if expected != hdr.dcid {
                        self.metrics.record_quic_retry_invalid();
                        debug!(%from, "QUIC Retry destination connection ID mismatch");
                        return;
                    }
                    (
                        quiche::ConnectionId::from_vec(hdr.dcid.to_vec()),
                        Some(odcid),
                    )
                };

                // Stateful admission happens only after address validation, so
                // a spoofed flood cannot consume either connection table.
                if self.connections.len() >= self.config.server.max_connections {
                    self.metrics.connection_rejected_limit();
                    warn!("max connections reached, rejecting new connection");
                    return;
                }
                let Some(source_admission) = self.shared.source_admissions.try_acquire(from.ip())
                else {
                    self.metrics.connection_rejected_source_limit();
                    warn!(%from, "source connection limit reached");
                    return;
                };

                let quic =
                    match quiche::accept(&scid, odcid.as_ref(), local, from, &mut self.quic_config)
                    {
                        Ok(connection) => connection,
                        Err(error) => {
                            error!(%error, "failed to accept connection");
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

                let client = ClientConnection::new(
                    quic,
                    conn_idx,
                    Arc::clone(&self.metrics),
                    source_admission,
                );
                self.connections.insert(scid.clone(), client);
                scid
            }
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

        // Resolve the client's certificate to a roster entry once, at the
        // handshake boundary. The TLS callback has already refused unknown
        // keys, so this is about attaching the identity that later decides
        // which addresses the tunnel gets — and about refusing to serve a
        // connection whose identity we somehow cannot name.
        if let Some(registry) = &self.client_certs
            && client.identity.is_none()
            && client.quic.is_established()
        {
            match client
                .quic
                .peer_cert()
                .map(|der| registry.load().identify(der))
            {
                Some(Ok(identity)) => {
                    self.metrics.record_auth_success();
                    info!(client = %identity.name, %from, "client authenticated by certificate");
                    client.identity = Some(identity);
                }
                other => {
                    self.metrics.record_auth_failure();
                    match other {
                        Some(Err(e)) => warn!(%e, "closing connection with unusable certificate"),
                        // Unreachable while the context sets
                        // FAIL_IF_NO_PEER_CERT, but the cost of being wrong is
                        // an unauthenticated tunnel.
                        None => warn!("closing connection that presented no certificate"),
                        Some(Ok(_)) => unreachable!(),
                    }
                    let _ = client.quic.close(false, 0x0100, b"unauthorized");
                    return;
                }
            }
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
        let enable_target_udp_gso = self.config.udp_proxy.enable_udp_gso;
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
                            #[cfg(target_os = "linux")]
                            let target_udp_gso = if enable_target_udp_gso {
                                use std::os::fd::AsRawFd as _;
                                target_udp::detect_udp_gso(
                                    std_sock.as_raw_fd(),
                                    target_datagram_size,
                                )
                            } else {
                                false
                            };
                            #[cfg(not(target_os = "linux"))]
                            let target_udp_gso = {
                                let _ = enable_target_udp_gso;
                                false
                            };
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
                                        stream_id,
                                        addr,
                                        std_sock,
                                        socket,
                                        recv_task,
                                        target_udp_gso,
                                    );
                                    info!(
                                        stream_id,
                                        target = %addr,
                                        udp_gso = target_udp_gso,
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

        // A client pinned to fixed addresses gets exactly those, and nothing
        // from the pool: its tunnel interface is configured out of band with
        // the same values, so an extra dynamic address would be advertised to a
        // client that has no interface to receive it on.
        let pinned = client
            .identity
            .as_ref()
            .filter(|identity| identity.has_static_addresses());

        let addresses = match pinned {
            Some(identity) => match claim_static_addresses(shared, identity) {
                Ok(addresses) => addresses,
                Err(e) => {
                    warn!(
                        stream_id,
                        client = %identity.name,
                        %e,
                        "cannot attach IP tunnel to this client's fixed addresses"
                    );
                    if let Some(h3) = &mut client.h3 {
                        Self::send_error_response(h3, &mut client.quic, stream_id, 503);
                    }
                    return;
                }
            },
            None => allocate_pool_addresses(shared),
        };

        if addresses.is_empty() {
            warn!(stream_id, "address pool exhausted for IP tunnel");
            if let Some(h3) = &mut client.h3 {
                Self::send_error_response(h3, &mut client.quic, stream_id, 503);
            }
            return;
        }

        for ip in &addresses {
            tunnel.assigned_addrs.push(*ip);
        }

        // Do not acknowledge the CONNECT until every address has been leased.
        // HTTP/3 permits only one response header block, so a 200 sent before
        // allocation cannot later be corrected to a 503.
        let headers = [
            quiche::h3::Header::new(b":status", b"200"),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        ];
        let Some(h3) = &mut client.h3 else {
            shared
                .address_pool
                .lock()
                .expect("address pool poisoned")
                .release_all(&addresses);
            warn!(
                stream_id,
                "HTTP/3 state disappeared during CONNECT-IP setup"
            );
            return;
        };
        if let Err(e) = h3.send_response(&mut client.quic, stream_id, &headers, false) {
            shared
                .address_pool
                .lock()
                .expect("address pool poisoned")
                .release_all(&addresses);
            warn!(stream_id, %e, "failed to send CONNECT-IP 200");
            return;
        }

        // A reconnect using the same registered key may briefly overlap its
        // stale predecessor. Inserting replaces the return route atomically;
        // remove_owned() prevents the predecessor's later cleanup from deleting
        // this newer route.
        for ip in &addresses {
            shared
                .routing_table
                .write()
                .expect("routing table poisoned")
                .insert(
                    *ip,
                    TunnelOwner {
                        conn_id: conn_idx,
                        stream_id,
                    },
                );
            info!(stream_id, addr = %ip, pinned = pinned.is_some(), "assigned address to IP tunnel");
        }

        // Send ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT back to back: one buffer,
        // one send_body call. The route advertisement is a default route, so
        // the client knows it can send all traffic through this tunnel.
        let capsules = encode_ip_setup_capsules(&addresses);

        if let Err(e) = h3.send_body(&mut client.quic, stream_id, &capsules, false) {
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
    fn handle_tcp_event_batch(&mut self, first: TcpRelayEvent) {
        let mut next = Some(first);
        let mut events = 0usize;
        let mut bytes = 0usize;

        while let Some(event) = next {
            bytes = bytes.saturating_add(event.payload_len());
            events += 1;
            self.handle_tcp_event(event);

            if events >= MAX_TCP_RELAY_EVENTS_PER_ROUND || bytes >= MAX_TCP_RELAY_BYTES_PER_ROUND {
                break;
            }
            next = self.tcp_event_rx.try_recv().ok();
        }

        self.metrics.record_tcp_relay_batch(events, bytes);
    }

    /// Apply one event generated by an asynchronous target TCP task.
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

                let datagram_count = batch.datagrams.len();
                for (index, datagram) in batch.datagrams.into_iter().enumerate() {
                    match client.quic.dgram_send_buf(datagram) {
                        Ok(()) => {}
                        // The send queue is full: stop draining and let the
                        // flush at the end of the loop make room.
                        Err(quiche::Error::Done) => {
                            queue_full = true;
                            self.metrics
                                .record_datagram_queue_drop(datagram_count - index);
                            break;
                        }
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
        if owner_shard.is_none() && self.shared.relay_http2_tun_packet(owner, pkt) {
            return true;
        }
        if let Some(shard) = owner_shard
            && shard != self.index
        {
            if self.shared.tun_tx[shard].try_send(pkt.to_vec()).is_err() {
                self.shared.record_tun_queue_drop(shard);
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
                self.metrics.record_datagram_queue_drop(1);
                return false;
            }

            tunnel.last_activity = Instant::now();
            self.dirty.mark(owner.conn_id);

            match client.quic.dgram_send_buf(tunnel.header.encode(pkt)) {
                Ok(()) => {}
                Err(quiche::Error::Done) => {
                    self.metrics.record_datagram_queue_drop(1);
                    return false;
                }
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
    /// Disconnect connections whose roster entry was removed or changed.
    ///
    /// A revoked client keeping its tunnel until it happens to reconnect would
    /// make revocation meaningless, so the connection is closed rather than
    /// merely barred from opening new streams. An entry that was edited counts
    /// as revoked too: its pinned addresses were decided at setup time, so the
    /// client has to come back to pick up the new ones.
    fn enforce_roster(&mut self) {
        let Some(roster) = self.client_certs.as_ref() else {
            return;
        };
        let current = roster.load();

        let mut revoked: Vec<quiche::ConnectionId<'static>> = Vec::new();
        for (conn_id, client) in &self.connections {
            let Some(identity) = client.identity.as_deref() else {
                continue;
            };
            if !current.still_authorizes(identity) {
                info!(client = %identity.name, "disconnecting client removed from the roster");
                revoked.push(conn_id.clone());
            }
        }

        for conn_id in revoked {
            if let Some(client) = self.connections.get_mut(&conn_id) {
                // A local close; the teardown that frees addresses and routes
                // runs from the normal closed-connection path.
                let _ = client.quic.close(true, 0x0100, b"revoked");
                self.dirty.mark(client.index);
            }
        }
    }

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
                ..
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

                let udp_gso_before_send = socket.udp_gso_enabled();
                match socket.send_batch(batch).await {
                    Ok(()) => self
                        .metrics
                        .record_send_batch(batch.packet_count(), batch.byte_count()),
                    Err(e) => warn!(%e, "socket send error"),
                }
                if udp_gso_before_send && !socket.udp_gso_enabled() {
                    self.metrics.disable_udp_gso();
                }

                if quiche_done || pacing_blocked {
                    break;
                }
            }

            // quiche's timer moves on nearly every recv and send, so the
            // connection's next wakeup is only knowable once it is fully
            // driven.
            Self::reschedule(client, timers, Instant::now());
            client.sync_metrics();
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
            auth: AuthSection {
                enabled: true,
                mode,
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
