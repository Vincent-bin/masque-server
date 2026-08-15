// QUIC listener and connection accept loop.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quiche::h3::NameValue;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::address_pool::AddressPool;
use crate::capsule;
use crate::capsule::{AssignedAddress, CapsuleFrame, IpAddress, IpAddressRange};
use crate::config::ServerConfig;
use crate::connection::ClientConnection;
use crate::datagram::{self, DatagramHeader};
use crate::fxhash::FxHashMap;
use crate::ip_packet;
use crate::policy::TargetPolicy;
use crate::quic_udp::{
    MAX_BATCH_PACKETS, MAX_DATAGRAM_SIZE, QuicUdpSocket, RecvPacketBatch,
    SendPacketBatch,
};
use crate::routing::{RoutingTable, TunnelOwner};
use crate::tun::TunManager;
use crate::tunnel::ip::IpTunnel;
use crate::tunnel::udp::UdpTunnel;
use crate::uri;

/// Unique connection ID length.
const CONN_ID_LEN: usize = 16;

/// Bounded queue used by per-tunnel receive tasks to wake the main loop.
const UDP_RESPONSE_QUEUE_CAPACITY: usize = 4096;

/// Drain a bounded batch of already-buffered QUIC packets per readiness wakeup.
const MAX_QUIC_RECV_BATCH: usize = MAX_BATCH_PACKETS;

/// Drain a bounded batch of already-buffered TUN packets per readiness wakeup,
/// so a busy TUN device cannot starve the QUIC socket.
const MAX_TUN_RECV_BATCH: usize = 64;

/// How often idle tunnels are swept. Tunnels close after `idle_timeout_secs`,
/// so this is a background chore rather than something that belongs on the
/// packet path.
const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

struct UdpResponse {
    connection_index: u64,
    stream_id: u64,
    datagram: Vec<u8>,
}

/// Top-level MASQUE server.
pub struct Server {
    socket: QuicUdpSocket,
    quic_config: quiche::Config,
    h3_config: quiche::h3::Config,
    connections: FxHashMap<quiche::ConnectionId<'static>, ClientConnection>,
    udp_policy: TargetPolicy,
    address_pool: AddressPool,
    routing_table: RoutingTable,
    config: ServerConfig,
    /// Monotonically increasing connection index used as the conn_id in
    /// TunnelOwner (since quiche ConnectionId is not easily hashable).
    ///
    /// Indices are never reused, so a route left behind by a torn-down tunnel
    /// can never resolve to a later connection.
    next_conn_index: u64,
    /// Reverse index for routing TUN packets without scanning every connection.
    conn_by_index: FxHashMap<u64, quiche::ConnectionId<'static>>,
    /// Key for deriving a server connection ID from a client's DCID.
    ///
    /// Generated per-process, so a client cannot precompute which server
    /// connection ID — or which hash bucket — its DCID will map to.
    conn_id_key: ring::hmac::Key,
    /// Shared TUN device for CONNECT-IP tunnels (None if IP proxy disabled).
    tun: Option<TunManager>,
    udp_response_tx: mpsc::Sender<UdpResponse>,
    udp_response_rx: mpsc::Receiver<UdpResponse>,
}

impl Server {
    /// Create a new server bound to the configured address.
    pub async fn bind(config: ServerConfig) -> anyhow::Result<Self> {
        let socket = QuicUdpSocket::bind(
            config.server.listen_addr,
            config.quic.max_datagram_size,
            config.quic.enable_udp_gso,
            config.quic.enable_udp_gro,
        )
        .await?;
        info!(
            addr = %config.server.listen_addr,
            udp_gso = socket.udp_gso_enabled(),
            udp_gro = socket.udp_gro_enabled(),
            "listening"
        );

        let mut quic_config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

        // TLS
        quic_config.load_cert_chain_from_pem_file(
            config.tls.cert_path.to_str().unwrap_or(""),
        )?;
        quic_config.load_priv_key_from_pem_file(
            config.tls.key_path.to_str().unwrap_or(""),
        )?;

        quic_config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;

        // Transport parameters
        quic_config.set_max_idle_timeout(
            (config.server.idle_timeout_secs * 1000) as u64,
        );
        quic_config
            .set_max_recv_udp_payload_size(config.quic.max_datagram_size);
        quic_config
            .set_max_send_udp_payload_size(config.quic.max_datagram_size);
        quic_config.set_initial_max_data(10_000_000);
        quic_config.set_initial_max_stream_data_bidi_local(1_000_000);
        quic_config.set_initial_max_stream_data_bidi_remote(1_000_000);
        quic_config.set_initial_max_stream_data_uni(1_000_000);
        quic_config.set_initial_max_streams_bidi(
            config.quic.initial_max_streams_bidi,
        );
        quic_config.set_initial_max_streams_uni(100);
        quic_config.enable_pacing(true);

        // DATAGRAM extension
        if config.quic.enable_dgram {
            quic_config.enable_dgram(true, 1000, 1000);
        }

        let mut h3_config = quiche::h3::Config::new()?;
        h3_config.set_max_field_section_size(8192);

        let udp_policy = TargetPolicy::new(
            &config.udp_proxy.allow_targets,
            &config.udp_proxy.deny_targets,
        );

        let address_pool = AddressPool::new(
            &config.ip_proxy.ipv4_pool,
            &config.ip_proxy.ipv6_pool,
        )
        .map_err(|e| anyhow::anyhow!("address pool: {e}"))?;

        // Create TUN device if IP proxy is enabled.
        let tun = if config.ip_proxy.enabled {
            // Parse pool CIDRs to get the gateway address (network + 1)
            // that we assign to the TUN device itself.
            let (v4_gw, v4_prefix) = if !config.ip_proxy.ipv4_pool.is_empty() {
                let net: ipnet::Ipv4Net = config
                    .ip_proxy
                    .ipv4_pool
                    .parse()
                    .map_err(|e| anyhow::anyhow!("bad v4 pool: {e}"))?;
                let gw_bits = u32::from(net.network()) | 1;
                (
                    Some(std::net::Ipv4Addr::from(gw_bits)),
                    net.prefix_len(),
                )
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
                (
                    Some(std::net::Ipv6Addr::from(gw_bits)),
                    net.prefix_len(),
                )
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
            ) {
                Ok(t) => Some(t),
                Err(e) => {
                    warn!(%e, "failed to create TUN device — CONNECT-IP will be unavailable");
                    None
                }
            }
        } else {
            None
        };

        let (udp_response_tx, udp_response_rx) =
            mpsc::channel(UDP_RESPONSE_QUEUE_CAPACITY);

        let mut key_bytes = [0u8; 32];
        ring::rand::SecureRandom::fill(
            &ring::rand::SystemRandom::new(),
            &mut key_bytes,
        )
        .map_err(|_| anyhow::anyhow!("failed to seed connection ID key"))?;

        Ok(Self {
            socket,
            quic_config,
            h3_config,
            connections: FxHashMap::default(),
            udp_policy,
            address_pool,
            routing_table: RoutingTable::new(),
            config,
            next_conn_index: 0,
            conn_by_index: FxHashMap::default(),
            conn_id_key: ring::hmac::Key::new(
                ring::hmac::HMAC_SHA256,
                &key_bytes,
            ),
            tun,
            udp_response_tx,
            udp_response_rx,
        })
    }

    /// Run the server event loop.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut dgram_buf = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut tun_buf = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut recv_batch = RecvPacketBatch::new(MAX_QUIC_RECV_BATCH);
        let mut send_batch = SendPacketBatch::new();
        let tun_device = self.tun.as_ref().map(TunManager::device);

        let local_addr = self.socket.local_addr()?;
        let idle_timeout =
            Duration::from_secs(self.config.server.idle_timeout_secs);

        let mut shutting_down = false;
        let mut drain_deadline: Option<tokio::time::Instant> = None;
        const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
        let mut next_idle_sweep = Instant::now() + IDLE_SWEEP_INTERVAL;

        loop {
            // Calculate the earliest QUIC or pacing timer across all
            // connections. The 50ms cap also keeps shutdown and housekeeping
            // responsive while the server is otherwise idle.
            let now = Instant::now();
            let mut next_wakeup = Duration::from_millis(50);
            for client in self.connections.values() {
                if let Some(timeout) = client.quic.timeout() {
                    next_wakeup = next_wakeup.min(timeout);
                }
                if let Some(deadline) = client.deferred_send.deadline() {
                    next_wakeup = next_wakeup
                        .min(deadline.saturating_duration_since(now));
                }
            }
            let timeout = Some(next_wakeup);

            // Wait for a packet, signal, or timeout.
            enum Event {
                PacketBatch(std::io::Result<usize>),
                TargetDatagram(Option<UdpResponse>),
                TunPacket(std::io::Result<usize>),
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
                    result = async {
                        tun_device
                            .as_ref()
                            .expect("TUN select branch requires a device")
                            .recv(&mut tun_buf)
                            .await
                    }, if tun_device.is_some() && !shutting_down => {
                        Event::TunPacket(result)
                    }
                    result = tokio::time::timeout(
                        timeout, self.socket.recv_batch(&mut recv_batch)
                    ) => match result {
                        Ok(r) => Event::PacketBatch(r),
                        Err(_) => Event::Timeout,
                    },
                }
            } else {
                Event::PacketBatch(
                    self.socket.recv_batch(&mut recv_batch).await
                )
            };

            match event {
                Event::Shutdown => {
                    info!("shutdown signal received, draining connections...");
                    shutting_down = true;
                    drain_deadline =
                        Some(tokio::time::Instant::now() + DRAIN_TIMEOUT);

                    for client in self.connections.values_mut() {
                        if let Some(h3) = &mut client.h3 {
                            h3.send_goaway(&mut client.quic, 0).ok();
                        }
                        client
                            .quic
                            .close(true, 0x0, b"server shutting down")
                            .ok();
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
                        if let Ok(hdr) =
                            quiche::Header::from_slice(packet, CONN_ID_LEN)
                        {
                            if let Some(client) =
                                self.connections.get_mut(&hdr.dcid)
                            {
                                let recv_info =
                                    quiche::RecvInfo { from, to: local_addr };
                                client.quic.recv(packet, recv_info).ok();
                            }
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
                Event::TunPacket(Ok(len)) => {
                    if self.relay_tun_packet(&tun_buf[..len]) {
                        self.relay_tun_inbound(&mut tun_buf);
                    }
                }
                Event::TunPacket(Err(e)) => {
                    error!(%e, "TUN recv error");
                }
                Event::Timeout => {}
            }

            // Process QUIC DATAGRAMs → forward to target UDP/TUN.
            if !shutting_down {
                self.relay_client_datagrams(&mut dgram_buf);

                // Sweeping every iteration would walk every connection and
                // every tunnel per packet batch; once a second is plenty for a
                // timeout measured in seconds.
                let now = Instant::now();
                if now >= next_idle_sweep {
                    self.cleanup_idle_tunnels(idle_timeout);
                    next_idle_sweep = now + IDLE_SWEEP_INTERVAL;
                }
            }

            // Drive all connections: handle timers, send pending data.
            self.drive_connections(&mut out, &mut send_batch).await;

            // Remove closed connections and clean up their resources.
            let closed_ids: Vec<quiche::ConnectionId<'static>> = self
                .connections
                .iter()
                .filter(|(_, c)| c.quic.is_closed())
                .map(|(id, _)| id.clone())
                .collect();

            for id in closed_ids {
                if let Some(client) = self.connections.remove(&id) {
                    info!(?id, "connection closed");
                    for tunnel in client.ip_tunnels.values() {
                        self.address_pool.release_all(&tunnel.assigned_addrs);
                        // Remove by key rather than scanning the whole routing
                        // table once per tunnel.
                        self.routing_table.remove_owned(
                            &tunnel.assigned_addrs,
                            &TunnelOwner {
                                conn_id: client.index,
                                stream_id: tunnel.stream_id,
                            },
                        );
                    }
                    self.conn_by_index.remove(&client.index);
                }
            }

            // During shutdown, exit once all connections are drained or
            // the drain deadline is reached.
            if shutting_down {
                if self.connections.is_empty() {
                    info!("all connections drained, exiting");
                    return Ok(());
                }
                if let Some(deadline) = drain_deadline {
                    if tokio::time::Instant::now() >= deadline {
                        warn!(
                            remaining = self.connections.len(),
                            "drain timeout reached, forcing exit"
                        );
                        // Release all remaining IP tunnel resources.
                        for client in self.connections.values() {
                            for tunnel in client.ip_tunnels.values() {
                                self.address_pool
                                    .release_all(&tunnel.assigned_addrs);
                            }
                        }
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Process an incoming UDP packet (QUIC).
    fn handle_packet(
        &mut self,
        buf: &mut [u8],
        from: SocketAddr,
        local: SocketAddr,
    ) {
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
        let key = if let Some((conn_id, _)) =
            self.connections.get_key_value(&hdr.dcid)
        {
            conn_id.clone()
        } else {
            let conn_id = ring::hmac::sign(&self.conn_id_key, &hdr.dcid);
            let conn_id = quiche::ConnectionId::from_vec(
                conn_id.as_ref()[..CONN_ID_LEN].to_vec(),
            );

            if !self.connections.contains_key(&conn_id) {
                if hdr.ty != quiche::Type::Initial {
                    debug!("non-initial packet for unknown connection");
                    return;
                }

                // Enforce max_connections limit.
                if self.connections.len()
                    >= self.config.server.max_connections
                {
                    warn!("max connections reached, rejecting new connection");
                    return;
                }

                let scid = quiche::ConnectionId::from_vec(
                    conn_id.as_ref().to_vec(),
                );

                let quic = match quiche::accept(
                    &scid,
                    None,
                    local,
                    from,
                    &mut self.quic_config,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        error!(%e, "failed to accept connection");
                        return;
                    }
                };

                info!(?scid, %from, "new connection");

                let conn_idx = self.next_conn_index;
                self.next_conn_index += 1;
                self.conn_by_index.insert(conn_idx, scid.clone());

                let client = ClientConnection::new(quic, conn_idx);
                self.connections.insert(scid, client);
            }

            conn_id
        };

        let client = self.connections.get_mut(&key).unwrap();
        let conn_idx = client.index;

        // Feed the packet to quiche.
        let recv_info = quiche::RecvInfo { from, to: local };

        if let Err(e) = client.quic.recv(buf, recv_info) {
            debug!(%e, "quiche recv error");
            return;
        }

        // Upgrade to HTTP/3 once QUIC handshake completes.
        if client.h3.is_none() && client.quic.is_established() {
            match quiche::h3::Connection::with_transport(
                &mut client.quic,
                &self.h3_config,
            ) {
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
        let mut pending_udp_setups: Vec<(u64, uri::UdpTarget)> = Vec::new();
        let mut pending_ip_setups: Vec<u64> = Vec::new();
        let mut closed_ip_streams: Vec<u64> = Vec::new();

        // Process HTTP/3 events.
        if let Some(h3) = &mut client.h3 {
            loop {
                match h3.poll(&mut client.quic) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        Self::handle_request(
                            h3,
                            &mut client.quic,
                            stream_id,
                            &list,
                            &self.config,
                            &self.udp_policy,
                            &mut pending_udp_setups,
                            &mut pending_ip_setups,
                        );
                    }
                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        debug!(stream_id, "H3 data event");
                    }
                    Ok((stream_id, quiche::h3::Event::Finished)) => {
                        // Stream closed by client — remove tunnel if any.
                        if client.udp_tunnels.remove(&stream_id).is_some() {
                            info!(stream_id, "UDP tunnel closed by client");
                        }
                        if client.ip_tunnels.contains_key(&stream_id) {
                            closed_ip_streams.push(stream_id);
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Reset { .. })) => {
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

        // Handle tunnel setups after releasing the HTTP/3 borrow.
        let max_tunnels = self.config.server.max_tunnels_per_connection;
        let udp_response_tx = if pending_udp_setups.is_empty() {
            None
        } else {
            Some(self.udp_response_tx.clone())
        };
        for (stream_id, target) in pending_udp_setups {
            if client.tunnel_count() >= max_tunnels {
                warn!(
                    stream_id,
                    total_tunnels = client.tunnel_count(),
                    "tunnel limit reached, rejecting"
                );
                if let Some(h3) = &mut client.h3 {
                    Self::send_error_response(
                        h3, &mut client.quic, stream_id, 503,
                    );
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
                        Self::send_error_response(
                            h3, &mut client.quic, stream_id, 400,
                        );
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
                                    Self::send_error_response(
                                        h3, &mut client.quic, stream_id, 502,
                                    );
                                }
                                continue;
                            }
                            std_sock.set_nonblocking(true).ok();
                            match UdpSocket::from_std(std_sock) {
                                Ok(tok_sock) => {
                                    let socket = Arc::new(tok_sock);
                                    let recv_socket = Arc::clone(&socket);
                                    let response_tx = udp_response_tx
                                        .as_ref()
                                        .unwrap()
                                        .clone();
                                    let recv_task = tokio::spawn(async move {
                                        let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
                                        loop {
                                            match recv_socket.recv(&mut buf).await {
                                                Ok(len) => {
                                                    let response = UdpResponse {
                                                        connection_index: conn_idx,
                                                        stream_id,
                                                        datagram: header.encode(&buf[..len]),
                                                    };
                                                    if response_tx.send(response).await.is_err() {
                                                        break;
                                                    }
                                                }
                                                Err(e) => {
                                                    debug!(stream_id, %e, "target recv failed");
                                                    break;
                                                }
                                            }
                                        }
                                    });
                                    let tunnel = UdpTunnel::from_socket(
                                        stream_id,
                                        addr,
                                        socket,
                                        recv_task,
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
                                            h3, &mut client.quic, stream_id, 502,
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!(stream_id, %e, "UDP bind failed");
                            if let Some(h3) = &mut client.h3 {
                                Self::send_error_response(
                                    h3, &mut client.quic, stream_id, 502,
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(stream_id, %e, "DNS resolution failed");
                    if let Some(h3) = &mut client.h3 {
                        Self::send_error_response(
                            h3, &mut client.quic, stream_id, 502,
                        );
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
                    Self::send_error_response(
                        h3, &mut client.quic, stream_id, 503,
                    );
                }
                continue;
            }
            Self::setup_ip_tunnel(
                &mut self.address_pool,
                &mut self.routing_table,
                client,
                stream_id,
                conn_idx,
            );
        }

        // Clean up closed IP tunnels: release addresses, remove routes.
        for stream_id in closed_ip_streams {
            Self::teardown_ip_tunnel(
                &mut self.address_pool,
                &mut self.routing_table,
                client,
                stream_id,
                conn_idx,
            );
        }
    }

    /// Allocate addresses, register routes, send capsules for a new IP tunnel.
    fn setup_ip_tunnel(
        address_pool: &mut AddressPool,
        routing_table: &mut RoutingTable,
        client: &mut ClientConnection,
        stream_id: u64,
        conn_idx: u64,
    ) {
        let mut tunnel = IpTunnel::new(stream_id);

        // Allocate an IPv4 address if the pool has one.
        let v4_result = address_pool.allocate_v4();
        let v6_result = address_pool.allocate_v6();

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
            routing_table.insert(
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
            routing_table.insert(
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
        capsule::encoder::encode(
            &CapsuleFrame::AddressAssign(assigned),
            &mut capsules,
        );
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

        if let Some(h3) = &mut client.h3 {
            if let Err(e) =
                h3.send_body(&mut client.quic, stream_id, &capsules, false)
            {
                warn!(stream_id, %e, "failed to send CONNECT-IP capsules");
            }
        }

        client.ip_tunnels.insert(stream_id, tunnel);
        info!(stream_id, "CONNECT-IP tunnel established");
    }

    /// Release addresses and remove routes for a closing IP tunnel.
    fn teardown_ip_tunnel(
        address_pool: &mut AddressPool,
        routing_table: &mut RoutingTable,
        client: &mut ClientConnection,
        stream_id: u64,
        conn_idx: u64,
    ) {
        if let Some(tunnel) = client.ip_tunnels.remove(&stream_id) {
            info!(stream_id, "IP tunnel closed");

            // Release addresses back to the pool.
            address_pool.release_all(&tunnel.assigned_addrs);

            // Remove this tunnel's routes by key — the tunnel knows exactly
            // which addresses it holds, so there is no need to scan the table.
            routing_table.remove_owned(
                &tunnel.assigned_addrs,
                &TunnelOwner {
                    conn_id: conn_idx,
                    stream_id,
                },
            );
        }
    }

    /// Handle an incoming HTTP/3 request.
    fn handle_request(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        headers: &[quiche::h3::Header],
        config: &ServerConfig,
        udp_policy: &TargetPolicy,
        pending_udp_setups: &mut Vec<(u64, uri::UdpTarget)>,
        pending_ip_setups: &mut Vec<u64>,
    ) {
        // One pass over the header list, borrowing the values rather than
        // copying each one into an owned String.
        let mut method: &[u8] = b"";
        let mut path: &[u8] = b"";
        let mut protocol: &[u8] = b"";

        for header in headers {
            match header.name() {
                b":method" => method = header.value(),
                b":path" => path = header.value(),
                b":protocol" => protocol = header.value(),
                _ => {}
            }
        }

        info!(
            stream_id,
            method = %String::from_utf8_lossy(method),
            path = %String::from_utf8_lossy(path),
            protocol = %String::from_utf8_lossy(protocol),
            "request received"
        );

        // Check for Extended CONNECT
        if method == b"CONNECT" {
            match protocol {
                b"connect-udp" if config.udp_proxy.enabled => {
                    Self::handle_connect_udp(
                        h3,
                        quic,
                        stream_id,
                        &String::from_utf8_lossy(path),
                        config,
                        udp_policy,
                        pending_udp_setups,
                    );
                    return;
                }
                b"connect-ip" if config.ip_proxy.enabled => {
                    Self::handle_connect_ip_response(
                        h3,
                        quic,
                        stream_id,
                        pending_ip_setups,
                    );
                    return;
                }
                _ => {}
            }
        }

        // Default: 404 for anything we don't handle.
        Self::send_error_response(h3, quic, stream_id, 404);
    }

    /// Send 200 OK for CONNECT-IP and defer address allocation.
    fn handle_connect_ip_response(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        pending_ip_setups: &mut Vec<u64>,
    ) {
        info!(stream_id, "CONNECT-IP request accepted");

        // Send 200 OK with Capsule-Protocol header (stream stays open).
        let headers = vec![
            quiche::h3::Header::new(b":status", b"200"),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        ];

        if let Err(e) = h3.send_response(quic, stream_id, &headers, false) {
            warn!(stream_id, %e, "failed to send CONNECT-IP 200");
            return;
        }

        // Defer address allocation to after we release the h3 borrow.
        pending_ip_setups.push(stream_id);
    }

    /// Handle a CONNECT-UDP request: parse, validate, respond 200, defer
    /// socket creation.
    fn handle_connect_udp(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        path: &str,
        config: &ServerConfig,
        udp_policy: &TargetPolicy,
        pending_udp_setups: &mut Vec<(u64, uri::UdpTarget)>,
    ) {
        // Parse URI template
        let target = match uri::parse_udp_path(path, &config.udp_proxy.uri_template) {
            Ok(t) => t,
            Err(e) => {
                warn!(stream_id, %e, "bad CONNECT-UDP URI");
                Self::send_error_response(h3, quic, stream_id, 400);
                return;
            }
        };

        info!(stream_id, host = %target.host, port = target.port, "CONNECT-UDP");

        // Policy check: resolve and check against allow/deny lists.
        // For hostnames, we need to resolve first. We do a quick sync
        // resolve here for the policy check.
        match target.resolved_ips() {
            Ok(ips) => {
                if !udp_policy.all_allowed(&ips) {
                    warn!(
                        stream_id,
                        host = %target.host,
                        "target denied by policy"
                    );
                    Self::send_error_response(h3, quic, stream_id, 403);
                    return;
                }
            }
            Err(e) => {
                warn!(stream_id, %e, "DNS resolution failed for policy check");
                Self::send_error_response(h3, quic, stream_id, 502);
                return;
            }
        }

        // Send 200 OK with Capsule-Protocol header (stream stays open).
        let headers = vec![
            quiche::h3::Header::new(b":status", b"200"),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        ];

        if let Err(e) = h3.send_response(quic, stream_id, &headers, false) {
            warn!(stream_id, %e, "failed to send CONNECT-UDP 200");
            return;
        }

        // Defer actual socket creation to after we release the h3 borrow.
        pending_udp_setups.push((stream_id, target));
    }

    /// Relay QUIC DATAGRAMs from clients to target UDP sockets and TUN device.
    fn relay_client_datagrams(&mut self, dgram_buf: &mut [u8]) {
        for client in self.connections.values_mut() {
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

                // Check UDP tunnels first.
                if let Some(tunnel) = client.udp_tunnels.get_mut(&dgram.stream_id) {
                    match tunnel.socket.try_send(dgram.payload) {
                        Ok(_) => {
                            tunnel.last_activity = std::time::Instant::now();
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(e) => {
                            debug!(
                                stream_id = dgram.stream_id,
                                %e,
                                "send to target failed"
                            );
                        }
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

                    // Write to TUN device.
                    if let Some(tun) = &self.tun {
                        match tun.try_send(dgram.payload) {
                            Ok(_) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                            Err(e) => {
                                debug!(
                                    stream_id = dgram.stream_id,
                                    %e,
                                    "TUN write failed"
                                );
                            }
                        }
                    }
                    continue;
                }

                debug!(
                    stream_id = dgram.stream_id,
                    "datagram for unknown tunnel"
                );
            }
        }
    }

    /// Forward queued target responses and drain the receive queue in a batch.
    fn relay_target_datagrams(&mut self, first: UdpResponse) {
        let mut response = Some(first);

        while let Some(dgram) = response {
            let mut queue_full = false;
            if let Some(conn_id) = self.conn_by_index.get(&dgram.connection_index) {
                if let Some(client) = self.connections.get_mut(conn_id) {
                    if let Some(tunnel) = client.udp_tunnels.get_mut(&dgram.stream_id) {
                        tunnel.last_activity = Instant::now();

                        match client.quic.dgram_send_buf(dgram.datagram) {
                            Ok(()) => {}
                            // The send queue is full: stop draining and let the
                            // flush at the end of the loop make room.
                            Err(quiche::Error::Done) => queue_full = true,
                            // Oversized, or datagrams disabled. Dropping this
                            // one says nothing about the next, so keep draining.
                            Err(e) => {
                                debug!(
                                    stream_id = dgram.stream_id,
                                    %e,
                                    "dgram_send failed"
                                );
                            }
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

    /// Read IP packets from TUN device and route them to the correct client.
    fn relay_tun_inbound(&mut self, buf: &mut [u8]) {
        // Non-blocking reads from TUN. Bounded so a saturated TUN device cannot
        // starve the QUIC socket.
        for _ in 1..MAX_TUN_RECV_BATCH {
            let len = match self.tun.as_ref().unwrap().try_recv(buf) {
                Ok(len) => len,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    debug!(%e, "TUN recv error");
                    break;
                }
            };

            if !self.relay_tun_packet(&buf[..len]) {
                break;
            }
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
        let owner = match self.routing_table.lookup(&dst) {
            Some(o) => *o,
            None => return true,
        };

        let conn_id = match self.conn_by_index.get(&owner.conn_id) {
            Some(conn_id) => conn_id,
            None => {
                debug!(
                    conn_id = owner.conn_id,
                    "TUN packet for unknown connection"
                );
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
        let mut idle_ip_tunnels: Vec<(quiche::ConnectionId<'static>, u64, u64)> =
            Vec::new();

        for (conn_id, client) in &mut self.connections {
            // Borrow the fields separately so the tunnel maps can be walked
            // while still writing to the same connection's H3 stream.
            let ClientConnection {
                quic,
                h3,
                udp_tunnels,
                ip_tunnels,
                index,
                deferred_send: _,
            } = client;

            // UDP tunnels: dropping the tunnel aborts its receive task.
            udp_tunnels.retain(|stream_id, tunnel| {
                if !tunnel.is_idle(timeout) {
                    return true;
                }
                info!(stream_id, "closing idle UDP tunnel");
                if let Some(h3) = h3.as_mut() {
                    h3.send_body(quic, *stream_id, b"", true).ok();
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
                }
                idle_ip_tunnels.push((conn_id.clone(), *stream_id, *index));
            }
        }

        // Now tear down idle IP tunnels (needs &mut self fields).
        for (conn_id, stream_id, conn_idx) in idle_ip_tunnels {
            if let Some(client) = self.connections.get_mut(&conn_id) {
                Self::teardown_ip_tunnel(
                    &mut self.address_pool,
                    &mut self.routing_table,
                    client,
                    stream_id,
                    conn_idx,
                );
            }
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

    /// Drive all connections: handle timers and flush outgoing packets.
    async fn drive_connections(
        &mut self,
        out: &mut [u8],
        batch: &mut SendPacketBatch,
    ) {
        let socket = &mut self.socket;

        for (_, client) in &mut self.connections {
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
                    if let Some((packet, send_info)) =
                        client.deferred_send.take_if_due(now)
                    {
                        generated_bytes += packet.len();
                        batch.push(
                            packet,
                            send_info,
                            socket.udp_gso_enabled(),
                            send_quantum,
                        );
                    }
                }

                while batch.packet_count() < MAX_BATCH_PACKETS &&
                    generated_bytes < send_quantum
                {
                    let (write, send_info) = match client.quic.send(out) {
                        Ok(v) => v,
                        Err(quiche::Error::Done) => {
                            quiche_done = true;
                            break;
                        },
                        Err(e) => {
                            error!(%e, "quiche send error");
                            client.quic.close(false, 0x1, b"send error").ok();
                            quiche_done = true;
                            break;
                        },
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
        }
    }
}
