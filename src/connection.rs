// Per-client QUIC + HTTP/3 connection state.

use crate::fxhash::FxHashMap;
use crate::tunnel::ip::IpTunnel;
use crate::tunnel::udp::UdpTunnel;

/// State for a single client connection.
pub struct ClientConnection {
    pub quic: quiche::Connection,
    pub h3: Option<quiche::h3::Connection>,
    /// Active UDP tunnels, keyed by stream ID.
    pub udp_tunnels: FxHashMap<u64, UdpTunnel>,
    /// Active IP tunnels, keyed by stream ID.
    pub ip_tunnels: FxHashMap<u64, IpTunnel>,
    /// Dense index for this connection, used as the `conn_id` in
    /// `TunnelOwner` and to address the connection from background tasks.
    pub index: u64,
}

impl ClientConnection {
    pub fn new(quic: quiche::Connection, index: u64) -> Self {
        Self {
            quic,
            h3: None,
            udp_tunnels: FxHashMap::default(),
            ip_tunnels: FxHashMap::default(),
            index,
        }
    }

    /// Total tunnels open on this connection, across both protocols.
    pub fn tunnel_count(&self) -> usize {
        self.udp_tunnels.len() + self.ip_tunnels.len()
    }
}
