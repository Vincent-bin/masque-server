// Per-client QUIC + HTTP/3 connection state.

use crate::fxhash::FxHashMap;
use crate::tunnel::ip::IpTunnel;
use crate::tunnel::tcp::{PendingTcpTunnel, TcpTunnel};
use crate::tunnel::udp::UdpTunnel;

/// One serialized QUIC packet waiting for its pacing deadline. The backing
/// allocation is retained and reused so pacing does not add a packet-sized
/// allocation to the hot path.
#[derive(Default)]
pub(crate) struct DeferredSend {
    packet: Vec<u8>,
    info: Option<quiche::SendInfo>,
}

impl DeferredSend {
    pub(crate) fn deadline(&self) -> Option<std::time::Instant> {
        self.info.map(|info| info.at)
    }

    pub(crate) fn schedule(&mut self, packet: &[u8], info: quiche::SendInfo) {
        debug_assert!(self.info.is_none());
        self.packet.clear();
        self.packet.extend_from_slice(packet);
        self.info = Some(info);
    }

    pub(crate) fn take_if_due(
        &mut self,
        now: std::time::Instant,
    ) -> Option<(&[u8], quiche::SendInfo)> {
        let info = self.info?;
        if info.at > now {
            return None;
        }

        self.info = None;
        Some((&self.packet, info))
    }
}

/// State for a single client connection.
pub struct ClientConnection {
    pub quic: quiche::Connection,
    pub h3: Option<quiche::h3::Connection>,
    /// Standard CONNECT tunnels waiting for a target TCP connection.
    pub pending_tcp_tunnels: FxHashMap<u64, PendingTcpTunnel>,
    /// Active standard CONNECT TCP tunnels, keyed by stream ID.
    pub tcp_tunnels: FxHashMap<u64, TcpTunnel>,
    /// Active UDP tunnels, keyed by stream ID.
    pub udp_tunnels: FxHashMap<u64, UdpTunnel>,
    /// Active IP tunnels, keyed by stream ID.
    pub ip_tunnels: FxHashMap<u64, IpTunnel>,
    /// Dense index for this connection, used as the `conn_id` in
    /// `TunnelOwner` and to address the connection from background tasks.
    pub index: u64,
    /// Packet already emitted by quiche but held until `SendInfo::at`.
    pub(crate) deferred_send: DeferredSend,
}

impl ClientConnection {
    pub fn new(quic: quiche::Connection, index: u64) -> Self {
        Self {
            quic,
            h3: None,
            pending_tcp_tunnels: FxHashMap::default(),
            tcp_tunnels: FxHashMap::default(),
            udp_tunnels: FxHashMap::default(),
            ip_tunnels: FxHashMap::default(),
            index,
            deferred_send: DeferredSend::default(),
        }
    }

    /// Total active or connecting tunnels open on this connection.
    pub fn tunnel_count(&self) -> usize {
        self.pending_tcp_tunnels.len()
            + self.tcp_tunnels.len()
            + self.udp_tunnels.len()
            + self.ip_tunnels.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    fn send_info(at: Instant) -> quiche::SendInfo {
        quiche::SendInfo {
            from: SocketAddr::from(([127, 0, 0, 1], 4433)),
            to: SocketAddr::from(([127, 0, 0, 1], 9443)),
            at,
        }
    }

    #[test]
    fn deferred_send_waits_for_deadline_and_reuses_storage() {
        let now = Instant::now();
        let mut deferred = DeferredSend::default();
        deferred.schedule(b"first", send_info(now + Duration::from_millis(10)));

        assert_eq!(
            deferred.deadline(),
            Some(now + Duration::from_millis(10))
        );
        assert!(deferred.take_if_due(now).is_none());

        let (packet, _) = deferred
            .take_if_due(now + Duration::from_millis(10))
            .unwrap();
        assert_eq!(packet, b"first");
        assert_eq!(deferred.deadline(), None);

        deferred.schedule(b"second", send_info(now));
        let (packet, _) = deferred.take_if_due(now).unwrap();
        assert_eq!(packet, b"second");
    }
}
