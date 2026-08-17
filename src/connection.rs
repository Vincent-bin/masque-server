// Per-client QUIC + HTTP/3 connection state.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::client_identity::ClientIdentity;
use crate::fxhash::FxHashMap;
use crate::tunnel::ip::IpTunnel;
use crate::tunnel::tcp::{PendingTcpTunnel, TcpTunnel};
use crate::tunnel::udp::UdpTunnel;

/// One CONNECT stream waiting for its credentials to be verified.
pub(crate) struct AwaitingAuth {
    pub(crate) client_finished: bool,
    cancelled: Arc<AtomicBool>,
    task: Option<tokio::task::AbortHandle>,
}

impl AwaitingAuth {
    pub(crate) fn new() -> Self {
        Self {
            client_finished: false,
            cancelled: Arc::new(AtomicBool::new(false)),
            task: None,
        }
    }

    pub(crate) fn cancellation_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }

    /// Attach the verification task after it has been admitted to the global
    /// bounded queue.
    pub(crate) fn set_task(&mut self, task: tokio::task::AbortHandle) {
        if let Some(previous) = self.task.replace(task) {
            previous.abort();
        }
    }
}

impl Drop for AwaitingAuth {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

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
    /// Streams whose CONNECT is waiting on credential verification.
    ///
    /// Request-body bytes for these streams are deliberately left unread in
    /// quiche, so an unauthenticated caller cannot make the server buffer
    /// anything; stream flow control bounds them until the tunnel exists.
    pub(crate) awaiting_auth: FxHashMap<u64, AwaitingAuth>,
    /// Dense index for this connection, used as the `conn_id` in
    /// `TunnelOwner` and to address the connection from background tasks.
    pub index: u64,
    /// The roster entry this connection's TLS client certificate resolved to,
    /// when client-certificate authentication is in use.
    ///
    /// Resolved once at handshake completion: the key cannot change for the
    /// life of the connection, so re-parsing the certificate per request would
    /// be wasted work.
    pub(crate) identity: Option<Arc<ClientIdentity>>,
    /// Packet already emitted by quiche but held until `SendInfo::at`.
    pub(crate) deferred_send: DeferredSend,
    /// The deadline this connection currently holds in the server's timer
    /// queue, used to tell a live wakeup from one a later deadline superseded.
    pub(crate) scheduled_deadline: Option<std::time::Instant>,
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
            awaiting_auth: FxHashMap::default(),
            index,
            identity: None,
            deferred_send: DeferredSend::default(),
            scheduled_deadline: None,
        }
    }

    /// The next instant this connection needs the event loop's attention:
    /// quiche's own timer, or the release time of a packet held back by pacing.
    pub(crate) fn next_deadline(&self, now: std::time::Instant) -> Option<std::time::Instant> {
        let quic = self.quic.timeout().map(|timeout| now + timeout);
        match (quic, self.deferred_send.deadline()) {
            (Some(quic), Some(pacing)) => Some(quic.min(pacing)),
            (quic, pacing) => quic.or(pacing),
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

        assert_eq!(deferred.deadline(), Some(now + Duration::from_millis(10)));
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

    #[tokio::test]
    async fn dropping_awaiting_auth_aborts_queued_task() {
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let slot = Arc::clone(&slots).acquire_owned().await.unwrap();
        let task = tokio::spawn(async move {
            let _slot = slot;
            std::future::pending::<()>().await;
        });
        let mut awaiting = AwaitingAuth::new();
        let cancelled = awaiting.cancellation_flag();
        awaiting.set_task(task.abort_handle());

        drop(awaiting);

        assert!(cancelled.load(Ordering::Acquire));
        let error = task
            .await
            .expect_err("dropping auth state must abort its task");
        assert!(error.is_cancelled());
        assert_eq!(slots.available_permits(), 1);
    }
}
