// CONNECT-UDP tunnel implementation (RFC 9298).
//
// Each tunnel owns a UDP socket connected to the target and relays datagrams
// bidirectionally between the QUIC client and the target.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::debug;

/// State for a single CONNECT-UDP tunnel.
pub struct UdpTunnel {
    /// The HTTP/3 stream ID this tunnel is bound to.
    pub stream_id: u64,
    /// Proxy-side UDP socket connected to the target.
    pub socket: Arc<UdpSocket>,
    /// Resolved target address.
    pub target_addr: SocketAddr,
    /// Timestamp of last datagram relayed (either direction).
    pub last_activity: Instant,
    /// Background task that waits for target responses and wakes the server.
    pub(crate) recv_task: Option<JoinHandle<()>>,
}

impl UdpTunnel {
    /// Create a new UDP tunnel by binding a local socket and connecting it to
    /// the target.
    pub async fn new(
        stream_id: u64,
        target_addr: SocketAddr,
    ) -> std::io::Result<Self> {
        // Bind to an ephemeral port. Use 0.0.0.0 for IPv4 targets, [::] for IPv6.
        let bind_addr: SocketAddr = if target_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(target_addr).await?;

        debug!(
            stream_id,
            local = %socket.local_addr().unwrap(),
            target = %target_addr,
            "UDP tunnel created"
        );

        Ok(Self {
            stream_id,
            socket: Arc::new(socket),
            target_addr,
            last_activity: Instant::now(),
            recv_task: None,
        })
    }

    pub(crate) fn from_socket(
        stream_id: u64,
        target_addr: SocketAddr,
        socket: Arc<UdpSocket>,
        recv_task: JoinHandle<()>,
    ) -> Self {
        Self {
            stream_id,
            socket,
            target_addr,
            last_activity: Instant::now(),
            recv_task: Some(recv_task),
        }
    }

    /// Forward a payload from the client to the target.
    pub async fn send_to_target(&mut self, payload: &[u8]) -> std::io::Result<()> {
        self.socket.send(payload).await?;
        self.last_activity = Instant::now();
        Ok(())
    }

    /// Wait for a packet from the target.
    pub async fn recv_from_target(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.socket.recv(buf).await?;
        self.last_activity = Instant::now();
        Ok(n)
    }

    /// Check whether the tunnel has been idle longer than `timeout`.
    pub fn is_idle(&self, timeout: std::time::Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    /// Get the quarter stream ID for datagram framing.
    pub fn quarter_stream_id(&self) -> u64 {
        self.stream_id / 4
    }
}

impl Drop for UdpTunnel {
    fn drop(&mut self) {
        if let Some(task) = self.recv_task.take() {
            task.abort();
        }
    }
}
