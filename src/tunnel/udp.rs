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

use crate::tunnel::target_io::TARGET_BATCH_SIZE;
#[cfg(target_os = "linux")]
use crate::tunnel::target_io;

/// State for a single CONNECT-UDP tunnel.
pub struct UdpTunnel {
    /// The HTTP/3 stream ID this tunnel is bound to.
    pub stream_id: u64,
    /// Tokio socket used by the background target-response receiver.
    pub socket: Arc<UdpSocket>,
    /// A duplicate descriptor used for immediate nonblocking sends.
    ///
    /// `tokio::net::UdpSocket::try_send()` is readiness-gated and can return
    /// `WouldBlock` without issuing a syscall immediately after registration.
    /// Keeping a standard-library duplicate avoids dropping the first client
    /// datagram while Tokio is still observing the socket's writable state.
    send_socket: std::net::UdpSocket,
    /// Resolved target address.
    pub target_addr: SocketAddr,
    /// Timestamp of last datagram relayed (either direction).
    pub last_activity: Instant,
    /// Background task that waits for target responses and wakes the server.
    pub(crate) recv_task: Option<JoinHandle<()>>,
    /// Client datagrams staged for one batched write to the target.
    ///
    /// A client burst arrives as several datagrams in one event-loop round;
    /// staging them turns what was a syscall per datagram into one per burst.
    send_stage: Vec<Vec<u8>>,
    staged: usize,
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

        let send_socket = std::net::UdpSocket::bind(bind_addr)?;
        send_socket.connect(target_addr)?;
        send_socket.set_nonblocking(true)?;
        let recv_socket = send_socket.try_clone()?;
        recv_socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(recv_socket)?;

        debug!(
            stream_id,
            local = %socket.local_addr().unwrap(),
            target = %target_addr,
            "UDP tunnel created"
        );

        Ok(Self {
            stream_id,
            socket: Arc::new(socket),
            send_socket,
            target_addr,
            last_activity: Instant::now(),
            recv_task: None,
            send_stage: Vec::new(),
            staged: 0,
        })
    }

    pub(crate) fn from_socket(
        stream_id: u64,
        target_addr: SocketAddr,
        send_socket: std::net::UdpSocket,
        socket: Arc<UdpSocket>,
        recv_task: JoinHandle<()>,
    ) -> Self {
        Self {
            stream_id,
            socket,
            send_socket,
            target_addr,
            last_activity: Instant::now(),
            recv_task: Some(recv_task),
            send_stage: Vec::new(),
            staged: 0,
        }
    }

    /// Forward a payload from the client to the target.
    pub async fn send_to_target(&mut self, payload: &[u8]) -> std::io::Result<()> {
        self.socket.send(payload).await?;
        self.last_activity = Instant::now();
        Ok(())
    }

    /// Forward a payload immediately without depending on Tokio's cached
    /// writable readiness for this newly registered socket.
    pub fn try_send_to_target(&mut self, payload: &[u8]) -> std::io::Result<()> {
        let sent = self.send_socket.send(payload)?;
        if sent != payload.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "partial UDP datagram send",
            ));
        }
        self.last_activity = Instant::now();
        Ok(())
    }

    /// Stage a client payload for the next batched write.
    ///
    /// Returns true when the batch is full and the caller should flush.
    pub fn stage_to_target(&mut self, payload: &[u8]) -> bool {
        if self.staged == self.send_stage.len() {
            self.send_stage.push(Vec::with_capacity(payload.len().max(1_500)));
        }
        let buffer = &mut self.send_stage[self.staged];
        buffer.clear();
        buffer.extend_from_slice(payload);
        self.staged += 1;
        self.staged >= TARGET_BATCH_SIZE
    }

    pub fn has_staged(&self) -> bool {
        self.staged > 0
    }

    /// Write every staged datagram, in one syscall where the platform allows.
    ///
    /// A datagram the socket refuses is dropped rather than retried: UDP has no
    /// delivery guarantee and the client will retransmit if it cares.
    pub fn flush_to_target(&mut self) -> std::io::Result<()> {
        if self.staged == 0 {
            return Ok(());
        }
        let staged = self.staged;
        self.staged = 0;
        self.last_activity = Instant::now();

        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: The socket is live, connected, and nonblocking.
            let sent = unsafe {
                target_io::send_mmsg(self.send_socket.as_raw_fd(), &self.send_stage[..staged])
            }?;
            if sent < staged {
                debug!(
                    stream_id = self.stream_id,
                    dropped = staged - sent,
                    "target socket accepted only part of the batch"
                );
            }
            return Ok(());
        }

        #[cfg(not(target_os = "linux"))]
        {
            for payload in &self.send_stage[..staged] {
                match self.send_socket.send(payload) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn immediate_nonblocking_send_reaches_target() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let mut tunnel = UdpTunnel::new(0, target_addr).await.unwrap();

        tunnel.try_send_to_target(b"first datagram").unwrap();

        let mut received = [0_u8; 64];
        let len = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            target.recv(&mut received),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&received[..len], b"first datagram");
    }
}
