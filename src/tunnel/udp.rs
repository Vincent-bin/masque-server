// CONNECT-UDP tunnel implementation (RFC 9298).
//
// Each tunnel owns a UDP socket connected to the target and relays datagrams
// bidirectionally between the QUIC client and the target.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::debug;
#[cfg(target_os = "linux")]
use tracing::warn;

#[cfg(target_os = "linux")]
use crate::net::target_udp;
use crate::net::target_udp::TARGET_BATCH_SIZE;
use crate::policy::TargetPolicy;
use crate::uri::UdpTarget;

use super::target::{TargetSetupFailure, resolve_allowed};

/// A connected target socket prepared off the HTTP/3 event loop.
pub(crate) struct ConnectedUdpTarget {
    target_addr: SocketAddr,
    send_socket: std::net::UdpSocket,
    recv_socket: UdpSocket,
    udp_gso: bool,
}

impl ConnectedUdpTarget {
    /// HTTP/2 uses Tokio's socket in both directions and does not need the
    /// duplicate descriptor retained by the HTTP/3 batching path.
    pub(crate) fn into_http2(self) -> (UdpSocket, SocketAddr) {
        (self.recv_socket, self.target_addr)
    }

    /// Split out every descriptor and the negotiated offload state HTTP/3
    /// needs when it installs the live tunnel.
    pub(crate) fn into_http3(self) -> (std::net::UdpSocket, Arc<UdpSocket>, SocketAddr, bool) {
        (
            self.send_socket,
            Arc::new(self.recv_socket),
            self.target_addr,
            self.udp_gso,
        )
    }
}

/// Completion sent from an asynchronous HTTP/3 UDP setup task to its shard.
pub(crate) struct UdpSetupResult {
    pub(crate) connection_index: u64,
    pub(crate) stream_id: u64,
    pub(crate) result: Result<ConnectedUdpTarget, TargetSetupFailure>,
}

/// A CONNECT-UDP stream whose one-shot resolution/socket setup is in flight.
pub(crate) struct PendingUdpTunnel {
    header: crate::datagram::DatagramHeader,
    started_at: Instant,
    setup_task: Option<JoinHandle<()>>,
}

impl PendingUdpTunnel {
    pub(crate) fn new(header: crate::datagram::DatagramHeader) -> Self {
        Self {
            header,
            started_at: Instant::now(),
            setup_task: None,
        }
    }

    pub(crate) fn start_setup(&mut self, task: JoinHandle<()>) {
        debug_assert!(self.setup_task.is_none());
        self.setup_task = Some(task);
    }

    pub(crate) fn header(&self) -> crate::datagram::DatagramHeader {
        self.header
    }

    pub(crate) fn is_idle(&self, timeout: Duration) -> bool {
        self.started_at.elapsed() > timeout
    }
}

impl Drop for PendingUdpTunnel {
    fn drop(&mut self) {
        if let Some(task) = self.setup_task.take() {
            task.abort();
        }
    }
}

/// Resolve and connect one UDP target under a single deadline. Both HTTP/2 and
/// HTTP/3 call this function, so policy always evaluates the same address
/// snapshot the socket subsequently uses.
pub(crate) async fn connect_udp_target(
    target: UdpTarget,
    policy: &TargetPolicy,
    timeout: Duration,
    enable_udp_gso: bool,
    max_datagram_size: usize,
) -> Result<ConnectedUdpTarget, TargetSetupFailure> {
    let deadline = tokio::time::Instant::now() + timeout;
    let resolved = resolve_allowed(&target.host, target.port, policy, deadline).await?;
    let mut last_error = None;

    for target_addr in resolved.into_addresses() {
        match open_connected_udp(target_addr, enable_udp_gso, max_datagram_size) {
            Ok(socket) => return Ok(socket),
            Err(error) => last_error = Some(error),
        }
    }

    Err(TargetSetupFailure::connect(
        "UDP",
        last_error.expect("resolved target contains at least one address"),
    ))
}

fn open_connected_udp(
    target_addr: SocketAddr,
    enable_udp_gso: bool,
    max_datagram_size: usize,
) -> std::io::Result<ConnectedUdpTarget> {
    let bind_addr: SocketAddr = if target_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let send_socket = std::net::UdpSocket::bind(bind_addr)?;
    send_socket.connect(target_addr)?;
    send_socket.set_nonblocking(true)?;

    #[cfg(target_os = "linux")]
    let udp_gso = if enable_udp_gso {
        use std::os::fd::AsRawFd as _;
        target_udp::detect_udp_gso(send_socket.as_raw_fd(), max_datagram_size)
    } else {
        false
    };
    #[cfg(not(target_os = "linux"))]
    let udp_gso = {
        let _ = (enable_udp_gso, max_datagram_size);
        false
    };

    let recv_socket = send_socket.try_clone()?;
    recv_socket.set_nonblocking(true)?;
    let recv_socket = UdpSocket::from_std(recv_socket)?;

    Ok(ConnectedUdpTarget {
        target_addr,
        send_socket,
        recv_socket,
        udp_gso,
    })
}

/// Start HTTP/3 UDP target setup without blocking its shard.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_udp_setup(
    connection_index: u64,
    stream_id: u64,
    target: UdpTarget,
    policy: TargetPolicy,
    timeout: Duration,
    enable_udp_gso: bool,
    max_datagram_size: usize,
    result_tx: mpsc::Sender<UdpSetupResult>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let result =
            connect_udp_target(target, &policy, timeout, enable_udp_gso, max_datagram_size).await;
        let _ = result_tx
            .send(UdpSetupResult {
                connection_index,
                stream_id,
                result,
            })
            .await;
    })
}

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
    /// Whether target-side UDP segmentation offload is active on Linux.
    #[cfg(target_os = "linux")]
    udp_gso: bool,
}

impl UdpTunnel {
    /// Create a new UDP tunnel by binding a local socket and connecting it to
    /// the target.
    pub async fn new(stream_id: u64, target_addr: SocketAddr) -> std::io::Result<Self> {
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
            #[cfg(target_os = "linux")]
            udp_gso: false,
        })
    }

    pub(crate) fn from_socket(
        stream_id: u64,
        target_addr: SocketAddr,
        send_socket: std::net::UdpSocket,
        socket: Arc<UdpSocket>,
        recv_task: JoinHandle<()>,
        udp_gso: bool,
    ) -> Self {
        #[cfg(not(target_os = "linux"))]
        let _ = udp_gso;

        Self {
            stream_id,
            socket,
            send_socket,
            target_addr,
            last_activity: Instant::now(),
            recv_task: Some(recv_task),
            send_stage: Vec::new(),
            staged: 0,
            #[cfg(target_os = "linux")]
            udp_gso,
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
            self.send_stage
                .push(Vec::with_capacity(payload.len().max(1_500)));
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
            let sent = match target_udp::send_mmsg(
                self.send_socket.as_raw_fd(),
                &self.send_stage[..staged],
                self.udp_gso,
            ) {
                Ok(sent) => sent,
                Err(error) if self.udp_gso && target_udp::is_udp_gso_error(&error) => {
                    self.udp_gso = false;
                    warn!(
                        stream_id = self.stream_id,
                        %error,
                        "target UDP GSO unavailable, falling back to sendmmsg"
                    );
                    target_udp::send_mmsg(
                        self.send_socket.as_raw_fd(),
                        &self.send_stage[..staged],
                        false,
                    )?
                }
                Err(error) => return Err(error),
            };
            if sent < staged {
                debug!(
                    stream_id = self.stream_id,
                    dropped = staged - sent,
                    "target socket accepted only part of the batch"
                );
            }
            Ok(())
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
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    fn loopback_policy() -> TargetPolicy {
        TargetPolicy::new(&["127.0.0.0/8".into()], &[])
    }

    #[tokio::test]
    async fn shared_target_setup_connects_the_checked_address() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let prepared = connect_udp_target(
            UdpTarget {
                host: target_addr.ip().to_string(),
                port: target_addr.port(),
            },
            &loopback_policy(),
            Duration::from_secs(1),
            false,
            1350,
        )
        .await
        .unwrap();
        let (socket, connected_addr) = prepared.into_http2();
        assert_eq!(connected_addr, target_addr);

        socket.send(b"checked snapshot").await.unwrap();
        let mut received = [0_u8; 64];
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(1), target.recv_from(&mut received))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&received[..len], b"checked snapshot");
    }

    #[tokio::test]
    async fn dropping_pending_udp_setup_cancels_its_task() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = Arc::clone(&dropped);
        let task = tokio::spawn(async move {
            let _drop = Dropped(task_dropped);
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;

        let mut pending = PendingUdpTunnel::new(crate::datagram::DatagramHeader::new(0).unwrap());
        pending.start_setup(task);
        drop(pending);
        tokio::task::yield_now().await;

        assert!(dropped.load(Ordering::Acquire));
    }

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
