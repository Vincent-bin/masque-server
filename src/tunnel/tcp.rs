// Standard HTTP CONNECT tunnel implementation over HTTP/3.

use std::collections::VecDeque;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::{JoinHandle, JoinSet};

use crate::policy::TargetPolicy;
use crate::uri::TcpTarget;

use super::target::resolve_allowed;

pub use super::target::TargetSetupFailure as TcpSetupFailure;

const TCP_READ_CHUNK_SIZE: usize = 64 * 1024;
pub const MAX_BUFFERED_CLIENT_BYTES: usize = 1024 * 1024;

/// Target-to-client bytes a single tunnel may hold in flight, counting both
/// the relay channel and the queue awaiting HTTP/3 capacity.
///
/// The reader reserves against this budget before each read, so it can stay
/// several chunks ahead of the event loop instead of stopping after every one,
/// while total memory stays bounded per tunnel.
pub const MAX_BUFFERED_RESPONSE_BYTES: usize = 256 * 1024;

// The reader reserves a whole chunk before each read, so a budget smaller than
// one chunk would never be satisfiable and the reader would hang forever.
const _: () = assert!(MAX_BUFFERED_RESPONSE_BYTES >= TCP_READ_CHUNK_SIZE);

pub enum TcpRelayEvent {
    ConnectResult {
        connection_index: u64,
        stream_id: u64,
        result: Result<(TcpStream, SocketAddr), TcpSetupFailure>,
    },
    Data {
        connection_index: u64,
        stream_id: u64,
        data: Bytes,
    },
    Eof {
        connection_index: u64,
        stream_id: u64,
    },
    Error {
        connection_index: u64,
        stream_id: u64,
        reason: String,
    },
}

impl TcpRelayEvent {
    /// Target payload carried by this event.
    ///
    /// Setup, EOF, and error notifications still count as relay events, but
    /// only data contributes to the per-round byte budget and metrics.
    pub(crate) fn payload_len(&self) -> usize {
        match self {
            Self::Data { data, .. } => data.len(),
            Self::ConnectResult { .. } | Self::Eof { .. } | Self::Error { .. } => 0,
        }
    }
}

enum TcpCommand {
    Data(Vec<u8>),
    Finish,
}

pub struct PendingTcpTunnel {
    pub stream_id: u64,
    pub last_activity: Instant,
    pub early_data: Vec<Vec<u8>>,
    pub early_bytes: usize,
    pub client_finished: bool,
    connect_task: Option<JoinHandle<()>>,
}

impl PendingTcpTunnel {
    pub fn staging(stream_id: u64) -> Self {
        Self {
            stream_id,
            last_activity: Instant::now(),
            early_data: Vec::new(),
            early_bytes: 0,
            client_finished: false,
            connect_task: None,
        }
    }

    pub fn start_connect(&mut self, connect_task: JoinHandle<()>) {
        debug_assert!(self.connect_task.is_none());
        self.connect_task = Some(connect_task);
    }

    pub fn buffer_client_data(&mut self, data: Vec<u8>) -> bool {
        let Some(new_len) = self.early_bytes.checked_add(data.len()) else {
            return false;
        };
        if new_len > MAX_BUFFERED_CLIENT_BYTES {
            return false;
        }
        self.early_bytes = new_len;
        self.last_activity = Instant::now();
        self.early_data.push(data);
        true
    }

    pub fn is_idle(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
}

impl Drop for PendingTcpTunnel {
    fn drop(&mut self) {
        if let Some(task) = self.connect_task.take() {
            task.abort();
        }
    }
}

/// One chunk of target output, and how much of it HTTP/3 has taken so far.
pub struct PendingTcpResponse {
    pub data: Bytes,
    pub offset: usize,
}

pub struct TcpTunnel {
    pub stream_id: u64,
    pub target_addr: SocketAddr,
    pub last_activity: Instant,
    /// Target output waiting for HTTP/3 capacity, oldest first.
    pending_responses: VecDeque<PendingTcpResponse>,
    pub upstream_finished: bool,
    pub response_finished: bool,
    pub client_finished: bool,
    command_tx: mpsc::UnboundedSender<TcpCommand>,
    queued_client_bytes: Arc<AtomicUsize>,
    /// Remaining target-to-client byte budget, shared with the reader task.
    response_credit: Arc<Semaphore>,
    reader_task: Option<JoinHandle<()>>,
    writer_task: Option<JoinHandle<()>>,
}

impl TcpTunnel {
    pub fn from_stream(
        connection_index: u64,
        stream_id: u64,
        target_addr: SocketAddr,
        stream: TcpStream,
        event_tx: mpsc::Sender<TcpRelayEvent>,
    ) -> Self {
        let (mut reader, mut writer) = stream.into_split();
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();
        let queued_client_bytes = Arc::new(AtomicUsize::new(0));
        let writer_queued_bytes = Arc::clone(&queued_client_bytes);
        let writer_event_tx = event_tx.clone();

        let writer_task = tokio::spawn(async move {
            while let Some(command) = command_rx.recv().await {
                match command {
                    TcpCommand::Data(data) => {
                        let len = data.len();
                        let result = writer.write_all(&data).await;
                        writer_queued_bytes.fetch_sub(len, Ordering::AcqRel);
                        if let Err(error) = result {
                            let _ = writer_event_tx
                                .send(TcpRelayEvent::Error {
                                    connection_index,
                                    stream_id,
                                    reason: format!("target TCP write failed: {error}"),
                                })
                                .await;
                            return;
                        }
                    }
                    TcpCommand::Finish => {
                        if let Err(error) = writer.shutdown().await {
                            let _ = writer_event_tx
                                .send(TcpRelayEvent::Error {
                                    connection_index,
                                    stream_id,
                                    reason: format!("target TCP shutdown failed: {error}"),
                                })
                                .await;
                        }
                        return;
                    }
                }
            }
        });

        let response_credit = Arc::new(Semaphore::new(MAX_BUFFERED_RESPONSE_BYTES));
        let reader_credit = Arc::clone(&response_credit);

        let reader_task = tokio::spawn(async move {
            // One backing allocation is split into `Bytes` chunks that share
            // it, so handing a chunk to the event loop costs no copy.
            let mut buffer = BytesMut::with_capacity(TCP_READ_CHUNK_SIZE);
            loop {
                // Reserve the whole chunk up front: the read is then bounded by
                // the budget rather than by the event loop acknowledging the
                // previous chunk. Unused reservation is returned below.
                let Ok(reservation) = Arc::clone(&reader_credit)
                    .acquire_many_owned(TCP_READ_CHUNK_SIZE as u32)
                    .await
                else {
                    // The tunnel was torn down.
                    return;
                };
                reservation.forget();

                buffer.reserve(TCP_READ_CHUNK_SIZE);
                // `reserve` may hand back more spare capacity than asked for,
                // and `read_buf` fills whatever is spare. Cap the read at the
                // reservation so the credit accounting below cannot underflow.
                let read = (&mut reader)
                    .take(TCP_READ_CHUNK_SIZE as u64)
                    .read_buf(&mut buffer)
                    .await;

                match read {
                    Ok(0) => {
                        reader_credit.add_permits(TCP_READ_CHUNK_SIZE);
                        let _ = event_tx
                            .send(TcpRelayEvent::Eof {
                                connection_index,
                                stream_id,
                            })
                            .await;
                        return;
                    }
                    Ok(len) => {
                        // Only the bytes actually read stay reserved; the event
                        // loop returns them as it writes them to HTTP/3.
                        reader_credit.add_permits(TCP_READ_CHUNK_SIZE - len);
                        let data = buffer.split_to(len).freeze();
                        if event_tx
                            .send(TcpRelayEvent::Data {
                                connection_index,
                                stream_id,
                                data,
                            })
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(error) => {
                        reader_credit.add_permits(TCP_READ_CHUNK_SIZE);
                        let _ = event_tx
                            .send(TcpRelayEvent::Error {
                                connection_index,
                                stream_id,
                                reason: format!("target TCP read failed: {error}"),
                            })
                            .await;
                        return;
                    }
                }
            }
        });

        Self {
            stream_id,
            target_addr,
            last_activity: Instant::now(),
            pending_responses: VecDeque::new(),
            upstream_finished: false,
            response_finished: false,
            client_finished: false,
            command_tx,
            queued_client_bytes,
            response_credit,
            reader_task: Some(reader_task),
            writer_task: Some(writer_task),
        }
    }

    pub fn queue_client_data(&mut self, data: Vec<u8>) -> bool {
        if self.client_finished {
            return false;
        }
        let len = data.len();
        if !reserve_bounded(&self.queued_client_bytes, len, MAX_BUFFERED_CLIENT_BYTES) {
            return false;
        }

        if self.command_tx.send(TcpCommand::Data(data)).is_err() {
            self.queued_client_bytes.fetch_sub(len, Ordering::AcqRel);
            return false;
        }
        self.last_activity = Instant::now();
        true
    }

    pub fn finish_client(&mut self) {
        if self.client_finished {
            return;
        }
        self.client_finished = true;
        self.last_activity = Instant::now();
        let _ = self.command_tx.send(TcpCommand::Finish);
    }

    /// Queue a chunk of target output for the client.
    ///
    /// The reader has already reserved these bytes against the tunnel's budget,
    /// so this only refuses a chunk that arrives after the response was closed.
    pub fn queue_response(&mut self, data: Bytes) -> bool {
        if self.response_finished {
            return false;
        }
        self.pending_responses
            .push_back(PendingTcpResponse { data, offset: 0 });
        self.last_activity = Instant::now();
        true
    }

    /// The oldest chunk still awaiting HTTP/3 capacity.
    pub fn front_response(&mut self) -> Option<&mut PendingTcpResponse> {
        self.pending_responses.front_mut()
    }

    /// Account for `written` bytes taken by HTTP/3, releasing that much of the
    /// reader's budget and retiring the chunk once it is fully written.
    pub fn advance_response(&mut self, written: usize) {
        let Some(response) = self.pending_responses.front_mut() else {
            return;
        };
        response.offset += written;
        if response.offset >= response.data.len() {
            self.pending_responses.pop_front();
        }
        self.response_credit.add_permits(written);
        self.last_activity = Instant::now();
    }

    pub fn has_pending_response(&self) -> bool {
        !self.pending_responses.is_empty()
    }

    pub fn is_complete(&self) -> bool {
        self.client_finished && self.response_finished
    }

    pub fn is_idle(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
}

/// Atomically reserve `amount` without allowing the counter to exceed `limit`.
///
/// This uses the long-standing compare-exchange API so the crate keeps its
/// Rust 1.88 MSRV; newer `try_update` is not available there.
fn reserve_bounded(counter: &AtomicUsize, amount: usize, limit: usize) -> bool {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let Some(next) = current.checked_add(amount).filter(|next| *next <= limit) else {
            return false;
        };
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

impl Drop for TcpTunnel {
    fn drop(&mut self) {
        if let Some(task) = self.reader_task.take() {
            task.abort();
        }
        if let Some(task) = self.writer_task.take() {
            task.abort();
        }
    }
}

pub fn spawn_tcp_connect(
    connection_index: u64,
    stream_id: u64,
    target: TcpTarget,
    policy: TargetPolicy,
    timeout: Duration,
    event_tx: mpsc::Sender<TcpRelayEvent>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let result = resolve_and_connect(target, &policy, timeout).await;
        let _ = event_tx
            .send(TcpRelayEvent::ConnectResult {
                connection_index,
                stream_id,
                result,
            })
            .await;
    })
}

pub(crate) async fn resolve_and_connect(
    target: TcpTarget,
    policy: &TargetPolicy,
    timeout: Duration,
) -> Result<(TcpStream, SocketAddr), TcpSetupFailure> {
    let deadline = tokio::time::Instant::now() + timeout;
    let resolved = resolve_allowed(&target.host, target.port, policy, deadline).await?;
    let connected =
        tokio::time::timeout_at(deadline, happy_eyeballs_connect(resolved.into_addresses()))
            .await
            .map_err(|_| TcpSetupFailure::timeout("DNS resolution or TCP connect"))?
            .map_err(|error| TcpSetupFailure::connect("TCP", error))?;

    let (stream, address) = connected;
    let _ = stream.set_nodelay(true);
    Ok((stream, address))
}

/// RFC 8305-style stagger between address-family attempts. An immediate
/// failure starts the next address without waiting for this delay.
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);

async fn happy_eyeballs_connect(
    addresses: Vec<SocketAddr>,
) -> std::io::Result<(TcpStream, SocketAddr)> {
    happy_eyeballs_connect_with(addresses, HAPPY_EYEBALLS_DELAY, |address| async move {
        TcpStream::connect(address).await
    })
    .await
}

/// Race interleaved IPv6/IPv4 candidates while retaining a deterministic hook
/// for dual-stack fallback tests.
async fn happy_eyeballs_connect_with<C, Fut, T>(
    addresses: Vec<SocketAddr>,
    attempt_delay: Duration,
    connector: C,
) -> std::io::Result<(T, SocketAddr)>
where
    C: Fn(SocketAddr) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = std::io::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    let addresses = interleave_address_families(addresses);
    if addresses.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no target addresses to connect",
        ));
    }

    let mut attempts = JoinSet::new();
    let mut next = 0usize;
    let mut next_launch = tokio::time::Instant::now();
    let mut last_error = None;

    while next < addresses.len() || !attempts.is_empty() {
        // Start the first candidate immediately. If every in-flight attempt
        // failed synchronously, also start its successor immediately.
        if attempts.is_empty() && next < addresses.len() {
            spawn_connect_attempt(&mut attempts, connector.clone(), addresses[next]);
            next += 1;
            next_launch = tokio::time::Instant::now() + attempt_delay;
        }

        let joined = if next < addresses.len() {
            tokio::select! {
                joined = attempts.join_next() => joined,
                _ = tokio::time::sleep_until(next_launch) => {
                    spawn_connect_attempt(&mut attempts, connector.clone(), addresses[next]);
                    next += 1;
                    next_launch = tokio::time::Instant::now() + attempt_delay;
                    continue;
                }
            }
        } else {
            attempts.join_next().await
        };

        match joined {
            Some(Ok((address, Ok(value)))) => return Ok((value, address)),
            Some(Ok((_, Err(error)))) => last_error = Some(error),
            Some(Err(error)) => {
                last_error = Some(std::io::Error::other(format!(
                    "target TCP connect task failed: {error}"
                )));
            }
            None => break,
        }
    }

    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "no target address connected")
    }))
}

fn spawn_connect_attempt<C, Fut, T>(
    attempts: &mut JoinSet<(SocketAddr, std::io::Result<T>)>,
    connector: C,
    address: SocketAddr,
) where
    C: Fn(SocketAddr) -> Fut + Send + 'static,
    Fut: Future<Output = std::io::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    attempts.spawn(async move { (address, connector(address).await) });
}

/// Preserve resolver preference while alternating address families. This
/// avoids waiting for every IPv6 record before the first IPv4 attempt (or the
/// reverse when the resolver prefers IPv4).
fn interleave_address_families(addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let Some(prefer_ipv6) = addresses.first().map(SocketAddr::is_ipv6) else {
        return addresses;
    };
    let mut ipv4 = VecDeque::new();
    let mut ipv6 = VecDeque::new();
    for address in addresses {
        if address.is_ipv4() {
            ipv4.push_back(address);
        } else {
            ipv6.push_back(address);
        }
    }

    let mut prefer_ipv6 = prefer_ipv6;
    let mut interleaved = Vec::with_capacity(ipv4.len() + ipv6.len());
    while !ipv4.is_empty() || !ipv6.is_empty() {
        let address = if prefer_ipv6 {
            ipv6.pop_front().or_else(|| ipv4.pop_front())
        } else {
            ipv4.pop_front().or_else(|| ipv6.pop_front())
        };
        interleaved.push(address.expect("one address family remains"));
        prefer_ipv6 = !prefer_ipv6;
    }
    interleaved
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_eyeballs_interleaves_families_without_losing_resolver_preference() {
        let v6_first: Vec<SocketAddr> = [
            "[2001:db8::1]:443",
            "[2001:db8::2]:443",
            "192.0.2.1:443",
            "192.0.2.2:443",
        ]
        .into_iter()
        .map(|address| address.parse().unwrap())
        .collect();
        let ordered = interleave_address_families(v6_first);
        assert_eq!(ordered[0], "[2001:db8::1]:443".parse().unwrap());
        assert_eq!(ordered[1], "192.0.2.1:443".parse().unwrap());
        assert_eq!(ordered[2], "[2001:db8::2]:443".parse().unwrap());
        assert_eq!(ordered[3], "192.0.2.2:443".parse().unwrap());
    }

    #[tokio::test]
    async fn happy_eyeballs_falls_back_to_ipv4_while_ipv6_is_stalled() {
        let ipv6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let ipv4: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            happy_eyeballs_connect_with(
                vec![ipv6, ipv4],
                Duration::from_millis(20),
                move |address| async move {
                    if address.is_ipv6() {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "simulated unreachable IPv6 path",
                        ))
                    } else {
                        Ok(address)
                    }
                },
            ),
        )
        .await
        .expect("IPv4 should race the stalled IPv6 attempt")
        .unwrap();

        assert_eq!(result, (ipv4, ipv4));
    }

    #[test]
    fn relay_event_payload_length_counts_only_data() {
        let data = TcpRelayEvent::Data {
            connection_index: 1,
            stream_id: 4,
            data: Bytes::from_static(b"payload"),
        };
        let eof = TcpRelayEvent::Eof {
            connection_index: 1,
            stream_id: 4,
        };

        assert_eq!(data.payload_len(), 7);
        assert_eq!(eof.payload_len(), 0);
    }

    #[tokio::test]
    async fn pending_tunnel_bounds_early_data() {
        let task = tokio::spawn(std::future::pending());
        let mut pending = PendingTcpTunnel::staging(0);
        pending.start_connect(task);
        assert!(pending.buffer_client_data(vec![0; MAX_BUFFERED_CLIENT_BYTES]));
        assert!(!pending.buffer_client_data(vec![0]));
    }

    /// Build a tunnel over a connected socket pair so the response queue can be
    /// driven without a live proxy.
    async fn test_tunnel() -> TcpTunnel {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, _) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let (event_tx, _event_rx) = mpsc::channel(8);
        TcpTunnel::from_stream(0, 0, addr, client.unwrap(), event_tx)
    }

    #[tokio::test]
    async fn response_queue_keeps_several_chunks_in_flight() {
        let mut tunnel = test_tunnel().await;

        assert!(tunnel.queue_response(Bytes::from_static(b"first")));
        assert!(tunnel.queue_response(Bytes::from_static(b"second")));
        assert!(tunnel.has_pending_response());

        // Chunks are handed to HTTP/3 oldest first.
        assert_eq!(&tunnel.front_response().unwrap().data[..], b"first");
        tunnel.advance_response(5);
        assert_eq!(&tunnel.front_response().unwrap().data[..], b"second");
        tunnel.advance_response(6);
        assert!(!tunnel.has_pending_response());
    }

    #[tokio::test]
    async fn partial_writes_release_credit_incrementally() {
        let mut tunnel = test_tunnel().await;
        let before = tunnel.response_credit.available_permits();

        tunnel.queue_response(Bytes::from_static(b"0123456789"));
        // Simulate the reader having reserved these bytes.
        tunnel
            .response_credit
            .acquire_many(10)
            .await
            .unwrap()
            .forget();
        assert_eq!(tunnel.response_credit.available_permits(), before - 10);

        tunnel.advance_response(4);
        assert_eq!(tunnel.response_credit.available_permits(), before - 6);
        assert!(tunnel.has_pending_response());
        assert_eq!(tunnel.front_response().unwrap().offset, 4);

        tunnel.advance_response(6);
        assert_eq!(tunnel.response_credit.available_permits(), before);
        assert!(!tunnel.has_pending_response());
    }

    #[tokio::test]
    async fn response_queue_refuses_chunks_after_the_response_closed() {
        let mut tunnel = test_tunnel().await;
        tunnel.response_finished = true;
        assert!(!tunnel.queue_response(Bytes::from_static(b"late")));
    }
}
