// Standard HTTP CONNECT tunnel implementation over HTTP/3.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::policy::TargetPolicy;
use crate::uri::TcpTarget;

const TCP_READ_CHUNK_SIZE: usize = 16 * 1024;
pub const MAX_BUFFERED_CLIENT_BYTES: usize = 1024 * 1024;

pub struct TcpSetupFailure {
    pub status: u16,
    pub reason: String,
}

pub enum TcpRelayEvent {
    ConnectResult {
        connection_index: u64,
        stream_id: u64,
        result: Result<(TcpStream, SocketAddr), TcpSetupFailure>,
    },
    Data {
        connection_index: u64,
        stream_id: u64,
        data: Vec<u8>,
        acknowledged: oneshot::Sender<()>,
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

pub struct PendingTcpResponse {
    pub data: Vec<u8>,
    pub offset: usize,
    acknowledged: Option<oneshot::Sender<()>>,
}

impl PendingTcpResponse {
    fn new(data: Vec<u8>, acknowledged: oneshot::Sender<()>) -> Self {
        Self {
            data,
            offset: 0,
            acknowledged: Some(acknowledged),
        }
    }

    pub fn acknowledge(mut self) {
        if let Some(tx) = self.acknowledged.take() {
            let _ = tx.send(());
        }
    }
}

pub struct TcpTunnel {
    pub stream_id: u64,
    pub target_addr: SocketAddr,
    pub last_activity: Instant,
    pub pending_response: Option<PendingTcpResponse>,
    pub upstream_finished: bool,
    pub response_finished: bool,
    pub client_finished: bool,
    command_tx: mpsc::UnboundedSender<TcpCommand>,
    queued_client_bytes: Arc<AtomicUsize>,
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

        let reader_task = tokio::spawn(async move {
            let mut buffer = vec![0_u8; TCP_READ_CHUNK_SIZE];
            loop {
                match reader.read(&mut buffer).await {
                    Ok(0) => {
                        let _ = event_tx
                            .send(TcpRelayEvent::Eof {
                                connection_index,
                                stream_id,
                            })
                            .await;
                        return;
                    }
                    Ok(len) => {
                        let (ack_tx, ack_rx) = oneshot::channel();
                        if event_tx
                            .send(TcpRelayEvent::Data {
                                connection_index,
                                stream_id,
                                data: buffer[..len].to_vec(),
                                acknowledged: ack_tx,
                            })
                            .await
                            .is_err()
                        {
                            return;
                        }
                        if ack_rx.await.is_err() {
                            return;
                        }
                    }
                    Err(error) => {
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
            pending_response: None,
            upstream_finished: false,
            response_finished: false,
            client_finished: false,
            command_tx,
            queued_client_bytes,
            reader_task: Some(reader_task),
            writer_task: Some(writer_task),
        }
    }

    pub fn queue_client_data(&mut self, data: Vec<u8>) -> bool {
        if self.client_finished {
            return false;
        }
        let len = data.len();
        let reserved = self.queued_client_bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
                queued
                    .checked_add(len)
                    .filter(|new_len| *new_len <= MAX_BUFFERED_CLIENT_BYTES)
            })
            .is_ok();
        if !reserved {
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

    pub fn set_pending_response(
        &mut self,
        data: Vec<u8>,
        acknowledged: oneshot::Sender<()>,
    ) -> bool {
        if self.pending_response.is_some() || self.response_finished {
            return false;
        }
        self.pending_response = Some(PendingTcpResponse::new(data, acknowledged));
        self.last_activity = Instant::now();
        true
    }

    pub fn is_complete(&self) -> bool {
        self.client_finished && self.response_finished
    }

    pub fn is_idle(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
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

async fn resolve_and_connect(
    target: TcpTarget,
    policy: &TargetPolicy,
    timeout: Duration,
) -> Result<(TcpStream, SocketAddr), TcpSetupFailure> {
    let setup = async {
        let addrs: Vec<SocketAddr> =
            tokio::net::lookup_host((target.host.as_str(), target.port))
                .await
                .map_err(|error| TcpSetupFailure {
                    status: 502,
                    reason: format!("target DNS resolution failed: {error}"),
                })?
                .collect();

        if addrs.is_empty() {
            return Err(TcpSetupFailure {
                status: 502,
                reason: "target DNS resolution returned no addresses".into(),
            });
        }
        let ips: Vec<_> = addrs.iter().map(|addr| addr.ip()).collect();
        if !policy.all_allowed(&ips) {
            return Err(TcpSetupFailure {
                status: 403,
                reason: "target denied by TCP policy".into(),
            });
        }

        let mut last_error = None;
        for addr in addrs {
            match TcpStream::connect(addr).await {
                Ok(stream) => return Ok((stream, addr)),
                Err(error) => last_error = Some(error),
            }
        }
        Err(TcpSetupFailure {
            status: 502,
            reason: format!(
                "target TCP connect failed: {}",
                last_error.expect("non-empty target address list")
            ),
        })
    };

    match tokio::time::timeout(timeout, setup).await {
        Ok(Ok((stream, addr))) => {
            let _ = stream.set_nodelay(true);
            Ok((stream, addr))
        }
        Ok(Err(failure)) => Err(failure),
        Err(_) => Err(TcpSetupFailure {
            status: 504,
            reason: "target DNS resolution or TCP connect timed out".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pending_tunnel_bounds_early_data() {
        let task = tokio::spawn(std::future::pending());
        let mut pending = PendingTcpTunnel::staging(0);
        pending.start_connect(task);
        assert!(pending.buffer_client_data(vec![0; MAX_BUFFERED_CLIENT_BYTES]));
        assert!(!pending.buffer_client_data(vec![0]));
    }
}
