//! Shared HTTP/2 stream lifecycle helpers.

use std::future::poll_fn;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Buf as _, Bytes};
use h2::server::SendResponse;
use h2::{Reason, SendStream};
use http::{Response, StatusCode};

use crate::metrics::ShardMetrics;

pub(super) async fn send_data(
    send: &mut SendStream<Bytes>,
    mut data: Bytes,
    end_stream: bool,
) -> Result<(), h2::Error> {
    if data.is_empty() {
        return send.send_data(data, end_stream);
    }

    while data.has_remaining() {
        send.reserve_capacity(data.remaining());
        let capacity = poll_fn(|cx| send.poll_capacity(cx))
            .await
            .ok_or_else(|| h2::Error::from(Reason::STREAM_CLOSED))??;
        let take = capacity.min(data.remaining());
        let chunk = data.split_to(take);
        let finished = end_stream && data.is_empty();
        send.send_data(chunk, finished)?;
    }
    Ok(())
}

pub(super) fn send_error(
    respond: &mut SendResponse<Bytes>,
    status: StatusCode,
) -> Result<(), h2::Error> {
    let response = Response::builder()
        .status(status)
        .body(())
        .expect("status-only response is valid");
    respond.send_response(response, true).map(|_| ())
}

pub(super) struct Activity {
    started: Instant,
    last_millis: std::sync::atomic::AtomicU64,
}

impl Activity {
    pub(super) fn new() -> Self {
        Self {
            started: Instant::now(),
            last_millis: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub(super) fn touch(&self) {
        use std::sync::atomic::Ordering;
        let elapsed = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        self.last_millis.store(elapsed, Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        use std::sync::atomic::Ordering;
        let last = self.last_millis.load(Ordering::Relaxed);
        let now = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        Duration::from_millis(now.saturating_sub(last))
    }
}

pub(super) async fn wait_until_idle(activity: Arc<Activity>, timeout: Duration) {
    let check_interval = timeout.min(Duration::from_secs(1));
    loop {
        tokio::time::sleep(check_interval).await;
        if activity.idle_for() >= timeout {
            return;
        }
    }
}

pub(super) struct ConnectionMetricsGuard {
    metrics: Arc<ShardMetrics>,
}

impl ConnectionMetricsGuard {
    pub(super) fn new(metrics: Arc<ShardMetrics>) -> Self {
        metrics.connection_opened();
        Self { metrics }
    }
}

impl Drop for ConnectionMetricsGuard {
    fn drop(&mut self) {
        self.metrics.connection_closed();
    }
}

pub(super) struct TunnelMetricsGuard {
    metrics: Arc<ShardMetrics>,
    protocol_index: usize,
}

impl TunnelMetricsGuard {
    pub(super) fn new(metrics: Arc<ShardMetrics>, protocol_index: usize) -> Self {
        metrics.tunnel_opened(protocol_index);
        Self {
            metrics,
            protocol_index,
        }
    }
}

impl Drop for TunnelMetricsGuard {
    fn drop(&mut self) {
        self.metrics.tunnel_closed(self.protocol_index);
    }
}
