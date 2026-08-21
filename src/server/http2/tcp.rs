//! TCP CONNECT relay over one HTTP/2 stream.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use h2::Reason;
use h2::server::SendResponse;
use http::{Response, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::OwnedSemaphorePermit;
use tracing::{info, warn};

use super::ConnectionContext;
use super::support::{Activity, TunnelMetricsGuard, send_data, send_error, wait_until_idle};
use crate::tunnel::tcp::{TcpSetupFailure, resolve_and_connect};
use crate::uri::TcpTarget;

const READ_CHUNK_SIZE: usize = 64 * 1024;

pub(super) async fn serve(
    stream_id: u32,
    target: TcpTarget,
    mut body: h2::RecvStream,
    mut respond: SendResponse<Bytes>,
    context: ConnectionContext,
    _tunnel_slot: OwnedSemaphorePermit,
) -> anyhow::Result<()> {
    let (stream, target_addr) = match resolve_and_connect(
        target,
        &context.tcp_policy,
        Duration::from_secs(context.config.tcp_proxy.connect_timeout_secs),
    )
    .await
    {
        Ok(connected) => connected,
        Err(TcpSetupFailure { status, reason }) => {
            warn!(stream_id, %reason, "HTTP/2 TCP target setup failed");
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
            send_error(&mut respond, status)?;
            return Ok(());
        }
    };

    let response = Response::builder().status(StatusCode::OK).body(())?;
    let mut send = respond.send_response(response, false)?;
    info!(stream_id, %target_addr, transport = "http2", "TCP tunnel established");
    let _metrics = TunnelMetricsGuard::new(Arc::clone(&context.metrics), 0);
    let activity = Arc::new(Activity::new());
    let (mut target_read, mut target_write) = stream.into_split();

    let client_to_target = async {
        while let Some(chunk) = body.data().await {
            let chunk = chunk?;
            target_write.write_all(&chunk).await?;
            body.flow_control().release_capacity(chunk.len())?;
            activity.touch();
        }
        target_write.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };
    let target_to_client = async {
        let mut buf = vec![0_u8; READ_CHUNK_SIZE];
        loop {
            let read = target_read.read(&mut buf).await?;
            if read == 0 {
                send_data(&mut send, Bytes::new(), true).await?;
                return Ok::<_, anyhow::Error>(());
            }
            activity.touch();
            send_data(&mut send, Bytes::copy_from_slice(&buf[..read]), false).await?;
        }
    };

    let relay = async { tokio::try_join!(client_to_target, target_to_client).map(|_| ()) };
    tokio::select! {
        result = relay => result?,
        _ = wait_until_idle(Arc::clone(&activity), Duration::from_secs(context.config.server.idle_timeout_secs)) => {
            send.send_reset(Reason::CANCEL);
        }
    }
    Ok(())
}
