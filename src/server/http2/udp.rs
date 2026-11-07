//! CONNECT-UDP relay over DATAGRAM capsules on one HTTP/2 stream.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use h2::Reason;
use h2::server::SendResponse;
use http::{Response, StatusCode};
use tokio::sync::OwnedSemaphorePermit;
use tracing::{debug, info, warn};

use super::ConnectionContext;
use super::request::CAPSULE_PROTOCOL;
use super::support::{
    Activity, TunnelMetricsGuard, send_data, send_error, until_reset, wait_until_idle,
};
use crate::capsule::datagram::DatagramCapsules;
use crate::capsule::encoder;
use crate::tunnel::udp::connect_udp_target;
use crate::uri::UdpTarget;
use crate::varint;

const MAX_UDP_PAYLOAD: usize = 65_527;
const RESPONSE_BATCH_PACKETS: usize = 16;
const RESPONSE_BATCH_BYTES: usize = 4 * 1024;

pub(super) async fn serve(
    stream_id: u32,
    target: UdpTarget,
    mut body: h2::RecvStream,
    mut respond: SendResponse<Bytes>,
    context: ConnectionContext,
    _tunnel_slot: OwnedSemaphorePermit,
) -> anyhow::Result<()> {
    let max_payload = context.config.http2.max_datagram_size.min(MAX_UDP_PAYLOAD);
    let setup = connect_udp_target(
        target,
        &context.udp_policy,
        Duration::from_secs(context.config.udp_proxy.connect_timeout_secs),
        false,
        max_payload,
        &context.resolver,
    );
    let Some(result) = until_reset(&mut respond, setup).await else {
        return Ok(());
    };
    let prepared = match result {
        Ok(prepared) => prepared,
        Err(failure) => {
            warn!(
                stream_id,
                status = failure.status,
                reason = %failure.reason,
                "HTTP/2 UDP target setup failed"
            );
            let status = StatusCode::from_u16(failure.status).unwrap_or(StatusCode::BAD_GATEWAY);
            send_error(&mut respond, status)?;
            return Ok(());
        }
    };
    let (socket, target_addr) = prepared.into_http2();

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CAPSULE_PROTOCOL, "?1")
        .body(())?;
    let mut send = respond.send_response(response, false)?;
    info!(stream_id, %target_addr, transport = "http2", "UDP tunnel established");
    let _metrics = TunnelMetricsGuard::new(Arc::clone(&context.metrics), 1);
    let activity = Arc::new(Activity::new());
    // QUIC varints may encode Context ID zero in 1, 2, 4, or 8 bytes. Keep
    // framing headroom separate from the decoded UDP payload limit below.
    // As on HTTP/3, unknown capsule values are discarded incrementally, with
    // no allocation or datagram-size restriction (RFC 9297 Section 3.2).
    let mut decoder = DatagramCapsules::new(max_payload + 8);

    let client_to_target = async {
        while let Some(chunk) = body.data().await {
            let chunk = chunk?;
            let datagrams = decoder.decode(&chunk)?;
            body.flow_control().release_capacity(chunk.len())?;
            for payload in datagrams {
                let (context_id, context_len) = varint::decode(&payload)
                    .map_err(|_| anyhow::anyhow!("DATAGRAM capsule has no Context ID"))?;
                if context_id != 0 {
                    continue;
                }
                let udp_payload = &payload[context_len..];
                if udp_payload.len() > max_payload {
                    anyhow::bail!("UDP payload exceeds configured HTTP/2 datagram limit");
                }
                let written = socket.send(udp_payload).await?;
                if written != udp_payload.len() {
                    anyhow::bail!("target UDP socket accepted a partial datagram");
                }
                activity.touch();
            }
        }
        if decoder.is_partial() {
            anyhow::bail!("request ended with a truncated capsule");
        }
        Ok::<_, anyhow::Error>(())
    };

    let target_to_client = async {
        // One extra byte detects a datagram larger than the configured limit;
        // never forward a silently truncated prefix.
        let mut recv = vec![0_u8; max_payload + 1];
        loop {
            let mut read = socket.recv(&mut recv).await?;
            let mut capsules = Vec::new();
            // Drain only packets that are already ready. The final capsule can
            // cross the soft byte limit by at most one datagram. Flow control
            // is applied before reading another batch.
            for index in 0..RESPONSE_BATCH_PACKETS {
                if read <= max_payload {
                    if capsules.is_empty() {
                        capsules.reserve(read + 8);
                    }
                    encoder::encode_datagram_context_zero(&recv[..read], &mut capsules);
                } else {
                    debug!(
                        stream_id,
                        read, max_payload, "dropping oversized HTTP/2 target datagram"
                    );
                }
                if capsules.len() >= RESPONSE_BATCH_BYTES || index + 1 == RESPONSE_BATCH_PACKETS {
                    break;
                }
                match socket.try_recv(&mut recv) {
                    Ok(len) => read = len,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error.into()),
                }
            }
            if !capsules.is_empty() {
                activity.touch();
                send_data(&mut send, Bytes::from(capsules), false).await?;
            }
        }
    };

    // RFC 9298 recommends not expiring UDP mappings in less than two minutes.
    let idle_timeout =
        Duration::from_secs(context.config.server.idle_timeout_secs).max(Duration::from_secs(120));
    enum Completion {
        Client(anyhow::Result<()>),
        Target(anyhow::Result<()>),
        Idle,
    }
    let completion = tokio::select! {
        result = client_to_target => Completion::Client(result),
        result = target_to_client => Completion::Target(result),
        _ = wait_until_idle(Arc::clone(&activity), idle_timeout) => Completion::Idle,
    };
    match completion {
        Completion::Client(Ok(())) => {
            send_data(&mut send, Bytes::new(), true).await?;
        }
        Completion::Client(Err(error)) | Completion::Target(Err(error)) => {
            send.send_reset(Reason::PROTOCOL_ERROR);
            return Err(error);
        }
        Completion::Target(Ok(())) => unreachable!("target receive loop never completes cleanly"),
        Completion::Idle => send.send_reset(Reason::CANCEL),
    }
    Ok(())
}
