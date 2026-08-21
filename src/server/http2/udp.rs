//! CONNECT-UDP relay over DATAGRAM capsules on one HTTP/2 stream.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use h2::Reason;
use h2::server::SendResponse;
use http::{Response, StatusCode};
use tokio::net::UdpSocket;
use tokio::sync::OwnedSemaphorePermit;
use tracing::{debug, info, warn};

use super::ConnectionContext;
use super::request::CAPSULE_PROTOCOL;
use super::support::{Activity, TunnelMetricsGuard, send_data, send_error, wait_until_idle};
use crate::capsule::decoder::CapsuleDecoder;
use crate::capsule::{CapsuleFrame, encoder};
use crate::uri::UdpTarget;
use crate::varint;

const MAX_UDP_PAYLOAD: usize = 65_527;

pub(super) async fn serve(
    stream_id: u32,
    target: UdpTarget,
    mut body: h2::RecvStream,
    mut respond: SendResponse<Bytes>,
    context: ConnectionContext,
    _tunnel_slot: OwnedSemaphorePermit,
) -> anyhow::Result<()> {
    let addrs: Vec<SocketAddr> =
        match tokio::net::lookup_host((target.host.as_str(), target.port)).await {
            Ok(addrs) => addrs.collect(),
            Err(error) => {
                warn!(stream_id, %error, "HTTP/2 UDP target DNS resolution failed");
                send_error(&mut respond, StatusCode::BAD_GATEWAY)?;
                return Ok(());
            }
        };
    if addrs.is_empty() {
        send_error(&mut respond, StatusCode::BAD_GATEWAY)?;
        return Ok(());
    }
    if !context
        .udp_policy
        .all_allowed(&addrs.iter().map(|addr| addr.ip()).collect::<Vec<_>>())
    {
        send_error(&mut respond, StatusCode::FORBIDDEN)?;
        return Ok(());
    }
    let target_addr = addrs[0];
    let socket = match UdpSocket::bind(if target_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await
    {
        Ok(socket) => socket,
        Err(error) => {
            warn!(stream_id, %error, "HTTP/2 UDP socket bind failed");
            send_error(&mut respond, StatusCode::BAD_GATEWAY)?;
            return Ok(());
        }
    };
    if let Err(error) = socket.connect(target_addr).await {
        warn!(stream_id, %error, "HTTP/2 UDP target connect failed");
        send_error(&mut respond, StatusCode::BAD_GATEWAY)?;
        return Ok(());
    }

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CAPSULE_PROTOCOL, "?1")
        .body(())?;
    let mut send = respond.send_response(response, false)?;
    info!(stream_id, %target_addr, transport = "http2", "UDP tunnel established");
    let _metrics = TunnelMetricsGuard::new(Arc::clone(&context.metrics), 1);
    let activity = Arc::new(Activity::new());
    let max_payload = context.config.http2.max_datagram_size.min(MAX_UDP_PAYLOAD);
    // One extra byte admits the context ID zero before the UDP payload.
    let mut decoder = CapsuleDecoder::with_max_capsule_size(max_payload + 1);

    let client_to_target = async {
        while let Some(chunk) = body.data().await {
            let chunk = chunk?;
            let frames = decoder.decode(&chunk)?;
            body.flow_control().release_capacity(chunk.len())?;
            for frame in frames {
                let CapsuleFrame::Datagram(payload) = frame else {
                    continue;
                };
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
        if decoder.buffered() != 0 {
            anyhow::bail!("request ended with a truncated DATAGRAM capsule");
        }
        Ok::<_, anyhow::Error>(())
    };

    let target_to_client = async {
        // One extra byte detects a datagram larger than the configured limit;
        // never forward a silently truncated prefix.
        let mut recv = vec![0_u8; max_payload + 1];
        let mut capsule = Vec::with_capacity(max_payload + 16);
        loop {
            let read = socket.recv(&mut recv).await?;
            if read > max_payload {
                debug!(
                    stream_id,
                    read, max_payload, "dropping oversized HTTP/2 target datagram"
                );
                continue;
            }
            activity.touch();
            // The HTTP Datagram payload begins with Context ID zero.
            capsule.clear();
            encoder::encode_datagram_context_zero(&recv[..read], &mut capsule);
            send_data(&mut send, Bytes::copy_from_slice(&capsule), false).await?;
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
