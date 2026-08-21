//! CONNECT-IP relay over DATAGRAM capsules and the shared Linux TUN.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use h2::Reason;
use h2::server::SendResponse;
use http::{Response, StatusCode};
use tokio::sync::{OwnedSemaphorePermit, mpsc};
use tracing::{debug, info, warn};

use super::super::{
    Http2TunRoute, Shared, allocate_pool_addresses, claim_static_addresses,
    encode_ip_setup_capsules,
};
use super::ConnectionContext;
use super::request::CAPSULE_PROTOCOL;
use super::support::{Activity, TunnelMetricsGuard, send_data, send_error, wait_until_idle};
use crate::capsule::decoder::CapsuleDecoder;
use crate::capsule::{CapsuleFrame, encoder};
use crate::client_identity::ClientIdentity;
use crate::ip_packet;
use crate::routing::TunnelOwner;
use crate::tun::TunSendBatch;
use crate::varint;

const MAX_TUN_QUEUE_PACKETS: usize = 256;
const RESPONSE_BATCH_SIZE: usize = 64 * 1024;
const MAX_CONTROL_CAPSULE_SIZE: usize = 64 * 1024;

/// CONNECT-IP has two HTTP/2 wire shapes in active use.
///
/// RFC 9484 uses Extended CONNECT and keeps Context ID zero in each DATAGRAM
/// capsule. Cloudflare's TCP fallback predates that shape: it uses a regular
/// CONNECT plus `cf-connect-proto`, and removes the zero byte from capsule
/// values. usque intentionally mirrors the latter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IpCapsuleMode {
    Standard,
    Cloudflare,
}

impl IpCapsuleMode {
    fn decode_packet(self, payload: &[u8]) -> anyhow::Result<Option<&[u8]>> {
        match self {
            Self::Cloudflare => Ok(Some(payload)),
            Self::Standard => {
                let (context_id, context_len) = varint::decode(payload)
                    .map_err(|_| anyhow::anyhow!("DATAGRAM capsule has no Context ID"))?;
                if context_id == 0 {
                    Ok(Some(&payload[context_len..]))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn encode_packet(self, packet: &[u8], output: &mut Vec<u8>) {
        match self {
            Self::Standard => encoder::encode_datagram_context_zero(packet, output),
            Self::Cloudflare => encoder::encode_datagram(packet, output),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn serve(
    connection_index: u64,
    stream_id: u32,
    mut body: h2::RecvStream,
    mut respond: SendResponse<Bytes>,
    context: ConnectionContext,
    authenticated_identity: Option<Arc<ClientIdentity>>,
    capsule_mode: IpCapsuleMode,
    _tunnel_slot: OwnedSemaphorePermit,
) -> anyhow::Result<()> {
    let stream_id = u64::from(stream_id);
    let pinned = authenticated_identity
        .as_deref()
        .filter(|identity| identity.has_static_addresses());
    let addresses = match pinned {
        Some(identity) => match claim_static_addresses(&context.shared, identity) {
            Ok(addresses) => addresses,
            Err(error) => {
                warn!(
                    stream_id,
                    client = %identity.name,
                    %error,
                    "cannot attach HTTP/2 IP tunnel to fixed addresses"
                );
                send_error(&mut respond, StatusCode::SERVICE_UNAVAILABLE)?;
                return Ok(());
            }
        },
        None => allocate_pool_addresses(&context.shared),
    };
    if addresses.is_empty() {
        warn!(stream_id, "address pool exhausted for HTTP/2 IP tunnel");
        send_error(&mut respond, StatusCode::SERVICE_UNAVAILABLE)?;
        return Ok(());
    }

    let owner = TunnelOwner {
        conn_id: connection_index,
        stream_id,
    };
    let max_ip_packet = context
        .config
        .ip_proxy
        .tun_mtu
        .min(context.config.http2.max_datagram_size);
    // Bound queued TUN data by the H2 stream's configured send-buffer budget,
    // not by a fixed packet count that could become tens of megabytes at a
    // jumbo MTU. One slot is retained even when one packet exceeds the budget.
    let return_queue_capacity = (context.config.http2.max_send_buffer_size / max_ip_packet.max(1))
        .clamp(1, MAX_TUN_QUEUE_PACKETS);
    let (return_sender, mut return_packets) = mpsc::channel(return_queue_capacity);
    context
        .shared
        .http2_tun_routes
        .write()
        .expect("HTTP/2 TUN routes poisoned")
        .insert(
            owner,
            Http2TunRoute {
                sender: return_sender,
                metrics: Arc::clone(&context.metrics),
            },
        );
    {
        let mut routes = context
            .shared
            .routing_table
            .write()
            .expect("routing table poisoned");
        for address in &addresses {
            routes.insert(*address, owner);
            info!(
                stream_id,
                addr = %address,
                pinned = pinned.is_some(),
                transport = "http2",
                "assigned address to IP tunnel"
            );
        }
    }
    let _lease = Http2IpLease {
        shared: Arc::clone(&context.shared),
        owner,
        addresses: addresses.clone(),
    };

    let mut response = Response::builder().status(StatusCode::OK);
    if capsule_mode == IpCapsuleMode::Standard {
        response = response.header(CAPSULE_PROTOCOL, "?1");
    }
    let response = response.body(())?;
    let mut send = respond.send_response(response, false)?;
    send_data(
        &mut send,
        Bytes::from(encode_ip_setup_capsules(&addresses)),
        false,
    )
    .await?;

    info!(
        stream_id,
        transport = "http2",
        capsule_mode = ?capsule_mode,
        "CONNECT-IP tunnel established"
    );
    let _metrics = TunnelMetricsGuard::new(Arc::clone(&context.metrics), 2);
    let activity = Arc::new(Activity::new());
    let idle = wait_until_idle(
        Arc::clone(&activity),
        Duration::from_secs(context.config.server.idle_timeout_secs),
    );
    tokio::pin!(idle);

    let context_bytes = usize::from(capsule_mode == IpCapsuleMode::Standard);
    let mut decoder = CapsuleDecoder::with_max_capsule_size(
        MAX_CONTROL_CAPSULE_SIZE.max(max_ip_packet.saturating_add(context_bytes)),
    );
    let mut tun_send = TunSendBatch::new();
    let mut response_capsules = Vec::with_capacity(RESPONSE_BATCH_SIZE);

    enum Completion {
        ClientClosed,
        Idle,
    }

    // Keep the two directions independent. In particular, waiting for response
    // flow-control credit must not stop us from consuming request DATA frames:
    // Cloudflare-style clients put each inner TCP ACK in a small DATA frame,
    // and h2 deliberately closes a connection when too many unconsumed small
    // frames accumulate. A single select loop whose return-path arm awaited
    // `send_data` could therefore reset an otherwise healthy bulk transfer.
    let client_to_tun = async {
        loop {
            let Some(chunk) = body.data().await else {
                if decoder.buffered() != 0 {
                    anyhow::bail!("request ended with a truncated CONNECT-IP capsule");
                }
                return Ok::<_, anyhow::Error>(());
            };
            let chunk = chunk?;
            let frames = decoder.decode(&chunk)?;
            body.flow_control().release_capacity(chunk.len())?;

            for frame in frames {
                let CapsuleFrame::Datagram(payload) = frame else {
                    // ADDRESS_* and ROUTE_ADVERTISEMENT are valid on this
                    // stream but do not alter the server's local lease or
                    // source-spoofing boundary.
                    continue;
                };
                let Some(packet) = capsule_mode.decode_packet(&payload)? else {
                    continue;
                };
                if packet.len() > max_ip_packet {
                    debug!(
                        stream_id,
                        packet_len = packet.len(),
                        max_ip_packet,
                        "dropping oversized HTTP/2 IP packet"
                    );
                    continue;
                }
                let source = match ip_packet::src_addr(packet) {
                    Ok(source) => source,
                    Err(error) => {
                        debug!(stream_id, %error, "invalid IP header in HTTP/2 client packet");
                        continue;
                    }
                };
                if !addresses.contains(&source) {
                    debug!(stream_id, %source, "spoofed HTTP/2 source address, dropping");
                    continue;
                }

                activity.touch();
                if let Some(tun) = &context.shared.tun {
                    if tun_send.is_full() {
                        tun.send_batch(&mut tun_send).await?;
                    }
                    tun_send.push(packet);
                }
            }
            if let Some(tun) = &context.shared.tun
                && !tun_send.is_empty()
            {
                tun.send_batch(&mut tun_send).await?;
            }
        }
    };

    let tun_to_client = async {
        loop {
            let Some(packet) = return_packets.recv().await else {
                anyhow::bail!("HTTP/2 TUN return path closed");
            };
            response_capsules.clear();
            if packet.len() <= max_ip_packet {
                capsule_mode.encode_packet(&packet, &mut response_capsules);
            }
            while response_capsules.len() < RESPONSE_BATCH_SIZE {
                let packet = match return_packets.try_recv() {
                    Ok(packet) => packet,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        anyhow::bail!("HTTP/2 TUN return path closed");
                    }
                };
                if packet.len() <= max_ip_packet {
                    capsule_mode.encode_packet(&packet, &mut response_capsules);
                }
            }
            if response_capsules.is_empty() {
                continue;
            }
            activity.touch();
            send_data(&mut send, Bytes::copy_from_slice(&response_capsules), false).await?;
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    };

    let relay = {
        tokio::pin!(client_to_tun);
        tokio::pin!(tun_to_client);
        tokio::select! {
            result = &mut client_to_tun => result.map(|()| Completion::ClientClosed),
            result = &mut tun_to_client => result.map(|()| Completion::ClientClosed),
            _ = &mut idle => Ok(Completion::Idle),
        }
    };

    match relay {
        Ok(Completion::ClientClosed) => send_data(&mut send, Bytes::new(), true).await?,
        Ok(Completion::Idle) => send.send_reset(Reason::CANCEL),
        Err(error) => {
            send.send_reset(Reason::PROTOCOL_ERROR);
            return Err(error);
        }
    }
    Ok(())
}

/// Synchronous cleanup makes task cancellation safe: aborting an H2 stream
/// immediately removes its return route and releases every address lease.
struct Http2IpLease {
    shared: Arc<Shared>,
    owner: TunnelOwner,
    addresses: Vec<IpAddr>,
}

impl Drop for Http2IpLease {
    fn drop(&mut self) {
        self.shared
            .http2_tun_routes
            .write()
            .expect("HTTP/2 TUN routes poisoned")
            .remove(&self.owner);
        self.shared
            .routing_table
            .write()
            .expect("routing table poisoned")
            .remove_owned(&self.addresses, &self.owner);
        self.shared
            .address_pool
            .lock()
            .expect("address pool poisoned")
            .release_all(&self.addresses);
        info!(
            stream_id = self.owner.stream_id,
            transport = "http2",
            "CONNECT-IP tunnel closed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::IpCapsuleMode;
    use crate::capsule::CapsuleFrame;
    use crate::capsule::decoder::CapsuleDecoder;

    #[test]
    fn standard_ip_capsule_keeps_context_id_zero() {
        let mut encoded = Vec::new();
        IpCapsuleMode::Standard.encode_packet(b"packet", &mut encoded);

        let frames = CapsuleDecoder::new().decode(&encoded).unwrap();
        assert_eq!(
            frames,
            vec![CapsuleFrame::Datagram(
                [vec![0], b"packet".to_vec()].concat()
            )]
        );
        assert_eq!(
            IpCapsuleMode::Standard.decode_packet(&[0, b'p']).unwrap(),
            Some(&b"p"[..])
        );
    }

    #[test]
    fn cloudflare_ip_capsule_omits_context_id_zero() {
        let mut encoded = Vec::new();
        IpCapsuleMode::Cloudflare.encode_packet(b"packet", &mut encoded);

        let frames = CapsuleDecoder::new().decode(&encoded).unwrap();
        assert_eq!(frames, vec![CapsuleFrame::Datagram(b"packet".to_vec())]);
        assert_eq!(
            IpCapsuleMode::Cloudflare.decode_packet(b"packet").unwrap(),
            Some(&b"packet"[..])
        );
    }

    #[test]
    fn standard_ip_capsule_ignores_unknown_context() {
        assert_eq!(
            IpCapsuleMode::Standard.decode_packet(&[1, 42]).unwrap(),
            None
        );
    }
}
