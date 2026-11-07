//! Bounded HTTP/3 capsule I/O for CONNECT-UDP and CONNECT-IP.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::{Shard, Shared};
use crate::capsule::CapsuleFrame;
use crate::capsule::datagram::DatagramCapsules;
use crate::capsule::decoder::DecodeError;
use crate::capsule::ip::{AddressRequests, IpCapsules};
use crate::connection::ClientConnection;
use crate::tunnel::udp::EarlyUdpDatagrams;
use crate::{capsule, varint};

const MAX_STREAM_SEND_BYTES: usize = 256 * 1024;
const MAX_CONNECTION_SEND_BYTES: usize = 1024 * 1024;
const MAX_STREAM_SEND_PACKETS: usize = 64;
const MAX_CONNECTION_SEND_PACKETS: usize = 256;
const MAX_RECEIVED_PACKETS: usize = 64;
const MAX_RECEIVED_BYTES: usize = 256 * 1024;
pub(super) const MAX_UDP_PAYLOAD: usize = 65_527;

enum StreamDecoder {
    Datagram(DatagramCapsules),
    Ip(IpCapsules),
}

impl StreamDecoder {
    fn decode(&mut self, data: &[u8]) -> Result<Vec<CapsuleFrame>, DecodeError> {
        match self {
            Self::Datagram(decoder) => {
                let mut frames = Vec::new();
                decoder.decode_with(data, |_, value| {
                    frames.push(CapsuleFrame::Datagram(value));
                    Ok(())
                })?;
                Ok(frames)
            }
            Self::Ip(decoder) => decoder.decode(data),
        }
    }

    fn is_partial(&self) -> bool {
        match self {
            Self::Datagram(decoder) => decoder.is_partial(),
            Self::Ip(decoder) => decoder.is_partial(),
        }
    }
}

pub(crate) struct CapsuleStream {
    decoder: StreamDecoder,
    address_requests: Option<AddressRequests>,
    send: VecDeque<Vec<u8>>,
    offset: usize,
    bytes: usize,
    max_payload: usize,
    finished_at: Option<Instant>,
    // Keep the original shared budget charged until the first body read can
    // distinguish an open request from an unread body followed by FIN.
    early_udp_datagrams: Option<EarlyUdpDatagrams>,
}

impl CapsuleStream {
    pub(super) fn new_udp(max_payload: usize, early_datagrams: EarlyUdpDatagrams) -> Self {
        Self {
            early_udp_datagrams: Some(early_datagrams),
            ..Self::new(max_payload)
        }
    }

    pub(super) fn new_ip(max_payload: usize) -> Self {
        Self {
            decoder: StreamDecoder::Ip(IpCapsules::new(max_payload + 8)),
            address_requests: Some(AddressRequests::default()),
            ..Self::new(max_payload)
        }
    }

    /// None denotes an open request, whose ordinary activity timeout applies.
    pub(super) fn drain_expired(&self, timeout: Duration) -> Option<bool> {
        self.finished_at
            .map(|finished| finished.elapsed() > timeout)
    }

    pub(super) fn has_partial_output(&self) -> bool {
        self.offset != 0
    }
    pub(super) fn new(max_payload: usize) -> Self {
        Self {
            decoder: StreamDecoder::Datagram(DatagramCapsules::new(max_payload + 8)),
            address_requests: None,
            send: VecDeque::new(),
            offset: 0,
            bytes: 0,
            max_payload,
            finished_at: None,
            early_udp_datagrams: None,
        }
    }
}

impl ClientConnection {
    pub(super) fn native_datagrams(&self) -> bool {
        self.h3
            .as_ref()
            .is_some_and(|h3| h3.dgram_enabled_by_peer(&self.quic))
    }

    pub(super) fn queue_capsule_bytes(&mut self, stream_id: u64, data: Vec<u8>) -> bool {
        let Some(stream) = self.capsule_streams.get_mut(&stream_id) else {
            return false;
        };
        // FIN drains only output already staged for this request. Later TUN
        // packets must not keep growing the queue while a control reply drains.
        if stream.finished_at.is_some()
            || stream.bytes + data.len() > MAX_STREAM_SEND_BYTES
            || self.capsule_send_bytes + data.len() > MAX_CONNECTION_SEND_BYTES
            || stream.send.len() >= MAX_STREAM_SEND_PACKETS
            || self.capsule_send_packets >= MAX_CONNECTION_SEND_PACKETS
        {
            return false;
        }
        stream.bytes += data.len();
        self.capsule_send_bytes += data.len();
        self.capsule_send_packets += 1;
        stream.send.push_back(data);
        self.capsule_writable.insert(stream_id);
        true
    }

    pub(super) fn queue_datagram_capsule(&mut self, stream_id: u64, payload: &[u8]) -> bool {
        // Check bounds before allocating the framing buffer.
        let Some(stream) = self.capsule_streams.get(&stream_id) else {
            return false;
        };
        if stream.finished_at.is_some()
            || self.capsule_send_bytes.saturating_add(payload.len() + 17)
                > MAX_CONNECTION_SEND_BYTES
            || stream.bytes.saturating_add(payload.len() + 17) > MAX_STREAM_SEND_BYTES
            || stream.send.len() >= MAX_STREAM_SEND_PACKETS
            || self.capsule_send_packets >= MAX_CONNECTION_SEND_PACKETS
        {
            return false;
        }
        let mut capsule = Vec::with_capacity(payload.len() + 17);
        capsule::encoder::encode_datagram_context_zero(payload, &mut capsule);
        self.queue_capsule_bytes(stream_id, capsule)
    }

    pub(super) fn mark_capsule_finished(&mut self, stream_id: u64) {
        if let Some(stream) = self.capsule_streams.get_mut(&stream_id)
            && stream.finished_at.is_none()
        {
            stream.finished_at = Some(Instant::now());
            self.finished_capsules.push(stream_id);
        }
    }

    fn discard_capsule_output(&mut self, stream_id: u64) {
        if let Some(stream) = self.capsule_streams.get_mut(&stream_id) {
            self.capsule_send_bytes -= stream.bytes;
            self.capsule_send_packets -= stream.send.len();
            stream.send.clear();
            stream.bytes = 0;
            stream.offset = 0;
        }
        self.capsule_writable.remove(&stream_id);
    }

    pub(super) fn remove_capsule_stream(&mut self, stream_id: u64) {
        if let Some(stream) = self.capsule_streams.remove(&stream_id) {
            self.capsule_send_bytes -= stream.bytes;
            self.capsule_send_packets -= stream.send.len();
        }
        self.capsule_readable.remove(&stream_id);
        self.capsule_read_resumes.remove(&stream_id);
        self.capsule_writable.remove(&stream_id);
        self.finished_capsules.retain(|id| *id != stream_id);
    }

    pub(super) fn flush_capsule_output(&mut self) {
        let Some(h3) = self.h3.as_mut() else {
            return;
        };
        self.capsule_writable.retain(|stream_id| {
            let Some(stream) = self.capsule_streams.get_mut(stream_id) else {
                return false;
            };
            while let Some(data) = stream.send.front() {
                match h3.send_body(&mut self.quic, *stream_id, &data[stream.offset..], false) {
                    Ok(0) | Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {
                        return true;
                    }
                    Ok(written) => {
                        stream.offset += written;
                        if stream.offset == data.len() {
                            // Charge the complete allocation until it is
                            // released, including a partially sent prefix.
                            stream.bytes -= data.len();
                            self.capsule_send_bytes -= data.len();
                            self.capsule_send_packets -= 1;
                            stream.send.pop_front();
                            stream.offset = 0;
                        }
                    }
                    Err(_) => {
                        self.capsule_send_bytes -= stream.bytes;
                        self.capsule_send_packets -= stream.send.len();
                        stream.bytes = 0;
                        stream.send.clear();
                        stream.offset = 0;
                        return false;
                    }
                }
            }
            false
        });
    }
}

impl Shard {
    pub(super) fn read_capsule_bodies(&mut self, dirty: &[u64]) {
        const MAX_FRAMING_RETRIES: usize = 32;
        for index in dirty {
            let Some(conn_id) = self.conn_by_index.get(index).cloned() else {
                continue;
            };
            let mut framing_before = crate::fxhash::FxHashMap::default();
            for attempt in 0..MAX_FRAMING_RETRIES {
                self.read_capsule_bodies_once(*index);
                let Some(client) = self.connections.get_mut(&conn_id) else {
                    break;
                };
                if client.quic.local_error().is_some()
                    || client.quic.is_draining()
                    || client.quic.is_closed()
                {
                    client.capsule_read_resumes.clear();
                    break;
                }
                if client.capsule_read_resumes.is_empty() {
                    break;
                }
                for stream in &client.capsule_read_resumes {
                    framing_before
                        .entry(*stream)
                        .or_insert_with(|| client.quic.stream_readable_len(*stream, usize::MAX));
                }
                // recv_body can stop at an empty DATA frame. Polling advances
                // its frame state before another read, even without a packet.
                self.poll_http3_events(*index);
                if attempt + 1 == MAX_FRAMING_RETRIES
                    && let Some(client) = self.connections.get_mut(&conn_id)
                {
                    // Continue on a local wake only when this bounded batch
                    // consumed bytes. A partial frame/gap cannot busy-loop.
                    client.capsule_read_resumes.retain(|stream| {
                        framing_before.get(stream).is_some_and(|before| {
                            client.quic.stream_readable_len(*stream, usize::MAX) < *before
                        })
                    });
                }
            }
        }
    }

    fn read_capsule_bodies_once(&mut self, index: u64) {
        let Some(id) = self.conn_by_index.get(&index) else {
            return;
        };
        let Some(client) = self.connections.get_mut(id) else {
            return;
        };
        let readable = std::mem::take(&mut client.capsule_readable);
        for stream_id in readable {
            client.capsule_read_resumes.remove(&stream_id);
            if client.awaiting_auth.contains_key(&stream_id)
                || client.pending_udp_tunnels.contains_key(&stream_id)
            {
                client.capsule_readable.insert(stream_id);
                continue;
            }
            if !client.capsule_streams.contains_key(&stream_id) {
                continue;
            }
            if client.h3.is_none() {
                continue;
            }
            let mut input = [0; 16 * 1024];
            let mut failed = false;
            loop {
                let count = match client.h3.as_mut().unwrap().recv_body(
                    &mut client.quic,
                    stream_id,
                    &mut input,
                ) {
                    Ok(0) | Err(quiche::h3::Error::Done) => break,
                    Ok(count) => count,
                    Err(_) => {
                        failed = true;
                        break;
                    }
                };
                let stream = client.capsule_streams.get_mut(&stream_id).unwrap();
                let max_payload = stream.max_payload;
                let packets = match stream.decoder.decode(&input[..count]) {
                    Ok(packets) => packets,
                    Err(_) => {
                        failed = true;
                        break;
                    }
                };
                for frame in packets {
                    let payload = match frame {
                        CapsuleFrame::Datagram(payload) => payload,
                        CapsuleFrame::AddressRequest(requests) => {
                            let Some(tunnel) = client.ip_tunnels.get_mut(&stream_id) else {
                                failed = true;
                                break;
                            };
                            let reply = client
                                .capsule_streams
                                .get_mut(&stream_id)
                                .unwrap()
                                .address_requests
                                .as_mut()
                                .unwrap()
                                .respond(&requests, &tunnel.assigned_addrs);
                            let Ok(reply) = reply else {
                                failed = true;
                                break;
                            };
                            tunnel.last_activity = std::time::Instant::now();
                            let mut output = Vec::new();
                            capsule::encoder::encode(&reply, &mut output);
                            if !client.queue_capsule_bytes(stream_id, output) {
                                failed = true;
                                break;
                            }
                            continue;
                        }
                        _ => continue,
                    };
                    let Ok((context, context_len)) = varint::decode(&payload) else {
                        continue;
                    };
                    if context != 0 {
                        continue;
                    }
                    if payload.len() - context_len > max_payload {
                        failed = true;
                        break;
                    }
                    if client.received_capsules.len() >= MAX_RECEIVED_PACKETS
                        || client.received_capsule_bytes + payload.len() + 8 > MAX_RECEIVED_BYTES
                    {
                        self.metrics.record_datagram_queue_drop(1);
                        continue;
                    }
                    let mut wire = Vec::with_capacity(payload.len() + 8);
                    varint::encode_to_vec(stream_id / 4, &mut wire)
                        .expect("request QSID fits varint");
                    wire.extend_from_slice(&payload);
                    client.received_capsule_bytes += wire.len();
                    client.received_capsules.push_back(wire);
                }
                if failed {
                    break;
                }
            }
            if client.quic.stream_finished(stream_id) {
                failed |= client
                    .capsule_streams
                    .get(&stream_id)
                    .unwrap()
                    .decoder
                    .is_partial();
                client.mark_capsule_finished(stream_id);
            }
            if failed {
                Self::close_capsule_stream(&self.shared, client, stream_id, true);
            } else if client.quic.stream_readable(stream_id)
                && !client.quic.stream_finished(stream_id)
                && client.quic.local_error().is_none()
            {
                client.capsule_readable.insert(stream_id);
                client.capsule_read_resumes.insert(stream_id);
            } else {
                // stream_finished() only reports EOF after reading the
                // body. Do not replay native input retained during auth,
                // setup, or blocked response HEADERS before this point.
                // With EOF, discard the ambiguous native queue, but keep
                // the complete pre-FIN capsules staged above for relay.
                let early_datagrams = client
                    .capsule_streams
                    .get_mut(&stream_id)
                    .and_then(|stream| stream.early_udp_datagrams.take());
                if !client.quic.stream_finished(stream_id)
                    && client.quic.local_error().is_none()
                    && !client.quic.is_draining()
                    && !client.quic.is_closed()
                    && let Some(early_datagrams) = early_datagrams
                    && let Some(tunnel) = client.udp_tunnels.get_mut(&stream_id)
                {
                    Self::relay_early_udp_datagrams(tunnel, early_datagrams);
                }
            }
        }
    }

    pub(super) fn finish_capsule_bodies(&mut self, dirty: &[u64]) {
        for index in dirty {
            let Some(id) = self.conn_by_index.get(index) else {
                continue;
            };
            let Some(client) = self.connections.get_mut(id) else {
                continue;
            };
            for stream_id in std::mem::take(&mut client.finished_capsules) {
                // All FIN paths drain complete CONNECT-IP control replies.
                // Reject truncated input before waiting for output credit;
                // the idle sweep bounds the drain from the first FIN.
                if client
                    .capsule_streams
                    .get(&stream_id)
                    .is_some_and(|stream| {
                        matches!(stream.decoder, StreamDecoder::Ip(_))
                            && !stream.decoder.is_partial()
                            && !stream.send.is_empty()
                    })
                {
                    client.finished_capsules.push(stream_id);
                    continue;
                }
                Self::close_capsule_stream(&self.shared, client, stream_id, false);
            }
        }
    }

    pub(super) fn close_capsule_stream(
        shared: &Shared,
        client: &mut ClientConnection,
        stream_id: u64,
        reset: bool,
    ) {
        // FIN may arrive in its own event after the last body read. Validate
        // input here as well so every close path rejects a truncated capsule,
        // regardless of packet timing or whether this is UDP or CONNECT-IP.
        let reset = reset
            || client
                .capsule_streams
                .get(&stream_id)
                .is_some_and(|stream| stream.decoder.is_partial());
        let partial = client
            .capsule_streams
            .get(&stream_id)
            .is_some_and(CapsuleStream::has_partial_output);
        if reset || partial {
            let error = if reset {
                quiche::h3::WireErrorCode::MessageError as u64
            } else {
                quiche::h3::WireErrorCode::RequestCancelled as u64
            };
            let _ = client
                .quic
                .stream_shutdown(stream_id, quiche::Shutdown::Read, error);
            let _ = client
                .quic
                .stream_shutdown(stream_id, quiche::Shutdown::Write, error);
        } else {
            // UDP is lossy: discard whole unsent capsules on FIN, but never
            // send them after a retried FIN. IP control output has already
            // drained before reaching this path.
            if !client.ip_tunnels.contains_key(&stream_id) {
                client.discard_capsule_output(stream_id);
            }
            if let Some(h3) = &mut client.h3
                && matches!(
                    h3.send_body(&mut client.quic, stream_id, &[], true),
                    Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked)
                )
            {
                // Even an empty H3 DATA frame needs flow-control credit for
                // its header. Retain the original deadline and retry FIN when
                // credit returns instead of silently abandoning the response.
                if !client.finished_capsules.contains(&stream_id) {
                    client.finished_capsules.push(stream_id);
                }
                return;
            }
        }
        client.udp_tunnels.remove(&stream_id);
        client.pending_udp_tunnels.remove(&stream_id);
        Self::teardown_ip_tunnel(shared, client, stream_id, client.index);
        client.remove_capsule_stream(stream_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::SourceAdmissionLimiter;
    use crate::metrics::Metrics;
    use crate::tunnel::resolver::ResolverBudget;

    fn client() -> ClientConnection {
        let local = "127.0.0.1:10000".parse().unwrap();
        let peer = "127.0.0.1:10001".parse().unwrap();
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        let id = quiche::ConnectionId::from_vec(vec![0xaa; 16]);
        let quic = quiche::connect(Some("localhost"), &id, local, peer, &mut config).unwrap();
        let metrics = Metrics::new(false)
            .register_listener(local, "http3", "none", 1, false, false)
            .remove(0);
        ClientConnection::new(
            quic,
            0,
            metrics,
            SourceAdmissionLimiter::new(1)
                .try_acquire(peer.ip())
                .unwrap(),
            id,
            ResolverBudget::default().connection(),
        )
    }

    #[test]
    fn deferred_early_native_input_keeps_its_budget_and_clears_resume_state() {
        let mut client = client();
        let budget = crate::tunnel::udp::EarlyUdpBudget::default();
        let mut early = EarlyUdpDatagrams::new(budget.clone());
        assert!(early.push(&vec![0; 64 * 1024]));
        client
            .capsule_streams
            .insert(0, CapsuleStream::new_udp(MAX_UDP_PAYLOAD, early));
        client.capsule_readable.insert(0);
        client.capsule_read_resumes.insert(0);
        let mut other = EarlyUdpDatagrams::new(budget);
        assert!(!other.push(b"budget remains charged after setup"));
        client.remove_capsule_stream(0);
        assert!(other.push(&vec![0; 64 * 1024]));
        assert!(client.capsule_read_resumes.is_empty());
        assert!(client.capsule_readable.is_empty());
    }

    #[test]
    fn capsule_send_bytes_are_bounded_and_returned_when_a_stream_closes() {
        let mut client = client();
        for id in [0, 4, 8, 12] {
            client
                .capsule_streams
                .insert(id, CapsuleStream::new(MAX_UDP_PAYLOAD));
            for _ in 0..32 {
                assert!(client.queue_capsule_bytes(id, vec![0; 8192]));
            }
            assert!(!client.queue_capsule_bytes(id, vec![0]));
        }
        assert_eq!(client.capsule_send_bytes, MAX_CONNECTION_SEND_BYTES);
        client
            .capsule_streams
            .insert(16, CapsuleStream::new(MAX_UDP_PAYLOAD));
        assert!(!client.queue_capsule_bytes(16, vec![0]));
        client.remove_capsule_stream(0);
        assert_eq!(
            client.capsule_send_bytes,
            MAX_CONNECTION_SEND_BYTES - MAX_STREAM_SEND_BYTES
        );
        assert!(client.queue_capsule_bytes(16, vec![0]));
        for id in [4, 8, 12, 16] {
            client.remove_capsule_stream(id);
        }
        assert_eq!(client.capsule_send_bytes, 0);
        assert_eq!(client.capsule_send_packets, 0);
        assert!(client.capsule_writable.is_empty());
    }

    #[test]
    fn capsule_fin_keeps_one_fixed_deadline_and_stops_new_output() {
        let mut client = client();
        client
            .capsule_streams
            .insert(0, CapsuleStream::new_ip(1280));
        assert!(client.queue_capsule_bytes(0, vec![1; 64]));
        client.mark_capsule_finished(0);
        assert_eq!(client.finished_capsules, [0]);
        assert_eq!(
            client.capsule_streams[&0].drain_expired(Duration::from_secs(1)),
            Some(false)
        );
        assert!(!client.queue_capsule_bytes(0, vec![2; 64]));
        assert!(!client.queue_datagram_capsule(0, &[3; 64]));
        assert_eq!(client.capsule_send_bytes, 64);
        assert_eq!(client.capsule_send_packets, 1);

        let expired = Instant::now() - Duration::from_secs(2);
        client.capsule_streams.get_mut(&0).unwrap().finished_at = Some(expired);
        client.mark_capsule_finished(0);
        client.mark_capsule_finished(4); // Unknown streams allocate no state.
        assert_eq!(client.finished_capsules, [0]);
        assert_eq!(client.capsule_streams[&0].finished_at, Some(expired));
        assert_eq!(
            client.capsule_streams[&0].drain_expired(Duration::from_secs(1)),
            Some(true)
        );
        client.discard_capsule_output(0);
        assert_eq!(client.capsule_send_bytes, 0);
        assert_eq!(client.capsule_send_packets, 0);
        assert!(client.capsule_streams[&0].send.is_empty());
        assert_eq!(client.capsule_streams[&0].finished_at, Some(expired));
        assert_eq!(client.finished_capsules, [0]);
        client.remove_capsule_stream(0);
        assert!(client.finished_capsules.is_empty());
        assert!(client.capsule_writable.is_empty());
        assert_eq!(client.capsule_send_bytes, 0);
        assert_eq!(client.capsule_send_packets, 0);
    }

    #[test]
    fn empty_datagrams_cannot_bypass_capsule_queue_packet_limits() {
        let mut client = client();
        for id in [0, 4, 8, 12] {
            client
                .capsule_streams
                .insert(id, CapsuleStream::new(MAX_UDP_PAYLOAD));
            for _ in 0..MAX_STREAM_SEND_PACKETS {
                assert!(client.queue_datagram_capsule(id, &[]));
            }
            assert!(!client.queue_datagram_capsule(id, &[]));
        }
        client
            .capsule_streams
            .insert(16, CapsuleStream::new(MAX_UDP_PAYLOAD));
        assert!(!client.queue_datagram_capsule(16, &[]));
        client.remove_capsule_stream(0);
        assert!(client.queue_datagram_capsule(16, &[]));
    }
}
