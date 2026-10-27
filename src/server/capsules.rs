//! Bounded HTTP/3 capsule I/O for CONNECT-UDP and CONNECT-IP.

use std::collections::VecDeque;

use super::{Shard, Shared};
use crate::capsule::datagram::DatagramCapsules;
use crate::connection::ClientConnection;
use crate::{capsule, varint};

const MAX_STREAM_SEND_BYTES: usize = 256 * 1024;
const MAX_CONNECTION_SEND_BYTES: usize = 1024 * 1024;
const MAX_STREAM_SEND_PACKETS: usize = 64;
const MAX_CONNECTION_SEND_PACKETS: usize = 256;
const MAX_RECEIVED_PACKETS: usize = 64;
const MAX_RECEIVED_BYTES: usize = 256 * 1024;
pub(super) const MAX_UDP_PAYLOAD: usize = 65_527;

pub(crate) struct CapsuleStream {
    decoder: DatagramCapsules,
    send: VecDeque<Vec<u8>>,
    offset: usize,
    bytes: usize,
    max_payload: usize,
}

impl CapsuleStream {
    pub(super) fn has_partial_output(&self) -> bool {
        self.offset != 0
    }
    pub(super) fn new(max_payload: usize) -> Self {
        Self {
            decoder: DatagramCapsules::new(max_payload + 8),
            send: VecDeque::new(),
            offset: 0,
            bytes: 0,
            max_payload,
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
        if stream.bytes + data.len() > MAX_STREAM_SEND_BYTES
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
        if self.capsule_send_bytes.saturating_add(payload.len() + 17) > MAX_CONNECTION_SEND_BYTES
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

    pub(super) fn remove_capsule_stream(&mut self, stream_id: u64) {
        if let Some(stream) = self.capsule_streams.remove(&stream_id) {
            self.capsule_send_bytes -= stream.bytes;
            self.capsule_send_packets -= stream.send.len();
        }
        self.capsule_readable.remove(&stream_id);
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
        for index in dirty {
            let Some(id) = self.conn_by_index.get(index) else {
                continue;
            };
            let Some(client) = self.connections.get_mut(id) else {
                continue;
            };
            let readable = std::mem::take(&mut client.capsule_readable);
            for stream_id in readable {
                if client.awaiting_auth.contains_key(&stream_id)
                    || client.pending_udp_tunnels.contains_key(&stream_id)
                {
                    client.capsule_readable.insert(stream_id);
                    continue;
                }
                let Some(stream) = client.capsule_streams.get_mut(&stream_id) else {
                    continue;
                };
                let Some(h3) = client.h3.as_mut() else {
                    continue;
                };
                let mut input = [0; 16 * 1024];
                let mut failed = false;
                loop {
                    let count = match h3.recv_body(&mut client.quic, stream_id, &mut input) {
                        Ok(0) | Err(quiche::h3::Error::Done) => break,
                        Ok(count) => count,
                        Err(_) => {
                            failed = true;
                            break;
                        }
                    };
                    let packets = match stream.decoder.decode(&input[..count]) {
                        Ok(packets) => packets,
                        Err(_) => {
                            failed = true;
                            break;
                        }
                    };
                    for payload in packets {
                        let Ok((context, context_len)) = varint::decode(&payload) else {
                            continue;
                        };
                        if context != 0 {
                            continue;
                        }
                        if payload.len() - context_len > stream.max_payload {
                            failed = true;
                            break;
                        }
                        if client.received_capsules.len() >= MAX_RECEIVED_PACKETS
                            || client.received_capsule_bytes + payload.len() + 8
                                > MAX_RECEIVED_BYTES
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
                    failed |= stream.decoder.is_partial();
                    client.finished_capsules.push(stream_id);
                }
                if failed {
                    Self::close_capsule_stream(&self.shared, client, stream_id, true);
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
            while let Some(stream_id) = client.finished_capsules.pop() {
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
        } else if let Some(h3) = &mut client.h3 {
            let _ = h3.send_body(&mut client.quic, stream_id, &[], true);
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
