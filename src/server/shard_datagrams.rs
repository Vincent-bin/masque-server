//! HTTP/3 shard datagrams operations.

use super::*;

impl Shard {
    /// Relay QUIC DATAGRAMs from clients to target UDP sockets and TUN device.
    ///
    /// A connection only has datagrams to hand over after receiving a packet,
    /// which is exactly what puts it in `dirty`.
    pub(super) async fn relay_client_datagrams(
        &mut self,
        dirty: &[u64],
        dgram_buf: &mut [u8],
        tun_send: &mut TunSendBatch,
    ) {
        // Which tunnels have datagrams waiting to be written, so the flush at
        // the end of each connection does not have to scan all of them.
        let mut staged_udp_tunnels: Vec<u64> = Vec::new();

        for index in dirty {
            let Some(conn_id) = self.conn_by_index.get(index) else {
                continue;
            };
            let Some(client) = self.connections.get_mut(conn_id) else {
                continue;
            };

            staged_udp_tunnels.clear();

            loop {
                // Capsules and native QUIC datagrams share target policy,
                // context handling, source validation, and bounded forwarding.
                let capsule = client.received_capsules.pop_front();
                let wire = if let Some(ref capsule) = capsule {
                    client.received_capsule_bytes -= capsule.len();
                    capsule.as_slice()
                } else {
                    let len = match client.quic.dgram_recv(dgram_buf) {
                        Ok(len) => len,
                        Err(quiche::Error::Done) => break,
                        Err(e) => {
                            debug!(%e, "dgram_recv error");
                            break;
                        }
                    };
                    &dgram_buf[..len]
                };

                let dgram = match datagram::decode_ref(wire) {
                    Ok(d) => d,
                    Err(e) => {
                        debug!(%e, "malformed datagram");
                        if e.is_connection_error() {
                            let _ = client.quic.close(
                                true,
                                datagram::H3_DATAGRAM_ERROR,
                                b"invalid HTTP Datagram quarter stream id",
                            );
                            break;
                        }
                        continue;
                    }
                };

                // Only handle context_id=0 (raw payload)
                if dgram.context_id != 0 {
                    debug!(
                        context_id = dgram.context_id,
                        "ignoring non-zero context_id"
                    );
                    continue;
                }

                // Check UDP tunnels first. Datagrams are staged and written
                // as a batch once the connection's queue is drained, so a
                // client burst costs one syscall rather than one per datagram.
                if let Some(tunnel) = client.udp_tunnels.get_mut(&dgram.stream_id) {
                    if !staged_udp_tunnels.contains(&dgram.stream_id) {
                        staged_udp_tunnels.push(dgram.stream_id);
                    }
                    // A full stage is written straight away so a long burst
                    // does not grow the staging buffer without bound.
                    if tunnel.stage_to_target(dgram.payload)
                        && let Err(e) = tunnel.flush_to_target()
                    {
                        debug!(
                            stream_id = dgram.stream_id,
                            %e,
                            "send to target failed"
                        );
                    }
                    continue;
                }

                // Check IP tunnels — validate source and forward to TUN.
                if let Some(tunnel) = client.ip_tunnels.get_mut(&dgram.stream_id) {
                    // Validate source address.
                    match ip_packet::src_addr(dgram.payload) {
                        Ok(src) => {
                            if !tunnel.owns_address(&src) {
                                debug!(
                                    stream_id = dgram.stream_id,
                                    %src,
                                    "spoofed source address, dropping"
                                );
                                continue;
                            }
                        }
                        Err(e) => {
                            debug!(
                                stream_id = dgram.stream_id,
                                %e,
                                "invalid IP header in client packet"
                            );
                            continue;
                        }
                    }

                    tunnel.last_activity = std::time::Instant::now();

                    // Stage for the TUN device rather than writing each packet
                    // on its own, so the offload path can coalesce them into
                    // one write instead of a syscall per packet.
                    if let Some(tun) = &self.shared.tun {
                        if tun_send.is_full()
                            && let Err(e) = tun.send_batch(tun_send).await
                        {
                            debug!(%e, "TUN batch write failed");
                        }
                        tun_send.push(dgram.payload);
                    }
                    continue;
                }

                match client.buffer_early_udp_datagram(dgram.stream_id, dgram.payload) {
                    EarlyUdpDatagramResult::Buffered => {
                        debug!(
                            stream_id = dgram.stream_id,
                            bytes = dgram.payload.len(),
                            "buffered early UDP datagram"
                        );
                        continue;
                    }
                    EarlyUdpDatagramResult::CapacityExceeded => {
                        debug!(
                            stream_id = dgram.stream_id,
                            bytes = dgram.payload.len(),
                            "early UDP datagram buffer full, dropping packet"
                        );
                        continue;
                    }
                    EarlyUdpDatagramResult::UnknownTunnel => {}
                }

                debug!(stream_id = dgram.stream_id, "datagram for unknown tunnel");
            }

            // The queue is drained, so whatever is still staged is a complete
            // burst and can go out in one syscall per tunnel.
            for stream_id in &staged_udp_tunnels {
                let Some(tunnel) = client.udp_tunnels.get_mut(stream_id) else {
                    continue;
                };
                if !tunnel.has_staged() {
                    continue;
                }
                if let Err(e) = tunnel.flush_to_target() {
                    debug!(stream_id, %e, "send to target failed");
                }
            }
        }
    }

    /// Forward queued target responses and drain the receive queue in a batch.
    pub(super) fn relay_target_datagrams(&mut self, first: UdpResponse) {
        let mut response = Some(first);

        while let Some(batch) = response {
            let mut queue_full = false;
            if let Some(conn_id) = self.conn_by_index.get(&batch.connection_index)
                && let Some(client) = self.connections.get_mut(conn_id)
                && let Some(tunnel) = client.udp_tunnels.get_mut(&batch.stream_id)
            {
                tunnel.last_activity = Instant::now();
                self.dirty.mark(batch.connection_index);

                let datagram_count = batch.datagrams.len();
                for (index, datagram) in batch.datagrams.into_iter().enumerate() {
                    if !client.native_datagrams() {
                        if let Ok(decoded) = datagram::decode_ref(&datagram)
                            && !client.queue_datagram_capsule(batch.stream_id, decoded.payload)
                        {
                            self.metrics.record_datagram_queue_drop(1);
                        }
                        continue;
                    }
                    match client.quic.dgram_send_buf(datagram) {
                        Ok(()) => {}
                        // The send queue is full: stop draining and let the
                        // flush at the end of the loop make room.
                        Err(quiche::Error::Done) => {
                            queue_full = true;
                            self.metrics
                                .record_datagram_queue_drop(datagram_count - index);
                            break;
                        }
                        // Oversized, or datagrams disabled. Dropping this one
                        // says nothing about the next, so keep draining.
                        Err(e) => {
                            debug!(
                                stream_id = batch.stream_id,
                                %e,
                                "dgram_send failed"
                            );
                        }
                    }
                }
            }

            if queue_full {
                break;
            }
            response = self.udp_response_rx.try_recv().ok();
        }
    }

    /// Route one TUN packet. Returns false when the QUIC DATAGRAM queue is full.
    pub(super) fn relay_tun_packet(&mut self, pkt: &[u8]) -> bool {
        // Extract destination IP from the packet header.
        let dst = match ip_packet::dst_addr(pkt) {
            Ok(addr) => addr,
            Err(e) => {
                debug!(%e, "invalid IP header from TUN");
                return true;
            }
        };

        // Look up the tunnel owner in the routing table.
        let owner = {
            let routing_table = self
                .shared
                .routing_table
                .read()
                .expect("routing table poisoned");
            match routing_table.lookup(&dst) {
                Some(owner) => *owner,
                None => return true,
            }
        };

        // Only one shard reads the device, so most packets belong to a
        // connection owned elsewhere and have to be handed over.
        let owner_shard = self
            .shared
            .index_shard
            .read()
            .expect("index ownership poisoned")
            .get(&owner.conn_id)
            .copied();
        if owner_shard.is_none() && self.shared.relay_http2_tun_packet(owner, pkt) {
            return true;
        }
        if let Some(shard) = owner_shard
            && shard != self.index
        {
            if self.shared.tun_tx[shard].try_send(pkt.to_vec()).is_err() {
                self.shared.record_tun_queue_drop(shard);
                debug!(shard, "shard TUN queue full, dropping packet");
            }
            return true;
        }

        let conn_id = match self.conn_by_index.get(&owner.conn_id) {
            Some(conn_id) => conn_id,
            None => {
                debug!(conn_id = owner.conn_id, "TUN packet for unknown connection");
                return true;
            }
        };

        let client = match self.connections.get_mut(conn_id) {
            Some(client) => client,
            None => return true,
        };

        if !client.native_datagrams() {
            if let Some(tunnel) = client.ip_tunnels.get_mut(&owner.stream_id) {
                tunnel.last_activity = Instant::now();
                self.dirty.mark(owner.conn_id);
                if !client.queue_datagram_capsule(owner.stream_id, pkt) {
                    self.metrics.record_datagram_queue_drop(1);
                }
            }
            return true;
        }

        // Update tunnel activity and send DATAGRAM to client.
        if let Some(tunnel) = client.ip_tunnels.get_mut(&owner.stream_id) {
            // Check for backpressure before framing, so a full queue costs no
            // allocation.
            if client.quic.is_dgram_send_queue_full() {
                self.metrics.record_datagram_queue_drop(1);
                return false;
            }

            tunnel.last_activity = Instant::now();
            self.dirty.mark(owner.conn_id);

            match client.quic.dgram_send_buf(tunnel.header.encode(pkt)) {
                Ok(()) => {}
                Err(quiche::Error::Done) => {
                    self.metrics.record_datagram_queue_drop(1);
                    return false;
                }
                // Oversized, or datagrams disabled — dropping this packet says
                // nothing about the next one, so keep draining the device.
                Err(e) => {
                    debug!(
                        stream_id = owner.stream_id,
                        %e,
                        "dgram_send for TUN packet failed"
                    );
                }
            }
        }

        true
    }
}
