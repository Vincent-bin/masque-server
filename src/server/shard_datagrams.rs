//! HTTP/3 shard datagrams operations.

use super::*;

impl Shard {
    /// Replay bounded setup-time native input only after the initial request
    /// body has been read and validated, and only if that request is still open.
    pub(super) fn relay_early_udp_datagrams(
        tunnel: &mut UdpTunnel,
        early_datagrams: crate::tunnel::udp::EarlyUdpDatagrams,
    ) {
        let count = early_datagrams.len();
        let bytes = early_datagrams.bytes();
        for payload in early_datagrams.into_payloads() {
            if tunnel.stage_to_target(&payload)
                && let Err(error) = tunnel.flush_to_target()
            {
                debug!(stream_id = tunnel.stream_id, %error, "failed to flush early UDP datagrams");
            }
        }
        if tunnel.has_staged()
            && let Err(error) = tunnel.flush_to_target()
        {
            debug!(stream_id = tunnel.stream_id, %error, "failed to flush early UDP datagrams");
        }
        if count > 0 {
            debug!(
                stream_id = tunnel.stream_id,
                datagrams = count,
                bytes,
                "relayed buffered early UDP datagrams"
            );
        }
    }

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

            if client.quic.local_error().is_some()
                || client.quic.is_draining()
                || client.quic.is_closed()
            {
                continue;
            }

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

                // RFC 9297 section 2.1: native datagrams received after the
                // request's receive side closes are silently discarded. QUIC
                // retains EOF even while auth/setup or response FIN is pending.
                // Capsules already parsed before FIN still need forwarding.
                if capsule.is_none()
                    && (client.quic.stream_finished(dgram.stream_id)
                        || (client.capsule_streams.contains_key(&dgram.stream_id)
                            && client.quic.stream_readable(dgram.stream_id)))
                {
                    // An active stream can still be draining buffered H3
                    // framing before EOF becomes observable. Native input is
                    // lossy: do not forward it ahead of that receive-state check.
                    continue;
                }

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

                // Check IP tunnels — validate source and destination before TUN.
                if let Some(tunnel) = client.ip_tunnels.get_mut(&dgram.stream_id) {
                    // Validate source address.
                    match ip_packet::parse(dgram.payload) {
                        Ok(header) => {
                            if !tunnel.owns_address(&header.src) {
                                debug!(
                                    stream_id = dgram.stream_id,
                                    source = %header.src,
                                    "spoofed source address, dropping"
                                );
                                continue;
                            }
                            if !self.shared.ip_policy.is_allowed(header.dst)
                                || !ip_packet::has_safe_routing(dgram.payload)
                            {
                                debug!(
                                    stream_id = dgram.stream_id,
                                    "CONNECT-IP destination policy denied packet"
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

    /// Forward a bounded batch of target responses before servicing other events.
    pub(super) fn relay_target_datagrams(&mut self, first: UdpResponse) {
        let mut first = Some(first);

        for _ in 0..MAX_UDP_RESPONSES_PER_ROUND {
            let Some(batch) = first
                .take()
                .or_else(|| self.udp_response_rx.try_recv().ok())
            else {
                break;
            };
            let mut queue_full = false;
            if let Some(conn_id) = self.conn_by_index.get(&batch.connection_index)
                && let Some(client) = self.connections.get_mut(conn_id)
                && let Some(tunnel) = client.udp_tunnels.get_mut(&batch.stream_id)
            {
                self.dirty.mark(batch.connection_index);
                let datagrams = match batch.datagrams {
                    Ok(datagrams) => datagrams,
                    Err(error) => {
                        debug!(stream_id = batch.stream_id, %error, "target recv failed");
                        Self::reset_udp_stream(client, batch.stream_id);
                        continue;
                    }
                };
                tunnel.last_activity = Instant::now();

                let datagram_count = datagrams.len();
                for (index, datagram) in datagrams.into_iter().enumerate() {
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
        }
    }

    /// A dead target receiver cannot leave a send-only CONNECT-UDP tunnel.
    /// Reset this stream (not its connection) so the client can reconnect;
    /// removing capsule state releases queued output and its shared budget.
    pub(super) fn reset_udp_stream(client: &mut ClientConnection, stream_id: u64) {
        client.udp_tunnels.remove(&stream_id);
        client.remove_capsule_stream(stream_id);
        let error = quiche::h3::WireErrorCode::ConnectError as u64;
        let _ = client
            .quic
            .stream_shutdown(stream_id, quiche::Shutdown::Read, error);
        let _ = client
            .quic
            .stream_shutdown(stream_id, quiche::Shutdown::Write, error);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_receive_failure_releases_tunnel_and_capsule_resources() {
        let local = "127.0.0.1:10000".parse().unwrap();
        let peer = "127.0.0.1:10001".parse().unwrap();
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        let id = quiche::ConnectionId::from_vec(vec![0xaa; 16]);
        let quic = quiche::connect(Some("localhost"), &id, local, peer, &mut config).unwrap();
        let metrics = Metrics::new(false)
            .register_listener(local, "http3", "none", 1, false, false)
            .remove(0);
        let mut client = ClientConnection::new(
            quic,
            0,
            metrics,
            SourceAdmissionLimiter::new(1)
                .try_acquire(peer.ip())
                .unwrap(),
            id,
            ResolverBudget::default().connection(),
        );
        let mut tunnel = UdpTunnel::new(0, peer).await.unwrap();
        let socket = Arc::downgrade(&tunnel.socket);
        let task = tokio::spawn(std::future::pending());
        let abort = task.abort_handle();
        tunnel.recv_task = Some(task);
        client.udp_tunnels.insert(0, tunnel);
        client
            .udp_tunnels
            .insert(4, UdpTunnel::new(4, peer).await.unwrap());
        for stream in [0, 4] {
            client.capsule_streams.insert(
                stream,
                capsules::CapsuleStream::new(capsules::MAX_UDP_PAYLOAD),
            );
            client.capsule_readable.insert(stream);
            client.finished_capsules.push(stream);
            assert!(client.queue_capsule_bytes(stream, vec![0; 1024]));
        }
        Shard::reset_udp_stream(&mut client, 0);
        tokio::task::yield_now().await;
        assert!(abort.is_finished());
        assert!(socket.upgrade().is_none());
        assert!(!client.udp_tunnels.contains_key(&0));
        assert!(!client.capsule_streams.contains_key(&0));
        assert!(!client.capsule_readable.contains(&0));
        assert!(!client.capsule_writable.contains(&0));
        assert_eq!(client.finished_capsules, [4]);
        assert_eq!(client.capsule_send_bytes, 1024);
        assert_eq!(client.capsule_send_packets, 1);
        assert!(client.udp_tunnels.contains_key(&4));
        assert!(client.capsule_streams.contains_key(&4));
        assert!(!client.quic.is_closed());
    }
}
