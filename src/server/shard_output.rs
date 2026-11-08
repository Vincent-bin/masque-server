//! HTTP/3 shard output operations.

use super::*;

const MAX_READY_BATCH_CONNECTIONS: usize = 8;

impl Shard {
    /// Reject unverified Basic credentials with the same empty 404 as an
    /// unsupported request, including when verification is overloaded.
    pub(super) fn send_auth_rejection(
        h3: &mut quiche::h3::Connection,
        quic: &mut crate::connection::ServerQuic,
        pending_errors: &mut crate::connection::PendingErrorResponses,
        stream_id: u64,
    ) {
        Self::send_error_response(h3, quic, pending_errors, stream_id, 404);
    }

    /// Send an HTTP error response.
    pub(super) fn send_error_response(
        h3: &mut quiche::h3::Connection,
        quic: &mut crate::connection::ServerQuic,
        pending_errors: &mut crate::connection::PendingErrorResponses,
        stream_id: u64,
        status: u16,
    ) {
        pending_errors.send(h3, quic, stream_id, status);
    }

    /// Drive the connections with work pending: handle timers, flush outgoing
    /// packets, and queue each one's next wakeup.
    pub(super) async fn drive_connections(
        &mut self,
        dirty: &[u64],
        out: &mut [u8],
        batch: &mut SendPacketBatch,
    ) {
        let socket = &mut self.socket;
        let connections = &mut self.connections;
        let conn_by_index = &self.conn_by_index;
        let timers = &mut self.timers;
        let metrics = &self.metrics;
        let direct_gso = cfg!(target_os = "linux") && !self.config.quic.discover_pmtu;
        let share_ready = cfg!(target_os = "linux") && dirty.len() > 1;
        batch.clear();

        for (position, index) in dirty.iter().enumerate() {
            // Bound how many other connections can run before an already
            // ready packet leaves, including connections with no output.
            if share_ready
                && position.is_multiple_of(MAX_READY_BATCH_CONNECTIONS)
                && !batch.is_empty()
            {
                Self::flush_ready_batch(socket, batch, metrics).await;
            }
            let Some(conn_id) = conn_by_index.get(index) else {
                continue;
            };
            let Some(client) = connections.get_mut(conn_id) else {
                continue;
            };
            let direct_gso = direct_gso && client.quic.is_established();
            let share_connection = share_ready
                && !client.udp_tunnels.is_empty()
                && client.native_datagrams()
                && client.tcp_tunnels.is_empty()
                && client.pending_tcp_tunnels.is_empty()
                && client.deferred_send.deadline().is_none();
            if !share_connection && !batch.is_empty() {
                Self::flush_ready_batch(socket, batch, metrics).await;
            }

            client.expire_first_auth();
            client.quic.on_timeout();
            if client.quic.local_error().is_some()
                || client.quic.is_draining()
                || client.quic.is_closed()
            {
                client.deferred_send.discard();
                client.pending_error_responses.clear();
            } else if let Some(h3) = client.h3.as_mut() {
                client.pending_error_responses.retry(h3, &mut client.quic);
            }
            client.flush_capsule_output();

            // Build at most one congestion-control send quantum at a time.
            // Linux can collapse equal-sized packets into one GSO aggregate;
            // remaining messages are still emitted by one sendmmsg syscall.
            loop {
                let queued_before = batch.packet_count();
                batch.start_group();
                let max_packet_size = client.quic.max_send_udp_payload_size();
                let send_quantum = client
                    .quic
                    .send_quantum()
                    .max(max_packet_size)
                    .min(MAX_DATAGRAM_SIZE);
                let mut generated_bytes = 0;
                let mut quiche_done = false;
                let mut pacing_blocked = false;

                // `quiche::Connection::send()` serializes and accounts a
                // packet before returning its desired release time. Resume a
                // group retained by the previous loop once its first packet
                // is due. Release up to one timer tick ahead to batch sends.
                if let Some(deadline) = client.deferred_send.deadline() {
                    let now = Instant::now();
                    if deadline > now {
                        break;
                    }
                    let release_horizon = now + crate::connection::PACING_HORIZON;
                    while let Some((packet, send_info)) =
                        client.deferred_send.take_if_due(release_horizon)
                    {
                        generated_bytes += packet.len();
                        batch.push(&packet, send_info, socket.udp_gso_enabled(), send_quantum);
                        client.deferred_send.recycle(packet);
                    }
                    pacing_blocked = client.deferred_send.deadline().is_some();
                }

                while !pacing_blocked
                    && batch.packet_count() + client.deferred_send.len() < MAX_BATCH_PACKETS
                    // A shared batch retains at most one datagram beyond
                    // this byte limit, even with larger configured packets.
                    && (queued_before == 0 || batch.byte_count() < MAX_DATAGRAM_SIZE)
                    && generated_bytes < send_quantum
                    && client.deferred_send.has_capacity(max_packet_size)
                {
                    let tail = if direct_gso
                        && socket.udp_gso_enabled()
                        && client.deferred_send.len() == 0
                    {
                        batch.gso_tail(max_packet_size, send_quantum)
                    } else {
                        None
                    };
                    let mut staged = tail.is_some();
                    let result = if let Some(tail) = tail {
                        client.quic.send(tail)
                    } else {
                        client.quic.send(out)
                    };
                    // A changed path may require more space than the active
                    // path's packet size used to select the batch tail.
                    let result = match result {
                        Err(quiche::Error::BufferTooShort) if staged => {
                            staged = false;
                            client.quic.send(out)
                        }
                        result => result,
                    };
                    let (write, send_info) = match result {
                        Ok(v) => v,
                        Err(quiche::Error::Done) => {
                            quiche_done = true;
                            break;
                        }
                        Err(e) => {
                            error!(%e, "quiche send error");
                            client.quic.close(false, 0x1, b"send error").ok();
                            quiche_done = true;
                            break;
                        }
                    };

                    generated_bytes += write;
                    // Serialize a bounded group ahead of its release time.
                    // Packets within one timer tick can share this send; later
                    // packets remain bounded in the deferred queue.
                    let deferred = send_info.at
                        > Instant::now() + crate::connection::PACING_HORIZON
                        || client.deferred_send.len() != 0;
                    if staged && batch.finish_gso_tail(write, send_info, !deferred, out) {
                        continue;
                    }
                    if deferred {
                        client.deferred_send.schedule(&out[..write], send_info);
                        if !client.deferred_send.can_prefetch() {
                            pacing_blocked = true;
                        }
                        continue;
                    }

                    batch.push(
                        &out[..write],
                        send_info,
                        socket.udp_gso_enabled(),
                        send_quantum,
                    );
                }

                if batch.packet_count() == queued_before {
                    break;
                }

                let deferred = client.deferred_send.deadline().is_some();
                if share_connection
                    && quiche_done
                    && !deferred
                    && batch.packet_count() < MAX_BATCH_PACKETS
                    && batch.byte_count() < MAX_DATAGRAM_SIZE
                {
                    // Only share a completed quantum of already ready packets.
                    // Flush in this round, without waiting for another event.
                    break;
                }
                Self::flush_ready_batch(socket, batch, metrics).await;
                if quiche_done || pacing_blocked || deferred {
                    break;
                }
            }

            // quiche's timer moves on nearly every recv and send, so the
            // connection's next wakeup is only knowable once it is fully
            // driven.
            Self::reschedule(client, timers);
            client.sync_metrics();
        }
        if !batch.is_empty() {
            Self::flush_ready_batch(socket, batch, metrics).await;
        }
    }

    async fn flush_ready_batch(
        socket: &mut QuicUdpSocket,
        batch: &mut SendPacketBatch,
        metrics: &ShardMetrics,
    ) {
        let udp_gso_before_send = socket.udp_gso_enabled();
        match socket.send_batch(batch).await {
            Ok(()) => metrics.record_send_batch(batch.packet_count(), batch.byte_count()),
            Err(error) => warn!(%error, "socket send error"),
        }
        if udp_gso_before_send && !socket.udp_gso_enabled() {
            metrics.disable_udp_gso();
        }
        batch.clear();
    }
}
