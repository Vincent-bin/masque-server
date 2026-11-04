//! HTTP/3 shard lifecycle operations.

use super::*;

impl Shard {
    /// Close tunnels that have been idle too long.
    /// Disconnect connections whose roster entry was removed or changed.
    ///
    /// A revoked client keeping its tunnel until it happens to reconnect would
    /// make revocation meaningless, so the connection is closed rather than
    /// merely barred from opening new streams. An entry that was edited counts
    /// as revoked too: its pinned addresses were decided at setup time, so the
    /// client has to come back to pick up the new ones.
    pub(super) fn enforce_roster(&mut self) {
        let Some(roster) = self.client_certs.as_ref() else {
            return;
        };
        let current = roster.load();

        let mut revoked: Vec<quiche::ConnectionId<'static>> = Vec::new();
        for (conn_id, client) in &self.connections {
            let Some(identity) = client.identity.as_deref() else {
                continue;
            };
            if !current.still_authorizes(identity) {
                info!(client = %identity.name, "disconnecting client removed from the roster");
                revoked.push(conn_id.clone());
            }
        }

        for conn_id in revoked {
            if let Some(client) = self.connections.get_mut(&conn_id) {
                // A local close; the teardown that frees addresses and routes
                // runs from the normal closed-connection path.
                let _ = client.quic.close(true, 0x0100, b"revoked");
                self.dirty.mark(client.index);
            }
        }
    }

    pub(super) fn cleanup_idle_tunnels(&mut self, timeout: Duration) {
        // Collect idle IP tunnel info so we can clean up after the loop.
        let mut idle_ip_tunnels: Vec<(quiche::ConnectionId<'static>, u64, u64)> = Vec::new();
        let dirty = &mut self.dirty;

        for (conn_id, client) in &mut self.connections {
            let expired_ip: Vec<u64> = client
                .pending_ip_responses
                .iter()
                .filter_map(|(stream, started)| (started.elapsed() > timeout).then_some(*stream))
                .collect();
            for stream in expired_ip {
                client.pending_ip_responses.remove(&stream);
                let code = quiche::h3::WireErrorCode::RequestCancelled as u64;
                let _ = client
                    .quic
                    .stream_shutdown(stream, quiche::Shutdown::Read, code);
                let _ = client
                    .quic
                    .stream_shutdown(stream, quiche::Shutdown::Write, code);
                dirty.mark(client.index);
            }
            // Borrow the fields separately so the tunnel maps can be walked
            // while still writing to the same connection's H3 stream.
            let ClientConnection {
                quic,
                h3,
                pending_tcp_tunnels,
                tcp_tunnels,
                pending_udp_tunnels,
                udp_tunnels,
                ip_tunnels,
                capsule_streams,
                index,
                ..
            } = client;

            // Closing a tunnel writes a response or a FIN to the connection,
            // so it has to be driven afterwards to put those on the wire.
            let mut wrote = false;

            // Pending connects are bounded by their connect timeout, but the
            // idle sweep is also a final guard if a resolver stalls.
            pending_tcp_tunnels.retain(|stream_id, tunnel| {
                if !tunnel.is_idle(timeout) {
                    return true;
                }
                info!(stream_id, "closing idle pending TCP tunnel");
                if tunnel.connected.is_some() {
                    let error = quiche::h3::WireErrorCode::RequestCancelled as u64;
                    let _ = quic.stream_shutdown(*stream_id, quiche::Shutdown::Read, error);
                    let _ = quic.stream_shutdown(*stream_id, quiche::Shutdown::Write, error);
                    wrote = true;
                    return false;
                }
                if let Some(h3) = h3.as_mut() {
                    Self::send_error_response(h3, quic, *stream_id, 504);
                    wrote = true;
                }
                false
            });

            pending_udp_tunnels.retain(|stream_id, tunnel| {
                if !tunnel.is_idle(timeout) {
                    return true;
                }
                info!(stream_id, "closing idle pending UDP tunnel");
                if tunnel.prepared.is_some() {
                    let error = quiche::h3::WireErrorCode::RequestCancelled as u64;
                    let _ = quic.stream_shutdown(*stream_id, quiche::Shutdown::Read, error);
                    let _ = quic.stream_shutdown(*stream_id, quiche::Shutdown::Write, error);
                    wrote = true;
                    return false;
                }
                if let Some(h3) = h3.as_mut() {
                    Self::send_error_response(h3, quic, *stream_id, 504);
                    wrote = true;
                }
                false
            });

            tcp_tunnels.retain(|stream_id, tunnel| {
                if !tunnel.is_idle(timeout) {
                    return true;
                }
                info!(stream_id, "closing idle TCP tunnel");
                if let Some(h3) = h3.as_mut() {
                    h3.send_body(quic, *stream_id, b"", true).ok();
                    wrote = true;
                }
                false
            });

            // UDP tunnels: dropping the tunnel aborts its receive task.
            udp_tunnels.retain(|stream_id, tunnel| {
                if !tunnel.is_idle(timeout) {
                    return true;
                }
                info!(stream_id, "closing idle UDP tunnel");
                if capsule_streams
                    .get(stream_id)
                    .is_some_and(capsules::CapsuleStream::has_partial_output)
                {
                    let _ = quic.stream_shutdown(
                        *stream_id,
                        quiche::Shutdown::Write,
                        quiche::h3::WireErrorCode::RequestCancelled as u64,
                    );
                    wrote = true;
                } else if let Some(h3) = h3.as_mut() {
                    h3.send_body(quic, *stream_id, b"", true).ok();
                    wrote = true;
                }
                false
            });

            // IP tunnels also need pool and route cleanup, which needs
            // `&mut self`, so only signal the close here and tear down below.
            for (stream_id, tunnel) in ip_tunnels.iter() {
                if !tunnel.is_idle(timeout) {
                    continue;
                }
                info!(stream_id, "closing idle IP tunnel");
                if capsule_streams
                    .get(stream_id)
                    .is_some_and(capsules::CapsuleStream::has_partial_output)
                {
                    let _ = quic.stream_shutdown(
                        *stream_id,
                        quiche::Shutdown::Write,
                        quiche::h3::WireErrorCode::RequestCancelled as u64,
                    );
                    wrote = true;
                } else if let Some(h3) = h3.as_mut() {
                    h3.send_body(quic, *stream_id, b"", true).ok();
                    wrote = true;
                }
                idle_ip_tunnels.push((conn_id.clone(), *stream_id, *index));
            }

            if wrote {
                dirty.mark(*index);
            }
            let closed: Vec<_> = client
                .capsule_streams
                .keys()
                .copied()
                .filter(|id| {
                    !client.udp_tunnels.contains_key(id) && !client.ip_tunnels.contains_key(id)
                })
                .collect();
            for stream_id in closed {
                client.remove_capsule_stream(stream_id);
            }
        }

        // Now tear down idle IP tunnels (needs &mut self fields).
        for (conn_id, stream_id, conn_idx) in idle_ip_tunnels {
            if let Some(client) = self.connections.get_mut(&conn_id) {
                Self::teardown_ip_tunnel(&self.shared, client, stream_id, conn_idx);
            }
        }
    }
}
