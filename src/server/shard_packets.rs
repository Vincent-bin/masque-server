//! HTTP/3 packet ingress, connection IDs, and timer scheduling.

use super::*;
use quiche::h3::NameValue as _;

impl Shard {
    /// Mark every connection whose deadline has arrived as needing servicing.
    ///
    /// There is at most one queued deadline per live connection.
    pub(super) fn expire_connection_timers(&mut self, now: Instant) {
        let connections = &mut self.connections;
        let conn_by_index = &self.conn_by_index;
        let dirty = &mut self.dirty;

        self.timers.expire(now, |index, at| {
            let Some(conn_id) = conn_by_index.get(&index) else {
                return;
            };
            let Some(client) = connections.get_mut(conn_id) else {
                return;
            };
            if client.scheduled_deadline != Some(at) {
                return;
            }
            // Cleared so `reschedule` always queues a fresh entry for whatever
            // deadline the connection has after being driven.
            client.scheduled_deadline = None;
            dirty.mark(index);
        });
    }

    /// Queue this connection's next wakeup, if it changed.
    ///
    /// An unchanged deadline already has a live entry in the queue, so leaving
    /// it alone avoids unnecessary heap updates.
    pub(super) fn reschedule(client: &mut ClientConnection, timers: &mut TimerQueue) {
        let deadline = client.next_deadline();
        if client.scheduled_deadline == deadline {
            return;
        }
        client.scheduled_deadline = deadline;
        if let Some(at) = deadline {
            timers.schedule(client.index, at);
        } else {
            timers.cancel(client.index);
        }
    }

    fn derive_connection_id(
        &self,
        destination: &quiche::ConnectionId<'_>,
    ) -> quiche::ConnectionId<'static> {
        let signed = ring::hmac::sign(&self.shared.conn_id_key, destination);
        let mut id = signed.as_ref()[..CONN_ID_LEN].to_vec();
        if let Some(index) = self.reuseport_index {
            id[0] = index;
        }
        quiche::ConnectionId::from_vec(id)
    }

    /// Apply edge-triggered path notifications after a successful receive.
    /// `PeerMigrated` is emitted by quiche only after PATH_RESPONSE validated
    /// the replacement path, so it is the first safe point to move IP-based
    /// resource accounting.
    fn handle_path_events(metrics: &ShardMetrics, client: &mut ClientConnection) -> bool {
        while let Some(event) = client.quic.path_event_next() {
            metrics.record_quic_path_event(&event);
            match event {
                quiche::PathEvent::PeerMigrated(_local, peer) => {
                    if !client.rebind_source_ip(peer.ip()) {
                        metrics.record_quic_migration_source_limit();
                        warn!(
                            connection_index = client.index,
                            "closing migrated connection at source connection limit"
                        );
                        let _ = client.quic.close(
                            true,
                            MIGRATION_SOURCE_LIMIT_ERROR,
                            b"migration source limit",
                        );
                        return false;
                    }
                    info!(connection_index = client.index, "QUIC peer path migrated");
                }
                quiche::PathEvent::FailedValidation(..) => {
                    debug!(
                        connection_index = client.index,
                        "QUIC peer path validation failed"
                    );
                }
                quiche::PathEvent::ReusedSourceConnectionId(..) => {
                    debug!(
                        connection_index = client.index,
                        "peer reused a source connection ID on another path"
                    );
                }
                quiche::PathEvent::PmtuUpdated { pmtu, .. } => {
                    debug!(
                        connection_index = client.index,
                        pmtu, "QUIC path MTU updated"
                    );
                }
                quiche::PathEvent::New(..)
                | quiche::PathEvent::Validated(..)
                | quiche::PathEvent::Closed(..) => {}
                _ => debug!(
                    connection_index = client.index,
                    "unrecognized QUIC path event"
                ),
            }
        }
        true
    }

    /// Remove retired server CIDs and keep one spare available for a client
    /// that wants to migrate without reusing the ID visible on its old path.
    fn sync_connection_ids(
        shared: &Shared,
        shard: usize,
        reuseport_index: Option<u8>,
        aliases: &mut FxHashMap<quiche::ConnectionId<'static>, quiche::ConnectionId<'static>>,
        primary: &quiche::ConnectionId<'static>,
        client: &mut ClientConnection,
    ) {
        let mut retired = Vec::new();
        while let Some(id) = client.quic.retired_scid_next() {
            retired.push(id);
        }
        if !retired.is_empty() {
            let mut routes = shared.cid_shard.write().expect("cid ownership poisoned");
            for id in retired {
                routes.remove(&id);
                aliases.remove(&id);
                client.retire_connection_id(&id);
            }
        }

        if !client.quic.is_established() {
            return;
        }

        while client.quic.scids_left() > 0 {
            let mut random = [0u8; CONN_ID_LEN + 16];
            if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random)
                .is_err()
            {
                warn!(
                    connection_index = client.index,
                    "cannot generate spare QUIC connection ID"
                );
                return;
            }
            if let Some(index) = reuseport_index {
                random[0] = index;
            }
            let id = quiche::ConnectionId::from_vec(random[..CONN_ID_LEN].to_vec());
            let reset_token = u128::from_be_bytes(
                random[CONN_ID_LEN..]
                    .try_into()
                    .expect("reset token has a fixed 16-byte slice"),
            );

            let mut routes = shared.cid_shard.write().expect("cid ownership poisoned");
            if routes.contains_key(&id) {
                continue;
            }
            if let Err(error) = client.quic.new_scid(&id, reset_token, false) {
                debug!(
                    connection_index = client.index,
                    %error,
                    "cannot publish spare QUIC connection ID"
                );
                return;
            }
            routes.insert(id.clone(), shard);
            drop(routes);
            aliases.insert(id.clone(), primary.clone());
            client.publish_connection_id(id);
        }
    }

    fn queue_forward_packet(
        &self,
        shard: usize,
        packet: &[u8],
        from: SocketAddr,
        batches: &mut [PendingForwardBatch],
    ) {
        if let Some(batch) = batches.get_mut(shard) {
            batch.push(packet, from);
        }
    }

    /// Publish at most one channel item per destination shard for this receive
    /// round while preserving the original packet-count queue bound.
    pub(super) fn flush_forward_batches(&self, batches: &mut [PendingForwardBatch]) {
        for (shard, pending) in batches.iter_mut().enumerate() {
            if pending.packets.is_empty() {
                continue;
            }

            let packets = pending.packets.len();
            let bytes = pending.bytes;
            let slots = Arc::clone(&self.shared.forward_slots[shard]);
            let Ok(slots) = slots.try_acquire_many_owned(packets as u32) else {
                pending.packets.clear();
                pending.bytes = 0;
                self.shared.record_shard_queue_drop(shard, packets);
                debug!(shard, packets, "shard forward queue full, dropping batch");
                continue;
            };

            let batch = ForwardedPacketBatch {
                packets: std::mem::take(&mut pending.packets),
                bytes,
                _slots: slots,
            };
            pending.bytes = 0;
            if self.shared.forward_tx[shard].try_send(batch).is_err() {
                self.shared.record_shard_queue_drop(shard, packets);
                debug!(shard, packets, "shard forward inbox full, dropping batch");
                continue;
            }
            self.shared
                .record_cross_shard_forward(shard, packets, bytes);
        }
    }

    fn queue_stateless_packet(
        &self,
        packet: &[u8],
        from: SocketAddr,
        to: SocketAddr,
        batch: &mut SendPacketBatch,
    ) {
        batch.push(
            packet,
            quiche::SendInfo {
                from,
                to,
                at: Instant::now(),
            },
            self.socket.udp_gso_enabled(),
            MAX_DATAGRAM_SIZE,
        );
    }

    /// Process an incoming UDP packet (QUIC).
    pub(super) fn handle_packet(
        &mut self,
        buf: &mut [u8],
        from: SocketAddr,
        local: SocketAddr,
        output: &mut PacketOutput<'_>,
    ) {
        let hdr = match quiche::Header::from_slice(buf, CONN_ID_LEN) {
            Ok(v) => v,
            Err(e) => {
                debug!(%e, "failed to parse QUIC header");
                return;
            }
        };

        // Established packets carry the server-issued CID and take this fast
        // path without hashing. If migration made the packet land on another
        // SO_REUSEPORT shard, the shared ownership map names the right inbox.
        let key = if let Some((conn_id, client)) = self.connections.get_key_value(&hdr.dcid)
            && client.primary_connection_id_active()
        {
            conn_id.clone()
        } else if let Some(conn_id) = self.connection_id_aliases.get(&hdr.dcid) {
            conn_id.clone()
        } else {
            let direct_owner = self
                .shared
                .cid_shard
                .read()
                .expect("cid ownership poisoned")
                .get(&hdr.dcid)
                .copied();
            if let Some(owner) = direct_owner {
                if owner != self.index {
                    self.queue_forward_packet(owner, buf, from, output.forward_batches);
                } else {
                    debug!("connection ownership published without local state or CID alias");
                }
                return;
            }

            if hdr.ty != quiche::Type::Initial {
                debug!("non-initial packet for unknown connection");
                return;
            }

            // A client Initial datagram is required to be at least 1200 bytes.
            // Reject a short spoofed packet before emitting Version
            // Negotiation or Retry, preserving QUIC's amplification bound.
            if buf.len() < quiche::MIN_CLIENT_INITIAL_LEN {
                debug!(bytes = buf.len(), "dropping undersized QUIC Initial");
                return;
            }

            if !quiche::version_is_supported(hdr.version) {
                match quiche::negotiate_version(&hdr.scid, &hdr.dcid, output.stateless) {
                    Ok(written) => self.queue_stateless_packet(
                        &output.stateless[..written],
                        local,
                        from,
                        output.stateless_batch,
                    ),
                    Err(error) => debug!(%error, "failed to build QUIC version negotiation"),
                }
                return;
            }

            // A retransmitted first Initial still carries the client's
            // original destination CID. Find the state created for its first
            // copy before deciding this is a new connection.
            let derived = self.derive_connection_id(&hdr.dcid);
            if self.connections.contains_key(&derived) {
                derived
            } else {
                let derived_owner = self
                    .shared
                    .cid_shard
                    .read()
                    .expect("cid ownership poisoned")
                    .get(&derived)
                    .copied();
                if let Some(owner) = derived_owner {
                    if owner != self.index {
                        self.queue_forward_packet(owner, buf, from, output.forward_batches);
                    } else {
                        debug!("derived connection ownership published without local state");
                    }
                    return;
                }

                let token = hdr.token.as_deref().unwrap_or_default();
                let retry_required = retry::retry_required(
                    self.config.quic.retry_mode,
                    self.connections.len(),
                    self.config.quic.retry_connection_threshold,
                );

                if token.is_empty() && retry_required {
                    let Ok(retry_token) = self.shared.retry_tokens.mint(from, local, &hdr.dcid)
                    else {
                        warn!("cannot seal QUIC Retry token");
                        return;
                    };
                    match quiche::retry(
                        &hdr.scid,
                        &hdr.dcid,
                        &derived,
                        &retry_token,
                        hdr.version,
                        output.stateless,
                    ) {
                        Ok(written) => {
                            self.queue_stateless_packet(
                                &output.stateless[..written],
                                local,
                                from,
                                output.stateless_batch,
                            );
                            *output.stateless_retries += 1;
                        }
                        Err(error) => debug!(%error, "failed to build QUIC Retry"),
                    }
                    return;
                }

                let (scid, odcid) = if token.is_empty()
                    || self.config.quic.retry_mode == crate::config::QuicRetryMode::Off
                {
                    (derived, None)
                } else {
                    let Some(odcid) = self.shared.retry_tokens.validate(from, local, token) else {
                        self.metrics.record_quic_retry_invalid();
                        debug!(%from, "invalid or expired QUIC Retry token");
                        return;
                    };
                    let expected = self.derive_connection_id(&odcid);
                    if expected != hdr.dcid {
                        self.metrics.record_quic_retry_invalid();
                        debug!(%from, "QUIC Retry destination connection ID mismatch");
                        return;
                    }
                    (
                        quiche::ConnectionId::from_vec(hdr.dcid.to_vec()),
                        Some(odcid),
                    )
                };

                // Stateful admission happens only after address validation, so
                // a spoofed flood cannot consume either connection table.
                if self.connections.len() >= self.config.server.max_connections {
                    self.metrics.connection_rejected_limit();
                    warn!("max connections reached, rejecting new connection");
                    return;
                }
                let Some(source_admission) = self.shared.source_admissions.try_acquire(from.ip())
                else {
                    self.metrics.connection_rejected_source_limit();
                    warn!(%from, "source connection limit reached");
                    return;
                };

                let quic =
                    match quiche::accept(&scid, odcid.as_ref(), local, from, &mut self.quic_config)
                    {
                        Ok(connection) => connection,
                        Err(error) => {
                            error!(%error, "failed to accept connection");
                            return;
                        }
                    };

                info!(shard = self.index, ?scid, %from, "new connection");

                let conn_idx = self.shared.next_conn_index.fetch_add(1, Ordering::Relaxed);
                self.conn_by_index.insert(conn_idx, scid.clone());
                // Publish ownership so another shard can hand back a packet
                // that reaches it after this client migrates, and so TUN
                // packets can find this connection.
                self.shared
                    .cid_shard
                    .write()
                    .expect("cid ownership poisoned")
                    .insert(scid.clone(), self.index);
                self.shared
                    .index_shard
                    .write()
                    .expect("index ownership poisoned")
                    .insert(conn_idx, self.index);

                let mut client = ClientConnection::new(
                    quic,
                    conn_idx,
                    Arc::clone(&self.metrics),
                    source_admission,
                    scid.clone(),
                    self.shared.resolver.connection(),
                );
                if self.auth.is_some() {
                    client.first_auth_deadline = Instant::now().checked_add(Duration::from_secs(
                        self.config.server.idle_timeout_secs.max(1),
                    ));
                }
                self.connections.insert(scid.clone(), client);
                scid
            }
        };

        let client = self.connections.get_mut(&key).unwrap();
        let conn_idx = client.index;
        // Anything quiche does with this packet — ACKs, stream data, timer
        // changes — needs a following drive, so the connection is dirty from
        // here regardless of which path below it takes.
        self.dirty.mark(conn_idx);

        // Feed the packet to quiche.
        let recv_info = quiche::RecvInfo { from, to: local };

        if let Err(e) = client.quic.recv(buf, recv_info) {
            debug!(%e, "quiche recv error");
            return;
        }

        if !Self::handle_path_events(&self.metrics, client) {
            return;
        }
        Self::sync_connection_ids(
            &self.shared,
            self.index,
            self.reuseport_index,
            &mut self.connection_id_aliases,
            &key,
            client,
        );

        // Resolve the client's certificate to a roster entry once, at the
        // handshake boundary. The TLS callback has already refused unknown
        // keys, so this is about attaching the identity that later decides
        // which addresses the tunnel gets — and about refusing to serve a
        // connection whose identity we somehow cannot name.
        if let Some(registry) = &self.client_certs
            && client.identity.is_none()
            && client.quic.is_established()
        {
            match client
                .quic
                .peer_cert()
                .map(|der| registry.load().identify(der))
            {
                Some(Ok(identity)) => {
                    self.metrics.record_auth_success();
                    info!(client = %identity.name, %from, "client authenticated by certificate");
                    client.identity = Some(identity);
                }
                other => {
                    self.metrics.record_auth_failure();
                    match other {
                        Some(Err(e)) => warn!(%e, "closing connection with unusable certificate"),
                        // Unreachable while the context sets
                        // FAIL_IF_NO_PEER_CERT, but the cost of being wrong is
                        // an unauthenticated tunnel.
                        None => warn!("closing connection that presented no certificate"),
                        Some(Ok(_)) => unreachable!(),
                    }
                    let _ = client.quic.close(false, 0x0100, b"unauthorized");
                    return;
                }
            }
        }

        // Upgrade only after the full handshake. The TLS context rejects
        // Early Data; the second condition is defense in depth against a
        // future TLS/configuration regression reaching this application gate.
        if client.h3.is_none() && client.quic.is_established() && !client.quic.is_in_early_data() {
            match quiche::h3::Connection::with_transport(&mut client.quic, &self.h3_config) {
                Ok(h3) => {
                    client.h3 = Some(h3);
                    debug!("HTTP/3 connection established");
                }
                Err(e) => {
                    warn!(%e, "failed to create HTTP/3 connection");
                }
            }
        }

        self.poll_http3_events(conn_idx);
    }

    /// Drive buffered HTTP/3 events after packet ingress or a deferred body
    /// read. Capacity and authentication wakeups need the same framing and
    /// lifecycle processing even when the peer sends no additional packet.
    pub(super) fn poll_http3_events(&mut self, conn_idx: u64) {
        let Some(conn_id) = self.conn_by_index.get(&conn_idx) else {
            return;
        };
        let Some(client) = self.connections.get_mut(conn_id) else {
            return;
        };

        if client.quic.local_error().is_some() || client.expire_first_auth() {
            return;
        }

        // Collect pending tunnel setups so we can do async I/O outside
        // the borrow of h3.
        let mut pending_setups = PendingConnectSetups::default();
        let mut closed_ip_streams: Vec<u64> = Vec::new();
        let mut failed_tcp_streams: Vec<u64> = Vec::new();
        let mut closed_capsule_streams: Vec<u64> = Vec::new();
        let mut finished_capsule_streams: Vec<u64> = Vec::new();
        let mut pending_auth: Vec<PendingAuth> = Vec::new();
        let early_udp_budget = client.early_udp_budget();

        // Process HTTP/3 events.
        if let Some(h3) = &mut client.h3 {
            loop {
                match h3.poll(&mut client.quic) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        if client.request_headers_seen.contains(&stream_id) {
                            // Later HEADERS are trailers. Pseudo-headers here
                            // are malformed and must never start another CONNECT.
                            if list.iter().any(|header| header.name().starts_with(b":")) {
                                let code = quiche::h3::WireErrorCode::MessageError as u64;
                                let _ = client.quic.stream_shutdown(
                                    stream_id,
                                    quiche::Shutdown::Read,
                                    code,
                                );
                                let _ = client.quic.stream_shutdown(
                                    stream_id,
                                    quiche::Shutdown::Write,
                                    code,
                                );
                                client
                                    .pending_error_responses
                                    .cancel(&mut client.quic, stream_id);
                                client.awaiting_auth.remove(&stream_id);
                                client.pending_tcp_tunnels.remove(&stream_id);
                                client.tcp_tunnels.remove(&stream_id);
                                client.tcp_read_resumes.remove(&stream_id);
                                client.pending_udp_tunnels.remove(&stream_id);
                                client.udp_tunnels.remove(&stream_id);
                                client.pending_ip_responses.remove(&stream_id);
                                pending_setups.ip.retain(|id| *id != stream_id);
                                closed_capsule_streams.push(stream_id);
                                if client.ip_tunnels.contains_key(&stream_id) {
                                    closed_ip_streams.push(stream_id);
                                }
                            }
                            continue;
                        }
                        if client.pending_error_responses.contains(stream_id) {
                            continue;
                        }
                        // QUIC bounds concurrent streams. Retire completed
                        // entries before enforcing the fixed upper bound.
                        if client.request_headers_seen.len() >= MAX_QUIC_STREAMS_BIDI as usize {
                            client
                                .request_headers_seen
                                .retain(|id| !client.quic.stream_closed(*id));
                            if client.request_headers_seen.len() >= MAX_QUIC_STREAMS_BIDI as usize {
                                let code = quiche::h3::WireErrorCode::ExcessiveLoad as u64;
                                let _ = client.quic.stream_shutdown(
                                    stream_id,
                                    quiche::Shutdown::Read,
                                    code,
                                );
                                let _ = client.quic.stream_shutdown(
                                    stream_id,
                                    quiche::Shutdown::Write,
                                    code,
                                );
                                continue;
                            }
                        }
                        client.request_headers_seen.insert(stream_id);
                        let tcp_setup_count = pending_setups.tcp.len();
                        let udp_setup_count = pending_setups.udp.len();
                        let mut request_context = RequestContext {
                            metrics: &self.metrics,
                            config: &self.config,
                            auth: self.auth.as_deref(),
                            first_auth_deadline: &mut client.first_auth_deadline,
                        };
                        if let Some(pending) = Self::handle_request(
                            h3,
                            &mut client.quic,
                            &mut client.pending_error_responses,
                            stream_id,
                            &list,
                            &mut request_context,
                            &mut pending_setups,
                        ) {
                            if client.awaiting_auth.len() >= MAX_PENDING_AUTH_PER_CONNECTION {
                                warn!(
                                    stream_id,
                                    "too many CONNECT requests awaiting authorization"
                                );
                                Self::send_auth_rejection(
                                    h3,
                                    &mut client.quic,
                                    &mut client.pending_error_responses,
                                    stream_id,
                                );
                            } else {
                                let connect_udp =
                                    matches!(&pending.request, ConnectRequest::Udp { .. });
                                client.awaiting_auth.insert(
                                    stream_id,
                                    AwaitingAuth::new(connect_udp, early_udp_budget.clone()),
                                );
                                pending_auth.push(pending);
                            }
                        }
                        if pending_setups.tcp.len() > tcp_setup_count {
                            debug_assert_eq!(pending_setups.tcp.len(), tcp_setup_count + 1);
                            debug_assert_eq!(pending_setups.tcp.last().unwrap().0, stream_id);
                            client
                                .pending_tcp_tunnels
                                .insert(stream_id, PendingTcpTunnel::staging(stream_id));
                        }
                        if pending_setups.udp.len() > udp_setup_count {
                            debug_assert_eq!(pending_setups.udp.len(), udp_setup_count + 1);
                            let (pending_stream, _, header) =
                                pending_setups.udp.last().expect("one UDP setup added");
                            debug_assert_eq!(*pending_stream, stream_id);
                            client.pending_udp_tunnels.insert(
                                stream_id,
                                PendingUdpTunnel::new(*header, early_udp_budget.clone()),
                            );
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        if !client.pending_tcp_tunnels.contains_key(&stream_id)
                            && !client.tcp_tunnels.contains_key(&stream_id)
                        {
                            client.capsule_readable.insert(stream_id);
                        }
                        // Unread until the CONNECT is authorized, so a caller
                        // that never authenticates buffers nothing here.
                        if client.awaiting_auth.contains_key(&stream_id) {
                            continue;
                        }
                        if Self::relay_tcp_request_body(
                            h3,
                            &mut client.quic,
                            stream_id,
                            &mut client.pending_tcp_tunnels,
                            &mut client.tcp_tunnels,
                        )
                        .is_err()
                        {
                            failed_tcp_streams.push(stream_id);
                        } else if client.quic.stream_readable(stream_id)
                            && (client
                                .tcp_tunnels
                                .get(&stream_id)
                                .is_some_and(|t| t.client_capacity() > 0)
                                || client
                                    .pending_tcp_tunnels
                                    .get(&stream_id)
                                    .is_some_and(|t| t.client_capacity() > 0))
                        {
                            client.tcp_read_resumes.insert(stream_id);
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Finished)) => {
                        client.request_headers_seen.remove(&stream_id);
                        client.tcp_read_resumes.remove(&stream_id);
                        if client.capsule_streams.contains_key(&stream_id) {
                            finished_capsule_streams.push(stream_id);
                            continue;
                        }
                        if let Some(finished) = client.awaiting_auth.get_mut(&stream_id) {
                            finished.client_finished = true;
                            continue;
                        }
                        // Request FIN must not cancel authorization, target
                        // setup, or a flow-control-blocked response. Setup
                        // schedules a body read even if no DATA event remains,
                        // and QUIC retains EOF until that read can run.
                        if client.pending_udp_tunnels.contains_key(&stream_id)
                            || client.pending_ip_responses.contains_key(&stream_id)
                            || pending_setups.ip.contains(&stream_id)
                        {
                            continue;
                        }
                        closed_capsule_streams.push(stream_id);
                        if let Some(tunnel) = client.pending_tcp_tunnels.get_mut(&stream_id) {
                            tunnel.client_finished = true;
                            tunnel.last_activity = Instant::now();
                        }
                        if let Some(tunnel) = client.tcp_tunnels.get_mut(&stream_id) {
                            tunnel.finish_client();
                        }
                        // Stream closed by client — remove tunnel if any.
                        if client.udp_tunnels.remove(&stream_id).is_some() {
                            info!(stream_id, "UDP tunnel closed by client");
                        }
                        if client.ip_tunnels.contains_key(&stream_id) {
                            closed_ip_streams.push(stream_id);
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Reset { .. })) => {
                        client.request_headers_seen.remove(&stream_id);
                        client
                            .pending_error_responses
                            .cancel(&mut client.quic, stream_id);
                        client.tcp_read_resumes.remove(&stream_id);
                        client.pending_ip_responses.remove(&stream_id);
                        closed_capsule_streams.push(stream_id);
                        // A late verification result for this stream is moot.
                        client.awaiting_auth.remove(&stream_id);
                        if client.pending_tcp_tunnels.remove(&stream_id).is_some() {
                            info!(stream_id, "pending TCP tunnel reset by client");
                        }
                        if client.tcp_tunnels.remove(&stream_id).is_some() {
                            info!(stream_id, "TCP tunnel reset by client");
                        }
                        if client.pending_udp_tunnels.remove(&stream_id).is_some() {
                            info!(stream_id, "pending UDP tunnel reset by client");
                        }
                        if client.udp_tunnels.remove(&stream_id).is_some() {
                            info!(stream_id, "UDP tunnel reset by client");
                        }
                        if client.ip_tunnels.contains_key(&stream_id) {
                            closed_ip_streams.push(stream_id);
                        }
                    }
                    Ok((_stream_id, quiche::h3::Event::PriorityUpdate)) => {}
                    Ok((_stream_id, quiche::h3::Event::GoAway)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => {
                        error!(%e, "HTTP/3 error");
                        break;
                    }
                }
            }
        }

        for stream_id in closed_capsule_streams {
            client.remove_capsule_stream(stream_id);
        }
        for stream_id in finished_capsule_streams {
            client.mark_capsule_finished(stream_id);
        }
        for stream_id in failed_tcp_streams {
            warn!(
                stream_id,
                "closing TCP tunnel after request-body backpressure failure"
            );
            Self::reset_tcp_stream(client, stream_id);
        }

        // Clean up closed IP tunnels: release addresses, remove routes.
        for stream_id in closed_ip_streams {
            Self::teardown_ip_tunnel(&self.shared, client, stream_id, conn_idx);
        }

        self.apply_connect_setups(conn_idx, pending_setups);
        self.spawn_auth_verifications(conn_idx, pending_auth);
    }
}
