//! HTTP/3 shard tunnels operations.

use super::*;

impl Shard {
    /// Apply the tunnel setups a batch of CONNECT requests produced.
    ///
    /// Split out of `handle_packet` because a request whose credentials are
    /// verified off the event loop arrives here later, through
    /// `handle_auth_result`, rather than in the same pass as its headers.
    pub(super) fn apply_connect_setups(&mut self, conn_idx: u64, pending: PendingConnectSetups) {
        if pending.is_empty() {
            return;
        }
        let PendingConnectSetups {
            tcp: pending_tcp_setups,
            udp: pending_udp_setups,
            ip: pending_ip_setups,
        } = pending;
        let Some(conn_id) = self.conn_by_index.get(&conn_idx).cloned() else {
            return;
        };
        let Some(client) = self.connections.get_mut(&conn_id) else {
            return;
        };
        let max_tunnels = self.config.server.max_tunnels_per_connection;

        for (stream_id, target) in pending_tcp_setups {
            if !client.pending_tcp_tunnels.contains_key(&stream_id) {
                continue;
            }
            if client.tunnel_count() > max_tunnels {
                warn!(
                    stream_id,
                    total_tunnels = client.tunnel_count(),
                    "tunnel limit reached, rejecting TCP tunnel"
                );
                if let Some(h3) = &mut client.h3 {
                    Self::send_error_response(
                        h3,
                        &mut client.quic,
                        &mut client.pending_error_responses,
                        stream_id,
                        503,
                    );
                }
                client.pending_tcp_tunnels.remove(&stream_id);
                continue;
            }

            let connect_task = spawn_tcp_connect(
                conn_idx,
                stream_id,
                target,
                self.tcp_policy.clone(),
                Duration::from_secs(self.config.tcp_proxy.connect_timeout_secs),
                self.tcp_event_tx.clone(),
                client.resolver.clone(),
            );
            if let Some(pending) = client.pending_tcp_tunnels.get_mut(&stream_id) {
                pending.start_connect(connect_task);
            }
        }

        // The listener itself cannot receive a larger UDP datagram than this,
        // so matching that effective QUIC limit keeps target responses intact
        // without allowing a bad configuration to allocate unbounded buffers
        // per tunnel.
        let target_datagram_size = self.max_datagram_size.clamp(1, MAX_DATAGRAM_SIZE);
        let enable_target_udp_gso = self.config.udp_proxy.enable_udp_gso;
        for (stream_id, target, _header) in pending_udp_setups {
            if !client.pending_udp_tunnels.contains_key(&stream_id) {
                continue;
            }
            if client.tunnel_count() > max_tunnels {
                warn!(
                    stream_id,
                    total_tunnels = client.tunnel_count(),
                    "tunnel limit reached, rejecting"
                );
                if let Some(h3) = &mut client.h3 {
                    Self::send_error_response(
                        h3,
                        &mut client.quic,
                        &mut client.pending_error_responses,
                        stream_id,
                        503,
                    );
                }
                client.pending_udp_tunnels.remove(&stream_id);
                continue;
            }
            let setup_task = spawn_udp_setup(
                conn_idx,
                stream_id,
                target,
                self.udp_policy.clone(),
                Duration::from_secs(self.config.udp_proxy.connect_timeout_secs),
                enable_target_udp_gso,
                target_datagram_size,
                self.udp_setup_tx.clone(),
                client.resolver.clone(),
            );
            if let Some(pending) = client.pending_udp_tunnels.get_mut(&stream_id) {
                pending.start_setup(setup_task);
            }
        }

        // Handle pending CONNECT-IP tunnel setups: allocate addresses,
        // register routes, send capsules.
        for stream_id in pending_ip_setups {
            if client.tunnel_count() >= max_tunnels {
                warn!(
                    stream_id,
                    total_tunnels = client.tunnel_count(),
                    "tunnel limit reached, rejecting IP tunnel"
                );
                if let Some(h3) = &mut client.h3 {
                    Self::send_error_response(
                        h3,
                        &mut client.quic,
                        &mut client.pending_error_responses,
                        stream_id,
                        503,
                    );
                }
                continue;
            }
            Self::setup_ip_tunnel(
                &self.shared,
                client,
                stream_id,
                conn_idx,
                self.config.ip_proxy.tun_mtu,
            );
        }
    }

    /// Allocate addresses, register routes, send capsules for a new IP tunnel.
    fn setup_ip_tunnel(
        shared: &Shared,
        client: &mut ClientConnection,
        stream_id: u64,
        conn_idx: u64,
        max_payload: usize,
    ) {
        let mut tunnel = IpTunnel::new(stream_id);

        // A client pinned to fixed addresses gets exactly those, and nothing
        // from the pool: its tunnel interface is configured out of band with
        // the same values, so an extra dynamic address would be advertised to a
        // client that has no interface to receive it on.
        let pinned = client
            .identity
            .as_ref()
            .filter(|identity| identity.has_static_addresses());

        let addresses = match pinned {
            Some(identity) => match claim_static_addresses(shared, identity) {
                Ok(addresses) => addresses,
                Err(e) => {
                    warn!(
                        stream_id,
                        client = %identity.name,
                        %e,
                        "cannot attach IP tunnel to this client's fixed addresses"
                    );
                    if let Some(h3) = &mut client.h3 {
                        Self::send_error_response(
                            h3,
                            &mut client.quic,
                            &mut client.pending_error_responses,
                            stream_id,
                            503,
                        );
                    }
                    return;
                }
            },
            None => allocate_pool_addresses(shared),
        };

        if addresses.is_empty() {
            warn!(stream_id, "address pool exhausted for IP tunnel");
            if let Some(h3) = &mut client.h3 {
                Self::send_error_response(
                    h3,
                    &mut client.quic,
                    &mut client.pending_error_responses,
                    stream_id,
                    503,
                );
            }
            return;
        }

        for ip in &addresses {
            tunnel.assigned_addrs.push(*ip);
        }

        // Do not acknowledge the CONNECT until every address has been leased.
        // HTTP/3 permits only one response header block, so a 200 sent before
        // allocation cannot later be corrected to a 503.
        let headers = [
            quiche::h3::Header::new(b":status", b"200"),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        ];
        let Some(h3) = &mut client.h3 else {
            shared
                .address_pool
                .lock()
                .expect("address pool poisoned")
                .release_all(&addresses);
            warn!(
                stream_id,
                "HTTP/3 state disappeared during CONNECT-IP setup"
            );
            return;
        };
        if let Err(e) = h3.send_response(&mut client.quic, stream_id, &headers, false) {
            shared
                .address_pool
                .lock()
                .expect("address pool poisoned")
                .release_all(&addresses);
            if matches!(
                e,
                quiche::h3::Error::StreamBlocked | quiche::h3::Error::Done
            ) {
                client
                    .pending_ip_responses
                    .entry(stream_id)
                    .or_insert_with(Instant::now);
                return;
            }
            warn!(stream_id, %e, "failed to send CONNECT-IP 200");
            return;
        }
        client.pending_ip_responses.remove(&stream_id);

        // A reconnect using the same registered key may briefly overlap its
        // stale predecessor. Inserting replaces the return route atomically;
        // remove_owned() prevents the predecessor's later cleanup from deleting
        // this newer route.
        for ip in &addresses {
            shared
                .routing_table
                .write()
                .expect("routing table poisoned")
                .insert(
                    *ip,
                    TunnelOwner {
                        conn_id: conn_idx,
                        stream_id,
                    },
                );
            info!(stream_id, addr = %ip, pinned = pinned.is_some(), "assigned address to IP tunnel");
        }

        // Control capsules use the same bounded, partial-write-aware queue as
        // fallback data. A small peer receive window must not truncate setup.
        let capsules = encode_ip_setup_capsules(&addresses);
        client
            .capsule_streams
            .insert(stream_id, capsules::CapsuleStream::new_ip(max_payload));
        client.ip_tunnels.insert(stream_id, tunnel);
        // DATA/FIN may already have been polled while authentication or the
        // response headers were pending. Resume from QUIC's bounded storage.
        client.capsule_readable.insert(stream_id);
        if !client.queue_capsule_bytes(stream_id, capsules) {
            Self::teardown_ip_tunnel(shared, client, stream_id, conn_idx);
            let error = quiche::h3::WireErrorCode::ExcessiveLoad as u64;
            let _ = client
                .quic
                .stream_shutdown(stream_id, quiche::Shutdown::Read, error);
            let _ = client
                .quic
                .stream_shutdown(stream_id, quiche::Shutdown::Write, error);
            return;
        }
        info!(stream_id, "CONNECT-IP tunnel established");
    }

    pub(super) fn retry_ip_connect_responses(&mut self, dirty: &[u64]) {
        for index in dirty {
            let Some(conn_id) = self.conn_by_index.get(index) else {
                continue;
            };
            let Some(client) = self.connections.get_mut(conn_id) else {
                continue;
            };
            let streams: Vec<u64> = client.pending_ip_responses.keys().copied().collect();
            for stream_id in streams {
                let started = client
                    .pending_ip_responses
                    .remove(&stream_id)
                    .expect("pending response exists");
                Self::setup_ip_tunnel(
                    &self.shared,
                    client,
                    stream_id,
                    *index,
                    self.config.ip_proxy.tun_mtu,
                );
                if let Some(blocked_at) = client.pending_ip_responses.get_mut(&stream_id) {
                    *blocked_at = started;
                }
            }
        }
    }

    /// Release addresses and remove routes for a closing IP tunnel.
    pub(super) fn teardown_ip_tunnel(
        shared: &Shared,
        client: &mut ClientConnection,
        stream_id: u64,
        conn_idx: u64,
    ) {
        if let Some(tunnel) = client.ip_tunnels.remove(&stream_id) {
            client.remove_capsule_stream(stream_id);
            info!(stream_id, "IP tunnel closed");

            // Release addresses back to the pool.
            shared
                .address_pool
                .lock()
                .expect("address pool poisoned")
                .release_all(&tunnel.assigned_addrs);

            // Remove this tunnel's routes by key — the tunnel knows exactly
            // which addresses it holds, so there is no need to scan the table.
            shared
                .routing_table
                .write()
                .expect("routing table poisoned")
                .remove_owned(
                    &tunnel.assigned_addrs,
                    &TunnelOwner {
                        conn_id: conn_idx,
                        stream_id,
                    },
                );
        }
    }

    /// Drain HTTP/3 request-body data for a standard CONNECT stream and queue
    /// it for the target TCP writer. An error asks the caller to reset; true
    /// means recv_body stopped at framing while QUIC still has buffered bytes.
    pub(super) fn relay_tcp_request_body(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        pending_tunnels: &mut FxHashMap<u64, PendingTcpTunnel>,
        tunnels: &mut FxHashMap<u64, TcpTunnel>,
    ) -> Result<bool, ()> {
        if !pending_tunnels.contains_key(&stream_id) && !tunnels.contains_key(&stream_id) {
            debug!(stream_id, "H3 data event for a non-TCP tunnel");
            return Ok(false);
        }

        let mut body = [0_u8; 16 * 1024];
        loop {
            // A capacity wakeup can drain the final bytes without another
            // packet/H3 poll. Propagate FIN now, after all body bytes, rather
            // than relying on a future Finished event to wake the shard.
            if quic.stream_finished(stream_id) {
                if let Some(tunnel) = tunnels.get_mut(&stream_id) {
                    tunnel.finish_client();
                } else if let Some(tunnel) = pending_tunnels.get_mut(&stream_id) {
                    tunnel.client_finished = true;
                }
                return Ok(false);
            }
            let capacity = if let Some(tunnel) = tunnels.get(&stream_id) {
                tunnel.client_capacity()
            } else {
                pending_tunnels[&stream_id].client_capacity()
            };
            if capacity == 0 {
                // Leave the bytes in QUIC so its receive window applies
                // backpressure. Connect completion or a writer notification
                // explicitly retries this edge-triggered HTTP/3 Data event.
                return Ok(false);
            }
            let read_limit = body.len().min(capacity);
            let len = match h3.recv_body(quic, stream_id, &mut body[..read_limit]) {
                Ok(len) => len,
                Err(quiche::h3::Error::Done) => return Ok(quic.stream_readable(stream_id)),
                Err(error) => {
                    warn!(stream_id, %error, "failed to receive CONNECT body");
                    return Err(());
                }
            };
            if len == 0 {
                continue;
            }

            if let Some(tunnel) = tunnels.get_mut(&stream_id) {
                if !tunnel.queue_client_data(body[..len].to_vec()) {
                    warn!(stream_id, "TCP client-to-target buffer exhausted");
                    return Err(());
                }
                continue;
            }
            if let Some(tunnel) = pending_tunnels.get_mut(&stream_id)
                && !tunnel.buffer_client_data(body[..len].to_vec())
            {
                warn!(stream_id, "pending TCP tunnel buffer exhausted");
                return Err(());
            }
        }
    }

    /// Install a target socket prepared by the asynchronous CONNECT-UDP setup
    /// task, then send the first successful response for the stream.
    pub(super) fn handle_udp_setup_result(&mut self, setup: UdpSetupResult) {
        let UdpSetupResult {
            connection_index,
            stream_id,
            result,
        } = setup;
        let Some(conn_id) = self.conn_by_index.get(&connection_index).cloned() else {
            return;
        };
        let Some(client) = self.connections.get_mut(&conn_id) else {
            return;
        };
        let Some(mut pending) = client.pending_udp_tunnels.remove(&stream_id) else {
            // The stream or connection disappeared while DNS was in flight.
            return;
        };
        self.dirty.mark(connection_index);

        let prepared = match result {
            Ok(prepared) => prepared,
            Err(failure) => {
                warn!(
                    stream_id,
                    status = failure.status,
                    reason = %failure.reason,
                    "UDP tunnel setup failed"
                );
                if let Some(h3) = client.h3.as_mut() {
                    Self::send_error_response(
                        h3,
                        &mut client.quic,
                        &mut client.pending_error_responses,
                        stream_id,
                        failure.status,
                    );
                }
                return;
            }
        };

        let Some(h3) = client.h3.as_mut() else {
            return;
        };
        let headers = [
            quiche::h3::Header::new(b":status", b"200"),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        ];
        if let Err(error) = h3.send_response(&mut client.quic, stream_id, &headers, false) {
            if matches!(
                error,
                quiche::h3::Error::StreamBlocked | quiche::h3::Error::Done
            ) {
                pending.prepared = Some(prepared);
                client.pending_udp_tunnels.insert(stream_id, pending);
                return;
            }
            warn!(stream_id, %error, "failed to send CONNECT-UDP response");
            return;
        }

        let header = pending.header();
        let early_datagrams = pending.take_early_datagrams();
        drop(pending);
        let (send_socket, socket, target_addr, target_udp_gso) = prepared.into_http3();
        let recv_socket = Arc::clone(&socket);
        let response_tx = self.udp_response_tx.clone();
        let capsule_transport = !client.native_datagrams();
        let target_datagram_size = self.max_datagram_size.clamp(1, MAX_DATAGRAM_SIZE);
        let recv_task = tokio::spawn(async move {
            if capsule_transport {
                // Large reliable fallback payloads use one receive buffer and
                // one packet per queued message, keeping memory independent of
                // the native path's Linux batch size.
                let mut buffer = vec![0; capsules::MAX_UDP_PAYLOAD + 1];
                loop {
                    let len = match recv_socket.recv(&mut buffer).await {
                        Ok(len) => len,
                        Err(error) => {
                            report_udp_receive_error(
                                &response_tx,
                                connection_index,
                                stream_id,
                                error,
                            )
                            .await;
                            return;
                        }
                    };
                    if len > capsules::MAX_UDP_PAYLOAD {
                        continue;
                    }
                    if response_tx
                        .send(UdpResponse {
                            connection_index,
                            stream_id,
                            datagrams: Ok(vec![header.encode(&buffer[..len])]),
                        })
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
            // One `recvmmsg` per readiness instead of a `recvfrom` per
            // datagram, and one channel send per batch.
            let mut batch = TargetRecvBatch::new(target_datagram_size);
            loop {
                let received = match recv_target_batch(&recv_socket, &mut batch).await {
                    Ok(received) => received,
                    Err(error) => {
                        report_udp_receive_error(&response_tx, connection_index, stream_id, error)
                            .await;
                        break;
                    }
                };

                let datagrams: Vec<Vec<u8>> = batch
                    .datagrams(received)
                    .map(|payload| header.encode(payload))
                    .collect();
                if datagrams.is_empty() {
                    continue;
                }
                if response_tx
                    .send(UdpResponse {
                        connection_index,
                        stream_id,
                        datagrams: Ok(datagrams),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let tunnel = UdpTunnel::from_socket(
            stream_id,
            target_addr,
            send_socket,
            socket,
            recv_task,
            target_udp_gso,
        );
        info!(
            stream_id,
            target = %target_addr,
            udp_gso = target_udp_gso,
            "UDP tunnel established"
        );
        client.udp_tunnels.insert(stream_id, tunnel);
        client.capsule_streams.insert(
            stream_id,
            capsules::CapsuleStream::new_udp(capsules::MAX_UDP_PAYLOAD, early_datagrams),
        );
        // Also run for HEADERS+FIN: there may be no future Data/Finished event
        // after async authentication/setup or a blocked 200 response.
        client.capsule_readable.insert(stream_id);
    }

    pub(super) fn retry_udp_connect_responses(&mut self, dirty: &[u64]) {
        let mut ready = Vec::new();
        for index in dirty {
            let Some(conn_id) = self.conn_by_index.get(index) else {
                continue;
            };
            let Some(client) = self.connections.get_mut(conn_id) else {
                continue;
            };
            for (stream_id, pending) in &mut client.pending_udp_tunnels {
                if let Some(prepared) = pending.prepared.take() {
                    ready.push(UdpSetupResult {
                        connection_index: *index,
                        stream_id: *stream_id,
                        result: Ok(prepared),
                    });
                }
            }
        }
        for result in ready {
            self.handle_udp_setup_result(result);
        }
    }

    /// Apply an event generated by an asynchronous target TCP task.
    pub(super) fn handle_tcp_event_batch(&mut self, first: TcpRelayEvent) {
        let mut next = Some(first);
        let mut events = 0usize;
        let mut bytes = 0usize;

        while let Some(event) = next {
            bytes = bytes.saturating_add(event.payload_len());
            events += 1;
            self.handle_tcp_event(event);

            if events >= MAX_TCP_RELAY_EVENTS_PER_ROUND || bytes >= MAX_TCP_RELAY_BYTES_PER_ROUND {
                break;
            }
            next = self.tcp_event_rx.try_recv().ok();
        }

        self.metrics.record_tcp_relay_batch(events, bytes);
    }

    /// Apply one event generated by an asynchronous target TCP task.
    fn handle_tcp_event(&mut self, event: TcpRelayEvent) {
        let resume_body = matches!(
            &event,
            TcpRelayEvent::ConnectResult { .. } | TcpRelayEvent::Writable { .. }
        );
        let (connection_index, stream_id) = match &event {
            TcpRelayEvent::ConnectResult {
                connection_index,
                stream_id,
                ..
            }
            | TcpRelayEvent::Data {
                connection_index,
                stream_id,
                ..
            }
            | TcpRelayEvent::Writable {
                connection_index,
                stream_id,
            }
            | TcpRelayEvent::WriteFinished {
                connection_index,
                stream_id,
            }
            | TcpRelayEvent::Eof {
                connection_index,
                stream_id,
            }
            | TcpRelayEvent::Error {
                connection_index,
                stream_id,
                ..
            } => (*connection_index, *stream_id),
        };

        let Some(conn_id) = self.conn_by_index.get(&connection_index).cloned() else {
            return;
        };
        let Some(client) = self.connections.get_mut(&conn_id) else {
            return;
        };
        // Every arm can change stream output, receive credit or completion,
        // so all of them need a following drive and metrics synchronization.
        self.dirty.mark(connection_index);

        match event {
            TcpRelayEvent::ConnectResult { result, .. } => {
                let Some(mut pending) = client.pending_tcp_tunnels.remove(&stream_id) else {
                    return;
                };

                match result {
                    Ok((stream, target_addr)) => {
                        let Some(h3) = client.h3.as_mut() else {
                            return;
                        };
                        let headers = [quiche::h3::Header::new(b":status", b"200")];
                        if let Err(error) =
                            h3.send_response(&mut client.quic, stream_id, &headers, false)
                        {
                            if matches!(
                                error,
                                quiche::h3::Error::StreamBlocked | quiche::h3::Error::Done
                            ) {
                                pending.connected = Some((stream, target_addr));
                                pending.response_blocked_at.get_or_insert_with(Instant::now);
                                client.pending_tcp_tunnels.insert(stream_id, pending);
                                return;
                            }
                            warn!(
                                stream_id,
                                %error,
                                "failed to send standard CONNECT response"
                            );
                            Self::reset_tcp_stream(client, stream_id);
                            return;
                        }

                        let early_data = std::mem::take(&mut pending.early_data);
                        let client_finished = pending.client_finished;
                        drop(pending);

                        let mut tunnel = TcpTunnel::from_stream(
                            connection_index,
                            stream_id,
                            target_addr,
                            stream,
                            self.tcp_event_tx.clone(),
                        );
                        for data in early_data {
                            if !tunnel.queue_client_data(data) {
                                warn!(stream_id, "failed to transfer early CONNECT body");
                                Self::reset_tcp_stream(client, stream_id);
                                return;
                            }
                        }
                        if client_finished {
                            tunnel.finish_client();
                        }
                        client.tcp_tunnels.insert(stream_id, tunnel);
                        info!(
                            stream_id,
                            target = %target_addr,
                            "TCP tunnel established"
                        );
                    }
                    Err(failure) => {
                        warn!(
                            stream_id,
                            status = failure.status,
                            reason = %failure.reason,
                            "TCP tunnel setup failed"
                        );
                        if let Some(h3) = client.h3.as_mut() {
                            Self::send_error_response(
                                h3,
                                &mut client.quic,
                                &mut client.pending_error_responses,
                                stream_id,
                                failure.status,
                            );
                        }
                    }
                }
            }
            TcpRelayEvent::Data { data, .. } => {
                let accepted = client
                    .tcp_tunnels
                    .get_mut(&stream_id)
                    .is_some_and(|tunnel| tunnel.queue_response(data));
                if !accepted && client.tcp_tunnels.contains_key(&stream_id) {
                    warn!(stream_id, "TCP response chunk after the response closed");
                    Self::reset_tcp_stream(client, stream_id);
                }
            }
            TcpRelayEvent::Writable { .. } => {}
            TcpRelayEvent::WriteFinished { .. } => {
                if let Some(tunnel) = client.tcp_tunnels.get_mut(&stream_id) {
                    tunnel.writer_finished = true;
                    tunnel.last_activity = Instant::now();
                }
            }
            TcpRelayEvent::Eof { .. } => {
                if let Some(tunnel) = client.tcp_tunnels.get_mut(&stream_id) {
                    tunnel.upstream_finished = true;
                    tunnel.last_activity = Instant::now();
                }
            }
            TcpRelayEvent::Error { reason, .. } => {
                if client.tcp_tunnels.contains_key(&stream_id) {
                    warn!(stream_id, %reason, "TCP relay failed");
                    Self::reset_tcp_stream(client, stream_id);
                }
            }
        }
        if resume_body {
            self.resume_tcp_request_body(connection_index, stream_id);
        }
    }

    /// Resume the HTTP/3 Data edge after a target-write or setup wakeup.
    /// Empty DATA frames can require poll() to advance framing without issuing
    /// another Data event. Alternate both operations while buffered wire bytes
    /// decrease; never spin on incomplete framing or missing target capacity.
    pub(super) fn resume_tcp_request_body(&mut self, index: u64, stream_id: u64) {
        const MAX_FRAMING_RETRIES: usize = 64;
        let mut framing_before = None;
        for attempt in 0..MAX_FRAMING_RETRIES {
            let Some(conn_id) = self.conn_by_index.get(&index).cloned() else {
                return;
            };
            let Some(client) = self.connections.get_mut(&conn_id) else {
                return;
            };
            client.tcp_read_resumes.remove(&stream_id);
            if client.quic.local_error().is_some() || client.quic.is_draining() {
                return;
            }
            let Some(h3) = client.h3.as_mut() else {
                return;
            };
            let needs_poll = match Self::relay_tcp_request_body(
                h3,
                &mut client.quic,
                stream_id,
                &mut client.pending_tcp_tunnels,
                &mut client.tcp_tunnels,
            ) {
                Ok(needs_poll) => needs_poll,
                Err(()) => {
                    Self::reset_tcp_stream(client, stream_id);
                    return;
                }
            };
            // Scan buffered chunks only once per bounded framing batch,
            // never per empty frame or on ordinary full-queue writer wakes.
            if needs_poll && framing_before.is_none() {
                framing_before = Some(client.quic.stream_readable_len(stream_id, usize::MAX));
            }
            self.poll_http3_events(index);
            if !needs_poll {
                return;
            }
            let Some(client) = self.connections.get_mut(&conn_id) else {
                return;
            };
            client.tcp_read_resumes.remove(&stream_id);
            let capacity = client
                .tcp_tunnels
                .get(&stream_id)
                .map(TcpTunnel::client_capacity)
                .or_else(|| {
                    client
                        .pending_tcp_tunnels
                        .get(&stream_id)
                        .map(PendingTcpTunnel::client_capacity)
                })
                .unwrap_or(0);
            if capacity == 0
                || client.quic.local_error().is_some()
                || !client.quic.stream_readable(stream_id)
            {
                return;
            }
            if attempt + 1 == MAX_FRAMING_RETRIES {
                let after = client.quic.stream_readable_len(stream_id, usize::MAX);
                if framing_before.is_some_and(|before| after < before) {
                    // One set entry per tunnel, serviced through the existing
                    // connection timer. No task or unbounded retry queue is added.
                    client.tcp_read_resumes.insert(stream_id);
                }
            }
        }
    }

    pub(super) fn retry_tcp_request_bodies(&mut self, dirty: &[u64]) {
        for index in dirty {
            let Some(conn_id) = self.conn_by_index.get(index) else {
                continue;
            };
            let Some(client) = self.connections.get_mut(conn_id) else {
                continue;
            };
            let streams = std::mem::take(&mut client.tcp_read_resumes);
            for stream_id in streams {
                self.resume_tcp_request_body(*index, stream_id);
            }
        }
    }

    /// Retry only connections made dirty by incoming packets or timers. A
    /// blocked response does not mark itself dirty, avoiding a busy loop.
    pub(super) fn retry_tcp_connect_responses(&mut self, dirty: &[u64]) {
        let mut ready = Vec::new();
        for index in dirty {
            let Some(conn_id) = self.conn_by_index.get(index) else {
                continue;
            };
            let Some(client) = self.connections.get_mut(conn_id) else {
                continue;
            };
            for (stream_id, pending) in &mut client.pending_tcp_tunnels {
                if let Some(connected) = pending.connected.take() {
                    ready.push(TcpRelayEvent::ConnectResult {
                        connection_index: *index,
                        stream_id: *stream_id,
                        result: Ok(connected),
                    });
                }
            }
        }
        for event in ready {
            self.handle_tcp_event(event);
        }
    }

    /// Move target TCP response bytes into HTTP/3 with partial-write support.
    ///
    /// A blocked stream unblocks only when the peer grants more flow-control
    /// credit, which arrives as a packet and marks the connection dirty again,
    /// so visiting just `dirty` cannot strand a pending response.
    pub(super) fn flush_tcp_responses(&mut self, dirty: &[u64]) {
        for index in dirty {
            let Some(conn_id) = self.conn_by_index.get(index) else {
                continue;
            };
            let Some(client) = self.connections.get_mut(conn_id) else {
                continue;
            };
            if client.tcp_tunnels.is_empty() {
                continue;
            }

            let mut failed = Vec::new();
            let mut completed = Vec::new();

            {
                let Some(h3) = client.h3.as_mut() else {
                    continue;
                };

                for (stream_id, tunnel) in &mut client.tcp_tunnels {
                    // Drain as many queued chunks as HTTP/3 will take. Each
                    // write releases that many bytes of the reader's budget, so
                    // the reader keeps running ahead instead of waiting for a
                    // round trip through this loop.
                    while let Some(response) = tunnel.front_response() {
                        let remaining = &response.data[response.offset..];
                        match h3.send_body(&mut client.quic, *stream_id, remaining, false) {
                            Ok(0) => break,
                            Ok(written) => tunnel.advance_response(written),
                            Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {
                                break;
                            }
                            Err(error) => {
                                warn!(
                                    stream_id,
                                    %error,
                                    "failed to send CONNECT response body"
                                );
                                failed.push(*stream_id);
                                break;
                            }
                        }
                    }

                    if !failed.contains(stream_id)
                        && !tunnel.has_pending_response()
                        && tunnel.upstream_finished
                        && !tunnel.response_finished
                    {
                        match h3.send_body(&mut client.quic, *stream_id, b"", true) {
                            Ok(_) => tunnel.response_finished = true,
                            Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {}
                            Err(error) => {
                                warn!(
                                    stream_id,
                                    %error,
                                    "failed to finish CONNECT response body"
                                );
                                failed.push(*stream_id);
                            }
                        }
                    }

                    if tunnel.is_complete() {
                        completed.push(*stream_id);
                    }
                }
            }

            failed.sort_unstable();
            failed.dedup();
            for stream_id in failed {
                Self::reset_tcp_stream(client, stream_id);
            }
            for stream_id in completed {
                if client.tcp_tunnels.remove(&stream_id).is_some() {
                    info!(stream_id, "TCP tunnel closed cleanly");
                }
            }
        }
    }

    pub(super) fn reset_tcp_stream(client: &mut ClientConnection, stream_id: u64) {
        client.pending_tcp_tunnels.remove(&stream_id);
        client.tcp_tunnels.remove(&stream_id);
        client.tcp_read_resumes.remove(&stream_id);
        let error = quiche::h3::WireErrorCode::ConnectError as u64;
        client
            .quic
            .stream_shutdown(stream_id, quiche::Shutdown::Read, error)
            .ok();
        client
            .quic
            .stream_shutdown(stream_id, quiche::Shutdown::Write, error)
            .ok();
    }
}

/// A failed receiver must wake its owning shard even if the response queue is
/// full. Awaiting this existing bounded channel adds no retry queue, and tunnel
/// teardown aborts this wait with the rest of the receive task.
async fn report_udp_receive_error(
    response_tx: &mpsc::Sender<UdpResponse>,
    connection_index: u64,
    stream_id: u64,
    error: std::io::Error,
) {
    let _ = response_tx
        .send(UdpResponse {
            connection_index,
            stream_id,
            datagrams: Err(error),
        })
        .await;
}

#[cfg(test)]
mod udp_receive_tests {
    use super::*;

    fn response() -> UdpResponse {
        UdpResponse {
            connection_index: 7,
            stream_id: 4,
            datagrams: Ok(vec![vec![0]]),
        }
    }

    #[tokio::test]
    async fn udp_receive_failure_waits_for_full_queue_instead_of_losing_close() {
        let (tx, mut rx) = mpsc::channel(1);
        tx.send(response()).await.unwrap();
        let task = tokio::spawn(async move {
            report_udp_receive_error(&tx, 7, 4, std::io::ErrorKind::ConnectionRefused.into()).await;
        });
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        assert!(rx.recv().await.unwrap().datagrams.is_ok());
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        let failed = rx.recv().await.unwrap();
        assert_eq!(failed.connection_index, 7);
        assert_eq!(failed.stream_id, 4);
        assert_eq!(
            failed.datagrams.unwrap_err().kind(),
            std::io::ErrorKind::ConnectionRefused
        );
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn udp_receive_failure_wait_is_cancelled_when_tunnel_is_dropped() {
        let (tx, mut rx) = mpsc::channel(1);
        tx.send(response()).await.unwrap();
        let task = tokio::spawn(async move {
            report_udp_receive_error(&tx, 7, 4, std::io::ErrorKind::ConnectionRefused.into()).await;
        });
        let abort = task.abort_handle();
        let mut tunnel = UdpTunnel::new(4, "127.0.0.1:9".parse().unwrap())
            .await
            .unwrap();
        tunnel.recv_task = Some(task);
        tokio::task::yield_now().await;
        assert!(!abort.is_finished());
        drop(tunnel);
        tokio::task::yield_now().await;
        assert!(abort.is_finished());
        assert!(rx.recv().await.unwrap().datagrams.is_ok());
        assert!(rx.recv().await.is_none());
    }
}
