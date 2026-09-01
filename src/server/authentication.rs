//! Bounded asynchronous credential verification and request resumption.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use tracing::{info, warn};

use crate::connection::AwaitingAuth;
use crate::tunnel::tcp::PendingTcpTunnel;

use super::Shard;
use super::request::{ConnectRequest, PendingAuth, PendingConnectSetups, RequestContext};

/// The result of verifying one request's credentials, sent back to the shard
/// that parsed it.
pub(super) struct AuthOutcome {
    connection_index: u64,
    stream_id: u64,
    request: ConnectRequest,
    authorized: bool,
}

impl Shard {
    /// Verify prechecked credentials off the event loop.
    ///
    /// Argon2id costs tens of milliseconds; running it inline would stall
    /// every connection owned by this shard.
    pub(super) fn spawn_auth_verifications(&mut self, conn_idx: u64, pending: Vec<PendingAuth>) {
        if pending.is_empty() {
            return;
        }
        if self.auth.is_none() {
            return;
        }
        let Some(conn_id) = self.conn_by_index.get(&conn_idx).cloned() else {
            return;
        };
        let Some(source_ip) = self
            .connections
            .get(&conn_id)
            .map(|client| client.source_ip())
        else {
            return;
        };

        for request in pending {
            let stream_id = request.stream_id;
            let Some(cancelled) = self
                .connections
                .get(&conn_id)
                .and_then(|client| client.awaiting_auth.get(&stream_id))
                .map(AwaitingAuth::cancellation_flag)
            else {
                // The stream was reset later in the same H3 poll batch.
                continue;
            };

            let source_slot = match self.shared.auth_source_admissions.try_acquire(source_ip) {
                Some(slot) => slot,
                None => {
                    self.metrics.record_auth_overloaded();
                    warn!(stream_id, %source_ip, "source credential verification limit reached");
                    if let Some(client) = self.connections.get_mut(&conn_id) {
                        client.awaiting_auth.remove(&stream_id);
                        if let Some(h3) = &mut client.h3 {
                            Self::send_auth_rejection(
                                h3,
                                &mut client.quic,
                                stream_id,
                                self.stealth_auth,
                                503,
                            );
                        }
                    }
                    continue;
                }
            };
            let queue_slot = match Arc::clone(&self.shared.auth_queue_slots).try_acquire_owned() {
                Ok(slot) => slot,
                Err(_) => {
                    self.metrics.record_auth_overloaded();
                    warn!(stream_id, "credential verification queue is full");
                    if let Some(client) = self.connections.get_mut(&conn_id) {
                        client.awaiting_auth.remove(&stream_id);
                        if let Some(h3) = &mut client.h3 {
                            Self::send_auth_rejection(
                                h3,
                                &mut client.quic,
                                stream_id,
                                self.stealth_auth,
                                503,
                            );
                        }
                    }
                    continue;
                }
            };
            let pending_gauge = self.metrics.auth_pending_guard();

            let auth_tx = self.auth_tx.clone();
            let permits = Arc::clone(&self.shared.auth_permits);
            let metrics = Arc::clone(&self.metrics);
            let PendingAuth {
                stream_id,
                credential,
                password,
                request,
            } = request;

            let task = tokio::spawn(async move {
                let _pending_gauge = pending_gauge;
                // Admission above bounds waiting tasks; this second permit
                // bounds the Argon2 CPU and memory actually running at once.
                let Ok(permit) = permits.acquire_owned().await else {
                    return;
                };
                let running_gauge = metrics.auth_running_guard();

                let verified = tokio::task::spawn_blocking(move || {
                    let _source_slot = source_slot;
                    let _queue_slot = queue_slot;
                    let _running_gauge = running_gauge;
                    // Aborting an async task cannot stop spawn_blocking after
                    // it begins. This check prevents queued blocking work from
                    // starting Argon2 after its stream has disappeared.
                    if cancelled.load(Ordering::Acquire) {
                        drop(permit);
                        return None;
                    }
                    let authorized = credential.verify(&password);
                    drop(permit);
                    Some(authorized)
                })
                .await;

                let authorized = match verified {
                    Ok(Some(authorized)) => authorized,
                    Ok(None) => return,
                    Err(_) => false,
                };
                // Count completed verification even when the stream or
                // connection disappeared while Argon2 was running. Otherwise
                // disconnecting after each bad password would hide abusive
                // work from the authentication metrics.
                if authorized {
                    metrics.record_auth_success();
                } else {
                    metrics.record_auth_failure();
                }
                let _ = auth_tx
                    .send(AuthOutcome {
                        connection_index: conn_idx,
                        stream_id,
                        request,
                        authorized,
                    })
                    .await;
            });

            if let Some(waiting) = self
                .connections
                .get_mut(&conn_id)
                .and_then(|client| client.awaiting_auth.get_mut(&stream_id))
            {
                waiting.set_task(task.abort_handle());
            } else {
                // Do not detach work that no longer has connection state.
                task.abort();
            }
        }
    }

    /// Resume a CONNECT request once its credentials have been verified.
    pub(super) fn handle_auth_result(&mut self, outcome: AuthOutcome) {
        let AuthOutcome {
            connection_index,
            stream_id,
            request,
            authorized,
        } = outcome;

        let Some(conn_id) = self.conn_by_index.get(&connection_index).cloned() else {
            return;
        };
        if !self.connections.contains_key(&conn_id) {
            return;
        }
        self.dirty.mark(connection_index);

        let mut pending_setups = PendingConnectSetups::default();

        {
            let client = self
                .connections
                .get_mut(&conn_id)
                .expect("connection checked above");
            let Some(h3) = client.h3.as_mut() else {
                return;
            };

            let Some(awaiting) = client.awaiting_auth.remove(&stream_id) else {
                // The stream was reset while the hash was running.
                return;
            };
            let client_finished = awaiting.client_finished;

            if !authorized {
                warn!(stream_id, "proxy authentication failed");
                Self::send_auth_rejection(h3, &mut client.quic, stream_id, self.stealth_auth, 407);
                return;
            }

            // A half-closed datagram/IP request will never use the tunnel.
            if client_finished && !matches!(request, ConnectRequest::Tcp { .. }) {
                info!(stream_id, "CONNECT abandoned before authorization");
                return;
            }

            let request_context = RequestContext {
                config: &self.config,
                auth: self.auth.as_deref(),
                stealth_auth: self.stealth_auth,
            };
            Self::dispatch_connect(
                h3,
                &mut client.quic,
                stream_id,
                &request,
                &request_context,
                &mut pending_setups,
            );

            if !pending_setups.tcp.is_empty() {
                client
                    .pending_tcp_tunnels
                    .insert(stream_id, PendingTcpTunnel::staging(stream_id));

                // Body bytes stayed unread while the password verified; take
                // them now that bounded tunnel storage exists.
                if !Self::relay_tcp_request_body(
                    h3,
                    &mut client.quic,
                    stream_id,
                    &mut client.pending_tcp_tunnels,
                    &mut client.tcp_tunnels,
                ) {
                    warn!(stream_id, "early CONNECT body exceeded its buffer");
                    Self::reset_tcp_stream(client, stream_id);
                    return;
                }
                if client_finished
                    && let Some(pending) = client.pending_tcp_tunnels.get_mut(&stream_id)
                {
                    pending.client_finished = true;
                }
            }
            if let Some((pending_stream, _, header)) = pending_setups.udp.last() {
                debug_assert_eq!(*pending_stream, stream_id);
                client.pending_udp_tunnels.insert(
                    stream_id,
                    crate::tunnel::udp::PendingUdpTunnel::new(*header),
                );
            }
        }

        self.apply_connect_setups(connection_index, pending_setups);
    }
}
