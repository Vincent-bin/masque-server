//! Bounded asynchronous credential verification and request resumption.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tracing::{info, warn};

use crate::auth::{BasicCredential, PasswordVerification};
use crate::connection::AwaitingAuth;
use crate::metrics::ShardMetrics;
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

/// One bounded cold request, shared by H2 and H3. Followers hold admission
/// slots but never a CPU permit or blocking thread. Once work starts, its
/// admission guards live until Argon2 actually finishes, even after a reset.
pub(super) async fn verify_basic_password(
    credential: Arc<BasicCredential>,
    password: zeroize::Zeroizing<Vec<u8>>,
    permits: Arc<tokio::sync::Semaphore>,
    metrics: Arc<ShardMetrics>,
    held: impl Send + 'static,
    cancelled: Arc<AtomicBool>,
) -> Option<bool> {
    struct CancelOnDrop(Arc<AtomicBool>);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let _cancellation = CancelOnDrop(Arc::clone(&cancelled));
    let pending = metrics.auth_pending_guard();
    loop {
        if cancelled.load(Ordering::Acquire) {
            return None;
        }
        let result = match credential.begin_verification(&password) {
            PasswordVerification::Cached => {
                metrics.record_auth_cache_hit();
                Some(true)
            }
            PasswordVerification::Follower(waiter) => {
                metrics.record_auth_coalesced();
                waiter.wait().await
            }
            PasswordVerification::Leader(leader) => {
                let permit = permits.acquire_owned().await.ok()?;
                let running = metrics.auth_running_guard();
                let failure_metrics = Arc::clone(&metrics);
                return match tokio::task::spawn_blocking(move || {
                    let (_held, _pending, _running, _permit) = (held, pending, running, permit);
                    if cancelled.load(Ordering::Acquire) {
                        return None;
                    }
                    metrics.record_auth_argon2();
                    let authorized = leader.verify(&password);
                    record_result(&metrics, authorized);
                    Some(authorized)
                })
                .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        failure_metrics.record_auth_failure();
                        Some(false)
                    }
                };
            }
        };
        if let Some(authorized) = result {
            record_result(&metrics, authorized);
            return Some(authorized);
        }
        // A cancelled leader never leaves its followers waiting forever.
    }
}

fn record_result(metrics: &ShardMetrics, authorized: bool) {
    if authorized {
        metrics.record_auth_success();
    } else {
        metrics.record_auth_failure();
    }
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
                let Some(authorized) = verify_basic_password(
                    credential,
                    password,
                    permits,
                    metrics,
                    (source_slot, queue_slot),
                    cancelled,
                )
                .await
                else {
                    return;
                };
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

            let Some(mut awaiting) = client.awaiting_auth.remove(&stream_id) else {
                // The stream was reset while the hash was running.
                return;
            };
            let client_finished = awaiting.client_finished;
            let early_udp_datagrams = awaiting.take_early_udp_datagrams();

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
                metrics: &self.metrics,
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
                    crate::tunnel::udp::PendingUdpTunnel::with_early_datagrams(
                        *header,
                        early_udp_datagrams.unwrap_or_default(),
                    ),
                );
            }
        }

        self.apply_connect_setups(connection_index, pending_setups);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthPrecheck, BasicAuthenticator};
    use crate::metrics::Metrics;
    use base64::Engine as _;
    use std::time::Duration;

    fn credential() -> Arc<BasicCredential> {
        let auth = BasicAuthenticator::new("test", "$argon2id$v=19$m=19456,t=2,p=1$1xNVXhqKU7jJ6cqTBJKphQ$GXXAINVTW1qhloFtN1IR8lSr7pI7QEY79fq4K6d8scQ").unwrap();
        let header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("test:test-password")
        );
        let AuthPrecheck::NeedsVerify { credential, .. } = auth.precheck(Some(header.as_bytes()))
        else {
            panic!("cold credentials");
        };
        credential
    }

    fn counter(metrics: &Metrics, name: &str) -> u64 {
        metrics
            .render()
            .lines()
            .find(|line| line.starts_with(&format!("{name}{{")))
            .unwrap()
            .rsplit_once(' ')
            .unwrap()
            .1
            .parse()
            .unwrap()
    }

    async fn wait_for(metrics: &Metrics, name: &str, expected: u64) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while counter(metrics, name) != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn identical_requests_share_one_argon2_call_before_cpu_admission() {
        let registry = Metrics::new(true);
        let metrics = registry
            .register_listener(
                "127.0.0.1:0".parse().unwrap(),
                "http3",
                "basic",
                1,
                false,
                false,
            )
            .remove(0);
        let credential = credential();
        let permits = Arc::new(tokio::sync::Semaphore::new(0));
        let mut tasks = Vec::new();
        for _ in 0..32 {
            tasks.push(tokio::spawn(verify_basic_password(
                Arc::clone(&credential),
                zeroize::Zeroizing::new(b"test-password".to_vec()),
                Arc::clone(&permits),
                Arc::clone(&metrics),
                (),
                Arc::new(AtomicBool::new(false)),
            )));
        }
        wait_for(&registry, "masque_auth_coalesced_total", 31).await;
        assert_eq!(counter(&registry, "masque_auth_argon2_total"), 0);
        permits.add_permits(1);
        for task in tasks {
            assert_eq!(task.await.unwrap(), Some(true));
        }
        assert_eq!(counter(&registry, "masque_auth_argon2_total"), 1);
        assert_eq!(counter(&registry, "masque_auth_pending"), 0);
        assert_eq!(counter(&registry, "masque_auth_running_max"), 1);
    }

    #[tokio::test]
    async fn cancelling_a_queued_leader_does_not_cancel_other_requests() {
        let registry = Metrics::new(true);
        let metrics = registry
            .register_listener(
                "127.0.0.1:0".parse().unwrap(),
                "http2",
                "basic",
                1,
                false,
                false,
            )
            .remove(0);
        let credential = credential();
        let permits = Arc::new(tokio::sync::Semaphore::new(0));
        let start = || {
            tokio::spawn(verify_basic_password(
                Arc::clone(&credential),
                zeroize::Zeroizing::new(b"test-password".to_vec()),
                Arc::clone(&permits),
                Arc::clone(&metrics),
                (),
                Arc::new(AtomicBool::new(false)),
            ))
        };
        let leader = start();
        wait_for(&registry, "masque_auth_pending", 1).await;
        let follower = start();
        wait_for(&registry, "masque_auth_coalesced_total", 1).await;
        leader.abort();
        assert!(leader.await.unwrap_err().is_cancelled());
        permits.add_permits(1);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), follower)
                .await
                .unwrap()
                .unwrap(),
            Some(true)
        );
        assert_eq!(counter(&registry, "masque_auth_argon2_total"), 1);
    }
}
