//! Bounds system resolver work, including work outliving a cancelled request.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use tokio::sync::Semaphore;

/// Leave headroom in Tokio's blocking pool for credential checks and host I/O.
const MAX_LOOKUPS: usize = 128;
const MAX_LOOKUPS_PER_CONNECTION: usize = 8;

pub(crate) struct ResolverBudget(Arc<Semaphore>);

impl Default for ResolverBudget {
    fn default() -> Self {
        Self(Arc::new(Semaphore::new(MAX_LOOKUPS)))
    }
}

impl ResolverBudget {
    pub(crate) fn connection(&self) -> TargetResolver {
        TargetResolver {
            global: Arc::clone(&self.0),
            local: Arc::new(Semaphore::new(MAX_LOOKUPS_PER_CONNECTION)),
        }
    }
}

/// Clones share one connection's allowance across all its TCP/UDP requests.
#[derive(Clone)]
pub(crate) struct TargetResolver {
    global: Arc<Semaphore>,
    local: Arc<Semaphore>,
}

impl TargetResolver {
    pub(crate) async fn lookup(&self, host: String, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        self.run(move || {
            (host.as_str(), port)
                .to_socket_addrs()
                .map(Iterator::collect)
        })
        .await
    }

    async fn run<F>(&self, lookup: F) -> std::io::Result<Vec<SocketAddr>>
    where
        F: FnOnce() -> std::io::Result<Vec<SocketAddr>> + Send + 'static,
    {
        // Take the local slot first: a connection waiting for its own capacity
        // must not reserve capacity from other connections.
        let local = Arc::clone(&self.local)
            .acquire_owned()
            .await
            .expect("resolver budget is never closed");
        let global = Arc::clone(&self.global)
            .acquire_owned()
            .await
            .expect("resolver budget is never closed");
        tokio::task::spawn_blocking(move || {
            // getaddrinfo cannot be cancelled. Both permits belong to this
            // blocking closure, even if its caller times out or disconnects.
            let _permits = (local, global);
            lookup()
        })
        .await
        .map_err(std::io::Error::other)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn cancelled_lookup_keeps_both_slots_until_the_blocking_call_ends() {
        let resolver = TargetResolver {
            global: Arc::new(Semaphore::new(1)),
            local: Arc::new(Semaphore::new(1)),
        };
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let owned = resolver.clone();
        let task = tokio::spawn(async move {
            owned
                .run(move || {
                    let _ = started_tx.send(());
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    Ok(Vec::new())
                })
                .await
        });
        started_rx.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(resolver.local.available_permits(), 0);
        assert_eq!(resolver.global.available_permits(), 0);
        release_tx.send(()).unwrap();
        let local = tokio::time::timeout(Duration::from_secs(2), resolver.local.acquire())
            .await
            .unwrap()
            .unwrap();
        let global = tokio::time::timeout(Duration::from_secs(2), resolver.global.acquire())
            .await
            .unwrap()
            .unwrap();
        drop((local, global));
    }

    #[tokio::test]
    async fn cancelling_a_wait_for_global_capacity_returns_the_local_slot() {
        let budget = ResolverBudget::default();
        let resolver = budget.connection();
        let _occupied = budget.0.acquire_many(MAX_LOOKUPS as u32).await.unwrap();
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = Arc::clone(&called);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                resolver.run(move || {
                    observed.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(Vec::new())
                })
            )
            .await
            .is_err()
        );
        assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            resolver.local.available_permits(),
            MAX_LOOKUPS_PER_CONNECTION
        );
    }

    #[tokio::test]
    async fn waiting_for_local_capacity_does_not_take_a_global_slot() {
        let budget = ResolverBudget::default();
        let busy = budget.connection();
        let other = budget.connection();
        let _occupied = busy
            .local
            .acquire_many(MAX_LOOKUPS_PER_CONNECTION as u32)
            .await
            .unwrap();
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = Arc::clone(&called);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                busy.run(move || {
                    observed.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(Vec::new())
                })
            )
            .await
            .is_err()
        );
        assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(budget.0.available_permits(), MAX_LOOKUPS);
        assert!(other.run(|| Ok(Vec::new())).await.is_ok());
    }
}
