//! Process-wide source admission for transport connections.
//!
//! One source may legitimately use several HTTP/2 and HTTP/3 connections, but
//! it must not be able to consume the entire process-wide connection budget.
//! The table is bounded by live admissions: every key owns at least one guard,
//! and every guard is released when its connection task or QUIC state drops.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

struct Inner {
    max_per_ip: usize,
    // Source addresses are attacker-influenced, so retain HashMap's randomized
    // hashing rather than using the packet-path FxHashMap here.
    counts: Mutex<HashMap<IpAddr, usize>>,
}

#[derive(Clone)]
pub(crate) struct SourceAdmissionLimiter {
    inner: Arc<Inner>,
}

impl SourceAdmissionLimiter {
    pub(crate) fn new(max_per_ip: usize) -> Self {
        debug_assert!(max_per_ip > 0);
        Self {
            inner: Arc::new(Inner {
                max_per_ip,
                counts: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub(crate) fn try_acquire(&self, source: IpAddr) -> Option<SourceAdmission> {
        let source = canonical_ip(source);
        let mut counts = self
            .inner
            .counts
            .lock()
            .expect("source admissions poisoned");
        let count = counts.entry(source).or_default();
        if *count >= self.inner.max_per_ip {
            return None;
        }
        *count += 1;
        Some(SourceAdmission {
            source,
            inner: Arc::clone(&self.inner),
        })
    }
}

pub(crate) struct SourceAdmission {
    source: IpAddr,
    inner: Arc<Inner>,
}

impl SourceAdmission {
    pub(crate) fn source(&self) -> IpAddr {
        self.source
    }
}

impl Drop for SourceAdmission {
    fn drop(&mut self) {
        let mut counts = self
            .inner
            .counts
            .lock()
            .expect("source admissions poisoned");
        let Some(count) = counts.get_mut(&self.source) else {
            debug_assert!(false, "live source admission has no counter");
            return;
        };
        *count -= 1;
        if *count == 0 {
            counts.remove(&self.source);
        }
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_source_is_bounded_and_release_restores_capacity() {
        let limiter = SourceAdmissionLimiter::new(2);
        let first = limiter.try_acquire("192.0.2.1".parse().unwrap()).unwrap();
        let second = limiter.try_acquire("192.0.2.1".parse().unwrap()).unwrap();
        assert!(limiter.try_acquire("192.0.2.1".parse().unwrap()).is_none());

        drop(first);
        assert!(limiter.try_acquire("192.0.2.1".parse().unwrap()).is_some());
        drop(second);
    }

    #[test]
    fn independent_sources_do_not_share_a_limit() {
        let limiter = SourceAdmissionLimiter::new(1);
        let _first = limiter.try_acquire("192.0.2.1".parse().unwrap()).unwrap();
        let _second = limiter.try_acquire("192.0.2.2".parse().unwrap()).unwrap();
    }

    #[test]
    fn ipv4_mapped_ipv6_uses_the_ipv4_counter() {
        let limiter = SourceAdmissionLimiter::new(1);
        let _first = limiter.try_acquire("192.0.2.1".parse().unwrap()).unwrap();
        let mapped = "::ffff:192.0.2.1".parse::<IpAddr>().unwrap();
        assert!(limiter.try_acquire(mapped).is_none());
    }
}
