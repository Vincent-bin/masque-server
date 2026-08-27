//! One-shot target resolution shared by every proxy transport.
//!
//! A hostname is resolved exactly once. The complete result is checked against
//! the configured target policy, then the same immutable snapshot is handed to
//! the socket setup code. Keeping those two operations tied together prevents
//! a short-TTL or attacker-controlled name from changing addresses between the
//! policy decision and the actual connect.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};

use tokio::time::Instant;

use crate::policy::TargetPolicy;

/// An HTTP status and operator-facing reason for target setup failure.
#[derive(Debug)]
pub struct TargetSetupFailure {
    pub status: u16,
    pub reason: String,
}

impl TargetSetupFailure {
    pub(crate) fn timeout(operation: &str) -> Self {
        Self {
            status: 504,
            reason: format!("target {operation} timed out"),
        }
    }

    pub(crate) fn connect(protocol: &str, error: std::io::Error) -> Self {
        Self {
            status: 502,
            reason: format!("target {protocol} connect failed: {error}"),
        }
    }
}

/// Addresses from one DNS snapshot that has already passed target policy.
#[derive(Debug)]
pub(crate) struct ResolvedTarget {
    addresses: Vec<SocketAddr>,
}

impl ResolvedTarget {
    pub(crate) fn into_addresses(self) -> Vec<SocketAddr> {
        self.addresses
    }

    #[cfg(test)]
    fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
}

/// Resolve a target once, with a shared deadline, and validate that exact
/// result against policy.
pub(crate) async fn resolve_allowed(
    host: &str,
    port: u16,
    policy: &TargetPolicy,
    deadline: Instant,
) -> Result<ResolvedTarget, TargetSetupFailure> {
    resolve_allowed_with(host, port, policy, deadline, |host, port| async move {
        tokio::net::lookup_host((host.as_str(), port))
            .await
            .map(|addresses| addresses.collect())
    })
    .await
}

async fn resolve_allowed_with<R, Fut>(
    host: &str,
    port: u16,
    policy: &TargetPolicy,
    deadline: Instant,
    resolver: R,
) -> Result<ResolvedTarget, TargetSetupFailure>
where
    R: FnOnce(String, u16) -> Fut,
    Fut: Future<Output = std::io::Result<Vec<SocketAddr>>>,
{
    let addresses = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        match tokio::time::timeout_at(deadline, resolver(host.to_owned(), port)).await {
            Ok(Ok(addresses)) => addresses,
            Ok(Err(error)) => {
                return Err(TargetSetupFailure {
                    status: 502,
                    reason: format!("target DNS resolution failed: {error}"),
                });
            }
            Err(_) => return Err(TargetSetupFailure::timeout("DNS resolution")),
        }
    };

    // A resolver can repeat records. Removing duplicates avoids launching two
    // identical TCP attempts without changing the resolver's family order.
    let mut unique = Vec::with_capacity(addresses.len());
    for address in addresses {
        if !unique.contains(&address) {
            unique.push(address);
        }
    }
    if unique.is_empty() {
        return Err(TargetSetupFailure {
            status: 502,
            reason: "target DNS resolution returned no addresses".into(),
        });
    }

    let ips: Vec<_> = unique.iter().map(|address| address.ip()).collect();
    if !policy.all_allowed(&ips) {
        return Err(TargetSetupFailure {
            status: 403,
            reason: "target denied by policy".into(),
        });
    }

    Ok(ResolvedTarget { addresses: unique })
}

#[cfg(test)]
mod tests {
    use std::future;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    fn policy(allow: &[&str], deny: &[&str]) -> TargetPolicy {
        TargetPolicy::new(
            &allow
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>(),
            &deny
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>(),
        )
    }

    #[tokio::test]
    async fn one_dns_snapshot_is_used_for_policy_and_connect() {
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&calls);
        let allowed: SocketAddr = "192.0.2.10:443".parse().unwrap();
        let denied: SocketAddr = "10.0.0.10:443".parse().unwrap();
        let target_policy = policy(&["192.0.2.0/24"], &["10.0.0.0/8"]);

        let resolved = resolve_allowed_with(
            "rebinding.test",
            443,
            &target_policy,
            Instant::now() + Duration::from_secs(1),
            move |_, _| async move {
                let call = resolver_calls.fetch_add(1, Ordering::SeqCst);
                // A second lookup would return a policy-denied address. The
                // production API returns the first checked snapshot instead
                // of retaining the hostname for socket setup.
                Ok(if call == 0 {
                    vec![allowed]
                } else {
                    vec![denied]
                })
            },
        )
        .await
        .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(resolved.addresses(), &[allowed]);
    }

    #[tokio::test]
    async fn dns_resolution_obeys_the_setup_deadline() {
        let error = resolve_allowed_with(
            "slow.test",
            443,
            &policy(&["0.0.0.0/0", "::/0"], &[]),
            Instant::now() + Duration::from_millis(20),
            |_, _| future::pending::<std::io::Result<Vec<SocketAddr>>>(),
        )
        .await
        .unwrap_err();

        assert_eq!(error.status, 504);
        assert!(error.reason.contains("DNS resolution"));
    }

    #[tokio::test]
    async fn a_mixed_allowed_and_denied_answer_fails_closed() {
        let allowed: SocketAddr = "192.0.2.10:53".parse().unwrap();
        let denied: SocketAddr = "10.0.0.10:53".parse().unwrap();
        let error = resolve_allowed_with(
            "mixed.test",
            53,
            &policy(&["192.0.2.0/24"], &["10.0.0.0/8"]),
            Instant::now() + Duration::from_secs(1),
            move |_, _| async move { Ok(vec![allowed, denied]) },
        )
        .await
        .unwrap_err();

        assert_eq!(error.status, 403);
    }

    #[tokio::test]
    async fn ip_literals_do_not_enter_the_dns_resolver() {
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&calls);
        let resolved = resolve_allowed_with(
            "192.0.2.20",
            8443,
            &policy(&["192.0.2.0/24"], &[]),
            Instant::now() + Duration::from_secs(1),
            move |_, _| {
                resolver_calls.fetch_add(1, Ordering::SeqCst);
                future::ready(Ok(Vec::new()))
            },
        )
        .await
        .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(resolved.addresses(), &["192.0.2.20:8443".parse().unwrap()]);
    }
}
