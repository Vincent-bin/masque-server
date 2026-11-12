//! HTTP/2 connection identity and per-request Basic authentication.

use std::future::poll_fn;
use std::sync::{Arc, atomic::AtomicBool};

use bytes::Bytes;
use h2::server::SendResponse;
use http::header::{AUTHORIZATION, HeaderValue, PROXY_AUTHORIZATION};
use http::{HeaderMap, StatusCode};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use super::ConnectionContext;
use super::support::send_error;
use crate::admission::SourceAdmission;
use crate::auth::{AuthPrecheck, BasicCredential};
use crate::client_identity::{ClientIdentity, SharedRoster};
use crate::metrics::ShardMetrics;

/// Resolve a certificate against one stable roster generation.
///
/// A SIGHUP can replace the roster between any two reads. Retrying when its
/// generation changes prevents a connection from retaining an identity from
/// the old roster while recording the new generation as already enforced.
pub(super) fn identify_current_client(
    roster: &SharedRoster,
    cert_der: &[u8],
) -> Option<(Arc<ClientIdentity>, u64)> {
    loop {
        let before = roster.generation();
        let identity = roster.load().identify(cert_der);
        let after = roster.generation();
        if before == after {
            return identity.ok().map(|identity| (identity, after));
        }
    }
}

pub(super) enum Authorization {
    Granted,
    ResponseSent,
}

/// Authenticate one recognized proxy request and emit any terminal response.
pub(super) async fn authorize_request(
    headers: &HeaderMap,
    accepts_authorization: bool,
    respond: &mut SendResponse<Bytes>,
    context: &ConnectionContext,
    auth_slots: Arc<Semaphore>,
    source_ip: std::net::IpAddr,
) -> Authorization {
    let Some(auth) = &context.auth else {
        return Authorization::Granted;
    };

    let authorization = accepts_authorization
        .then(|| headers.get_all(AUTHORIZATION).iter())
        .into_iter()
        .flatten();
    let mut values = headers
        .get_all(PROXY_AUTHORIZATION)
        .iter()
        .chain(authorization);
    let first = values.next().map(HeaderValue::as_bytes);
    if values.next().is_some() {
        context.metrics.record_auth_failure();
        let _ = send_auth_rejection(respond);
        return Authorization::ResponseSent;
    }
    let (credential, password) = match auth.precheck(first) {
        AuthPrecheck::Authenticated => {
            context.metrics.record_auth_cache_hit();
            context.metrics.record_auth_success();
            return Authorization::Granted;
        }
        AuthPrecheck::Rejected => {
            context.metrics.record_auth_failure();
            let _ = send_auth_rejection(respond);
            return Authorization::ResponseSent;
        }
        AuthPrecheck::NeedsVerify {
            credential,
            password,
        } => (credential, password),
    };
    let auth_slot = match auth_slots.try_acquire_owned() {
        Ok(slot) => slot,
        Err(_) => {
            context.metrics.record_auth_overloaded();
            let _ = send_auth_rejection(respond);
            return Authorization::ResponseSent;
        }
    };
    let source_slot = match context.shared.auth_source_admissions.try_acquire(source_ip) {
        Some(slot) => slot,
        None => {
            context.metrics.record_auth_overloaded();
            let _ = send_auth_rejection(respond);
            return Authorization::ResponseSent;
        }
    };
    let verification = verify_password(
        credential,
        password,
        Arc::clone(&context.shared.auth_queue_slots),
        Arc::clone(&context.shared.auth_permits),
        Arc::clone(&context.metrics),
        auth_slot,
        source_slot,
    );
    tokio::pin!(verification);
    let authorized = tokio::select! {
        result = &mut verification => result,
        _ = poll_fn(|cx| respond.poll_reset(cx)) => return Authorization::ResponseSent,
    };
    match authorized {
        AuthResult::Authorized => Authorization::Granted,
        AuthResult::Rejected => {
            let _ = send_auth_rejection(respond);
            Authorization::ResponseSent
        }
        AuthResult::Overloaded => {
            let _ = send_auth_rejection(respond);
            Authorization::ResponseSent
        }
    }
}

enum AuthResult {
    Authorized,
    Rejected,
    Overloaded,
}

async fn verify_password(
    credential: Arc<BasicCredential>,
    password: Zeroizing<Vec<u8>>,
    queue_slots: Arc<Semaphore>,
    permits: Arc<Semaphore>,
    metrics: Arc<ShardMetrics>,
    _connection_slot: OwnedSemaphorePermit,
    source_slot: SourceAdmission,
) -> AuthResult {
    let queue_slot = match queue_slots.try_acquire_owned() {
        Ok(slot) => slot,
        Err(_) => {
            metrics.record_auth_overloaded();
            return AuthResult::Overloaded;
        }
    };
    match super::super::authentication::verify_basic_password(
        credential,
        password,
        permits,
        metrics,
        (_connection_slot, source_slot, queue_slot),
        Arc::new(AtomicBool::new(false)),
    )
    .await
    {
        Some(true) => AuthResult::Authorized,
        Some(false) | None => AuthResult::Rejected,
    }
}

/// Match the empty response used for unsupported requests before authorization.
fn send_auth_rejection(respond: &mut SendResponse<Bytes>) -> Result<(), h2::Error> {
    send_error(respond, StatusCode::NOT_FOUND)
}
