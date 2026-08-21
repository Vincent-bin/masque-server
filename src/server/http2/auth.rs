//! HTTP/2 connection identity and per-request Basic authentication.

use std::future::poll_fn;
use std::sync::Arc;

use bytes::Bytes;
use h2::server::SendResponse;
use http::header::{HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION};
use http::{Request, Response, StatusCode};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use super::ConnectionContext;
use super::support::send_error;
use crate::auth::{AuthPrecheck, BasicAuthenticator};
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
    request: &Request<h2::RecvStream>,
    respond: &mut SendResponse<Bytes>,
    context: &ConnectionContext,
    auth_slots: Arc<Semaphore>,
) -> Authorization {
    let Some(auth) = &context.auth else {
        return Authorization::Granted;
    };

    let mut values = request.headers().get_all(PROXY_AUTHORIZATION).iter();
    let first = values.next().map(HeaderValue::as_bytes);
    if values.next().is_some() {
        let _ = send_proxy_auth_required(respond);
        return Authorization::ResponseSent;
    }
    let password = match auth.precheck(first) {
        AuthPrecheck::Rejected => {
            let _ = send_proxy_auth_required(respond);
            return Authorization::ResponseSent;
        }
        AuthPrecheck::NeedsVerify(password) => password,
    };
    let auth_slot = match auth_slots.try_acquire_owned() {
        Ok(slot) => slot,
        Err(_) => {
            context.metrics.record_auth_overloaded();
            let _ = send_error(respond, StatusCode::SERVICE_UNAVAILABLE);
            return Authorization::ResponseSent;
        }
    };
    let verification = verify_password(
        Arc::clone(auth),
        password,
        Arc::clone(&context.shared.auth_queue_slots),
        Arc::clone(&context.shared.auth_permits),
        Arc::clone(&context.metrics),
        auth_slot,
    );
    tokio::pin!(verification);
    let authorized = tokio::select! {
        result = &mut verification => result,
        _ = poll_fn(|cx| respond.poll_reset(cx)) => return Authorization::ResponseSent,
    };
    match authorized {
        AuthResult::Authorized => Authorization::Granted,
        AuthResult::Rejected => {
            let _ = send_proxy_auth_required(respond);
            Authorization::ResponseSent
        }
        AuthResult::Overloaded => {
            let _ = send_error(respond, StatusCode::SERVICE_UNAVAILABLE);
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
    auth: Arc<BasicAuthenticator>,
    password: Zeroizing<Vec<u8>>,
    queue_slots: Arc<Semaphore>,
    permits: Arc<Semaphore>,
    metrics: Arc<ShardMetrics>,
    _connection_slot: OwnedSemaphorePermit,
) -> AuthResult {
    let queue_slot = match queue_slots.try_acquire_owned() {
        Ok(slot) => slot,
        Err(_) => {
            metrics.record_auth_overloaded();
            return AuthResult::Overloaded;
        }
    };
    let pending = metrics.auth_pending_guard();
    let permit = match permits.acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => return AuthResult::Rejected,
    };
    drop(pending);
    let running = metrics.auth_running_guard();
    let completion_metrics = Arc::clone(&metrics);
    match tokio::task::spawn_blocking(move || {
        let _queue_slot = queue_slot;
        let _permit = permit;
        let _running = running;
        let authorized = auth.verify(&password);
        if authorized {
            completion_metrics.record_auth_success();
        } else {
            completion_metrics.record_auth_failure();
        }
        authorized
    })
    .await
    {
        Ok(true) => AuthResult::Authorized,
        Ok(false) | Err(_) => AuthResult::Rejected,
    }
}

fn send_proxy_auth_required(respond: &mut SendResponse<Bytes>) -> Result<(), h2::Error> {
    let response = Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header(
            PROXY_AUTHENTICATE,
            "Basic realm=\"masque\", charset=\"UTF-8\"",
        )
        .body(())
        .expect("static proxy-authenticate response is valid");
    respond.send_response(response, true).map(|_| ())
}
