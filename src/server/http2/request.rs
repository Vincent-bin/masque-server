//! HTTP/2 CONNECT recognition and transport-specific validation.

use http::header::{HeaderName, HeaderValue};
use http::{Request, StatusCode};

use super::super::request::{ConnectRequest, classify_connect_request, prepare_connect_ip};
use super::ip::IpCapsuleMode;
use crate::config::ServerConfig;
use crate::uri::{self, TcpTarget, UdpTarget};

pub(super) const CAPSULE_PROTOCOL: HeaderName = HeaderName::from_static("capsule-protocol");
const LEGACY_CONNECT_PROTOCOL_HEADER: HeaderName = HeaderName::from_static("cf-connect-proto");

pub(super) enum RequestKind {
    Tcp(TcpTarget),
    Udp(UdpTarget),
    Ip(IpCapsuleMode),
}

/// The protocol-independent CONNECT classification plus the HTTP/2 wire shape
/// needed after authentication succeeds.
pub(super) struct RecognizedRequest {
    connect: ConnectRequest,
    context_free_capsules: bool,
    duplicate_legacy_protocol: bool,
}

/// Recognize a proxy request without parsing its target.
///
/// Keeping recognition separate from `prepare` preserves the authentication
/// boundary: a known proxy request authenticates before malformed target or
/// capsule details can produce a different status code.
pub(super) fn recognize(
    request: &Request<h2::RecvStream>,
    config: &ServerConfig,
) -> Option<RecognizedRequest> {
    let protocol = request
        .extensions()
        .get::<h2::ext::Protocol>()
        .map(|protocol| protocol.as_str().to_owned());
    let mut legacy_protocols = request
        .headers()
        .get_all(&LEGACY_CONNECT_PROTOCOL_HEADER)
        .iter();
    let legacy_protocol = legacy_protocols.next().map(HeaderValue::as_bytes);
    let duplicate_legacy_protocol = legacy_protocols.next().is_some();
    let context_free_capsules = protocol.is_none() && legacy_protocol == Some(b"cf-connect-ip");
    let effective_protocol = if context_free_capsules {
        "cf-connect-ip"
    } else {
        protocol.as_deref().unwrap_or("")
    };
    let authority = request
        .uri()
        .authority()
        .map_or("", |authority| authority.as_str());
    // CONNECT-IP must match its complete configured URI. Keep the existing
    // CONNECT-UDP path-only interpretation outside that stricter scope check.
    let path = if effective_protocol == "connect-udp" {
        request.uri().path()
    } else {
        request
            .uri()
            .path_and_query()
            .map_or("", |path| path.as_str())
    };
    let connect = classify_connect_request(
        request.method().as_str().as_bytes(),
        effective_protocol.as_bytes(),
        authority.as_bytes(),
        path.as_bytes(),
        request.uri().scheme_str().unwrap_or("").as_bytes(),
        config,
    )?;
    Some(RecognizedRequest {
        connect,
        context_free_capsules,
        duplicate_legacy_protocol,
    })
}

pub(super) fn prepare(
    request: &Request<h2::RecvStream>,
    recognized: RecognizedRequest,
    config: &ServerConfig,
) -> Result<RequestKind, StatusCode> {
    match recognized.connect {
        ConnectRequest::Tcp { authority } => uri::parse_connect_authority(&authority)
            .map(RequestKind::Tcp)
            .map_err(|_| StatusCode::BAD_REQUEST),
        ConnectRequest::Udp { path } => {
            if !uses_capsule_protocol(request) {
                return Err(StatusCode::BAD_REQUEST);
            }
            uri::parse_udp_path(&path, &config.udp_proxy.uri_template)
                .map(RequestKind::Udp)
                .map_err(|_| StatusCode::BAD_REQUEST)
        }
        ConnectRequest::Ip {
            path,
            standard,
            valid_pseudo_headers,
        } => {
            if recognized.context_free_capsules {
                if recognized.duplicate_legacy_protocol {
                    return Err(StatusCode::BAD_REQUEST);
                }
                return Ok(RequestKind::Ip(IpCapsuleMode::ContextFree));
            }
            if !uses_capsule_protocol(request) {
                return Err(StatusCode::BAD_REQUEST);
            }
            prepare_connect_ip(&path, standard, valid_pseudo_headers, config)
                .map_err(|status| StatusCode::from_u16(status).expect("valid IP request status"))?;
            Ok(RequestKind::Ip(IpCapsuleMode::Standard))
        }
    }
}

/// HTTP/2 Extended CONNECT has no native datagram frame, so both datagram
/// protocols require the Capsule Protocol on a fully formed absolute URI.
fn uses_capsule_protocol(request: &Request<h2::RecvStream>) -> bool {
    request.uri().scheme().is_some()
        && request.uri().authority().is_some()
        && !request.uri().path().is_empty()
        && request.headers().get_all(&CAPSULE_PROTOCOL).iter().count() == 1
        && request.headers().get(&CAPSULE_PROTOCOL) == Some(&HeaderValue::from_static("?1"))
}
