//! HTTP/2 CONNECT recognition and transport-specific validation.

use http::header::{HeaderName, HeaderValue};
use http::{Request, StatusCode};

use super::super::request::{ConnectRequest, classify_connect_request};
use super::ip::IpCapsuleMode;
use crate::config::ServerConfig;
use crate::uri::{self, TcpTarget, UdpTarget};

pub(super) const CAPSULE_PROTOCOL: HeaderName = HeaderName::from_static("capsule-protocol");
const CF_CONNECT_PROTO: HeaderName = HeaderName::from_static("cf-connect-proto");

pub(super) enum RequestKind {
    Tcp(TcpTarget),
    Udp(UdpTarget),
    Ip(IpCapsuleMode),
}

/// The protocol-independent CONNECT classification plus the HTTP/2 wire shape
/// needed after authentication succeeds.
pub(super) struct RecognizedRequest {
    connect: ConnectRequest,
    cloudflare_capsules: bool,
    duplicate_cloudflare_protocol: bool,
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
    let mut cloudflare_protocols = request.headers().get_all(&CF_CONNECT_PROTO).iter();
    let cloudflare_protocol = cloudflare_protocols.next().map(HeaderValue::as_bytes);
    let duplicate_cloudflare_protocol = cloudflare_protocols.next().is_some();
    let cloudflare_capsules = protocol.is_none() && cloudflare_protocol == Some(b"cf-connect-ip");
    let effective_protocol = if cloudflare_capsules {
        "cf-connect-ip"
    } else {
        protocol.as_deref().unwrap_or("")
    };
    let authority = request
        .uri()
        .authority()
        .map_or("", |authority| authority.as_str());
    let connect = classify_connect_request(
        request.method().as_str().as_bytes(),
        effective_protocol.as_bytes(),
        authority.as_bytes(),
        request.uri().path().as_bytes(),
        config,
    )?;
    Some(RecognizedRequest {
        connect,
        cloudflare_capsules,
        duplicate_cloudflare_protocol,
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
        ConnectRequest::Ip => {
            if recognized.cloudflare_capsules {
                if recognized.duplicate_cloudflare_protocol {
                    return Err(StatusCode::BAD_REQUEST);
                }
                return Ok(RequestKind::Ip(IpCapsuleMode::Cloudflare));
            }
            if !uses_capsule_protocol(request) {
                return Err(StatusCode::BAD_REQUEST);
            }
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
