//! CONNECT request classification, authentication precheck, and dispatch.

use std::sync::Arc;

use quiche::h3::NameValue;
use tracing::{info, warn};

use crate::auth::{AuthPrecheck, BasicCredential, SharedBasicAuthenticator};
use crate::config::ServerConfig;
use crate::uri;

use super::Shard;

/// The target of a CONNECT request, held while its credentials are verified.
#[derive(Debug)]
pub(super) enum ConnectRequest {
    Tcp {
        authority: String,
    },
    Udp {
        path: String,
    },
    Ip {
        path: String,
        standard: bool,
        valid_pseudo_headers: bool,
    },
}

/// A prechecked CONNECT request whose password still has to be verified.
pub(super) struct PendingAuth {
    pub(super) stream_id: u64,
    pub(super) credential: Arc<BasicCredential>,
    pub(super) password: zeroize::Zeroizing<Vec<u8>>,
    pub(super) request: ConnectRequest,
}

/// Tunnel work created while request headers are processed.
///
/// Setup itself runs after the HTTP/3 connection borrow is released.
#[derive(Default)]
pub(super) struct PendingConnectSetups {
    pub(super) tcp: Vec<(u64, uri::TcpTarget)>,
    pub(super) udp: Vec<(u64, uri::UdpTarget, crate::datagram::DatagramHeader)>,
    pub(super) ip: Vec<u64>,
}

impl PendingConnectSetups {
    pub(super) fn is_empty(&self) -> bool {
        self.tcp.is_empty() && self.udp.is_empty() && self.ip.is_empty()
    }
}

/// Whether `protocol` names CONNECT-IP according to the configured list.
///
/// RFC 9484 registers `connect-ip`, but Cloudflare's endpoint uses
/// `cf-connect-ip`, and clients written against it send only that. The value is
/// compared case-sensitively: `:protocol` is a registered token, not a header
/// name.
///
/// An empty `protocol` never matches, however the list is configured, because
/// that is a standard CONNECT and belongs to the TCP path.
fn accepts_connect_ip(configured: &[String], protocol: &[u8]) -> bool {
    !protocol.is_empty()
        && configured
            .iter()
            .any(|accepted| accepted.as_bytes() == protocol)
}

/// Classify the transport-neutral semantics of one header block.
///
/// HTTP/2 and HTTP/3 encode their pseudo-headers differently in memory, but
/// the supported CONNECT methods and feature gates must stay identical.
pub(super) fn classify_connect_request(
    method: &[u8],
    protocol: &[u8],
    authority: &[u8],
    path: &[u8],
    scheme: &[u8],
    config: &ServerConfig,
) -> Option<ConnectRequest> {
    if method != b"CONNECT" {
        return None;
    }

    if protocol.is_empty() && config.tcp_proxy.enabled {
        Some(ConnectRequest::Tcp {
            authority: String::from_utf8_lossy(authority).into_owned(),
        })
    } else if protocol == b"connect-udp" && config.udp_proxy.enabled {
        Some(ConnectRequest::Udp {
            path: String::from_utf8_lossy(path).into_owned(),
        })
    } else if config.ip_proxy.enabled
        && accepts_connect_ip(&config.ip_proxy.connect_protocols, protocol)
    {
        Some(ConnectRequest::Ip {
            path: String::from_utf8_lossy(path).into_owned(),
            standard: protocol == b"connect-ip",
            valid_pseudo_headers: !authority.is_empty() && !scheme.is_empty() && !path.is_empty(),
        })
    } else {
        None
    }
}

/// Validate only after authentication, before address allocation or a 2xx.
/// No current data path enforces per-request destination/protocol scope, so
/// accepting a scoped URI would incorrectly establish an unrestricted tunnel.
pub(super) fn prepare_connect_ip(
    path: &str,
    standard: bool,
    valid_pseudo_headers: bool,
    config: &ServerConfig,
) -> Result<(), u16> {
    if !standard {
        // Preserve deployed cf-connect-ip and explicitly configured aliases.
        return Ok(());
    }
    if !valid_pseudo_headers {
        return Err(400);
    }
    let scope = uri::parse_ip_path(path, &config.ip_proxy.uri_template).map_err(|_| 400u16)?;
    if scope.target.is_some() || scope.ipproto.is_some() {
        return Err(501);
    }
    Ok(())
}

#[derive(Default)]
struct RequestHeaders<'a> {
    method: Option<&'a [u8]>,
    path: Option<&'a [u8]>,
    scheme: Option<&'a [u8]>,
    protocol: Option<&'a [u8]>,
    authority: Option<&'a [u8]>,
    proxy_authorization: Option<&'a [u8]>,
    duplicate_proxy_authorization: bool,
}

impl<'a> RequestHeaders<'a> {
    /// Validate the field section in one pass, borrowing the values.
    /// Target parsing still runs after authentication.
    fn parse(headers: &'a [quiche::h3::Header]) -> Option<Self> {
        let mut request = Self::default();
        let mut regular_field_seen = false;
        for header in headers {
            let name = header.name();
            let value = header.value();
            if value
                .iter()
                .any(|byte| byte.is_ascii_control() && *byte != b'\t')
            {
                return None;
            }
            if name.starts_with(b":") {
                let field = match name {
                    b":method" => &mut request.method,
                    b":path" => &mut request.path,
                    b":scheme" => &mut request.scheme,
                    b":protocol" => &mut request.protocol,
                    b":authority" => &mut request.authority,
                    _ => return None,
                };
                if regular_field_seen || field.replace(value).is_some() {
                    return None;
                }
                continue;
            }

            regular_field_seen = true;
            if name.is_empty()
                || !name
                    .iter()
                    .all(|byte| token_byte(*byte) && !byte.is_ascii_uppercase())
            {
                return None;
            }
            match name {
                b"connection" | b"proxy-connection" | b"keep-alive" | b"transfer-encoding"
                | b"upgrade" => return None,
                b"te"
                    if !value
                        .split(|byte| *byte == b',')
                        .map(<[u8]>::trim_ascii)
                        .all(|coding| {
                            coding.is_empty() || coding.eq_ignore_ascii_case(b"trailers")
                        }) =>
                {
                    return None;
                }
                b"proxy-authorization" => {
                    request.duplicate_proxy_authorization |=
                        request.proxy_authorization.replace(value).is_some();
                }
                _ => {}
            }
        }

        let method = request
            .method
            .filter(|value| !value.is_empty() && value.iter().copied().all(token_byte))?;
        if method == b"CONNECT" {
            request.authority.filter(|value| !value.is_empty())?;
            match request.protocol {
                None => {
                    if request.path.is_some() || request.scheme.is_some() {
                        return None;
                    }
                    return Some(request);
                }
                Some(protocol)
                    if !protocol.is_empty() && protocol.iter().copied().all(token_byte) => {}
                Some(_) => return None,
            }
        } else if request.protocol.is_some() {
            return None;
        }

        let scheme = request.scheme?;
        let (first, rest) = scheme.split_first()?;
        if !first.is_ascii_alphabetic()
            || !rest
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
        {
            return None;
        }
        let path = request.path?;
        match path {
            [b'/', ..] => {}
            b"*" if method == b"OPTIONS" => {}
            b"" if method != b"CONNECT"
                && !scheme.eq_ignore_ascii_case(b"http")
                && !scheme.eq_ignore_ascii_case(b"https") => {}
            _ => return None,
        }
        Some(request)
    }
}

fn token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^`_|~".contains(&byte)
}

/// Shared request dependencies passed together to keep dispatch APIs focused.
pub(super) struct RequestContext<'a> {
    pub(super) metrics: &'a crate::metrics::ShardMetrics,
    pub(super) config: &'a ServerConfig,
    pub(super) auth: Option<&'a SharedBasicAuthenticator>,
    pub(super) first_auth_deadline: &'a mut Option<std::time::Instant>,
}

impl Shard {
    /// Handle an incoming HTTP/3 request.
    pub(super) fn handle_request(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        pending_errors: &mut crate::connection::PendingErrorResponses,
        stream_id: u64,
        headers: &[quiche::h3::Header],
        context: &mut RequestContext<'_>,
        pending: &mut PendingConnectSetups,
    ) -> Option<PendingAuth> {
        let Some(headers) = RequestHeaders::parse(headers) else {
            let code = quiche::h3::WireErrorCode::MessageError as u64;
            let _ = quic.stream_shutdown(stream_id, quiche::Shutdown::Read, code);
            let _ = quic.stream_shutdown(stream_id, quiche::Shutdown::Write, code);
            return None;
        };
        let method = headers.method.unwrap_or_default();
        let path = headers.path.unwrap_or_default();
        let scheme = headers.scheme.unwrap_or_default();
        let protocol = headers.protocol.unwrap_or_default();
        let authority = headers.authority.unwrap_or_default();

        info!(
            stream_id,
            method = %String::from_utf8_lossy(method),
            path = %String::from_utf8_lossy(path),
            protocol = %String::from_utf8_lossy(protocol),
            authority = %String::from_utf8_lossy(authority),
            "request received"
        );

        // Authenticate supported proxy requests before parsing their target
        // or allocating any tunnel resources. Duplicate credentials are
        // rejected rather than choosing one ambiguously.
        if let Some(request) =
            classify_connect_request(method, protocol, authority, path, scheme, context.config)
        {
            let Some(auth) = context.auth else {
                Self::dispatch_connect(
                    h3,
                    quic,
                    pending_errors,
                    stream_id,
                    &request,
                    context,
                    pending,
                );
                return None;
            };

            // The cheap half runs here; only a well-formed request for the
            // configured user reaches the password hash, and that is
            // deliberately slow enough that it must not run on this thread.
            if headers.duplicate_proxy_authorization {
                context.metrics.record_auth_failure();
                warn!(stream_id, "duplicate proxy credentials");
                Self::send_auth_rejection(h3, quic, pending_errors, stream_id);
                return None;
            }
            match auth.precheck(headers.proxy_authorization) {
                AuthPrecheck::Authenticated => {
                    // A long batch of header events can cross the deadline
                    // after the shard began polling it.
                    if context
                        .first_auth_deadline
                        .is_some_and(|deadline| std::time::Instant::now() >= deadline)
                    {
                        return None;
                    }
                    *context.first_auth_deadline = None;
                    context.metrics.record_auth_cache_hit();
                    context.metrics.record_auth_success();
                    Self::dispatch_connect(
                        h3,
                        quic,
                        pending_errors,
                        stream_id,
                        &request,
                        context,
                        pending,
                    );
                    return None;
                }
                AuthPrecheck::Rejected => {
                    context.metrics.record_auth_failure();
                    warn!(stream_id, "proxy authentication failed");
                    Self::send_auth_rejection(h3, quic, pending_errors, stream_id);
                    return None;
                }
                AuthPrecheck::NeedsVerify {
                    credential,
                    password,
                } => {
                    return Some(PendingAuth {
                        stream_id,
                        credential,
                        password,
                        request,
                    });
                }
            }
        }

        // Default: 404 for anything we don't handle.
        Self::send_error_response(h3, quic, pending_errors, stream_id, 404);
        None
    }

    /// Act on an authorized CONNECT request.
    pub(super) fn dispatch_connect(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        pending_errors: &mut crate::connection::PendingErrorResponses,
        stream_id: u64,
        request: &ConnectRequest,
        context: &RequestContext<'_>,
        pending: &mut PendingConnectSetups,
    ) {
        match request {
            ConnectRequest::Tcp { authority } => match uri::parse_connect_authority(authority) {
                Ok(target) => {
                    info!(
                        stream_id,
                        host = %target.host,
                        port = target.port,
                        "standard CONNECT"
                    );
                    pending.tcp.push((stream_id, target));
                }
                Err(error) => {
                    warn!(stream_id, %error, "bad CONNECT authority");
                    Self::send_error_response(h3, quic, pending_errors, stream_id, 400);
                }
            },
            ConnectRequest::Udp { path } => {
                Self::handle_connect_udp(
                    h3,
                    quic,
                    pending_errors,
                    stream_id,
                    path,
                    context.config,
                    &mut pending.udp,
                );
            }
            ConnectRequest::Ip {
                path,
                standard,
                valid_pseudo_headers,
            } => {
                if let Err(status) =
                    prepare_connect_ip(path, *standard, *valid_pseudo_headers, context.config)
                {
                    Self::send_error_response(h3, quic, pending_errors, stream_id, status);
                    return;
                }
                // Address allocation can fail (pool exhaustion, bad fixed
                // lease), so defer the response with the setup. Sending 200
                // here would make a later 503 both illegal and invisible to
                // the client.
                info!(stream_id, "CONNECT-IP request accepted for setup");
                pending.ip.push(stream_id);
            }
        }
    }

    /// Parse CONNECT-UDP and defer resolution, policy, and socket setup.
    ///
    /// The eventual setup result sends either the final error or the first
    /// `200`, so a failed target cannot leave an already-accepted stream.
    fn handle_connect_udp(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        pending_errors: &mut crate::connection::PendingErrorResponses,
        stream_id: u64,
        path: &str,
        config: &ServerConfig,
        pending_udp_setups: &mut Vec<(u64, uri::UdpTarget, crate::datagram::DatagramHeader)>,
    ) {
        let target = match uri::parse_udp_path(path, &config.udp_proxy.uri_template) {
            Ok(target) => target,
            Err(e) => {
                warn!(stream_id, %e, "bad CONNECT-UDP URI");
                Self::send_error_response(h3, quic, pending_errors, stream_id, 400);
                return;
            }
        };

        info!(stream_id, host = %target.host, port = target.port, "CONNECT-UDP");
        let header = match crate::datagram::DatagramHeader::new(stream_id) {
            Ok(header) => header,
            Err(error) => {
                warn!(stream_id, %error, "cannot frame datagrams for stream");
                Self::send_error_response(h3, quic, pending_errors, stream_id, 400);
                return;
            }
        };
        pending_udp_setups.push((stream_id, target, header));
    }
}

#[cfg(test)]
mod tests {
    use super::accepts_connect_ip;
    use crate::config::IpProxySection;

    fn defaults() -> Vec<String> {
        IpProxySection::default().connect_protocols
    }

    #[test]
    fn default_list_accepts_both_the_registered_and_cloudflare_identifiers() {
        assert!(accepts_connect_ip(&defaults(), b"connect-ip"));
        assert!(accepts_connect_ip(&defaults(), b"cf-connect-ip"));
    }

    #[test]
    fn other_protocols_are_not_treated_as_connect_ip() {
        assert!(!accepts_connect_ip(&defaults(), b"connect-udp"));
        assert!(!accepts_connect_ip(&defaults(), b"websocket"));
        // A prefix or suffix of an accepted token must not match.
        assert!(!accepts_connect_ip(&defaults(), b"connect"));
        assert!(!accepts_connect_ip(&defaults(), b"cf-connect-ip-v2"));
    }

    #[test]
    fn absent_protocol_stays_with_the_tcp_path() {
        // An empty `:protocol` is a standard CONNECT; claiming it here would
        // divert every plain CONNECT into the IP tunnel.
        assert!(!accepts_connect_ip(&defaults(), b""));
        assert!(!accepts_connect_ip(&[String::new()], b""));
    }

    #[test]
    fn matching_is_case_sensitive() {
        // `:protocol` carries a registered token, not a header name.
        assert!(!accepts_connect_ip(&defaults(), b"CONNECT-IP"));
        assert!(!accepts_connect_ip(&defaults(), b"CF-Connect-IP"));
    }

    #[test]
    fn an_operator_can_narrow_the_list() {
        let strict = vec!["connect-ip".to_string()];
        assert!(accepts_connect_ip(&strict, b"connect-ip"));
        assert!(!accepts_connect_ip(&strict, b"cf-connect-ip"));

        // Or drop CONNECT-IP support without disabling the proxy section.
        assert!(!accepts_connect_ip(&[], b"connect-ip"));
    }
}
