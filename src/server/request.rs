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
    Tcp { authority: String },
    Udp { path: String },
    Ip,
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
        Some(ConnectRequest::Ip)
    } else {
        None
    }
}

/// Shared request dependencies passed together to keep dispatch APIs focused.
pub(super) struct RequestContext<'a> {
    pub(super) config: &'a ServerConfig,
    pub(super) auth: Option<&'a SharedBasicAuthenticator>,
}

impl Shard {
    /// Handle an incoming HTTP/3 request.
    pub(super) fn handle_request(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        headers: &[quiche::h3::Header],
        context: &RequestContext<'_>,
        pending: &mut PendingConnectSetups,
    ) -> Option<PendingAuth> {
        // One pass over the header list, borrowing the values rather than
        // copying each one into an owned String.
        let mut method: &[u8] = b"";
        let mut path: &[u8] = b"";
        let mut protocol: &[u8] = b"";
        let mut authority: &[u8] = b"";
        let mut proxy_authorization: Option<&[u8]> = None;
        let mut duplicate_proxy_authorization = false;

        for header in headers {
            match header.name() {
                b":method" => method = header.value(),
                b":path" => path = header.value(),
                b":protocol" => protocol = header.value(),
                b":authority" => authority = header.value(),
                b"proxy-authorization" => {
                    duplicate_proxy_authorization |=
                        proxy_authorization.replace(header.value()).is_some();
                }
                _ => {}
            }
        }

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
            classify_connect_request(method, protocol, authority, path, context.config)
        {
            let Some(auth) = context.auth else {
                Self::dispatch_connect(h3, quic, stream_id, &request, context, pending);
                return None;
            };

            // The cheap half runs here; only a well-formed request for the
            // configured user reaches the password hash, and that is
            // deliberately slow enough that it must not run on this thread.
            if duplicate_proxy_authorization {
                warn!(stream_id, "duplicate proxy credentials");
                Self::send_proxy_auth_required(h3, quic, stream_id);
                return None;
            }
            match auth.precheck(proxy_authorization) {
                AuthPrecheck::Rejected => {
                    warn!(stream_id, "proxy authentication failed");
                    Self::send_proxy_auth_required(h3, quic, stream_id);
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
        Self::send_error_response(h3, quic, stream_id, 404);
        None
    }

    /// Act on an authorized CONNECT request.
    pub(super) fn dispatch_connect(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
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
                    Self::send_error_response(h3, quic, stream_id, 400);
                }
            },
            ConnectRequest::Udp { path } => {
                Self::handle_connect_udp(
                    h3,
                    quic,
                    stream_id,
                    path,
                    context.config,
                    &mut pending.udp,
                );
            }
            ConnectRequest::Ip => {
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
        stream_id: u64,
        path: &str,
        config: &ServerConfig,
        pending_udp_setups: &mut Vec<(u64, uri::UdpTarget, crate::datagram::DatagramHeader)>,
    ) {
        let target = match uri::parse_udp_path(path, &config.udp_proxy.uri_template) {
            Ok(target) => target,
            Err(e) => {
                warn!(stream_id, %e, "bad CONNECT-UDP URI");
                Self::send_error_response(h3, quic, stream_id, 400);
                return;
            }
        };

        info!(stream_id, host = %target.host, port = target.port, "CONNECT-UDP");
        let header = match crate::datagram::DatagramHeader::new(stream_id) {
            Ok(header) => header,
            Err(error) => {
                warn!(stream_id, %error, "cannot frame datagrams for stream");
                Self::send_error_response(h3, quic, stream_id, 400);
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
