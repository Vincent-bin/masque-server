//! CONNECT request classification, authentication precheck, and dispatch.

use quiche::h3::NameValue;
use tracing::{info, warn};

use crate::auth::{AuthPrecheck, BasicAuthenticator};
use crate::config::ServerConfig;
use crate::policy::TargetPolicy;
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
    pub(super) password: zeroize::Zeroizing<Vec<u8>>,
    pub(super) request: ConnectRequest,
}

/// Tunnel work created while request headers are processed.
///
/// Setup itself runs after the HTTP/3 connection borrow is released.
#[derive(Default)]
pub(super) struct PendingConnectSetups {
    pub(super) tcp: Vec<(u64, uri::TcpTarget)>,
    pub(super) udp: Vec<(u64, uri::UdpTarget)>,
    pub(super) ip: Vec<u64>,
}

impl PendingConnectSetups {
    pub(super) fn is_empty(&self) -> bool {
        self.tcp.is_empty() && self.udp.is_empty() && self.ip.is_empty()
    }
}

/// Shared request dependencies passed together to keep dispatch APIs focused.
pub(super) struct RequestContext<'a> {
    pub(super) config: &'a ServerConfig,
    pub(super) auth: Option<&'a BasicAuthenticator>,
    pub(super) udp_policy: &'a TargetPolicy,
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
        if method == b"CONNECT" {
            let request = if protocol.is_empty() && context.config.tcp_proxy.enabled {
                Some(ConnectRequest::Tcp {
                    authority: String::from_utf8_lossy(authority).into_owned(),
                })
            } else if protocol == b"connect-udp" && context.config.udp_proxy.enabled {
                Some(ConnectRequest::Udp {
                    path: String::from_utf8_lossy(path).into_owned(),
                })
            } else if protocol == b"connect-ip" && context.config.ip_proxy.enabled {
                Some(ConnectRequest::Ip)
            } else {
                None
            };

            if let Some(request) = request {
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
                    AuthPrecheck::NeedsVerify(password) => {
                        return Some(PendingAuth {
                            stream_id,
                            password,
                            request,
                        });
                    }
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
                    context.udp_policy,
                    &mut pending.udp,
                );
            }
            ConnectRequest::Ip => {
                Self::handle_connect_ip_response(h3, quic, stream_id, &mut pending.ip);
            }
        }
    }

    /// Send 200 OK for CONNECT-IP and defer address allocation.
    fn handle_connect_ip_response(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        pending_ip_setups: &mut Vec<u64>,
    ) {
        info!(stream_id, "CONNECT-IP request accepted");

        let headers = vec![
            quiche::h3::Header::new(b":status", b"200"),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        ];

        if let Err(e) = h3.send_response(quic, stream_id, &headers, false) {
            warn!(stream_id, %e, "failed to send CONNECT-IP 200");
            return;
        }

        pending_ip_setups.push(stream_id);
    }

    /// Parse and authorize CONNECT-UDP, respond, then defer socket creation.
    fn handle_connect_udp(
        h3: &mut quiche::h3::Connection,
        quic: &mut quiche::Connection,
        stream_id: u64,
        path: &str,
        config: &ServerConfig,
        udp_policy: &TargetPolicy,
        pending_udp_setups: &mut Vec<(u64, uri::UdpTarget)>,
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

        match target.resolved_ips() {
            Ok(ips) => {
                if !udp_policy.all_allowed(&ips) {
                    warn!(stream_id, host = %target.host, "target denied by policy");
                    Self::send_error_response(h3, quic, stream_id, 403);
                    return;
                }
            }
            Err(e) => {
                warn!(stream_id, %e, "DNS resolution failed for policy check");
                Self::send_error_response(h3, quic, stream_id, 502);
                return;
            }
        }

        let headers = vec![
            quiche::h3::Header::new(b":status", b"200"),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        ];

        if let Err(e) = h3.send_response(quic, stream_id, &headers, false) {
            warn!(stream_id, %e, "failed to send CONNECT-UDP 200");
            return;
        }

        pending_udp_setups.push((stream_id, target));
    }
}
