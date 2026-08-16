// Error types with HTTP status code mapping.

use std::io;

/// Top-level error type for the MASQUE server.
#[derive(Debug, thiserror::Error)]
pub enum MasqueError {
    // ── Transport layer ───────────────────────────────────────────────
    #[error("QUIC error: {0}")]
    Quic(#[from] quiche::Error),

    #[error("HTTP/3 error: {0}")]
    H3(#[from] quiche::h3::Error),

    // ── Tunnel layer ──────────────────────────────────────────────────
    #[error("invalid URI template path: {0}")]
    BadRequest(String),

    #[error("target denied by policy: {0}")]
    Forbidden(String),

    #[error("DNS resolution failed for {host}: {source}")]
    DnsResolution { host: String, source: io::Error },

    #[error("upstream connection failed: {0}")]
    UpstreamConnect(io::Error),

    // ── Capsule layer ─────────────────────────────────────────────────
    #[error("malformed capsule: {0}")]
    CapsuleDecode(String),

    // ── TUN layer ─────────────────────────────────────────────────────
    #[error("TUN device error: {0}")]
    Tun(io::Error),

    #[error("address pool exhausted")]
    AddressPoolExhausted,

    // ── Generic I/O ───────────────────────────────────────────────────
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

impl MasqueError {
    /// Map this error to an HTTP status code for the CONNECT response.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::BadRequest(_) | Self::CapsuleDecode(_) => 400,
            Self::Forbidden(_) => 403,
            Self::DnsResolution { .. } | Self::UpstreamConnect(_) => 502,
            Self::AddressPoolExhausted => 503,
            _ => 500,
        }
    }

    /// Whether this error is recoverable at the stream level (i.e. the QUIC
    /// connection can stay open for other tunnels).
    pub fn is_stream_error(&self) -> bool {
        matches!(
            self,
            Self::BadRequest(_)
                | Self::Forbidden(_)
                | Self::DnsResolution { .. }
                | Self::UpstreamConnect(_)
                | Self::CapsuleDecode(_)
                | Self::Tun(_)
                | Self::AddressPoolExhausted
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_request_maps_to_400() {
        let err = MasqueError::BadRequest("bad path".into());
        assert_eq!(err.http_status(), 400);
    }

    #[test]
    fn capsule_decode_maps_to_400() {
        let err = MasqueError::CapsuleDecode("truncated".into());
        assert_eq!(err.http_status(), 400);
    }

    #[test]
    fn forbidden_maps_to_403() {
        let err = MasqueError::Forbidden("127.0.0.1".into());
        assert_eq!(err.http_status(), 403);
    }

    #[test]
    fn dns_resolution_maps_to_502() {
        let err = MasqueError::DnsResolution {
            host: "bad.example".into(),
            source: io::Error::other("nxdomain"),
        };
        assert_eq!(err.http_status(), 502);
    }

    #[test]
    fn upstream_connect_maps_to_502() {
        let err = MasqueError::UpstreamConnect(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "refused",
        ));
        assert_eq!(err.http_status(), 502);
    }

    #[test]
    fn address_pool_exhausted_maps_to_503() {
        let err = MasqueError::AddressPoolExhausted;
        assert_eq!(err.http_status(), 503);
    }

    #[test]
    fn io_error_maps_to_500() {
        let err = MasqueError::Io(io::Error::other("unexpected"));
        assert_eq!(err.http_status(), 500);
    }

    #[test]
    fn tun_error_maps_to_500() {
        let err = MasqueError::Tun(io::Error::other("device gone"));
        assert_eq!(err.http_status(), 500);
    }

    #[test]
    fn quic_error_maps_to_500() {
        let err = MasqueError::Quic(quiche::Error::Done);
        assert_eq!(err.http_status(), 500);
    }

    // ── is_stream_error ───────────────────────────────────────────────

    #[test]
    fn stream_errors_are_recoverable() {
        assert!(MasqueError::BadRequest("x".into()).is_stream_error());
        assert!(MasqueError::Forbidden("x".into()).is_stream_error());
        assert!(MasqueError::CapsuleDecode("x".into()).is_stream_error());
        assert!(MasqueError::AddressPoolExhausted.is_stream_error());
    }

    #[test]
    fn transport_errors_are_not_stream_errors() {
        assert!(!MasqueError::Quic(quiche::Error::Done).is_stream_error());
    }

    // ── Display ───────────────────────────────────────────────────────

    #[test]
    fn display_formats() {
        let err = MasqueError::BadRequest("missing target".into());
        assert_eq!(err.to_string(), "invalid URI template path: missing target");

        let err = MasqueError::AddressPoolExhausted;
        assert_eq!(err.to_string(), "address pool exhausted");
    }
}
