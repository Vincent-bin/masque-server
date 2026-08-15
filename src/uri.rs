// URI template parsing for CONNECT-UDP and CONNECT-IP paths.
//
// CONNECT-UDP: /.well-known/masque/udp/{target_host}/{target_port}/
// CONNECT-IP:  /.well-known/masque/ip/{target}/{ipproto}/

use std::net::{IpAddr, SocketAddr};

/// Parsed CONNECT-UDP target from the URI path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpTarget {
    pub host: String,
    pub port: u16,
}

/// A standard CONNECT target parsed from the `:authority` pseudo-header.
pub type TcpTarget = UdpTarget;

/// Parsed CONNECT-IP target from the URI path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpTarget {
    /// Target host/prefix, or None if the tunnel carries all traffic.
    pub target: Option<String>,
    /// IP protocol number, or None for wildcard (*).
    pub ipproto: Option<u8>,
}

/// Error from URI parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UriError {
    /// Path doesn't match expected prefix.
    PathMismatch,
    /// Missing required segment (target_host or target_port).
    MissingSegment(String),
    /// Invalid port number.
    InvalidPort(String),
    /// Invalid IP protocol number.
    InvalidProtocol(String),
}

impl std::fmt::Display for UriError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UriError::PathMismatch => {
                write!(f, "path does not match URI template")
            }
            UriError::MissingSegment(s) => {
                write!(f, "missing URI segment: {s}")
            }
            UriError::InvalidPort(s) => write!(f, "invalid port: {s}"),
            UriError::InvalidProtocol(s) => write!(f, "invalid protocol: {s}"),
        }
    }
}

impl std::error::Error for UriError {}

/// Percent-decode a URI component (minimal: %XX sequences).
fn percent_decode(s: &str) -> String {
    let mut result = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                result.push(byte);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).into_owned()
}

/// Parse a CONNECT-UDP URI path.
///
/// The `template` is the configured prefix (e.g.
/// `/.well-known/masque/udp/`). The two trailing segments are
/// `{target_host}/{target_port}/`.
pub fn parse_udp_path(path: &str, template: &str) -> Result<UdpTarget, UriError> {
    let udp_prefix = extract_prefix(template);

    let rest = path
        .strip_prefix(&udp_prefix)
        .ok_or(UriError::PathMismatch)?;

    // Split remaining path into segments, filtering empty
    let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();

    if segments.is_empty() {
        return Err(UriError::MissingSegment("target_host".into()));
    }
    if segments.len() < 2 {
        return Err(UriError::MissingSegment("target_port".into()));
    }

    let host = percent_decode(segments[0]);
    let port_str = percent_decode(segments[1]);
    let port: u16 = port_str
        .parse()
        .map_err(|_| UriError::InvalidPort(port_str.clone()))?;

    if port == 0 {
        return Err(UriError::InvalidPort("0".into()));
    }

    Ok(UdpTarget { host, port })
}

/// Parse the authority form used by standard HTTP CONNECT.
///
/// IPv6 literals must use brackets (for example `[2001:db8::1]:443`).
pub fn parse_connect_authority(authority: &str) -> Result<TcpTarget, UriError> {
    if authority.is_empty()
        || authority
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || authority.contains(['/', '@'])
    {
        return Err(UriError::PathMismatch);
    }

    let (host, port_str) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or(UriError::MissingSegment("target_port".into()))?;
        if host.is_empty() || host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(UriError::PathMismatch);
        }
        (host, port)
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or(UriError::MissingSegment("target_port".into()))?;
        if host.is_empty() || host.contains(':') {
            return Err(UriError::PathMismatch);
        }
        (host, port)
    };

    let port = port_str
        .parse::<u16>()
        .map_err(|_| UriError::InvalidPort(port_str.into()))?;
    if port == 0 {
        return Err(UriError::InvalidPort("0".into()));
    }

    Ok(TcpTarget {
        host: host.into(),
        port,
    })
}

/// Parse a CONNECT-IP URI path.
///
/// Both `{target}` and `{ipproto}` are optional per RFC 9484.
pub fn parse_ip_path(path: &str, template: &str) -> Result<IpTarget, UriError> {
    let ip_prefix = extract_prefix(template);

    let rest = path
        .strip_prefix(&ip_prefix)
        .ok_or(UriError::PathMismatch)?;

    let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();

    let target = segments.first().map(|s| percent_decode(s));
    let ipproto = match segments.get(1) {
        Some(&"*") | None => None,
        Some(s) => {
            let decoded = percent_decode(s);
            let proto: u8 = decoded
                .parse()
                .map_err(|_| UriError::InvalidProtocol(decoded.clone()))?;
            Some(proto)
        }
    };

    Ok(IpTarget { target, ipproto })
}

/// Extract the static prefix from a URI template (everything before the first `{`).
fn extract_prefix(template: &str) -> String {
    match template.find('{') {
        Some(pos) => template[..pos].to_string(),
        None => template.to_string(),
    }
}

impl UdpTarget {
    /// Resolve the target to a socket address.
    ///
    /// If the host is already an IP address, no DNS lookup is performed.
    pub fn resolve(&self) -> Result<Vec<SocketAddr>, std::io::Error> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<SocketAddr> = (self.host.as_str(), self.port).to_socket_addrs()?.collect();
        if addrs.is_empty() {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no addresses found for {}:{}", self.host, self.port),
            ))
        } else {
            Ok(addrs)
        }
    }

    /// Get the target IP addresses (for policy checking).
    pub fn resolved_ips(&self) -> Result<Vec<IpAddr>, std::io::Error> {
        Ok(self.resolve()?.into_iter().map(|a| a.ip()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UDP_TEMPLATE: &str = "/.well-known/masque/udp/{target_host}/{target_port}/";
    const IP_TEMPLATE: &str = "/.well-known/masque/ip/{target}/{ipproto}/";

    // ── CONNECT-UDP parsing ───────────────────────────────────────────

    #[test]
    fn parse_udp_basic() {
        let target =
            parse_udp_path("/.well-known/masque/udp/192.0.2.1/443/", UDP_TEMPLATE).unwrap();
        assert_eq!(target.host, "192.0.2.1");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn parse_udp_hostname() {
        let target =
            parse_udp_path("/.well-known/masque/udp/dns.example.com/53/", UDP_TEMPLATE).unwrap();
        assert_eq!(target.host, "dns.example.com");
        assert_eq!(target.port, 53);
    }

    #[test]
    fn parse_udp_ipv6() {
        // IPv6 addresses in URI are percent-encoded colons: %3A
        let target = parse_udp_path(
            "/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/",
            UDP_TEMPLATE,
        )
        .unwrap();
        assert_eq!(target.host, "2001:db8::1");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn parse_udp_no_trailing_slash() {
        let target = parse_udp_path("/.well-known/masque/udp/10.0.0.1/8080", UDP_TEMPLATE).unwrap();
        assert_eq!(target.host, "10.0.0.1");
        assert_eq!(target.port, 8080);
    }

    #[test]
    fn parse_udp_missing_host() {
        let err = parse_udp_path("/.well-known/masque/udp/", UDP_TEMPLATE).unwrap_err();
        assert_eq!(err, UriError::MissingSegment("target_host".into()));
    }

    #[test]
    fn parse_udp_missing_port() {
        let err = parse_udp_path("/.well-known/masque/udp/10.0.0.1/", UDP_TEMPLATE).unwrap_err();
        assert_eq!(err, UriError::MissingSegment("target_port".into()));
    }

    #[test]
    fn parse_udp_invalid_port_string() {
        let err =
            parse_udp_path("/.well-known/masque/udp/10.0.0.1/abc/", UDP_TEMPLATE).unwrap_err();
        assert!(matches!(err, UriError::InvalidPort(_)));
    }

    #[test]
    fn parse_udp_port_zero() {
        let err = parse_udp_path("/.well-known/masque/udp/10.0.0.1/0/", UDP_TEMPLATE).unwrap_err();
        assert!(matches!(err, UriError::InvalidPort(_)));
    }

    #[test]
    fn parse_udp_port_overflow() {
        let err =
            parse_udp_path("/.well-known/masque/udp/10.0.0.1/99999/", UDP_TEMPLATE).unwrap_err();
        assert!(matches!(err, UriError::InvalidPort(_)));
    }

    #[test]
    fn parse_udp_wrong_prefix() {
        let err = parse_udp_path("/other/path/10.0.0.1/443/", UDP_TEMPLATE).unwrap_err();
        assert_eq!(err, UriError::PathMismatch);
    }

    // ── CONNECT-IP parsing ────────────────────────────────────────────

    #[test]
    fn parse_connect_authority_hostname() {
        assert_eq!(
            parse_connect_authority("example.com:443").unwrap(),
            TcpTarget {
                host: "example.com".into(),
                port: 443
            }
        );
    }

    #[test]
    fn parse_connect_authority_ipv4() {
        assert_eq!(
            parse_connect_authority("192.0.2.1:8443").unwrap(),
            TcpTarget {
                host: "192.0.2.1".into(),
                port: 8443
            }
        );
    }

    #[test]
    fn parse_connect_authority_ipv6() {
        assert_eq!(
            parse_connect_authority("[2001:db8::1]:443").unwrap(),
            TcpTarget {
                host: "2001:db8::1".into(),
                port: 443
            }
        );
    }

    #[test]
    fn parse_connect_authority_rejects_invalid_values() {
        for authority in [
            "example.com",
            "example.com:0",
            "example.com:99999",
            "2001:db8::1:443",
            "[not-v6]:443",
            "user@example.com:443",
            "example.com:443/path",
            "example.com:44 3",
        ] {
            assert!(parse_connect_authority(authority).is_err(), "{authority}");
        }
    }

    #[test]
    fn parse_ip_full_vpn_mode() {
        // No target, no ipproto → full VPN tunnel
        let target = parse_ip_path("/.well-known/masque/ip/", IP_TEMPLATE).unwrap();
        assert_eq!(target.target, None);
        assert_eq!(target.ipproto, None);
    }

    #[test]
    fn parse_ip_with_target() {
        let target = parse_ip_path("/.well-known/masque/ip/192.0.2.0/", IP_TEMPLATE).unwrap();
        assert_eq!(target.target, Some("192.0.2.0".into()));
        assert_eq!(target.ipproto, None);
    }

    #[test]
    fn parse_ip_with_target_and_wildcard() {
        let target = parse_ip_path("/.well-known/masque/ip/192.0.2.0/*/", IP_TEMPLATE).unwrap();
        assert_eq!(target.target, Some("192.0.2.0".into()));
        assert_eq!(target.ipproto, None); // wildcard = all protocols
    }

    #[test]
    fn parse_ip_with_target_and_proto() {
        let target = parse_ip_path("/.well-known/masque/ip/192.0.2.0/6/", IP_TEMPLATE).unwrap();
        assert_eq!(target.target, Some("192.0.2.0".into()));
        assert_eq!(target.ipproto, Some(6)); // TCP
    }

    #[test]
    fn parse_ip_with_ipv6_target() {
        let target =
            parse_ip_path("/.well-known/masque/ip/2001%3Adb8%3A%3A/17/", IP_TEMPLATE).unwrap();
        assert_eq!(target.target, Some("2001:db8::".into()));
        assert_eq!(target.ipproto, Some(17)); // UDP
    }

    #[test]
    fn parse_ip_invalid_proto() {
        let err = parse_ip_path("/.well-known/masque/ip/10.0.0.0/abc/", IP_TEMPLATE).unwrap_err();
        assert!(matches!(err, UriError::InvalidProtocol(_)));
    }

    #[test]
    fn parse_ip_wrong_prefix() {
        let err = parse_ip_path("/other/path/", IP_TEMPLATE).unwrap_err();
        assert_eq!(err, UriError::PathMismatch);
    }

    // ── percent_decode ────────────────────────────────────────────────

    #[test]
    fn percent_decode_colons() {
        assert_eq!(percent_decode("2001%3Adb8%3A%3A1"), "2001:db8::1");
    }

    #[test]
    fn percent_decode_noop() {
        assert_eq!(percent_decode("hello"), "hello");
    }

    #[test]
    fn percent_decode_space() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
    }

    // ── extract_prefix ────────────────────────────────────────────────

    #[test]
    fn extract_prefix_udp_template() {
        assert_eq!(extract_prefix(UDP_TEMPLATE), "/.well-known/masque/udp/");
    }

    #[test]
    fn extract_prefix_ip_template() {
        assert_eq!(extract_prefix(IP_TEMPLATE), "/.well-known/masque/ip/");
    }

    #[test]
    fn extract_prefix_no_braces() {
        assert_eq!(extract_prefix("/static/path/"), "/static/path/");
    }

    // ── UdpTarget::resolve ────────────────────────────────────────────

    #[test]
    fn resolve_ip_address() {
        let target = UdpTarget {
            host: "127.0.0.1".into(),
            port: 53,
        };
        let addrs = target.resolve().unwrap();
        assert!(!addrs.is_empty());
        assert_eq!(addrs[0].ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(addrs[0].port(), 53);
    }

    #[test]
    fn resolve_ipv6_address() {
        let target = UdpTarget {
            host: "::1".into(),
            port: 443,
        };
        let addrs = target.resolve().unwrap();
        assert!(!addrs.is_empty());
        assert_eq!(addrs[0].port(), 443);
    }
}
