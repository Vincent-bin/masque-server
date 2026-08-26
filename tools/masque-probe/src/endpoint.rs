use std::collections::HashSet;
use std::net::{SocketAddr, ToSocketAddrs};

use crate::report::ProbeFailure;

#[derive(Debug, Clone)]
pub struct Authority {
    pub original: String,
    pub host: String,
    pub port: u16,
}

impl Authority {
    pub fn parse(value: &str, what: &'static str) -> Result<Self, ProbeFailure> {
        if value.contains('@') {
            return Err(ProbeFailure::new(
                "INVALID_ENDPOINT",
                format!("invalid {what}: user information is not allowed"),
            ));
        }
        let parsed = masque::uri::parse_connect_authority(value).map_err(|error| {
            ProbeFailure::new(
                "INVALID_ENDPOINT",
                format!("invalid {what} {value:?}: {error}"),
            )
        })?;
        if parsed.port == 0 {
            return Err(ProbeFailure::new(
                "INVALID_ENDPOINT",
                format!("invalid {what}: port must be between 1 and 65535"),
            ));
        }
        Ok(Self {
            original: value.to_owned(),
            host: parsed.host,
            port: parsed.port,
        })
    }

    pub fn resolve(&self) -> Result<Vec<SocketAddr>, ProbeFailure> {
        let mut seen = HashSet::new();
        let addresses = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|error| {
                ProbeFailure::new(
                    "DNS_ERROR",
                    format!("could not resolve {}: {error}", self.original),
                )
            })?
            .filter(|address| seen.insert(*address))
            .take(8)
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(ProbeFailure::new(
                "DNS_ERROR",
                format!("{} resolved to no addresses", self.original),
            ));
        }
        Ok(addresses)
    }
}

pub fn validate_server_name(value: &str) -> Result<(), ProbeFailure> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || value.contains(['/', '@', ':'])
    {
        return Err(ProbeFailure::new(
            "INVALID_SERVER_NAME",
            "--server-name must be one DNS name without a port",
        ));
    }
    Ok(())
}

pub fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dns_and_ipv6_authorities() {
        let dns = Authority::parse("proxy.example:8449", "endpoint").unwrap();
        assert_eq!(dns.host, "proxy.example");
        assert_eq!(dns.port, 8449);

        let ipv6 = Authority::parse("[2001:db8::1]:443", "endpoint").unwrap();
        assert_eq!(ipv6.host, "2001:db8::1");
        assert_eq!(ipv6.port, 443);
    }

    #[test]
    fn rejects_user_information_and_port_zero() {
        assert!(Authority::parse("user@proxy.example:443", "endpoint").is_err());
        assert!(Authority::parse("proxy.example:0", "endpoint").is_err());
    }

    #[test]
    fn percent_encodes_ipv6_for_connect_udp_path() {
        assert_eq!(encode_path_segment("2001:db8::1"), "2001%3Adb8%3A%3A1");
    }
}
