//! Authenticated QUIC Retry tokens.
//!
//! Tokens are intentionally process-local: a fresh key on restart invalidates
//! outstanding tokens, which live for only a few seconds and carry no session
//! state. The client address is bound by IP rather than port so a NAT is free
//! to rewrite its mapping between the Retry packet and the second Initial.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::{Duration, Instant};

use ring::hmac;

use crate::config::QuicRetryMode;

const TOKEN_VERSION: u8 = 1;
const TAG_LEN: usize = 32;

pub(super) struct RetryTokenCodec {
    key: hmac::Key,
    epoch: Instant,
    ttl: Duration,
}

impl RetryTokenCodec {
    pub(super) fn new(key: hmac::Key, ttl: Duration) -> Self {
        Self {
            key,
            epoch: Instant::now(),
            ttl,
        }
    }

    pub(super) fn mint(
        &self,
        source: SocketAddr,
        local: SocketAddr,
        original_dcid: &quiche::ConnectionId<'_>,
    ) -> Vec<u8> {
        let mut token = Vec::with_capacity(112);
        token.push(TOKEN_VERSION);
        token.extend_from_slice(&self.epoch.elapsed().as_secs().to_be_bytes());
        encode_ip(canonical_ip(source.ip()), &mut token);
        encode_socket(canonical_socket(local), &mut token);
        token.push(original_dcid.len() as u8);
        token.extend_from_slice(original_dcid);
        let tag = hmac::sign(&self.key, &token);
        token.extend_from_slice(tag.as_ref());
        token
    }

    pub(super) fn validate(
        &self,
        source: SocketAddr,
        local: SocketAddr,
        token: &[u8],
    ) -> Option<quiche::ConnectionId<'static>> {
        self.validate_at(source, local, token, self.epoch.elapsed().as_secs())
    }

    fn validate_at(
        &self,
        source: SocketAddr,
        local: SocketAddr,
        token: &[u8],
        now: u64,
    ) -> Option<quiche::ConnectionId<'static>> {
        if token.len() <= TAG_LEN {
            return None;
        }
        let (body, tag) = token.split_at(token.len() - TAG_LEN);
        hmac::verify(&self.key, body, tag).ok()?;

        let mut cursor = 0usize;
        if *take(body, &mut cursor, 1)?.first()? != TOKEN_VERSION {
            return None;
        }
        let issued = u64::from_be_bytes(take(body, &mut cursor, 8)?.try_into().ok()?);
        if issued > now || now - issued > self.ttl.as_secs() {
            return None;
        }

        if decode_ip(body, &mut cursor)? != canonical_ip(source.ip()) {
            return None;
        }
        if decode_socket(body, &mut cursor)? != canonical_socket(local) {
            return None;
        }
        let odcid_len = *take(body, &mut cursor, 1)?.first()? as usize;
        if !(1..=quiche::MAX_CONN_ID_LEN).contains(&odcid_len) {
            return None;
        }
        let odcid = take(body, &mut cursor, odcid_len)?;
        if cursor != body.len() {
            return None;
        }
        Some(quiche::ConnectionId::from_vec(odcid.to_vec()))
    }
}

pub(super) fn retry_required(
    mode: QuicRetryMode,
    active_connections: usize,
    adaptive_threshold: usize,
) -> bool {
    match mode {
        QuicRetryMode::Off => false,
        QuicRetryMode::Always => true,
        QuicRetryMode::Adaptive => active_connections >= adaptive_threshold,
    }
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Option<&'a [u8]> {
    let end = cursor.checked_add(len)?;
    let value = bytes.get(*cursor..end)?;
    *cursor = end;
    Some(value)
}

fn encode_ip(ip: IpAddr, out: &mut Vec<u8>) {
    match ip {
        IpAddr::V4(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(6);
            out.extend_from_slice(&ip.octets());
        }
    }
}

fn decode_ip(bytes: &[u8], cursor: &mut usize) -> Option<IpAddr> {
    match *take(bytes, cursor, 1)?.first()? {
        4 => Some(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(take(bytes, cursor, 4)?).ok()?,
        ))),
        6 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(take(bytes, cursor, 16)?).ok()?,
        ))),
        _ => None,
    }
}

fn encode_socket(address: SocketAddr, out: &mut Vec<u8>) {
    encode_ip(address.ip(), out);
    out.extend_from_slice(&address.port().to_be_bytes());
    let scope_id = match address {
        SocketAddr::V4(_) => 0,
        SocketAddr::V6(address) => address.scope_id(),
    };
    out.extend_from_slice(&scope_id.to_be_bytes());
}

fn decode_socket(bytes: &[u8], cursor: &mut usize) -> Option<SocketAddr> {
    let ip = decode_ip(bytes, cursor)?;
    let port = u16::from_be_bytes(take(bytes, cursor, 2)?.try_into().ok()?);
    let scope_id = u32::from_be_bytes(take(bytes, cursor, 4)?.try_into().ok()?);
    match ip {
        IpAddr::V4(ip) if scope_id == 0 => Some(SocketAddr::new(IpAddr::V4(ip), port)),
        IpAddr::V4(_) => None,
        IpAddr::V6(ip) => Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope_id))),
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

fn canonical_socket(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V4(address) => SocketAddr::V4(address),
        SocketAddr::V6(address) => match address.ip().to_ipv4_mapped() {
            Some(ip) => SocketAddr::new(IpAddr::V4(ip), address.port()),
            None => SocketAddr::V6(SocketAddrV6::new(
                *address.ip(),
                address.port(),
                0,
                address.scope_id(),
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codec(ttl: Duration) -> RetryTokenCodec {
        RetryTokenCodec::new(hmac::Key::new(hmac::HMAC_SHA256, &[0x42; 32]), ttl)
    }

    #[test]
    fn token_round_trips_and_carries_the_original_dcid() {
        let codec = codec(Duration::from_secs(30));
        let source = "192.0.2.10:12345".parse().unwrap();
        let local = "[2001:db8::1]:443".parse().unwrap();
        let odcid = quiche::ConnectionId::from_ref(b"original-dcid");
        let token = codec.mint(source, local, &odcid);
        assert_eq!(codec.validate(source, local, &token).unwrap(), odcid);
    }

    #[test]
    fn token_is_bound_to_source_ip_but_not_source_port() {
        let codec = codec(Duration::from_secs(30));
        let source = "192.0.2.10:12345".parse().unwrap();
        let local = "192.0.2.20:443".parse().unwrap();
        let odcid = quiche::ConnectionId::from_ref(b"original-dcid");
        let token = codec.mint(source, local, &odcid);

        assert!(
            codec
                .validate("192.0.2.10:54321".parse().unwrap(), local, &token)
                .is_some()
        );
        assert!(
            codec
                .validate("192.0.2.11:12345".parse().unwrap(), local, &token)
                .is_none()
        );
    }

    #[test]
    fn token_is_bound_to_listener_and_authenticated() {
        let codec = codec(Duration::from_secs(30));
        let source = "192.0.2.10:12345".parse().unwrap();
        let local = "192.0.2.20:443".parse().unwrap();
        let odcid = quiche::ConnectionId::from_ref(b"original-dcid");
        let mut token = codec.mint(source, local, &odcid);
        assert!(
            codec
                .validate(source, "192.0.2.20:8443".parse().unwrap(), &token)
                .is_none()
        );
        token[10] ^= 1;
        assert!(codec.validate(source, local, &token).is_none());
    }

    #[test]
    fn token_keeps_a_link_local_listener_scope() {
        let codec = codec(Duration::from_secs(30));
        let source = "[2001:db8::10]:12345".parse().unwrap();
        let local = "[fe80::1%2]:443".parse().unwrap();
        let other_scope = "[fe80::1%3]:443".parse().unwrap();
        let odcid = quiche::ConnectionId::from_ref(b"original-dcid");
        let token = codec.mint(source, local, &odcid);

        assert!(codec.validate(source, local, &token).is_some());
        assert!(codec.validate(source, other_scope, &token).is_none());
    }

    #[test]
    fn token_expires_after_its_ttl() {
        let codec = codec(Duration::from_secs(30));
        let source = "192.0.2.10:12345".parse().unwrap();
        let local = "192.0.2.20:443".parse().unwrap();
        let odcid = quiche::ConnectionId::from_ref(b"original-dcid");
        let token = codec.mint(source, local, &odcid);

        assert!(codec.validate_at(source, local, &token, 30).is_some());
        assert!(codec.validate_at(source, local, &token, 31).is_none());
    }

    #[test]
    fn policy_switches_only_at_the_adaptive_threshold() {
        assert!(!retry_required(QuicRetryMode::Off, 1_000, 64));
        assert!(retry_required(QuicRetryMode::Always, 0, 64));
        assert!(!retry_required(QuicRetryMode::Adaptive, 63, 64));
        assert!(retry_required(QuicRetryMode::Adaptive, 64, 64));
    }
}
