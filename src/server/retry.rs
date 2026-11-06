//! Opaque, authenticated QUIC Retry tokens.
//!
//! Tokens are intentionally process-local: a fresh key on restart invalidates
//! outstanding tokens, which live for only a few seconds and carry no session
//! state. The client address is bound by IP rather than port so a NAT is free
//! to rewrite its mapping between the Retry packet and the second Initial.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::{Duration, Instant};

use ring::{aead, error::Unspecified, rand::SecureRandom};

use crate::config::QuicRetryMode;

const TOKEN_VERSION: u8 = 1;
const NONCE_LEN: usize = aead::NONCE_LEN;
const TAG_LEN: usize = 16;
// Bound the encoded version, timestamp, source IP, listener IP/port/scope,
// and length-prefixed original CID. Encrypt the fields without extra padding.
const MIN_BODY_LEN: usize = 1 + 8 + (1 + 4) + (1 + 4 + 2 + 4) + 1 + 1;
const MAX_BODY_LEN: usize = 1 + 8 + (1 + 16) + (1 + 16 + 2 + 4) + 1 + quiche::MAX_CONN_ID_LEN;
const MIN_TOKEN_LEN: usize = NONCE_LEN + MIN_BODY_LEN + TAG_LEN;
const MAX_TOKEN_LEN: usize = NONCE_LEN + MAX_BODY_LEN + TAG_LEN;
const TOKEN_CONTEXT: &[u8] = b"quic retry address validation";

pub(super) struct RetryTokenCodec {
    key: aead::LessSafeKey,
    epoch: Instant,
    ttl: Duration,
}

impl RetryTokenCodec {
    pub(super) fn new(key: &[u8], ttl: Duration) -> Result<Self, Unspecified> {
        Ok(Self {
            key: aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, key)?),
            epoch: Instant::now(),
            ttl,
        })
    }

    pub(super) fn mint(
        &self,
        source: SocketAddr,
        local: SocketAddr,
        original_dcid: &quiche::ConnectionId<'_>,
    ) -> Result<Vec<u8>, Unspecified> {
        if !(1..=quiche::MAX_CONN_ID_LEN).contains(&original_dcid.len()) {
            return Err(Unspecified);
        }
        let mut nonce = [0; NONCE_LEN];
        ring::rand::SystemRandom::new().fill(&mut nonce)?;
        let mut body = Vec::with_capacity(MAX_BODY_LEN + TAG_LEN);
        body.push(TOKEN_VERSION);
        body.extend_from_slice(&self.epoch.elapsed().as_secs().to_be_bytes());
        encode_ip(canonical_ip(source.ip()), &mut body);
        encode_socket(canonical_socket(local), &mut body);
        body.push(original_dcid.len() as u8);
        body.extend_from_slice(original_dcid);
        self.key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(TOKEN_CONTEXT),
            &mut body,
        )?;
        let mut token = Vec::with_capacity(NONCE_LEN + body.len());
        token.extend_from_slice(&nonce);
        token.extend_from_slice(&body);
        Ok(token)
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
        // Bound unauthenticated allocation and decryption before inspecting
        // any fields. No version, timestamp, address, or CID is sent in clear.
        if !(MIN_TOKEN_LEN..=MAX_TOKEN_LEN).contains(&token.len()) {
            return None;
        }
        let nonce: [u8; NONCE_LEN] = token[..NONCE_LEN].try_into().ok()?;
        let mut ciphertext = token[NONCE_LEN..].to_vec();
        let body = self
            .key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(TOKEN_CONTEXT),
                &mut ciphertext,
            )
            .ok()?;

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
        RetryTokenCodec::new(&[0x42; 32], ttl).unwrap()
    }

    #[test]
    fn token_round_trips_and_carries_the_original_dcid() {
        let codec = codec(Duration::from_secs(30));
        let source = "192.0.2.10:12345".parse().unwrap();
        let local = "[2001:db8::1]:443".parse().unwrap();
        let odcid = quiche::ConnectionId::from_ref(b"original-dcid");
        let token = codec.mint(source, local, &odcid).unwrap();
        assert_eq!(codec.validate(source, local, &token).unwrap(), odcid);
    }

    #[test]
    fn token_is_bound_to_source_ip_but_not_source_port() {
        let codec = codec(Duration::from_secs(30));
        let source = "192.0.2.10:12345".parse().unwrap();
        let local = "192.0.2.20:443".parse().unwrap();
        let odcid = quiche::ConnectionId::from_ref(b"original-dcid");
        let token = codec.mint(source, local, &odcid).unwrap();

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
        let mut token = codec.mint(source, local, &odcid).unwrap();
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
        let token = codec.mint(source, local, &odcid).unwrap();

        assert!(codec.validate(source, local, &token).is_some());
        assert!(codec.validate(source, other_scope, &token).is_none());
    }

    #[test]
    fn token_expires_after_its_ttl() {
        let codec = codec(Duration::from_secs(30));
        let source = "192.0.2.10:12345".parse().unwrap();
        let local = "192.0.2.20:443".parse().unwrap();
        let odcid = quiche::ConnectionId::from_ref(b"original-dcid");
        let token = codec.mint(source, local, &odcid).unwrap();

        assert!(codec.validate_at(source, local, &token, 30).is_some());
        assert!(codec.validate_at(source, local, &token, 31).is_none());
    }

    #[test]
    fn tokens_encrypt_bindings_with_fresh_nonces() {
        let codec = codec(Duration::from_secs(30));
        let source = "[2001:db8::1234]:23456".parse().unwrap();
        let local = "[2001:db8::5678]:443".parse().unwrap();
        let odcid = quiche::ConnectionId::from_ref(b"public-cid-sentinel!");
        let mut nonces = std::collections::HashSet::new();
        let mut lengths = std::collections::HashSet::new();
        for _ in 0..64 {
            let token = codec.mint(source, local, &odcid).unwrap();
            assert!((MIN_TOKEN_LEN..=MAX_TOKEN_LEN).contains(&token.len()));
            assert!(nonces.insert(token[..NONCE_LEN].to_vec()));
            lengths.insert(token.len());
            assert!(
                !token
                    .windows(odcid.len())
                    .any(|value| value == odcid.as_ref())
            );
            assert_eq!(codec.validate(source, local, &token).unwrap(), odcid);
        }
        assert_eq!(lengths.len(), 1, "token size follows its encoded fields");
    }

    #[test]
    fn token_bounds_cover_address_families_and_cid_lengths() {
        let codec = codec(Duration::from_secs(30));
        let sources = ["192.0.2.10:12345", "[2001:db8::10]:12345"];
        let listeners = ["192.0.2.20:443", "[2001:db8::20]:443"];
        let mut shortest = usize::MAX;
        let mut longest = 0;
        for source in sources {
            for local in listeners {
                for len in 1..=quiche::MAX_CONN_ID_LEN {
                    let source = source.parse().unwrap();
                    let local = local.parse().unwrap();
                    let odcid = quiche::ConnectionId::from_vec(vec![0x42; len]);
                    let token = codec.mint(source, local, &odcid).unwrap();
                    assert_eq!(codec.validate(source, local, &token).unwrap(), odcid);
                    shortest = shortest.min(token.len());
                    longest = longest.max(token.len());
                }
            }
        }
        assert_eq!(shortest, MIN_TOKEN_LEN);
        assert_eq!(longest, MAX_TOKEN_LEN);
    }

    #[test]
    fn tampering_truncation_append_and_wrong_key_are_rejected() {
        let codec = codec(Duration::from_secs(30));
        let source = "192.0.2.10:12345".parse().unwrap();
        let local = "192.0.2.20:443".parse().unwrap();
        let odcid = quiche::ConnectionId::from_ref(b"original-dcid");
        let token = codec.mint(source, local, &odcid).unwrap();
        for index in 0..token.len() {
            let mut changed = token.clone();
            changed[index] ^= 1;
            assert!(codec.validate(source, local, &changed).is_none());
            assert!(codec.validate(source, local, &token[..index]).is_none());
        }
        let mut appended = token.clone();
        appended.push(0);
        assert!(codec.validate(source, local, &appended).is_none());
        let other = RetryTokenCodec::new(&[0x24; 32], Duration::from_secs(30)).unwrap();
        assert!(other.validate(source, local, &token).is_none());
        assert!(
            codec
                .validate(source, local, &[0; MAX_TOKEN_LEN + 1])
                .is_none()
        );
        assert!(
            codec
                .mint(source, local, &quiche::ConnectionId::from_ref(b""))
                .is_err()
        );
        assert!(
            codec
                .mint(source, local, &quiche::ConnectionId::from_ref(&[0; 21]))
                .is_err()
        );
    }

    #[test]
    fn encrypted_tokens_keep_ipv4_mapped_address_equivalence() {
        let codec = codec(Duration::from_secs(30));
        let source = "[::ffff:192.0.2.10]:12345".parse().unwrap();
        let local = "[::ffff:192.0.2.20]:443".parse().unwrap();
        let odcid = quiche::ConnectionId::from_ref(b"original-dcid");
        let token = codec.mint(source, local, &odcid).unwrap();
        assert_eq!(
            codec
                .validate(
                    "192.0.2.10:54321".parse().unwrap(),
                    "192.0.2.20:443".parse().unwrap(),
                    &token
                )
                .unwrap(),
            odcid
        );
    }

    #[test]
    fn policy_switches_only_at_the_adaptive_threshold() {
        assert!(!retry_required(QuicRetryMode::Off, 1_000, 64));
        assert!(retry_required(QuicRetryMode::Always, 0, 64));
        assert!(!retry_required(QuicRetryMode::Adaptive, 63, 64));
        assert!(retry_required(QuicRetryMode::Adaptive, 64, 64));
    }
}
