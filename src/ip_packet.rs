// Minimal IP packet header parser for CONNECT-IP routing.
//
// Extracts source and destination addresses from IPv4/IPv6 headers without
// pulling in a full packet parsing library. Only the fields needed for
// routing decisions are extracted.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Extracted header info from an IP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpPacketInfo {
    pub version: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    /// Next header / protocol number (e.g. 6=TCP, 17=UDP).
    pub protocol: u8,
    /// Total packet length (from the IP header).
    pub total_len: u16,
}

/// Errors from parsing an IP packet header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Packet too short to contain even a version nibble.
    TooShort,
    /// Unrecognised IP version (neither 4 nor 6).
    UnknownVersion(u8),
    /// IPv4 header length field is invalid (< 20 bytes).
    InvalidIhl(u8),
    /// Packet is shorter than the header indicates.
    Truncated,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::TooShort => write!(f, "packet too short"),
            ParseError::UnknownVersion(v) => write!(f, "unknown IP version {v}"),
            ParseError::InvalidIhl(ihl) => write!(f, "invalid IPv4 IHL: {ihl}"),
            ParseError::Truncated => write!(f, "packet truncated"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse the IP header from a raw packet and extract routing-relevant fields.
pub fn parse(packet: &[u8]) -> Result<IpPacketInfo, ParseError> {
    if packet.is_empty() {
        return Err(ParseError::TooShort);
    }

    let version = packet[0] >> 4;
    match version {
        4 => parse_v4(packet),
        6 => parse_v6(packet),
        v => Err(ParseError::UnknownVersion(v)),
    }
}

/// Extract source IP from a raw packet.
///
/// The relay path only needs one address per packet, so this reads that field
/// directly instead of building a full [`IpPacketInfo`].
pub fn src_addr(packet: &[u8]) -> Result<IpAddr, ParseError> {
    addr_at(packet, 12, 8)
}

/// Extract destination IP from a raw packet.
pub fn dst_addr(packet: &[u8]) -> Result<IpAddr, ParseError> {
    addr_at(packet, 16, 24)
}

/// A destination ACL must not be bypassed by a later source-routing hop.
/// Reject IPv4 source-route options and IPv6 routing headers, including those
/// after extension headers in initial/atomic fragments. Noninitial fragment
/// payload is opaque. Ordinary transport packets take a short fixed path;
/// extension traversal is bounded by the packet length.
pub(crate) fn has_safe_routing(packet: &[u8]) -> bool {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => {
            let header_len = usize::from(packet[0] & 15) * 4;
            if header_len < 20 || packet.len() < header_len {
                return false;
            }
            let mut offset = 20;
            while offset < header_len {
                match packet[offset] {
                    0 => break,
                    1 => {
                        offset += 1;
                        continue;
                    }
                    131 | 137 => return false,
                    _ => {}
                }
                let Some(&length) = packet.get(offset + 1) else {
                    return false;
                };
                if length < 2 || offset + usize::from(length) > header_len {
                    return false;
                }
                offset += usize::from(length);
            }
            true
        }
        Some(6) if packet.len() >= 40 => {
            let mut next = packet[6];
            let mut offset = 40;
            loop {
                if next == 43 {
                    return false;
                }
                if !matches!(next, 0 | 60 | 44 | 51) {
                    return true;
                }
                let Some(header) = packet.get(offset..).filter(|header| header.len() >= 8) else {
                    return false;
                };
                if next == 44 && u16::from_be_bytes([header[2], header[3]]) & 0xfff8 != 0 {
                    // RFC 8200 section 4.5: only offset zero contains the
                    // post-fragment header chain. Later fragments contain
                    // opaque data, and their Next Header is not used for
                    // reassembly. Every fragment's preceding headers have
                    // already been checked; the mandatory first fragment
                    // must pass the full chain check before reaching TUN.
                    return true;
                }
                let length = match next {
                    44 => 8,
                    51 => (usize::from(header[1]) + 2) * 4,
                    _ => (usize::from(header[1]) + 1) * 8,
                };
                if length > header.len() {
                    return false;
                }
                next = header[0];
                offset += length;
            }
        }
        _ => false,
    }
}

/// Read the address at `v4_offset` (IPv4) or `v6_offset` (IPv6), after the
/// same header validation `parse` performs.
#[inline]
fn addr_at(packet: &[u8], v4_offset: usize, v6_offset: usize) -> Result<IpAddr, ParseError> {
    let version = *packet.first().ok_or(ParseError::TooShort)? >> 4;
    match version {
        4 => {
            if packet.len() < 20 {
                return Err(ParseError::TooShort);
            }
            let ihl = packet[0] & 0x0f;
            if ihl < 5 {
                return Err(ParseError::InvalidIhl(ihl));
            }
            if packet.len() < (ihl as usize) * 4 {
                return Err(ParseError::Truncated);
            }
            let octets: [u8; 4] = packet[v4_offset..v4_offset + 4].try_into().unwrap();
            Ok(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        6 => {
            if packet.len() < 40 {
                return Err(ParseError::TooShort);
            }
            let octets: [u8; 16] = packet[v6_offset..v6_offset + 16].try_into().unwrap();
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        v => Err(ParseError::UnknownVersion(v)),
    }
}

// IPv4 header: minimum 20 bytes
// Byte 0: version(4) + IHL(4)
// Bytes 2-3: total length
// Byte 9: protocol
// Bytes 12-15: source address
// Bytes 16-19: destination address
fn parse_v4(packet: &[u8]) -> Result<IpPacketInfo, ParseError> {
    if packet.len() < 20 {
        return Err(ParseError::TooShort);
    }

    let ihl = packet[0] & 0x0f;
    if ihl < 5 {
        return Err(ParseError::InvalidIhl(ihl));
    }
    let header_len = (ihl as usize) * 4;
    if packet.len() < header_len {
        return Err(ParseError::Truncated);
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]);
    let protocol = packet[9];
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    Ok(IpPacketInfo {
        version: 4,
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        protocol,
        total_len,
    })
}

// IPv6 header: fixed 40 bytes
// Byte 0: version(4) + traffic class high(4)
// Bytes 4-5: payload length
// Byte 6: next header
// Bytes 8-23: source address (16 bytes)
// Bytes 24-39: destination address (16 bytes)
fn parse_v6(packet: &[u8]) -> Result<IpPacketInfo, ParseError> {
    if packet.len() < 40 {
        return Err(ParseError::TooShort);
    }

    let payload_len = u16::from_be_bytes([packet[4], packet[5]]);
    let next_header = packet[6];

    let mut src_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&packet[8..24]);
    let mut dst_bytes = [0u8; 16];
    dst_bytes.copy_from_slice(&packet[24..40]);

    // Total length = 40-byte fixed header + payload length
    let total_len = 40u16.saturating_add(payload_len);

    Ok(IpPacketInfo {
        version: 6,
        src: IpAddr::V6(Ipv6Addr::from(src_bytes)),
        dst: IpAddr::V6(Ipv6Addr::from(dst_bytes)),
        protocol: next_header,
        total_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper: build minimal IPv4 packet ───────────────────────────

    fn make_v4_packet(src: Ipv4Addr, dst: Ipv4Addr, proto: u8) -> Vec<u8> {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45; // version=4, IHL=5
        let total_len = 20u16;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[9] = proto;
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());
        pkt
    }

    fn make_v6_packet(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60; // version=6
        // payload length = 0
        pkt[6] = next_header;
        pkt[8..24].copy_from_slice(&src.octets());
        pkt[24..40].copy_from_slice(&dst.octets());
        pkt
    }

    // ── Empty / too short ───────────────────────────────────────────

    #[test]
    fn empty_packet() {
        assert_eq!(parse(&[]), Err(ParseError::TooShort));
    }

    #[test]
    fn single_byte() {
        // Version nibble = 4 but too short for IPv4 header
        assert_eq!(parse(&[0x45]), Err(ParseError::TooShort));
    }

    #[test]
    fn unknown_version() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x35; // version=3
        assert_eq!(parse(&pkt), Err(ParseError::UnknownVersion(3)));
    }

    // ── IPv4 ────────────────────────────────────────────────────────

    #[test]
    fn parse_v4_basic() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 1);
        let pkt = make_v4_packet(src, dst, 17); // UDP

        let info = parse(&pkt).unwrap();
        assert_eq!(info.version, 4);
        assert_eq!(info.src, IpAddr::V4(src));
        assert_eq!(info.dst, IpAddr::V4(dst));
        assert_eq!(info.protocol, 17);
        assert_eq!(info.total_len, 20);
    }

    #[test]
    fn parse_v4_tcp() {
        let src = Ipv4Addr::new(10, 89, 0, 5);
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let pkt = make_v4_packet(src, dst, 6); // TCP

        let info = parse(&pkt).unwrap();
        assert_eq!(info.protocol, 6);
        assert_eq!(info.src, IpAddr::V4(src));
        assert_eq!(info.dst, IpAddr::V4(dst));
    }

    #[test]
    fn parse_v4_with_options() {
        // IHL=6 means 24-byte header (with 4 bytes of options)
        let mut pkt = vec![0u8; 24];
        pkt[0] = 0x46; // version=4, IHL=6
        pkt[2..4].copy_from_slice(&24u16.to_be_bytes());
        pkt[9] = 1; // ICMP
        let src = Ipv4Addr::new(172, 16, 0, 1);
        let dst = Ipv4Addr::new(172, 16, 0, 2);
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());

        let info = parse(&pkt).unwrap();
        assert_eq!(info.version, 4);
        assert_eq!(info.src, IpAddr::V4(src));
        assert_eq!(info.dst, IpAddr::V4(dst));
    }

    #[test]
    fn parse_v4_invalid_ihl() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x43; // version=4, IHL=3 (invalid, min is 5)
        assert_eq!(parse(&pkt), Err(ParseError::InvalidIhl(3)));
    }

    #[test]
    fn parse_v4_truncated_options() {
        // IHL=6 needs 24 bytes but we only provide 20
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x46; // version=4, IHL=6
        assert_eq!(parse(&pkt), Err(ParseError::Truncated));
    }

    #[test]
    fn parse_v4_exactly_20_bytes() {
        let pkt = make_v4_packet(Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(127, 0, 0, 1), 6);
        assert_eq!(pkt.len(), 20);
        assert!(parse(&pkt).is_ok());
    }

    #[test]
    fn parse_v4_with_payload() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let mut pkt = make_v4_packet(src, dst, 17);
        // Add 100 bytes of payload
        pkt.extend_from_slice(&[0xAB; 100]);
        pkt[2..4].copy_from_slice(&120u16.to_be_bytes()); // total_len = 20 + 100

        let info = parse(&pkt).unwrap();
        assert_eq!(info.total_len, 120);
        assert_eq!(info.src, IpAddr::V4(src));
    }

    // ── IPv6 ────────────────────────────────────────────────────────

    #[test]
    fn parse_v6_basic() {
        let src: Ipv6Addr = "fd00::1".parse().unwrap();
        let dst: Ipv6Addr = "fd00::2".parse().unwrap();
        let pkt = make_v6_packet(src, dst, 17); // UDP

        let info = parse(&pkt).unwrap();
        assert_eq!(info.version, 6);
        assert_eq!(info.src, IpAddr::V6(src));
        assert_eq!(info.dst, IpAddr::V6(dst));
        assert_eq!(info.protocol, 17);
        assert_eq!(info.total_len, 40); // 40 header + 0 payload
    }

    #[test]
    fn parse_v6_with_payload_len() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let mut pkt = make_v6_packet(src, dst, 6); // TCP
        // Set payload length to 200
        pkt[4..6].copy_from_slice(&200u16.to_be_bytes());
        // Append enough bytes so the packet buffer is valid
        pkt.extend_from_slice(&[0u8; 200]);

        let info = parse(&pkt).unwrap();
        assert_eq!(info.total_len, 240); // 40 + 200
        assert_eq!(info.protocol, 6);
    }

    #[test]
    fn parse_v6_too_short() {
        let mut pkt = vec![0u8; 39]; // 1 byte too short
        pkt[0] = 0x60;
        assert_eq!(parse(&pkt), Err(ParseError::TooShort));
    }

    #[test]
    fn parse_v6_icmpv6() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "ff02::1".parse().unwrap();
        let pkt = make_v6_packet(src, dst, 58); // ICMPv6

        let info = parse(&pkt).unwrap();
        assert_eq!(info.protocol, 58);
    }

    // ── Convenience functions ───────────────────────────────────────

    #[test]
    fn src_addr_v4() {
        let pkt = make_v4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 1), 17);
        assert_eq!(
            src_addr(&pkt).unwrap(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))
        );
    }

    #[test]
    fn dst_addr_v6() {
        let dst: Ipv6Addr = "fd00::99".parse().unwrap();
        let pkt = make_v6_packet("fd00::1".parse().unwrap(), dst, 17);
        assert_eq!(dst_addr(&pkt).unwrap(), IpAddr::V6(dst));
    }

    #[test]
    fn addr_shortcuts_agree_with_full_parse() {
        let v4 = make_v4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(8, 8, 8, 8), 6);
        let v6 = make_v6_packet(
            "fd00::1".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            17,
        );

        let mut bad_ihl = v4.clone();
        bad_ihl[0] = 0x44; // IHL=4, below the 20-byte minimum
        let mut truncated_v4 = v4.clone();
        truncated_v4[0] = 0x46; // IHL=6 claims 24 bytes, packet is 20

        let cases: [&[u8]; 8] = [
            &v4,
            &v6,
            &bad_ihl,
            &truncated_v4,
            &[],
            &[0x45],          // v4 header cut short
            &v6[..20],        // v6 header cut short
            &[0x70, 0, 0, 0], // unknown version
        ];

        for pkt in cases {
            assert_eq!(
                src_addr(pkt),
                parse(pkt).map(|i| i.src),
                "src mismatch for {pkt:02x?}"
            );
            assert_eq!(
                dst_addr(pkt),
                parse(pkt).map(|i| i.dst),
                "dst mismatch for {pkt:02x?}"
            );
        }
    }
}

#[cfg(test)]
mod routing_tests {
    use super::*;

    fn ipv6_fragment(next: u8, offset_and_flags: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet[6] = 44;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        packet[40] = next;
        packet[42..44].copy_from_slice(&offset_and_flags.to_be_bytes());
        packet[44..48].copy_from_slice(&123u32.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    #[test]
    fn ipv6_fragmented_destination_options_accept_all_fragments() {
        // Fragment -> Destination Options -> UDP. Only the first fragment
        // contains the options and UDP headers; the later fragments are data.
        let mut first_payload = vec![17, 0, 0, 0, 0, 0, 0, 0];
        first_payload.extend_from_slice(&[0x12, 0x34, 0x56, 0x78, 0, 27, 0, 1]);
        first_payload.extend_from_slice(&[0xab; 8]);
        let fragments = [
            ipv6_fragment(60, 1, &first_payload),
            ipv6_fragment(60, 24 | 1, &[43, 255, 0, 0, 0, 0, 0, 0]),
            ipv6_fragment(60, 32, &[0xab; 3]),
        ];
        for (index, fragment) in fragments.iter().enumerate() {
            assert!(has_safe_routing(fragment), "fragment {index} was rejected");
        }
    }

    #[test]
    fn ipv6_noninitial_fragment_payload_is_opaque() {
        // RFC 8200 section 4.5 uses only offset zero's Next Header value for
        // reassembly. Later fragments may even carry a different value.
        for next in [0, 17, 43, 44, 51, 60] {
            for offset_and_flags in [8, 9, 0xfff8, 0xfff9] {
                for payload in [&[43, 255, 0, 0, 0, 0, 0, 0][..], &[0xab; 3][..]] {
                    assert!(has_safe_routing(&ipv6_fragment(
                        next,
                        offset_and_flags,
                        payload
                    )));
                }
            }
        }
    }

    #[test]
    fn ipv6_initial_and_atomic_fragments_still_reject_routing_headers() {
        for flags in [0, 1] {
            assert!(!has_safe_routing(&ipv6_fragment(43, flags, &[0; 8])));
            for next in [0, 51, 60] {
                let mut extension = vec![0; 16];
                extension[0] = 43;
                assert!(!has_safe_routing(&ipv6_fragment(next, flags, &extension)));
                extension[0] = 17;
                assert!(has_safe_routing(&ipv6_fragment(next, flags, &extension)));
                assert!(!has_safe_routing(&ipv6_fragment(next, flags, &[17; 7])));
            }
        }
        // Per-fragment headers must still be checked on every fragment.
        let mut packet = ipv6_fragment(17, 8, &[0; 8]);
        packet[6] = 60;
        packet.splice(40..40, [43, 0, 0, 0, 0, 0, 0, 0]);
        assert!(!has_safe_routing(&packet));
    }

    #[test]
    fn ipv6_truncated_fragment_headers_are_rejected() {
        let packet = ipv6_fragment(17, 8, &[]);
        for length in 40..48 {
            assert!(!has_safe_routing(&packet[..length]));
        }
    }

    #[test]
    fn source_routes_cannot_hide_the_final_destination() {
        let mut v4 = vec![0; 28];
        v4[0] = 0x45;
        assert!(has_safe_routing(&v4));
        v4[0] = 0x47;
        for kind in [131, 137] {
            v4[20] = kind;
            v4[21] = 7;
            assert!(!has_safe_routing(&v4));
        }
        v4[20] = 1;
        v4[21] = 0;
        assert!(has_safe_routing(&v4));
        let mut v6 = vec![0; 64];
        v6[0] = 0x60;
        v6[6] = 17;
        assert!(has_safe_routing(&v6));
        for extension in [0, 60, 44, 51] {
            v6[6] = extension;
            v6[40] = 43;
            assert!(!has_safe_routing(&v6));
            v6[40] = 17;
            assert!(has_safe_routing(&v6));
        }
        v6[6] = 43;
        assert!(!has_safe_routing(&v6));
        v6[6] = 60;
        v6[41] = 255;
        assert!(!has_safe_routing(&v6));
        assert!(!has_safe_routing(&[]));
    }
}
