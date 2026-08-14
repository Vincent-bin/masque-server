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

/// Read the address at `v4_offset` (IPv4) or `v6_offset` (IPv6), after the
/// same header validation `parse` performs.
#[inline]
fn addr_at(
    packet: &[u8],
    v4_offset: usize,
    v6_offset: usize,
) -> Result<IpAddr, ParseError> {
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
            let octets: [u8; 4] =
                packet[v4_offset..v4_offset + 4].try_into().unwrap();
            Ok(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        6 => {
            if packet.len() < 40 {
                return Err(ParseError::TooShort);
            }
            let octets: [u8; 16] =
                packet[v6_offset..v6_offset + 16].try_into().unwrap();
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
        let pkt = make_v4_packet(
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(127, 0, 0, 1),
            6,
        );
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
        let pkt = make_v4_packet(
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(10, 0, 0, 1),
            17,
        );
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
        let v4 = make_v4_packet(
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(8, 8, 8, 8),
            6,
        );
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
            &[0x45],           // v4 header cut short
            &v6[..20],         // v6 header cut short
            &[0x70, 0, 0, 0],  // unknown version
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
