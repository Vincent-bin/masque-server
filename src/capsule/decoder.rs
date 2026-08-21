// Incremental capsule TLV decoder.
//
// Handles partial reads from an HTTP/3 stream: accumulates bytes and yields
// zero or more CapsuleFrame values per `decode` call.

use super::*;
use crate::varint;

/// Error from the capsule decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Not enough data yet — feed more bytes and retry.
    Incomplete,
    /// The capsule value could not be parsed.
    Malformed(String),
    /// The declared capsule value exceeds the configured memory bound.
    TooLarge { length: u64, max: usize },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Incomplete => write!(f, "incomplete capsule data"),
            DecodeError::Malformed(msg) => write!(f, "malformed capsule: {msg}"),
            DecodeError::TooLarge { length, max } => {
                write!(f, "capsule value is {length} bytes, limit is {max}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Incremental capsule decoder.
pub struct CapsuleDecoder {
    buf: Vec<u8>,
    /// Bytes at the front of `buf` that have already been decoded.
    consumed: usize,
    max_capsule_size: usize,
}

/// Compact `buf` once the decoded prefix grows past this many bytes, so a long
/// stream neither memmoves after every capsule nor grows without bound.
const COMPACT_THRESHOLD: usize = 16 * 1024;
const DEFAULT_MAX_CAPSULE_SIZE: usize = 1024 * 1024;

impl CapsuleDecoder {
    pub fn new() -> Self {
        Self::with_max_capsule_size(DEFAULT_MAX_CAPSULE_SIZE)
    }

    /// Build a decoder that rejects a capsule before buffering a value larger
    /// than `max_capsule_size`.
    pub fn with_max_capsule_size(max_capsule_size: usize) -> Self {
        Self {
            buf: Vec::new(),
            consumed: 0,
            max_capsule_size,
        }
    }

    /// Feed data into the decoder and try to extract complete capsules.
    ///
    /// Returns a list of decoded frames. `Incomplete` data is buffered
    /// internally and will be re-tried on the next call.
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<CapsuleFrame>, DecodeError> {
        // Drop the already-decoded prefix before appending, rather than
        // memmoving the remainder after every single capsule.
        if self.consumed > 0
            && (self.consumed >= COMPACT_THRESHOLD || self.consumed == self.buf.len())
        {
            self.buf.drain(..self.consumed);
            self.consumed = 0;
        }

        self.buf.extend_from_slice(data);
        let mut frames = Vec::new();

        loop {
            match try_decode_one(&self.buf[self.consumed..], self.max_capsule_size) {
                Ok((frame, consumed)) => {
                    frames.push(frame);
                    self.consumed += consumed;
                }
                Err(DecodeError::Incomplete) => break,
                Err(e) => return Err(e),
            }
        }

        Ok(frames)
    }

    /// Returns the number of buffered bytes not yet decoded.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.consumed
    }
}

impl Default for CapsuleDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Try to decode one capsule from `buf`. Returns `(frame, bytes_consumed)`.
fn try_decode_one(
    buf: &[u8],
    max_capsule_size: usize,
) -> Result<(CapsuleFrame, usize), DecodeError> {
    // Parse Type varint
    let (capsule_type, tlen) = varint::decode(buf).map_err(|_| DecodeError::Incomplete)?;

    // Parse Length varint
    let (length, llen) = varint::decode(&buf[tlen..]).map_err(|_| DecodeError::Incomplete)?;

    if length > max_capsule_size as u64 {
        return Err(DecodeError::TooLarge {
            length,
            max: max_capsule_size,
        });
    }

    let header_len = tlen + llen;
    let total_len = header_len
        .checked_add(length as usize)
        .ok_or_else(|| DecodeError::Malformed("capsule length overflows usize".into()))?;

    if buf.len() < total_len {
        return Err(DecodeError::Incomplete);
    }

    let value = &buf[header_len..total_len];

    let frame = parse_capsule_value(capsule_type, value)?;
    Ok((frame, total_len))
}

/// Interpret the capsule value bytes based on the type.
fn parse_capsule_value(capsule_type: u64, value: &[u8]) -> Result<CapsuleFrame, DecodeError> {
    match capsule_type {
        CAPSULE_DATAGRAM => Ok(CapsuleFrame::Datagram(value.to_vec())),

        CAPSULE_ADDRESS_ASSIGN => {
            let addrs = parse_assigned_addresses(value)?;
            Ok(CapsuleFrame::AddressAssign(addrs))
        }

        CAPSULE_ADDRESS_REQUEST => {
            let addrs = parse_assigned_addresses(value)?;
            Ok(CapsuleFrame::AddressRequest(addrs))
        }

        CAPSULE_ROUTE_ADVERTISEMENT => {
            let ranges = parse_address_ranges(value)?;
            Ok(CapsuleFrame::RouteAdvertisement(ranges))
        }

        _ => Ok(CapsuleFrame::Unknown {
            capsule_type,
            value: value.to_vec(),
        }),
    }
}

/// Parse ADDRESS_ASSIGN / ADDRESS_REQUEST value.
fn parse_assigned_addresses(mut buf: &[u8]) -> Result<Vec<AssignedAddress>, DecodeError> {
    let mut addrs = Vec::new();

    while !buf.is_empty() {
        let (request_id, rlen) = varint::decode(buf)
            .map_err(|_| DecodeError::Malformed("truncated request_id".into()))?;
        buf = &buf[rlen..];

        if buf.is_empty() {
            return Err(DecodeError::Malformed("missing ip_version".into()));
        }
        let ip_version = buf[0];
        buf = &buf[1..];

        let (ip, addr_len) = match ip_version {
            4 => {
                if buf.len() < 4 {
                    return Err(DecodeError::Malformed("truncated IPv4".into()));
                }
                let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                (IpAddress::V4(addr), 4)
            }
            6 => {
                if buf.len() < 16 {
                    return Err(DecodeError::Malformed("truncated IPv6".into()));
                }
                let octets: [u8; 16] = buf[..16].try_into().unwrap();
                (IpAddress::V6(Ipv6Addr::from(octets)), 16)
            }
            v => {
                return Err(DecodeError::Malformed(format!("invalid ip_version: {v}")));
            }
        };
        buf = &buf[addr_len..];

        if buf.is_empty() {
            return Err(DecodeError::Malformed("missing prefix_len".into()));
        }
        let prefix_len = buf[0];
        buf = &buf[1..];

        addrs.push(AssignedAddress {
            request_id,
            ip,
            prefix_len,
        });
    }

    Ok(addrs)
}

/// Parse ROUTE_ADVERTISEMENT value.
fn parse_address_ranges(mut buf: &[u8]) -> Result<Vec<IpAddressRange>, DecodeError> {
    let mut ranges = Vec::new();

    while !buf.is_empty() {
        if buf.is_empty() {
            return Err(DecodeError::Malformed("missing ip_version".into()));
        }
        let ip_version = buf[0];
        buf = &buf[1..];

        let (start, end, addr_len) = match ip_version {
            4 => {
                if buf.len() < 8 {
                    return Err(DecodeError::Malformed("truncated IPv4 range".into()));
                }
                let start = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let end = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                (IpAddress::V4(start), IpAddress::V4(end), 8)
            }
            6 => {
                if buf.len() < 32 {
                    return Err(DecodeError::Malformed("truncated IPv6 range".into()));
                }
                let start: [u8; 16] = buf[..16].try_into().unwrap();
                let end: [u8; 16] = buf[16..32].try_into().unwrap();
                (
                    IpAddress::V6(Ipv6Addr::from(start)),
                    IpAddress::V6(Ipv6Addr::from(end)),
                    32,
                )
            }
            v => {
                return Err(DecodeError::Malformed(format!("invalid ip_version: {v}")));
            }
        };
        buf = &buf[addr_len..];

        if buf.is_empty() {
            return Err(DecodeError::Malformed("missing ip_protocol".into()));
        }
        let ip_protocol = buf[0];
        buf = &buf[1..];

        ranges.push(IpAddressRange {
            start,
            end,
            ip_protocol,
        });
    }

    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::encoder;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ── Round-trip tests ──────────────────────────────────────────────

    #[test]
    fn roundtrip_datagram() {
        let original = CapsuleFrame::Datagram(vec![1, 2, 3, 4, 5]);
        let mut wire = Vec::new();
        encoder::encode(&original, &mut wire);

        let mut dec = CapsuleDecoder::new();
        let frames = dec.decode(&wire).unwrap();
        assert_eq!(frames, vec![original]);
        assert_eq!(dec.buffered(), 0);
    }

    #[test]
    fn roundtrip_empty_datagram() {
        let original = CapsuleFrame::Datagram(vec![]);
        let mut wire = Vec::new();
        encoder::encode(&original, &mut wire);

        let mut dec = CapsuleDecoder::new();
        let frames = dec.decode(&wire).unwrap();
        assert_eq!(frames, vec![original]);
    }

    #[test]
    fn roundtrip_address_assign_v4() {
        let original = CapsuleFrame::AddressAssign(vec![AssignedAddress {
            request_id: 1,
            ip: IpAddress::V4(Ipv4Addr::new(10, 89, 0, 1)),
            prefix_len: 32,
        }]);
        let mut wire = Vec::new();
        encoder::encode(&original, &mut wire);

        let mut dec = CapsuleDecoder::new();
        let frames = dec.decode(&wire).unwrap();
        assert_eq!(frames, vec![original]);
    }

    #[test]
    fn roundtrip_address_assign_v6() {
        let addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let original = CapsuleFrame::AddressAssign(vec![AssignedAddress {
            request_id: 0,
            ip: IpAddress::V6(addr),
            prefix_len: 128,
        }]);
        let mut wire = Vec::new();
        encoder::encode(&original, &mut wire);

        let mut dec = CapsuleDecoder::new();
        let frames = dec.decode(&wire).unwrap();
        assert_eq!(frames, vec![original]);
    }

    #[test]
    fn roundtrip_address_assign_empty() {
        let original = CapsuleFrame::AddressAssign(vec![]);
        let mut wire = Vec::new();
        encoder::encode(&original, &mut wire);

        let mut dec = CapsuleDecoder::new();
        let frames = dec.decode(&wire).unwrap();
        assert_eq!(frames, vec![original]);
    }

    #[test]
    fn roundtrip_address_request() {
        let original = CapsuleFrame::AddressRequest(vec![AssignedAddress {
            request_id: 42,
            ip: IpAddress::V4(Ipv4Addr::UNSPECIFIED),
            prefix_len: 32,
        }]);
        let mut wire = Vec::new();
        encoder::encode(&original, &mut wire);

        let mut dec = CapsuleDecoder::new();
        let frames = dec.decode(&wire).unwrap();
        assert_eq!(frames, vec![original]);
    }

    #[test]
    fn roundtrip_route_advertisement_v4() {
        let original = CapsuleFrame::RouteAdvertisement(vec![IpAddressRange {
            start: IpAddress::V4(Ipv4Addr::new(0, 0, 0, 0)),
            end: IpAddress::V4(Ipv4Addr::new(255, 255, 255, 255)),
            ip_protocol: 0,
        }]);
        let mut wire = Vec::new();
        encoder::encode(&original, &mut wire);

        let mut dec = CapsuleDecoder::new();
        let frames = dec.decode(&wire).unwrap();
        assert_eq!(frames, vec![original]);
    }

    #[test]
    fn roundtrip_route_advertisement_v6() {
        let original = CapsuleFrame::RouteAdvertisement(vec![IpAddressRange {
            start: IpAddress::V6(Ipv6Addr::UNSPECIFIED),
            end: IpAddress::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            )),
            ip_protocol: 0,
        }]);
        let mut wire = Vec::new();
        encoder::encode(&original, &mut wire);

        let mut dec = CapsuleDecoder::new();
        let frames = dec.decode(&wire).unwrap();
        assert_eq!(frames, vec![original]);
    }

    #[test]
    fn roundtrip_multiple_addresses() {
        let original = CapsuleFrame::AddressAssign(vec![
            AssignedAddress {
                request_id: 1,
                ip: IpAddress::V4(Ipv4Addr::new(10, 0, 0, 1)),
                prefix_len: 24,
            },
            AssignedAddress {
                request_id: 2,
                ip: IpAddress::V6(Ipv6Addr::LOCALHOST),
                prefix_len: 128,
            },
        ]);
        let mut wire = Vec::new();
        encoder::encode(&original, &mut wire);

        let mut dec = CapsuleDecoder::new();
        let frames = dec.decode(&wire).unwrap();
        assert_eq!(frames, vec![original]);
    }

    #[test]
    fn roundtrip_unknown_capsule() {
        let original = CapsuleFrame::Unknown {
            capsule_type: 0xff,
            value: vec![0xaa, 0xbb],
        };
        let mut wire = Vec::new();
        encoder::encode(&original, &mut wire);

        let mut dec = CapsuleDecoder::new();
        let frames = dec.decode(&wire).unwrap();
        assert_eq!(frames, vec![original]);
    }

    // ── Incremental decoding ──────────────────────────────────────────

    #[test]
    fn incremental_byte_at_a_time() {
        let frame = CapsuleFrame::Datagram(vec![0xca, 0xfe]);
        let mut wire = Vec::new();
        encoder::encode(&frame, &mut wire);

        let mut dec = CapsuleDecoder::new();

        // Feed one byte at a time; should get Incomplete until the last byte
        for &b in &wire[..wire.len() - 1] {
            let frames = dec.decode(&[b]).unwrap();
            assert!(frames.is_empty(), "got frame too early");
        }

        let frames = dec.decode(&wire[wire.len() - 1..]).unwrap();
        assert_eq!(frames, vec![frame]);
        assert_eq!(dec.buffered(), 0);
    }

    #[test]
    fn multiple_capsules_in_one_chunk() {
        let f1 = CapsuleFrame::Datagram(vec![1]);
        let f2 = CapsuleFrame::Datagram(vec![2]);
        let f3 = CapsuleFrame::Datagram(vec![3]);

        let mut wire = Vec::new();
        encoder::encode(&f1, &mut wire);
        encoder::encode(&f2, &mut wire);
        encoder::encode(&f3, &mut wire);

        let mut dec = CapsuleDecoder::new();
        let frames = dec.decode(&wire).unwrap();
        assert_eq!(frames, vec![f1, f2, f3]);
    }

    #[test]
    fn split_across_two_chunks() {
        let f1 = CapsuleFrame::Datagram(vec![0xaa; 10]);
        let f2 = CapsuleFrame::Datagram(vec![0xbb; 10]);

        let mut wire = Vec::new();
        encoder::encode(&f1, &mut wire);
        encoder::encode(&f2, &mut wire);

        let mid = wire.len() / 2;
        let mut dec = CapsuleDecoder::new();

        let frames1 = dec.decode(&wire[..mid]).unwrap();
        let frames2 = dec.decode(&wire[mid..]).unwrap();

        let mut all = frames1;
        all.extend(frames2);
        assert_eq!(all, vec![f1, f2]);
    }

    #[test]
    fn empty_input_returns_empty() {
        let mut dec = CapsuleDecoder::new();
        let frames = dec.decode(&[]).unwrap();
        assert!(frames.is_empty());
    }

    // ── Error cases ───────────────────────────────────────────────────

    #[test]
    fn malformed_address_bad_ip_version() {
        // Construct a capsule with type=ADDRESS_ASSIGN, invalid ip_version=3
        let mut wire = Vec::new();
        crate::varint::encode_to_vec(CAPSULE_ADDRESS_ASSIGN, &mut wire).unwrap();
        // value: request_id=0, ip_version=3 (invalid), ... truncated
        let value = vec![0x00, 3];
        crate::varint::encode_to_vec(value.len() as u64, &mut wire).unwrap();
        wire.extend_from_slice(&value);

        let mut dec = CapsuleDecoder::new();
        let result = dec.decode(&wire);
        assert!(matches!(result, Err(DecodeError::Malformed(_))));
    }

    #[test]
    fn malformed_address_truncated_ipv4() {
        let mut wire = Vec::new();
        crate::varint::encode_to_vec(CAPSULE_ADDRESS_ASSIGN, &mut wire).unwrap();
        // request_id=0, ip_version=4, but only 2 bytes of address
        let value = vec![0x00, 4, 10, 0];
        crate::varint::encode_to_vec(value.len() as u64, &mut wire).unwrap();
        wire.extend_from_slice(&value);

        let mut dec = CapsuleDecoder::new();
        let result = dec.decode(&wire);
        assert!(matches!(result, Err(DecodeError::Malformed(_))));
    }

    #[test]
    fn malformed_route_bad_ip_version() {
        let mut wire = Vec::new();
        crate::varint::encode_to_vec(CAPSULE_ROUTE_ADVERTISEMENT, &mut wire).unwrap();
        let value = vec![5]; // invalid ip_version
        crate::varint::encode_to_vec(value.len() as u64, &mut wire).unwrap();
        wire.extend_from_slice(&value);

        let mut dec = CapsuleDecoder::new();
        let result = dec.decode(&wire);
        assert!(matches!(result, Err(DecodeError::Malformed(_))));
    }

    #[test]
    fn malformed_route_truncated_v4_range() {
        let mut wire = Vec::new();
        crate::varint::encode_to_vec(CAPSULE_ROUTE_ADVERTISEMENT, &mut wire).unwrap();
        // ip_version=4, but only 4 bytes (need 8 for start+end)
        let value = vec![4, 0, 0, 0, 0];
        crate::varint::encode_to_vec(value.len() as u64, &mut wire).unwrap();
        wire.extend_from_slice(&value);

        let mut dec = CapsuleDecoder::new();
        let result = dec.decode(&wire);
        assert!(matches!(result, Err(DecodeError::Malformed(_))));
    }

    #[test]
    fn declared_value_over_the_limit_is_rejected_from_its_header() {
        let mut wire = Vec::new();
        crate::varint::encode_to_vec(CAPSULE_DATAGRAM, &mut wire).unwrap();
        crate::varint::encode_to_vec(65_000, &mut wire).unwrap();

        let mut decoder = CapsuleDecoder::with_max_capsule_size(1_200);
        assert_eq!(
            decoder.decode(&wire),
            Err(DecodeError::TooLarge {
                length: 65_000,
                max: 1_200,
            })
        );
        assert_eq!(decoder.buffered(), wire.len());
    }
}
