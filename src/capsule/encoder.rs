// Capsule encoder — serialises CapsuleFrame into TLV wire format.

use super::*;
use crate::varint;

/// Encode a capsule frame into TLV format, appending to `buf`.
pub fn encode(frame: &CapsuleFrame, buf: &mut Vec<u8>) {
    match frame {
        CapsuleFrame::Datagram(payload) => {
            encode_raw(CAPSULE_DATAGRAM, payload, buf);
        }
        CapsuleFrame::AddressAssign(addrs) => {
            let value = encode_assigned_addresses(addrs);
            encode_raw(CAPSULE_ADDRESS_ASSIGN, &value, buf);
        }
        CapsuleFrame::AddressRequest(addrs) => {
            let value = encode_assigned_addresses(addrs);
            encode_raw(CAPSULE_ADDRESS_REQUEST, &value, buf);
        }
        CapsuleFrame::RouteAdvertisement(ranges) => {
            let value = encode_address_ranges(ranges);
            encode_raw(CAPSULE_ROUTE_ADVERTISEMENT, &value, buf);
        }
        CapsuleFrame::Unknown {
            capsule_type,
            value,
        } => {
            encode_raw(*capsule_type, value, buf);
        }
    }
}

/// Encode a raw capsule: Type(varint) + Length(varint) + Value.
fn encode_raw(capsule_type: u64, value: &[u8], buf: &mut Vec<u8>) {
    varint::encode_to_vec(capsule_type, buf).expect("capsule type fits varint");
    varint::encode_to_vec(value.len() as u64, buf).expect("capsule length fits varint");
    buf.extend_from_slice(value);
}

/// Encode a list of AssignedAddress / RequestedAddress entries.
fn encode_assigned_addresses(addrs: &[AssignedAddress]) -> Vec<u8> {
    let mut value = Vec::new();
    for addr in addrs {
        varint::encode_to_vec(addr.request_id, &mut value).expect("request_id fits varint");
        match &addr.ip {
            IpAddress::V4(v4) => {
                value.push(4); // IP Version
                value.extend_from_slice(&v4.octets());
            }
            IpAddress::V6(v6) => {
                value.push(6); // IP Version
                value.extend_from_slice(&v6.octets());
            }
        }
        value.push(addr.prefix_len);
    }
    value
}

/// Encode a list of IpAddressRange entries.
fn encode_address_ranges(ranges: &[IpAddressRange]) -> Vec<u8> {
    let mut value = Vec::new();
    for range in ranges {
        match (&range.start, &range.end) {
            (IpAddress::V4(start), IpAddress::V4(end)) => {
                value.push(4);
                value.extend_from_slice(&start.octets());
                value.extend_from_slice(&end.octets());
            }
            (IpAddress::V6(start), IpAddress::V6(end)) => {
                value.push(6);
                value.extend_from_slice(&start.octets());
                value.extend_from_slice(&end.octets());
            }
            _ => panic!("start and end IP versions must match"),
        }
        value.push(range.ip_protocol);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn encode_datagram_capsule() {
        let frame = CapsuleFrame::Datagram(vec![0xde, 0xad, 0xbe, 0xef]);
        let mut buf = Vec::new();
        encode(&frame, &mut buf);

        // Type=0x00(1 byte), Length=4(1 byte), Value=4 bytes
        assert_eq!(buf.len(), 1 + 1 + 4);
        assert_eq!(buf[0], 0x00); // type
        assert_eq!(buf[1], 0x04); // length
        assert_eq!(&buf[2..], &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn encode_empty_datagram() {
        let frame = CapsuleFrame::Datagram(vec![]);
        let mut buf = Vec::new();
        encode(&frame, &mut buf);

        assert_eq!(buf, vec![0x00, 0x00]); // type=0, length=0
    }

    #[test]
    fn encode_address_assign_v4() {
        let frame = CapsuleFrame::AddressAssign(vec![AssignedAddress {
            request_id: 1,
            ip: IpAddress::V4(Ipv4Addr::new(10, 89, 0, 1)),
            prefix_len: 32,
        }]);
        let mut buf = Vec::new();
        encode(&frame, &mut buf);

        // Type=0x01, then Length varint, then:
        //   request_id=1(1B) + ip_version=4(1B) + addr(4B) + prefix(1B) = 7
        assert_eq!(buf[0], 0x01); // type = ADDRESS_ASSIGN
        assert_eq!(buf[1], 7); // length
        assert_eq!(buf[2], 1); // request_id
        assert_eq!(buf[3], 4); // ip version
        assert_eq!(&buf[4..8], &[10, 89, 0, 1]); // address
        assert_eq!(buf[8], 32); // prefix length
    }

    #[test]
    fn encode_address_assign_v6() {
        let addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let frame = CapsuleFrame::AddressAssign(vec![AssignedAddress {
            request_id: 0,
            ip: IpAddress::V6(addr),
            prefix_len: 128,
        }]);
        let mut buf = Vec::new();
        encode(&frame, &mut buf);

        // request_id=0(1B) + ip_version=6(1B) + addr(16B) + prefix(1B) = 19
        assert_eq!(buf[0], 0x01); // type
        assert_eq!(buf[1], 19); // length
        assert_eq!(buf[3], 6); // ip version
    }

    #[test]
    fn encode_address_assign_empty_withdraws() {
        let frame = CapsuleFrame::AddressAssign(vec![]);
        let mut buf = Vec::new();
        encode(&frame, &mut buf);

        // Empty ADDRESS_ASSIGN withdraws all addresses
        assert_eq!(buf, vec![0x01, 0x00]);
    }

    #[test]
    fn encode_address_request() {
        let frame = CapsuleFrame::AddressRequest(vec![AssignedAddress {
            request_id: 42,
            ip: IpAddress::V4(Ipv4Addr::UNSPECIFIED),
            prefix_len: 32,
        }]);
        let mut buf = Vec::new();
        encode(&frame, &mut buf);

        assert_eq!(buf[0], 0x02); // type = ADDRESS_REQUEST
        assert_eq!(buf[2], 42); // request_id
    }

    #[test]
    fn encode_route_advertisement_v4() {
        let frame = CapsuleFrame::RouteAdvertisement(vec![IpAddressRange {
            start: IpAddress::V4(Ipv4Addr::new(0, 0, 0, 0)),
            end: IpAddress::V4(Ipv4Addr::new(255, 255, 255, 255)),
            ip_protocol: 0, // all protocols
        }]);
        let mut buf = Vec::new();
        encode(&frame, &mut buf);

        // ip_version(1B) + start(4B) + end(4B) + protocol(1B) = 10
        assert_eq!(buf[0], 0x03); // type = ROUTE_ADVERTISEMENT
        assert_eq!(buf[1], 10); // length
        assert_eq!(buf[2], 4); // ip version
        assert_eq!(&buf[3..7], &[0, 0, 0, 0]);
        assert_eq!(&buf[7..11], &[255, 255, 255, 255]);
        assert_eq!(buf[11], 0); // protocol
    }

    #[test]
    fn encode_route_advertisement_v6() {
        let start = Ipv6Addr::UNSPECIFIED;
        let end = Ipv6Addr::new(
            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        );
        let frame = CapsuleFrame::RouteAdvertisement(vec![IpAddressRange {
            start: IpAddress::V6(start),
            end: IpAddress::V6(end),
            ip_protocol: 0,
        }]);
        let mut buf = Vec::new();
        encode(&frame, &mut buf);

        // ip_version(1B) + start(16B) + end(16B) + protocol(1B) = 34
        assert_eq!(buf[0], 0x03);
        assert_eq!(buf[1], 34);
        assert_eq!(buf[2], 6);
    }

    #[test]
    fn encode_multiple_addresses() {
        let frame = CapsuleFrame::AddressAssign(vec![
            AssignedAddress {
                request_id: 1,
                ip: IpAddress::V4(Ipv4Addr::new(10, 0, 0, 1)),
                prefix_len: 24,
            },
            AssignedAddress {
                request_id: 2,
                ip: IpAddress::V4(Ipv4Addr::new(10, 0, 0, 2)),
                prefix_len: 24,
            },
        ]);
        let mut buf = Vec::new();
        encode(&frame, &mut buf);

        // Each address: request_id(1) + version(1) + addr(4) + prefix(1) = 7
        // Two addresses = 14 bytes value
        assert_eq!(buf[0], 0x01); // type
        assert_eq!(buf[1], 14); // length
    }

    #[test]
    fn encode_unknown_capsule() {
        let frame = CapsuleFrame::Unknown {
            capsule_type: 0xff,
            value: vec![1, 2, 3],
        };
        let mut buf = Vec::new();
        encode(&frame, &mut buf);

        // 0xff > 63, so type needs 2-byte varint encoding
        let (typ, tlen) = crate::varint::decode(&buf).unwrap();
        assert_eq!(typ, 0xff);
        let (length, llen) = crate::varint::decode(&buf[tlen..]).unwrap();
        assert_eq!(length, 3);
        assert_eq!(&buf[tlen + llen..], &[1, 2, 3]);
    }

    #[test]
    fn encode_multiple_routes_sorted() {
        let frame = CapsuleFrame::RouteAdvertisement(vec![
            IpAddressRange {
                start: IpAddress::V4(Ipv4Addr::new(10, 0, 0, 0)),
                end: IpAddress::V4(Ipv4Addr::new(10, 0, 0, 255)),
                ip_protocol: 6, // TCP
            },
            IpAddressRange {
                start: IpAddress::V4(Ipv4Addr::new(10, 0, 1, 0)),
                end: IpAddress::V4(Ipv4Addr::new(10, 0, 1, 255)),
                ip_protocol: 17, // UDP
            },
        ]);
        let mut buf = Vec::new();
        encode(&frame, &mut buf);

        // Each range: version(1) + start(4) + end(4) + protocol(1) = 10
        // Two ranges = 20 bytes
        assert_eq!(buf[0], 0x03);
        assert_eq!(buf[1], 20);
    }
}
