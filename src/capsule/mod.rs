// Capsule Protocol (RFC 9297) — types, encoder, and incremental decoder.
//
// Wire format:
//   Capsule {
//     Type   (varint),
//     Length (varint),
//     Value  (Length bytes),
//   }

pub mod decoder;
pub mod encoder;

use std::net::{Ipv4Addr, Ipv6Addr};

/// Capsule type IDs (RFC 9297, RFC 9484).
pub const CAPSULE_DATAGRAM: u64 = 0x00;
pub const CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;
pub const CAPSULE_ADDRESS_REQUEST: u64 = 0x02;
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;

/// A decoded capsule frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsuleFrame {
    /// DATAGRAM capsule (type 0x00) — raw payload for stream-based fallback.
    Datagram(Vec<u8>),

    /// ADDRESS_ASSIGN capsule (type 0x01).
    AddressAssign(Vec<AssignedAddress>),

    /// ADDRESS_REQUEST capsule (type 0x02).
    AddressRequest(Vec<RequestedAddress>),

    /// ROUTE_ADVERTISEMENT capsule (type 0x03).
    RouteAdvertisement(Vec<IpAddressRange>),

    /// Unknown capsule type — must be silently ignored per spec.
    Unknown { capsule_type: u64, value: Vec<u8> },
}

/// An address in ADDRESS_ASSIGN / ADDRESS_REQUEST capsules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignedAddress {
    pub request_id: u64,
    pub ip: IpAddress,
    pub prefix_len: u8,
}

/// Alias: ADDRESS_REQUEST uses the same wire format.
pub type RequestedAddress = AssignedAddress;

/// An IP address (v4 or v6) as it appears in capsule fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAddress {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

/// A route entry in ROUTE_ADVERTISEMENT capsules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAddressRange {
    pub start: IpAddress,
    pub end: IpAddress,
    pub ip_protocol: u8,
}
