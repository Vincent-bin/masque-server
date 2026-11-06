//! Bounded CONNECT-IP control input and replies for an existing address lease.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::datagram::DatagramCapsules;
use super::decoder::{DecodeError, parse_capsule_value};
use super::{AssignedAddress, CAPSULE_DATAGRAM, CapsuleFrame, IpAddress, RequestedAddress};

/// Limit control buffering independently of the negotiated packet MTU.
pub const MAX_ADDRESS_REQUEST_SIZE: usize = 16 * 1024;
/// Retain all used IDs, but never allow a stream to grow history indefinitely.
pub const MAX_ADDRESS_REQUEST_IDS: usize = 1024;

/// Stream decoder that validates known IP controls and skips unknown capsules
/// without buffering their values. Peer assignments never change the local lease.
pub struct IpCapsules {
    decoder: DatagramCapsules,
}

impl IpCapsules {
    /// `max_datagram` includes the Context ID for the standard wire format.
    pub fn new(max_datagram: usize) -> Self {
        Self {
            decoder: DatagramCapsules::with_ip_controls(max_datagram, MAX_ADDRESS_REQUEST_SIZE),
        }
    }

    pub fn is_partial(&self) -> bool {
        self.decoder.is_partial()
    }

    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<CapsuleFrame>, DecodeError> {
        let mut frames = Vec::new();
        self.decoder.decode_with(data, |kind, value| {
            frames.push(if kind == CAPSULE_DATAGRAM {
                CapsuleFrame::Datagram(value)
            } else {
                parse_capsule_value(kind, &value)?
            });
            Ok(())
        })?;
        Ok(frames)
    }
}

/// Request IDs are opaque, nonzero, and unique within this request stream.
/// Never allocate new addresses or widen the source-address boundary in response
/// to client preferences. The configured pool or pinned identity owns the lease.
#[derive(Default)]
pub struct AddressRequests {
    seen: HashSet<u64>,
}

impl AddressRequests {
    pub fn respond(
        &mut self,
        requests: &[RequestedAddress],
        lease: &[IpAddr],
    ) -> Result<CapsuleFrame, DecodeError> {
        if requests.is_empty() || requests.len() > MAX_ADDRESS_REQUEST_IDS - self.seen.len() {
            return Err(DecodeError::Malformed(
                "ADDRESS_REQUEST limit exceeded".into(),
            ));
        }
        for request in requests {
            if request.request_id == 0 || !self.seen.insert(request.request_id) {
                return Err(DecodeError::Malformed(
                    "reused ADDRESS_REQUEST identifier".into(),
                ));
            }
        }

        let mut assigned = Vec::with_capacity(requests.len() + lease.len());
        for request in requests {
            let ip = lease.iter().copied().find(|ip| match (ip, &request.ip) {
                (IpAddr::V4(ip), IpAddress::V4(wanted)) => {
                    request.prefix_len == 32 && (wanted.is_unspecified() || ip == wanted)
                }
                (IpAddr::V6(ip), IpAddress::V6(wanted)) => {
                    request.prefix_len == 128 && (wanted.is_unspecified() || ip == wanted)
                }
                _ => false,
            });
            let rejected = match request.ip {
                IpAddress::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddress::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            };
            assigned.push(assignment(request.request_id, ip.unwrap_or(rejected)));
        }
        // RFC 9484 section 4.7.1 makes each assignment a complete snapshot.
        // Retain the other family and every existing lease even on rejection;
        // never repeat a rejection in later snapshots.
        for ip in lease {
            let entry = assignment(0, *ip);
            if !assigned.iter().any(|address| address.ip == entry.ip) {
                assigned.push(entry);
            }
        }
        Ok(CapsuleFrame::AddressAssign(assigned))
    }
}

fn assignment(request_id: u64, ip: IpAddr) -> AssignedAddress {
    match ip {
        IpAddr::V4(ip) => AssignedAddress {
            request_id,
            ip: IpAddress::V4(ip),
            prefix_len: 32,
        },
        IpAddr::V6(ip) => AssignedAddress {
            request_id,
            ip: IpAddress::V6(ip),
            prefix_len: 128,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::{CAPSULE_ADDRESS_REQUEST, encoder};
    use crate::varint;

    fn request(id: u64, ip: &str, prefix: u8) -> RequestedAddress {
        let mut request = assignment(id, ip.parse().unwrap());
        request.prefix_len = prefix;
        request
    }

    fn assigned(frame: CapsuleFrame) -> Vec<AssignedAddress> {
        let CapsuleFrame::AddressAssign(addresses) = frame else {
            panic!("not an assignment")
        };
        addresses
    }

    #[test]
    fn replies_match_opaque_ids_and_preserve_the_complete_lease() {
        let lease = ["192.0.2.2".parse().unwrap(), "2001:db8::2".parse().unwrap()];
        let mut state = AddressRequests::default();
        let requests = [
            request(varint::MAX_VALUE, "::", 128),
            request(7, "0.0.0.0", 32),
        ];
        let result = assigned(state.respond(&requests, &lease).unwrap());
        assert_eq!(
            result,
            [
                assignment(varint::MAX_VALUE, lease[1]),
                assignment(7, lease[0])
            ]
        );
        let result = assigned(
            state
                .respond(&[request(1, "192.0.2.2", 32)], &lease)
                .unwrap(),
        );
        assert_eq!(result, [assignment(1, lease[0]), assignment(0, lease[1])]);
    }

    #[test]
    fn foreign_addresses_prefixes_and_missing_families_are_rejected_without_revoking_lease() {
        let lease = ["192.0.2.2".parse().unwrap()];
        let mut state = AddressRequests::default();
        for (id, ip, prefix) in [(1, "192.0.2.3", 32), (2, "0.0.0.0", 24), (3, "::", 128)] {
            let request = request(id, ip, prefix);
            let result = assigned(state.respond(&[request], &lease).unwrap());
            let rejection = if id == 3 { "::" } else { "0.0.0.0" };
            assert_eq!(
                result,
                [
                    assignment(id, rejection.parse().unwrap()),
                    assignment(0, lease[0])
                ]
            );
        }
        assert_eq!(
            assigned(state.respond(&[request(4, "0.0.0.0", 32)], &lease).unwrap()),
            [assignment(4, lease[0])]
        );
    }

    #[test]
    fn request_ids_are_unique_nonzero_and_bounded_not_monotonic() {
        let mut state = AddressRequests::default();
        assert!(state.respond(&[], &[]).is_err());
        assert!(state.respond(&[request(0, "::", 128)], &[]).is_err());
        for id in (1..=MAX_ADDRESS_REQUEST_IDS as u64).rev() {
            assert!(state.respond(&[request(id, "::", 128)], &[]).is_ok());
        }
        assert_eq!(state.seen.len(), MAX_ADDRESS_REQUEST_IDS);
        assert!(state.respond(&[request(1025, "::", 128)], &[]).is_err());
        assert_eq!(state.seen.len(), MAX_ADDRESS_REQUEST_IDS);
        let mut state = AddressRequests::default();
        let request = request(9, "::", 128);
        assert!(state.respond(std::slice::from_ref(&request), &[]).is_ok());
        assert!(state.respond(std::slice::from_ref(&request), &[]).is_err());
        assert!(
            AddressRequests::default()
                .respond(&[request.clone(), request], &[])
                .is_err()
        );
    }

    #[test]
    fn ip_requests_and_datagrams_survive_every_split() {
        let requests =
            CapsuleFrame::AddressRequest(vec![request(42, "::", 128), request(1, "0.0.0.0", 32)]);
        let mut wire = vec![0x20, 3, 0xff, 0xff, 0xff];
        encoder::encode(&requests, &mut wire);
        encoder::encode_datagram_context_zero(b"packet", &mut wire);
        for split in 0..=wire.len() {
            let mut decoder = IpCapsules::new(128);
            let mut frames = decoder.decode(&wire[..split]).unwrap();
            frames.extend(decoder.decode(&wire[split..]).unwrap());
            assert_eq!(
                frames,
                [
                    requests.clone(),
                    CapsuleFrame::Datagram(b"\0packet".to_vec())
                ]
            );
            assert!(!decoder.is_partial());
        }
    }

    #[test]
    fn malformed_empty_zero_id_and_noncanonical_prefixes_are_rejected() {
        let mut frames = vec![CapsuleFrame::AddressRequest(vec![])];
        for (id, ip, prefix) in [
            (0, "0.0.0.0", 32),
            (1, "0.0.0.0", 33),
            (1, "::", 129),
            (1, "192.0.2.1", 24),
            (1, "2001:db8::1", 64),
        ] {
            frames.push(CapsuleFrame::AddressRequest(vec![request(id, ip, prefix)]));
        }
        for frame in frames {
            let mut wire = Vec::new();
            encoder::encode(&frame, &mut wire);
            assert!(IpCapsules::new(128).decode(&wire).is_err(), "{frame:?}");
        }
        for value in [
            vec![1],
            vec![1, 3],
            vec![1, 4, 0, 0, 0],
            vec![1, 4, 0, 0, 0, 0],
        ] {
            let mut wire = vec![CAPSULE_ADDRESS_REQUEST as u8, value.len() as u8];
            wire.extend(value);
            assert!(IpCapsules::new(128).decode(&wire).is_err());
        }
    }

    #[test]
    fn control_limits_apply_at_header_and_unknown_values_need_no_buffer() {
        let mut wire = vec![CAPSULE_ADDRESS_REQUEST as u8];
        varint::encode_to_vec(MAX_ADDRESS_REQUEST_SIZE as u64 + 1, &mut wire).unwrap();
        assert!(matches!(
            IpCapsules::new(128).decode(&wire),
            Err(DecodeError::TooLarge { .. })
        ));
        let mut decoder = IpCapsules::new(128);
        let mut wire = vec![0x20];
        varint::encode_to_vec(varint::MAX_VALUE, &mut wire).unwrap();
        assert!(decoder.decode(&wire).unwrap().is_empty());
        for _ in 0..32 {
            assert!(decoder.decode(&[0; 1024]).unwrap().is_empty());
        }
        assert!(decoder.is_partial());
    }

    #[test]
    fn route_ranges_require_ordered_disjoint_intervals() {
        use crate::capsule::IpAddressRange;
        let range = |start: &str, end: &str, ip_protocol| IpAddressRange {
            start: assignment(0, start.parse().unwrap()).ip,
            end: assignment(0, end.parse().unwrap()).ip,
            ip_protocol,
        };
        let first = range("192.0.2.0", "192.0.2.5", 6);
        let second = range("192.0.2.6", "192.0.2.10", 6);
        let ipv6 = range("2001:db8::", "2001:db8::5", 0);
        let invalid = [
            vec![range("192.0.2.2", "192.0.2.1", 0)],
            vec![range("2001:db8::2", "2001:db8::1", 0)],
            vec![second.clone(), first.clone()],
            vec![first.clone(), range("192.0.2.5", "192.0.2.10", 6)],
            vec![first.clone(), range("192.0.2.6", "192.0.2.10", 0)],
            vec![ipv6.clone(), first.clone()],
        ];
        for ranges in invalid {
            let mut wire = Vec::new();
            encoder::encode(&CapsuleFrame::RouteAdvertisement(ranges), &mut wire);
            assert!(IpCapsules::new(128).decode(&wire).is_err());
        }
        let valid = CapsuleFrame::RouteAdvertisement(vec![first, second, ipv6]);
        let mut wire = Vec::new();
        encoder::encode(&valid, &mut wire);
        assert_eq!(IpCapsules::new(128).decode(&wire).unwrap(), [valid]);
    }

    #[test]
    fn lifetime_control_response_bytes_remain_below_64k() {
        let lease = ["192.0.2.2".parse().unwrap(), "2001:db8::2".parse().unwrap()];
        let mut state = AddressRequests::default();
        let mut wire = Vec::new();
        // Worst-case IDs and a rejected IPv6 preference repeat both leases.
        for offset in 0..MAX_ADDRESS_REQUEST_IDS as u64 {
            let reply = state
                .respond(
                    &[request(varint::MAX_VALUE - offset, "2001:db8::99", 128)],
                    &lease,
                )
                .unwrap();
            encoder::encode(&reply, &mut wire);
        }
        assert!(wire.len() < 64 * 1024, "{}", wire.len());
    }
}
