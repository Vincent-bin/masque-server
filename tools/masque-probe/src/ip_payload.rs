//! Small IP/UDP requests carried inside CONNECT-IP; no local TUN or raw socket.
use std::net::{IpAddr, SocketAddr};

use masque::capsule::{AssignedAddress, IpAddress};
use ring::rand::SecureRandom as _;

use crate::{protocol::dns_query, report::ProbeFailure};

pub struct IpExchange {
    source: SocketAddr,
    target: SocketAddr,
    payload: Vec<u8>,
    dns: bool,
}

impl IpExchange {
    pub fn new(
        addresses: &[AssignedAddress],
        target: SocketAddr,
        dns: bool,
    ) -> Result<Self, ProbeFailure> {
        if target.port() == 0 {
            return Err(invalid("inner UDP target port must be nonzero"));
        }
        let source = addresses
            .iter()
            .filter(|entry| entry.request_id == 0)
            .find_map(|entry| {
                let ip = match entry.ip {
                    IpAddress::V4(ip) => IpAddr::V4(ip),
                    IpAddress::V6(ip) => IpAddr::V6(ip),
                };
                (ip.is_ipv4() == target.is_ipv4() && !ip.is_unspecified()).then_some(ip)
            })
            .ok_or_else(|| {
                ProbeFailure::new(
                    "CONNECT_IP_NO_ADDRESS",
                    "no assigned address matches the IP target family",
                )
            })?;
        let mut random = [0; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| invalid("cannot generate IP probe nonce"))?;
        let source_port = 49152 + u16::from_be_bytes([random[0], random[1]]) % 16384;
        let payload = if dns {
            let mut query = dns_query();
            query[..2].copy_from_slice(&random[2..4]);
            query
        } else {
            random.to_vec()
        };
        Ok(Self {
            source: SocketAddr::new(source, source_port),
            target,
            payload,
            dns,
        })
    }

    pub fn packet(&self) -> Vec<u8> {
        udp_packet(self.source, self.target, &self.payload)
    }

    pub fn validate(&self, packet: &[u8]) -> Result<(), ProbeFailure> {
        let header =
            masque::ip_packet::parse(packet).map_err(|_| invalid("invalid IP response header"))?;
        if header.src != self.target.ip()
            || header.dst != self.source.ip()
            || header.protocol != 17
            || usize::from(header.total_len) != packet.len()
        {
            return Err(invalid(
                "IP response addresses, protocol or length do not match the request",
            ));
        }
        let offset = if header.version == 4 {
            let length = usize::from(packet[0] & 15) * 4;
            if packet[6] & 0x3f != 0 || packet[7] != 0 || checksum(&packet[..length]) != 0 {
                return Err(invalid("fragmented or corrupt IPv4 response"));
            }
            length
        } else {
            40
        };
        let udp = packet
            .get(offset..)
            .filter(|bytes| bytes.len() >= 8)
            .ok_or_else(|| invalid("truncated UDP response"))?;
        if udp[..2] != self.target.port().to_be_bytes()
            || udp[2..4] != self.source.port().to_be_bytes()
            || usize::from(u16::from_be_bytes([udp[4], udp[5]])) != udp.len()
        {
            return Err(invalid(
                "UDP response ports or length do not match the request",
            ));
        }
        if udp[6..8] == [0, 0] {
            if header.version == 6 {
                return Err(invalid("missing IPv6 UDP checksum"));
            }
        } else if udp_checksum(header.src, header.dst, udp) != 0 {
            return Err(invalid("invalid UDP checksum"));
        }
        let response = &udp[8..];
        if self.dns {
            if response.len() < 12 || response[..2] != self.payload[..2] || response[2] & 0x80 == 0
            {
                return Err(invalid("inner payload is not the matching DNS response"));
            }
        } else if response != self.payload {
            return Err(invalid(
                "inner echo payload does not match the request nonce",
            ));
        }
        Ok(())
    }
}

fn invalid(detail: &str) -> ProbeFailure {
    ProbeFailure::new("CONNECT_IP_RESPONSE_INVALID", detail)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_checksum(source: IpAddr, target: IpAddr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + udp.len());
    match (source, target) {
        (IpAddr::V4(source), IpAddr::V4(target)) => {
            pseudo.extend_from_slice(&source.octets());
            pseudo.extend_from_slice(&target.octets());
            pseudo.extend_from_slice(&[0, 17]);
            pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            pseudo.extend_from_slice(&source.octets());
            pseudo.extend_from_slice(&target.octets());
            pseudo.extend_from_slice(&(udp.len() as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 17]);
        }
        _ => unreachable!("IP probe families must match"),
    }
    pseudo.extend_from_slice(udp);
    checksum(&pseudo)
}

fn udp_packet(source: SocketAddr, target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let offset = if source.is_ipv4() { 20 } else { 40 };
    let mut packet = vec![0; offset + 8 + payload.len()];
    let total = packet.len() as u16;
    match (source.ip(), target.ip()) {
        (IpAddr::V4(source), IpAddr::V4(target)) => {
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&total.to_be_bytes());
            packet[6] = 0x40;
            packet[8] = 64;
            packet[9] = 17;
            packet[12..16].copy_from_slice(&source.octets());
            packet[16..20].copy_from_slice(&target.octets());
            let sum = checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&(total - 40).to_be_bytes());
            packet[6] = 17;
            packet[7] = 64;
            packet[8..24].copy_from_slice(&source.octets());
            packet[24..40].copy_from_slice(&target.octets());
        }
        _ => unreachable!("IP probe families must match"),
    }
    let udp = &mut packet[offset..];
    let length = udp.len() as u16;
    udp[..2].copy_from_slice(&source.port().to_be_bytes());
    udp[2..4].copy_from_slice(&target.port().to_be_bytes());
    udp[4..6].copy_from_slice(&length.to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let sum = udp_checksum(source.ip(), target.ip(), udp);
    udp[6..8].copy_from_slice(&(if sum == 0 { u16::MAX } else { sum }).to_be_bytes());
    packet
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipv4_ipv6_echo_and_dns_validate_matching_packets_only() {
        for (source, target) in [
            ("192.0.2.2:50000", "198.51.100.1:53"),
            ("[2001:db8::2]:50000", "[2001:db8::1]:53"),
        ] {
            for dns in [false, true] {
                let request = IpExchange {
                    source: source.parse().unwrap(),
                    target: target.parse().unwrap(),
                    payload: if dns {
                        dns_query()
                    } else {
                        b"random-echo-test".to_vec()
                    },
                    dns,
                };
                let mut payload = request.payload.clone();
                if dns {
                    payload[2] |= 0x80;
                }
                let response = udp_packet(request.target, request.source, &payload);
                assert!(request.validate(&response).is_ok());
                assert!(request.validate(&request.packet()).is_err());
                for length in 0..response.len() {
                    assert!(request.validate(&response[..length]).is_err());
                }
                let mut corrupt = response.clone();
                *corrupt.last_mut().unwrap() ^= 1;
                assert!(request.validate(&corrupt).is_err());
                let wrong = udp_packet(
                    request.target,
                    SocketAddr::new(request.source.ip(), 50001),
                    &payload,
                );
                assert!(request.validate(&wrong).is_err());
            }
        }
    }
}
