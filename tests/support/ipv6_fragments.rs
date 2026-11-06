use std::net::Ipv6Addr;

use masque::capsule::{CapsuleFrame, IpAddress};
use masque::config::ServerConfig;

pub const TARGET: &str = "2001:db8::1";
pub const PAYLOAD: [u8; 19] = [
    0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 43, 255, 0, 0, 0, 0, 0, 0, 0xab, 0xab, 0xab,
];

pub fn configure(config: &mut ServerConfig) {
    assert_eq!(
        std::env::var("MASQUE_TEST_NETNS").as_deref(),
        Ok("1"),
        "run through tests/connect-ip-fragments.sh in an isolated network namespace"
    );
    config.ip_proxy.enabled = true;
    config.ip_proxy.require_tun = true;
    config.ip_proxy.tun_offload = std::env::var("MASQUE_IP_TEST_TUN_OFFLOAD").as_deref() == Ok("1");
}

pub fn assigned_source(frames: &[CapsuleFrame]) -> Ipv6Addr {
    frames
        .iter()
        .find_map(|frame| match frame {
            CapsuleFrame::AddressAssign(addresses) => addresses.iter().find_map(|a| match a.ip {
                IpAddress::V6(ip) => Some(ip),
                _ => None,
            }),
            _ => None,
        })
        .expect("CONNECT-IP must assign an IPv6 address")
}

pub fn packets(source: Ipv6Addr, port: u16) -> Vec<Vec<u8>> {
    let target: Ipv6Addr = TARGET.parse().unwrap();
    let mut udp = vec![0; 8];
    udp[..2].copy_from_slice(&49152u16.to_be_bytes());
    udp[2..4].copy_from_slice(&port.to_be_bytes());
    udp[4..6].copy_from_slice(&((8 + PAYLOAD.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&PAYLOAD);
    // IPv6 requires a nonzero UDP checksum over the complete reassembled UDP
    // datagram and pseudo-header; Destination Options are not included.
    let mut checksum_input = source.octets().to_vec();
    checksum_input.extend_from_slice(&target.octets());
    checksum_input.extend_from_slice(&(udp.len() as u32).to_be_bytes());
    checksum_input.extend_from_slice(&[0, 0, 0, 17]);
    checksum_input.extend_from_slice(&udp);
    checksum_input.push(0);
    let mut sum: u32 = checksum_input
        .chunks_exact(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    udp[6..8].copy_from_slice(&if checksum == 0 { 0xffff } else { checksum }.to_be_bytes());
    let mut fragmentable = vec![17, 0, 0, 0, 0, 0, 0, 0]; // Destination Options, Pad1
    fragmentable.extend_from_slice(&udp);
    // Deliver the final fragment first to verify no first-fragment state is
    // required. The middle payload resembles an invalid extension header;
    // the final payload is shorter than an extension header.
    [(32usize, 35usize), (0, 24), (24, 32)]
        .into_iter()
        .map(|(start, end)| {
            let mut packet = vec![0; 48];
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&((8 + end - start) as u16).to_be_bytes());
            packet[6] = 44;
            packet[7] = 64;
            packet[8..24].copy_from_slice(&source.octets());
            packet[24..40].copy_from_slice(&target.octets());
            packet[40] = 60;
            let flags = start as u16 | u16::from(end != fragmentable.len());
            packet[42..44].copy_from_slice(&flags.to_be_bytes());
            packet[44..48].copy_from_slice(&123u32.to_be_bytes());
            packet.extend_from_slice(&fragmentable[start..end]);
            packet
        })
        .collect()
}
