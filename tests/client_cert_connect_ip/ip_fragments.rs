use super::*;

#[path = "../support/ipv6_fragments.rs"]
mod fragments;

#[test]
#[ignore = "requires an isolated Linux network namespace and TUN; run tests/connect-ip-fragments.sh"]
fn ipv6_fragments_reach_udp_target() {
    let dir = TempDir::new("ipv6-fragments");
    let key = p256_key();
    let (cert, key) = write_pem(dir.path(), "server", &key, &self_signed(&key, None));
    let mut config = server_config(cert, key, ephemeral_addr(), vec![]);
    config.listeners[0].auth.enabled = false;
    fragments::configure(&mut config);
    let peer = spawn_server(config)[0];
    let target = UdpSocket::bind((fragments::TARGET, 0)).unwrap();
    target.set_nonblocking(true).unwrap();
    for native in [false, true] {
        let mut client = Client::connect_with_transport(
            peer,
            None,
            None,
            false,
            "127.0.0.1".parse().unwrap(),
            native,
            262_144,
        )
        .unwrap();
        client.handshake(Duration::from_secs(5)).unwrap();
        client.init_h3().unwrap();
        let stream = client.send_connect_ip("connect-ip").unwrap();
        assert_eq!(
            client
                .response_status(stream, Duration::from_secs(5))
                .unwrap(),
            200
        );
        let frames = client.capsules(stream, 2, Duration::from_secs(5));
        let source = fragments::assigned_source(&frames);
        for packet in fragments::packets(source, target.local_addr().unwrap().port()) {
            if native {
                let wire = DatagramHeader::new(stream).unwrap().encode(&packet);
                client.quic.dgram_send(&wire).unwrap();
            } else {
                let mut payload = vec![0];
                payload.extend_from_slice(&packet);
                let mut wire = Vec::new();
                masque::capsule::encoder::encode(&CapsuleFrame::Datagram(payload), &mut wire);
                client
                    .h3
                    .as_mut()
                    .unwrap()
                    .send_body(&mut client.quic, stream, &wire, false)
                    .unwrap();
            }
        }
        client.flush().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let mut response = [0; 64];
            match target.recv_from(&mut response) {
                Ok((length, peer)) => {
                    assert_eq!(&response[..length], &fragments::PAYLOAD);
                    assert_eq!(peer.ip(), source);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "fragmented IPv6 datagram did not reach the UDP target (native={native})"
                    );
                    client.drive().unwrap();
                }
                Err(error) => panic!("UDP receive failed: {error}"),
            }
        }
    }
}
