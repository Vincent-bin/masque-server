use super::*;
use masque::capsule::{AssignedAddress, encoder};

#[cfg(target_os = "linux")]
use super::ipv6_fragments as packets;

fn request_addresses(client: &mut Client, stream: u64, tail: &[u8]) {
    let mut wire = Vec::new();
    encoder::encode(
        &CapsuleFrame::AddressRequest(
            (1..=256)
                .map(|request_id| AssignedAddress {
                    request_id,
                    ip: IpAddress::V6(Ipv6Addr::UNSPECIFIED),
                    prefix_len: 128,
                })
                .collect(),
        ),
        &mut wire,
    );
    wire.extend_from_slice(tail);
    assert_eq!(
        client
            .h3
            .as_mut()
            .unwrap()
            .send_body(&mut client.quic, stream, &wire, false)
            .unwrap(),
        wire.len()
    );
    client.flush().unwrap();
    // Do not consume the response: a DATA event proves the complete request
    // was parsed, but leaves its reply blocked on the 64-byte stream window.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        while let Ok((id, event)) = client.h3.as_mut().unwrap().poll(&mut client.quic) {
            if id == stream {
                match event {
                    quiche::h3::Event::Data => return,
                    quiche::h3::Event::Reset(code) => panic!("unexpected reset: {code}"),
                    _ => {}
                }
            }
        }
        assert!(Instant::now() < deadline, "missing blocked response prefix");
        client.drive().unwrap();
    }
}

fn finish_request(client: &mut Client, stream: u64) {
    client
        .h3
        .as_mut()
        .unwrap()
        .send_body(&mut client.quic, stream, &[], true)
        .unwrap();
    client.flush().unwrap();
    // Deliver FIN while still withholding response credit. Reading first
    // would allow the response to drain and fail to exercise the regression.
    let deadline = Instant::now() + Duration::from_millis(300);
    while Instant::now() < deadline {
        client.drive().unwrap();
    }
}

fn read_finished_reply(client: &mut Client, stream: u64) -> Vec<CapsuleFrame> {
    let mut decoder = CapsuleDecoder::new();
    let mut frames = Vec::new();
    let mut input = [0; 4096];
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        while let Ok((id, event)) = client.h3.as_mut().unwrap().poll(&mut client.quic) {
            if id == stream {
                match event {
                    quiche::h3::Event::Finished => return frames,
                    quiche::h3::Event::Reset(code) => panic!("reply reset before FIN: {code}"),
                    _ => {}
                }
            }
        }
        loop {
            match client
                .h3
                .as_mut()
                .unwrap()
                .recv_body(&mut client.quic, stream, &mut input)
            {
                Ok(0) | Err(quiche::h3::Error::Done) => break,
                Ok(count) => match decoder.decode(&input[..count]) {
                    Ok(mut decoded) => frames.append(&mut decoded),
                    Err(DecodeError::Incomplete) => {}
                    Err(error) => panic!("invalid response capsule: {error:?}"),
                },
                Err(error) => panic!("response body failed: {error:?}"),
            }
        }
        assert!(Instant::now() < deadline, "response did not finish");
        client.drive().unwrap();
    }
}

#[test]
fn separate_fin_drains_blocked_ip_address_reply_and_releases_leases() {
    let fixture = fixture("ip-fin-drain");
    for native_datagrams in [false, true] {
        let mut client = Client::connect_with_transport(
            fixture.peer,
            Some((&fixture.client_cert, &fixture.client_key)),
            None,
            false,
            "127.0.0.1".parse().unwrap(),
            native_datagrams,
            64,
        )
        .unwrap();
        client.handshake(Duration::from_secs(5)).unwrap();
        client.init_h3().unwrap();
        for protocol in ["connect-ip", "cf-connect-ip"] {
            let stream = client.send_connect_ip(protocol).unwrap();
            assert_eq!(
                client
                    .response_status(stream, Duration::from_secs(5))
                    .unwrap(),
                200
            );
            assert_eq!(client.capsules(stream, 2, Duration::from_secs(5)).len(), 2);
            request_addresses(&mut client, stream, &[]);
            finish_request(&mut client, stream);
            let reply = read_finished_reply(&mut client, stream);
            let [CapsuleFrame::AddressAssign(assigned)] = reply.as_slice() else {
                panic!("missing complete ADDRESS_ASSIGN: {reply:?}");
            };
            // Verify the entire response, not just its first capsule byte.
            for id in 1..=256 {
                let entries: Vec<_> = assigned
                    .iter()
                    .filter(|entry| entry.request_id == id)
                    .collect();
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].ip, IpAddress::V6(CLIENT_IPV6.parse().unwrap()));
                assert_eq!(entries[0].prefix_len, 128);
            }
            assert!(client.quic.peer_error().is_none());
            // The next CONNECT reuses the same pinned leases, proving normal
            // completion releases routes/addresses without closing QUIC.
        }
        let stream = client.send_connect_ip("connect-ip").unwrap();
        assert_eq!(
            client
                .response_status(stream, Duration::from_secs(5))
                .unwrap(),
            200
        );
        assert_eq!(client.capsules(stream, 2, Duration::from_secs(5)).len(), 2);
        finish_request(&mut client, stream);
        assert!(read_finished_reply(&mut client, stream).is_empty());
    }
}

#[test]
fn separate_fin_rejects_truncated_ip_input_before_draining_blocked_reply() {
    let fixture = fixture("ip-fin-truncated-drain");
    let mut client = Client::connect_with_transport(
        fixture.peer,
        Some((&fixture.client_cert, &fixture.client_key)),
        None,
        false,
        "127.0.0.1".parse().unwrap(),
        false,
        64,
    )
    .unwrap();
    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();
    for tail in [&[0xff][..], &[2, 8, 1, 4, 0][..]] {
        let stream = client.send_connect_ip("connect-ip").unwrap();
        assert_eq!(
            client
                .response_status(stream, Duration::from_secs(5))
                .unwrap(),
            200
        );
        assert_eq!(client.capsules(stream, 2, Duration::from_secs(5)).len(), 2);
        request_addresses(&mut client, stream, tail);
        finish_request(&mut client, stream);
        assert_eq!(
            client.stream_reset(stream),
            quiche::h3::WireErrorCode::MessageError as u64
        );
        assert!(client.quic.peer_error().is_none());
    }
}

#[test]
fn blocked_ip_fin_drain_expires_despite_late_native_datagrams() {
    let dir = TempDir::new("ip-fin-drain-timeout");
    let key = p256_key();
    let (cert, key) = write_pem(dir.path(), "server", &key, &self_signed(&key, None));
    let mut config = server_config(cert, key, ephemeral_addr(), vec![]);
    config.listeners[0].auth.enabled = false;
    config.server.idle_timeout_secs = 1;
    config.server.max_tunnels_per_connection = 1;
    config.ip_proxy.ipv4_pool = "10.89.0.0/30".into();
    config.ip_proxy.ipv6_pool = "fd00:abcd::/126".into();
    config.ip_proxy.allow_targets = vec!["192.0.2.0/24".into()];
    config.ip_proxy.deny_targets.clear();
    let peer = spawn_server(config)[0];
    let mut client = Client::connect_with_transport(
        peer,
        None,
        None,
        false,
        "127.0.0.1".parse().unwrap(),
        true,
        64,
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
    let setup = client.capsules(stream, 2, Duration::from_secs(5));
    assert_eq!(setup.len(), 2);
    let source = setup
        .iter()
        .find_map(|frame| {
            let CapsuleFrame::AddressAssign(assigned) = frame else {
                return None;
            };
            assigned.iter().find_map(|entry| match entry.ip {
                IpAddress::V4(ip) => Some(ip),
                _ => None,
            })
        })
        .unwrap();
    request_addresses(&mut client, stream, &[]);
    let finished_at = Instant::now();
    finish_request(&mut client, stream);

    // Keep attempting valid native input after FIN without a target or TUN.
    // These packets must be discarded and cannot renew the drain deadline.
    let mut packet = [0; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&20u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 253;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
    let wire = DatagramHeader::new(stream).unwrap().encode(&packet);
    let deadline = finished_at + Duration::from_secs(4);
    'wait_for_reset: loop {
        client.quic.dgram_send(&wire).unwrap();
        client.flush().unwrap();
        client.drive().unwrap();
        while let Ok((id, event)) = client.h3.as_mut().unwrap().poll(&mut client.quic) {
            if id == stream {
                match event {
                    quiche::h3::Event::Reset(code) => {
                        assert_eq!(code, quiche::h3::WireErrorCode::RequestCancelled as u64);
                        break 'wait_for_reset;
                    }
                    quiche::h3::Event::Finished => panic!("incomplete reply must reset, not FIN"),
                    _ => {}
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "activity renewed the FIN drain deadline"
        );
    }
    assert!(client.quic.peer_error().is_none());
    // Expiry must return the only tunnel slot and the single usable IPv4
    // lease, even though the client never consumed the blocked response.
    let next = client.send_connect_ip("connect-ip").unwrap();
    assert_eq!(
        client
            .response_status(next, Duration::from_secs(5))
            .unwrap(),
        200
    );
    let setup = client.capsules(next, 2, Duration::from_secs(5));
    assert_eq!(setup.len(), 2);
    assert!(setup.iter().any(|frame| matches!(frame,
        CapsuleFrame::AddressAssign(assigned) if assigned.iter().any(|entry| entry.ip == IpAddress::V4(source)))));
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires an isolated Linux network namespace and TUN; run tests/connect-ip-fin.sh"]
fn ip_native_datagrams_stop_at_request_fin_while_control_reply_is_blocked() {
    let dir = TempDir::new("ip-native-fin");
    let key = p256_key();
    let (cert, key) = write_pem(dir.path(), "server", &key, &self_signed(&key, None));
    let mut config = server_config(cert, key, ephemeral_addr(), vec![]);
    config.listeners[0].auth.enabled = false;
    packets::configure(&mut config);
    let peer = spawn_server(config)[0];
    let target = UdpSocket::bind((packets::TARGET, 0)).unwrap();
    target.set_nonblocking(true).unwrap();
    let mut client = Client::connect_with_transport(
        peer,
        None,
        None,
        false,
        "127.0.0.1".parse().unwrap(),
        true,
        64,
    )
    .unwrap();
    client
        .socket
        .set_read_timeout(Some(Duration::from_millis(2)))
        .unwrap();
    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();
    for protocol in ["connect-ip", "cf-connect-ip"] {
        let stream = client.send_connect_ip(protocol).unwrap();
        assert_eq!(
            client
                .response_status(stream, Duration::from_secs(5))
                .unwrap(),
            200
        );
        let setup = client.capsules(stream, 2, Duration::from_secs(5));
        let source = packets::assigned_source(&setup);
        let wire_packets = packets::packets(source, target.local_addr().unwrap().port());
        let send = |client: &mut Client| {
            for packet in &wire_packets {
                let wire = DatagramHeader::new(stream).unwrap().encode(packet);
                client.quic.dgram_send(&wire).unwrap();
            }
            client.flush().unwrap();
        };
        // A real kernel-delivered payload before FIN rules out a false pass
        // caused by disabled TUN forwarding, policy, or invalid packet bytes.
        send(&mut client);
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut received = [0; 2048];
        loop {
            match target.recv_from(&mut received) {
                Ok((length, from)) => {
                    assert_eq!(&received[..length], &packets::PAYLOAD);
                    assert_eq!(from.ip(), source);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "pre-FIN IP forwarding failed");
                    client.drive().unwrap();
                }
                Err(e) => panic!("target receive failed: {e}"),
            }
        }
        request_addresses(&mut client, stream, &[]);
        finish_request(&mut client, stream);
        send(&mut client);
        let until = Instant::now() + Duration::from_millis(500);
        while Instant::now() < until {
            client.drive().unwrap();
            let error = target
                .recv(&mut received)
                .expect_err("IP native DATAGRAM after FIN reached TUN target");
            assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
            while let Ok((id, event)) = client.h3.as_mut().unwrap().poll(&mut client.quic) {
                if id == stream {
                    assert!(
                        !matches!(
                            event,
                            quiche::h3::Event::Finished | quiche::h3::Event::Reset(_)
                        ),
                        "control reply did not remain blocked: {event:?}"
                    );
                }
            }
        }
        let frames = read_finished_reply(&mut client, stream);
        let [CapsuleFrame::AddressAssign(assigned)] = frames.as_slice() else {
            panic!("incomplete control reply: {frames:?}");
        };
        for id in 1..=256 {
            let entries: Vec<_> = assigned
                .iter()
                .filter(|entry| entry.request_id == id)
                .collect();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].ip, IpAddress::V6(source));
            assert_eq!(entries[0].prefix_len, 128);
        }
        assert!(client.quic.peer_error().is_none());
        // The next protocol reuses the same connection and released leases.
    }
}

#[test]
fn stop_sending_releases_connect_ip_address_before_replacement() {
    let dir = TempDir::new("ip-stop-sending");
    let key = p256_key();
    let (cert, key) = write_pem(dir.path(), "server", &key, &self_signed(&key, None));
    let mut config = server_config(cert, key, ephemeral_addr(), vec![]);
    config.listeners[0].auth.enabled = false;
    config.ip_proxy.ipv4_pool = "10.89.0.0/30".into();
    config.ip_proxy.ipv6_pool.clear();
    let peer = spawn_server(config)[0];
    let mut client = Client::connect_anonymous(peer).unwrap();
    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();

    let first = client.send_connect_ip("connect-ip").unwrap();
    assert_eq!(
        client
            .response_status(first, Duration::from_secs(5))
            .unwrap(),
        200
    );
    let addresses = assigned_addresses(&mut client, first);
    assert_eq!(addresses.len(), 1);
    client
        .quic
        .stream_shutdown(
            first,
            quiche::Shutdown::Read,
            quiche::h3::WireErrorCode::RequestCancelled as u64,
        )
        .unwrap();
    let replacement = client.send_connect_ip("connect-ip").unwrap();
    assert_eq!(
        client
            .response_status(replacement, Duration::from_secs(5))
            .unwrap(),
        200
    );
    assert_eq!(assigned_addresses(&mut client, replacement), addresses);
}
