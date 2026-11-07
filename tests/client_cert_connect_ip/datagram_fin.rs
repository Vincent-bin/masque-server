//! Native DATAGRAM input closes independently of a blocked response FIN.

use super::*;
use masque::capsule::{RequestedAddress, encoder};

fn fixture() -> (TempDir, Client, UdpSocket) {
    let dir = TempDir::new("native-datagram-fin");
    let key = p256_key();
    let (cert, key) = write_pem(dir.path(), "server", &key, &self_signed(&key, None));
    let mut config = ServerConfig::default();
    config.tls.cert_path = cert;
    config.tls.key_path = key;
    config.listeners[0].listen_addr = ephemeral_addr();
    config.listeners[0].shards = 1;
    config.listeners[0].auth.enabled = false;
    config.udp_proxy.allow_targets = vec!["127.0.0.0/8".into()];
    config.udp_proxy.deny_targets.clear();
    let peer = spawn_server(config)[0];
    let mut client = Client::connect_with_windows(
        peer,
        None,
        None,
        false,
        "127.0.0.1".parse().unwrap(),
        true,
        4096,
        256,
    )
    .unwrap();
    client
        .socket
        .set_read_timeout(Some(Duration::from_millis(2)))
        .unwrap();
    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();
    let target = UdpSocket::bind(ephemeral_addr()).unwrap();
    target.set_nonblocking(true).unwrap();
    (dir, client, target)
}

fn udp_request(client: &mut Client, target: &UdpSocket, fin: bool) -> u64 {
    let target = target.local_addr().unwrap();
    let path = format!("/.well-known/masque/udp/{}/{}/", target.ip(), target.port());
    let headers = [
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"connect-udp"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"localhost"),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
    ];
    let stream = client
        .h3
        .as_mut()
        .unwrap()
        .send_request(&mut client.quic, &headers, fin)
        .unwrap();
    client.flush().unwrap();
    stream
}

fn open_udp(client: &mut Client, target: &UdpSocket) -> u64 {
    let stream = udp_request(client, target, false);
    assert_eq!(
        client
            .response_status(stream, Duration::from_secs(5))
            .unwrap(),
        200
    );
    stream
}

fn block_response_credit(client: &mut Client) -> u64 {
    let stream = client.send_connect_ip("connect-ip").unwrap();
    assert_eq!(
        client
            .response_status(stream, Duration::from_secs(5))
            .unwrap(),
        200
    );
    assert_eq!(client.capsules(stream, 2, Duration::from_secs(5)).len(), 2);
    let mut wire = Vec::new();
    encoder::encode(
        &CapsuleFrame::AddressRequest(
            (1..=256)
                .map(|request_id| RequestedAddress {
                    request_id,
                    ip: IpAddress::V4(Ipv4Addr::UNSPECIFIED),
                    prefix_len: 32,
                })
                .collect(),
        ),
        &mut wire,
    );
    assert_eq!(
        client
            .h3
            .as_mut()
            .unwrap()
            .send_body(&mut client.quic, stream, &wire, true)
            .unwrap(),
        wire.len()
    );
    client.flush().unwrap();
    // Receiving, but not reading, a response larger than the entire connection
    // window blocks every subsequent response FIN and pending CONNECT header.
    let until = Instant::now() + Duration::from_millis(300);
    while Instant::now() < until {
        client.drive().unwrap();
    }
    stream
}

fn send_native(client: &mut Client, stream: u64, payload: &[u8]) {
    client
        .quic
        .dgram_send(&DatagramHeader::new(stream).unwrap().encode(payload))
        .unwrap();
    client.flush().unwrap();
}

fn receive_target(client: &mut Client, target: &UdpSocket, expected: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0; 2048];
    loop {
        match target.recv(&mut buf) {
            Ok(len) => {
                assert_eq!(&buf[..len], expected);
                return;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "valid datagram did not reach target"
                );
                client.drive().unwrap();
            }
            Err(e) => panic!("target receive failed: {e}"),
        }
    }
}

fn assert_blocked(client: &mut Client, stream: u64) {
    let until = Instant::now() + Duration::from_millis(300);
    while Instant::now() < until {
        client.drive().unwrap();
        while let Ok((id, event)) = client.h3.as_mut().unwrap().poll(&mut client.quic) {
            assert_ne!(id, stream, "response was not blocked: {event:?}");
        }
    }
}

fn assert_no_target_packet(client: &mut Client, target: &UdpSocket) {
    let until = Instant::now() + Duration::from_millis(300);
    while Instant::now() < until {
        client.drive().unwrap();
        let error = target
            .recv(&mut [0; 2048])
            .expect_err("native datagram after request FIN reached target");
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    }
    assert!(
        client.quic.peer_error().is_none(),
        "late DATAGRAM must be silently discarded"
    );
}

fn drain_responses(client: &mut Client, blocker: u64, stream: u64, pending_headers: bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut finished = Vec::new();
    let mut body = Vec::new();
    let mut headers_seen = false;
    while finished.len() < 2 {
        while let Ok((id, event)) = client.h3.as_mut().unwrap().poll(&mut client.quic) {
            if id != blocker && id != stream {
                continue;
            }
            match event {
                quiche::h3::Event::Headers { list, .. } if id == stream => {
                    assert!(pending_headers && !headers_seen);
                    assert!(
                        list.iter()
                            .any(|h| h.name() == b":status" && h.value() == b"200")
                    );
                    headers_seen = true;
                }
                quiche::h3::Event::Finished => {
                    assert!(!finished.contains(&id));
                    finished.push(id);
                }
                quiche::h3::Event::Reset(code) => {
                    panic!("response reset instead of draining: {code}")
                }
                _ => {}
            }
        }
        for id in [blocker, stream] {
            let mut buffer = [0; 4096];
            while let Ok(count) =
                client
                    .h3
                    .as_mut()
                    .unwrap()
                    .recv_body(&mut client.quic, id, &mut buffer)
            {
                if count == 0 {
                    break;
                }
                assert_eq!(id, blocker, "UDP response must stay empty");
                body.extend_from_slice(&buffer[..count]);
            }
        }
        assert!(Instant::now() < deadline, "queued reply/FIN did not finish");
        client.drive().unwrap();
    }
    assert_eq!(headers_seen, pending_headers);
    let frames = CapsuleDecoder::new().decode(&body).unwrap();
    let [CapsuleFrame::AddressAssign(assigned)] = frames.as_slice() else {
        panic!("incomplete control reply: {frames:?}");
    };
    assert_eq!(
        assigned
            .iter()
            .filter(|entry| entry.request_id != 0)
            .count(),
        256
    );
    for id in 1..=256 {
        assert_eq!(
            assigned
                .iter()
                .filter(|entry| entry.request_id == id)
                .count(),
            1
        );
    }
    assert!(client.quic.peer_error().is_none());
}

#[test]
fn udp_native_datagrams_stop_at_request_fin_while_response_fin_is_blocked() {
    let (_dir, mut client, target) = fixture();
    let stream = open_udp(&mut client, &target);
    let sibling = open_udp(&mut client, &target);
    send_native(&mut client, stream, b"before FIN");
    receive_target(&mut client, &target, b"before FIN");
    let blocker = block_response_credit(&mut client);
    // This capsule was received before FIN in the same body read. The native
    // guard must not discard it merely because forwarding runs after EOF.
    let mut capsule = Vec::new();
    encoder::encode_datagram_context_zero(b"capsule before FIN", &mut capsule);
    assert_eq!(
        client
            .h3
            .as_mut()
            .unwrap()
            .send_body(&mut client.quic, stream, &capsule, true)
            .unwrap(),
        capsule.len()
    );
    client.flush().unwrap();
    receive_target(&mut client, &target, b"capsule before FIN");
    assert_blocked(&mut client, stream);
    for _ in 0..3 {
        send_native(&mut client, stream, b"after FIN");
        assert_no_target_packet(&mut client, &target);
    }
    send_native(&mut client, sibling, b"sibling still open");
    receive_target(&mut client, &target, b"sibling still open");
    drain_responses(&mut client, blocker, stream, false);
    let replacement = open_udp(&mut client, &target);
    send_native(&mut client, replacement, b"replacement works");
    receive_target(&mut client, &target, b"replacement works");
}

#[test]
fn udp_native_datagrams_after_headers_fin_are_not_buffered_during_pending_setup() {
    let (_dir, mut client, target) = fixture();
    let blocker = block_response_credit(&mut client);
    let stream = udp_request(&mut client, &target, true);
    assert_blocked(&mut client, stream);
    send_native(&mut client, stream, b"after pending FIN");
    assert_no_target_packet(&mut client, &target);
    drain_responses(&mut client, blocker, stream, true);
    assert_no_target_packet(&mut client, &target);
    let replacement = open_udp(&mut client, &target);
    send_native(&mut client, replacement, b"replacement works");
    receive_target(&mut client, &target, b"replacement works");
}
