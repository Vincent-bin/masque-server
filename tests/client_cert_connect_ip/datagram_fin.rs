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
    drain_responses_with_prefix(client, blocker, stream, pending_headers, Vec::new());
}

fn drain_responses_with_prefix(
    client: &mut Client,
    blocker: u64,
    stream: u64,
    pending_headers: bool,
    mut body: Vec<u8>,
) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut finished = Vec::new();
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

#[test]
fn udp_native_datagrams_after_body_fin_are_not_replayed_after_pending_response() {
    let (_dir, mut client, target) = fixture();
    let blocker = block_response_credit(&mut client);
    let stream = udp_request(&mut client, &target, false);
    let mut capsule = Vec::new();
    encoder::encode_datagram_context_zero(b"capsule before pending FIN", &mut capsule);
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
    // HEADERS cannot complete, so the server has the full body and FIN but
    // has not consumed that body. Send native input in a later QUIC packet.
    assert_blocked(&mut client, stream);
    send_native(&mut client, stream, b"native after pending body FIN");
    assert_no_target_packet(&mut client, &target);
    drain_responses(&mut client, blocker, stream, true);
    receive_target(&mut client, &target, b"capsule before pending FIN");
    assert_no_target_packet(&mut client, &target);
    let replacement = open_udp(&mut client, &target);
    send_native(&mut client, replacement, b"replacement works");
    receive_target(&mut client, &target, b"replacement works");
}

fn send_empty_data(client: &mut Client, stream: u64, count: usize) {
    // send_body suppresses non-FIN empty DATA frames. Insert their valid H3
    // encoding directly, ahead of the real capsule body and its FIN.
    let wire = vec![0; 2 * count];
    assert_eq!(
        client.quic.stream_send(stream, &wire, false).unwrap(),
        wire.len()
    );
}

#[test]
fn pending_udp_body_fin_after_empty_data_drains_body_without_more_client_packets() {
    let (_dir, mut client, target) = fixture();
    let blocker = block_response_credit(&mut client);
    let stream = udp_request(&mut client, &target, false);
    send_empty_data(&mut client, stream, 256);
    let mut capsule = Vec::new();
    encoder::encode_datagram_context_zero(b"capsule after empty frames", &mut capsule);
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
    assert_blocked(&mut client, stream);
    send_native(
        &mut client,
        stream,
        b"late native after empty frames and FIN",
    );
    assert_no_target_packet(&mut client, &target);
    let mut buffer = [0; 4096];
    let mut prefix = Vec::new();
    while let Ok(count) =
        client
            .h3
            .as_mut()
            .unwrap()
            .recv_body(&mut client.quic, blocker, &mut buffer)
    {
        if count == 0 {
            break;
        }
        prefix.extend_from_slice(&buffer[..count]);
    }
    client.flush().unwrap();
    // Grant credit once, then withhold every client packet, including ACKs.
    // Delivery of the capsule beyond 256 empty frames proves local parsing
    // progress. The large blocker can legitimately use up response FIN credit.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        client.recv_once().unwrap();
        match target.recv(&mut buffer) {
            Ok(len) => {
                assert_eq!(&buffer[..len], b"capsule after empty frames");
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "buffered empty DATA/FIN needed another client packet"
                );
            }
            Err(e) => panic!("target receive failed: {e}"),
        }
    }
    // Restore output credit separately and still require the full control
    // reply and a clean response FIN, with no post-FIN native packet delivered.
    drain_responses_with_prefix(&mut client, blocker, stream, true, prefix);
    assert_no_target_packet(&mut client, &target);
}

// Release the blocker without requiring the tested stream's send side to
// finish, so open-request and malformed-request cases can check their outcome.
fn release_blocker(client: &mut Client, blocker: u64, stream: u64, reset: Option<u64>) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut blocker_done = false;
    let mut headers = false;
    let mut reset_seen = false;
    while !blocker_done || !headers || (reset.is_some() && !reset_seen) {
        while let Ok((id, event)) = client.h3.as_mut().unwrap().poll(&mut client.quic) {
            match event {
                quiche::h3::Event::Finished if id == blocker => blocker_done = true,
                quiche::h3::Event::Headers { list, .. } if id == stream => {
                    assert!(
                        list.iter()
                            .any(|h| h.name() == b":status" && h.value() == b"200")
                    );
                    headers = true;
                }
                quiche::h3::Event::Reset(code) if id == stream => {
                    assert_eq!(Some(code), reset);
                    reset_seen = true;
                }
                quiche::h3::Event::Finished if id == stream => {
                    panic!("request unexpectedly finished")
                }
                _ => {}
            }
        }
        let mut buffer = [0; 4096];
        while client
            .h3
            .as_mut()
            .unwrap()
            .recv_body(&mut client.quic, blocker, &mut buffer)
            .is_ok()
        {}
        assert!(Instant::now() < deadline, "pending response did not resume");
        client.drive().unwrap();
    }
}

#[test]
fn pending_open_udp_body_preserves_capsules_and_bounded_early_native_input() {
    let (_dir, mut client, target) = fixture();
    let blocker = block_response_credit(&mut client);
    let stream = udp_request(&mut client, &target, false);
    send_empty_data(&mut client, stream, 256);
    let mut capsule = Vec::new();
    encoder::encode_datagram_context_zero(b"open capsule", &mut capsule);
    assert_eq!(
        client
            .h3
            .as_mut()
            .unwrap()
            .send_body(&mut client.quic, stream, &capsule, false)
            .unwrap(),
        capsule.len()
    );
    client.flush().unwrap();
    assert_blocked(&mut client, stream);
    send_native(&mut client, stream, b"open native");
    assert_no_target_packet(&mut client, &target);
    release_blocker(&mut client, blocker, stream, None);
    // No relative ordering is guaranteed across capsule and native delivery.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut received = Vec::new();
    while received.len() < 2 {
        let mut buffer = [0; 2048];
        match target.recv(&mut buffer) {
            Ok(len) => received.push(buffer[..len].to_vec()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "open input was lost");
                client.drive().unwrap();
            }
            Err(e) => panic!("target receive failed: {e}"),
        }
    }
    received.sort();
    assert_eq!(
        received,
        [b"open capsule".to_vec(), b"open native".to_vec()]
    );
    send_native(&mut client, stream, b"still open");
    receive_target(&mut client, &target, b"still open");
}

#[test]
fn pending_truncated_udp_body_fin_drops_early_native_input() {
    let (_dir, mut client, target) = fixture();
    let blocker = block_response_credit(&mut client);
    let stream = udp_request(&mut client, &target, false);
    send_empty_data(&mut client, stream, 256);
    // DATAGRAM capsule claims two bytes but only carries Context ID zero.
    client
        .h3
        .as_mut()
        .unwrap()
        .send_body(&mut client.quic, stream, &[0, 2, 0], true)
        .unwrap();
    client.flush().unwrap();
    assert_blocked(&mut client, stream);
    send_native(&mut client, stream, b"native after malformed FIN");
    assert_no_target_packet(&mut client, &target);
    release_blocker(
        &mut client,
        blocker,
        stream,
        Some(quiche::h3::WireErrorCode::MessageError as u64),
    );
    assert_no_target_packet(&mut client, &target);
    let replacement = open_udp(&mut client, &target);
    send_native(&mut client, replacement, b"replacement works");
    receive_target(&mut client, &target, b"replacement works");
}

#[test]
fn udp_stop_sending_drops_late_native_responses_without_affecting_siblings() {
    let (_dir, mut client, target) = fixture();
    let stopped = open_udp(&mut client, &target);
    let sibling = open_udp(&mut client, &target);
    let mut target_peers = Vec::new();
    let mut buf = [0; 128];
    for stream in [stopped, sibling] {
        send_native(&mut client, stream, b"discover target socket");
        let deadline = Instant::now() + Duration::from_secs(3);
        let peer = loop {
            client.drive().unwrap();
            match target.recv_from(&mut buf) {
                Ok((len, peer)) => {
                    assert_eq!(&buf[..len], b"discover target socket");
                    break peer;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "no datagram reached target");
                }
                Err(e) => panic!("target receive: {e}"),
            }
        };
        target_peers.push(peer);
    }

    client
        .quic
        .stream_shutdown(
            stopped,
            quiche::Shutdown::Read,
            quiche::h3::WireErrorCode::RequestCancelled as u64,
        )
        .unwrap();
    client.flush().unwrap();
    let check = client
        .h3
        .as_mut()
        .unwrap()
        .send_request(
            &mut client.quic,
            &[
                quiche::h3::Header::new(b":method", b"GET"),
                quiche::h3::Header::new(b":scheme", b"https"),
                quiche::h3::Header::new(b":authority", b"localhost"),
                quiche::h3::Header::new(b":path", b"/"),
            ],
            true,
        )
        .unwrap();
    assert_eq!(
        client
            .response_status(check, Duration::from_secs(2))
            .unwrap(),
        404
    );
    target.send_to(b"late response", target_peers[0]).unwrap();
    target.send_to(b"active response", target_peers[1]).unwrap();

    let deadline = Instant::now() + Duration::from_millis(700);
    let mut received_sibling = false;
    while Instant::now() < deadline {
        client.drive().unwrap();
        while let Ok(len) = client.quic.dgram_recv(&mut buf) {
            let datagram = masque::datagram::decode_ref(&buf[..len]).unwrap();
            assert_ne!(
                datagram.stream_id, stopped,
                "datagram arrived after STOP_SENDING"
            );
            assert_eq!(datagram.stream_id, sibling);
            assert_eq!(datagram.payload, b"active response");
            received_sibling = true;
        }
    }
    assert!(received_sibling);
    assert!(client.quic.peer_error().is_none());
}
