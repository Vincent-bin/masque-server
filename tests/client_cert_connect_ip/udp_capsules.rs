//! CONNECT-UDP shares the same skip/length/EOF behavior on HTTP/2 and HTTP/3.

use super::*;
use masque::capsule::encoder;

#[path = "../support/udp_capsules.rs"]
mod wire_fixtures;

fn open_udp(client: &mut Client, target: SocketAddr) -> u64 {
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
        .send_request(&mut client.quic, &headers, false)
        .unwrap();
    assert_eq!(
        client
            .response_status(stream, Duration::from_secs(5))
            .unwrap(),
        200
    );
    stream
}

fn send_fragment(client: &mut Client, stream: u64, mut bytes: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !bytes.is_empty() {
        match client
            .h3
            .as_mut()
            .unwrap()
            .send_body(&mut client.quic, stream, bytes, false)
        {
            Ok(0) | Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {
                assert!(
                    Instant::now() < deadline,
                    "capsule input stayed flow-control blocked"
                );
                client.drive().unwrap();
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) => panic!("sending capsule fragment failed: {error}"),
        }
        client.flush().unwrap();
    }
}

fn fixture() -> (TempDir, Client, UdpSocket) {
    let dir = TempDir::new("h3-udp-unknown-capsules");
    let key = p256_key();
    let (cert, key_path) = write_pem(
        dir.path(),
        "server",
        &key,
        &self_signed(&key, Some("localhost")),
    );
    let mut config = ServerConfig::default();
    config.tls.cert_path = cert;
    config.tls.key_path = key_path;
    config.listeners[0].listen_addr = ephemeral_addr();
    config.listeners[0].shards = 1;
    config.listeners[0].auth.enabled = false;
    config.ip_proxy.enabled = false;
    config.udp_proxy.allow_targets = vec!["127.0.0.0/8".into()];
    config.udp_proxy.deny_targets.clear();
    config.quic.initial_max_stream_data = 4096;
    let peer = spawn_server(config)[0];
    let target = UdpSocket::bind(ephemeral_addr()).unwrap();
    target.set_nonblocking(true).unwrap();
    let mut client = Client::connect_with_transport(
        peer,
        None,
        None,
        false,
        "127.0.0.1".parse().unwrap(),
        false,
        262_144,
    )
    .unwrap();
    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();
    (dir, client, target)
}

fn assert_echo(client: &mut Client, target: &UdpSocket, stream: u64, payload: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut received = vec![0; payload.len() + 1];
    let (length, source) = loop {
        match target.recv_from(&mut received) {
            Ok(packet) => break packet,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "UDP payload did not reach the target"
                );
                client.drive().unwrap();
            }
            Err(error) => panic!("target receive failed: {error}"),
        }
    };
    assert_eq!(&received[..length], payload);
    target.send_to(payload, source).unwrap();
    assert_eq!(
        client.capsules(stream, 1, Duration::from_secs(5)),
        [CapsuleFrame::Datagram([&[0][..], payload].concat())]
    );
    assert!(client.quic.peer_error().is_none());
}

fn assert_clean_finish(client: &mut Client, stream: u64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match client.h3.as_mut().unwrap().poll(&mut client.quic) {
            Ok((id, quiche::h3::Event::Finished)) if id == stream => return,
            Ok((id, quiche::h3::Event::Reset(code))) if id == stream => {
                panic!("complete capsules were reset with {code}");
            }
            Ok(_) => {}
            Err(quiche::h3::Error::Done) => {
                assert!(
                    Instant::now() < deadline,
                    "complete capsule stream did not finish"
                );
                client.drive().unwrap();
            }
            Err(error) => panic!("HTTP/3 poll while waiting for FIN: {error}"),
        }
    }
}

#[test]
fn http3_udp_unknown_capsules_match_http2_streaming_and_truncation_behavior() {
    let (_dir, mut client, target) = fixture();

    let mut malformed = wire_fixtures::truncated_capsules()
        .into_iter()
        .map(|wire| (wire, true))
        .collect::<Vec<_>>();
    let mut oversized = vec![0];
    masque::varint::encode_to_vec(65_536, &mut oversized).unwrap();
    // Reject an oversized known DATAGRAM from its length, without FIN/value.
    malformed.push((oversized, false));
    for (wire, finish) in malformed {
        let stream = open_udp(&mut client, target.local_addr().unwrap());
        send_fragment(&mut client, stream, &wire);
        if finish {
            client
                .h3
                .as_mut()
                .unwrap()
                .send_body(&mut client.quic, stream, &[], true)
                .unwrap();
        }
        client.flush().unwrap();
        assert_eq!(
            client.stream_reset(stream),
            quiche::h3::WireErrorCode::MessageError as u64
        );
        assert!(client.quic.peer_error().is_none());
    }

    let stream = open_udp(&mut client, target.local_addr().unwrap());
    for marker in [0x55, 0x77] {
        let payload = [marker; 1200];
        let wire = wire_fixtures::ignored_capsules_then_datagram(&payload);
        for chunk in wire[..16].chunks(1).chain(wire[16..].chunks(997)) {
            send_fragment(&mut client, stream, chunk);
        }
        assert_echo(&mut client, &target, stream, &payload);
    }
    client
        .h3
        .as_mut()
        .unwrap()
        .send_body(&mut client.quic, stream, &[], true)
        .unwrap();
    client.flush().unwrap();
    assert_clean_finish(&mut client, stream);
}

#[test]
fn http3_udp_separate_fin_rejects_truncated_capsules_and_preserves_other_streams() {
    let (_dir, mut client, target) = fixture();
    let healthy = open_udp(&mut client, target.local_addr().unwrap());
    for tail in wire_fixtures::truncated_capsules() {
        let stream = open_udp(&mut client, target.local_addr().unwrap());
        let payload = b"body parsed before standalone FIN";
        let mut wire = Vec::new();
        encoder::encode_datagram_context_zero(payload, &mut wire);
        wire.extend(tail);
        send_fragment(&mut client, stream, &wire);
        // The prefix and truncated tail fit in one body read. Its echo proves
        // the decoder has consumed that read before a separate FIN arrives.
        assert_echo(&mut client, &target, stream, payload);
        client
            .h3
            .as_mut()
            .unwrap()
            .send_body(&mut client.quic, stream, &[], true)
            .unwrap();
        client.flush().unwrap();
        assert_eq!(
            client.stream_reset(stream),
            quiche::h3::WireErrorCode::MessageError as u64
        );
        assert!(client.quic.peer_error().is_none());

        let mut wire = Vec::new();
        encoder::encode_datagram_context_zero(b"still usable", &mut wire);
        send_fragment(&mut client, healthy, &wire);
        assert_echo(&mut client, &target, healthy, b"still usable");
    }
}
