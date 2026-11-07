//! FIN must not depend on whether Basic credentials are cold or cached.

use super::*;
use masque::capsule::{RequestedAddress, encoder};

const CREDENTIALS: &str = "Basic dGVzdDp0ZXN0LXBhc3N3b3Jk";

fn fixture(native_datagrams: bool) -> (TempDir, Client, UdpSocket) {
    fixture_with_windows(native_datagrams, 1, 64, 1_048_576)
}

fn fixture_with_windows(
    native_datagrams: bool,
    max_tunnels: usize,
    stream_window: u64,
    connection_window: u64,
) -> (TempDir, Client, UdpSocket) {
    let dir = TempDir::new("cold-auth-fin");
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
    config.listeners[0].auth.username = "test".into();
    config.listeners[0].auth.password_hash = "$argon2id$v=19$m=19456,t=2,p=1$1xNVXhqKU7jJ6cqTBJKphQ$GXXAINVTW1qhloFtN1IR8lSr7pI7QEY79fq4K6d8scQ".into();
    // Every following request needs the previous tunnel slot and lease back.
    config.server.max_tunnels_per_connection = max_tunnels;
    config.ip_proxy.ipv4_pool = if max_tunnels == 1 {
        "10.89.0.0/30"
    } else {
        "10.89.0.0/29"
    }
    .into();
    config.ip_proxy.ipv6_pool = "fd00:abcd::/126".into();
    config.udp_proxy.allow_targets = vec!["127.0.0.0/8".into()];
    config.udp_proxy.deny_targets.clear();
    let peer = spawn_server(config)[0];
    let target = UdpSocket::bind(ephemeral_addr()).unwrap();
    target
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut client = Client::connect_with_windows(
        peer,
        None,
        None,
        false,
        "127.0.0.1".parse().unwrap(),
        native_datagrams,
        stream_window,
        connection_window,
    )
    .unwrap();
    client
        .socket
        .set_read_timeout(Some(Duration::from_millis(2)))
        .unwrap();
    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();
    (dir, client, target)
}

fn path(protocol: &str, target: &UdpSocket) -> String {
    if protocol == "connect-udp" {
        let target = target.local_addr().unwrap();
        format!("/.well-known/masque/udp/{}/{}/", target.ip(), target.port())
    } else {
        "/.well-known/masque/ip/*/*/".into()
    }
}

fn send_request(
    client: &mut Client,
    protocol: &str,
    path: &str,
    credentials: Option<&str>,
    body: Option<&[u8]>,
) -> u64 {
    let mut headers = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", protocol.as_bytes()),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"localhost"),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
    ];
    if let Some(credentials) = credentials {
        headers.push(quiche::h3::Header::new(
            b"proxy-authorization",
            credentials.as_bytes(),
        ));
    }
    let h3 = client.h3.as_mut().unwrap();
    let stream = h3
        .send_request(&mut client.quic, &headers, body.is_none())
        .unwrap();
    if let Some(body) = body {
        assert_eq!(
            h3.send_body(&mut client.quic, stream, body, true).unwrap(),
            body.len()
        );
    }
    // HEADERS and the complete request body/FIN arrive before any response.
    client.flush().unwrap();
    stream
}

#[derive(Default)]
struct Response {
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
    reset: Option<u64>,
}

fn response(client: &mut Client, stream: u64) -> Response {
    responses(client, &[stream]).remove(0)
}

fn responses(client: &mut Client, streams: &[u64]) -> Vec<Response> {
    let mut responses: Vec<_> = streams.iter().map(|_| Response::default()).collect();
    let mut finished = vec![false; streams.len()];
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let h3 = client.h3.as_mut().unwrap();
        let event = h3.poll(&mut client.quic);
        let index = match &event {
            Ok((id, _)) => streams.iter().position(|stream| stream == id),
            Err(_) => None,
        };
        if event.is_ok() && index.is_none() {
            continue;
        }
        let index = index.unwrap_or(0);
        let stream = streams[index];
        let response = &mut responses[index];
        match event {
            Ok((id, quiche::h3::Event::Headers { list, .. })) if id == stream => {
                assert!(response.headers.is_empty(), "only one final response");
                response.headers = list
                    .iter()
                    .map(|h| (h.name().to_vec(), h.value().to_vec()))
                    .collect();
            }
            Ok((id, quiche::h3::Event::Data)) if id == stream => {
                let mut buffer = [0; 4096];
                while let Ok(count) = h3.recv_body(&mut client.quic, stream, &mut buffer) {
                    if count == 0 {
                        break;
                    }
                    response.body.extend_from_slice(&buffer[..count]);
                }
            }
            Ok((id, quiche::h3::Event::Finished)) if id == stream => finished[index] = true,
            Ok((id, quiche::h3::Event::Reset(code))) if id == stream => {
                response.reset = Some(code);
                finished[index] = true;
            }
            Ok(_) => {}
            Err(quiche::h3::Error::Done) => {
                assert!(Instant::now() < deadline, "response/FIN did not complete");
                client.drive().unwrap();
            }
            Err(error) => panic!("HTTP/3 response poll failed: {error}"),
        }
        if finished.iter().all(|finished| *finished) {
            return responses;
        }
    }
}

fn assert_status(response: &Response, status: u16) {
    assert_eq!(
        response.reset, None,
        "request must receive a clean response"
    );
    assert!(
        response
            .headers
            .iter()
            .any(|(name, value)| { name == b":status" && value == status.to_string().as_bytes() })
    );
}

fn decode(body: &[u8]) -> Vec<CapsuleFrame> {
    let mut decoder = CapsuleDecoder::new();
    let frames = decoder.decode(body).unwrap();
    assert!(
        decoder.buffered() == 0,
        "response truncated a control capsule"
    );
    frames
}

#[test]
fn headers_fin_completes_udp_and_ip_for_cold_and_warm_basic_auth() {
    for native in [false, true] {
        for protocol in ["connect-udp", "connect-ip"] {
            let (_dir, mut client, target) = fixture(native);
            let mut addresses = None;
            for _ in 0..3 {
                let stream = send_request(
                    &mut client,
                    protocol,
                    &path(protocol, &target),
                    Some(CREDENTIALS),
                    None,
                );
                let reply = response(&mut client, stream);
                assert_status(&reply, 200);
                if protocol == "connect-ip" {
                    let frames = decode(&reply.body);
                    assert_eq!(frames.len(), 2);
                    assert!(matches!(frames[0], CapsuleFrame::AddressAssign(_)));
                    assert!(matches!(frames[1], CapsuleFrame::RouteAdvertisement(_)));
                    let CapsuleFrame::AddressAssign(assigned) = &frames[0] else {
                        unreachable!();
                    };
                    let ipv4 = assigned
                        .iter()
                        .find(|address| matches!(address.ip, IpAddress::V4(_)))
                        .unwrap();
                    if let Some(previous) = &addresses {
                        assert_eq!(previous, ipv4, "closed request returns its only IPv4 lease");
                    }
                    addresses = Some(ipv4.clone());
                } else {
                    assert!(reply.body.is_empty());
                }
                assert!(client.quic.peer_error().is_none());
            }
        }
    }
}

#[test]
fn body_fin_is_processed_after_cold_auth_and_validated_after_warm_auth() {
    for protocol in ["connect-udp", "connect-ip"] {
        let (_dir, mut client, target) = fixture(false);
        for _ in 0..2 {
            let mut wire = Vec::new();
            if protocol == "connect-udp" {
                encoder::encode_datagram_context_zero(b"body before auth", &mut wire);
            } else {
                encoder::encode(
                    &CapsuleFrame::AddressRequest(vec![RequestedAddress {
                        request_id: 7,
                        ip: IpAddress::V4(Ipv4Addr::UNSPECIFIED),
                        prefix_len: 32,
                    }]),
                    &mut wire,
                );
            }
            let stream = send_request(
                &mut client,
                protocol,
                &path(protocol, &target),
                Some(CREDENTIALS),
                Some(&wire),
            );
            let reply = response(&mut client, stream);
            assert_status(&reply, 200);
            if protocol == "connect-udp" {
                let mut buffer = [0; 64];
                let count = target.recv(&mut buffer).unwrap();
                assert_eq!(&buffer[..count], b"body before auth");
            } else {
                let frames = decode(&reply.body);
                assert_eq!(frames.len(), 3);
                assert!(matches!(&frames[2], CapsuleFrame::AddressAssign(addresses)
                    if addresses.iter().any(|address| address.request_id == 7)));
            }
        }
        let stream = send_request(
            &mut client,
            protocol,
            &path(protocol, &target),
            Some(CREDENTIALS),
            Some(&[0, 2, 0]),
        );
        assert_eq!(
            response(&mut client, stream).reset,
            Some(quiche::h3::WireErrorCode::MessageError as u64)
        );
        let stream = send_request(
            &mut client,
            protocol,
            &path(protocol, &target),
            Some(CREDENTIALS),
            None,
        );
        assert_status(&response(&mut client, stream), 200);
    }
}

#[test]
fn fin_preserves_stealth_rejections_and_authenticated_validation() {
    for protocol in ["connect-udp", "connect-ip"] {
        let (_dir, mut client, target) = fixture(false);
        let wrong = format!("Basic {}", STANDARD.encode("test:wrong"));
        for credentials in [None, Some("invalid"), Some(wrong.as_str())] {
            for body in [None, Some([0, 2, 0].as_slice())] {
                let stream = send_request(&mut client, protocol, "/", credentials, body);
                let reply = response(&mut client, stream);
                assert_status(&reply, 404);
                assert!(reply.body.is_empty());
                assert_eq!(reply.headers.len(), 2, "empty stealth response only");
                assert!(
                    reply
                        .headers
                        .iter()
                        .any(|(name, value)| { name == b"content-length" && value == b"0" })
                );
            }
        }
        // Still cold: rejected credentials cannot populate the success cache.
        for _ in 0..2 {
            let stream = send_request(&mut client, protocol, "/", Some(CREDENTIALS), None);
            assert_status(&response(&mut client, stream), 400);
        }
        let stream = send_request(
            &mut client,
            protocol,
            &path(protocol, &target),
            Some(CREDENTIALS),
            None,
        );
        assert_status(&response(&mut client, stream), 200);
    }
}

#[test]
fn truncated_body_fin_after_cold_auth_resets_only_its_stream() {
    for protocol in ["connect-udp", "connect-ip"] {
        let (_dir, mut client, target) = fixture(false);
        let stream = send_request(
            &mut client,
            protocol,
            &path(protocol, &target),
            Some(CREDENTIALS),
            Some(&[0, 2, 0]),
        );
        assert_eq!(
            response(&mut client, stream).reset,
            Some(quiche::h3::WireErrorCode::MessageError as u64)
        );
        assert!(client.quic.peer_error().is_none());
        let stream = send_request(
            &mut client,
            protocol,
            &path(protocol, &target),
            Some(CREDENTIALS),
            None,
        );
        assert_status(&response(&mut client, stream), 200);
    }
}

#[test]
fn headers_fin_waits_for_pending_udp_and_ip_response_credit() {
    for protocol in ["connect-udp", "connect-ip"] {
        let (_dir, mut client, target) = fixture_with_windows(false, 2, 4096, 256);
        // A complete IP control response fills the connection receive window.
        // It needs no target service and remains queued until the client reads.
        let mut body = Vec::new();
        encoder::encode(
            &CapsuleFrame::AddressRequest(
                (1..=64)
                    .map(|request_id| RequestedAddress {
                        request_id,
                        ip: IpAddress::V4(Ipv4Addr::UNSPECIFIED),
                        prefix_len: 32,
                    })
                    .collect(),
            ),
            &mut body,
        );
        let blocker = send_request(
            &mut client,
            "connect-ip",
            &path("connect-ip", &target),
            Some(CREDENTIALS),
            Some(&body),
        );
        assert_eq!(
            client
                .response_status(blocker, Duration::from_secs(5))
                .unwrap(),
            200
        );
        let until = Instant::now() + Duration::from_millis(100);
        while Instant::now() < until {
            client.drive().unwrap();
        }
        let stream = send_request(
            &mut client,
            protocol,
            &path(protocol, &target),
            Some(CREDENTIALS),
            None,
        );
        let until = Instant::now() + Duration::from_millis(100);
        while Instant::now() < until {
            client.drive().unwrap();
        }
        assert!(
            !client.quic.stream_readable(stream),
            "response must wait for connection credit"
        );
        let replies = responses(&mut client, &[blocker, stream]);
        assert_eq!(replies[0].reset, None);
        assert_eq!(decode(&replies[0].body).len(), 3);
        assert_status(&replies[1], 200);
        if protocol == "connect-ip" {
            assert_eq!(decode(&replies[1].body).len(), 2);
        }
        let stream = send_request(
            &mut client,
            protocol,
            &path(protocol, &target),
            Some(CREDENTIALS),
            None,
        );
        assert_status(&response(&mut client, stream), 200);
    }
}
