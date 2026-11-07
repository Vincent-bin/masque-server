use super::*;

const CREDENTIALS: &str = "Basic dGVzdDp0ZXN0LXBhc3N3b3Jk";

fn fixture(auth: bool) -> (TempDir, Client, std::net::TcpListener) {
    let dir = TempDir::new("request-header-ownership");
    let key = p256_key();
    let (cert, key) = write_pem(dir.path(), "server", &key, &self_signed(&key, None));
    let target = std::net::TcpListener::bind(ephemeral_addr()).unwrap();
    target.set_nonblocking(true).unwrap();
    let mut config = server_config(cert, key, ephemeral_addr(), vec![]);
    config.listeners[0].auth.enabled = auth;
    if auth {
        config.listeners[0].auth.mode = AuthMode::Basic;
        config.listeners[0].auth.username = "test".into();
        config.listeners[0].auth.password_hash = "$argon2id$v=19$m=19456,t=2,p=1$1xNVXhqKU7jJ6cqTBJKphQ$GXXAINVTW1qhloFtN1IR8lSr7pI7QEY79fq4K6d8scQ".into();
    }
    config.server.max_tunnels_per_connection = 1;
    config.tcp_proxy.enabled = true;
    config.tcp_proxy.allow_targets = vec!["127.0.0.0/8".into()];
    config.tcp_proxy.deny_targets.clear();
    config.udp_proxy.enabled = true;
    config.udp_proxy.allow_targets = vec!["127.0.0.0/8".into()];
    config.udp_proxy.deny_targets.clear();
    let peer = spawn_server(config)[0];
    let mut client = Client::connect_anonymous(peer).unwrap();
    client
        .socket
        .set_read_timeout(Some(Duration::from_millis(5)))
        .unwrap();
    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();
    (dir, client, target)
}

fn tcp_headers(target: &std::net::TcpListener, credentials: bool) -> Vec<quiche::h3::Header> {
    let authority = target.local_addr().unwrap().to_string();
    let mut headers = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":authority", authority.as_bytes()),
    ];
    if credentials {
        headers.push(quiche::h3::Header::new(
            b"proxy-authorization",
            CREDENTIALS.as_bytes(),
        ));
    }
    headers
}

fn request(client: &mut Client, headers: &[quiche::h3::Header]) -> u64 {
    client
        .h3
        .as_mut()
        .unwrap()
        .send_request(&mut client.quic, headers, false)
        .unwrap()
}

fn trailers(client: &mut Client, stream: u64, headers: &[quiche::h3::Header], fin: bool) {
    client
        .h3
        .as_mut()
        .unwrap()
        .send_additional_headers(&mut client.quic, stream, headers, true, fin)
        .unwrap();
    client.flush().unwrap();
}

fn expect_reset(client: &mut Client, stream: u64) {
    assert_eq!(
        client.stream_reset(stream),
        quiche::h3::WireErrorCode::MessageError as u64
    );
    assert!(client.quic.peer_error().is_none());
}

fn accept_count(client: &mut Client, target: &std::net::TcpListener) -> usize {
    let deadline = Instant::now() + Duration::from_millis(350);
    let mut accepted = Vec::new();
    while Instant::now() < deadline {
        match target.accept() {
            Ok((socket, _)) => accepted.push(socket),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("target accept: {error}"),
        }
        client.drive().unwrap();
    }
    accepted.len()
}

fn accept_one(client: &mut Client, target: &std::net::TcpListener) -> std::net::TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match target.accept() {
            Ok((socket, _)) => return socket,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "target connection did not arrive"
                );
                client.drive().unwrap();
            }
            Err(error) => panic!("target accept: {error}"),
        }
    }
}

#[test]
fn duplicate_tcp_headers_in_same_batch_cannot_start_multiple_connections() {
    for auth in [false, true] {
        let (_dir, mut client, target) = fixture(auth);
        let headers = tcp_headers(&target, auth);
        let stream = request(&mut client, &headers);
        trailers(&mut client, stream, &headers, false);
        expect_reset(&mut client, stream);
        assert_eq!(accept_count(&mut client, &target), 0);
        let sibling = request(&mut client, &headers);
        client.flush().unwrap();
        assert_eq!(
            client
                .response_status(sibling, Duration::from_secs(5))
                .unwrap(),
            200
        );
        assert_eq!(accept_count(&mut client, &target), 1);
    }
}

#[test]
fn duplicate_tcp_headers_after_setup_close_only_the_offending_stream() {
    let (_dir, mut client, target) = fixture(true);
    let headers = tcp_headers(&target, true);
    let stream = request(&mut client, &headers);
    client.flush().unwrap();
    assert_eq!(
        client
            .response_status(stream, Duration::from_secs(5))
            .unwrap(),
        200
    );
    let _socket = accept_one(&mut client, &target);
    trailers(&mut client, stream, &headers, false);
    expect_reset(&mut client, stream);
    assert_eq!(accept_count(&mut client, &target), 0);
    let sibling = request(&mut client, &headers);
    client.flush().unwrap();
    assert_eq!(
        client
            .response_status(sibling, Duration::from_secs(5))
            .unwrap(),
        200
    );
}

#[test]
fn ordinary_trailers_do_not_dispatch_a_second_request() {
    let (_dir, mut client, target) = fixture(false);
    let headers = tcp_headers(&target, false);
    let stream = request(&mut client, &headers);
    client.flush().unwrap();
    assert_eq!(
        client
            .response_status(stream, Duration::from_secs(5))
            .unwrap(),
        200
    );
    let mut socket = accept_one(&mut client, &target);
    trailers(
        &mut client,
        stream,
        &[quiche::h3::Header::new(b"x-test", b"value")],
        true,
    );
    use std::io::Write as _;
    socket.write_all(b"reply after trailers").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut received = Vec::new();
    while received.len() < b"reply after trailers".len() {
        while let Ok((id, event)) = client.h3.as_mut().unwrap().poll(&mut client.quic) {
            if id == stream {
                assert!(
                    !matches!(event, quiche::h3::Event::Reset(_)),
                    "valid trailers reset the stream"
                );
            }
        }
        let mut buf = [0; 128];
        if let Ok(count) = client
            .h3
            .as_mut()
            .unwrap()
            .recv_body(&mut client.quic, stream, &mut buf)
        {
            received.extend_from_slice(&buf[..count]);
        }
        assert!(
            Instant::now() < deadline,
            "target reply did not reach client"
        );
        client.drive().unwrap();
    }
    assert_eq!(received, b"reply after trailers");
}

#[test]
fn duplicate_ip_headers_do_not_allocate_a_lease() {
    let (_dir, mut client, _target) = fixture(false);
    let headers = [
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"connect-ip"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"localhost"),
        quiche::h3::Header::new(b":path", b"/.well-known/masque/ip/*/*/"),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
    ];
    let stream = request(&mut client, &headers);
    trailers(&mut client, stream, &headers, false);
    expect_reset(&mut client, stream);
    let sibling = client.send_connect_ip("connect-ip").unwrap();
    assert_eq!(
        client
            .response_status(sibling, Duration::from_secs(5))
            .unwrap(),
        200
    );
    assert_eq!(client.capsules(sibling, 2, Duration::from_secs(5)).len(), 2);
}

#[test]
fn duplicate_udp_headers_cancel_setup_and_leave_the_connection_usable() {
    let (_dir, mut client, _target) = fixture(false);
    let target = UdpSocket::bind(ephemeral_addr()).unwrap();
    let path = format!(
        "/.well-known/masque/udp/127.0.0.1/{}/",
        target.local_addr().unwrap().port()
    );
    let headers = [
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"connect-udp"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"localhost"),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
    ];
    let stream = request(&mut client, &headers);
    trailers(&mut client, stream, &headers, false);
    expect_reset(&mut client, stream);
    let sibling = request(&mut client, &headers);
    client.flush().unwrap();
    assert_eq!(
        client
            .response_status(sibling, Duration::from_secs(5))
            .unwrap(),
        200
    );
}

#[test]
fn credentials_in_later_headers_cannot_authorize_an_initially_unauthenticated_request() {
    let (_dir, mut client, target) = fixture(true);
    let initial = tcp_headers(&target, false);
    let later = tcp_headers(&target, true);
    let stream = request(&mut client, &initial);
    trailers(&mut client, stream, &later, false);
    assert_eq!(
        client
            .response_status(stream, Duration::from_secs(5))
            .unwrap(),
        404
    );
    assert_eq!(accept_count(&mut client, &target), 0);
}
