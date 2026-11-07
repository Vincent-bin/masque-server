use super::*;

fn error_client(
    mut config: ServerConfig,
    stream_window: u64,
    connection_window: u64,
) -> (TempDir, Client) {
    let dir = TempDir::new("error-response-credit");
    let key = p256_key();
    let (cert, key) = write_pem(
        dir.path(),
        "server",
        &key,
        &self_signed(&key, Some("masque-server")),
    );
    config.tls.cert_path = cert;
    config.tls.key_path = key;
    config.listeners[0].listen_addr = ephemeral_addr();
    config.listeners[0].shards = 1;
    config.tcp_proxy.allow_targets = vec!["127.0.0.0/8".into()];
    config.tcp_proxy.deny_targets.clear();
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
        stream_window,
        connection_window,
    )
    .unwrap();
    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();
    (dir, client)
}

fn unauthenticated_config() -> ServerConfig {
    let mut config = ServerConfig::default();
    config.listeners[0].auth.enabled = false;
    config
}

fn block_connection(client: &mut Client, credentials: Option<&str>) -> u64 {
    use std::io::Write as _;
    let target = std::net::TcpListener::bind(ephemeral_addr()).unwrap();
    let authority = target.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        let (mut socket, _) = target.accept().unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let chunk = [0x42; 16384];
        for _ in 0..1024 {
            if socket.write_all(&chunk).is_err() {
                break;
            }
        }
    });
    let mut headers = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":authority", authority.as_bytes()),
    ];
    if let Some(credentials) = credentials {
        headers.push(quiche::h3::Header::new(
            b"proxy-authorization",
            credentials.as_bytes(),
        ));
    }
    let bulk = send(client, &headers, false);
    assert_eq!(
        client
            .response_status(bulk, Duration::from_secs(5))
            .unwrap(),
        200
    );
    // Receive but do not consume the bulk body. This exhausts the connection
    // window even though each individual response stream has ample capacity.
    let until = Instant::now() + Duration::from_millis(800);
    while Instant::now() < until {
        client.drive().unwrap();
    }
    bulk
}

fn send(client: &mut Client, headers: &[quiche::h3::Header], fin: bool) -> u64 {
    let stream = client
        .h3
        .as_mut()
        .unwrap()
        .send_request(&mut client.quic, headers, fin)
        .unwrap();
    client.flush().unwrap();
    stream
}

fn tcp(client: &mut Client, authority: &str, fin: bool) -> u64 {
    send(
        client,
        &[
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":authority", authority.as_bytes()),
        ],
        fin,
    )
}

fn unsupported(client: &mut Client, fin: bool) -> u64 {
    send(
        client,
        &[
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b":path", b"/"),
        ],
        fin,
    )
}

fn reset_while_active(client: &mut Client, stream: u64) -> u64 {
    let until = Instant::now() + Duration::from_secs(4);
    while Instant::now() < until {
        // Keep the connection alive and repeatedly drive the blocked retry.
        client.quic.send_ack_eliciting().unwrap();
        client.drive().unwrap();
        while let Ok((id, event)) = client.h3.as_mut().unwrap().poll(&mut client.quic) {
            if id == stream {
                if let quiche::h3::Event::Reset(code) = event {
                    return code;
                }
                panic!("unexpected blocked response event: {event:?}");
            }
        }
    }
    panic!("stream {stream} did not expire on an active connection");
}

fn assert_blocked(client: &mut Client, streams: &[u64]) {
    let until = Instant::now() + Duration::from_millis(400);
    while Instant::now() < until {
        client.drive().unwrap();
        while let Ok((id, event)) = client.h3.as_mut().unwrap().poll(&mut client.quic) {
            assert!(
                !streams.contains(&id),
                "response {id} was not blocked: {event:?}"
            );
        }
    }
}

fn resume_errors(client: &mut Client, bulk: u64, expected: &[(u64, &[u8])]) {
    let mut headers_seen = Vec::new();
    let mut finished = Vec::new();
    let mut buffer = [0u8; 16384];
    let until = Instant::now() + Duration::from_secs(8);
    while Instant::now() < until && finished.len() != expected.len() {
        while client
            .h3
            .as_mut()
            .unwrap()
            .recv_body(&mut client.quic, bulk, &mut buffer)
            .is_ok()
        {}
        client.drive().unwrap();
        while let Ok((id, event)) = client.h3.as_mut().unwrap().poll(&mut client.quic) {
            let Some((_, status)) = expected.iter().find(|(stream, _)| *stream == id) else {
                continue;
            };
            match event {
                quiche::h3::Event::Headers { list, .. } => {
                    assert!(!headers_seen.contains(&id), "duplicate response on {id}");
                    assert_eq!(
                        list.len(),
                        2,
                        "error must not disclose authentication details"
                    );
                    assert!(
                        list.iter()
                            .any(|h| h.name() == b":status" && h.value() == *status)
                    );
                    assert!(
                        list.iter()
                            .any(|h| h.name() == b"content-length" && h.value() == b"0")
                    );
                    headers_seen.push(id);
                }
                quiche::h3::Event::Finished => {
                    assert!(headers_seen.contains(&id), "FIN without response headers");
                    assert!(!finished.contains(&id));
                    finished.push(id);
                }
                other => panic!("unexpected error response event: {other:?}"),
            }
        }
    }
    assert_eq!(
        finished.len(),
        expected.len(),
        "all blocked errors must resume with FIN"
    );
}

#[test]
fn blocked_error_responses_resume_after_credit_returns() {
    let (_dir, mut client) = error_client(unauthenticated_config(), 262_144, 8192);
    let bulk = block_connection(&mut client, None);
    let bad_tcp = tcp(&mut client, "127.0.0.1:0", false);
    let bad_udp = send(
        &mut client,
        &[
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"connect-udp"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b":path", b"/.well-known/masque/udp/127.0.0.1/0/"),
        ],
        true,
    );
    let scoped = client
        .send_connect_ip_path("connect-ip", "/.well-known/masque/ip/example.com/*/", None)
        .unwrap();
    let unknown = unsupported(&mut client, true);
    // Policy failures arrive asynchronously through the target-setup path.
    let forbidden = tcp(&mut client, "192.0.2.1:80", false);
    let forbidden_udp = send(
        &mut client,
        &[
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"connect-udp"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b":path", b"/.well-known/masque/udp/192.0.2.1/80/"),
        ],
        false,
    );
    assert_blocked(
        &mut client,
        &[bad_tcp, bad_udp, scoped, unknown, forbidden, forbidden_udp],
    );
    // A separately arriving request FIN must not cancel the pending response.
    client
        .h3
        .as_mut()
        .unwrap()
        .send_body(&mut client.quic, bad_tcp, b"", true)
        .unwrap();
    client.flush().unwrap();
    resume_errors(
        &mut client,
        bulk,
        &[
            (bad_tcp, b"400"),
            (bad_udp, b"400"),
            (scoped, b"501"),
            (unknown, b"404"),
            (forbidden, b"403"),
            (forbidden_udp, b"403"),
        ],
    );
}

#[test]
fn blocked_basic_rejections_keep_the_same_empty_404() {
    for stealth in [false, true] {
        let mut config = ServerConfig::default();
        config.listeners[0].auth.username = BASIC_USERNAME.into();
        config.listeners[0].auth.password_hash =
            masque::auth::hash_password(BASIC_PASSWORD.as_bytes()).unwrap();
        config.listeners[0].auth.stealth = stealth;
        let (_dir, mut client) = error_client(config, 262_144, 8192);
        let correct = format!(
            "Basic {}",
            STANDARD.encode(format!("{BASIC_USERNAME}:{BASIC_PASSWORD}"))
        );
        let wrong = format!(
            "Basic {}",
            STANDARD.encode(format!("{BASIC_USERNAME}:wrong"))
        );
        let bulk = block_connection(&mut client, Some(&correct));
        let mut expected = Vec::new();
        for credentials in [
            None,
            Some("Bearer bad"),
            Some(wrong.as_str()),
            Some(correct.as_str()),
        ] {
            let mut headers = vec![
                quiche::h3::Header::new(b":method", b"CONNECT"),
                quiche::h3::Header::new(b":authority", b"127.0.0.1:0"),
            ];
            if let Some(value) = credentials {
                headers.push(quiche::h3::Header::new(
                    b"proxy-authorization",
                    value.as_bytes(),
                ));
                if value == correct {
                    headers.push(quiche::h3::Header::new(
                        b"proxy-authorization",
                        value.as_bytes(),
                    ));
                }
            }
            expected.push((send(&mut client, &headers, true), b"404".as_slice()));
        }
        expected.push((unsupported(&mut client, true), b"404".as_slice()));
        assert_blocked(
            &mut client,
            &expected.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        );
        resume_errors(&mut client, bulk, &expected);
    }
}

#[test]
fn blocked_errors_count_toward_tunnel_admission_and_release_it() {
    let mut config = unauthenticated_config();
    config.server.max_tunnels_per_connection = 2;
    let (_dir, mut client) = error_client(config, 262_144, 8192);
    let bulk = block_connection(&mut client, None);
    let rejected = unsupported(&mut client, true);
    assert_blocked(&mut client, &[rejected]);
    let limited = client.send_connect_ip("connect-ip").unwrap();
    assert_blocked(&mut client, &[limited]);
    resume_errors(&mut client, bulk, &[(rejected, b"404"), (limited, b"503")]);
    // The two error entries no longer hold slots. Stop the bulk stream so its
    // download cannot hide the successful post-recovery admission response.
    client
        .quic
        .stream_shutdown(bulk, quiche::Shutdown::Read, 0)
        .unwrap();
    client
        .quic
        .stream_shutdown(bulk, quiche::Shutdown::Write, 0)
        .unwrap();
    let admitted = client.send_connect_ip("connect-ip").unwrap();
    assert_eq!(
        client
            .response_status(admitted, Duration::from_secs(5))
            .unwrap(),
        200
    );
}

#[test]
fn blocked_error_queue_is_bounded_and_reset_releases_a_slot() {
    let (_dir, mut client) = error_client(unauthenticated_config(), 1, 1_048_576);
    let streams: Vec<_> = (0..64).map(|_| unsupported(&mut client, false)).collect();
    assert_blocked(&mut client, &streams);
    let overflow = unsupported(&mut client, false);
    assert_eq!(
        client.stream_reset(overflow),
        quiche::h3::WireErrorCode::ExcessiveLoad as u64
    );
    client
        .quic
        .stream_shutdown(streams[0], quiche::Shutdown::Write, 0)
        .unwrap();
    client.flush().unwrap();
    assert_eq!(
        client.stream_reset(streams[0]),
        quiche::h3::WireErrorCode::RequestCancelled as u64
    );
    let replacement = unsupported(&mut client, true);
    assert_blocked(&mut client, &[replacement]);
    let overflow_again = unsupported(&mut client, false);
    assert_eq!(
        client.stream_reset(overflow_again),
        quiche::h3::WireErrorCode::ExcessiveLoad as u64
    );

    // STOP_SENDING alone is terminal, even without a request RESET_STREAM.
    // Batch it with the replacement request so admission must reclaim the
    // stopped slot before the next normal output drive.
    client
        .quic
        .stream_shutdown(streams[1], quiche::Shutdown::Read, 0)
        .unwrap();
    let replacement = unsupported(&mut client, true);
    assert_blocked(&mut client, &[replacement]);
    let overflow = unsupported(&mut client, false);
    assert_eq!(
        client.stream_reset(overflow),
        quiche::h3::WireErrorCode::ExcessiveLoad as u64
    );
}

#[test]
fn blocked_error_timeout_is_not_renewed_by_retries() {
    let mut config = unauthenticated_config();
    config.server.idle_timeout_secs = 1;
    let (_dir, mut client) = error_client(config, 1, 1_048_576);
    let stream = unsupported(&mut client, true);
    // PINGs repeatedly wake the server while no stream window update is
    // possible. Retries must not renew the original timeout.
    assert_eq!(
        reset_while_active(&mut client, stream),
        quiche::h3::WireErrorCode::RequestCancelled as u64
    );
    let next = unsupported(&mut client, true);
    assert_blocked(&mut client, &[next]);
    assert_eq!(
        reset_while_active(&mut client, next),
        quiche::h3::WireErrorCode::RequestCancelled as u64
    );
}
