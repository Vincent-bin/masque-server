use super::*;

fn error_server(mut config: ServerConfig) -> (TempDir, SocketAddr, Option<SocketAddr>) {
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
    let (peers, metrics) = spawn_server_with_observability(config);
    (dir, peers[0], metrics)
}

fn error_client(
    config: ServerConfig,
    stream_window: u64,
    connection_window: u64,
) -> (TempDir, Client) {
    let (dir, peer, _) = error_server(config);
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

#[test]
fn idle_tunnels_close_while_connection_credit_is_exhausted() {
    let mut config = unauthenticated_config();
    config.server.idle_timeout_secs = 1;
    let (_dir, mut client) = error_client(config, 32768, 16384);

    let tcp_target = std::net::TcpListener::bind(ephemeral_addr()).unwrap();
    let tcp = tcp(
        &mut client,
        &tcp_target.local_addr().unwrap().to_string(),
        false,
    );
    assert_eq!(
        client.response_status(tcp, Duration::from_secs(5)).unwrap(),
        200
    );
    let (_upstream, _) = tcp_target.accept().unwrap();
    let udp_target = UdpSocket::bind(ephemeral_addr()).unwrap();
    let target = udp_target.local_addr().unwrap();
    let path = format!("/.well-known/masque/udp/127.0.0.1/{}/", target.port());
    let udp = send(
        &mut client,
        &[
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"connect-udp"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b":path", path.as_bytes()),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        ],
        false,
    );
    assert_eq!(
        client.response_status(udp, Duration::from_secs(5)).unwrap(),
        200
    );
    let ip = client.send_connect_ip("connect-ip").unwrap();
    assert_eq!(
        client.response_status(ip, Duration::from_secs(5)).unwrap(),
        200
    );
    assert_eq!(client.capsules(ip, 2, Duration::from_secs(5)).len(), 2);

    let bulk = block_connection(&mut client, None);
    let mut pending = [tcp, udp, ip]
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    let mut reset_count = 0;
    let deadline = Instant::now() + Duration::from_secs(4);
    while !pending.is_empty() && Instant::now() < deadline {
        // Keep the bulk tunnel alive without reading its response. If it
        // resets too, discarding its buffered bytes can restore QUIC credit.
        client
            .h3
            .as_mut()
            .unwrap()
            .send_body(&mut client.quic, bulk, b"x", false)
            .unwrap();
        client.drive().unwrap();
        while let Ok((id, event)) = client.h3.as_mut().unwrap().poll(&mut client.quic) {
            if pending.contains(&id) {
                match event {
                    quiche::h3::Event::Reset(code) => {
                        assert_eq!(code, quiche::h3::WireErrorCode::RequestCancelled as u64);
                        reset_count += 1;
                    }
                    quiche::h3::Event::Finished => {}
                    quiche::h3::Event::Data => {
                        // Any residual credit may fit an empty FIN frame.
                        let _ = client.h3.as_mut().unwrap().recv_body(
                            &mut client.quic,
                            id,
                            &mut [0; 32],
                        );
                        continue;
                    }
                    _ => panic!("unexpected event while waiting for idle cleanup: {event:?}"),
                }
                pending.remove(&id);
            }
        }
    }
    assert!(pending.is_empty(), "idle streams still open: {pending:?}");
    assert!(reset_count > 0, "no idle close encountered backpressure");
    let check = unsupported(&mut client, true);
    resume_errors(&mut client, bulk, &[(check, b"404")]);
}

#[test]
fn first_basic_auth_has_a_fixed_quic_deadline() {
    use argon2::password_hash::{PasswordHasher, SaltString};
    use argon2::{Algorithm, Argon2, Params, Version};

    const AUTH_WINDOW: Duration = Duration::from_secs(3);
    let mut config = ServerConfig::default();
    config.server.idle_timeout_secs = AUTH_WINDOW.as_secs();
    config.observability.listen_addr = Some(ephemeral_addr());
    config.listeners[0].auth.username = BASIC_USERNAME.into();
    // Exercise a cold verification without making this deadline test depend
    // on production Argon2 cost under concurrent debug test load.
    let salt = SaltString::encode_b64(b"auth-deadline-test").unwrap();
    config.listeners[0].auth.password_hash = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(64, 1, 1, None).unwrap(),
    )
    .hash_password(BASIC_PASSWORD.as_bytes(), &salt)
    .unwrap()
    .to_string();

    let (_dir, peer, metrics) = error_server(config);
    let metrics = metrics.unwrap();
    let active = || metric_total(&scrape_metrics(metrics), "masque_connections_active{");
    let mut client = Client::connect_anonymous(peer).unwrap();
    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();
    assert_eq!(active(), 1);

    // Measure server-side reclamation. QUIC can close silently if its
    // transport idle timer expires before a close packet can be sent.
    let deadline = Instant::now() + AUTH_WINDOW + Duration::from_secs(4);
    while active() != 0 {
        assert!(
            Instant::now() < deadline,
            "keepalive extended the first Basic auth deadline"
        );
        if client.quic.peer_error().is_none() {
            client.quic.send_ack_eliciting().unwrap();
            client.drive().unwrap();
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let credentials = format!(
        "Basic {}",
        STANDARD.encode(format!("{BASIC_USERNAME}:{BASIC_PASSWORD}"))
    );
    // A fresh connection exercises cold authentication first and the shared
    // credential cache on the next connection.
    for _ in 0..2 {
        let mut client = Client::connect_anonymous(peer).unwrap();
        client.handshake(Duration::from_secs(5)).unwrap();
        client.init_h3().unwrap();
        let stream = client
            .send_connect_ip_with_credentials("connect-ip", Some(&credentials))
            .unwrap();
        assert_eq!(
            client
                .response_status(stream, Duration::from_secs(5))
                .unwrap(),
            200
        );
        let deadline = Instant::now() + AUTH_WINDOW + Duration::from_millis(200);
        while Instant::now() < deadline {
            client.quic.send_ack_eliciting().unwrap();
            client.drive().unwrap();
            std::thread::sleep(Duration::from_millis(80));
        }
        let request = unsupported(&mut client, true);
        assert_eq!(
            client
                .response_status(request, Duration::from_secs(5))
                .unwrap(),
            404
        );
    }
}

#[test]
fn idle_tunnels_release_the_bidirectional_stream_slot() {
    let mut config = unauthenticated_config();
    config.server.idle_timeout_secs = 1;
    config.quic.initial_max_streams_bidi = 1;
    let (_dir, mut client) = error_client(config, 262_144, 1_048_576);
    let target = std::net::TcpListener::bind(ephemeral_addr()).unwrap();
    let udp_target = UdpSocket::bind(ephemeral_addr()).unwrap();
    let udp_path = format!(
        "/.well-known/masque/udp/127.0.0.1/{}/",
        udp_target.local_addr().unwrap().port()
    );

    for protocol in ["tcp", "udp", "ip"] {
        let stream = match protocol {
            "tcp" => tcp(
                &mut client,
                &target.local_addr().unwrap().to_string(),
                false,
            ),
            "udp" => send(
                &mut client,
                &[
                    quiche::h3::Header::new(b":method", b"CONNECT"),
                    quiche::h3::Header::new(b":protocol", b"connect-udp"),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", b"localhost"),
                    quiche::h3::Header::new(b":path", udp_path.as_bytes()),
                ],
                false,
            ),
            _ => client.send_connect_ip("connect-ip").unwrap(),
        };
        assert_eq!(
            client
                .response_status(stream, Duration::from_secs(2))
                .unwrap(),
            200
        );
        assert_eq!(client.quic.peer_streams_left_bidi(), 0);
        let deadline = Instant::now() + Duration::from_secs(4);
        let mut finished = false;
        let mut body = [0; 1024];
        while Instant::now() < deadline && !(finished && client.quic.peer_streams_left_bidi() > 0) {
            client.quic.send_ack_eliciting().unwrap();
            client.drive().unwrap();
            let h3 = client.h3.as_mut().unwrap();
            while let Ok((id, event)) = h3.poll(&mut client.quic) {
                if id != stream {
                    continue;
                }
                match event {
                    quiche::h3::Event::Data => {
                        while h3.recv_body(&mut client.quic, id, &mut body).is_ok() {}
                    }
                    quiche::h3::Event::Finished => finished = true,
                    other => panic!("unexpected idle {protocol} event: {other:?}"),
                }
            }
        }
        assert!(finished, "idle {protocol} response did not finish");
        assert_eq!(
            client.quic.peer_streams_left_bidi(),
            1,
            "idle {protocol} request held the stream slot"
        );
    }
}

#[test]
fn stop_sending_releases_silent_tcp_tunnel_before_admission() {
    assert_stop_sending_releases_silent_tcp_tunnel(false);
}

#[test]
fn stop_sending_with_fin_releases_silent_tcp_tunnel_before_admission() {
    assert_stop_sending_releases_silent_tcp_tunnel(true);
}

fn assert_stop_sending_releases_silent_tcp_tunnel(with_fin: bool) {
    use std::io::Read as _;

    let mut config = unauthenticated_config();
    config.server.max_tunnels_per_connection = 1;
    let (_dir, mut client) = error_client(config, 262_144, 1_048_576);
    let target = std::net::TcpListener::bind(ephemeral_addr()).unwrap();
    let authority = target.local_addr().unwrap().to_string();
    let first = tcp(&mut client, &authority, false);
    assert_eq!(
        client
            .response_status(first, Duration::from_secs(2))
            .unwrap(),
        200
    );
    let (mut first_target, _) = target.accept().unwrap();

    // Queue FIN (when requested), STOP_SENDING and replacement HEADERS
    // before flushing, without sending a request RESET_STREAM.
    if with_fin {
        client.quic.stream_send(first, b"", true).unwrap();
    }
    client
        .quic
        .stream_shutdown(
            first,
            quiche::Shutdown::Read,
            quiche::h3::WireErrorCode::RequestCancelled as u64,
        )
        .unwrap();
    let replacement = tcp(&mut client, &authority, false);
    assert_eq!(
        client
            .response_status(replacement, Duration::from_secs(2))
            .unwrap(),
        200
    );
    first_target
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    assert_eq!(
        first_target.read(&mut [0]).unwrap(),
        0,
        "silent target was not closed"
    );
}

#[test]
fn malformed_initial_headers_never_open_a_target() {
    let (_dir, mut client) = error_client(unauthenticated_config(), 262_144, 1_048_576);
    let target = std::net::TcpListener::bind(ephemeral_addr()).unwrap();
    target.set_nonblocking(true).unwrap();
    let authority = target.local_addr().unwrap().to_string();
    let connect = [
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":authority", authority.as_bytes()),
    ];
    let additions: &[&[(&[u8], &[u8])]] = &[
        &[(b":method", b"CONNECT")],
        &[(b":authority", b"localhost:443")],
        &[(b":protocol", b"")],
        &[(b":path", b"/")],
        &[(b":status", b"200")],
        &[(b"x-test", b"ok"), (b":scheme", b"https")],
        &[(b"connection", b"keep-alive")],
        &[(b"proxy-connection", b"keep-alive")],
        &[(b"transfer-encoding", b"chunked")],
        &[(b"te", b"gzip")],
        &[(b"x-test", b"invalid\r\nvalue")],
    ];
    for addition in additions {
        let mut headers = connect.to_vec();
        headers.extend(
            addition
                .iter()
                .map(|(name, value)| quiche::h3::Header::new(name, value)),
        );
        let stream = send(&mut client, &headers, false);
        assert_eq!(
            client.stream_reset(stream),
            quiche::h3::WireErrorCode::MessageError as u64
        );
        assert_eq!(
            target.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    let mut valid = connect.to_vec();
    valid.push(quiche::h3::Header::new(b"te", b"trailers"));
    let stream = send(&mut client, &valid, false);
    assert_eq!(
        client
            .response_status(stream, Duration::from_secs(2))
            .unwrap(),
        200
    );
    target.accept().unwrap();
}
