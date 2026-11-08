//! Real-socket handshake and idle lifecycle checks, including admission reuse.
//! Run with `cargo test --test http2_connect timeouts:: -- --nocapture`.

use std::net::SocketAddr;

use super::*;

const IO_TIMEOUT: Duration = Duration::from_secs(3);
// Both handshake phases have a 10-second deadline. Two seconds of slack
// accommodate scheduler jitter.
const HANDSHAKE_DEADLINE_WITH_SLACK: Duration = Duration::from_secs(12);
const IDLE_SECS: u64 = 1;
const IDLE_DEADLINE_WITH_SLACK: Duration = Duration::from_secs(3);

struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct ObservedServer {
    addr: SocketAddr,
    metrics_addr: SocketAddr,
    _task: AbortOnDrop<()>,
}

impl ObservedServer {
    async fn start(files: &TestFiles, source_limit: bool) -> Self {
        let mut config = http2_config(files);
        config.server.idle_timeout_secs = IDLE_SECS;
        // Exercise the listener cap and process-wide source cap separately.
        config.server.max_connections = if source_limit { 2 } else { 1 };
        config.server.max_connections_per_ip = if source_limit { 1 } else { 2 };
        config.server.max_tunnels_per_connection = 1;
        Self::bind(config).await
    }

    async fn bind(mut config: ServerConfig) -> Self {
        config.observability.listen_addr = Some("127.0.0.1:0".parse().unwrap());
        let mut server = Server::bind(config).await.unwrap();
        let addr = server.listen_addrs()[0];
        let metrics_addr = server.observability_addr().unwrap();
        let task = tokio::spawn(async move { server.run().await.unwrap() });
        Self {
            addr,
            metrics_addr,
            _task: AbortOnDrop(task),
        }
    }

    async fn metrics(&self) -> String {
        tokio::time::timeout(IO_TIMEOUT, async {
            let mut stream = TcpStream::connect(self.metrics_addr).await.unwrap();
            stream
                .write_all(b"GET /metrics HTTP/1.0\r\n\r\n")
                .await
                .unwrap();
            let mut text = String::new();
            stream.read_to_string(&mut text).await.unwrap();
            text
        })
        .await
        .expect("metrics endpoint stalled")
    }

    async fn active_until(&self, expected: u64, budget: Duration) -> u64 {
        let deadline = tokio::time::Instant::now() + budget;
        loop {
            let count = metric(&self.metrics().await, "masque_connections_active", &[]);
            if count == expected || tokio::time::Instant::now() >= deadline {
                return count;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn expect_active(&self, expected: u64) {
        assert_eq!(self.active_until(expected, IO_TIMEOUT).await, expected);
    }

    async fn expect_rejected(&self, reason: &str) {
        let labels = [format!("reason=\"{reason}\"")];
        let labels = [labels[0].as_str()];
        let before = metric(
            &self.metrics().await,
            "masque_connections_rejected_total",
            &labels,
        );
        let mut excess = TcpStream::connect(self.addr).await.unwrap();
        let mut byte = [0];
        let closed = tokio::time::timeout(IO_TIMEOUT, excess.read(&mut byte))
            .await
            .expect("excess connection was neither rejected nor admitted promptly");
        assert!(
            matches!(closed, Ok(0) | Err(_)),
            "server unexpectedly sent data on an excess connection"
        );
        let after = metric(
            &self.metrics().await,
            "masque_connections_rejected_total",
            &labels,
        );
        assert_eq!(after, before + 1, "wrong connection rejection reason");
    }

    async fn expect_new_request_works(&self) {
        let (mut client, driver) = tokio::time::timeout(IO_TIMEOUT, connect_h2(self.addr))
            .await
            .expect("replacement connection could not complete TLS/H2");
        let driver = AbortOnDrop(driver);
        let request = Request::builder()
            .uri("https://localhost/not-a-tunnel")
            .body(())
            .unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        assert_eq!(
            tokio::time::timeout(IO_TIMEOUT, response)
                .await
                .expect("replacement request stalled")
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        drop(client);
        drop(driver);
        self.expect_active(0).await;
    }

    // Prove cleanup and replacement admission even on a regression, thereby
    // distinguishing indefinite occupancy from a post-disconnect leak.
    async fn assert_reclaimed(
        &self,
        phase: &str,
        budget: Duration,
        rejection_reason: &str,
        release_peer: impl FnOnce(),
    ) {
        self.expect_active(1).await;
        self.expect_rejected(rejection_reason).await;
        let started = tokio::time::Instant::now();
        let remaining = self.active_until(0, budget).await;
        let elapsed = started.elapsed();
        if remaining != 0 {
            self.expect_rejected(rejection_reason).await;
        }
        release_peer();
        self.expect_active(0).await;
        self.expect_new_request_works().await;
        eprintln!(
            "HTTP2_TIMEOUT phase={phase} elapsed_ms={} active_after_deadline={remaining} \
             rejection_reason={rejection_reason} cleanup_active=0 replacement_request=ok",
            elapsed.as_millis()
        );
        assert_eq!(
            remaining, 0,
            "{phase}: connection and admission slot remained occupied after {budget:?}"
        );
    }
}

fn metric(text: &str, name: &str, labels: &[&str]) -> u64 {
    let samples: Vec<_> = text
        .lines()
        .filter(|line| {
            line.starts_with(&format!("{name}{{"))
                && labels.iter().all(|label| line.contains(label))
        })
        .collect();
    assert!(!samples.is_empty(), "missing metric {name} for {labels:?}");
    samples
        .into_iter()
        .map(|line| {
            line.split_ascii_whitespace()
                .nth(1)
                .unwrap()
                .parse::<u64>()
                .unwrap()
        })
        .sum()
}

async fn connect_tls(addr: SocketAddr) -> tokio_boring::SslStream<TcpStream> {
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_verify(SslVerifyMode::NONE);
    connector.set_alpn_protos(b"\x02h2").unwrap();
    let tls = tokio::time::timeout(IO_TIMEOUT, async {
        tokio_boring::connect(
            connector.build().configure().unwrap(),
            "localhost",
            TcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap()
    })
    .await
    .expect("test client TLS handshake stalled");
    assert_eq!(tls.ssl().selected_alpn_protocol(), Some(&b"h2"[..]));
    tls
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_without_client_hello_times_out_and_releases_admission() {
    let files = TestFiles::new();
    let server = ObservedServer::start(&files, true).await;
    let mut peer = TcpStream::connect(server.addr).await.unwrap();
    server
        .assert_reclaimed(
            "tls_no_client_hello",
            HANDSHAKE_DEADLINE_WITH_SLACK,
            "source_limit",
            || {},
        )
        .await;
    let mut byte = [0];
    assert!(matches!(
        tokio::time::timeout(IO_TIMEOUT, peer.read(&mut byte))
            .await
            .unwrap(),
        Ok(0) | Err(_)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_tls_record_times_out_and_releases_admission() {
    let files = TestFiles::new();
    let server = ObservedServer::start(&files, false).await;
    let mut peer = TcpStream::connect(server.addr).await.unwrap();
    // A handshake record announcing 256 bytes, with no payload.
    peer.write_all(&[0x16, 0x03, 0x01, 0x01, 0x00])
        .await
        .unwrap();
    server
        .assert_reclaimed(
            "tls_partial_record",
            HANDSHAKE_DEADLINE_WITH_SLACK,
            "limit",
            || drop(peer),
        )
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_without_preface_times_out_and_releases_admission() {
    let files = TestFiles::new();
    let server = ObservedServer::start(&files, true).await;
    let peer = connect_tls(server.addr).await;
    server
        .assert_reclaimed(
            "h2_no_preface",
            HANDSHAKE_DEADLINE_WITH_SLACK,
            "source_limit",
            || drop(peer),
        )
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_h2_preface_times_out_and_releases_admission() {
    let files = TestFiles::new();
    let server = ObservedServer::start(&files, false).await;
    let mut peer = connect_tls(server.addr).await;
    peer.write_all(b"PRI * HTTP/2.0\r\n").await.unwrap();
    server
        .assert_reclaimed(
            "h2_partial_preface",
            HANDSHAKE_DEADLINE_WITH_SLACK,
            "limit",
            || drop(peer),
        )
        .await;
}

async fn assert_idle_h2_reclaimed(send_request_first: bool) {
    let files = TestFiles::new();
    let server = ObservedServer::start(&files, !send_request_first).await;
    let tls = connect_tls(server.addr).await;
    let (client, mut connection) = h2::client::handshake(tls).await.unwrap();
    let mut ping = connection.ping_pong().unwrap();
    let driver = AbortOnDrop(tokio::spawn(connection));
    // SETTINGS/ACK and a PING round trip establish that this is genuinely an
    // idle H2 connection, not another stalled preface case. No HTTP request is
    // needed for this barrier, and no keepalive is sent during the idle wait.
    tokio::time::timeout(IO_TIMEOUT, ping.ping(h2::Ping::opaque()))
        .await
        .expect("H2 PING round trip stalled")
        .unwrap();
    let mut client = tokio::time::timeout(IO_TIMEOUT, client.ready())
        .await
        .unwrap()
        .unwrap();
    if send_request_first {
        let request = Request::builder()
            .uri("https://localhost/not-a-tunnel")
            .body(())
            .unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        assert_eq!(
            tokio::time::timeout(IO_TIMEOUT, response)
                .await
                .unwrap()
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    server
        .assert_reclaimed(
            if send_request_first {
                "h2_idle_after_request"
            } else {
                "h2_idle_no_requests"
            },
            IDLE_DEADLINE_WITH_SLACK,
            if send_request_first {
                "limit"
            } else {
                "source_limit"
            },
            || {
                drop(client);
                drop(driver);
            },
        )
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_without_requests_expires_after_idle_timeout() {
    assert_idle_h2_reclaimed(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_after_completed_request_expires_after_idle_timeout() {
    assert_idle_h2_reclaimed(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_idle_shutdown_does_not_require_settings_or_ping_acknowledgements() {
    let files = TestFiles::new();
    // The h2 handshake resolves on the 24-byte preface, before SETTINGS.
    // Neither peer reads or responds to the server's SETTINGS or any PING.
    for (phase, settings) in [
        ("h2_missing_settings_ack", &b"\0\0\0\x04\0\0\0\0\0"[..]),
        ("h2_partial_initial_settings", &b"\0\0\0\x04"[..]),
    ] {
        let server = ObservedServer::start(&files, false).await;
        let mut peer = connect_tls(server.addr).await;
        peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .unwrap();
        peer.write_all(settings).await.unwrap();
        server
            .assert_reclaimed(phase, IDLE_DEADLINE_WITH_SLACK, "limit", || drop(peer))
            .await;
    }
}

fn udp_request(target_addr: SocketAddr) -> Request<()> {
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!(
            "https://localhost/.well-known/masque/udp/127.0.0.1/{}/",
            target_addr.port()
        ))
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap();
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("connect-udp"));
    request
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn active_tcp_tunnel_survives_then_idle_timeout_releases_its_slot() {
    let files = TestFiles::new();
    let server = ObservedServer::start(&files, false).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let (mut client, driver) = connect_h2(server.addr).await;
    let _driver = AbortOnDrop(driver);
    let (response, mut body) = client
        .send_request(connect_request(target_addr), false)
        .unwrap();
    let mut response = tokio::time::timeout(IO_TIMEOUT, response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let (mut upstream, _) = tokio::time::timeout(IO_TIMEOUT, target.accept())
        .await
        .unwrap()
        .unwrap();

    // Exchange traffic for longer than the configured idle interval. A total
    // connection-age timeout would incorrectly kill this healthy tunnel.
    for _ in 0..6 {
        body.send_data(Bytes::from_static(b"x"), false).unwrap();
        let mut byte = [0];
        tokio::time::timeout(IO_TIMEOUT, upstream.read_exact(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&byte, b"x");
        upstream.write_all(&byte).await.unwrap();
        let echo = tokio::time::timeout(IO_TIMEOUT, response.body_mut().data())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(&echo[..], b"x");
        response
            .body_mut()
            .flow_control()
            .release_capacity(echo.len())
            .unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let started = tokio::time::Instant::now();
    let reset = tokio::time::timeout(IDLE_DEADLINE_WITH_SLACK, response.body_mut().data())
        .await
        .expect("idle CONNECT stream did not close")
        .expect("expected a CANCEL reset")
        .unwrap_err();
    assert_eq!(reset.reason(), Some(h2::Reason::CANCEL));
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(IO_TIMEOUT, upstream.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    // A replacement stream on the same connection proves the sole tunnel
    // permit was returned. Keep it open until the successful 200 is observed.
    let (response, replacement_body) = client
        .send_request(connect_request(target_addr), false)
        .unwrap();
    assert_eq!(
        tokio::time::timeout(IO_TIMEOUT, response)
            .await
            .unwrap()
            .unwrap()
            .status(),
        StatusCode::OK
    );
    eprintln!(
        "HTTP2_TIMEOUT phase=tcp_tunnel idle_close_ms={} active_survived_ms=1500 target_eof=true replacement_stream=200",
        started.elapsed().as_millis()
    );
    drop(replacement_body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quiet_udp_tunnel_is_not_connection_idle_and_closing_it_starts_a_fresh_deadline() {
    let files = TestFiles::new();
    let server = ObservedServer::start(&files, false).await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let (mut client, driver) = connect_h2(server.addr).await;
    let _driver = AbortOnDrop(driver);
    let request = udp_request(target_addr);
    let (response, mut body) = client.send_request(request, false).unwrap();
    let mut response = tokio::time::timeout(IO_TIMEOUT, response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Completing another request must not arm the connection idle timer while
    // this UDP task remains. UDP mappings have their own 120-second minimum.
    let (short_response, _) = client
        .send_request(
            Request::builder()
                .uri("https://localhost/not-a-tunnel")
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    assert_eq!(
        tokio::time::timeout(IO_TIMEOUT, short_response)
            .await
            .unwrap()
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    tokio::time::sleep(Duration::from_secs(IDLE_SECS + 1)).await;
    server.expect_active(1).await;
    let mut capsule = Vec::new();
    encoder::encode_datagram_context_zero(b"still alive", &mut capsule);
    body.send_data(Bytes::from(capsule), false).unwrap();
    let mut packet = [0; 64];
    let (read, peer) = tokio::time::timeout(IO_TIMEOUT, target.recv_from(&mut packet))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&packet[..read], b"still alive");
    target.send_to(&packet[..read], peer).await.unwrap();
    let echo = tokio::time::timeout(IO_TIMEOUT, response.body_mut().data())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut decoder = CapsuleDecoder::new();
    assert_eq!(
        decoder.decode(&echo).unwrap(),
        vec![CapsuleFrame::Datagram(b"\0still alive".to_vec())]
    );
    response
        .body_mut()
        .flow_control()
        .release_capacity(echo.len())
        .unwrap();

    body.send_data(Bytes::new(), true).unwrap();
    tokio::time::timeout(IO_TIMEOUT, async {
        while let Some(chunk) = response.body_mut().data().await {
            assert!(
                chunk.unwrap().is_empty(),
                "unexpected trailing UDP response"
            );
        }
    })
    .await
    .expect("UDP stream did not finish after client END_STREAM");
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        metric(&server.metrics().await, "masque_connections_active", &[]),
        1,
        "old connection deadline was reused after the final stream completed"
    );
    assert_eq!(server.active_until(0, IDLE_DEADLINE_WITH_SLACK).await, 0);
    server.expect_new_request_works().await;
    eprintln!(
        "HTTP2_TIMEOUT phase=quiet_udp active_survived_secs=2 final_stream_fresh_deadline=true replacement_request=ok"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resetting_the_last_tunnel_starts_connection_idle_cleanup() {
    let files = TestFiles::new();
    let server = ObservedServer::start(&files, false).await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (mut client, driver) = connect_h2(server.addr).await;
    let _driver = AbortOnDrop(driver);
    let (response, mut body) = client
        .send_request(udp_request(target.local_addr().unwrap()), false)
        .unwrap();
    let response = tokio::time::timeout(IO_TIMEOUT, response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    body.send_reset(h2::Reason::CANCEL);
    assert_eq!(
        server.active_until(0, IDLE_DEADLINE_WITH_SLACK).await,
        0,
        "cancelled request kept the connection active"
    );
    server.expect_new_request_works().await;
    eprintln!("HTTP2_TIMEOUT phase=last_tunnel_reset cleanup_active=0 replacement_request=ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_basic_auth_deadline_releases_active_unauthenticated_connection() {
    let files = TestFiles::new();
    let mut config = http2_config(&files);
    config.listeners[0].auth.enabled = true;
    config.listeners[0].auth.username = "test".into();
    config.listeners[0].auth.password_hash = masque::auth::hash_password(b"password").unwrap();
    config.server.idle_timeout_secs = IDLE_SECS;
    config.server.max_connections = 1;
    let server = ObservedServer::bind(config).await;
    let addr = server.addr;
    let (mut client, driver) = connect_h2(addr).await;
    let _driver = AbortOnDrop(driver);

    let unknown = || {
        Request::builder()
            .uri("https://localhost/not-a-tunnel")
            .body(())
            .unwrap()
    };
    let (first, _) = client.send_request(unknown(), true).unwrap();
    assert_eq!(first.await.unwrap().status(), StatusCode::NOT_FOUND);
    server.expect_active(1).await;
    tokio::time::timeout(IDLE_DEADLINE_WITH_SLACK, async {
        while let Ok((response, _)) = client.send_request(unknown(), true) {
            match response.await {
                Ok(response) => assert_eq!(response.status(), StatusCode::NOT_FOUND),
                Err(_) => break,
            }
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
    })
    .await
    .expect("unauthenticated requests extended the first Basic auth deadline");
    server.expect_active(0).await;

    let (mut client, driver) = connect_h2(addr).await;
    let _driver = AbortOnDrop(driver);
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut request = connect_request(target.local_addr().unwrap());
    request.headers_mut().insert(
        "proxy-authorization",
        format!("Basic {}", STANDARD.encode("test:password"))
            .parse()
            .unwrap(),
    );
    let (response, _request_body) = client.send_request(request, false).unwrap();
    assert_eq!(response.await.unwrap().status(), StatusCode::OK);
    let (_upstream, _) = target.accept().await.unwrap();

    // Keep issuing unsupported requests past the original deadline. The
    // connection should remain usable after the first successful Basic auth.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
    while tokio::time::Instant::now() < deadline {
        let (response, _) = client.send_request(unknown(), true).unwrap();
        assert_eq!(response.await.unwrap().status(), StatusCode::NOT_FOUND);
        tokio::time::sleep(Duration::from_millis(80)).await;
    }
}

#[test]
fn reset_during_target_setup_releases_the_tunnel_slot() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap()
        .block_on(async {
            let files = TestFiles::new();
            let mut config = http2_config(&files);
            config.server.max_tunnels_per_connection = 1;
            config.tcp_proxy.connect_timeout_secs = 15;
            config.udp_proxy.connect_timeout_secs = 15;
            let server = ObservedServer::bind(config).await;
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = target.local_addr().unwrap();

            // Keep the sole blocking worker busy so hostname resolution in
            // the real target setup cannot finish. The replacement uses a
            // numeric address and needs no blocking worker.
            let (release, hold) = std::sync::mpsc::channel::<()>();
            let (started, waiting) = tokio::sync::oneshot::channel();
            let worker = tokio::task::spawn_blocking(move || {
                started.send(()).unwrap();
                let _ = hold.recv();
            });
            waiting.await.unwrap();

            let connect = |authority: &str| {
                Request::builder()
                    .method(Method::CONNECT)
                    .uri(authority)
                    .body(())
                    .unwrap()
            };
            let mut udp = Request::builder()
                .method(Method::CONNECT)
                .uri(format!(
                    "https://localhost/.well-known/masque/udp/localhost/{}/",
                    addr.port()
                ))
                .header("capsule-protocol", "?1")
                .body(())
                .unwrap();
            udp.extensions_mut()
                .insert(h2::ext::Protocol::from_static("connect-udp"));

            for request in [connect(&format!("localhost:{}", addr.port())), udp] {
                let (mut client, driver) = connect_h2(server.addr).await;
                let _driver = AbortOnDrop(driver);
                let (mut waiting, mut stream) = client.send_request(request, false).unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(150), &mut waiting)
                        .await
                        .is_err(),
                    "target setup was not pending"
                );

                let (limited, _) = client
                    .send_request(connect(&addr.to_string()), true)
                    .unwrap();
                assert_eq!(
                    tokio::time::timeout(IO_TIMEOUT, limited)
                        .await
                        .unwrap()
                        .unwrap()
                        .status(),
                    StatusCode::SERVICE_UNAVAILABLE
                );
                stream.send_reset(h2::Reason::CANCEL);
                tokio::time::timeout(IO_TIMEOUT, async {
                    loop {
                        let (replacement, _) = client
                            .send_request(connect(&addr.to_string()), true)
                            .unwrap();
                        let status = replacement.await.unwrap().status();
                        if status == StatusCode::OK {
                            break;
                        }
                        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                })
                .await
                .expect("reset did not release the tunnel slot before the setup timeout");
                tokio::time::timeout(IO_TIMEOUT, target.accept())
                    .await
                    .unwrap()
                    .unwrap();
            }

            drop(release);
            worker.await.unwrap();
        });
}

#[tokio::test]
async fn tcp_reset_after_request_fin_releases_the_tunnel_slot() {
    let files = TestFiles::new();
    let mut config = http2_config(&files);
    config.server.max_tunnels_per_connection = 1;
    let server = ObservedServer::bind(config).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let (mut client, driver) = connect_h2(server.addr).await;
    let _driver = AbortOnDrop(driver);
    let (response, mut body) = client
        .send_request(connect_request(target_addr), false)
        .unwrap();
    let response = tokio::time::timeout(IO_TIMEOUT, response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let (mut upstream, _) = tokio::time::timeout(IO_TIMEOUT, target.accept())
        .await
        .unwrap()
        .unwrap();

    body.send_data(Bytes::new(), true).unwrap();
    assert_eq!(
        tokio::time::timeout(IO_TIMEOUT, upstream.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    // Keep the silent target's response direction open after observing FIN.
    body.send_reset(h2::Reason::CANCEL);
    expect_replacement_tcp_tunnel(&mut client, target_addr).await;
    drop((response, upstream));
}

#[tokio::test]
async fn tcp_reset_after_response_fin_releases_a_backpressured_upload() {
    let files = TestFiles::new();
    let mut config = http2_config(&files);
    config.server.max_tunnels_per_connection = 1;
    let server = ObservedServer::bind(config).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    // Keep the target's receive window bounded from the TCP handshake onward.
    socket2::SockRef::from(&target)
        .set_recv_buffer_size(16 * 1024)
        .unwrap();
    let target_addr = target.local_addr().unwrap();
    let (mut client, driver) = connect_h2(server.addr).await;
    let _driver = AbortOnDrop(driver);
    let (response, mut upload) = client
        .send_request(connect_request(target_addr), false)
        .unwrap();
    let response = tokio::time::timeout(IO_TIMEOUT, response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let (mut upstream, _) = tokio::time::timeout(IO_TIMEOUT, target.accept())
        .await
        .unwrap()
        .unwrap();
    upstream.shutdown().await.unwrap();
    let mut download = response.into_body();
    tokio::time::timeout(IO_TIMEOUT, async {
        while let Some(data) = download.data().await {
            assert!(data.unwrap().is_empty());
        }
    })
    .await
    .expect("target FIN did not reach the client");

    // The target keeps its read half open without draining it. Send within
    // the H2 window until the relay stops returning upload credit.
    let chunk = Bytes::from_static(&[0x5a; 16 * 1024]);
    let mut blocked = false;
    for _ in 0..1024 {
        upload.reserve_capacity(chunk.len());
        let Ok(capacity) = tokio::time::timeout(
            Duration::from_millis(500),
            std::future::poll_fn(|cx| upload.poll_capacity(cx)),
        )
        .await
        else {
            blocked = true;
            break;
        };
        let capacity = capacity.unwrap().unwrap().min(chunk.len());
        upload.send_data(chunk.slice(..capacity), false).unwrap();
    }
    assert!(blocked, "upload never encountered target backpressure");
    let (limited, _) = client
        .send_request(connect_request(target_addr), true)
        .unwrap();
    assert_eq!(
        tokio::time::timeout(IO_TIMEOUT, limited)
            .await
            .unwrap()
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    upload.send_reset(h2::Reason::CANCEL);
    expect_replacement_tcp_tunnel(&mut client, target_addr).await;
    drop(upstream);
}

async fn expect_replacement_tcp_tunnel(
    client: &mut h2::client::SendRequest<Bytes>,
    target_addr: SocketAddr,
) {
    tokio::time::timeout(IO_TIMEOUT, async {
        loop {
            let (replacement, _upload) = client
                .send_request(connect_request(target_addr), false)
                .unwrap();
            let status = replacement.await.unwrap().status();
            if status == StatusCode::OK {
                break;
            }
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("reset did not release the tunnel slot after FIN");
}
