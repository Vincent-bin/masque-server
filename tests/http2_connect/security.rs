use super::*;

fn basic_config(files: &TestFiles) -> ServerConfig {
    let mut config = http2_config(files);
    config.listeners[0].auth.enabled = true;
    config.listeners[0].auth.users = vec![BasicUser {
        username: "audit".into(),
        password_hash: masque::auth::hash_password(b"audit-test-secret").unwrap(),
    }];
    config
}

fn ip_request() -> Request<()> {
    let mut request = connect_ip_request("connect-ip");
    request.headers_mut().insert(
        "proxy-authorization",
        format!("Basic {}", STANDARD.encode("audit:audit-test-secret"))
            .parse()
            .unwrap(),
    );
    request
}

async fn limited_window_client(
    addr: std::net::SocketAddr,
    window: u32,
) -> (
    h2::client::SendRequest<Bytes>,
    tokio::task::JoinHandle<Result<(), h2::Error>>,
) {
    let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
    connector.set_verify(SslVerifyMode::NONE);
    connector.set_alpn_protos(b"\x02h2").unwrap();
    let tls = tokio_boring::connect(
        connector.build().configure().unwrap(),
        "localhost",
        TcpStream::connect(addr).await.unwrap(),
    )
    .await
    .unwrap();
    let mut builder = h2::client::Builder::new();
    builder.initial_window_size(window);
    let (client, connection) = builder.handshake(tls).await.unwrap();
    let driver = tokio::spawn(connection);
    (client.ready().await.unwrap(), driver)
}

async fn assert_reusable(addr: std::net::SocketAddr) {
    tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let (mut client, driver) = connect_h2(addr).await;
                let (response, mut request_body) = client.send_request(ip_request(), false).unwrap();
                let response = response.await.unwrap();
                if response.status() == StatusCode::OK {
                    let (frames, _body) = read_connect_ip_setup(response).await;
                    assert!(matches!(&frames[0], CapsuleFrame::AddressAssign(addresses) if addresses.len() == 1));
                    request_body.send_reset(h2::Reason::CANCEL);
                    driver.abort();
                    break;
                }
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                driver.abort();
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await.expect("address was not reclaimed after peer termination");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_ip_setup_expires_and_releases_lease_and_slot() {
    let files = TestFiles::new();
    let mut config = basic_config(&files);
    config.ip_proxy.enabled = true;
    config.ip_proxy.ipv4_pool = "192.0.2.0/30".into();
    config.ip_proxy.ipv6_pool.clear();
    config.server.idle_timeout_secs = 1;
    config.server.max_tunnels_per_connection = 1;
    let (addr, server_task) = spawn_http2_config(config).await;
    for window in [0, 1] {
        let (mut client, driver) = limited_window_client(addr, window).await;
        let (response, _body) = client.send_request(ip_request(), false).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut blocked_response = response.into_body();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match blocked_response.data().await {
                    Some(Ok(_)) => {} // Deliberately withhold WINDOW_UPDATE.
                    Some(Err(error)) => {
                        assert_eq!(error.reason(), Some(h2::Reason::CANCEL));
                        break;
                    }
                    None => panic!("expected stalled initialization to reset"),
                }
            }
        })
        .await
        .expect("stalled initialization exceeded its deadline");
        // Same connection proves its sole tunnel slot is reusable.
        let (second, mut body) = client.send_request(ip_request(), false).unwrap();
        assert_eq!(second.await.unwrap().status(), StatusCode::OK);
        body.send_reset(h2::Reason::CANCEL);
        assert_reusable(addr).await;
        driver.abort();
    }
    // Disconnect while initialization is still blocked also releases the pool.
    let (mut client, driver) = limited_window_client(addr, 0).await;
    let (response, body) = client.send_request(ip_request(), false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    driver.abort();
    drop((client, body, response));
    assert_reusable(addr).await;
    server_task.abort();
}

async fn failures(addr: std::net::SocketAddr) -> u64 {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /metrics HTTP/1.0\r\n\r\n")
        .await
        .unwrap();
    let mut text = String::new();
    stream.read_to_string(&mut text).await.unwrap();
    text.lines()
        .filter(|line| {
            line.starts_with("masque_auth_attempts_total{") && line.contains("result=\"failure\"")
        })
        .map(|line| {
            line.split_whitespace()
                .last()
                .unwrap()
                .parse::<u64>()
                .unwrap()
        })
        .sum()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_basic_rejections_are_counted_once() {
    let files = TestFiles::new();
    let mut config = basic_config(&files);
    config.observability.listen_addr = Some("127.0.0.1:0".parse().unwrap());
    let mut server = Server::bind(config).await.unwrap();
    let addr = server.listen_addrs()[0];
    let metrics = server.observability_addr().unwrap();
    let server_task = tokio::spawn(async move { server.run().await.unwrap() });
    let (mut client, driver) = connect_h2(addr).await;
    let baseline = failures(metrics).await;
    let unknown = format!("Basic {}", STANDARD.encode("unknown:secret"));
    for value in [
        None,
        Some("invalid"),
        Some(unknown.as_str()),
        Some("duplicate"),
    ] {
        let mut request = connect_request("127.0.0.1:9".parse().unwrap());
        if let Some(value) = value {
            request
                .headers_mut()
                .append("proxy-authorization", value.parse().unwrap());
            if value == "duplicate" {
                request
                    .headers_mut()
                    .append("proxy-authorization", value.parse().unwrap());
            }
        }
        let (response, _) = client.send_request(request, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(response.headers().get("proxy-authenticate").is_none());
    }
    let fast = failures(metrics).await - baseline;
    assert_eq!(fast, 4);
    let wrong = basic_connect_status(&client, "audit", "wrong-password").await;
    assert_eq!(wrong, StatusCode::NOT_FOUND);
    let hashed = failures(metrics).await - baseline;
    assert_eq!(hashed, 5);
    driver.abort();
    server_task.abort();
}
