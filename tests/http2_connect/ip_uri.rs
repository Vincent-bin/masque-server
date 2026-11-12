//! URI scope checks must precede setup but follow the authentication boundary.
use super::*;

fn ip_request(path: &str, protocol: &'static str) -> Request<()> {
    let mut request = connect_ip_request(protocol);
    *request.uri_mut() = format!("https://localhost{path}").parse().unwrap();
    request
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_ip_query_matching_preserves_udp_path_only_matching() {
    let files = TestFiles::new();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut config = http2_config(&files);
    config.ip_proxy.enabled = true;
    config.ip_proxy.uri_template = "/vpn{?target,ipproto}".into();
    let (addr, server_task) = spawn_http2_config(config).await;
    let (mut client, driver) = connect_h2(addr).await;
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!(
            "https://localhost/.well-known/masque/udp/127.0.0.1/{}/?unchanged=query",
            target.local_addr().unwrap().port()
        ))
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap();
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("connect-udp"));
    let (response, mut body) = client.send_request(request, false).unwrap();
    assert_eq!(response.await.unwrap().status(), StatusCode::OK);
    body.send_reset(h2::Reason::CANCEL);
    server_task.abort();
    driver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standard_ip_uri_rejects_malformed_and_unsupported_scopes_before_setup() {
    let files = TestFiles::new();
    let mut config = http2_config(&files);
    config.ip_proxy.enabled = true;
    // Exactly one dynamic IPv4 lease, so rejected requests would exhaust it
    // if they accidentally reached tunnel allocation.
    config.ip_proxy.ipv4_pool = "192.0.2.0/30".into();
    config.ip_proxy.ipv6_pool.clear();
    let (addr, server_task) = spawn_http2_config(config).await;
    let (mut client, driver) = connect_h2(addr).await;
    for (path, status) in [
        ("/", 400),
        ("/.well-known/masque/ip/", 400),
        ("/.well-known/masque/ip/*/", 400),
        ("/.well-known/masque/ip/*/*/extra", 400),
        ("/.well-known/masque/ip//*/", 400),
        ("/.well-known/masque/ip/*/256/", 400),
        ("/.well-known/masque/ip/192.0.2.1%2F24/*/", 400),
        ("/.well-known/masque/ip/%XX/*/", 400),
        ("/.well-known/masque/ip/*/*/?target=192.0.2.1", 400),
        ("/.well-known/masque/ip/192.0.2.1/*/", 501),
        ("/.well-known/masque/ip/example.invalid/*/", 501),
        ("/.well-known/masque/ip/*/17/", 501),
        ("/.well-known/masque/ip/0.0.0.0%2F0/*/", 501),
    ] {
        let (response, _) = client
            .send_request(ip_request(path, "connect-ip"), false)
            .unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status().as_u16(), status, "{path}");
        assert!(response.headers().get("capsule-protocol").is_none());
        assert!(response.headers().get("proxy-status").is_none());
        assert!(response.headers().get("server").is_none());
    }
    let (response, _request_body) = client
        .send_request(
            ip_request("/.well-known/masque/ip/%2A/%2a/", "connect-ip"),
            false,
        )
        .unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let (frames, _body) = read_connect_ip_setup(response).await;
    assert!(matches!(
        frames.first(),
        Some(CapsuleFrame::AddressAssign(_))
    ));
    server_task.abort();
    driver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standard_ip_query_template_is_matched_on_both_path_and_query() {
    let files = TestFiles::new();
    let mut config = http2_config(&files);
    config.ip_proxy.enabled = true;
    config.ip_proxy.uri_template = "/vpn{?target,ipproto}".into();
    let (addr, server_task) = spawn_http2_config(config).await;
    let (mut client, driver) = connect_h2(addr).await;
    for (path, status) in [
        ("/.well-known/masque/ip/*/*/", 400),
        ("/vpn/extra", 400),
        ("/vpn?ipproto=17", 501),
        ("/vpn?target=192.0.2.1", 501),
        ("/vpn?target=*&target=192.0.2.1", 400),
        ("/vpn?ipproto=", 400),
        ("/vpn?target=%2A&ipproto=%2A", 200),
        ("/vpn", 200),
    ] {
        let (response, mut body) = client
            .send_request(ip_request(path, "connect-ip"), false)
            .unwrap();
        assert_eq!(response.await.unwrap().status().as_u16(), status, "{path}");
        body.send_reset(h2::Reason::CANCEL);
    }
    // Legacy Extended CONNECT keeps its arbitrary path; cf-connect-proto
    // authority-only compatibility remains covered by the existing suite.
    let (response, _) = client
        .send_request(ip_request("/", "cf-connect-ip"), false)
        .unwrap();
    assert_eq!(response.await.unwrap().status(), StatusCode::OK);
    server_task.abort();
    driver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ip_uri_validation_does_not_create_an_unauthenticated_stealth_oracle() {
    let files = TestFiles::new();
    let mut config = http2_config(&files);
    config.ip_proxy.enabled = true;
    config.listeners[0].auth.enabled = true;
    config.listeners[0].auth.mode = AuthMode::Basic;
    config.listeners[0].auth.stealth = true;
    config.listeners[0].auth.users = vec![BasicUser {
        username: "alice".into(),
        password_hash: masque::auth::hash_password(b"alice-secret").unwrap(),
    }];
    let (addr, server_task) = spawn_http2_config(config).await;
    let (mut client, driver) = connect_h2(addr).await;
    let wrong = format!("Basic {}", STANDARD.encode("alice:wrong"));
    let valid = format!("Basic {}", STANDARD.encode("alice:alice-secret"));
    for credential in [None, Some(&wrong)] {
        for path in [
            "/",
            "/.well-known/masque/ip/*/*/",
            "/.well-known/masque/ip/*/17/",
        ] {
            let mut request = ip_request(path, "connect-ip");
            if let Some(credential) = credential {
                request
                    .headers_mut()
                    .insert("proxy-authorization", credential.parse().unwrap());
            }
            let (response, _) = client.send_request(request, false).unwrap();
            let response = response.await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
            assert!(response.headers().get("proxy-authenticate").is_none());
            assert!(response.headers().get("capsule-protocol").is_none());
            assert!(response.headers().get("proxy-status").is_none());
        }
    }
    for name in ["authorization", "proxy-authorization"] {
        for (path, status) in [
            ("/", 400),
            ("/.well-known/masque/ip/*/17/", 501),
            ("/.well-known/masque/ip/*/*/", 200),
        ] {
            let mut request = ip_request(path, "connect-ip");
            request.headers_mut().insert(name, valid.parse().unwrap());
            let (response, mut body) = client.send_request(request, false).unwrap();
            let response = response.await.unwrap();
            assert_eq!(response.status().as_u16(), status, "{name} {path}");
            if status == 200 {
                let (frames, _response_body) = read_connect_ip_setup(response).await;
                assert!(matches!(
                    frames.first(),
                    Some(CapsuleFrame::AddressAssign(_))
                ));
            }
            body.send_reset(h2::Reason::CANCEL);
        }
    }
    for (protocol, path, extra_header, credential) in [
        (
            "connect-ip",
            "/.well-known/masque/ip/*/*/",
            None,
            wrong.as_str(),
        ),
        (
            "connect-ip",
            "/.well-known/masque/ip/*/*/",
            Some("authorization"),
            valid.as_str(),
        ),
        (
            "connect-ip",
            "/.well-known/masque/ip/*/*/",
            Some("proxy-authorization"),
            valid.as_str(),
        ),
        ("cf-connect-ip", "/", None, valid.as_str()),
        ("connect-udp", "/", None, valid.as_str()),
    ] {
        let mut request = ip_request(path, protocol);
        request
            .headers_mut()
            .insert("authorization", credential.parse().unwrap());
        if let Some(name) = extra_header {
            request.headers_mut().append(name, valid.parse().unwrap());
        }
        let (response, _) = client.send_request(request, false).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{protocol}");
        assert!(response.headers().get("www-authenticate").is_none());
        assert!(response.headers().get("proxy-authenticate").is_none());
        assert!(response.into_body().data().await.is_none());
    }
    server_task.abort();
    driver.abort();
}
