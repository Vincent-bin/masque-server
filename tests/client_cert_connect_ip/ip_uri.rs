//! Standard request validation preserves legacy framing and the authentication boundary.
use super::*;

#[test]
fn standard_ip_uri_validation_and_legacy_compatibility_over_http3() {
    let fixture = fixture("ip-uri-validation");
    let mut client =
        Client::connect(fixture.peer, &fixture.client_cert, &fixture.client_key).unwrap();
    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();
    for (path, expected) in [
        ("/", 400),
        ("/.well-known/masque/ip/", 400),
        ("/.well-known/masque/ip/*/", 400),
        ("/.well-known/masque/ip/*/*/extra", 400),
        ("/.well-known/masque/ip//*/", 400),
        ("/.well-known/masque/ip/*/256/", 400),
        ("/.well-known/masque/ip/192.0.2.1%2F24/*/", 400),
        ("/.well-known/masque/ip/*/*/?target=192.0.2.1", 400),
        ("/.well-known/masque/ip/192.0.2.1/*/", 501),
        ("/.well-known/masque/ip/example.invalid/*/", 501),
        ("/.well-known/masque/ip/*/17/", 501),
        ("/.well-known/masque/ip/0.0.0.0%2F0/*/", 501),
    ] {
        let stream = client
            .send_connect_ip_path("connect-ip", path, None)
            .unwrap();
        let headers = client
            .response_headers(stream, Duration::from_secs(5))
            .unwrap();
        let status = headers.iter().find(|(name, _)| name == b":status").unwrap();
        assert_eq!(
            std::str::from_utf8(&status.1).unwrap(),
            expected.to_string(),
            "{path}"
        );
        assert!(headers.iter().all(|(name, _)| {
            ![b"server".as_slice(), b"proxy-status", b"capsule-protocol"].contains(&name.as_slice())
        }));
    }
    let malformed = client
        .send_connect_ip_path("connect-ip", "/.well-known/masque/ip/%XX/*/", None)
        .unwrap();
    assert_eq!(
        client.stream_reset(malformed),
        quiche::h3::WireErrorCode::MessageError as u64
    );
    let stream = client
        .send_connect_ip_path("connect-ip", "/.well-known/masque/ip/%2A/%2a/", None)
        .unwrap();
    assert_eq!(
        client
            .response_status(stream, Duration::from_secs(5))
            .unwrap(),
        200
    );
    let addresses = assigned_addresses(&mut client, stream);
    assert!(addresses.contains(&IpAddress::V4(CLIENT_IPV4.parse().unwrap())));

    // A fresh connection can reclaim the same pinned addresses without
    // confusing the existing pinned-stream ownership on the first one.
    let mut legacy =
        Client::connect(fixture.peer, &fixture.client_cert, &fixture.client_key).unwrap();
    legacy.handshake(Duration::from_secs(5)).unwrap();
    legacy.init_h3().unwrap();
    let stream = legacy
        .send_connect_ip_path("cf-connect-ip", "/", None)
        .unwrap();
    assert_eq!(
        legacy
            .response_status(stream, Duration::from_secs(5))
            .unwrap(),
        200
    );
}

#[test]
fn ip_uri_validation_preserves_http3_stealth_authentication_boundary() {
    let fixture = dual_fixture_with_stealth("ip-uri-stealth", true);
    let mut client = Client::connect_anonymous(fixture.basic_peer).unwrap();
    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();
    let wrong = format!(
        "Basic {}",
        STANDARD.encode(format!("{BASIC_USERNAME}:wrong"))
    );
    for credential in [None, Some(wrong.as_str())] {
        for path in [
            "/",
            "/.well-known/masque/ip/*/*/",
            "/.well-known/masque/ip/*/17/",
        ] {
            let stream = client
                .send_connect_ip_path("connect-ip", path, credential)
                .unwrap();
            let headers = client
                .response_headers(stream, Duration::from_secs(5))
                .unwrap();
            assert_eq!(
                headers
                    .iter()
                    .find(|(name, _)| name == b":status")
                    .unwrap()
                    .1,
                b"404"
            );
            assert!(headers.iter().all(|(name, _)| {
                ![
                    b"proxy-authenticate".as_slice(),
                    b"proxy-status",
                    b"capsule-protocol",
                ]
                .contains(&name.as_slice())
            }));
        }
    }
    for (path, expected) in [
        ("/", 400),
        ("/.well-known/masque/ip/*/17/", 501),
        ("/.well-known/masque/ip/*/*/", 200),
    ] {
        let stream = client
            .send_connect_ip_path("connect-ip", path, Some(&fixture.credentials))
            .unwrap();
        assert_eq!(
            client
                .response_status(stream, Duration::from_secs(5))
                .unwrap(),
            expected
        );
    }
}

#[test]
fn standard_ip_query_template_over_http3() {
    let dir = TempDir::new("ip-uri-query");
    let key = p256_key();
    let (cert_path, key_path) = write_pem(
        dir.path(),
        "server",
        &key,
        &self_signed(&key, Some("localhost")),
    );
    let mut config = server_config(cert_path, key_path, ephemeral_addr(), vec![]);
    config.listeners[0].auth.enabled = false;
    config.ip_proxy.uri_template = "/vpn{?target,ipproto}".into();
    let peer = spawn_server(config)[0];
    let mut client = Client::connect_anonymous(peer).unwrap();
    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();
    for (path, expected) in [
        ("/.well-known/masque/ip/*/*/", 400),
        ("/vpn/extra", 400),
        ("/vpn?ipproto=17", 501),
        ("/vpn?target=192.0.2.1", 501),
        ("/vpn?target=*&target=192.0.2.1", 400),
        ("/vpn?ipproto=", 400),
        ("/vpn?target=%2A&ipproto=%2A", 200),
        ("/vpn", 200),
    ] {
        let stream = client
            .send_connect_ip_path("connect-ip", path, None)
            .unwrap();
        assert_eq!(
            client
                .response_status(stream, Duration::from_secs(5))
                .unwrap(),
            expected,
            "{path}"
        );
    }
}
