//! CONNECT-UDP datagram limits, ignored capsules, and incremental framing.

use super::*;

#[path = "../support/udp_capsules.rs"]
mod wire_fixtures;

fn udp_request(target: std::net::SocketAddr) -> Request<()> {
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!(
            "https://localhost/.well-known/masque/udp/{}/{}/",
            target.ip(),
            target.port()
        ))
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap();
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("connect-udp"));
    request
}

fn context_zero(width: usize) -> Vec<u8> {
    let mut context = vec![0; width];
    context[0] = match width {
        1 => 0,
        2 => 0x40,
        4 => 0x80,
        8 => 0xc0,
        _ => unreachable!(),
    };
    context
}

fn datagram_capsule(context: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    encoder::encode_datagram(&[context, payload].concat(), &mut wire);
    wire
}

async fn assert_echo(target: &UdpSocket, response_body: &mut h2::RecvStream, payload: &[u8]) {
    let mut received = vec![0; payload.len() + 1];
    let (length, peer) =
        tokio::time::timeout(Duration::from_secs(2), target.recv_from(&mut received))
            .await
            .expect("UDP payload did not reach the target")
            .unwrap();
    assert_eq!(&received[..length], payload);
    target.send_to(payload, peer).await.unwrap();

    let mut decoder = CapsuleDecoder::new();
    let frames = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let data = response_body.data().await.unwrap().unwrap();
            response_body
                .flow_control()
                .release_capacity(data.len())
                .unwrap();
            let frames = decoder.decode(&data).unwrap();
            if !frames.is_empty() {
                break frames;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        frames,
        [CapsuleFrame::Datagram([&[0][..], payload].concat())]
    );
    assert_eq!(decoder.buffered(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_context_zero_width_accepts_the_configured_udp_payload_limit() {
    let files = TestFiles::new();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for limit in [1, 1200] {
        let mut config = http2_config(&files);
        config.http2.max_datagram_size = limit;
        let (server_addr, server_task) = spawn_http2_config(config).await;
        let (mut client, driver) = connect_h2(server_addr).await;
        let (response, mut request_body) = client
            .send_request(udp_request(target.local_addr().unwrap()), false)
            .unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut response_body = response.into_body();

        for width in [1, 2, 4, 8] {
            for length in [0, limit - 1, limit] {
                let payload = vec![width as u8; length];
                let wire = datagram_capsule(&context_zero(width), &payload);
                let header_len = wire.len() - width - payload.len();
                // Split inside the capsule header and the Context ID, then
                // across the payload boundary. Decoding must stay incremental.
                for part in [
                    &wire[..1],
                    &wire[1..header_len + 1],
                    &wire[header_len + 1..header_len + width],
                    &wire[header_len + width..],
                ] {
                    if !part.is_empty() {
                        request_body
                            .send_data(Bytes::copy_from_slice(part), false)
                            .unwrap();
                    }
                }
                assert_echo(&target, &mut response_body, &payload).await;
            }
        }
        request_body.send_data(Bytes::new(), true).unwrap();
        server_task.abort();
        driver.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn context_headroom_never_relaxes_the_udp_payload_limit() {
    const LIMIT: usize = 1200;
    let files = TestFiles::new();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut config = http2_config(&files);
    config.http2.max_datagram_size = LIMIT;
    let (server_addr, server_task) = spawn_http2_config(config).await;
    let (mut client, driver) = connect_h2(server_addr).await;

    let mut invalid = Vec::new();
    for width in [1, 2, 4, 8] {
        // Some values fit the extra Context ID budget but must still fail
        // the post-decode payload check. Larger values fail the framing bound.
        for excess in 1..=8 {
            invalid.push((
                datagram_capsule(&context_zero(width), &vec![0x55; LIMIT + excess]),
                false,
            ));
        }
    }
    let mut oversized_header = vec![0];
    masque::varint::encode_to_vec((LIMIT + 9) as u64, &mut oversized_header).unwrap();
    // No value or END_STREAM: reject from the length alone, without waiting.
    invalid.push((oversized_header, false));
    invalid.push((datagram_capsule(&[], &[]), false));
    for width in [2, 4, 8] {
        let context = context_zero(width);
        invalid.push((datagram_capsule(&context[..width - 1], &[]), false));
        let mut truncated = datagram_capsule(&context, &[]);
        truncated.pop();
        invalid.push((truncated, true));
    }

    for (wire, end_stream) in invalid {
        let (response, mut request_body) = client
            .send_request(udp_request(target.local_addr().unwrap()), false)
            .unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut response_body = response.into_body();
        request_body
            .send_data(Bytes::from(wire), end_stream)
            .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(2), response_body.data())
            .await
            .expect("invalid capsule did not reset its stream")
            .expect("invalid capsule ended without a reset")
            .unwrap_err();
        assert_eq!(error.reason(), Some(h2::Reason::PROTOCOL_ERROR));
        let mut received = [0; LIMIT + 9];
        assert_eq!(
            target.try_recv_from(&mut received).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "invalid capsule reached the UDP target"
        );
    }

    // Bad streams must not poison the connection. Unknown Context IDs still
    // get ignored, even at the wire-size limit, before a valid packet follows.
    let (response, mut request_body) = client
        .send_request(udp_request(target.local_addr().unwrap()), false)
        .unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut response_body = response.into_body();
    let mut context = context_zero(8);
    context[7] = 1;
    let mut wire = datagram_capsule(&context, &[0x55; LIMIT]);
    let payload = [0x77; LIMIT];
    wire.extend(datagram_capsule(&context_zero(8), &payload));
    request_body.send_data(Bytes::from(wire), false).unwrap();
    assert_echo(&target, &mut response_body, &payload).await;

    request_body.send_data(Bytes::new(), true).unwrap();
    server_task.abort();
    driver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_unknown_udp_capsules_are_skipped_across_flow_control_windows() {
    let files = TestFiles::new();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut config = http2_config(&files);
    config.http2.max_datagram_size = 1200;
    config.http2.initial_stream_window = 4096;
    let (server_addr, server_task) = spawn_http2_config(config).await;
    let (mut client, driver) = connect_h2(server_addr).await;
    let (response, mut request_body) = client
        .send_request(udp_request(target.local_addr().unwrap()), false)
        .unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut response_body = response.into_body();

    for marker in [0x55, 0x77] {
        let payload = [marker; 1200];
        let wire = wire_fixtures::ignored_capsules_then_datagram(&payload);
        // Fragment the type/length header byte-by-byte, then split values and
        // capsule boundaries across DATA frames and many receive windows.
        for chunk in wire[..16].chunks(1).chain(wire[16..].chunks(997)) {
            request_body
                .send_data(Bytes::copy_from_slice(chunk), false)
                .unwrap();
        }
        assert_echo(&target, &mut response_body, &payload).await;
    }
    request_body.send_data(Bytes::new(), true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(data) = response_body.data().await {
            assert!(
                data.expect("complete skipped capsules must allow a clean FIN")
                    .is_empty()
            );
        }
    })
    .await
    .expect("complete capsule stream did not finish");
    server_task.abort();
    driver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn truncated_skipped_udp_capsules_reset_only_the_affected_stream() {
    let files = TestFiles::new();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (server_addr, server_task) = spawn_http2_config(http2_config(&files)).await;
    let (mut client, driver) = connect_h2(server_addr).await;

    for wire in wire_fixtures::truncated_capsules() {
        let (response, mut request_body) = client
            .send_request(udp_request(target.local_addr().unwrap()), false)
            .unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut response_body = response.into_body();
        for byte in wire {
            request_body
                .send_data(Bytes::from(vec![byte]), false)
                .unwrap();
        }
        request_body.send_data(Bytes::new(), true).unwrap();
        let error = tokio::time::timeout(Duration::from_secs(2), response_body.data())
            .await
            .expect("truncated capsule did not reset its stream")
            .expect("truncated capsule ended without a reset")
            .unwrap_err();
        assert_eq!(error.reason(), Some(h2::Reason::PROTOCOL_ERROR));
    }

    let (response, mut request_body) = client
        .send_request(udp_request(target.local_addr().unwrap()), false)
        .unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut response_body = response.into_body();
    request_body
        .send_data(Bytes::from(datagram_capsule(&[0], b"still usable")), false)
        .unwrap();
    assert_echo(&target, &mut response_body, b"still usable").await;
    server_task.abort();
    driver.abort();
}
