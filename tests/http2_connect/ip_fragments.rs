use super::*;

#[path = "../support/ipv6_fragments.rs"]
mod fragments;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an isolated Linux network namespace and TUN; run tests/connect-ip-fragments.sh"]
async fn ipv6_fragments_reach_udp_target() {
    let files = TestFiles::new();
    let mut config = http2_config(&files);
    fragments::configure(&mut config);
    let (server_addr, server_task) = spawn_http2_config(config).await;
    let target = UdpSocket::bind((fragments::TARGET, 0)).await.unwrap();
    let (mut client, driver) = connect_h2(server_addr).await;
    let (response, mut request_body) = client
        .send_request(connect_ip_request("connect-ip"), false)
        .unwrap();
    let (frames, _response_body) = read_connect_ip_setup(response.await.unwrap()).await;
    let source = fragments::assigned_source(&frames);
    for packet in fragments::packets(source, target.local_addr().unwrap().port()) {
        let mut payload = vec![0]; // RFC 9484 context ID
        payload.extend_from_slice(&packet);
        let mut wire = Vec::new();
        encoder::encode(&CapsuleFrame::Datagram(payload), &mut wire);
        request_body.send_data(Bytes::from(wire), false).unwrap();
    }
    let mut response = [0; 64];
    let (length, peer) =
        tokio::time::timeout(Duration::from_secs(3), target.recv_from(&mut response))
            .await
            .expect("fragmented IPv6 datagram did not reach the UDP target")
            .unwrap();
    assert_eq!(&response[..length], &fragments::PAYLOAD);
    assert_eq!(peer.ip(), source);
    request_body.send_reset(h2::Reason::CANCEL);
    driver.abort();
    server_task.abort();
}
