//! Reliable upload backpressure through real QUIC, HTTP/3 and TCP sockets.

use super::*;
use std::io::{Read, Write};

fn open_tcp(client: &mut Client, target: SocketAddr) -> u64 {
    let authority = target.to_string();
    client
        .h3
        .as_mut()
        .unwrap()
        .send_request(
            &mut client.quic,
            &[
                quiche::h3::Header::new(b":method", b"CONNECT"),
                quiche::h3::Header::new(b":authority", authority.as_bytes()),
            ],
            false,
        )
        .unwrap()
}

fn poll_upload(client: &mut Client, stream: u64, response: &mut Vec<u8>) -> bool {
    let mut finished = false;
    loop {
        match client.h3.as_mut().unwrap().poll(&mut client.quic) {
            Ok((id, quiche::h3::Event::Reset(code))) => panic!("stream {id} reset: {code}"),
            Ok((id, quiche::h3::Event::Headers { list, .. })) if id == stream => {
                assert!(
                    list.iter()
                        .any(|h| h.name() == b":status" && h.value() == b"200")
                );
            }
            Ok((id, quiche::h3::Event::Data)) if id == stream => {
                let mut buffer = [0; 4096];
                while let Ok(len) =
                    client
                        .h3
                        .as_mut()
                        .unwrap()
                        .recv_body(&mut client.quic, stream, &mut buffer)
                {
                    response.extend_from_slice(&buffer[..len]);
                }
            }
            Ok((id, quiche::h3::Event::Finished)) if id == stream => finished = true,
            Ok(_) => {}
            Err(quiche::h3::Error::Done) => break,
            Err(error) => panic!("HTTP/3 upload poll: {error}"),
        }
    }
    finished
}

fn send_upload(client: &mut Client, stream: u64, payload: &[u8], sent: &mut usize) {
    if *sent == payload.len() {
        return;
    }
    let end = (*sent + 64 * 1024).min(payload.len());
    match client.h3.as_mut().unwrap().send_body(
        &mut client.quic,
        stream,
        &payload[*sent..end],
        end == payload.len(),
    ) {
        Ok(len) => *sent += len,
        Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => {}
        Err(error) => panic!("HTTP/3 upload write: {error}"),
    }
}

fn upload_resumes_after_pressure(pending: bool, target_half_closed: bool, empty_frame: bool) {
    let dir = TempDir::new("tcp-upload-backpressure");
    let key = p256_key();
    let (cert, key) = write_pem(
        dir.path(),
        "server",
        &key,
        &self_signed(&key, Some("server")),
    );
    let target = std::net::TcpListener::bind(ephemeral_addr()).unwrap();
    // Bound the target's receive window before the SYN exchange. This makes
    // pressure independent of the host's receive-buffer auto-tuning ceiling.
    socket2::SockRef::from(&target)
        .set_recv_buffer_size(64 * 1024)
        .unwrap();
    let target_addr = target.local_addr().unwrap();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (received_tx, received_rx) = std::sync::mpsc::channel();
    let target_thread = std::thread::spawn(move || {
        let (mut socket, _) = target.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        if target_half_closed {
            socket.shutdown(std::net::Shutdown::Write).unwrap();
        }
        if release_rx.recv_timeout(Duration::from_secs(15)).is_err() {
            return;
        }
        let mut received = Vec::new();
        socket.read_to_end(&mut received).unwrap();
        if !target_half_closed {
            socket.write_all(b"upload complete").unwrap();
        }
        received_tx.send(received).unwrap();
    });
    let mut config = ServerConfig::default();
    config.tls.cert_path = cert;
    config.tls.key_path = key;
    config.listeners[0].listen_addr = ephemeral_addr();
    // Exercise writer/shard wakeup races on Linux's multithreaded shard
    // runtime while retaining portable single-shard coverage elsewhere.
    config.listeners[0].shards = if cfg!(target_os = "linux") && !pending {
        2
    } else {
        1
    };
    config.listeners[0].auth.enabled = false;
    config.ip_proxy.enabled = false;
    config.tcp_proxy.allow_targets = vec!["127.0.0.0/8".into()];
    config.tcp_proxy.deny_targets.clear();
    config.quic.initial_max_stream_data = if pending { 4 * 1024 * 1024 } else { 256 * 1024 };
    config.quic.max_stream_window = config.quic.initial_max_stream_data;
    let peer = spawn_server(config)[0];
    let mut client = Client::connect_with_windows(
        peer,
        None,
        None,
        false,
        "127.0.0.1".parse().unwrap(),
        true,
        262_144,
        if pending { 8192 } else { 1024 * 1024 },
    )
    .unwrap();
    client
        .socket
        .set_read_timeout(Some(Duration::from_millis(1)))
        .unwrap();
    client.handshake(Duration::from_secs(5)).unwrap();
    client.init_h3().unwrap();

    // Exhaust connection response credit, keeping the upload in its pending
    // CONNECT state until we consume this unrelated response below.
    let bulk = if pending {
        let bulk_target = std::net::TcpListener::bind(ephemeral_addr()).unwrap();
        let bulk_addr = bulk_target.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut socket, _) = bulk_target.accept().unwrap();
            socket.write_all(&[0x42; 8192]).unwrap();
        });
        let bulk = open_tcp(&mut client, bulk_addr);
        client.flush().unwrap();
        assert_eq!(
            client
                .response_status(bulk, Duration::from_secs(5))
                .unwrap(),
            200
        );
        let until = Instant::now() + Duration::from_millis(200);
        while Instant::now() < until {
            client.drive().unwrap();
        }
        Some(bulk)
    } else {
        None
    };
    let stream = open_tcp(&mut client, target_addr);
    client.flush().unwrap();
    if !pending {
        assert_eq!(
            client
                .response_status(stream, Duration::from_secs(5))
                .unwrap(),
            200
        );
    }
    let upload_size = if pending { 2 } else { 8 } * 1024 * 1024;
    let payload: Vec<u8> = (0..upload_size).map(|i| (i % 251) as u8).collect();
    let mut sent = 0;
    let mut injected_empty = 0;
    let mut response = Vec::new();
    let mut response_finished = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut progressed = Instant::now();
    loop {
        let before = sent;
        if empty_frame && injected_empty < 512 && sent >= 1536 * 1024 {
            // send_body deliberately suppresses non-FIN empty DATA, so insert
            // 256 valid empty frames between complete DATA frames directly.
            let empty_frames = [0; 512];
            match client
                .quic
                .stream_send(stream, &empty_frames[injected_empty..], false)
            {
                Ok(len) => injected_empty += len,
                Err(quiche::Error::Done) => {}
                Err(error) => panic!("empty DATA write: {error}"),
            }
        } else {
            send_upload(&mut client, stream, &payload, &mut sent);
        }
        client.drive().unwrap();
        response_finished |= poll_upload(&mut client, stream, &mut response);
        if sent != before {
            progressed = Instant::now();
        } else if progressed.elapsed() > Duration::from_millis(200) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "upload never reached backpressure"
        );
        if !pending {
            assert!(
                sent < payload.len(),
                "target must stall before consuming the upload"
            );
        }
    }
    assert!(
        sent >= 1024 * 1024,
        "must fill the application upload budget"
    );
    if pending {
        assert_eq!(
            sent,
            payload.len(),
            "FIN must already be buffered before CONNECT resumes"
        );
    } else {
        assert!(
            sent < payload.len(),
            "upload must be flow-controlled, not fully buffered"
        );
        // A stalled upload must not block another stream on the same shard
        // and connection. Verify a complete independent tunnel before release.
        let other = std::net::TcpListener::bind(ephemeral_addr()).unwrap();
        let other_addr = other.local_addr().unwrap();
        let sibling_target = std::thread::spawn(move || {
            let (mut socket, _) = other.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            socket.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"sibling");
            socket.write_all(&request).unwrap();
        });
        let sibling = open_tcp(&mut client, other_addr);
        client.flush().unwrap();
        assert_eq!(
            client
                .response_status(sibling, Duration::from_secs(5))
                .unwrap(),
            200
        );
        client
            .h3
            .as_mut()
            .unwrap()
            .send_body(&mut client.quic, sibling, b"sibling", true)
            .unwrap();
        let mut echoed = Vec::new();
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            client.drive().unwrap();
            if poll_upload(&mut client, sibling, &mut echoed) {
                break;
            }
            assert!(Instant::now() < until, "stalled upload blocked its sibling");
        }
        assert_eq!(echoed, b"sibling");
        sibling_target.join().unwrap();
    }

    // No new upload event is required for already-buffered data: the target
    // writer and pending-response retry must wake the shard on capacity return.
    if empty_frame {
        let mut buffer = [0; 16384];
        while client
            .h3
            .as_mut()
            .unwrap()
            .recv_body(&mut client.quic, bulk.unwrap(), &mut buffer)
            .is_ok()
        {}
        // Grant response credit once, then send no packets at all. Parsing
        // 256 buffered empty DATA frames and FIN must finish on local wakes.
        client.flush().unwrap();
    }
    release_tx.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut received = None;
    while Instant::now() < deadline {
        if let Some(bulk) = bulk {
            let mut buffer = [0; 16384];
            while client
                .h3
                .as_mut()
                .unwrap()
                .recv_body(&mut client.quic, bulk, &mut buffer)
                .is_ok()
            {}
        }
        send_upload(&mut client, stream, &payload, &mut sent);
        if empty_frame {
            client.recv_once().unwrap();
        } else {
            client.drive().unwrap();
        }
        response_finished |= poll_upload(&mut client, stream, &mut response);
        if received.is_none() {
            received = received_rx.try_recv().ok();
        }
        if sent == payload.len() && received.is_some() && response_finished {
            break;
        }
    }
    assert_eq!(sent, payload.len(), "upload did not resume");
    assert_eq!(
        received.as_deref(),
        Some(payload.as_slice()),
        "target must receive every byte before FIN"
    );
    assert!(response_finished, "response EOF must propagate");
    if !target_half_closed {
        assert_eq!(response, b"upload complete");
    }
    target_thread.join().unwrap();
}

#[test]
fn slow_target_upload_resumes_without_reset() {
    upload_resumes_after_pressure(false, false, false);
}

#[test]
fn pending_connect_upload_resumes_without_reset() {
    upload_resumes_after_pressure(true, false, false);
}

#[test]
fn half_closed_target_receives_entire_backpressured_upload() {
    upload_resumes_after_pressure(false, true, false);
}

#[test]
fn pending_upload_resumes_across_empty_data_frame() {
    upload_resumes_after_pressure(true, false, true);
}
