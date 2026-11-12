use super::*;
use std::collections::VecDeque;

pub async fn run(a: &Args) -> Result<()> {
    let socket = tokio::net::UdpSocket::from_std(open_socket(a)?)?;
    let local = socket.local_addr()?;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let cipher_ok = Arc::new(AtomicBool::new(false));
    let observed_cipher = cipher_ok.clone();
    let mut tls = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls())?;
    tls.set_info_callback(move |ssl, mode, _| {
        if mode == boring::ssl::SslInfoCallbackMode::HANDSHAKE_DONE {
            let cipher = ssl.current_cipher().map(|c| c.name()).unwrap_or("unknown");
            observed_cipher.store(cipher == "TLS_AES_128_GCM_SHA256", Ordering::Relaxed);
            println!("{}", serde_json::json!({"event":"tls", "cipher":cipher}));
        }
    });
    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls)?;
    config.set_application_protos(&[ALPN])?;
    config.set_max_idle_timeout(10_000);
    config.set_max_recv_udp_payload_size(MTU);
    config.set_max_send_udp_payload_size(MTU);
    config.set_initial_max_data(WINDOW);
    config.set_initial_max_stream_data_bidi_local(WINDOW);
    config.set_initial_max_stream_data_bidi_remote(WINDOW);
    config.set_max_connection_window(WINDOW);
    config.set_max_stream_window(WINDOW);
    config.set_initial_max_streams_bidi(1);
    config.set_initial_max_streams_uni(0);
    config.set_cc_algorithm_name("cubic")?;
    config.set_initial_congestion_window_packets(10);
    config.enable_pacing(true);
    config.discover_pmtu(false);
    config.enable_dgram(true, QUEUE, QUEUE);
    let mut cid = [0; 16];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut cid)
        .map_err(|_| anyhow::anyhow!("random generation failed"))?;
    let scid = quiche::ConnectionId::from_ref(&cid);
    let mut input = vec![0; 65536];
    let mut connection = if a.server {
        config
            .load_cert_chain_from_pem_file(a.cert.to_str().context("certificate path encoding")?)?;
        config.load_priv_key_from_pem_file(
            a.key
                .as_ref()
                .context("key required")?
                .to_str()
                .context("key path encoding")?,
        )?;
        config.verify_peer(false); // This experiment uses server authentication, not mTLS.
        println!("{}", serde_json::json!({"event":"ready"}));
        let (n, peer) = socket.recv_from(&mut input).await?;
        let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
        conn.recv(
            &mut input[..n],
            quiche::RecvInfo {
                from: peer,
                to: local,
            },
        )?;
        conn
    } else {
        config.load_verify_locations_from_file(
            a.cert.to_str().context("certificate path encoding")?,
        )?;
        config.verify_peer(true);
        quiche::connect(
            Some("localhost"),
            &scid,
            local,
            a.peer.context("peer required")?,
            &mut config,
        )?
    };
    let mut pending: VecDeque<(Vec<u8>, quiche::SendInfo)> = VecDeque::new();
    let mut output = vec![0; MTU];
    let mut app_buffer = vec![0x5a; CHUNK];
    let mut request = Vec::with_capacity(8);
    let mut requested = false;
    let mut stream_left = None;
    let mut stream_start = None;
    let mut stream_received = 0;
    let mut load = None;
    let mut close_at = None;
    let mut echoed = 0u64;
    loop {
        if connection.is_closed() {
            ensure!(
                a.server || close_at.is_some(),
                "connection closed before result"
            );
            break;
        }
        if close_at.is_some_and(|t| Instant::now() >= t) {
            break;
        }
        if connection
            .timeout_instant()
            .is_some_and(|t| t <= Instant::now())
        {
            connection.on_timeout();
        }
        if connection.is_established() && close_at.is_none() {
            ensure!(
                cipher_ok.load(Ordering::Relaxed),
                "cipher must be TLS_AES_128_GCM_SHA256"
            );
            if a.mode == Mode::Datagram {
                if !a.server && load.is_none() {
                    load = Some(Load::new(a));
                }
                for _ in 0..256 {
                    match connection.dgram_recv(&mut app_buffer) {
                        Ok(n) => {
                            if a.server {
                                if connection.dgram_send(&app_buffer[..n]).is_ok() {
                                    echoed += 1;
                                }
                            } else {
                                load.as_mut().unwrap().receive(&app_buffer[..n]);
                            }
                        }
                        Err(quiche::Error::Done) => break,
                        Err(e) => return Err(e.into()),
                    }
                }
                if let Some(load) = &mut load {
                    for _ in 0..32 {
                        let Some(data) = load.prepare() else {
                            break;
                        };
                        match connection.dgram_send(data) {
                            Ok(()) => load.committed(),
                            Err(quiche::Error::Done) => break,
                            Err(e) => return Err(e.into()),
                        }
                    }
                    if load.done() {
                        load.report(a);
                        connection.close(true, 0, b"done")?;
                        close_at = Some(Instant::now() + Duration::from_millis(100));
                    }
                }
            } else {
                if !a.server && !requested {
                    stream_start = Some(Instant::now());
                    ensure!(
                        connection.stream_send(0, &a.bytes.to_be_bytes(), true)? == 8,
                        "partial request"
                    );
                    requested = true;
                }
                for _ in 0..256 {
                    match connection.stream_recv(0, &mut app_buffer) {
                        Ok((n, fin)) => {
                            if a.server {
                                ensure!(request.len() + n <= 8, "oversized request");
                                request.extend_from_slice(&app_buffer[..n]);
                                if fin {
                                    ensure!(request.len() == 8, "short request");
                                    let total = u64::from_be_bytes(request[..].try_into().unwrap());
                                    ensure!(total <= 4 * 1024 * 1024 * 1024, "request too large");
                                    stream_left = Some(total);
                                    app_buffer.fill(0x5a);
                                }
                            } else {
                                stream_received += n as u64;
                                if fin {
                                    report_stream(a, stream_received, stream_start.unwrap())?;
                                    connection.close(true, 0, b"done")?;
                                    close_at = Some(Instant::now() + Duration::from_millis(100));
                                    break;
                                }
                            }
                            if fin {
                                break;
                            }
                        }
                        Err(quiche::Error::Done) | Err(quiche::Error::InvalidStreamState(_)) => {
                            break;
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                if let Some(left) = &mut stream_left {
                    for _ in 0..32 {
                        if *left == 0 {
                            break;
                        }
                        let n = (*left as usize).min(app_buffer.len());
                        match connection.stream_send(0, &app_buffer[..n], *left == n as u64) {
                            Ok(written) => *left -= written as u64,
                            Err(quiche::Error::Done) => break,
                            Err(e) => return Err(e.into()),
                        }
                    }
                }
            }
        }
        // Keep pacing outside recv processing: sleeping for a send must never
        // block incoming ACKs. This queue is capped at 64 packets / 86,400 bytes.
        while pending.len() < 64 {
            match connection.send(&mut output) {
                Ok((n, info)) => pending.push_back((output[..n].to_vec(), info)),
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(e.into()),
            }
        }
        let output_budget_exhausted = pending.len() == 64;
        let mut blocked = false;
        while pending
            .front()
            .is_some_and(|(_, info)| info.at <= Instant::now())
        {
            let (data, info) = pending.front().unwrap();
            match socket.try_send_to(data, info.to) {
                Ok(_) => {
                    pending.pop_front();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    blocked = true;
                    break;
                }
                Err(e) => return Err(e.into()),
            }
        }
        let mut wake = Instant::now() + Duration::from_millis(10);
        if let Some(t) = connection.timeout_instant() {
            wake = wake.min(t);
        }
        if !blocked && let Some((_, info)) = pending.front() {
            wake = wake.min(info.at);
        }
        if let Some(load) = &load
            && close_at.is_none()
        {
            wake = wake.min(load.wake());
        }
        if let Some(t) = close_at {
            wake = wake.min(t);
        }
        // If the application can fill more stream credit, or the packet queue
        // was full, continue driving without adding a millisecond timer gap.
        let more_output = pending.is_empty()
            && (output_budget_exhausted
                || ((connection.send_quantum() > 0)
                    && stream_left.is_some_and(|n| n > 0)
                    && connection.stream_capacity(0).unwrap_or(0) > 0));
        tokio::select! {
            ready=socket.readable()=>{ready?;},
            ready=socket.writable(),if blocked=>{ready?;},
            _=tokio::time::sleep_until(wake.into())=>{},
            _=tokio::task::yield_now(),if more_output=>{},
        }
        for _ in 0..32 {
            match socket.try_recv_from(&mut input) {
                Ok((n, from)) => {
                    match connection.recv(&mut input[..n], quiche::RecvInfo { from, to: local }) {
                        Ok(_) | Err(quiche::Error::Done) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            }
        }
    }
    if a.server && a.mode == Mode::Datagram {
        println!(
            "{}",
            serde_json::json!({"event":"server_datagrams","echoed":echoed})
        );
    }
    let stats = connection.stats();
    println!(
        "{}",
        serde_json::json!({"event":"transport","packets_sent":stats.sent,"packets_recv":stats.recv,"packets_lost":stats.lost})
    );
    Ok(())
}
