use super::*;
use bytes::Bytes;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};

/// Match the quiche harness: ordinary UDP syscalls, no GSO, GRO, ECN or PMTUD.
#[derive(Debug)]
struct PlainSocket(Arc<tokio::net::UdpSocket>);
type Writable = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;
struct Poller {
    socket: Arc<tokio::net::UdpSocket>,
    wait: Option<Writable>,
}
impl std::fmt::Debug for Poller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Poller")
    }
}
impl quinn::UdpPoller for Poller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let s = self.get_mut();
        if s.wait.is_none() {
            let socket = s.socket.clone();
            s.wait = Some(Box::pin(async move { socket.writable().await }));
        }
        let result = s.wait.as_mut().unwrap().as_mut().poll(cx);
        if result.is_ready() {
            s.wait = None;
        }
        result
    }
}
impl quinn::AsyncUdpSocket for PlainSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(Poller {
            socket: self.0.clone(),
            wait: None,
        })
    }
    fn try_send(&self, t: &quinn::udp::Transmit) -> io::Result<()> {
        self.0.try_send_to(t.contents, t.destination).map(|_| ())
    }
    fn poll_recv(
        &self,
        cx: &mut TaskContext<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut count = 0;
        for (buf, meta) in bufs.iter_mut().zip(meta.iter_mut()).take(32) {
            let mut rb = tokio::io::ReadBuf::new(buf);
            match self.0.poll_recv_from(cx, &mut rb) {
                Poll::Ready(Ok(addr)) => {
                    let len = rb.filled().len();
                    *meta = quinn::udp::RecvMeta {
                        addr,
                        len,
                        stride: len,
                        ecn: None,
                        dst_ip: None,
                    };
                    count += 1;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => break,
            }
        }
        if count > 0 {
            Poll::Ready(Ok(count))
        } else {
            Poll::Pending
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

pub async fn run(a: &Args) -> Result<()> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(&a.cert)?))
        .collect::<io::Result<Vec<_>>>()?;
    let mut transport = quinn::TransportConfig::default();
    let mut cubic = quinn::congestion::CubicConfig::default();
    cubic.initial_window(10 * MTU as u64);
    transport
        .congestion_controller_factory(Arc::new(cubic))
        .initial_mtu(MTU as u16)
        .min_mtu(MTU as u16)
        .mtu_discovery_config(None)
        .enable_segmentation_offload(false)
        .receive_window(quinn::VarInt::from_u32(WINDOW as u32))
        .stream_receive_window(quinn::VarInt::from_u32(WINDOW as u32))
        .send_window(WINDOW)
        .max_concurrent_bidi_streams(1u32.into())
        .max_concurrent_uni_streams(0u32.into())
        .datagram_receive_buffer_size(Some(QUEUE * MTU))
        .datagram_send_buffer_size(QUEUE * MTU)
        .max_idle_timeout(Some(Duration::from_secs(10).try_into()?));
    let transport = Arc::new(transport);
    let server = if a.server {
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(
            a.key.as_ref().context("server key required")?,
        )?))?
        .context("empty key")?;
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key)?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        tls.max_early_data_size = 0;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
        ));
        config.transport_config(transport.clone());
        Some(config)
    } else {
        None
    };
    let socket = Arc::new(PlainSocket(Arc::new(tokio::net::UdpSocket::from_std(
        open_socket(a)?,
    )?)));
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        server,
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    if a.server {
        println!("{}", serde_json::json!({"event":"ready"}));
        let incoming = endpoint.accept().await.context("endpoint stopped")?;
        let connection = incoming.await?;
        if a.mode == Mode::Stream {
            let (mut tx, mut rx) = connection.accept_bi().await?;
            let mut request = [0; 8];
            rx.read_exact(&mut request).await?;
            let count = u64::from_be_bytes(request);
            ensure!(
                count <= 4 * 1024 * 1024 * 1024,
                "request exceeds experiment limit"
            );
            let buffer = vec![0x5a; CHUNK];
            let mut left = count;
            while left > 0 {
                let n = (left as usize).min(buffer.len());
                tx.write_all(&buffer[..n]).await?;
                left -= n as u64;
            }
            tx.finish()?;
            connection.closed().await;
        } else {
            let mut echoed = 0u64;
            while let Ok(data) = connection.read_datagram().await {
                // Avoid Quinn's drop-oldest policy; both harnesses drop new work
                // once their outgoing bounded datagram queue is full.
                if connection.datagram_send_buffer_space() >= data.len()
                    && connection.send_datagram(data).is_ok()
                {
                    echoed += 1;
                }
            }
            println!(
                "{}",
                serde_json::json!({"event":"server_datagrams","echoed":echoed})
            );
        }
    } else {
        let mut roots = rustls::RootCertStore::empty();
        for cert in certs {
            roots.add(cert)?;
        }
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![ALPN.to_vec()];
        tls.enable_early_data = false;
        let mut config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
        ));
        config.transport_config(transport);
        endpoint.set_default_client_config(config);
        let connection = endpoint
            .connect(a.peer.context("peer required")?, "localhost")?
            .await?;
        if a.mode == Mode::Stream {
            let start = Instant::now();
            let (mut tx, mut rx) = connection.open_bi().await?;
            tx.write_all(&a.bytes.to_be_bytes()).await?;
            tx.finish()?;
            let mut buf = vec![0; CHUNK];
            let mut count = 0u64;
            while let Some(n) = rx.read(&mut buf).await? {
                count += n as u64;
            }
            report_stream(a, count, start)?;
        } else {
            let mut load = Load::new(a);
            while !load.done() {
                for _ in 0..32 {
                    let Some(data) = load.prepare() else {
                        break;
                    };
                    if connection.datagram_send_buffer_space() < data.len() {
                        break;
                    }
                    connection.send_datagram(Bytes::copy_from_slice(data))?;
                    load.committed();
                }
                // Yield to Quinn's endpoint/connection tasks even at saturation.
                tokio::select! {
                    result=connection.read_datagram()=>load.receive(&result?),
                    _=tokio::time::sleep_until(load.wake().into())=>{},
                }
            }
            load.report(a);
        }
        connection.close(0u32.into(), b"done");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    endpoint.close(0u32.into(), b"done");
    Ok(())
}
