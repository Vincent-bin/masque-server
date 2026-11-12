use anyhow::{Result, anyhow, bail, ensure};
use futures_util::StreamExt;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::{net::UdpSocket, sync::oneshot, task::JoinHandle, time::Instant};
use tokio_quiche::{
    ApplicationOverQuic, ConnectionIdGenerator, ConnectionParams, QuicResult, ServerH3Controller,
    ServerH3Driver,
    http3::{
        driver::{IncomingH3Headers, ServerH3Event},
        settings::Http3Settings,
    },
    metrics::{DefaultMetrics, Metrics},
    quic::{ConnectionHook, HandshakeInfo, QuicheConnection},
    settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths},
    socket::QuicListener,
};

use crate::{
    client::{Client, DEADLINE},
    identity::Identity,
};

struct Cids(usize);
impl ConnectionIdGenerator<'static> for Cids {
    #[cfg(feature = "upstream-patch")]
    fn connection_id_len(&self) -> usize {
        self.0
    }

    fn new_connection_id(&self) -> quiche::ConnectionId<'static> {
        let mut bytes = vec![0; self.0];
        boring::rand::rand_bytes(&mut bytes).expect("test RNG");
        quiche::ConnectionId::from_vec(bytes)
    }
    fn verify_connection_id(&self, cid: &quiche::ConnectionId<'_>) -> QuicResult<()> {
        if cid.len() != self.0 {
            return Err("unexpected CID length".into());
        }
        Ok(())
    }
}

/// Observe arrival before the H3 driver consumes the native DATAGRAM queue.
/// This supplies an ordering barrier without timing-dependent network sleeps.
struct ObservedDriver {
    inner: ServerH3Driver,
    datagrams: Arc<AtomicUsize>,
}

fn driver(datagrams: Arc<AtomicUsize>) -> (ObservedDriver, ServerH3Controller) {
    let mut h3 = Http3Settings::default();
    h3.enable_extended_connect = true;
    h3.max_header_list_size = Some(8192);
    #[cfg(feature = "upstream-patch")]
    {
        h3.preserve_stream_directions = true;
        h3.discard_unknown_datagrams = true;
        h3.discard_datagrams_after_read_fin = true;
        h3.suppress_body_progress_events = true;
    }
    let (inner, controller) = ServerH3Driver::new(h3);
    (ObservedDriver { inner, datagrams }, controller)
}

struct PreparedTlsHook {
    context: Mutex<Option<boring::ssl::SslContextBuilder>>,
    calls: Arc<AtomicUsize>,
}
impl ConnectionHook for PreparedTlsHook {
    fn create_custom_ssl_context_builder(
        &self,
        _: TlsCertificatePaths<'_>,
    ) -> Option<boring::ssl::SslContextBuilder> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        // This test creates exactly one listener. Production must provide a
        // prepared context for every socket and fail before bind on errors.
        self.context.lock().unwrap().take()
    }
}
impl ApplicationOverQuic for ObservedDriver {
    fn on_conn_established(
        &mut self,
        q: &mut QuicheConnection,
        h: &HandshakeInfo,
    ) -> QuicResult<()> {
        self.inner.on_conn_established(q, h)
    }
    fn should_act(&self) -> bool {
        self.inner.should_act()
    }
    async fn wait_for_data(&mut self, q: &mut QuicheConnection) -> QuicResult<()> {
        self.inner.wait_for_data(q).await
    }
    fn process_reads(&mut self, q: &mut QuicheConnection) -> QuicResult<()> {
        self.datagrams
            .fetch_add(q.dgram_recv_queue_len(), Ordering::SeqCst);
        self.inner.process_reads(q)
    }
    fn process_writes(&mut self, q: &mut QuicheConnection) -> QuicResult<()> {
        self.inner.process_writes(q)
    }
    fn on_conn_close<M: Metrics>(&mut self, q: &mut QuicheConnection, m: &M, r: &QuicResult<()>) {
        self.inner.on_conn_close(q, m, r);
    }
}

/// Exactly one listener and one test connection, living only inside this process.
pub struct Pair {
    pub client: Client,
    pub controller: ServerH3Controller,
    pub datagrams: Arc<AtomicUsize>,
    pub worker_stopped: Arc<AtomicBool>,
    pub tls_hook_calls: Arc<AtomicUsize>,
    listener: JoinHandle<()>,
    _identity: Identity,
}

impl Pair {
    pub async fn new(cid_len: usize) -> Result<Self> {
        Self::new_with_tls_hook(cid_len, false).await
    }

    pub async fn new_with_tls_hook(cid_len: usize, custom_tls: bool) -> Result<Self> {
        Self::new_with_options(cid_len, custom_tls, false).await
    }

    pub async fn new_with_retry() -> Result<Self> {
        Self::new_with_options(20, false, true).await
    }

    async fn new_with_options(cid_len: usize, custom_tls: bool, retry: bool) -> Result<Self> {
        let identity = Identity::new()?;
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        let mut listener = QuicListener::try_from(socket)?;
        listener.cid_generator = Arc::new(Cids(cid_len));
        let mut settings = QuicSettings::default();
        settings.disable_client_ip_validation = !retry;
        settings.enable_dgram = true;
        settings.dgram_recv_max_queue_len = 256;
        settings.dgram_send_max_queue_len = 256;
        settings.enable_early_data = false;
        settings.initial_max_data = 1 << 20;
        settings.initial_max_stream_data_bidi_local = 1 << 20;
        settings.initial_max_stream_data_bidi_remote = 1 << 20;
        settings.initial_max_stream_data_uni = 1 << 20;
        settings.initial_max_streams_bidi = 16;
        settings.initial_max_streams_uni = 16;
        settings.max_connection_window = 1 << 20;
        settings.max_stream_window = 1 << 20;
        settings.max_recv_udp_payload_size = 1350;
        settings.max_send_udp_payload_size = 1350;
        settings.listen_backlog = 1;
        settings.handshake_timeout = Some(DEADLINE);
        settings.max_idle_timeout = Some(std::time::Duration::from_secs(5));
        settings.discover_path_mtu = false;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hooks = Hooks::default();
        if custom_tls {
            use boring::ssl::{SslContextBuilder, SslFiletype, SslMethod, SslVersion};
            let mut context = SslContextBuilder::new(SslMethod::tls())?;
            context.set_min_proto_version(Some(SslVersion::TLS1_3))?;
            context.set_max_proto_version(Some(SslVersion::TLS1_3))?;
            context.set_certificate_chain_file(&identity.cert)?;
            context.set_private_key_file(&identity.key, SslFiletype::PEM)?;
            context.check_private_key()?;
            hooks.connection_hook = Some(Arc::new(PreparedTlsHook {
                context: Mutex::new(Some(context)),
                calls: calls.clone(),
            }));
        }
        let params = ConnectionParams::new_server(
            settings,
            TlsCertificatePaths {
                cert: if custom_tls {
                    "unused-custom-context-certificate"
                } else {
                    identity.cert.to_str().unwrap()
                },
                private_key: if custom_tls {
                    "unused-custom-context-key"
                } else {
                    identity.key.to_str().unwrap()
                },
                kind: CertificateKind::X509,
            },
            hooks,
        );
        // Capabilities are explicitly disabled for the portability control.
        let mut listeners =
            tokio_quiche::listen_with_capabilities([listener], params, DefaultMetrics)?;
        let mut stream = listeners.pop().unwrap();
        let (tx, rx) = oneshot::channel();
        let datagrams = Arc::new(AtomicUsize::new(0));
        let counter = datagrams.clone();
        let listener = tokio::spawn(async move {
            if let Some(Ok(conn)) = stream.next().await {
                let (driver, controller) = driver(counter);
                let _connection = conn.start(driver);
                let _ = tx.send(controller);
                // Keep the accept receiver/socket alive. Runtime teardown kills
                // every library task; each observation gets its own process.
                std::future::pending::<()>().await;
            }
        });
        let result = async {
            let mut client = Client::new(addr, &identity).await?;
            client.handshake().await?;
            let controller = tokio::time::timeout(DEADLINE, rx).await??;
            Ok::<_, anyhow::Error>((client, controller))
        }
        .await;
        match result {
            Ok((client, controller)) => Ok(Self {
                client,
                controller,
                datagrams,
                worker_stopped: Arc::new(AtomicBool::new(false)),
                tls_hook_calls: calls,
                listener,
                _identity: identity,
            }),
            Err(e) => {
                listener.abort();
                Err(e)
            }
        }
    }

    /// Public raw API feasibility control. One connection, no Retry/admission
    /// policy or migration: this is not an alternative production router.
    pub async fn new_raw() -> Result<Self> {
        use tokio_quiche::{
            quic::{Incoming, raw::wrap_quiche_conn},
            socket::Socket,
        };
        let identity = Identity::new()?;
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let addr = socket.local_addr()?;
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        config.load_cert_chain_from_pem_file(identity.cert.to_str().unwrap())?;
        config.load_priv_key_from_pem_file(identity.key.to_str().unwrap())?;
        config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
        config.set_initial_max_data(1 << 20);
        config.set_initial_max_stream_data_bidi_remote(1 << 20);
        config.set_initial_max_stream_data_uni(1 << 20);
        config.set_initial_max_streams_bidi(16);
        config.set_initial_max_streams_uni(16);
        config.set_max_idle_timeout(5_000);
        config.set_max_send_udp_payload_size(1350);
        config.enable_dgram(true, 256, 256);
        let (tx, rx) = oneshot::channel();
        let datagrams = Arc::new(AtomicUsize::new(0));
        let counter = datagrams.clone();
        let stopped = Arc::new(AtomicBool::new(false));
        let stopped_signal = stopped.clone();
        let listener = tokio::spawn(async move {
            let mut packet = vec![0; 65_535];
            let (n, peer) = socket.recv_from(&mut packet).await.unwrap();
            let header = quiche::Header::from_slice(&mut packet[..n], 16).unwrap();
            assert_eq!(header.ty, quiche::Type::Initial);
            let initial_dcid = header.dcid.into_owned();
            let scid = Cids(16).new_connection_id();
            let qconn =
                quiche::accept_with_buf_factory(&scid, None, addr, peer, &mut config).unwrap();
            let wrapped = wrap_quiche_conn(
                qconn,
                Socket {
                    send: socket.clone(),
                    recv: (),
                    local_addr: addr,
                    peer_addr: peer,
                    capabilities: Default::default(),
                },
                DefaultMetrics,
            );
            let incoming = |buf: Vec<u8>, peer_addr| Incoming {
                buf,
                peer_addr,
                local_addr: addr,
                gro: None,
                rx_time: None,
                #[cfg(target_os = "linux")]
                so_mark_data: None,
            };
            wrapped
                .incoming_tx
                .try_send(incoming(packet[..n].to_vec(), peer))
                .unwrap();
            let (driver, controller) = driver(counter);
            let _connection = wrapped.conn.start(driver);
            let mut shutdown = wrapped.worker_shutdown_rx;
            let mut close = wrapped.conn_close_rx;
            let _ = tx.send(controller);
            let mut saw_close = false;
            loop {
                tokio::select! {
                    _ = close.recv(), if !saw_close => { saw_close = true; }
                    _ = shutdown.recv() => {
                        stopped_signal.store(true, Ordering::SeqCst);
                        break;
                    }
                    received = socket.recv_from(&mut packet) => {
                        let (n, from) = received.unwrap();
                        if from != peer { continue; }
                        let Ok(header) = quiche::Header::from_slice(&mut packet[..n], 16) else {continue};
                        if header.dcid != scid && header.dcid != initial_dcid {continue}
                        let _ = wrapped.incoming_tx.try_send(incoming(packet[..n].to_vec(),from));
                    }
                }
            }
        });
        let result = async {
            let mut client = Client::new(addr, &identity).await?;
            client.handshake().await?;
            let controller = tokio::time::timeout(DEADLINE, rx).await??;
            Ok::<_, anyhow::Error>((client, controller))
        }
        .await;
        match result {
            Ok((client, controller)) => Ok(Self {
                client,
                controller,
                datagrams,
                listener,
                _identity: identity,
                worker_stopped: stopped,
                tls_hook_calls: Arc::new(AtomicUsize::new(0)),
            }),
            Err(error) => {
                listener.abort();
                Err(error)
            }
        }
    }

    pub async fn headers(
        &mut self,
        protocol: Option<&[u8]>,
        fin: bool,
    ) -> Result<IncomingH3Headers> {
        let id = self.client.request(protocol, fin)?;
        let end = Instant::now() + DEADLINE;
        loop {
            ensure!(Instant::now() < end, "request headers deadline");
            self.client.pump().await?;
            while let Ok(event) = self.controller.event_receiver_mut().try_recv() {
                if let ServerH3Event::Headers {
                    incoming_headers, ..
                } = event
                {
                    ensure!(incoming_headers.stream_id == id, "wrong request stream");
                    return Ok(incoming_headers);
                }
            }
        }
    }

    pub async fn barrier(&mut self) -> Result<()> {
        let (tx, mut rx) = oneshot::channel();
        self.controller
            .cmd_sender()
            .send(tokio_quiche::quic::QuicCommand::Custom(Box::new(
                move |_| {
                    let _ = tx.send(());
                },
            )))
            .map_err(|_| anyhow!("driver command channel closed"))?;
        let end = Instant::now() + DEADLINE;
        loop {
            match rx.try_recv() {
                Ok(()) => return Ok(()),
                Err(oneshot::error::TryRecvError::Closed) => bail!("driver closed before barrier"),
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
            ensure!(Instant::now() < end, "driver barrier deadline");
            self.client.pump().await?;
        }
    }

    pub async fn stream_readable(&mut self, stream_id: u64) -> Result<bool> {
        let (tx, mut rx) = oneshot::channel();
        self.controller
            .cmd_sender()
            .send(tokio_quiche::quic::QuicCommand::Custom(Box::new(
                move |q| {
                    let _ = tx.send(q.stream_readable(stream_id));
                },
            )))
            .map_err(|_| anyhow!("driver command channel closed"))?;
        let end = Instant::now() + DEADLINE;
        loop {
            match rx.try_recv() {
                Ok(readable) => return Ok(readable),
                Err(oneshot::error::TryRecvError::Closed) => {
                    bail!("driver closed before inspection")
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
            ensure!(Instant::now() < end, "driver inspection deadline");
            self.client.pump().await?;
        }
    }

    pub async fn datagram(&mut self, bytes: &[u8]) -> Result<()> {
        let before = self.datagrams.load(Ordering::SeqCst);
        self.client.quic.dgram_send(bytes)?;
        let end = Instant::now() + DEADLINE;
        while self.datagrams.load(Ordering::SeqCst) == before {
            ensure!(Instant::now() < end, "datagram arrival deadline");
            self.client.pump().await?;
        }
        Ok(())
    }

    pub async fn receive_body(&mut self, request: &mut IncomingH3Headers) -> Result<(usize, bool)> {
        let end = Instant::now() + DEADLINE;
        loop {
            match request.recv.try_recv() {
                Ok(tokio_quiche::http3::driver::InboundFrame::Body(bytes, fin)) => {
                    return Ok((bytes.len(), fin));
                }
                Ok(_) => bail!("datagram on body channel"),
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    return Err(anyhow!("body channel closed"));
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
            }
            ensure!(Instant::now() < end, "body deadline");
            self.client.pump().await?;
        }
    }
}
impl Drop for Pair {
    fn drop(&mut self) {
        self.listener.abort();
    }
}
