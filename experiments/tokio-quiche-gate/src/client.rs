//! Independent quiche HTTP/3 client; deliberately does not use tokio-quiche.
use anyhow::{Result, bail, ensure};
use quiche::h3::{Header, NameValue};
use std::{collections::BTreeMap, net::SocketAddr, time::Duration};
use tokio::{net::UdpSocket, time::Instant};

use crate::identity::Identity;

pub const DEADLINE: Duration = Duration::from_secs(3);
const MTU: usize = 1350;
const WINDOW: u64 = 1 << 20;

#[derive(Default)]
pub struct Response {
    pub status: Option<Vec<u8>>,
    pub body: Vec<u8>,
    pub fin: bool,
    pub reset: Option<u64>,
}

pub struct Client {
    socket: UdpSocket,
    pub quic: quiche::Connection,
    h3: Option<quiche::h3::Connection>,
    pub responses: BTreeMap<u64, Response>,
    pub retry_token: Option<Vec<u8>>,
}

impl Client {
    pub async fn new(peer: SocketAddr, identity: &Identity) -> Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        socket.connect(peer).await?;
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        config.load_verify_locations_from_file(identity.cert.to_str().unwrap())?;
        config.verify_peer(true);
        config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
        config.set_max_idle_timeout(5_000);
        config.set_max_recv_udp_payload_size(MTU);
        config.set_max_send_udp_payload_size(MTU);
        config.set_initial_max_data(WINDOW);
        config.set_initial_max_stream_data_bidi_local(WINDOW);
        config.set_initial_max_stream_data_bidi_remote(WINDOW);
        config.set_initial_max_stream_data_uni(WINDOW);
        config.set_initial_max_streams_bidi(16);
        config.set_initial_max_streams_uni(16);
        config.set_active_connection_id_limit(2);
        config.set_disable_active_migration(false);
        config.enable_dgram(true, 256, 256);
        let mut scid = [0; 20];
        boring::rand::rand_bytes(&mut scid)?;
        let quic = quiche::connect(
            Some("localhost"),
            &quiche::ConnectionId::from_ref(&scid),
            socket.local_addr()?,
            peer,
            &mut config,
        )?;
        Ok(Self {
            socket,
            quic,
            h3: None,
            responses: BTreeMap::new(),
            retry_token: None,
        })
    }

    pub async fn flush(&mut self) -> Result<()> {
        let mut out = [0; MTU];
        loop {
            match self.quic.send(&mut out) {
                Ok((len, info)) => {
                    tokio::time::sleep_until(info.at.into()).await;
                    self.socket.send(&out[..len]).await?;
                }
                Err(quiche::Error::Done) => return Ok(()),
                Err(e) => return Err(e.into()),
            }
        }
    }

    pub async fn pump(&mut self) -> Result<()> {
        self.flush().await?;
        let deadline = self.quic.timeout().map(|d| Instant::now() + d);
        let delay = deadline.map_or(Duration::from_millis(5), |d| {
            d.saturating_duration_since(Instant::now())
                .min(Duration::from_millis(5))
        });
        // Keep the fixed receive capacity off nested async-future stacks.
        let mut packet = vec![0; 65_535];
        match tokio::time::timeout(delay, self.socket.recv(&mut packet)).await {
            Ok(Ok(n)) => {
                if let Ok(header) = quiche::Header::from_slice(&mut packet[..n], 20)
                    && header.ty == quiche::Type::Retry
                {
                    let token = header.token.unwrap_or_default();
                    ensure!(token.len() <= 256, "test Retry token budget");
                    self.retry_token = Some(token);
                }
                let info = quiche::RecvInfo {
                    from: self.socket.peer_addr()?,
                    to: self.socket.local_addr()?,
                };
                match self.quic.recv(&mut packet[..n], info) {
                    Ok(_) | Err(quiche::Error::Done) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                if deadline.is_some_and(|d| Instant::now() >= d) {
                    self.quic.on_timeout();
                }
            }
        }
        if self.quic.is_established() && self.h3.is_none() {
            self.h3 = Some(quiche::h3::Connection::with_transport(
                &mut self.quic,
                &quiche::h3::Config::new()?,
            )?);
        }
        self.poll_h3()?;
        self.flush().await
    }

    fn poll_h3(&mut self) -> Result<()> {
        let Some(h3) = &mut self.h3 else {
            return Ok(());
        };
        loop {
            match h3.poll(&mut self.quic) {
                Ok((id, event)) => {
                    ensure!(
                        self.responses.len() < 16 || self.responses.contains_key(&id),
                        "response budget"
                    );
                    let response = self.responses.entry(id).or_default();
                    match event {
                        quiche::h3::Event::Headers { list, .. } => {
                            response.status = list
                                .iter()
                                .find(|h| h.name() == b":status")
                                .map(|h| h.value().to_vec());
                        }
                        quiche::h3::Event::Data => {
                            let mut body = [0; 4096];
                            loop {
                                match h3.recv_body(&mut self.quic, id, &mut body) {
                                    Ok(n) => {
                                        ensure!(
                                            response.body.len() + n <= 1 << 20,
                                            "response byte budget"
                                        );
                                        response.body.extend_from_slice(&body[..n]);
                                    }
                                    Err(quiche::h3::Error::Done) => break,
                                    Err(quiche::h3::Error::TransportError(
                                        quiche::Error::StreamReset(code),
                                    )) => {
                                        response.reset = Some(code);
                                        break;
                                    }
                                    Err(e) => return Err(e.into()),
                                }
                            }
                        }
                        quiche::h3::Event::Finished => response.fin = true,
                        quiche::h3::Event::Reset(code) => response.reset = Some(code),
                        _ => {}
                    }
                }
                Err(quiche::h3::Error::Done) => break,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    pub async fn handshake(&mut self) -> Result<()> {
        let end = Instant::now() + DEADLINE;
        while Instant::now() < end {
            self.pump().await?;
            if self
                .h3
                .as_ref()
                .is_some_and(|h| h.peer_settings_raw().is_some())
            {
                return Ok(());
            }
            ensure!(!self.quic.is_closed(), "handshake closed");
        }
        bail!("handshake/settings deadline")
    }

    pub fn request(&mut self, protocol: Option<&[u8]>, fin: bool) -> Result<u64> {
        let mut headers = vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b":authority", b"localhost:443"),
        ];
        if let Some(protocol) = protocol {
            headers.extend([
                Header::new(b":protocol", protocol),
                Header::new(b":scheme", b"https"),
                Header::new(b":path", b"/.well-known/masque/udp/localhost/443/"),
            ]);
        }
        Ok(self
            .h3
            .as_mut()
            .unwrap()
            .send_request(&mut self.quic, &headers, fin)?)
    }

    pub fn body(&mut self, id: u64, body: &[u8], fin: bool) -> Result<()> {
        let written = self
            .h3
            .as_mut()
            .unwrap()
            .send_body(&mut self.quic, id, body, fin)?;
        ensure!(written == body.len(), "partial test upload");
        Ok(())
    }

    pub async fn wait_response(&mut self, id: u64) -> Result<bool> {
        let end = Instant::now() + DEADLINE;
        while Instant::now() < end {
            self.pump().await?;
            if self.responses.get(&id).is_some_and(|r| r.fin) {
                return Ok(true);
            }
            if self.quic.is_closed() || self.quic.peer_error().is_some() {
                break;
            }
        }
        Ok(false)
    }
}
