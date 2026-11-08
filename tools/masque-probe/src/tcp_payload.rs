//! Bounded, transport-independent TCP data-plane checks.
use std::collections::VecDeque;
use std::io::{self, Read, Write};

use boring::ssl::{HandshakeError, MidHandshakeSslStream, SslConnector, SslMethod, SslStream};
use ring::rand::SecureRandom as _;

use crate::{TcpMode, report::ProbeFailure};

const MAX_BUFFER: usize = 64 * 1024;

#[derive(Default)]
struct MemoryIo {
    input: VecDeque<u8>,
    output: Vec<u8>,
}

impl Read for MemoryIo {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.input.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let length = output.len().min(self.input.len());
        for byte in &mut output[..length] {
            *byte = self.input.pop_front().unwrap();
        }
        Ok(length)
    }
}

impl Write for MemoryIo {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.output.len() + data.len() > MAX_BUFFER {
            return Err(io::Error::other("TLS probe output limit exceeded"));
        }
        self.output.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

enum TlsState {
    Pending(MidHandshakeSslStream<MemoryIo>),
    Complete(SslStream<MemoryIo>),
}

impl TlsState {
    fn from_result(
        result: Result<SslStream<MemoryIo>, HandshakeError<MemoryIo>>,
    ) -> Result<Self, ProbeFailure> {
        match result {
            Ok(stream) => Ok(Self::Complete(stream)),
            Err(HandshakeError::WouldBlock(stream)) => Ok(Self::Pending(stream)),
            Err(_) => Err(ProbeFailure::new(
                "TCP_TLS_FAILED",
                "target TLS handshake or certificate verification failed through CONNECT",
            )),
        }
    }
    fn io(&mut self) -> &mut MemoryIo {
        match self {
            Self::Pending(stream) => stream.get_mut(),
            Self::Complete(stream) => stream.get_mut(),
        }
    }
}

pub struct TcpExchange {
    tls: Option<TlsState>,
    echo: Vec<u8>,
    echo_received: usize,
    output: Vec<u8>,
}

impl TcpExchange {
    pub fn new(host: &str, mode: TcpMode) -> Result<Self, ProbeFailure> {
        let mut exchange = Self {
            tls: None,
            echo: Vec::new(),
            echo_received: 0,
            output: Vec::new(),
        };
        match mode {
            TcpMode::Tls => {
                let mut connector =
                    SslConnector::builder(SslMethod::tls()).map_err(tls_setup_error)?;
                connector
                    .set_default_verify_paths()
                    .map_err(tls_setup_error)?;
                exchange.tls = Some(TlsState::from_result(
                    connector.build().connect(host, MemoryIo::default()),
                )?);
            }
            TcpMode::Echo => {
                exchange.echo = b"masque-probe-tcp-".to_vec();
                let mut nonce = [0; 32];
                ring::rand::SystemRandom::new()
                    .fill(&mut nonce)
                    .map_err(|_| {
                        ProbeFailure::new("RANDOM_ERROR", "cannot generate probe nonce")
                    })?;
                exchange.echo.extend_from_slice(&nonce);
                exchange.output = exchange.echo.clone();
            }
        }
        Ok(exchange)
    }

    pub fn outgoing(&mut self) -> Vec<u8> {
        if let Some(tls) = &mut self.tls {
            std::mem::take(&mut tls.io().output)
        } else {
            std::mem::take(&mut self.output)
        }
    }

    pub fn receive(&mut self, bytes: &[u8]) -> Result<(), ProbeFailure> {
        if let Some(mut tls) = self.tls.take() {
            if tls.io().input.len() + bytes.len() > MAX_BUFFER {
                return Err(ProbeFailure::new(
                    "TCP_RESPONSE_INVALID",
                    "target TLS response exceeded probe buffer limit",
                ));
            }
            tls.io().input.extend(bytes);
            self.tls = Some(match tls {
                TlsState::Pending(stream) => TlsState::from_result(stream.handshake())?,
                complete => complete,
            });
        } else {
            let end = self.echo_received.saturating_add(bytes.len());
            if self.echo.get(self.echo_received..end) != Some(bytes) {
                return Err(ProbeFailure::new(
                    "TCP_RESPONSE_INVALID",
                    "TCP echo response does not match the random request",
                ));
            }
            self.echo_received = end;
        }
        Ok(())
    }

    pub fn complete(&self) -> bool {
        match &self.tls {
            Some(tls) => matches!(tls, TlsState::Complete(_)),
            None => self.echo_received == self.echo.len(),
        }
    }
}

fn tls_setup_error(_: boring::error::ErrorStack) -> ProbeFailure {
    ProbeFailure::new(
        "TCP_TLS_FAILED",
        "cannot initialize target TLS verification",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::{
        asn1::Asn1Time,
        bn::BigNum,
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        ssl::SslAcceptor,
        x509::{X509Builder, X509NameBuilder},
    };

    #[test]
    fn echo_requires_the_complete_random_payload() {
        let mut exchange = TcpExchange::new("localhost", TcpMode::Echo).unwrap();
        let payload = exchange.outgoing();
        assert!(!exchange.complete());
        exchange.receive(&payload[..3]).unwrap();
        assert!(!exchange.complete());
        exchange.receive(&payload[3..]).unwrap();
        assert!(exchange.complete());
        assert!(exchange.receive(b"extra").is_err());
    }

    #[test]
    fn tls_engine_completes_a_verified_bidirectional_handshake() {
        let key = PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
        )
        .unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "localhost").unwrap();
        let name = name.build();
        let mut certificate = X509Builder::new().unwrap();
        certificate.set_version(2).unwrap();
        certificate
            .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate.sign(&key, MessageDigest::sha256()).unwrap();
        let certificate = certificate.build();
        let mut server = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        server.set_certificate(&certificate).unwrap();
        server.set_private_key(&key).unwrap();
        let mut client = SslConnector::builder(SslMethod::tls()).unwrap();
        client.cert_store_mut().add_cert(certificate).unwrap();
        let mut exchange = TcpExchange {
            tls: Some(
                TlsState::from_result(client.build().connect("localhost", MemoryIo::default()))
                    .unwrap(),
            ),
            echo: Vec::new(),
            echo_received: 0,
            output: Vec::new(),
        };
        let mut server = TlsState::from_result(server.build().accept(MemoryIo::default())).unwrap();
        for _ in 0..20 {
            server.io().input.extend(exchange.outgoing());
            server = match server {
                TlsState::Pending(stream) => TlsState::from_result(stream.handshake()).unwrap(),
                complete => complete,
            };
            let reply = std::mem::take(&mut server.io().output);
            if !reply.is_empty() {
                exchange.receive(&reply).unwrap();
            }
            if exchange.complete() && matches!(server, TlsState::Complete(_)) {
                return;
            }
        }
        panic!("handshake did not complete");
    }
}
