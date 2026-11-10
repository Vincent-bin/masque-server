//! A single timed HTTPS download inside an HTTP/3 CONNECT stream.

use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use boring::ssl::{SslConnector, SslMethod};
use quiche::h3::{Error, Event};

use crate::{Client, HttpDownloadResponse, connect_tcp_headers};

const SECONDS: usize = 10;
const WINDOW: Duration = Duration::from_secs(SECONDS as u64);

struct Tunnel<'a> {
    client: &'a mut Client,
    stream: u64,
    deadline: Instant,
    finished: bool,
}

impl Tunnel<'_> {
    fn receive(&mut self) -> io::Result<()> {
        self.flush()?;
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.client.recv_once(remaining).map_err(io::Error::other)?;
        Ok(())
    }
}

impl Read for Tunnel<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            let h3 = self.client.h3.as_mut().expect("initialized HTTP/3");
            loop {
                match h3.poll(&mut self.client.quic) {
                    Ok((stream, Event::Finished)) if stream == self.stream => self.finished = true,
                    Ok((stream, Event::Reset(code))) if stream == self.stream => {
                        return Err(io::Error::other(format!("CONNECT reset {code}")));
                    }
                    Ok(_) => {}
                    Err(Error::Done) => break,
                    Err(error) => return Err(io::Error::other(error.to_string())),
                }
            }
            match h3.recv_body(&mut self.client.quic, self.stream, buffer) {
                Ok(len) if len > 0 => {
                    self.flush()?;
                    return Ok(len);
                }
                Ok(_) | Err(Error::Done) if self.finished => return Ok(0),
                Ok(_) | Err(Error::Done) => self.receive()?,
                Err(error) => return Err(io::Error::other(error.to_string())),
            }
        }
    }
}

impl Write for Tunnel<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            let h3 = self.client.h3.as_mut().expect("initialized HTTP/3");
            match h3.send_body(&mut self.client.quic, self.stream, bytes, false) {
                Ok(0) | Err(Error::Done | Error::StreamBlocked) => self.receive()?,
                Ok(len) => {
                    self.flush()?;
                    return Ok(len);
                }
                Err(error) => return Err(io::Error::other(error.to_string())),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.client.flush().map_err(io::Error::other)
    }
}

pub(crate) fn run(server: &str, url: &str) -> Result<()> {
    ensure!(!url.contains('#'), "HTTPS URL must not include a fragment");
    let uri: http::Uri = url.parse().context("parse benchmark HTTPS URL")?;
    ensure!(
        uri.scheme_str() == Some("https"),
        "expected an absolute HTTPS URL"
    );
    let authority = uri.authority().context("HTTPS URL has no authority")?;
    let connect_authority = if authority.as_str() == authority.host() {
        format!("{authority}:443")
    } else {
        authority.to_string()
    };
    let target = masque::uri::parse_connect_authority(&connect_authority)
        .context("invalid benchmark HTTPS authority")?;
    let path = uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);

    let path_prefix = if path.starts_with('?') { "/" } else { "" };

    // Use the same explicit trust bundle for the proxy and the HTTPS origin.
    // Client::connect enables certificate verification when this is set.
    let ca = std::env::var_os("MASQUE_BENCH_CA_CERT")
        .context("MASQUE_BENCH_CA_CERT is required for the HTTPS download benchmark")?;
    let mut connector = SslConnector::builder(SslMethod::tls_client())?;
    connector.set_ca_file(ca)?;
    connector.set_alpn_protos(b"\x08http/1.1")?;
    let connector = connector.build();
    let headers = connect_tcp_headers(&connect_authority)?;

    let started = Instant::now();
    let deadline = started + WINDOW;
    let mut client = Client::connect(server)?;
    client.handshake().context("proxy QUIC handshake")?;
    client.h3 = Some(quiche::h3::Connection::with_transport(
        &mut client.quic,
        &quiche::h3::Config::new()?,
    )?);
    let quic_elapsed = started.elapsed();
    let stream = client.send_request(&headers, false)?;
    let (response_stream, status) = client.poll_response(
        deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(5)),
    )?;
    ensure!(
        response_stream == stream && status == 200,
        "proxy CONNECT status {status}"
    );
    let connect_elapsed = started.elapsed();

    let tunnel = Tunnel {
        client: &mut client,
        stream,
        deadline,
        finished: false,
    };
    let mut tls = connector
        .connect(&target.host, tunnel)
        .map_err(|error| anyhow::anyhow!("origin HTTPS handshake: {error}"))?;
    let tls_elapsed = started.elapsed();
    write!(
        tls,
        "GET {path_prefix}{path} HTTP/1.1\r\nHost: {authority}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    )?;
    tls.flush()?;

    let mut response = HttpDownloadResponse::new();
    let mut bins = [0_u64; SECONDS];
    let mut buffer = [0_u8; 64 * 1024];
    let body_complete = loop {
        if Instant::now() >= deadline {
            break false;
        }
        let size = match tls.read(&mut buffer) {
            Ok(0) => anyhow::bail!("origin closed before the full HTTPS body arrived"),
            Ok(size) => size,
            Err(error) if error.kind() == io::ErrorKind::TimedOut && Instant::now() >= deadline => {
                break false;
            }
            Err(error) => return Err(error).context("read HTTPS response"),
        };
        let now = Instant::now();
        let Some(bin) = bins.get_mut(now.duration_since(started).as_secs() as usize) else {
            break false;
        };
        let had_headers = response.header_complete;
        let previous = response.body_bytes;
        response.ingest(&buffer[..size], now)?;
        if !had_headers && response.header_complete {
            ensure!(
                response.status == Some(200),
                "origin HTTP status {:?}",
                response.status
            );
            let header = std::str::from_utf8(&response.header)?;
            ensure!(
                !header
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .any(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding")),
                "HTTPS benchmark requires a response without Transfer-Encoding"
            );
            ensure!(
                response.content_length.is_some(),
                "HTTPS benchmark requires Content-Length"
            );
        }
        *bin += response.body_bytes - previous;
        if let Some(length) = response.content_length {
            ensure!(
                response.body_bytes <= length,
                "HTTPS body exceeded Content-Length"
            );
            if response.body_bytes == length {
                break true;
            }
        }
    };

    let elapsed = started.elapsed().min(WINDOW);
    let first_body = response.first_body_at.context("no HTTPS body arrived")?;
    let first_body_elapsed = first_body.duration_since(started);
    let transfer_elapsed = elapsed.saturating_sub(first_body_elapsed);
    ensure!(!transfer_elapsed.is_zero(), "empty download interval");
    let bytes = response.body_bytes;
    let mbps = |time: Duration| bytes as f64 * 8.0 / time.as_secs_f64() / 1_000_000.0;
    let rtt_ms = tls
        .get_ref()
        .client
        .quic
        .path_stats()
        .find(|path| path.active)
        .map_or(0.0, |path| path.rtt.as_secs_f64() * 1000.0);
    println!(
        "HTTPS_DOWNLOAD_RESULT transport=http3 status=200 body_bytes={bytes} wall_s={:.3} sample_mbps={:.3} transfer_mbps={:.3} quic_ms={:.0} connect_ms={:.0} tls_ms={:.0} first_body_ms={:.0} quic_rtt_ms={rtt_ms:.1} body_complete={body_complete} second_bytes={bins:?}",
        elapsed.as_secs_f64(),
        mbps(elapsed),
        mbps(transfer_elapsed),
        quic_elapsed.as_secs_f64() * 1000.0,
        connect_elapsed.as_secs_f64() * 1000.0,
        tls_elapsed.as_secs_f64() * 1000.0,
        first_body_elapsed.as_secs_f64() * 1000.0,
    );
    Ok(())
}
