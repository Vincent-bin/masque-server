//! Loopback-only operational HTTP endpoint.
//!
//! This intentionally implements only the small HTTP/1 subset needed by
//! health probes and Prometheus. Keeping it independent of the HTTP/3 proxy
//! makes health checks useful even when no client can complete a QUIC
//! handshake, and avoids pulling a general-purpose web stack into the server.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::metrics::Metrics;

const MAX_REQUEST_BYTES: usize = 8 * 1024;
const MAX_CONCURRENT_REQUESTS: usize = 32;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) struct ObservabilityServer {
    listener: TcpListener,
    metrics: Arc<Metrics>,
}

impl ObservabilityServer {
    pub(crate) async fn bind(
        addr: std::net::SocketAddr,
        metrics: Arc<Metrics>,
    ) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("failed to bind observability endpoint {addr}"))?;
        Ok(Self { listener, metrics })
    }

    pub(crate) fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    pub(crate) fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move { self.run().await })
    }

    async fn run(self) {
        let addr = self.listener.local_addr().ok();
        info!(?addr, "observability endpoint listening");
        let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS));

        loop {
            let (stream, peer) = match self.listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    warn!(%error, "observability accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let permit = match Arc::clone(&permits).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    debug!(%peer, "observability request limit reached");
                    continue;
                }
            };
            let metrics = Arc::clone(&self.metrics);
            tokio::spawn(async move {
                let result =
                    tokio::time::timeout(REQUEST_TIMEOUT, serve_connection(stream, metrics)).await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => debug!(%peer, %error, "observability request failed"),
                    Err(_) => debug!(%peer, "observability request timed out"),
                }
                drop(permit);
            });
        }
    }
}

async fn serve_connection(mut stream: TcpStream, metrics: Arc<Metrics>) -> std::io::Result<()> {
    let mut request = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        request.extend_from_slice(&chunk[..read]);
        if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n")
            && end + 4 <= MAX_REQUEST_BYTES
        {
            break;
        }
        if request.len() >= MAX_REQUEST_BYTES {
            write_response(
                &mut stream,
                431,
                "text/plain; charset=utf-8",
                "request too large\n",
                false,
            )
            .await?;
            // Keep the socket alive long enough to consume the rest of the
            // header. Closing a TCP socket with unread receive data can turn
            // the intended 431 into ECONNRESET on the client. The outer
            // request timeout and concurrency semaphore keep this bounded.
            drain_oversized_header(&mut stream, &request).await?;
            return Ok(());
        }
    }

    let request = match std::str::from_utf8(&request) {
        Ok(request) => request,
        Err(_) => {
            return write_response(
                &mut stream,
                400,
                "text/plain; charset=utf-8",
                "bad request\n",
                false,
            )
            .await;
        }
    };
    let Some(line) = request.lines().next() else {
        return Ok(());
    };
    let mut parts = line.split_ascii_whitespace();
    let (Some(method), Some(path), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return write_response(
            &mut stream,
            400,
            "text/plain; charset=utf-8",
            "bad request\n",
            false,
        )
        .await;
    };
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return write_response(
            &mut stream,
            400,
            "text/plain; charset=utf-8",
            "bad request\n",
            false,
        )
        .await;
    }
    let head = match method {
        "GET" => false,
        "HEAD" => true,
        _ => {
            return write_response(
                &mut stream,
                405,
                "text/plain; charset=utf-8",
                "method not allowed\n",
                false,
            )
            .await;
        }
    };

    match path.split_once('?').map_or(path, |(path, _)| path) {
        "/healthz" => {
            write_response(&mut stream, 200, "text/plain; charset=utf-8", "ok\n", head).await
        }
        "/readyz" if metrics.is_ready() => {
            write_response(
                &mut stream,
                200,
                "text/plain; charset=utf-8",
                "ready\n",
                head,
            )
            .await
        }
        "/readyz" => {
            write_response(
                &mut stream,
                503,
                "text/plain; charset=utf-8",
                "not ready\n",
                head,
            )
            .await
        }
        "/metrics" => {
            let body = metrics.render();
            write_response(
                &mut stream,
                200,
                "text/plain; version=0.0.4; charset=utf-8",
                &body,
                head,
            )
            .await
        }
        _ => {
            write_response(
                &mut stream,
                404,
                "text/plain; charset=utf-8",
                "not found\n",
                head,
            )
            .await
        }
    }
}

async fn drain_oversized_header(stream: &mut TcpStream, request: &[u8]) -> std::io::Result<()> {
    let mut suffix = request[request.len().saturating_sub(3)..].to_vec();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        suffix.extend_from_slice(&chunk[..read]);
        if suffix.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(());
        }
        let keep_from = suffix.len().saturating_sub(3);
        suffix.drain(..keep_from);
    }
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
    head: bool,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let headers = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    if !head {
        stream.write_all(body.as_bytes()).await?;
    }
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn request(addr: std::net::SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn exposes_health_readiness_and_metrics() {
        let metrics = Arc::new(Metrics::new(true));
        let _ = metrics.register_listener("127.0.0.1:8449".parse().unwrap(), "basic", 1);
        let server =
            ObservabilityServer::bind("127.0.0.1:0".parse().unwrap(), Arc::clone(&metrics))
                .await
                .unwrap();
        let addr = server.local_addr().unwrap();
        let task = server.spawn();

        let health = request(addr, "GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(health.starts_with("HTTP/1.1 200 OK\r\n"));
        let not_ready = request(addr, "GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(not_ready.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));

        metrics.set_ready(true);
        let ready = request(
            addr,
            "GET /readyz?probe=1 HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        assert!(ready.starts_with("HTTP/1.1 200 OK\r\n"));
        let scrape = request(addr, "GET /metrics HTTP/1.0\r\n\r\n").await;
        assert!(scrape.contains("masque_build_info{version="));
        assert!(scrape.contains("masque_server_ready 1"));

        task.abort();
    }

    #[tokio::test]
    async fn rejects_unknown_paths_and_methods() {
        let metrics = Arc::new(Metrics::new(true));
        let server =
            ObservabilityServer::bind("127.0.0.1:0".parse().unwrap(), Arc::clone(&metrics))
                .await
                .unwrap();
        let addr = server.local_addr().unwrap();
        let task = server.spawn();

        let missing = request(addr, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(missing.starts_with("HTTP/1.1 404 Not Found\r\n"));
        let post = request(addr, "POST /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(post.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        let oversized = format!(
            "GET /metrics HTTP/1.1\r\nX-Padding: {}\r\n\r\n",
            "x".repeat(MAX_REQUEST_BYTES)
        );
        let rejected = request(addr, &oversized).await;
        assert!(rejected.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n"));

        task.abort();
    }
}
