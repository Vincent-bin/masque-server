//! Disposable single-connection, raw QUIC comparison (no HTTP/3 or MASQUE).
mod quiche_backend;
mod quinn_backend;

use anyhow::{Context, Result, ensure};
use clap::{Parser, ValueEnum};
use hdrhistogram::Histogram;
use std::{
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant},
};

const ALPN: &[u8] = b"raw-quic-bench-v1";
const MTU: usize = 1350;
const WINDOW: u64 = 16 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;
const QUEUE: usize = 2048;
const EXPIRY: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Backend {
    Quiche,
    Quinn,
}
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq)]
enum Mode {
    Datagram,
    Stream,
}
#[derive(Parser, Debug)]
struct Args {
    #[arg(long, value_enum)]
    backend: Backend,
    #[arg(long)]
    server: bool,
    #[arg(long, default_value = "127.0.0.1:0")]
    bind: SocketAddr,
    #[arg(long)]
    peer: Option<SocketAddr>,
    #[arg(long)]
    cert: PathBuf,
    #[arg(long)]
    key: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "datagram")]
    mode: Mode,
    #[arg(long, default_value_t = 1200)]
    payload: usize,
    #[arg(long, default_value_t = 256)]
    window: usize,
    #[arg(long, default_value_t = 5.0)]
    seconds: f64,
    #[arg(long, default_value_t = 0)]
    pps: u64,
    #[arg(long, default_value_t = 268435456)]
    bytes: u64,
    #[arg(long, default_value_t = 2097152)]
    socket_buffer: usize,
}

fn cpu_seconds() -> f64 {
    let mut r = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage initializes this correctly aligned writable rusage on success.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, r.as_mut_ptr()) } != 0 {
        return 0.0;
    }
    // SAFETY: the successful syscall above initialized the entire structure.
    let r = unsafe { r.assume_init() };
    (r.ru_utime.tv_sec + r.ru_stime.tv_sec) as f64
        + (r.ru_utime.tv_usec + r.ru_stime.tv_usec) as f64 / 1e6
}

fn open_socket(args: &Args) -> Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(
        Domain::for_address(args.bind),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    socket.set_recv_buffer_size(args.socket_buffer)?;
    socket.set_send_buffer_size(args.socket_buffer)?;
    socket.set_nonblocking(true)?;
    socket.bind(&args.bind.into())?;
    println!(
        "{}",
        serde_json::json!({"event":"socket", "recv_buffer":socket.recv_buffer_size()?, "send_buffer":socket.send_buffer_size()?})
    );
    Ok(socket.into())
}

/// Bounded sequence slots; neither delayed echoes nor loss can grow storage.
struct Load {
    start: Instant,
    end: Instant,
    next_send: Instant,
    next_expire: Instant,
    interval: Option<Duration>,
    slots: Vec<Option<(u64, Instant)>>,
    in_flight: usize,
    sequence: u64,
    sent: u64,
    received: u64,
    invalid: u64,
    rtt: Histogram<u64>,
    payload: Vec<u8>,
}
impl Load {
    fn new(a: &Args) -> Self {
        let now = Instant::now();
        Self {
            start: now,
            end: now + Duration::from_secs_f64(a.seconds),
            next_send: now,
            next_expire: now,
            interval: (a.pps > 0).then(|| Duration::from_secs_f64(1.0 / a.pps as f64)),
            slots: vec![None; a.window],
            in_flight: 0,
            sequence: 0,
            sent: 0,
            received: 0,
            invalid: 0,
            rtt: Histogram::new_with_bounds(1, 10_000_000, 3).unwrap(),
            payload: vec![0x5a; a.payload],
        }
    }
    fn prepare(&mut self) -> Option<&[u8]> {
        let now = Instant::now();
        if now >= self.next_expire {
            for slot in &mut self.slots {
                if slot.is_some_and(|(_, t)| now.duration_since(t) >= EXPIRY) {
                    *slot = None;
                    self.in_flight -= 1;
                }
            }
            self.next_expire = now + Duration::from_millis(10);
        }
        if now >= self.end || now < self.next_send || self.in_flight == self.slots.len() {
            return None;
        }
        while self.slots[self.sequence as usize % self.slots.len()].is_some() {
            self.sequence += 1;
        }
        self.payload[..8].copy_from_slice(&self.sequence.to_be_bytes());
        Some(&self.payload)
    }
    fn committed(&mut self) {
        let now = Instant::now();
        let index = self.sequence as usize % self.slots.len();
        self.slots[index] = Some((self.sequence, now));
        self.sequence += 1;
        self.sent += 1;
        self.in_flight += 1;
        if let Some(interval) = self.interval {
            self.next_send = now + interval;
        }
    }
    fn receive(&mut self, data: &[u8]) {
        if data.len() != self.payload.len() || data.len() < 8 {
            self.invalid += 1;
            return;
        }
        let seq = u64::from_be_bytes(data[..8].try_into().unwrap());
        let index = seq as usize % self.slots.len();
        if let Some((expected, start)) = self.slots[index]
            && expected == seq
        {
            self.slots[index] = None;
            self.in_flight -= 1;
            self.received += 1;
            let _ = self.rtt.record(start.elapsed().as_micros().max(1) as u64);
        }
    }
    fn wake(&self) -> Instant {
        let mut next = self.next_expire.min(self.end + Duration::from_millis(500));
        if self.in_flight < self.slots.len() && Instant::now() < self.end {
            next = next.min(self.next_send);
        }
        next
    }
    fn done(&self) -> bool {
        Instant::now() >= self.end
            && (self.in_flight == 0 || Instant::now() >= self.end + Duration::from_millis(500))
    }
    fn report(&self, a: &Args) {
        println!(
            "{}",
            serde_json::json!({"event":"result", "mode":"datagram", "backend":format!("{:?}",a.backend),
            "seconds":a.seconds,"wall_with_drain":self.start.elapsed().as_secs_f64(),"payload":a.payload,"window":a.window,
            "target_pps":a.pps,"sent":self.sent,"received":self.received,"shortfall":self.sent-self.received,"invalid":self.invalid,
            "goodput_pps":self.received as f64/a.seconds,"goodput_mbps":self.received as f64*a.payload as f64*8.0/a.seconds/1e6,
            "rtt_p50_us":self.rtt.value_at_quantile(0.5),"rtt_p95_us":self.rtt.value_at_quantile(0.95),"rtt_p99_us":self.rtt.value_at_quantile(0.99)})
        );
    }
}

fn report_stream(a: &Args, bytes: u64, start: Instant) -> Result<()> {
    ensure!(bytes == a.bytes, "stream byte count mismatch");
    let seconds = start.elapsed().as_secs_f64();
    println!(
        "{}",
        serde_json::json!({"event":"result","mode":"stream","backend":format!("{:?}",a.backend),"bytes":bytes,"seconds":seconds,"goodput_mbps":bytes as f64*8.0/seconds/1e6})
    );
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let a = Args::parse();
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256];
    provider
        .install_default()
        .map_err(|_| anyhow::anyhow!("TLS provider already installed"))?;
    ensure!((8..=1200).contains(&a.payload), "payload must be 8..1200");
    ensure!((1..=4096).contains(&a.window), "window must be 1..4096");
    ensure!(
        a.seconds.is_finite() && a.seconds > 0.0 && a.seconds <= 30.0,
        "seconds must be 0..30"
    );
    ensure!(
        (1..=4 * 1024 * 1024 * 1024).contains(&a.bytes),
        "bytes out of bounds"
    );
    let cpu = cpu_seconds();
    let wall = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(90), async {
        match a.backend {
            Backend::Quiche => quiche_backend::run(&a).await,
            Backend::Quinn => quinn_backend::run(&a).await,
        }
    })
    .await
    .context("experiment timed out")?;
    println!(
        "{}",
        serde_json::json!({"event":"process","server":a.server,"cpu_seconds":cpu_seconds()-cpu,"wall_seconds":wall.elapsed().as_secs_f64()})
    );
    result
}
