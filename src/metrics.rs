//! Lock-free runtime metrics rendered in Prometheus' text exposition format.
//!
//! Packet-path instrumentation is deliberately batch based: one receive or
//! send batch updates a small fixed set of atomics, regardless of how many UDP
//! datagrams it contains. Scraping takes a read lock only over the immutable
//! listener list; shards never take that lock while serving traffic.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const RELAXED: Ordering = Ordering::Relaxed;
/// A shard that has not completed an event-loop round within this interval is
/// not ready. The normal heartbeat is once per second, leaving enough margin
/// for scheduler jitter without hiding a genuinely stuck shard.
const SHARD_STALE_AFTER: Duration = Duration::from_secs(5);

/// Process-wide metrics and readiness state.
pub(crate) struct Metrics {
    enabled: bool,
    ready: AtomicBool,
    started: Instant,
    start_time_seconds: u64,
    listeners: RwLock<Vec<ListenerMetrics>>,
    roster_reload_success: AtomicU64,
    roster_reload_failure: AtomicU64,
    forced_shutdowns: AtomicU64,
}

impl Metrics {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            ready: AtomicBool::new(false),
            started: Instant::now(),
            start_time_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            listeners: RwLock::new(Vec::new()),
            roster_reload_success: AtomicU64::new(0),
            roster_reload_failure: AtomicU64::new(0),
            forced_shutdowns: AtomicU64::new(0),
        }
    }

    /// Register a listener after an ephemeral port, if any, has been resolved.
    ///
    /// Registration finishes before the observability socket starts serving,
    /// so the lock is never taken from a proxy shard's packet path.
    pub(crate) fn register_listener(
        &self,
        addr: SocketAddr,
        auth: &'static str,
        shards: usize,
        udp_gso: bool,
        udp_gro: bool,
    ) -> Vec<Arc<ShardMetrics>> {
        let listener = ListenerMetrics::new(
            addr,
            auth,
            shards,
            udp_gso,
            udp_gro,
            self.enabled,
            self.elapsed_millis(),
        );
        let shard_metrics = listener.shards.clone();
        self.listeners
            .write()
            .expect("metrics listener list poisoned")
            .push(listener);
        shard_metrics
    }

    pub(crate) fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }

    /// Begin draining exactly once, returning whether this call changed state.
    pub(crate) fn begin_shutdown(&self) -> bool {
        self.ready.swap(false, Ordering::AcqRel)
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.is_ready_at(self.elapsed_millis())
    }

    fn is_ready_at(&self, now_millis: u64) -> bool {
        if !self.ready.load(Ordering::Acquire) {
            return false;
        }

        let stale_after = SHARD_STALE_AFTER.as_millis() as u64;
        self.listeners
            .read()
            .expect("metrics listener list poisoned")
            .iter()
            .flat_map(|listener| &listener.shards)
            .all(|shard| {
                now_millis.saturating_sub(shard.last_heartbeat_millis.load(RELAXED)) <= stale_after
            })
    }

    pub(crate) fn elapsed_millis(&self) -> u64 {
        self.started.elapsed().as_millis().min(u64::MAX as u128) as u64
    }

    pub(crate) fn record_roster_reload(&self, success: bool) {
        if !self.enabled {
            return;
        }
        if success {
            self.roster_reload_success.fetch_add(1, RELAXED);
        } else {
            self.roster_reload_failure.fetch_add(1, RELAXED);
        }
    }

    pub(crate) fn record_forced_shutdown(&self) {
        if !self.enabled {
            return;
        }
        // Several shards can hit the same process-wide drain deadline. This
        // metric describes the shutdown event, not the number of late shards.
        self.forced_shutdowns.store(1, RELAXED);
    }

    /// Render a self-contained Prometheus text response.
    pub(crate) fn render(&self) -> String {
        let mut out = String::with_capacity(8 * 1024);
        metric_header(
            &mut out,
            "masque_build_info",
            "Build information for the running MASQUE server.",
            "gauge",
        );
        writeln!(
            out,
            "masque_build_info{{version=\"{}\"}} 1",
            escape_label(env!("CARGO_PKG_VERSION"))
        )
        .unwrap();

        metric_header(
            &mut out,
            "masque_server_ready",
            "Whether proxy startup is complete and every shard heartbeat is current.",
            "gauge",
        );
        writeln!(out, "masque_server_ready {}", u8::from(self.is_ready())).unwrap();

        metric_header(
            &mut out,
            "masque_process_start_time_seconds",
            "Unix timestamp when this process started.",
            "gauge",
        );
        writeln!(
            out,
            "masque_process_start_time_seconds {}",
            self.start_time_seconds
        )
        .unwrap();
        metric_header(
            &mut out,
            "masque_process_uptime_seconds",
            "Elapsed process uptime in seconds.",
            "gauge",
        );
        writeln!(
            out,
            "masque_process_uptime_seconds {:.3}",
            self.started.elapsed().as_secs_f64()
        )
        .unwrap();

        metric_header(
            &mut out,
            "masque_roster_reloads_total",
            "Client-certificate roster reload attempts.",
            "counter",
        );
        writeln!(
            out,
            "masque_roster_reloads_total{{result=\"success\"}} {}",
            self.roster_reload_success.load(RELAXED)
        )
        .unwrap();
        writeln!(
            out,
            "masque_roster_reloads_total{{result=\"failure\"}} {}",
            self.roster_reload_failure.load(RELAXED)
        )
        .unwrap();
        metric_header(
            &mut out,
            "masque_forced_shutdowns_total",
            "Shutdowns that reached the bounded drain deadline.",
            "counter",
        );
        writeln!(
            out,
            "masque_forced_shutdowns_total {}",
            self.forced_shutdowns.load(RELAXED)
        )
        .unwrap();

        let now_millis = self.elapsed_millis();
        let listeners = self
            .listeners
            .read()
            .expect("metrics listener list poisoned");
        render_listener_headers(&mut out);
        for listener in listeners.iter() {
            listener.render(&mut out, now_millis);
        }
        out
    }
}

/// Scrape-side aggregation for one configured listener.
struct ListenerMetrics {
    label: String,
    shards: Vec<Arc<ShardMetrics>>,
}

impl ListenerMetrics {
    fn new(
        addr: SocketAddr,
        auth: &'static str,
        shards: usize,
        udp_gso: bool,
        udp_gro: bool,
        enabled: bool,
        now_millis: u64,
    ) -> Self {
        Self {
            label: format!(
                "listener=\"{}\",auth=\"{}\"",
                escape_label(&addr.to_string()),
                escape_label(auth)
            ),
            shards: (0..shards)
                .map(|_| Arc::new(ShardMetrics::new(enabled, now_millis, udp_gso, udp_gro)))
                .collect(),
        }
    }

    fn sum(&self, field: fn(&ShardMetrics) -> &AtomicU64) -> u64 {
        self.shards
            .iter()
            .map(|shard| field(shard).load(RELAXED))
            .sum()
    }

    fn render(&self, out: &mut String, now_millis: u64) {
        let label = &self.label;
        writeln!(
            out,
            "masque_listener_shards{{{label}}} {}",
            self.shards.len()
        )
        .unwrap();
        writeln!(
            out,
            "masque_quic_udp_gso_enabled{{{label}}} {}",
            u8::from(
                self.shards
                    .iter()
                    .all(|shard| shard.quic_udp_gso_enabled.load(RELAXED))
            )
        )
        .unwrap();
        writeln!(
            out,
            "masque_quic_udp_gro_enabled{{{label}}} {}",
            u8::from(
                self.shards
                    .iter()
                    .all(|shard| shard.quic_udp_gro_enabled.load(RELAXED))
            )
        )
        .unwrap();
        for (index, shard) in self.shards.iter().enumerate() {
            let heartbeat_age = now_millis.saturating_sub(shard.last_heartbeat_millis.load(RELAXED))
                as f64
                / 1_000.0;
            let lag = shard.event_loop_lag_micros.load(RELAXED) as f64 / 1_000_000.0;
            let lag_max = shard.event_loop_lag_max_micros.load(RELAXED) as f64 / 1_000_000.0;
            writeln!(
                out,
                "masque_shard_heartbeat_age_seconds{{{label},shard=\"{index}\"}} {heartbeat_age:.6}"
            )
            .unwrap();
            writeln!(
                out,
                "masque_event_loop_lag_seconds{{{label},shard=\"{index}\"}} {lag:.6}"
            )
            .unwrap();
            writeln!(
                out,
                "masque_event_loop_lag_max_seconds{{{label},shard=\"{index}\"}} {lag_max:.6}"
            )
            .unwrap();
        }
        render_value(
            out,
            "masque_connections_active",
            label,
            self.sum(|shard| &shard.connections_active),
        );
        render_value(
            out,
            "masque_connections_accepted_total",
            label,
            self.sum(|shard| &shard.connections_accepted),
        );
        writeln!(
            out,
            "masque_connections_rejected_total{{{label},reason=\"limit\"}} {}",
            self.sum(|shard| &shard.connections_rejected_limit)
        )
        .unwrap();
        for (name, field) in [
            (
                "masque_quic_receive_batches_total",
                (|shard: &ShardMetrics| &shard.quic_receive_batches)
                    as fn(&ShardMetrics) -> &AtomicU64,
            ),
            ("masque_quic_receive_packets_total", |shard| {
                &shard.quic_receive_packets
            }),
            ("masque_quic_receive_bytes_total", |shard| {
                &shard.quic_receive_bytes
            }),
            ("masque_quic_send_batches_total", |shard| {
                &shard.quic_send_batches
            }),
            ("masque_quic_send_packets_total", |shard| {
                &shard.quic_send_packets
            }),
            ("masque_quic_send_bytes_total", |shard| {
                &shard.quic_send_bytes
            }),
            ("masque_tcp_relay_batches_total", |shard| {
                &shard.tcp_relay_batches
            }),
            ("masque_tcp_relay_events_total", |shard| {
                &shard.tcp_relay_events
            }),
            ("masque_tcp_relay_bytes_total", |shard| {
                &shard.tcp_relay_bytes
            }),
        ] {
            render_value(out, name, label, self.sum(field));
        }
        for (index, protocol) in ["tcp", "udp", "ip"].into_iter().enumerate() {
            let value = self
                .shards
                .iter()
                .map(|shard| shard.tunnels_active[index].load(RELAXED))
                .sum::<u64>();
            writeln!(
                out,
                "masque_tunnels_active{{{label},protocol=\"{protocol}\"}} {value}"
            )
            .unwrap();
        }
        for (result, field) in [
            (
                "success",
                (|shard: &ShardMetrics| &shard.auth_success) as fn(&ShardMetrics) -> &AtomicU64,
            ),
            ("failure", |shard| &shard.auth_failure),
            ("overloaded", |shard| &shard.auth_overloaded),
        ] {
            writeln!(
                out,
                "masque_auth_attempts_total{{{label},result=\"{result}\"}} {}",
                self.sum(field)
            )
            .unwrap();
        }
        render_value(
            out,
            "masque_auth_pending",
            label,
            self.sum(|shard| &shard.auth_pending),
        );
        render_value(
            out,
            "masque_auth_running",
            label,
            self.sum(|shard| &shard.auth_running),
        );
        for (reason, field) in [
            (
                "shard_queue",
                (|shard: &ShardMetrics| &shard.dropped_shard_queue)
                    as fn(&ShardMetrics) -> &AtomicU64,
            ),
            ("datagram_queue", |shard| &shard.dropped_datagram_queue),
            ("tun_queue", |shard| &shard.dropped_tun_queue),
        ] {
            writeln!(
                out,
                "masque_packets_dropped_total{{{label},reason=\"{reason}\"}} {}",
                self.sum(field)
            )
            .unwrap();
        }
    }
}

/// Write-only counters owned by one shard.
///
/// Keeping a separate allocation per shard prevents high-throughput listeners
/// from bouncing one shared atomic cache line between event-loop cores. Only a
/// scrape reads across these allocations.
pub(crate) struct ShardMetrics {
    enabled: bool,
    /// Monotonic process-relative timestamp. Updated once per second even when
    /// Prometheus metrics are disabled because readiness and systemd watchdog
    /// supervision depend on it.
    last_heartbeat_millis: AtomicU64,
    event_loop_lag_micros: AtomicU64,
    event_loop_lag_max_micros: AtomicU64,
    quic_udp_gso_enabled: AtomicBool,
    quic_udp_gro_enabled: AtomicBool,
    connections_active: AtomicU64,
    connections_accepted: AtomicU64,
    connections_rejected_limit: AtomicU64,
    quic_receive_batches: AtomicU64,
    quic_receive_packets: AtomicU64,
    quic_receive_bytes: AtomicU64,
    quic_send_batches: AtomicU64,
    quic_send_packets: AtomicU64,
    quic_send_bytes: AtomicU64,
    tcp_relay_batches: AtomicU64,
    tcp_relay_events: AtomicU64,
    tcp_relay_bytes: AtomicU64,
    tunnels_active: [AtomicU64; 3],
    auth_success: AtomicU64,
    auth_failure: AtomicU64,
    auth_overloaded: AtomicU64,
    auth_pending: AtomicU64,
    auth_running: AtomicU64,
    dropped_shard_queue: AtomicU64,
    dropped_datagram_queue: AtomicU64,
    dropped_tun_queue: AtomicU64,
}

impl ShardMetrics {
    fn new(enabled: bool, now_millis: u64, udp_gso: bool, udp_gro: bool) -> Self {
        Self {
            enabled,
            last_heartbeat_millis: AtomicU64::new(now_millis),
            event_loop_lag_micros: AtomicU64::new(0),
            event_loop_lag_max_micros: AtomicU64::new(0),
            quic_udp_gso_enabled: AtomicBool::new(udp_gso),
            quic_udp_gro_enabled: AtomicBool::new(udp_gro),
            connections_active: AtomicU64::new(0),
            connections_accepted: AtomicU64::new(0),
            connections_rejected_limit: AtomicU64::new(0),
            quic_receive_batches: AtomicU64::new(0),
            quic_receive_packets: AtomicU64::new(0),
            quic_receive_bytes: AtomicU64::new(0),
            quic_send_batches: AtomicU64::new(0),
            quic_send_packets: AtomicU64::new(0),
            quic_send_bytes: AtomicU64::new(0),
            tcp_relay_batches: AtomicU64::new(0),
            tcp_relay_events: AtomicU64::new(0),
            tcp_relay_bytes: AtomicU64::new(0),
            tunnels_active: std::array::from_fn(|_| AtomicU64::new(0)),
            auth_success: AtomicU64::new(0),
            auth_failure: AtomicU64::new(0),
            auth_overloaded: AtomicU64::new(0),
            auth_pending: AtomicU64::new(0),
            auth_running: AtomicU64::new(0),
            dropped_shard_queue: AtomicU64::new(0),
            dropped_datagram_queue: AtomicU64::new(0),
            dropped_tun_queue: AtomicU64::new(0),
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    /// Publish the state accepted by this shard's bound QUIC socket.
    pub(crate) fn set_udp_offload_state(&self, udp_gso: bool, udp_gro: bool) {
        self.quic_udp_gso_enabled.store(udp_gso, RELAXED);
        self.quic_udp_gro_enabled.store(udp_gro, RELAXED);
    }

    /// Reflect the runtime fallback after an external path rejects GSO.
    pub(crate) fn disable_udp_gso(&self) {
        self.quic_udp_gso_enabled.store(false, RELAXED);
    }

    /// Publish liveness once per maintenance interval rather than on every
    /// packet batch, keeping this out of the high-throughput hot path.
    pub(crate) fn record_heartbeat(&self, now_millis: u64, lag: Duration) {
        self.last_heartbeat_millis.store(now_millis, RELAXED);
        if !self.enabled {
            return;
        }

        let lag_micros = lag.as_micros().min(u64::MAX as u128) as u64;
        self.event_loop_lag_micros.store(lag_micros, RELAXED);
        self.event_loop_lag_max_micros
            .fetch_max(lag_micros, RELAXED);
    }

    pub(crate) fn connection_opened(&self) {
        if !self.enabled {
            return;
        }
        self.connections_accepted.fetch_add(1, RELAXED);
        self.connections_active.fetch_add(1, RELAXED);
    }

    pub(crate) fn connection_closed(&self) {
        if !self.enabled {
            return;
        }
        subtract(&self.connections_active, 1);
    }

    pub(crate) fn connection_rejected_limit(&self) {
        if !self.enabled {
            return;
        }
        self.connections_rejected_limit.fetch_add(1, RELAXED);
    }

    #[inline]
    pub(crate) fn record_receive_batch(&self, packets: usize, bytes: usize) {
        if !self.enabled || packets == 0 {
            return;
        }
        self.quic_receive_batches.fetch_add(1, RELAXED);
        self.quic_receive_packets.fetch_add(packets as u64, RELAXED);
        self.quic_receive_bytes.fetch_add(bytes as u64, RELAXED);
    }

    #[inline]
    pub(crate) fn record_send_batch(&self, packets: usize, bytes: usize) {
        if !self.enabled || packets == 0 {
            return;
        }
        self.quic_send_batches.fetch_add(1, RELAXED);
        self.quic_send_packets.fetch_add(packets as u64, RELAXED);
        self.quic_send_bytes.fetch_add(bytes as u64, RELAXED);
    }

    #[inline]
    pub(crate) fn record_tcp_relay_batch(&self, events: usize, bytes: usize) {
        if !self.enabled || events == 0 {
            return;
        }
        self.tcp_relay_batches.fetch_add(1, RELAXED);
        self.tcp_relay_events.fetch_add(events as u64, RELAXED);
        self.tcp_relay_bytes.fetch_add(bytes as u64, RELAXED);
    }

    pub(crate) fn update_tunnels(&self, previous: [usize; 3], current: [usize; 3]) {
        if !self.enabled {
            return;
        }
        for ((metric, old), new) in self.tunnels_active.iter().zip(previous).zip(current) {
            if new >= old {
                metric.fetch_add((new - old) as u64, RELAXED);
            } else {
                subtract(metric, (old - new) as u64);
            }
        }
    }

    pub(crate) fn record_auth_success(&self) {
        if !self.enabled {
            return;
        }
        self.auth_success.fetch_add(1, RELAXED);
    }

    pub(crate) fn record_auth_failure(&self) {
        if !self.enabled {
            return;
        }
        self.auth_failure.fetch_add(1, RELAXED);
    }

    pub(crate) fn record_auth_overloaded(&self) {
        if !self.enabled {
            return;
        }
        self.auth_overloaded.fetch_add(1, RELAXED);
    }

    pub(crate) fn auth_pending_guard(self: &Arc<Self>) -> GaugeGuard {
        GaugeGuard::new(Arc::clone(self), Gauge::AuthPending)
    }

    pub(crate) fn auth_running_guard(self: &Arc<Self>) -> GaugeGuard {
        GaugeGuard::new(Arc::clone(self), Gauge::AuthRunning)
    }

    pub(crate) fn record_shard_queue_drop(&self) {
        if !self.enabled {
            return;
        }
        self.dropped_shard_queue.fetch_add(1, RELAXED);
    }

    pub(crate) fn record_datagram_queue_drop(&self, packets: usize) {
        if !self.enabled || packets == 0 {
            return;
        }
        self.dropped_datagram_queue
            .fetch_add(packets as u64, RELAXED);
    }

    pub(crate) fn record_tun_queue_drop(&self) {
        if !self.enabled {
            return;
        }
        self.dropped_tun_queue.fetch_add(1, RELAXED);
    }
}

#[derive(Clone, Copy)]
enum Gauge {
    AuthPending,
    AuthRunning,
}

/// An async-safe gauge increment. Aborting the task drops the guard and fixes
/// the gauge; no completion branch has to remember a matching decrement.
pub(crate) struct GaugeGuard {
    metrics: Arc<ShardMetrics>,
    gauge: Gauge,
    active: bool,
}

impl GaugeGuard {
    fn new(metrics: Arc<ShardMetrics>, gauge: Gauge) -> Self {
        let active = metrics.enabled;
        if active {
            match gauge {
                Gauge::AuthPending => &metrics.auth_pending,
                Gauge::AuthRunning => &metrics.auth_running,
            }
            .fetch_add(1, RELAXED);
        }
        Self {
            metrics,
            gauge,
            active,
        }
    }
}

impl Drop for GaugeGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let metric = match self.gauge {
            Gauge::AuthPending => &self.metrics.auth_pending,
            Gauge::AuthRunning => &self.metrics.auth_running,
        };
        subtract(metric, 1);
    }
}

fn subtract(metric: &AtomicU64, amount: u64) {
    metric
        .fetch_update(RELAXED, RELAXED, |current| {
            Some(current.saturating_sub(amount))
        })
        .ok();
}

fn render_value(out: &mut String, name: &str, label: &str, value: u64) {
    writeln!(out, "{name}{{{label}}} {value}").unwrap();
}

fn metric_header(out: &mut String, name: &str, help: &str, kind: &str) {
    writeln!(out, "# HELP {name} {help}").unwrap();
    writeln!(out, "# TYPE {name} {kind}").unwrap();
}

fn render_listener_headers(out: &mut String) {
    for (name, help, kind) in [
        (
            "masque_listener_shards",
            "Configured event-loop shards.",
            "gauge",
        ),
        (
            "masque_shard_heartbeat_age_seconds",
            "Seconds since a proxy shard last completed its event-loop heartbeat.",
            "gauge",
        ),
        (
            "masque_quic_udp_gso_enabled",
            "Whether the listener's Linux QUIC send socket is using UDP GSO.",
            "gauge",
        ),
        (
            "masque_quic_udp_gro_enabled",
            "Whether the listener's Linux QUIC receive socket is using UDP GRO.",
            "gauge",
        ),
        (
            "masque_event_loop_lag_seconds",
            "Delay of the latest scheduled proxy-shard heartbeat.",
            "gauge",
        ),
        (
            "masque_event_loop_lag_max_seconds",
            "Largest scheduled proxy-shard heartbeat delay since process start.",
            "gauge",
        ),
        (
            "masque_connections_active",
            "Currently active QUIC connections.",
            "gauge",
        ),
        (
            "masque_connections_accepted_total",
            "Accepted QUIC connections.",
            "counter",
        ),
        (
            "masque_connections_rejected_total",
            "Rejected QUIC connection attempts.",
            "counter",
        ),
        (
            "masque_quic_receive_batches_total",
            "Kernel receive batches containing QUIC packets.",
            "counter",
        ),
        (
            "masque_quic_receive_packets_total",
            "QUIC UDP datagrams received from the network.",
            "counter",
        ),
        (
            "masque_quic_receive_bytes_total",
            "QUIC UDP bytes received from the network.",
            "counter",
        ),
        (
            "masque_quic_send_batches_total",
            "Kernel send batches containing QUIC packets.",
            "counter",
        ),
        (
            "masque_quic_send_packets_total",
            "QUIC UDP datagrams sent to the network.",
            "counter",
        ),
        (
            "masque_quic_send_bytes_total",
            "QUIC UDP bytes sent to the network.",
            "counter",
        ),
        (
            "masque_tcp_relay_batches_total",
            "Event-loop rounds that consumed target TCP relay events.",
            "counter",
        ),
        (
            "masque_tcp_relay_events_total",
            "Target TCP relay events consumed by proxy shards.",
            "counter",
        ),
        (
            "masque_tcp_relay_bytes_total",
            "Target TCP response bytes handed to proxy shards.",
            "counter",
        ),
        (
            "masque_tunnels_active",
            "Currently active CONNECT tunnels by protocol.",
            "gauge",
        ),
        (
            "masque_auth_attempts_total",
            "Completed or load-shed authentication attempts.",
            "counter",
        ),
        (
            "masque_auth_pending",
            "Basic authentication requests admitted but not completed.",
            "gauge",
        ),
        (
            "masque_auth_running",
            "Argon2 password verifications currently executing.",
            "gauge",
        ),
        (
            "masque_packets_dropped_total",
            "Packets dropped by bounded internal queues.",
            "counter",
        ),
    ] {
        metric_header(out, name, help, kind);
    }
}

fn escape_label(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_prometheus_metrics_with_stable_low_cardinality_labels() {
        let metrics = Metrics::new(true);
        let shards =
            metrics.register_listener("127.0.0.1:8449".parse().unwrap(), "basic", 2, true, true);
        let listener = &shards[0];
        metrics.set_ready(true);
        listener.connection_opened();
        listener.record_receive_batch(4, 4800);
        listener.record_send_batch(3, 3600);
        listener.record_tcp_relay_batch(4, 256 * 1024);
        listener.update_tunnels([0, 0, 0], [1, 2, 1]);
        listener.record_auth_success();
        listener.record_heartbeat(metrics.elapsed_millis(), Duration::from_millis(25));
        shards[1].connection_opened();

        let rendered = metrics.render();
        assert!(rendered.contains("masque_server_ready 1\n"));
        assert!(
            rendered.contains(
                "masque_connections_active{listener=\"127.0.0.1:8449\",auth=\"basic\"} 2"
            )
        );
        assert!(rendered.contains(
            "masque_quic_receive_bytes_total{listener=\"127.0.0.1:8449\",auth=\"basic\"} 4800"
        ));
        assert!(
            rendered.contains(
                "masque_quic_udp_gso_enabled{listener=\"127.0.0.1:8449\",auth=\"basic\"} 1"
            )
        );
        assert!(rendered.contains(
            "masque_tcp_relay_events_total{listener=\"127.0.0.1:8449\",auth=\"basic\"} 4"
        ));
        assert!(rendered.contains(
            "masque_tcp_relay_bytes_total{listener=\"127.0.0.1:8449\",auth=\"basic\"} 262144"
        ));
        assert!(rendered.contains(
            "masque_tunnels_active{listener=\"127.0.0.1:8449\",auth=\"basic\",protocol=\"udp\"} 2"
        ));
        assert!(rendered.contains(
            "masque_event_loop_lag_seconds{listener=\"127.0.0.1:8449\",auth=\"basic\",shard=\"0\"} 0.025000"
        ));
        assert!(!rendered.contains("username="));
        assert!(!rendered.contains("target="));

        shards[1].disable_udp_gso();
        let after_fallback = metrics.render();
        assert!(
            after_fallback.contains(
                "masque_quic_udp_gso_enabled{listener=\"127.0.0.1:8449\",auth=\"basic\"} 0"
            )
        );
    }

    #[test]
    fn gauge_guards_are_balanced_when_dropped() {
        let metrics = Metrics::new(true);
        let shards =
            metrics.register_listener("[::1]:9090".parse().unwrap(), "basic", 1, false, true);
        let listener = &shards[0];
        {
            let _pending = listener.auth_pending_guard();
            let _running = listener.auth_running_guard();
            assert_eq!(listener.auth_pending.load(RELAXED), 1);
            assert_eq!(listener.auth_running.load(RELAXED), 1);
        }
        assert_eq!(listener.auth_pending.load(RELAXED), 0);
        assert_eq!(listener.auth_running.load(RELAXED), 0);
    }

    #[test]
    fn disabled_collection_does_not_touch_counters() {
        let metrics = Metrics::new(false);
        let shards =
            metrics.register_listener("127.0.0.1:8449".parse().unwrap(), "basic", 1, false, false);
        let shard = &shards[0];
        shard.connection_opened();
        shard.record_receive_batch(8, 9600);
        shard.record_send_batch(8, 9600);
        shard.record_tcp_relay_batch(4, 256 * 1024);
        shard.update_tunnels([0; 3], [1; 3]);
        shard.record_heartbeat(123, Duration::from_millis(25));
        let _pending = shard.auth_pending_guard();

        assert_eq!(shard.connections_active.load(RELAXED), 0);
        assert_eq!(shard.quic_receive_packets.load(RELAXED), 0);
        assert_eq!(shard.quic_send_packets.load(RELAXED), 0);
        assert_eq!(shard.tcp_relay_events.load(RELAXED), 0);
        assert_eq!(shard.auth_pending.load(RELAXED), 0);
        assert_eq!(shard.last_heartbeat_millis.load(RELAXED), 123);
        assert_eq!(shard.event_loop_lag_micros.load(RELAXED), 0);
    }

    #[test]
    fn readiness_fails_closed_when_any_shard_heartbeat_is_stale() {
        let metrics = Metrics::new(false);
        let shards =
            metrics.register_listener("127.0.0.1:8449".parse().unwrap(), "basic", 1, false, false);
        let registered_at = shards[0].last_heartbeat_millis.load(RELAXED);
        let stale_after = SHARD_STALE_AFTER.as_millis() as u64;
        metrics.set_ready(true);

        assert!(metrics.is_ready_at(registered_at + stale_after));
        assert!(!metrics.is_ready_at(registered_at + stale_after + 1));

        shards[0].record_heartbeat(registered_at + stale_after + 1, Duration::ZERO);
        assert!(metrics.is_ready_at(registered_at + stale_after + 1));
    }

    #[test]
    fn prometheus_label_values_are_escaped() {
        assert_eq!(escape_label("a\\b\"c\nd"), "a\\\\b\\\"c\\nd");
    }
}
