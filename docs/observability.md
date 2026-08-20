# Observability

MASQUE Server can expose a small HTTP/1 operational endpoint independently of
its HTTP/3 proxy listeners. It is disabled unless configured and is restricted
to an IPv4 or IPv6 loopback address because it has no authentication layer.

```toml
[observability]
listen_addr = "127.0.0.1:9090"
```

`check-config` validates the address and reports the three endpoint paths. A
wildcard or public address fails startup. Run the collector on the same host,
or reach loopback through an authenticated tunnel; do not publish this socket
through a firewall rule or unauthenticated reverse proxy.

## Endpoints

| Path | Success | Meaning |
| --- | --- | --- |
| `/healthz` | `200 ok` | The process and operational HTTP task are alive |
| `/readyz` | `200 ready` | All proxy sockets are bound and the server is accepting traffic |
| `/metrics` | `200` | Prometheus text exposition |

`/readyz` returns `503` before readiness and as soon as graceful shutdown
starts. `/healthz` and `/metrics` remain available during the bounded drain.
Only `GET` and `HEAD` are accepted, requests time out after two seconds, request
headers are capped at 8 KiB, and concurrency is bounded.

Quick local verification:

```sh
curl --fail http://127.0.0.1:9090/healthz
curl --fail http://127.0.0.1:9090/readyz
curl --fail http://127.0.0.1:9090/metrics
```

## Prometheus

Add the endpoint as a static target in the Prometheus instance running on the
host:

```yaml
scrape_configs:
  - job_name: masque-server
    static_configs:
      - targets: ["127.0.0.1:9090"]
```

The packaged rules are installed at:

```text
/usr/local/share/masque-server/monitoring/prometheus-rules.yml
```

Reference that file from Prometheus' [`rule_files` setting](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#rule_files)
and validate it with `promtool check rules` before reloading Prometheus. The
rules cover prolonged not-ready state, connection-limit rejection,
authentication overload and high failure ratios, sustained internal queue
drops, and forced shutdown. Alert on Prometheus' own
`up{job="masque-server"} == 0` as well; an application cannot emit a metric
after its process or host disappears.

## Grafana

The installer writes an importable classic dashboard JSON to:

```text
/usr/local/share/masque-server/monitoring/grafana-dashboard.json
```

Import it in Grafana and select the Prometheus data source when prompted. The
dashboard contains readiness, uptime, connections, tunnels, QUIC throughput
and packet rates, average kernel batch size, authentication pressure, and
internal queue drops. It can also be copied into a file-provisioned dashboard
directory using [Grafana dashboard provisioning](https://grafana.com/docs/grafana/latest/administration/provisioning/#dashboards).

## Exported metrics

All metric names start with `masque_`.

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `masque_build_info` | gauge | `version` | Running build version |
| `masque_server_ready` | gauge | — | `1` while ready, `0` while starting or draining |
| `masque_process_start_time_seconds` | gauge | — | Process start as a Unix timestamp |
| `masque_process_uptime_seconds` | gauge | — | Current process uptime |
| `masque_listener_shards` | gauge | `listener`, `auth` | Event loops assigned to the listener |
| `masque_connections_active` | gauge | `listener`, `auth` | Live QUIC connections |
| `masque_connections_accepted_total` | counter | `listener`, `auth` | Accepted connection objects |
| `masque_connections_rejected_total` | counter | `listener`, `auth`, `reason` | Connections rejected at a resource limit |
| `masque_quic_receive_batches_total` | counter | `listener`, `auth` | Non-empty network receive batches |
| `masque_quic_receive_packets_total` | counter | `listener`, `auth` | Received QUIC UDP datagrams |
| `masque_quic_receive_bytes_total` | counter | `listener`, `auth` | Received QUIC UDP bytes |
| `masque_quic_send_batches_total` | counter | `listener`, `auth` | Successful network send batches |
| `masque_quic_send_packets_total` | counter | `listener`, `auth` | Sent QUIC UDP datagrams |
| `masque_quic_send_bytes_total` | counter | `listener`, `auth` | Sent QUIC UDP bytes |
| `masque_tunnels_active` | gauge | `listener`, `auth`, `protocol` | Live `tcp`, `udp`, or `ip` tunnels |
| `masque_auth_attempts_total` | counter | `listener`, `auth`, `result` | Successful, failed, or load-shed verification |
| `masque_auth_pending` | gauge | `listener`, `auth` | Admitted Basic checks not yet completed |
| `masque_auth_running` | gauge | `listener`, `auth` | Argon2 jobs currently executing |
| `masque_packets_dropped_total` | counter | `listener`, `auth`, `reason` | Drops at bounded shard, datagram, or TUN queues |
| `masque_roster_reloads_total` | counter | `result` | Successful and rejected SIGHUP roster reloads |
| `masque_forced_shutdowns_total` | counter | — | Process shutdowns that reached the drain deadline |

Labels deliberately describe only configured listeners, authentication modes,
protocols, and fixed result classes. Usernames, client identities, target
addresses, stream IDs, and connection IDs are never labels, which avoids both
sensitive-data exposure and unbounded Prometheus cardinality.

Receive and send counters are updated once per kernel batch rather than once
per datagram. Connection counts use object lifetime, while tunnel gauges are
published once after a connection's event-loop work. Scraping is the only path
that formats text or takes the listener-list read lock. Each shard owns its
counter allocation, so event-loop cores never contend on a shared metric cache
line; when `[observability]` is absent, collection performs no counter atomics.

## Logs and systemd readiness

Text logs remain the default. Use newline-delimited structured logs when a
collector expects JSON:

```sh
masque-server --log-format json --config /etc/masque/masque.toml
```

`RUST_LOG` and `-v` keep their existing filtering behavior. For the packaged
service, add `--log-format json` to an `ExecStart` override when desired.

The supplied unit uses `Type=notify`. The process sends `READY=1` only after all
proxy sockets and the optional operational socket are bound, and sends
`STOPPING=1` when graceful draining begins. Manual foreground runs need no
special environment; notification is a no-op when `NOTIFY_SOCKET` is absent.
