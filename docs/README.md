# Documentation

- [Architecture](architecture.md): components, event loops, data flow, and
  resource bounds.
- [QUIC backend selection](tokio-quiche-evaluation.md): current quiche, Quinn,
  and tokio-quiche tradeoffs, dependency checks, and adoption decision gates.
- [tokio-quiche integration plan](tokio-quiche-integration-plan.md): proposed
  module changes, compatibility blockers, resource budgets, test matrix,
  staged implementation, and rollback requirements.
- [tokio-quiche G0 implementation results](tokio-quiche-g0-results.md): isolated
  endpoint, reproducible patches, macOS/Linux observations, and remaining gates.
- [Quinn migration proposal](quinn-migration-plan.md): conditional architecture
  and implementation plan if Quinn migration is reconsidered.
- [Configuration](configuration.md): configuration reference and policy.
- [Deployment](deployment.md): Linux installation, macOS/Linux probe packages,
  and systemd operation.
- [Operations](operations.md): guarded fleet inspection, rollout, and rollback,
  with an optional repo-scoped AI Skill.
- [AI-assisted changes](ai-operations.md): supported configuration and deployment
  workflows, verification evidence, and current automation boundaries.
- [Protocols](protocols.md): supported MASQUE, HTTP/2, and HTTP/3 behavior.
- [Performance](performance.md): fast paths, tuning, and benchmark rules.
- [Raw QUIC comparison](performance-quic-comparison.md): measured quiche/Quinn
  results on macOS, Linux, and a bidirectional LAN path, with limitations.
- [Observability](observability.md): health, readiness, Prometheus, Grafana,
  structured logs, and systemd notification.
- [Troubleshooting](troubleshooting.md): client-side protocol probing,
  shareable server diagnostics, and failure isolation.
- [Testing](testing.md): local, E2E, Linux, and release validation.
- [Security](security.md): threat model and operator hardening.

Contributor policy is in [`CONTRIBUTING.md`](../CONTRIBUTING.md), and private
vulnerability reporting is described in [`SECURITY.md`](../SECURITY.md).
