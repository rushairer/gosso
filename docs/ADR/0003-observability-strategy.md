# ADR-0003: Observability Strategy

- **Status**: Accepted
- **Date**: 2026-06-21

## Context

gosso is a production-deployed SSO server. It currently has structured logging (Zap) and audit logging, but no metrics or distributed tracing. For production operations, operators need:

1. Request latency and error rate visibility
2. Authentication success/failure rate monitoring
3. Database and Redis connection pool health
4. Distributed tracing for multi-service call chains

## Decision

We adopt **Prometheus** for metrics and **OpenTelemetry (OTLP)** for distributed tracing.

### Metrics

- Expose a `/metrics` endpoint using the Prometheus text format
- Use a custom `prometheus.Registry` to avoid global state conflicts
- Name all metrics with the `gosso_` prefix for namespace isolation
- HTTP request metrics use **route patterns** (e.g., `/api/v1/auth/login`) not actual paths (e.g., `/api/v1/auth/login/abc-123`) to avoid cardinality explosion
- Metrics are **disabled by default** and enabled via `observability.metrics_enabled: true`

### Tracing

- Use the OpenTelemetry SDK with an OTLP HTTP exporter
- Export to any OTLP-compatible backend (Jaeger, Tempo, Datadog, etc.)
- Configure via `observability.otlp_endpoint` and `GOUNO_OTEL_EXPORTER_OTLP_ENDPOINT` env var
- Tracing is **disabled by default** and enabled via `observability.tracing_enabled: true`
- When tracing is disabled, zero overhead (no SDK initialization)

### Key Metrics

| Metric | Type | Labels | Purpose |
|--------|------|--------|---------|
| `gosso_http_requests_total` | Counter | method, path, status | Request volume and error rate |
| `gosso_http_request_duration_seconds` | Histogram | method, path | Latency distribution |
| `gosso_auth_login_attempts_total` | Counter | result, method | Auth success/failure rate |
| `gosso_rate_limit_exceeded_total` | Counter | endpoint | Rate limit pressure |
| `gosso_active_sessions` | Gauge | — | Session count |
| `gosso_db_pool_*` | Gauge | — | DB connection pool health |
| `gosso_redis_pool_active_connections` | Gauge | — | Redis pool health |

## Consequences

- **Positive**: Standard Prometheus scraping works with Grafana, Datadog, etc.
- **Positive**: OTLP is vendor-neutral; switching backends requires only a config change
- **Positive**: Both are disabled by default — zero overhead when not needed
- **Negative**: Two new dependencies (prometheus/client_golang, go.opentelemetry.io/otel)
- **Negative**: Metrics endpoint must be protected in production (restrict to internal network or add auth)
