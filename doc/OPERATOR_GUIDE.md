# Operator Guide

This guide covers deploying, monitoring, and operating gosso in production.

> [中文版本](OPERATOR_GUIDE.zh-CN.md)

---

## Table of Contents

- [Deployment Architecture](#deployment-architecture)
- [Quick Start (Docker Compose)](#quick-start-docker-compose)
- [Standalone Binary](#standalone-binary)
- [Configuration Reference](#configuration-reference)
- [Health Checks](#health-checks)
- [Graceful Shutdown](#graceful-shutdown)
- [Monitoring & Observability](#monitoring--observability)
- [Resource Sizing](#resource-sizing)
- [Backup & Recovery](#backup--recovery)
- [Troubleshooting](#troubleshooting)

---

## Deployment Architecture

```
                    ┌─────────────┐
                    │   Clients   │
                    └──────┬──────┘
                           │ HTTPS :443
                    ┌──────┴──────┐
                    │    Nginx    │  TLS termination, rate limiting
                    └──────┬──────┘
                           │ HTTP :8080
                    ┌──────┴──────┐
                    │    gosso    │  OIDC / OAuth 2.0 provider
                    └──┬──────┬───┘
                       │      │
              ┌────────┘      └────────┐
              │                        │
       ┌──────┴──────┐          ┌──────┴──────┐
       │ PostgreSQL  │          │    Redis    │
       │    :5432    │          │    :6379    │
       └─────────────┘          └─────────────┘
```

gosso requires two backing services:

- **PostgreSQL 16+** — accounts, credentials, OAuth2 clients, audit logs, migrations
- **Redis 7+** — sessions, rate limiting, token blacklists, caching

All inter-service traffic stays within a private Docker network. Only Nginx exposes ports to the outside.

---

## Quick Start (Docker Compose)

### Prerequisites

- Docker Engine 24+ and Docker Compose v2
- A domain name with TLS certificate (or a reverse proxy like Cloudflare/Caddy in front)

### Steps

1. **Clone and configure:**

   ```bash
   git clone https://github.com/rushairer/gosso.git
   cd gosso
   cp .env.production.example .env.production
   ```

2. **Edit `.env.production`** — set at minimum:
   - `POSTGRES_PASSWORD` — strong random password
   - `REDIS_PASSWORD` — strong random password
   - `GOUNO_AUTH_ISSUER` — your HTTPS issuer URL (e.g., `https://sso.example.com`)
   - `GOUNO_AUTH_VERIFY_HASH_PEPPER` — random string (used for password hashing pepper)
   - `GOUNO_AUTH_TOTP_ENCRYPTION_KEY` — generate with `openssl rand -hex 32`
   - `GOUNO_CORS_ALLOWED_ORIGINS` — your application origins (e.g., `["https://app.example.com"]`)
   - `GOUNO_SMTP_*` — SMTP configuration for email delivery

3. **Generate JWT signing key** (if not already present):

   ```bash
   openssl genrsa -out ssl/private.pem 2048
   openssl rsa -in ssl/private.pem -pubout -out ssl/public.pem
   ```

4. **Start services:**

   ```bash
   make docker-prod-up
   ```

5. **Verify:**

   ```bash
   curl -s http://localhost/readiness | jq .
   # Expected: {"status":"ok","ready":true,"checks":{"database":"ok","redis":"ok"}}
   ```

---

## Standalone Binary

If deploying without Docker:

```bash
# Build
make build

# Set environment variables (or use config/*.yaml)
export GOUNO_ENV=production
export GOUNO_DATABASE_DRIVERS_POSTGRES_DSN="postgres://user:pass@host:5432/gosso?sslmode=require"
export GOUNO_REDIS_DSN="redis://:pass@host:6379/0"
# ... other variables as needed

# Run migrations first, then start
./bin/gosso web
```

---

## Configuration Reference

gosso uses Viper for configuration. Settings are loaded in order: **YAML files → environment variables**. All environment variables use the `GOUNO_` prefix and `_` as separator (e.g., `GOUNO_AUTH_ISSUER` maps to `auth.issuer` in YAML).

### Critical Production Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GOUNO_ENV` | ✅ | Set to `production` |
| `GIN_MODE` | ✅ | Set to `release` |
| `GOUNO_DATABASE_DRIVERS_POSTGRES_DSN` | ✅ | PostgreSQL connection string |
| `GOUNO_REDIS_DSN` | ✅ | Redis connection string |
| `GOUNO_AUTH_ISSUER` | ✅ | OIDC issuer URL (must be HTTPS) |
| `GOUNO_AUTH_VERIFY_HASH_PEPPER` | ✅ | Pepper for password hashing |
| `GOUNO_AUTH_TOTP_ENCRYPTION_KEY` | ✅ | 64-char hex string for TOTP secret encryption |
| `GOUNO_CORS_ALLOWED_ORIGINS` | ✅ | Allowed CORS origins (JSON array) |
| `GOUNO_WEB_SERVER_TRUSTED_PROXIES` | ✅ | Trusted proxy CIDRs (JSON array, e.g., `["172.22.0.0/16"]`) |

### Server Tuning

| Variable | Default | Description |
|----------|---------|-------------|
| `GOUNO_WEB_SERVER_ADDRESS` | `0.0.0.0` | Listen address |
| `GOUNO_WEB_SERVER_PORT` | `8080` | Listen port |
| `GOUNO_WEB_SERVER_READ_TIMEOUT` | `10s` | HTTP read timeout |
| `GOUNO_WEB_SERVER_WRITE_TIMEOUT` | `30s` | HTTP write timeout |
| `GOUNO_WEB_SERVER_IDLE_TIMEOUT` | `120s` | HTTP idle timeout (must be ≥ read_timeout) |
| `GOUNO_WEB_SERVER_SHUTDOWN_TIMEOUT` | `30s` | Graceful shutdown window (must be positive) |
| `GOUNO_WEB_SERVER_MAX_BODY_SIZE` | `10MB` | Maximum request body size |
| `GOUNO_WEB_SERVER_REQUEST_TIMEOUT` | `30s` | Per-request processing timeout |

### SMTP (Email Delivery)

| Variable | Description |
|----------|-------------|
| `GOUNO_SMTP_HOST` | SMTP server hostname |
| `GOUNO_SMTP_PORT` | SMTP port (typically 587) |
| `GOUNO_SMTP_USERNAME` | SMTP username |
| `GOUNO_SMTP_PASSWORD` | SMTP password |
| `GOUNO_SMTP_FROM` | Sender address (e.g., `noreply@sso.example.com`) |
| `GOUNO_SMTP_TLS_POLICY` | Must be `mandatory` in production |

GOSSO uses SMTP for email verification codes and password reset links. SMTP is optional only if those flows are not used; once `GOUNO_SMTP_HOST` is configured, validation also requires a valid password reset base URL.

#### Development with Mailpit

The development Compose profiles use Mailpit as a local SMTP sink:

```env
GOUNO_SMTP_HOST=mailpit
GOUNO_SMTP_PORT=1025
GOUNO_SMTP_FROM=noreply@gosso.com
GOUNO_SMTP_TLS_POLICY=notls
GOUNO_AUTH_PASSWORD_RESET_BASE_URL=http://localhost:3000/reset-password
```

Mailpit accepts messages on SMTP port `1025` and exposes the inbox at `http://localhost:8025` (or the configured `MAILPIT_WEB_EXTERNAL_PORT`). Use it to verify email-change codes and password-reset links without sending external mail.

#### Production SMTP

Use a real SMTP provider in production:

```env
GOUNO_SMTP_HOST=smtp.example.com
GOUNO_SMTP_PORT=587
GOUNO_SMTP_USERNAME=your-smtp-user
GOUNO_SMTP_PASSWORD=your-smtp-password
GOUNO_SMTP_FROM=noreply@sso.example.com
GOUNO_SMTP_TLS_POLICY=mandatory
GOUNO_AUTH_PASSWORD_RESET_BASE_URL=https://sso.example.com/reset-password
```

Operational notes:

- `GOUNO_SMTP_TLS_POLICY` supports `mandatory`, `opportunistic`, and `notls`; production rejects `notls`.
- `GOUNO_AUTH_PASSWORD_RESET_BASE_URL` is required when SMTP is configured and must use HTTPS in production.
- Store `GOUNO_SMTP_PASSWORD` in a secret manager or deployment secret, not in Git.
- Use a verified sender/domain for `GOUNO_SMTP_FROM` and configure SPF/DKIM/DMARC with your SMTP provider.
- `/readiness` checks PostgreSQL and Redis only; SMTP failures appear in application logs when a send is attempted.

### Optional: OAuth / Social Login

| Variable | Description |
|----------|-------------|
| `GOUNO_OAUTH_PROVIDERS_GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOUNO_OAUTH_PROVIDERS_GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `GOUNO_OAUTH_PROVIDERS_GOOGLE_REDIRECT_URI` | Google OAuth callback URL |
| `GOUNO_OAUTH_PROVIDERS_GITHUB_CLIENT_ID` | GitHub OAuth client ID |
| `GOUNO_OAUTH_PROVIDERS_GITHUB_CLIENT_SECRET` | GitHub OAuth client secret |
| `GOUNO_OAUTH_PROVIDERS_GITHUB_REDIRECT_URI` | GitHub OAuth callback URL |
| `GOUNO_OAUTH_PROVIDERS_WECHAT_CLIENT_ID` | WeChat OAuth client ID |
| `GOUNO_OAUTH_PROVIDERS_WECHAT_CLIENT_SECRET` | WeChat OAuth client secret |
| `GOUNO_OAUTH_PROVIDERS_WECHAT_REDIRECT_URI` | WeChat OAuth callback URL |

### Production Safety Checks

The configuration validator enforces these rules when `GOUNO_ENV=production`:

- Auth issuer URL must use HTTPS and cannot point to localhost
- SMTP TLS policy cannot be `notls`
- CORS allowed origins must be explicitly set
- Trusted proxies must be configured
- Database DSN must be explicitly set
- TOTP encryption key and verify hash pepper are required
- Debug mode (`DEBUG=true`) is blocked

---

## Health Checks

gosso exposes two health check endpoints:

### Liveness Probe: `GET /health`

- Returns `200 {"status":"ok"}` if the process is alive
- Does **not** check backend dependencies (DB/Redis)
- Use for Kubernetes `livenessProbe` or Docker `HEALTHCHECK`
- Fail-open rate limiting (request still succeeds if rate limit check fails)

### Readiness Probe: `GET /readiness`

- Pings both PostgreSQL and Redis with a 2-second timeout per check
- Returns `200` when both are reachable:
  ```json
  {"status":"ok","ready":true,"checks":{"database":"ok","redis":"ok"}}
  ```
- Returns `503` when either is unreachable:
  ```json
  {"status":"unavailable","ready":false,"checks":{"database":"ok","redis":"error: ..."}}
  ```
- Use for Kubernetes `readinessProbe` — routes traffic only when ready

### Docker HEALTHCHECK (built into Dockerfile)

```
Interval: 30s | Timeout: 10s | Retries: 3 | Start period: 40s
Command: wget --no-verbose --tries=1 --spider http://localhost:8080/readiness
```

### Kubernetes Probe Configuration

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 15
  timeoutSeconds: 5
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /readiness
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3
```

---

## Graceful Shutdown

When gosso receives `SIGTERM` or `SIGINT`, it performs an ordered shutdown:

1. **Stop accepting new connections** — HTTP server begins draining
2. **Wait for in-flight requests** — up to `ShutdownTimeout` (default 30s)
3. **Close email service ticker** — stop background email retry loop
4. **Wait for background goroutines** — e.g., session revocation after password reset
5. **Stop session cache cleanup** — `SessionService.StopCacheCleanup()`
6. **Drain audit batches** — flush any pending audit log entries to the database
7. **Sync logger** — flush buffered log entries
8. **Exit**

### Docker Compose

```yaml
stop_grace_period: 45s   # Must be > ShutdownTimeout
```

### Kubernetes

```yaml
spec:
  terminationGracePeriodSeconds: 45   # Must be > ShutdownTimeout
```

### Important Notes

- Set `ShutdownTimeout` to be **less than** the container/orchestrator grace period
- The default 30s shutdown timeout works well with 45s Docker/K8s grace periods
- During shutdown, the `/readiness` endpoint will start returning 503, causing load balancers to stop routing traffic

---

## Monitoring & Observability

### Prometheus Metrics

Enable metrics by setting `metrics_enabled: true` in config. Metrics are served at `GET /metrics`.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `gosso_http_requests_total` | Counter | method, path, status | Total HTTP requests |
| `gosso_http_request_duration_seconds` | Histogram | method, path | Request latency |
| `gosso_auth_login_attempts_total` | Counter | result, method | Login attempts (success/failure by method) |
| `gosso_rate_limit_exceeded_total` | Counter | endpoint | Requests rejected by rate limiter |
| `gosso_active_sessions` | Gauge | — | Currently active sessions |
| `gosso_db_pool_open_connections` | Gauge | — | PostgreSQL open connections |
| `gosso_db_pool_in_use` | Gauge | — | PostgreSQL in-use connections |
| `gosso_redis_pool_active_connections` | Gauge | — | Redis active connections |

### Recommended Alert Rules

```yaml
groups:
  - name: gosso
    rules:
      # High error rate
      - alert: GossoHighErrorRate
        expr: |
          sum(rate(gosso_http_requests_total{status=~"5.."}[5m]))
          / sum(rate(gosso_http_requests_total[5m])) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "gosso error rate > 5%"

      # Login failure spike
      - alert: GossoLoginFailureSpike
        expr: |
          sum(rate(gosso_auth_login_attempts_total{result="failure"}[5m]))
          / sum(rate(gosso_auth_login_attempts_total[5m])) > 0.3
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "gosso login failure rate > 30%"

      # DB connection pool exhaustion
      - alert: GossoDBPoolExhausted
        expr: gosso_db_pool_in_use / gosso_db_pool_open_connections > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "gosso DB connection pool > 90% utilized"

      # Service not ready
      - alert: GossoNotReady
        expr: up{job="gosso"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "gosso instance is down"
```

### Grafana Dashboard

A pre-built Grafana dashboard is available at [`deploy/grafana/gosso-dashboard.json`](../deploy/grafana/gosso-dashboard.json). Import it via Grafana UI → Dashboards → Import.

### Distributed Tracing

gosso supports OpenTelemetry with OTLP HTTP export. Configure:

| Variable | Description |
|----------|-------------|
| `GOUNO_OBSERVABILITY_TRACING_ENABLED` | Set to `true` to enable |
| `GOUNO_OBSERVABILITY_TRACING_ENDPOINT` | OTLP HTTP endpoint (e.g., `http://jaeger:4318`) |

### Structured Logging

gosso uses Zap for structured JSON logging in production.

| Variable | Values | Description |
|----------|--------|-------------|
| `GOUNO_LOGGING_LEVEL` | -1=debug, 0=info, 1=warn, 2=error, 4=dpanic, 5=panic, 6=fatal | Log verbosity |

Every request includes an `X-Request-ID` (UUID v4) in the response header and in the request-scoped logger. Use this to correlate logs across services.

**Security note**: Sensitive fields (emails, phone numbers, opaque IDs) are automatically masked in logs using built-in masking utilities.

---

## Resource Sizing

### Minimum Production (Docker Compose defaults)

| Service | CPU Limit | CPU Reserve | Memory Limit | Memory Reserve |
|---------|-----------|-------------|--------------|----------------|
| gosso | 2.0 | 0.5 | 1 GB | 256 MB |
| PostgreSQL | 1.0 | 0.25 | 1 GB | 256 MB |
| Redis | 0.5 | 0.1 | 512 MB | 64 MB |
| Nginx | 0.5 | 0.1 | 256 MB | 64 MB |
| **Total** | **4.0** | **0.95** | **2.75 GB** | **640 MB** |

### Scaling Guidelines

| Users | gosso Replicas | PostgreSQL | Redis |
|-------|---------------|------------|-------|
| < 1,000 | 1 | Single instance | Single instance |
| 1,000–10,000 | 2–3 | Primary + replica | Sentinel or single |
| 10,000+ | 3+ | Managed (RDS/CloudSQL) | Managed (ElastiCache/CloudMemorystore) |

For Kubernetes deployments, use the provided [Helm chart](../deploy/helm/gosso/) with HorizontalPodAutoscaler configured.

---

## Backup & Recovery

See [BACKUP_RESTORE.md](BACKUP_RESTORE.md) for detailed PostgreSQL backup and recovery procedures.

### Quick Reference

```bash
# Backup
pg_dump -h localhost -U gosso -d gosso -F c -f gosso_$(date +%Y%m%d).dump

# Restore
pg_restore -h localhost -U gosso -d gosso -c gosso_20260101.dump
```

**Redis** does not require persistent backups for gosso — all Redis data (sessions, rate limits, caches) is ephemeral and will be rebuilt. However, ensure Redis AOF persistence is enabled (`appendonly yes`) to survive restarts without losing active sessions.

---

## Troubleshooting

### Startup fails with "HTTPS required"

**Cause**: `GOUNO_AUTH_ISSUER` is set to an `http://` URL in production mode.

**Fix**: Set `GOUNO_AUTH_ISSUER=https://sso.example.com`

---

### Startup fails with "trusted proxies required"

**Cause**: Running in production without `GOUNO_WEB_SERVER_TRUSTED_PROXIES`.

**Fix**: Set `GOUNO_WEB_SERVER_TRUSTED_PROXIES=["172.22.0.0/16"]` to match your Docker network CIDR.

---

### Readiness probe returns 503

**Cause**: PostgreSQL or Redis is unreachable.

**Check**:
```bash
# Check if services are running
docker compose ps

# Check gosso logs
docker compose logs gosso --tail 50

# Test connections manually
docker compose exec postgres pg_isready -U gosso
docker compose exec redis redis-cli ping
```

---

### High memory usage

**Cause**: Large number of active sessions or audit log accumulation.

**Check**:
```bash
# Check active sessions via metrics
curl -s http://localhost:8080/metrics | grep gosso_active_sessions

# Check audit log table size
docker compose exec postgres psql -U gosso -c "SELECT pg_size_pretty(pg_total_relation_size('audit_record'));"
```

**Fix**: Configure session limits in config, and set up audit log rotation/archival.

---

### Rate limiting too aggressive

**Cause**: Default rate limits may be too low for your traffic pattern.

**Current defaults**:
- Login: 5 req/min per IP
- Token: 10 req/min per client
- API: 60 req/min per IP
- Admin: 30 req/min per IP

Rate limit headers are returned in every response:
- `X-RateLimit-Limit` — max requests in window
- `X-RateLimit-Remaining` — remaining requests
- `X-RateLimit-Reset` — window reset timestamp
- `Retry-After` — seconds to wait (when rate limited)
