# gosso

[中文](./README.zh-CN.md) | English

[![CI](https://github.com/rushairer/gosso/actions/workflows/ci.yml/badge.svg)](https://github.com/rushairer/gosso/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/rushairer/gosso)](https://goreportcard.com/report/github.com/rushairer/gosso)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A self-hosted OpenID Connect and OAuth 2.0 identity provider built with Go, Gin, PostgreSQL, and Redis.

For the integrated Gouno Blog deployment, see [the source-verified Blog/BFF/GOSSO architecture and SVG](https://github.com/rushairer/gouno-blog/blob/main/docs/architecture/README.md). GOSSO is a **separate identity provider**: the Blog Confidential BFF lives inside the **Blog Go backend**, and Blog authorization uses Blog-local permissions rather than GOSSO admin roles. The integrated Compose template shares PostgreSQL/Redis infrastructure but has separate logical `blog` and `gosso` databases.

gosso provides a complete SSO server with OAuth 2.0 authorization, OIDC discovery, JWT-based authentication, WebAuthn/Passkeys, MFA, social login, and an admin API -- all backed by a clean-architecture Go codebase built on the [gouno](https://github.com/rushairer/gouno) scaffold.

## Features

**OAuth 2.0**
- Authorization Code grant with PKCE (S256 mandatory for public clients)
- Refresh Token grant
- Client Credentials grant
- Device Code grant (RFC 8628)
- Token revocation and introspection (RFC 7009 / RFC 7662)

**OpenID Connect**
- Discovery (`.well-known/openid-configuration`)
- JWKS endpoint (RS256)
- ID Token issuance
- UserInfo endpoint
- RP-Initiated Logout

**Authentication**
- Username/email + password login (Argon2id)
- WebAuthn / Passkeys (registration and authentication)
- TOTP-based MFA with backup codes
- Social login (Google, GitHub, WeChat)
- Password reset via email
- Email verification codes (phone/SMS gateway not yet connected)

**Security**
- Per-endpoint rate limiting (fail-closed for security-sensitive endpoints, fail-open for non-critical)
- CSRF protection middleware
- JWT authentication middleware with session validation
- Token blacklisting
- Structured audit logging

**Operations**
- Health and readiness probes (`/health`, `/readiness`)
- Prometheus metrics (`/metrics`) with pre-built [Grafana dashboard](deploy/grafana/gosso-dashboard.json)
- OpenTelemetry distributed tracing (OTLP, configurable endpoint)
- OpenAPI spec and Swagger UI (debug mode)
- Docker and docker-compose for dev, test, and production
- [Helm chart](deploy/helm/gosso/) for Kubernetes deployment
- [Operator Guide](docs/OPERATOR_GUIDE.md) with deployment, monitoring, and troubleshooting docs
- GitHub Actions CI (lint, unit tests with 70% coverage threshold, govulncheck, integration tests, Trivy security scan, cosign image signing, SBOM generation)

## Prerequisites

- Go 1.26.11+
- PostgreSQL 15+
- Redis 7+

## Quick Start

### Build

```bash
make build
```

This produces `./bin/gosso`.

### Configure

Copy an environment template and fill in your values:

```bash
cp .env.development.example .env.development
```

Then create or update an environment-specific config YAML file such as `config/development.yaml` or `config/production.yaml`:

```yaml
web_server:
  address: "0.0.0.0"
  port: "8080"
  debug: true
  max_body_size: 10485760
  rate_limits:
    login: 5
    token: 10
    passkey: 10
    api: 60
    introspect: 20
    device_code: 10

database:
  default: postgres
  drivers:
    postgres:
      name: postgres
      driver: pgx
      dsn: "host=localhost user=gosso password=gosso dbname=gosso_dev port=5432 sslmode=disable"

redis:
  dsn: "redis://localhost:6379/0"
  max_active_conns: 10
  pool_timeout_seconds: 5

auth:
  issuer: "http://localhost:8080"
  access_token_expiry: 15m
  refresh_token_expiry: 168h
  id_token_expiry: 15m
  session_ttl: 24h
  max_sessions: 10
  authorization_code_expiry: 10m
  device_code_expiry: 10m
  device_code_interval: 5s
  private_key_path: "./keys/private.pem"
  key_id: "gosso-key-1"
  totp_encryption_key: "0000000000000000000000000000000000000000000000000000000000000000"  # 32 bytes as 64 hex characters -- use a real key
  default_scopes:
    - openid
    - profile
    - email
```

Configuration is loaded by Viper. Environment variables use the `GOUNO_` prefix with `_` replacing `.` (e.g. `GOUNO_AUTH_ISSUER`). See `.env.production.example` for a full reference.

### Run

```bash
./bin/gosso web --config ./config --env development --address 0.0.0.0 --port 8080
```

CLI flags:
- `--config` / `-c`: config directory path (default `./config`)
- `--env` / `-e`: config environment name, e.g. `development`, `test`, or `production` (default `production`)
- `--address` / `-a`: listen address (default `0.0.0.0`)
- `--port` / `-p`: listen port (default `8080`)
- `--debug` / `-d`: enable debug mode (default `false`)

### Development mode

```bash
make dev
```

Requires [air](https://github.com/air-verse/air) for hot-reload (auto-installed if missing).

## Docker

```bash
# Development
make docker-dev-up

# Test
make docker-test-up

# Production
make docker-prod-up
```

The repository root includes the local stack in `docker-compose.yml`. After startup, open `http://localhost:8080`. Development credentials are local-only and must never be reused in production. In the admin console, go to **User Accounts** and use **Add User** to create normal users; grant the `admin` role separately through **Roles** when needed.

User self-service security flows stay under the auth endpoints: change your own password via `/api/v1/auth/password/change`, manage TOTP MFA via `/api/v1/auth/mfa/*`, and manage passkeys via `/api/v1/passkey/*`. Admin-mediated account creation, enable/disable, deletion, password reset, and role assignment remain under `/api/v1/admin/*`.

Before starting production Docker, copy `.env.production.example` to `.env.production`,
fill in real values, and place the RSA private key at `./keys/private.pem`
so it is mounted into the container at `/app/keys/private.pem`.
The production env file is consumed by Docker Compose, so keep it in `KEY=value`
format. The bundled Postgres service uses `sslmode=disable`; switch to
`sslmode=require` only when connecting to a database configured with TLS.

Stop with the corresponding `make docker-*-down` commands.

## API Endpoints

The canonical application API is `/api/v1/*`; legacy unversioned `/api/auth/*`, `/api/admin/*`, `/api/passkey/*`, `/api/passkeys` and `/api/oauth2/clients*` receive a method-preserving HTTP 308 redirect. Clients should call `/api/v1/*` directly rather than rely on redirects, especially for credential-bearing requests. OAuth2/OIDC protocol endpoints remain unversioned. See [API Versioning](docs/API_VERSIONING.md).

### OIDC Discovery and JWKS

| Method | Path | Description |
|--------|------|-------------|
| GET | `/.well-known/openid-configuration` | OIDC Discovery document |
| GET | `/.well-known/jwks.json` | JSON Web Key Set |

### OAuth 2.0

| Method | Path | Description |
|--------|------|-------------|
| GET | `/oauth2/authorize` | Authorization endpoint (requires JWT auth) |
| POST | `/oauth2/authorize` | Consent submission |
| POST | `/oauth2/token` | Token endpoint |
| POST | `/oauth2/revoke` | Token revocation |
| POST | `/oauth2/introspect` | Token introspection |
| POST | `/oauth2/device/code` | Device authorization |
| GET | `/oauth2/device` | Device code user verification page |
| POST | `/oauth2/device` | Device code user verification submit |

### OIDC

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/oidc/userinfo` | UserInfo endpoint |
| POST | `/oidc/logout` | RP-Initiated Logout |

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/login` | Username/password login |
| POST | `/api/v1/auth/refresh` | Refresh access token |
| POST | `/api/v1/auth/logout` | Logout (authenticated) |
| GET | `/api/v1/auth/session` | Current session info (authenticated) |
| GET | `/api/v1/auth/sessions` | List sessions (authenticated) |
| DELETE | `/api/v1/auth/sessions/:id` | Revoke a session (authenticated) |
| POST | `/api/v1/auth/password/change` | Change your own password (authenticated) |

### Admin API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/admin/accounts` | List accounts (admin) |
| POST | `/api/v1/admin/accounts` | Create a user account (admin) |
| POST | `/api/v1/admin/accounts/:account_id/password` | Reset a user's password (admin, not self) |
| POST | `/api/v1/admin/accounts/:account_id/disable` | Disable an account (admin, not self) |
| POST | `/api/v1/admin/accounts/:account_id/enable` | Enable an account (admin, not self) |
| POST | `/api/v1/admin/accounts/:account_id/roles` | Assign a role (admin, not self) |
| DELETE | `/api/v1/admin/accounts/:account_id/roles/:role_id` | Remove a role (admin, not self) |

### MFA

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/mfa/verify` | Verify MFA challenge |
| POST | `/api/v1/auth/mfa/enroll` | Enroll TOTP (authenticated) |
| POST | `/api/v1/auth/mfa/activate` | Activate TOTP (authenticated) |
| DELETE | `/api/v1/auth/mfa` | Disable MFA (authenticated) |
| POST | `/api/v1/auth/mfa/backup-codes` | Generate backup codes (authenticated) |
| POST | `/api/v1/passkey/mfa/begin` | Begin MFA passkey challenge |
| POST | `/api/v1/passkey/mfa/complete` | Complete MFA passkey challenge |

### Passkeys

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/passkey/register/begin` | Begin passkey registration (authenticated) |
| POST | `/api/v1/passkey/register/complete` | Complete passkey registration (authenticated) |
| POST | `/api/v1/passkey/login/begin` | Begin passkey login |
| POST | `/api/v1/passkey/login/complete` | Complete passkey login |
| GET | `/api/v1/passkeys` | List passkeys (authenticated) |
| DELETE | `/api/v1/passkeys/:id` | Delete a passkey (authenticated) |

### Social Login

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/auth/social/:provider` | Redirect to social provider |
| GET | `/api/v1/auth/social/:provider/callback` | Social provider callback |

### Verification and Password Reset

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/verify/send` | Send email verification code (phone returns 501 until SMS is configured) |
| POST | `/api/v1/auth/verify/confirm` | Confirm verification code |
| POST | `/api/v1/auth/password/forgot` | Request password reset |
| POST | `/api/v1/auth/password/reset` | Complete password reset |

### Client Management

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/oauth2/clients` | List OAuth clients (authenticated) |
| POST | `/api/v1/oauth2/clients` | Register OAuth client (authenticated) |
| GET | `/api/v1/oauth2/clients/:client_id` | Get client details (authenticated) |
| PUT | `/api/v1/oauth2/clients/:client_id` | Update client (authenticated) |
| DELETE | `/api/v1/oauth2/clients/:client_id` | Delete client (authenticated) |

### Admin

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/admin/accounts` | List accounts |
| GET | `/api/v1/admin/accounts/:account_id` | Get account |
| DELETE | `/api/v1/admin/accounts/:account_id` | Delete account |
| POST | `/api/v1/admin/accounts/:account_id/disable` | Disable account |
| POST | `/api/v1/admin/accounts/:account_id/enable` | Enable account |
| GET | `/api/v1/admin/accounts/:account_id/roles` | Get account roles |
| POST | `/api/v1/admin/accounts/:account_id/roles` | Add role to account |
| DELETE | `/api/v1/admin/accounts/:account_id/roles/:role_id` | Remove role |

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness check |
| GET | `/readiness` | Readiness check (database + Redis) |

## Project Structure

```
cmd/                        # Application entry point
  main.go
  gouno/                    # CLI commands (root, web, migrate)
config/                     # Configuration structs and loader
router/                     # Route registration
middleware/                  # Global middleware (CSRF, rate limiting, logging, request ID)
internal/
  account/                  # Account, credential, federated identity, role
  admin/                    # Admin controller
  audit/                    # Audit logging
  auth/                     # Login, MFA, passkeys, social login, password reset, verification
  cache/                    # Redis client
  db/                       # Database transaction helpers
  notification/             # Email and SMS services
  oauth2/                   # OAuth 2.0 authorization, token, revoke, device code, client management
  oidc/                     # OIDC discovery, JWKS, ID token, UserInfo, logout
  session/                  # Session domain and service
  token/                    # Token service, key service, blacklist
  testutil/                 # Shared test helpers
  utility/                  # JSON, logging, masking, password, phone utilities
db/                         # Database migration files
docs/                       # OpenAPI/Swagger, architecture ADRs and operator guides
examples/                   # Usage examples
deploy/                     # Deployment configuration
script/                     # Utility scripts
ssl/                        # TLS certificates
```

Capabilities live under `internal/<capability>/`; domain, repository, service, controller and composition files are optional implementation layers rather than mandatory scaffolding (see `AGENTS.md`).

## Documentation

| Document | Description |
|----------|-------------|
| [Operator Guide](docs/OPERATOR_GUIDE.md) | Deployment, monitoring, and troubleshooting |
| [Architecture Invariants](docs/ARCHITECTURE_INVARIANTS.md) | Non-negotiable code rules (CI-enforced) |
| [Architecture Decision Records](docs/ADR/) | Design decisions (observability, API versioning, etc.) |
| [API Versioning](docs/API_VERSIONING.md) | API version policy, route compatibility and deprecation rules |
| [API Stability](docs/api-stability.md) | Stability tiers for all endpoints (Stable vs Experimental) |
| [Backup & Restore](docs/BACKUP_RESTORE.md) | PostgreSQL backup and recovery |
| [OpenAPI Spec](docs/openapi.yaml) | Machine-readable API specification |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting and deployment checklist |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup and PR workflow |

## Testing

```bash
# Unit tests
make test

# Integration tests (requires docker-test-up)
make docker-test-up
make test-integration
```

Unit tests use `testify/assert`, `go-sqlmock`, and `miniredis`. The CI pipeline requires a minimum of 70% test coverage across the coverage-gate package set and package-level coverage floors for critical auth, OAuth2, OIDC, token, and session services.

## Configuration Reference

Configuration is managed by [Viper](https://github.com/spf13/viper). The config struct is defined in `config/config.go` as `GoUnoConfig`.

| Section | Key fields | Env prefix example |
|---------|------------|-------------------|
| `web_server` | address, port, debug, timeouts, max_body_size, trusted_proxies, rate_limits | `GOUNO_WEB_SERVER_ADDRESS` |
| `database` | default driver, drivers map, connection pool settings | `GOUNO_DATABASE_DRIVERS_POSTGRES_DSN` |
| `redis` | dsn, max_active_conns, pool_timeout_seconds | `GOUNO_REDIS_DSN` |
| `auth` | issuer, token expiries, session_ttl, private_key_path, key_id, WebAuthn, TOTP, MFA, password reset, verification settings | `GOUNO_AUTH_ISSUER` |
| `cors` | allowed_origins, methods, headers, credentials, max_age | `GOUNO_CORS_ALLOWED_ORIGINS` |
| `smtp` | host, port, username, password, from, tls_policy | `GOUNO_SMTP_HOST` |
| `oauth_providers` | google, github, wechat (client_id, client_secret, redirect_uri, scopes) | `GOUNO_OAUTH_PROVIDERS_GOOGLE_CLIENT_ID` |
| `task_pipeline` | flush_size, buffer_size, flush_interval | `GOUNO_TASK_PIPELINE_FLUSH_SIZE` |
| `log` | level (-1=debug, 0=info, 1=warn, 2=error) | `GOUNO_LOG_LEVEL` |

Environment variables override config file values. The prefix is `GOUNO_` and dots are replaced with underscores.

## Makefile Commands

| Command | Description |
|---------|-------------|
| `make build` | Build the binary to `./bin/gosso` |
| `make run` | Build and run |
| `make dev` | Hot-reload development mode (requires air) |
| `make lint` | Run golangci-lint |
| `make lint-fix` | Run golangci-lint with auto-fix |
| `make test` | Run unit tests |
| `make test-integration` | Run integration tests |
| `make docker-dev-up` | Start development Docker environment |
| `make docker-test-up` | Start test Docker environment |
| `make docker-prod-up` | Start production Docker environment |
| `make docker-prod-down` | Stop production Docker environment |
| `make clean` | Remove build artifacts |
| `make bench` | Run benchmarks |
| `make security-scan` | Run Trivy security scan on Docker image |
| `make docker-build` | Build Docker image (no push) |
| `make sbom` | Generate CycloneDX SBOM (requires syft) |
| `make examples` | Run all examples |
| `make help` | Show all available commands |

## Built With

- [gouno](https://github.com/rushairer/gouno) -- Go web application scaffold
- [Gin](https://github.com/gin-gonic/gin) -- HTTP framework
- [Cobra](https://github.com/spf13/cobra) + [Viper](https://github.com/spf13/viper) -- CLI and configuration
- [golang-jwt](https://github.com/golang-jwt/jwt) -- JWT signing and verification
- [go-webauthn](https://github.com/go-webauthn/webauthn) -- WebAuthn/Passkey support
- [pgx](https://github.com/jackc/pgx) -- PostgreSQL driver
- [go-redis](https://github.com/redis/go-redis/v9) -- Redis client
- [zap](https://go.uber.org/zap) -- Structured logging

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and the PR workflow.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

