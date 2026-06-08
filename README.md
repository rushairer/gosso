# gosso

A self-hosted OpenID Connect and OAuth 2.0 identity provider built with Go, Gin, PostgreSQL, and Redis.

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
- Username/email + password login (bcrypt)
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
- OpenAPI spec and Swagger UI (debug mode)
- Docker and docker-compose for dev, test, and production
- GitHub Actions CI (lint, unit tests with 50% coverage threshold, govulncheck, integration tests, build, Docker build)

## Prerequisites

- Go 1.25.0+
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

Then create a config YAML file at `config/config.yaml` (or `config/development.yaml`, `config/production.yaml`, etc.):

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
  totp_encryption_key: "00000000000000000000000000000000"  # 32 bytes hex -- use a real key
  default_scopes:
    - openid
    - profile
    - email
```

Configuration is loaded by Viper. Environment variables use the `GOUNO_` prefix with `_` replacing `.` (e.g. `GOUNO_AUTH_ISSUER`). See `.env.production.example` for a full reference.

### Run

```bash
./bin/gosso web --config ./config/config.yaml --address 0.0.0.0 --port 8080
```

CLI flags:
- `--config` / `-c`: config file path (default `./config/config.yaml`)
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

Stop with the corresponding `make docker-*-down` commands.

## API Endpoints

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
| POST | `/api/auth/login` | Username/password login |
| POST | `/api/auth/refresh` | Refresh access token |
| POST | `/api/auth/logout` | Logout (authenticated) |
| GET | `/api/auth/session` | Current session info (authenticated) |
| GET | `/api/auth/sessions` | List sessions (authenticated) |
| DELETE | `/api/auth/sessions/:id` | Revoke a session (authenticated) |

### MFA

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/mfa/verify` | Verify MFA challenge |
| POST | `/api/auth/mfa/enroll` | Enroll TOTP (authenticated) |
| POST | `/api/auth/mfa/activate` | Activate TOTP (authenticated) |
| DELETE | `/api/auth/mfa` | Disable MFA (authenticated) |
| POST | `/api/auth/mfa/backup-codes` | Generate backup codes (authenticated) |
| POST | `/api/passkey/mfa/begin` | Begin MFA passkey challenge |
| POST | `/api/passkey/mfa/complete` | Complete MFA passkey challenge |

### Passkeys

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/passkey/register/begin` | Begin passkey registration (authenticated) |
| POST | `/api/passkey/register/complete` | Complete passkey registration (authenticated) |
| POST | `/api/passkey/login/begin` | Begin passkey login |
| POST | `/api/passkey/login/complete` | Complete passkey login |
| GET | `/api/passkeys` | List passkeys (authenticated) |
| DELETE | `/api/passkeys/:id` | Delete a passkey (authenticated) |

### Social Login

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/auth/social/:provider` | Redirect to social provider |
| GET | `/api/auth/social/:provider/callback` | Social provider callback |

### Verification and Password Reset

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/verify/send` | Send verification code |
| POST | `/api/auth/verify/confirm` | Confirm verification code |
| POST | `/api/auth/password/forgot` | Request password reset |
| POST | `/api/auth/password/reset` | Complete password reset |

### Client Management

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/oauth2/clients` | List OAuth clients (authenticated) |
| POST | `/api/oauth2/clients` | Register OAuth client (authenticated) |
| GET | `/api/oauth2/clients/:client_id` | Get client details (authenticated) |
| PUT | `/api/oauth2/clients/:client_id` | Update client (authenticated) |
| DELETE | `/api/oauth2/clients/:client_id` | Delete client (authenticated) |

### Admin

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/admin/accounts` | List accounts |
| GET | `/api/admin/accounts/:account_id` | Get account |
| DELETE | `/api/admin/accounts/:account_id` | Delete account |
| POST | `/api/admin/accounts/:account_id/disable` | Disable account |
| POST | `/api/admin/accounts/:account_id/enable` | Enable account |
| GET | `/api/admin/accounts/:account_id/roles` | Get account roles |
| POST | `/api/admin/accounts/:account_id/roles` | Add role to account |
| DELETE | `/api/admin/accounts/:account_id/roles/:role_id` | Remove role |

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
docs/                       # OpenAPI spec and Swagger UI
doc/                        # Design decision documents
examples/                   # Usage examples
deploy/                     # Deployment configuration
script/                     # Utility scripts
ssl/                        # TLS certificates
```

Each internal module follows a three-layer architecture: **domain** (models), **repository** (data access), and **service** (business logic).

## Testing

```bash
# Unit tests
make test

# Integration tests (requires docker-test-up)
make docker-test-up
make test-integration
```

Unit tests use `testify/assert`, `go-sqlmock`, and `miniredis`. The CI pipeline requires a minimum of 50% test coverage.

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

---

# gosso

一个基于 Go、Gin、PostgreSQL 和 Redis 构建的自托管 OpenID Connect / OAuth 2.0 身份提供商。

gosso 提供完整的 SSO 服务器，包含 OAuth 2.0 授权、OIDC 发现、JWT 认证、WebAuthn/Passkeys、MFA、社交登录和管理 API，所有功能基于 [gouno](https://github.com/rushairer/gouno) 脚手架的整洁架构代码库。

## 功能特性

**OAuth 2.0**
- 授权码模式 + PKCE（公共客户端强制 S256）
- 刷新令牌
- 客户端凭证模式
- 设备码模式（RFC 8628）
- 令牌撤销和内省（RFC 7009 / RFC 7662）

**OpenID Connect**
- 发现端点（`.well-known/openid-configuration`）
- JWKS 端点（RS256）
- ID Token 签发
- UserInfo 端点
- RP 发起的登出

**认证**
- 用户名/邮箱 + 密码登录（bcrypt）
- WebAuthn / Passkeys（注册和认证）
- 基于 TOTP 的 MFA，支持备份码
- 社交登录（Google、GitHub、微信）
- 邮件密码重置
- 邮箱验证码（手机短信网关暂未接入）

**安全**
- 按端点限流（安全敏感端点 fail-closed，非关键端点 fail-open）
- CSRF 防护中间件
- JWT 认证中间件，带会话验证
- 令牌黑名单
- 结构化审计日志

**运维**
- 健康检查和就绪探针（`/health`、`/readiness`）
- OpenAPI 规范和 Swagger UI（调试模式）
- Docker + docker-compose 支持开发、测试和生产环境
- GitHub Actions CI（lint、单测 50% 覆盖率门槛、govulncheck、集成测试、构建、Docker 构建）

## 前置条件

- Go 1.25.0+
- PostgreSQL 15+
- Redis 7+

## 快速开始

### 构建

```bash
make build
```

生成 `./bin/gosso`。

### 配置

复制环境模板并填入实际值：

```bash
cp .env.development.example .env.development
```

在 `config/config.yaml`（或 `config/development.yaml`、`config/production.yaml`）创建配置文件，结构参考上方英文配置示例。

配置由 Viper 加载。环境变量使用 `GOUNO_` 前缀，`.` 替换为 `_`（如 `GOUNO_AUTH_ISSUER`）。完整参考见 `.env.production.example`。

### 运行

```bash
./bin/gosso web --config ./config/config.yaml --address 0.0.0.0 --port 8080
```

CLI 参数：
- `--config` / `-c`：配置文件路径（默认 `./config/config.yaml`）
- `--address` / `-a`：监听地址（默认 `0.0.0.0`）
- `--port` / `-p`：监听端口（默认 `8080`）
- `--debug` / `-d`：开启调试模式（默认 `false`）

### 开发模式

```bash
make dev
```

需要 [air](https://github.com/air-verse/air) 实现热重载（缺失时自动安装）。

## Docker

```bash
# 开发环境
make docker-dev-up

# 测试环境
make docker-test-up

# 生产环境
make docker-prod-up
```

使用对应的 `make docker-*-down` 停止。

## API 端点

端点分组同上方英文版，此处仅列出主要分类：

- **OIDC**：`/.well-known/openid-configuration`、`/.well-known/jwks.json`
- **OAuth 2.0**：`/oauth2/authorize`、`/oauth2/token`、`/oauth2/revoke`、`/oauth2/introspect`、`/oauth2/device/code`
- **OIDC 用户**：`/oidc/userinfo`、`/oidc/logout`
- **认证**：`/api/auth/login`、`/api/auth/refresh`、`/api/auth/logout`、`/api/auth/session`、`/api/auth/sessions`
- **MFA**：`/api/auth/mfa/verify`、`/api/auth/mfa/enroll`、`/api/auth/mfa/activate`、`/api/auth/mfa/backup-codes`
- **Passkeys**：`/api/passkey/register/*`、`/api/passkey/login/*`、`/api/passkey/mfa/*`、`/api/passkeys`
- **社交登录**：`/api/auth/social/:provider`、`/api/auth/social/:provider/callback`
- **验证和密码重置**：`/api/auth/verify/send`、`/api/auth/verify/confirm`、`/api/auth/password/forgot`、`/api/auth/password/reset`
- **客户端管理**：`/api/oauth2/clients/*`
- **管理后台**：`/api/admin/accounts/*`
- **健康检查**：`/health`、`/readiness`

## 项目结构

同上方英文版。每个内部模块遵循三层架构：**domain**（领域模型）、**repository**（数据访问）、**service**（业务逻辑）。

## 测试

```bash
# 单元测试
make test

# 集成测试（需要先启动 docker-test-up）
make docker-test-up
make test-integration
```

单元测试使用 `testify/assert`、`go-sqlmock` 和 `miniredis`。CI 管线要求最低 50% 测试覆盖率。

## 贡献

欢迎贡献！请参阅 [CONTRIBUTING.md](CONTRIBUTING.md) 了解开发环境搭建、代码规范和 PR 流程。

## 许可证

本项目采用 MIT 许可证。详情见 [LICENSE](LICENSE) 文件。
