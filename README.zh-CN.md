# gosso

[English](./README.md)

[![CI](https://github.com/rushairer/gosso/actions/workflows/ci.yml/badge.svg)](https://github.com/rushairer/gosso/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/rushairer/gosso)](https://goreportcard.com/report/github.com/rushairer/gosso)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

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
- GitHub Actions CI（lint、覆盖率门禁包集合最低 60% 覆盖率、关键服务包覆盖率门禁、govulncheck、集成测试、构建、Docker 构建）

## 前置条件

- Go 1.26.0+
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

然后创建或更新环境专属的配置 YAML 文件，如 `config/development.yaml` 或 `config/production.yaml`：

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
  totp_encryption_key: "00000000000000000000000000000000"  # 32 字节十六进制 -- 请使用真实密钥
  default_scopes:
    - openid
    - profile
    - email
```

配置由 Viper 加载。环境变量使用 `GOUNO_` 前缀，`.` 替换为 `_`（如 `GOUNO_AUTH_ISSUER`）。完整参考见 `.env.production.example`。

### 运行

```bash
./bin/gosso web --config ./config --env development --address 0.0.0.0 --port 8080
```

CLI 参数：
- `--config` / `-c`：配置目录路径（默认 `./config`）
- `--env` / `-e`：配置环境名称，例如 `development`、`test` 或 `production`（默认 `production`）
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

本仓库根目录提供一套本地管理台编排（`../docker-compose.yml`）：启动后访问 `http://localhost:8080`，默认管理员为 `admin` / `admin123`。登录管理台后进入 **User Accounts**，点击 **Add User** 可创建普通用户账号；如需授予管理员权限，再通过 **Roles** 分配 `admin` 角色。

用户自助安全功能走认证域接口：修改自己的密码使用 `/api/v1/auth/password/change`，TOTP MFA 使用 `/api/v1/auth/mfa/*`，Passkey 使用 `/api/v1/passkey/*`。管理员代管他人账号的创建、启用/禁用、删除、重置密码和角色分配保留在 `/api/v1/admin/*`。

生产环境启动前，先复制 `.env.production.example` 到 `.env.production`，填写真实值，并将 RSA 私钥放到 `./keys/private.pem`，容器内挂载路径为 `/app/keys/private.pem`。生产环境变量文件由 Docker Compose 读取，请保持 `KEY=value` 格式。内置 Postgres 服务默认使用 `sslmode=disable`；只有连接已配置 TLS 的数据库时才切换为 `sslmode=require`。

使用对应的 `make docker-*-down` 停止。

## API 端点

### OIDC 发现和 JWKS

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/.well-known/openid-configuration` | OIDC 发现文档 |
| GET | `/.well-known/jwks.json` | JSON Web Key Set |

### OAuth 2.0

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/oauth2/authorize` | 授权端点（需要 JWT 认证） |
| POST | `/oauth2/authorize` | 提交授权同意 |
| POST | `/oauth2/token` | 令牌端点 |
| POST | `/oauth2/revoke` | 令牌撤销 |
| POST | `/oauth2/introspect` | 令牌内省 |
| POST | `/oauth2/device/code` | 设备授权 |
| GET | `/oauth2/device` | 设备码用户验证页面 |
| POST | `/oauth2/device` | 设备码用户验证提交 |

### OIDC

| 方法 | 路径 | 描述 |
|------|------|------|
| GET/POST | `/oidc/userinfo` | UserInfo 端点 |
| POST | `/oidc/logout` | RP 发起的登出 |

### 认证

| 方法 | 路径 | 描述 |
|------|------|------|
| POST | `/api/auth/login` | 用户名/密码登录 |
| POST | `/api/auth/refresh` | 刷新访问令牌 |
| POST | `/api/auth/logout` | 登出（已认证） |
| GET | `/api/auth/session` | 当前会话信息（已认证） |
| GET | `/api/auth/sessions` | 会话列表（已认证） |
| DELETE | `/api/auth/sessions/:id` | 撤销会话（已认证） |
| POST | `/api/auth/password/change` | 修改自己的密码（已认证） |

### 管理 API

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/api/admin/accounts` | 账号列表（管理员） |
| POST | `/api/admin/accounts` | 创建用户账号（管理员） |
| POST | `/api/admin/accounts/:account_id/password` | 重置用户密码（管理员，不能用于自己） |
| POST | `/api/admin/accounts/:account_id/disable` | 禁用用户账号（管理员，不能用于自己） |
| POST | `/api/admin/accounts/:account_id/enable` | 启用用户账号（管理员，不能用于自己） |
| POST | `/api/admin/accounts/:account_id/roles` | 分配角色（管理员，不能用于自己） |
| DELETE | `/api/admin/accounts/:account_id/roles/:role_id` | 移除角色（管理员，不能用于自己） |

### MFA

| 方法 | 路径 | 描述 |
|------|------|------|
| POST | `/api/auth/mfa/verify` | 验证 MFA 挑战 |
| POST | `/api/auth/mfa/enroll` | 注册 TOTP（已认证） |
| POST | `/api/auth/mfa/activate` | 激活 TOTP（已认证） |
| DELETE | `/api/auth/mfa` | 禁用 MFA（已认证） |
| POST | `/api/auth/mfa/backup-codes` | 生成备份码（已认证） |
| POST | `/api/passkey/mfa/begin` | 开始 MFA Passkey 挑战 |
| POST | `/api/passkey/mfa/complete` | 完成 MFA Passkey 挑战 |

### Passkeys

| 方法 | 路径 | 描述 |
|------|------|------|
| POST | `/api/passkey/register/begin` | 开始 Passkey 注册（已认证） |
| POST | `/api/passkey/register/complete` | 完成 Passkey 注册（已认证） |
| POST | `/api/passkey/login/begin` | 开始 Passkey 登录 |
| POST | `/api/passkey/login/complete` | 完成 Passkey 登录 |
| GET | `/api/passkeys` | Passkey 列表（已认证） |
| DELETE | `/api/passkeys/:id` | 删除 Passkey（已认证） |

### 社交登录

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/api/auth/social/:provider` | 重定向到社交登录提供商 |
| GET | `/api/auth/social/:provider/callback` | 社交登录提供商回调 |

### 验证和密码重置

| 方法 | 路径 | 描述 |
|------|------|------|
| POST | `/api/auth/verify/send` | 发送邮箱验证码（手机号在 SMS 配置完成前返回 501） |
| POST | `/api/auth/verify/confirm` | 确认验证码 |
| POST | `/api/auth/password/forgot` | 请求密码重置 |
| POST | `/api/auth/password/reset` | 完成密码重置 |

### 客户端管理

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/api/oauth2/clients` | OAuth 客户端列表（已认证） |
| POST | `/api/oauth2/clients` | 注册 OAuth 客户端（已认证） |
| GET | `/api/oauth2/clients/:client_id` | 获取客户端详情（已认证） |
| PUT | `/api/oauth2/clients/:client_id` | 更新客户端（已认证） |
| DELETE | `/api/oauth2/clients/:client_id` | 删除客户端（已认证） |

### 管理后台

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/api/admin/accounts` | 账户列表 |
| GET | `/api/admin/accounts/:account_id` | 获取账户 |
| DELETE | `/api/admin/accounts/:account_id` | 删除账户 |
| POST | `/api/admin/accounts/:account_id/disable` | 禁用账户 |
| POST | `/api/admin/accounts/:account_id/enable` | 启用账户 |
| GET | `/api/admin/accounts/:account_id/roles` | 获取账户角色 |
| POST | `/api/admin/accounts/:account_id/roles` | 为账户添加角色 |
| DELETE | `/api/admin/accounts/:account_id/roles/:role_id` | 移除角色 |

### 健康检查

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/health` | 存活检查 |
| GET | `/readiness` | 就绪检查（数据库 + Redis） |

## 项目结构

```
cmd/                        # 应用入口
  main.go
  gouno/                    # CLI 命令（root、web、migrate）
config/                     # 配置结构体和加载器
router/                     # 路由注册
middleware/                  # 全局中间件（CSRF、限流、日志、请求 ID）
internal/
  account/                  # 账户、凭证、联邦身份、角色
  admin/                    # 管理控制器
  audit/                    # 审计日志
  auth/                     # 登录、MFA、Passkeys、社交登录、密码重置、验证
  cache/                    # Redis 客户端
  db/                       # 数据库事务辅助工具
  notification/             # 邮件和短信服务
  oauth2/                   # OAuth 2.0 授权、令牌、撤销、设备码、客户端管理
  oidc/                     # OIDC 发现、JWKS、ID Token、UserInfo、登出
  session/                  # 会话领域和服务
  token/                    # 令牌服务、密钥服务、黑名单
  testutil/                 # 共享测试辅助工具
  utility/                  # JSON、日志、脱敏、密码、手机号工具
db/                         # 数据库迁移文件
docs/                       # OpenAPI 规范和 Swagger UI
doc/                        # 设计决策文档
examples/                   # 使用示例
deploy/                     # 部署配置
script/                     # 工具脚本
ssl/                        # TLS 证书
```

每个内部模块遵循三层架构：**domain**（领域模型）、**repository**（数据访问）、**service**（业务逻辑）。

## 测试

```bash
# 单元测试
make test

# 集成测试（需要先启动 docker-test-up）
make docker-test-up
make test-integration
```

单元测试使用 `testify/assert`、`go-sqlmock` 和 `miniredis`。CI 管线对覆盖率门禁包集合要求最低 60% 测试覆盖率，并对 auth、OAuth2、OIDC、token、session 等关键服务包设置单包覆盖率门禁。

## 配置参考

配置由 [Viper](https://github.com/spf13/viper) 管理，配置结构体定义在 `config/config.go` 中，类型为 `GoUnoConfig`。

| 配置段 | 关键字段 | 环境变量前缀示例 |
|--------|----------|------------------|
| `web_server` | address、port、debug、timeouts、max_body_size、trusted_proxies、rate_limits | `GOUNO_WEB_SERVER_ADDRESS` |
| `database` | 默认驱动、驱动映射、连接池设置 | `GOUNO_DATABASE_DRIVERS_POSTGRES_DSN` |
| `redis` | dsn、max_active_conns、pool_timeout_seconds | `GOUNO_REDIS_DSN` |
| `auth` | issuer、令牌过期时间、session_ttl、private_key_path、key_id、WebAuthn、TOTP、MFA、密码重置、验证设置 | `GOUNO_AUTH_ISSUER` |
| `cors` | allowed_origins、methods、headers、credentials、max_age | `GOUNO_CORS_ALLOWED_ORIGINS` |
| `smtp` | host、port、username、password、from、tls_policy | `GOUNO_SMTP_HOST` |
| `oauth_providers` | google、github、wechat（client_id、client_secret、redirect_uri、scopes） | `GOUNO_OAUTH_PROVIDERS_GOOGLE_CLIENT_ID` |
| `task_pipeline` | flush_size、buffer_size、flush_interval | `GOUNO_TASK_PIPELINE_FLUSH_SIZE` |
| `log` | level（-1=debug、0=info、1=warn、2=error） | `GOUNO_LOG_LEVEL` |

环境变量会覆盖配置文件中的值。前缀为 `GOUNO_`，`.` 替换为 `_`。

## Makefile 命令

| 命令 | 描述 |
|------|------|
| `make build` | 构建二进制文件到 `./bin/gosso` |
| `make run` | 构建并运行 |
| `make dev` | 热重载开发模式（需要 air） |
| `make lint` | 运行 golangci-lint |
| `make lint-fix` | 运行 golangci-lint 并自动修复 |
| `make test` | 运行单元测试 |
| `make test-integration` | 运行集成测试 |
| `make docker-dev-up` | 启动开发 Docker 环境 |
| `make docker-test-up` | 启动测试 Docker 环境 |
| `make docker-prod-up` | 启动生产 Docker 环境 |
| `make examples` | 运行所有示例 |
| `make help` | 显示所有可用命令 |

## 依赖项目

- [gouno](https://github.com/rushairer/gouno) -- Go Web 应用脚手架
- [Gin](https://github.com/gin-gonic/gin) -- HTTP 框架
- [Cobra](https://github.com/spf13/cobra) + [Viper](https://github.com/spf13/viper) -- CLI 和配置管理
- [golang-jwt](https://github.com/golang-jwt/jwt) -- JWT 签发和验证
- [go-webauthn](https://github.com/go-webauthn/webauthn) -- WebAuthn/Passkey 支持
- [pgx](https://github.com/jackc/pgx) -- PostgreSQL 驱动
- [go-redis](https://github.com/redis/go-redis/v9) -- Redis 客户端
- [zap](https://go.uber.org/zap) -- 结构化日志

## 贡献

欢迎贡献！请参阅 [CONTRIBUTING.md](CONTRIBUTING.md) 了解开发环境搭建、代码规范和 PR 流程。

## 许可证

本项目采用 MIT 许可证。详情见 [LICENSE](LICENSE) 文件。
