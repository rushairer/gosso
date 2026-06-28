# 运维指南

本文档介绍如何在生产环境中部署、监控和运维 gosso。

> [English Version](OPERATOR_GUIDE.md)

---

## 目录

- [部署架构](#部署架构)
- [快速开始（Docker Compose）](#快速开始docker-compose)
- [独立二进制部署](#独立二进制部署)
- [配置参考](#配置参考)
- [健康检查](#健康检查)
- [优雅关闭](#优雅关闭)
- [监控与可观测性](#监控与可观测性)
- [资源规划](#资源规划)
- [备份与恢复](#备份与恢复)
- [故障排查](#故障排查)

---

## 部署架构

```
                    ┌─────────────┐
                    │   客户端    │
                    └──────┬──────┘
                           │ HTTPS :443
                    ┌──────┴──────┐
                    │    Nginx    │  TLS 终止、限流
                    └──────┬──────┘
                           │ HTTP :8080
                    ┌──────┴──────┐
                    │    gosso    │  OIDC / OAuth 2.0 认证提供者
                    └──┬──────┬───┘
                       │      │
              ┌────────┘      └────────┐
              │                        │
       ┌──────┴──────┐          ┌──────┴──────┐
       │ PostgreSQL  │          │    Redis    │
       │    :5432    │          │    :6379    │
       └─────────────┘          └─────────────┘
```

gosso 需要两个后端服务：

- **PostgreSQL 16+** — 账户、凭证、OAuth2 客户端、审计日志、数据库迁移
- **Redis 7+** — 会话管理、限流、令牌黑名单、缓存

所有服务间通信通过私有 Docker 网络，仅 Nginx 对外暴露端口。

---

## 快速开始（Docker Compose）

### 前置条件

- Docker Engine 24+ 和 Docker Compose v2
- 域名和 TLS 证书（或在前方部署 Cloudflare/Caddy 等反向代理）

### 步骤

1. **克隆并配置：**

   ```bash
   git clone https://github.com/rushairer/gosso.git
   cd gosso
   cp .env.production.example .env.production
   ```

2. **编辑 `.env.production`** — 至少设置以下项：
   - `POSTGRES_PASSWORD` — 强随机密码
   - `REDIS_PASSWORD` — 强随机密码
   - `GOUNO_AUTH_ISSUER` — HTTPS 发行者 URL（如 `https://sso.example.com`）
   - `GOUNO_AUTH_VERIFY_HASH_PEPPER` — 随机字符串（密码哈希加盐）
   - `GOUNO_AUTH_TOTP_ENCRYPTION_KEY` — 使用 `openssl rand -hex 32` 生成
   - `GOUNO_CORS_ALLOWED_ORIGINS` — 应用来源（如 `["https://app.example.com"]`）
   - `GOUNO_SMTP_*` — 邮件发送配置

3. **生成 JWT 签名密钥**（如未生成）：

   ```bash
   openssl genrsa -out ssl/private.pem 2048
   openssl rsa -in ssl/private.pem -pubout -out ssl/public.pem
   ```

4. **启动服务：**

   ```bash
   make docker-prod-up
   ```

5. **验证：**

   ```bash
   curl -s http://localhost/readiness | jq .
   # 期望输出: {"status":"ok","ready":true,"checks":{"database":"ok","redis":"ok"}}
   ```

---

## 独立二进制部署

如不使用 Docker：

```bash
# 构建
make build

# 设置环境变量（或使用 config/*.yaml）
export GOUNO_ENV=production
export GOUNO_DATABASE_DRIVERS_POSTGRES_DSN="postgres://user:pass@host:5432/gosso?sslmode=require"
export GOUNO_REDIS_DSN="redis://:pass@host:6379/0"
# ... 其他必要变量

# 先运行数据库迁移，然后启动
./bin/gosso web
```

---

## 配置参考

gosso 使用 Viper 进行配置管理。配置加载顺序：**YAML 文件 → 环境变量**。所有环境变量使用 `GOUNO_` 前缀，`_` 作为分隔符（如 `GOUNO_AUTH_ISSUER` 对应 YAML 中的 `auth.issuer`）。

### 关键生产环境变量

| 变量 | 必填 | 说明 |
|------|------|------|
| `GOUNO_ENV` | ✅ | 设为 `production` |
| `GIN_MODE` | ✅ | 设为 `release` |
| `GOUNO_DATABASE_DRIVERS_POSTGRES_DSN` | ✅ | PostgreSQL 连接字符串 |
| `GOUNO_REDIS_DSN` | ✅ | Redis 连接字符串 |
| `GOUNO_AUTH_ISSUER` | ✅ | OIDC 发行者 URL（必须使用 HTTPS） |
| `GOUNO_AUTH_VERIFY_HASH_PEPPER` | ✅ | 密码哈希加盐 |
| `GOUNO_AUTH_TOTP_ENCRYPTION_KEY` | ✅ | 64 字符十六进制字符串，用于 TOTP 密钥加密 |
| `GOUNO_CORS_ALLOWED_ORIGINS` | ✅ | 允许的 CORS 来源（JSON 数组） |
| `GOUNO_WEB_SERVER_TRUSTED_PROXIES` | ✅ | 可信代理 CIDR（JSON 数组，如 `["172.22.0.0/16"]`） |

### 服务器调优

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `GOUNO_WEB_SERVER_ADDRESS` | `0.0.0.0` | 监听地址 |
| `GOUNO_WEB_SERVER_PORT` | `8080` | 监听端口 |
| `GOUNO_WEB_SERVER_READ_TIMEOUT` | `10s` | HTTP 读取超时 |
| `GOUNO_WEB_SERVER_WRITE_TIMEOUT` | `30s` | HTTP 写入超时 |
| `GOUNO_WEB_SERVER_IDLE_TIMEOUT` | `120s` | HTTP 空闲超时（必须 ≥ read_timeout） |
| `GOUNO_WEB_SERVER_SHUTDOWN_TIMEOUT` | `30s` | 优雅关闭窗口（必须为正数） |
| `GOUNO_WEB_SERVER_MAX_BODY_SIZE` | `10MB` | 最大请求体大小 |
| `GOUNO_WEB_SERVER_REQUEST_TIMEOUT` | `30s` | 单请求处理超时 |

### SMTP（邮件发送）

| 变量 | 说明 |
|------|------|
| `GOUNO_SMTP_HOST` | SMTP 服务器地址 |
| `GOUNO_SMTP_PORT` | SMTP 端口（通常为 587） |
| `GOUNO_SMTP_USERNAME` | SMTP 用户名 |
| `GOUNO_SMTP_PASSWORD` | SMTP 密码 |
| `GOUNO_SMTP_FROM` | 发件人地址（如 `noreply@sso.example.com`） |
| `GOUNO_SMTP_TLS_POLICY` | 生产环境必须为 `mandatory` |

GOSSO 使用 SMTP 发送邮箱验证码和密码重置链接。只有完全不使用这些流程时，SMTP 才可以不配置；一旦配置了 `GOUNO_SMTP_HOST`，系统也会要求配置有效的密码重置基础 URL。

#### 开发环境：Mailpit

开发 Compose 配置使用 Mailpit 作为本地 SMTP 收件箱：

```env
GOUNO_SMTP_HOST=mailpit
GOUNO_SMTP_PORT=1025
GOUNO_SMTP_FROM=noreply@gosso.com
GOUNO_SMTP_TLS_POLICY=notls
GOUNO_AUTH_PASSWORD_RESET_BASE_URL=http://localhost:3000/reset-password
```

Mailpit 在 SMTP `1025` 端口接收邮件，并通过 `http://localhost:8025` 提供 Web 收件箱（或使用已配置的 `MAILPIT_WEB_EXTERNAL_PORT`）。本地可以用它验证邮箱变更验证码和密码重置链接，而不会向外部真实邮箱发信。

#### 生产环境：真实 SMTP

生产环境应使用真实 SMTP 服务商：

```env
GOUNO_SMTP_HOST=smtp.example.com
GOUNO_SMTP_PORT=587
GOUNO_SMTP_USERNAME=your-smtp-user
GOUNO_SMTP_PASSWORD=your-smtp-password
GOUNO_SMTP_FROM=noreply@sso.example.com
GOUNO_SMTP_TLS_POLICY=mandatory
GOUNO_AUTH_PASSWORD_RESET_BASE_URL=https://sso.example.com/reset-password
```

运维注意事项：

- `GOUNO_SMTP_TLS_POLICY` 支持 `mandatory`、`opportunistic`、`notls`；生产环境会拒绝 `notls`。
- 配置 SMTP 后，`GOUNO_AUTH_PASSWORD_RESET_BASE_URL` 必填；生产环境必须使用 HTTPS。
- `GOUNO_SMTP_PASSWORD` 应放在 Secret Manager、Kubernetes Secret 或部署平台密钥中，不要提交到 Git。
- `GOUNO_SMTP_FROM` 应使用已在 SMTP 服务商验证过的发件域名，并配置 SPF/DKIM/DMARC。
- `/readiness` 只检查 PostgreSQL 和 Redis；SMTP 发送失败会在实际发信时记录到应用日志中。

### 可选：OAuth / 社交登录

| 变量 | 说明 |
|------|------|
| `GOUNO_OAUTH_PROVIDERS_GOOGLE_CLIENT_ID` | Google OAuth 客户端 ID |
| `GOUNO_OAUTH_PROVIDERS_GOOGLE_CLIENT_SECRET` | Google OAuth 客户端密钥 |
| `GOUNO_OAUTH_PROVIDERS_GOOGLE_REDIRECT_URI` | Google OAuth 回调 URL |
| `GOUNO_OAUTH_PROVIDERS_GITHUB_CLIENT_ID` | GitHub OAuth 客户端 ID |
| `GOUNO_OAUTH_PROVIDERS_GITHUB_CLIENT_SECRET` | GitHub OAuth 客户端密钥 |
| `GOUNO_OAUTH_PROVIDERS_GITHUB_REDIRECT_URI` | GitHub OAuth 回调 URL |
| `GOUNO_OAUTH_PROVIDERS_WECHAT_CLIENT_ID` | 微信 OAuth 客户端 ID |
| `GOUNO_OAUTH_PROVIDERS_WECHAT_CLIENT_SECRET` | 微信 OAuth 客户端密钥 |
| `GOUNO_OAUTH_PROVIDERS_WECHAT_REDIRECT_URI` | 微信 OAuth 回调 URL |

### 生产环境安全检查

当 `GOUNO_ENV=production` 时，配置校验器强制执行以下规则：

- Auth Issuer URL 必须使用 HTTPS，不能指向 localhost
- SMTP TLS 策略不能为 `notls`
- CORS 允许来源必须显式设置
- 必须配置可信代理
- 必须显式设置数据库 DSN
- TOTP 加密密钥和密码哈希加盐为必填
- 禁止开启调试模式（`DEBUG=true`）

---

## 健康检查

gosso 提供两个健康检查端点：

### 存活探针：`GET /health`

- 进程存活时返回 `200 {"status":"ok"}`
- **不**检查后端依赖（DB/Redis）
- 用于 Kubernetes `livenessProbe` 或 Docker `HEALTHCHECK`
- 限流策略为失败放行（限流检查失败时仍允许请求通过）

### 就绪探针：`GET /readiness`

- 检测 PostgreSQL 和 Redis 连接（每个检查 2 秒超时）
- 两者均可达时返回 `200`：
  ```json
  {"status":"ok","ready":true,"checks":{"database":"ok","redis":"ok"}}
  ```
- 任一不可达时返回 `503`：
  ```json
  {"status":"unavailable","ready":false,"checks":{"database":"ok","redis":"error: ..."}}
  ```
- 用于 Kubernetes `readinessProbe` — 仅在就绪时路由流量

### Docker HEALTHCHECK（内置于 Dockerfile）

```
间隔: 30s | 超时: 10s | 重试: 3 | 启动等待: 40s
命令: wget --no-verbose --tries=1 --spider http://localhost:8080/readiness
```

### Kubernetes 探针配置

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

## 优雅关闭

当 gosso 收到 `SIGTERM` 或 `SIGINT` 信号时，按以下顺序执行关闭：

1. **停止接受新连接** — HTTP 服务器开始排空
2. **等待进行中的请求** — 最长 `ShutdownTimeout`（默认 30 秒）
3. **关闭邮件服务定时器** — 停止后台邮件重试循环
4. **等待后台协程** — 如密码重置后的会话撤销
5. **停止会话缓存清理** — `SessionService.StopCacheCleanup()`
6. **排空审计批次** — 将待处理的审计日志条目刷入数据库
7. **同步日志** — 刷入缓冲的日志条目
8. **退出**

### Docker Compose

```yaml
stop_grace_period: 45s   # 必须大于 ShutdownTimeout
```

### Kubernetes

```yaml
spec:
  terminationGracePeriodSeconds: 45   # 必须大于 ShutdownTimeout
```

### 注意事项

- `ShutdownTimeout` 应**小于**容器/编排平台的宽限期
- 默认 30 秒关闭超时与 45 秒 Docker/K8s 宽限期配合良好
- 关闭期间 `/readiness` 端点将开始返回 503，导致负载均衡器停止路由流量

---

## 监控与可观测性

### Prometheus 指标

在配置中设置 `metrics_enabled: true` 启用指标。指标端点：`GET /metrics`。

| 指标名称 | 类型 | 标签 | 说明 |
|----------|------|------|------|
| `gosso_http_requests_total` | Counter | method, path, status | HTTP 请求总数 |
| `gosso_http_request_duration_seconds` | Histogram | method, path | 请求延迟 |
| `gosso_auth_login_attempts_total` | Counter | result, method | 登录尝试次数（按结果和方式分类） |
| `gosso_rate_limit_exceeded_total` | Counter | endpoint | 被限流拒绝的请求数 |
| `gosso_active_sessions` | Gauge | — | 当前活跃会话数 |
| `gosso_db_pool_open_connections` | Gauge | — | PostgreSQL 打开的连接数 |
| `gosso_db_pool_in_use` | Gauge | — | PostgreSQL 使用中的连接数 |
| `gosso_redis_pool_active_connections` | Gauge | — | Redis 活跃连接数 |

### 推荐告警规则

```yaml
groups:
  - name: gosso
    rules:
      # 高错误率
      - alert: GossoHighErrorRate
        expr: |
          sum(rate(gosso_http_requests_total{status=~"5.."}[5m]))
          / sum(rate(gosso_http_requests_total[5m])) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "gosso 错误率 > 5%"

      # 登录失败激增
      - alert: GossoLoginFailureSpike
        expr: |
          sum(rate(gosso_auth_login_attempts_total{result="failure"}[5m]))
          / sum(rate(gosso_auth_login_attempts_total[5m])) > 0.3
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "gosso 登录失败率 > 30%"

      # 数据库连接池耗尽
      - alert: GossoDBPoolExhausted
        expr: gosso_db_pool_in_use / gosso_db_pool_open_connections > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "gosso 数据库连接池使用率 > 90%"

      # 服务不可用
      - alert: GossoNotReady
        expr: up{job="gosso"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "gosso 实例宕机"
```

### Grafana Dashboard

预构建的 Grafana Dashboard 位于 [`deploy/grafana/gosso-dashboard.json`](../deploy/grafana/gosso-dashboard.json)。通过 Grafana UI → Dashboards → Import 导入。

### 分布式追踪

gosso 支持 OpenTelemetry OTLP HTTP 导出。配置：

| 变量 | 说明 |
|------|------|
| `GOUNO_OBSERVABILITY_TRACING_ENABLED` | 设为 `true` 启用 |
| `GOUNO_OBSERVABILITY_TRACING_ENDPOINT` | OTLP HTTP 端点（如 `http://jaeger:4318`） |

### 结构化日志

生产环境使用 Zap 输出结构化 JSON 日志。

| 变量 | 值 | 说明 |
|------|-----|------|
| `GOUNO_LOGGING_LEVEL` | -1=debug, 0=info, 1=warn, 2=error, 4=dpanic, 5=panic, 6=fatal | 日志级别 |

每个请求包含 `X-Request-ID`（UUID v4）响应头和请求级日志记录器。可用于跨服务日志关联。

**安全提示**：敏感字段（邮箱、手机号、不透明 ID）通过内置脱敏工具自动脱敏。

---

## 资源规划

### 最小生产配置（Docker Compose 默认值）

| 服务 | CPU 上限 | CPU 预留 | 内存上限 | 内存预留 |
|------|----------|----------|----------|----------|
| gosso | 2.0 | 0.5 | 1 GB | 256 MB |
| PostgreSQL | 1.0 | 0.25 | 1 GB | 256 MB |
| Redis | 0.5 | 0.1 | 512 MB | 64 MB |
| Nginx | 0.5 | 0.1 | 256 MB | 64 MB |
| **合计** | **4.0** | **0.95** | **2.75 GB** | **640 MB** |

### 扩容指南

| 用户数 | gosso 副本 | PostgreSQL | Redis |
|--------|-----------|------------|-------|
| < 1,000 | 1 | 单实例 | 单实例 |
| 1,000–10,000 | 2–3 | 主从 | Sentinel 或单实例 |
| 10,000+ | 3+ | 托管服务（RDS/CloudSQL） | 托管服务（ElastiCache/CloudMemorystore） |

Kubernetes 部署请使用提供的 [Helm Chart](../deploy/helm/gosso/) 并配置 HorizontalPodAutoscaler。

---

## 备份与恢复

详见 [BACKUP_RESTORE.md](BACKUP_RESTORE.md) 的 PostgreSQL 备份恢复流程。

### 快速参考

```bash
# 备份
pg_dump -h localhost -U gosso -d gosso -F c -f gosso_$(date +%Y%m%d).dump

# 恢复
pg_restore -h localhost -U gosso -d gosso -c gosso_20260101.dump
```

**Redis** 不需要持久化备份 — 所有 Redis 数据（会话、限流、缓存）均为临时数据，会自动重建。但请确保启用 Redis AOF 持久化（`appendonly yes`），以避免重启时丢失活跃会话。

---

## 故障排查

### 启动失败："HTTPS required"

**原因**：生产模式下 `GOUNO_AUTH_ISSUER` 设置为 `http://` URL。

**修复**：设置 `GOUNO_AUTH_ISSUER=https://sso.example.com`

---

### 启动失败："trusted proxies required"

**原因**：生产环境未配置 `GOUNO_WEB_SERVER_TRUSTED_PROXIES`。

**修复**：设置 `GOUNO_WEB_SERVER_TRUSTED_PROXIES=["172.22.0.0/16"]` 匹配 Docker 网络 CIDR。

---

### 就绪探针返回 503

**原因**：PostgreSQL 或 Redis 不可达。

**排查**：
```bash
# 检查服务是否运行
docker compose ps

# 查看 gosso 日志
docker compose logs gosso --tail 50

# 手动测试连接
docker compose exec postgres pg_isready -U gosso
docker compose exec redis redis-cli ping
```

---

### 内存占用过高

**原因**：大量活跃会话或审计日志堆积。

**排查**：
```bash
# 通过指标检查活跃会话
curl -s http://localhost:8080/metrics | grep gosso_active_sessions

# 检查审计日志表大小
docker compose exec postgres psql -U gosso -c "SELECT pg_size_pretty(pg_total_relation_size('audit_record'));"
```

**修复**：在配置中设置会话数量限制，并建立审计日志轮转/归档机制。

---

### 限流过于严格

**原因**：默认限流策略可能对您的流量模式过于严格。

**当前默认值**：
- 登录：每 IP 5 次/分钟
- Token：每客户端 10 次/分钟
- API：每 IP 60 次/分钟
- Admin：每 IP 30 次/分钟

每个响应都包含限流头信息：
- `X-RateLimit-Limit` — 窗口内最大请求数
- `X-RateLimit-Remaining` — 剩余请求数
- `X-RateLimit-Reset` — 窗口重置时间戳
- `Retry-After` — 需等待秒数（被限流时）
