# GOSSO API 版本策略

[English](API_VERSIONING.md)

## API 契约边界

应用 API 的路径版本与服务软件发布版本独立。即使 GOSSO 软件已发布到 v1.7.x，应用 API 仍然使用 /api/v1/。只有确实需要不兼容契约变更时，才应引入 /api/v2/。

| 范围 | 正式路径 | 规则 |
|---|---|---|
| 登录与 MFA | /api/v1/auth/* | 应用 API 路径版本化 |
| Passkey | /api/v1/passkey/*、/api/v1/passkeys | 应用 API 路径版本化 |
| OAuth 客户端管理 | /api/v1/oauth2/clients | 应用 API 路径版本化 |
| 管理后台 | /api/v1/admin/* | 应用 API 路径版本化 |
| OAuth2 / OIDC | /oauth2/*、/oidc/*、/.well-known/* | 遵循标准协议与发现地址，不使用应用版本前缀 |
| 基础设施 | /health、/readiness、/metrics | 不使用应用版本前缀 |

协议端点依据已实现的协议标准和互操作性要求演进，不自动随应用路径版本或服务 SemVer 变化。

## 历史无版本路径兼容

旧路径 /api/auth/*、/api/admin/*、/api/passkey/*、/api/passkeys 及其子路径、/api/oauth2/clients 及其子路径，返回 HTTP 308 Permanent Redirect，跳转到对应 /api/v1 路径。保留请求方法与原始查询参数；重定向发生在 CSRF 之前，但正式端点仍完整执行 CSRF、认证、授权和限流。重定向本身不执行业务操作。

未知 /api/* 路径、未来的 /api/v2/* 以及标准协议端点均不重定向。客户端应直接调用正式路径；并非所有 HTTP 客户端都能在跳转过程中一致地转发请求体和 Authorization 头。

## 版本演进与弃用

- 兼容性新增可继续扩展当前应用 API v1。
- 不兼容契约变更需要明确引入新前缀（例如 /api/v2/）并提供迁移说明；不自动从 v1 跳转到 v2。
- 正式 API 版本弃用需公告、至少六个月的迁移窗口及适用的 Sunset 响应头。HTTP 410 Gone 只有在明确实现并发布之后才生效。
- 历史**无版本路径**目前为过渡兼容入口，尚未宣布删除日期。

## 权威实现与文档

- [ADR-0004](ADR/0004-api-versioning.md) 记录原始架构决策。
- router/web.go 注册正式路由；middleware/api_version_redirect.go 在 CSRF 之前处理兼容跳转。
- docs/openapi.yaml 描述正式 API 契约；[API 稳定性](api-stability.md) 定义支持级别。

当前应用 API 路径版本：**v1**。
