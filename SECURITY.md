# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in gosso, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please use [GitHub Private Vulnerability Reporting](https://github.com/rushairer/gosso/security/advisories/new) or email **abensos@163.com** with:

- A description of the vulnerability
- Steps to reproduce the issue
- The potential impact
- Any suggested fixes (if applicable)

You should receive a response within 48 hours. We will work with you to understand the issue and coordinate a fix before any public disclosure.

## Security Considerations

gosso is a production SSO server handling authentication credentials, OAuth2 tokens, and user sessions. Key security measures:

- **Password hashing**: Argon2id with a per-password random salt; password verification uses the encoded Argon2id parameters stored with the hash. `VerifyHashPepper` protects verification-code hashes and is not a password pepper.
- **Token signing**: RS256 with configurable RSA key size (minimum 2048 bits), `kid`-based verification, and active/retained public-key overlap for signing-key rotation.
- **Token principals**: User sessions, delegated users, and `client_credentials` machine clients are distinct principals; machine tokens do not inherit the registering account's authority.
- **Resource binding**: OAuth access tokens are bound to the selected RFC 8707 resource; resource servers must validate their expected audience.
- **Rate limiting**: Redis-backed application rate limits protect authentication and protocol endpoints.
- **Session management**: Redis-backed with atomic Lua scripts, bounded in-memory cache, server-side revocation checks, and opaque browser session cookies.
- **Input validation**: Multi-layer (binding tags, service-level, domain-level).
- **Security headers**: CSP with per-request nonces, HSTS, X-Frame-Options, COOP/CORP, and restrictive Permissions Policy.
- **Audit logging**: Async batch writing with synchronous fallback for security-critical events.
- **Back-channel egress**: OIDC Back-Channel Logout permits public IP targets by default; private targets require an explicit CIDR/IP allow policy, while loopback/link-local/metadata/multicast targets remain hard-denied.

## Signing-Key Rotation

Use a unique `auth.key_id` for each active signing key. During a rotation, retain only the **old public key** and configure:

- `GOUNO_AUTH_PREVIOUS_PUBLIC_KEY_PATH=/path/to/old-public.pem`
- `GOUNO_AUTH_PREVIOUS_KEY_ID=<old-kid>`

Then deploy the new active private key with its new `auth.key_id`. Gosso publishes and verifies both active and retained public keys during the overlap. After all tokens/sign-out hints that can reference the old key are outside the accepted retention window, remove the two previous-key environment variables and redeploy. Do not reuse a `kid` for different key material.

## Deployment Security Checklist

- [ ] Use HTTPS in production (`auth.issuer` must use `https://`).
- [ ] Set strong `TOTPEncryptionKey` (32-byte hex, unique per environment).
- [ ] Set strong `VerifyHashPepper` (32-byte hex, unique per environment) for verification-code hashing.
- [ ] Configure explicit CORS origins (no wildcards in production).
- [ ] Set trusted proxies to your actual proxy IPs.
- [ ] Store private keys and application secrets outside source-controlled config.
- [ ] Enable Redis password authentication.
- [ ] Use PostgreSQL with `sslmode=require` in production.
- [ ] Use a unique RSA signing `kid` per key and retain the old public key during rotation overlap.
- [ ] Configure `backchannel_allowed_cidrs` only for explicitly trusted internal targets; leave it empty for public-only egress.
- [ ] For `client_credentials`, register and request an explicit RFC 8707 `resource` and validate the matching audience at the resource server.

---

# 安全策略

## 报告漏洞

如果您发现 gosso 的安全漏洞，请负责任地报告。

**请勿为安全漏洞打开公开的 GitHub issue。**

请使用 [GitHub 私密漏洞报告](https://github.com/rushairer/gosso/security/advisories/new) 或发送邮件至 **abensos@163.com**。

## 部署安全检查清单

- [ ] 生产环境使用 HTTPS。
- [ ] 设置强 `TOTPEncryptionKey`（32 字节 hex）。
- [ ] 设置强 `VerifyHashPepper`（32 字节 hex，仅用于验证码/验证哈希，不是密码 pepper）。
- [ ] 配置明确的 CORS 来源（生产环境不使用通配符）。
- [ ] 私钥和应用密钥不得写入源码仓库。
- [ ] 启用 Redis 密码认证。
- [ ] PostgreSQL 使用 `sslmode=require`。
- [ ] RSA 签名密钥轮换时必须使用新的 `kid`，并在重叠窗口仅保留旧公钥用于验证/JWKS。
- [ ] Back-Channel Logout 默认只允许公网目标，私网目标必须显式加入 `backchannel_allowed_cidrs`。
- [ ] `client_credentials` 必须请求已登记的 RFC 8707 `resource`，资源服务器必须校验 `aud`。
