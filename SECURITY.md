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

- **Password hashing**: Argon2id with pepper, constant-time comparison
- **Token signing**: RS256 with configurable RSA key size (minimum 2048 bits)
- **Rate limiting**: Dual-layer (Nginx + application) with Redis-backed sliding window
- **Session management**: Redis-backed with atomic Lua scripts, bounded in-memory cache
- **Input validation**: Multi-layer (binding tags, service-level, domain-level)
- **Security headers**: CSP with per-request nonces, HSTS, X-Frame-Options, COOP/COEP
- **Audit logging**: Async batch writing with synchronous fallback for security-critical events

## Deployment Security Checklist

- [ ] Use HTTPS in production (`auth.issuer` must use `https://`)
- [ ] Set strong `TOTPEncryptionKey` (32-byte hex, unique per environment)
- [ ] Set strong `VerifyHashPepper` (32-byte hex, unique per environment)
- [ ] Configure explicit CORS origins (no wildcards in production)
- [ ] Set trusted proxies to your actual proxy IPs
- [ ] Use environment variables for all secrets (not config files)
- [ ] Enable Redis password authentication
- [ ] Use PostgreSQL with `sslmode=require` in production
- [ ] Review and rotate RSA signing keys periodically

---

# 安全策略

## 报告漏洞

如果您发现 gosso 的安全漏洞，请负责任地报告。

**请勿为安全漏洞打开公开的 GitHub issue。**

请使用 [GitHub 私密漏洞报告](https://github.com/rushairer/gosso/security/advisories/new) 或发送邮件至 **abensos@163.com**。

## 部署安全检查清单

- [ ] 生产环境使用 HTTPS
- [ ] 设置强 `TOTPEncryptionKey`（32 字节 hex）
- [ ] 设置强 `VerifyHashPepper`（32 字节 hex）
- [ ] 配置明确的 CORS 来源（生产环境不使用通配符）
- [ ] 使用环境变量存储所有密钥
- [ ] 启用 Redis 密码认证
- [ ] PostgreSQL 使用 `sslmode=require`
