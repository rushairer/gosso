# SSO 系统开发工作清单

## 项目概述
基于 Go + Gin 框架构建企业级 SSO (单点登录) 系统，支持 OAuth 2.1 / OIDC 协议，提供统一认证与授权服务。

---

## 阶段一：基础设施与核心框架 (第 1-2 周)

### ✅ 1. 项目初始化（已完成）
- [x] 基础 Gin 框架搭建
- [x] 配置管理（Viper）
- [x] 日志系统（Zap）
- [x] 数据库迁移工具
- [x] 审计日志模块

### 🔲 2. 数据库设计与账号基础模块
**知识点**: PostgreSQL、UUID、JSONB、数据库索引、密码哈希（bcrypt/argon2）、复合索引

- [ ] 设计核心账号表（accounts）
  - 字段：id (UUID), username (VARCHAR(50), UNIQUE), display_name (VARCHAR(100)), avatar_url (TEXT), status (VARCHAR(20)), locale (VARCHAR(10)), timezone (VARCHAR(50)), metadata (JSONB), created_at, updated_at
  - 索引：username（条件索引，WHERE username IS NOT NULL）
  - 说明：仅存储账号身份信息，不包含认证凭证
- [ ] 设计认证凭证表（account_credentials）
  - 字段：id (UUID), account_id (UUID FK), credential_type (VARCHAR(20)), identifier (VARCHAR(255)), credential_value (TEXT), verified (BOOLEAN), primary_credential (BOOLEAN), metadata (JSONB), created_at, verified_at, last_used_at
  - credential_type 枚举：password, email, phone, totp, webauthn
  - 复合唯一索引：(credential_type, identifier)
  - 索引：account_id, (credential_type, verified)
  - 说明：支持一个账号多个凭证，灵活扩展认证方式
- [ ] 设计第三方身份关联表（federated_identities）
  - 字段：id (UUID), account_id (UUID FK), provider (VARCHAR(50)), provider_user_id (VARCHAR(255)), profile (JSONB), created_at
  - 唯一索引：(provider, provider_user_id)
  - 说明：管理 Google、GitHub、微信等第三方登录
- [ ] 设计群组表（groups）
  - 字段：id (UUID), name (VARCHAR(100)), description (TEXT), parent_id (UUID), metadata (JSONB), created_at, updated_at
  - 索引：parent_id（支持树形结构）
- [ ] 设计角色表（roles）
  - 字段：id (UUID), name (VARCHAR(50), UNIQUE), description (TEXT), permissions (JSONB), metadata (JSONB), created_at, updated_at
- [ ] 设计账号角色关联表（account_roles）
  - 多对多关系：account_id (UUID FK), role_id (UUID FK)
  - 主键：(account_id, role_id)
  - 索引：account_id, role_id
- [ ] 设计账号群组关联表（account_groups）
  - 多对多关系：account_id (UUID FK), group_id (UUID FK)
  - 主键：(account_id, group_id)
  - 索引：account_id, group_id
- [ ] 编写数据库迁移脚本（db/migrations/0002_accounts.up.sql）
  - 包含所有表定义、索引、外键约束
  - 添加 ON DELETE CASCADE 级联删除
- [ ] 创建账号领域模型（internal/account/domain/account.go）
  - Account 结构体
  - Credential 结构体
  - FederatedIdentity 结构体
- [ ] 实现账号仓储接口（internal/account/repository/account_repository.go）
  - FindByID, FindByUsername, FindByCredential
  - CreateAccount, UpdateAccount, DeleteAccount
  - AddCredential, VerifyCredential, RemoveCredential
  - LinkFederatedIdentity, UnlinkFederatedIdentity

**参考文档**:
- PostgreSQL 官方文档
- Go database/sql 包
- jackc/pgx 驱动文档

---

### 🔲 3. Redis 缓存与会话存储
**知识点**: Redis、Session 管理、TTL、键设计模式

- [ ] 配置 Redis 连接池（已有配置，需实现连接层）
- [ ] 实现 Redis 客户端封装（internal/cache/redis_client.go）
- [ ] 实现会话存储服务（internal/session/service/session_service.go）
  - 会话创建、读取、更新、删除
  - 会话 TTL 管理
- [ ] 实现验证码缓存服务（internal/captcha/service/captcha_service.go）
  - 验证码生成与验证
  - 防重放攻击
- [ ] 实现 Token 黑名单服务（internal/token/service/blacklist_service.go）

**参考文档**:
- Redis 官方文档
- go-redis/redis 库文档

---

### 🔲 4. 密钥管理与 JWKS
**知识点**: RSA/ECDSA、JWT、JWKS、密钥轮换、PEM 格式

- [ ] 设计密钥表（crypto_keys）
  - 字段：id, kid, algorithm, public_key, private_key, status, created_at, rotated_at
- [ ] 编写数据库迁移脚本（db/migrations/0003_crypto_keys.up.sql）
- [ ] 实现密钥生成工具（internal/crypto/keygen.go）
  - RSA-2048/4096 密钥生成
  - ES256 密钥生成
- [ ] 实现密钥管理服务（internal/crypto/service/key_service.go）
  - 密钥创建、存储、轮换
  - 密钥状态管理（active/retired）
- [ ] 实现 JWKS 端点（router/oidc.go）
  - GET /.well-known/jwks.json
  - 返回公钥集合
- [ ] 实现密钥轮换定时任务（internal/crypto/task/key_rotation.go）

**参考文档**:
- RFC 7517 (JSON Web Key)
- RFC 7518 (JWA)
- golang-jwt/jwt 库

---

## 阶段二：认证模块 (第 3-4 周)

### 🔲 5. 账号注册与密码管理
**知识点**: 密码强度验证、邮箱验证、手机验证、SMTP、bcrypt

- [ ] 实现账号注册 API（internal/authn/handler/register_handler.go）
  - POST /api/v1/auth/register
  - 创建 account 记录
  - 添加 email/phone 凭证到 account_credentials
  - 添加 password 凭证（bcrypt hash）
  - 密码强度校验（8+ 字符，大小写+数字+特殊字符）
  - 验证码验证
- [ ] 实现邮箱验证服务（internal/authn/service/email_verification.go）
  - 发送验证邮件（包含验证链接）
  - 验证 Token 校验（JWT 或 随机 Token）
  - 更新 account_credentials.verified = true
- [ ] 实现手机验证服务（internal/authn/service/phone_verification.go）
  - 短信验证码发送（接入阿里云/腾讯云 SMS）
  - 验证码校验（6 位数字，5 分钟有效）
  - 更新 account_credentials.verified = true
- [ ] 实现密码重置功能
  - POST /api/v1/auth/password/reset/request（请求重置）
    - 通过 email/phone 凭证查找账号
    - 发送重置链接/验证码
  - POST /api/v1/auth/password/reset/confirm（确认重置）
    - 验证 Token/验证码
    - 更新 password 凭证的 credential_value
- [ ] 实现密码修改功能
  - POST /api/v1/auth/password/change（已登录账号修改密码）
    - 验证旧密码
    - 更新 password 凭证

**参考文档**:
- OWASP 密码强度指南
- SMTP 协议
- 阿里云短信服务 SDK / 腾讯云短信 SDK

---

### 🔲 6. 本地登录与会话管理
**知识点**: Cookie、HttpOnly、SameSite、CSRF、会话固定攻击、凭证查询

- [ ] 实现账号登录 API（internal/authn/handler/login_handler.go）
  - POST /api/v1/auth/login
  - 支持多种登录方式：
    - 用户名 + 密码：通过 username 查找账号
    - 邮箱 + 密码：通过 email 凭证查找账号
    - 手机号 + 密码：通过 phone 凭证查找账号
  - 查询逻辑：JOIN account_credentials 表，验证 verified = true
  - 密码验证：从 password 类型凭证获取 credential_value，bcrypt 比对
  - 验证码校验（可选，登录失败 3 次后强制）
  - 登录失败次数限制（防暴力破解，Redis 计数）
  - 更新 account_credentials.last_used_at
- [ ] 实现会话创建与 Cookie 设置
  - HttpOnly, Secure, SameSite=Lax
  - 会话 ID 生成（UUID v4）
  - Redis 存储会话数据（key: session:{id}, value: account_id + metadata）
  - TTL 设置（默认 24 小时）
- [ ] 实现登录中间件（middleware/auth_middleware.go）
  - 从 Cookie 读取 session_id
  - Redis 验证会话有效性
  - 加载账号信息到 Context
  - 刷新会话过期时间（滑动窗口）
- [ ] 实现登出 API
  - POST /api/v1/auth/logout
  - 清除会话 Cookie（Max-Age=-1）
  - 删除 Redis 会话
- [ ] 实现"记住我"功能
  - 长期会话 Token（7/30 天）
  - 独立的 remember_token 存储（account_credentials 表，新类型）
  - 设备指纹绑定（存储在 credential_value）

**参考文档**:
- OWASP Session Management Cheat Sheet
- MDN Web Docs - HTTP Cookies

---

### 🔲 7. 多因素认证（MFA）
**知识点**: TOTP、HOTP、RFC 6238、QR Code、备用码

- [ ] 设计 MFA 凭证（复用 account_credentials 表）
  - credential_type = 'totp'：TOTP 密钥
  - credential_type = 'backup_code'：备用码（多条记录）
  - identifier：备用码值（用于查找）
  - credential_value：TOTP secret（Base32 编码）或备用码 hash
  - metadata：存储 QR Code URI、使用记录等
- [ ] 实现 TOTP 服务（internal/mfa/service/totp_service.go）
  - 生成 TOTP 密钥（32 字节随机数，Base32 编码）
  - 生成 QR Code URI（otpauth://totp/SSO:user@example.com?secret=...&issuer=SSO）
  - 验证 TOTP 码（6 位数字，允许 ±1 时间窗口容错）
  - 防重放攻击（Redis 记录已使用的 TOTP 码）
- [ ] 实现 MFA 启用 API
  - POST /api/v1/auth/mfa/totp/enable
    - 生成 TOTP secret
    - 插入 account_credentials 记录（verified=false）
    - 返回 QR Code 和备用码（10 个随机码）
  - POST /api/v1/auth/mfa/totp/verify-enable
    - 验证用户输入的 TOTP 码
    - 更新 verified=true，enabled=true
- [ ] 实现 MFA 验证 API
  - POST /api/v1/auth/mfa/verify
    - 登录流程集成：密码验证通过后，检查是否启用 MFA
    - 验证 TOTP 码或备用码
    - MFA 验证通过后创建完整会话
- [ ] 实现备用码管理
  - 生成备用码：10 个 8 位随机字符串
  - 使用后标记（metadata 记录使用时间）
  - 重新生成：POST /api/v1/auth/mfa/backup-codes/regenerate

**参考文档**:
- RFC 6238 (TOTP)
- pquerna/otp 库文档
- Google Authenticator 协议

---

### 🔲 8. 第三方登录（Social Login）
**知识点**: OAuth 2.0、OpenID Connect、授权码流程、Redirect URI

- [ ] 设计外部身份提供商配置表（identity_providers）
  - 字段：id, name, type(google/github/wechat), client_id, client_secret, config(jsonb), enabled, created_at
  - 说明：管理员配置的第三方登录平台
- [ ] 使用已有的 federated_identities 表（在任务 2 中已设计）
  - 字段：id, account_id, provider, provider_user_id, profile(jsonb), created_at
  - 唯一索引：(provider, provider_user_id)
  - 说明：记录账号与第三方身份的绑定关系
- [ ] 实现 OAuth2 客户端封装（internal/federation/oauth2_client.go）
  - 授权 URL 生成（构建 state 参数，Redis 临时存储）
  - Token 交换（authorization_code -> access_token）
  - 用户信息获取（调用第三方 UserInfo 端点）
- [ ] 实现 Google OAuth2 登录
  - GET /api/v1/auth/oauth2/google/authorize
    - 重定向到 Google 授权页面
  - GET /api/v1/auth/oauth2/google/callback
    - 接收 code，交换 token
    - 获取 Google 用户信息（email, name, picture）
    - 查找或创建账号：
      - 通过 email 凭证查找现有账号
      - 不存在则创建新账号 + email 凭证
      - 插入 federated_identities 记录
    - 创建登录会话
- [ ] 实现 GitHub OAuth2 登录
  - GET /api/v1/auth/oauth2/github/authorize
  - GET /api/v1/auth/oauth2/github/callback
    - 类似 Google 流程，使用 GitHub API
- [ ] 实现账号关联/解绑功能
  - POST /api/v1/user/federated-identities/link
    - 已登录账号绑定第三方身份
    - 检查第三方身份是否已被其他账号使用
  - DELETE /api/v1/user/federated-identities/{provider}
    - 解绑第三方身份
    - 至少保留一种登录方式（email/phone 或 password）

**参考文档**:
- OAuth 2.0 RFC 6749
- Google Identity Platform
- GitHub OAuth Apps
- golang.org/x/oauth2 库

---

## 阶段三：OAuth 2.1 / OIDC 授权服务器 (第 5-7 周)

### 🔲 9. 客户端（Relying Party）管理
**知识点**: OAuth 2.0 Client Types、Redirect URI 验证、Client Credentials

- [ ] 设计客户端表（oauth2_clients）
  - 字段：client_id, client_secret_hash, name, type(public/confidential), redirect_uris(jsonb), allowed_scopes(jsonb), pkce_required, grant_types(jsonb), token_endpoint_auth_method, created_at
- [ ] 编写数据库迁移脚本（db/migrations/0006_oauth2_clients.up.sql）
- [ ] 实现客户端管理 API（internal/oauth2/handler/client_handler.go）
  - POST /api/v1/oauth2/clients（创建客户端）
  - GET /api/v1/oauth2/clients/{client_id}（查询客户端）
  - PUT /api/v1/oauth2/clients/{client_id}（更新客户端）
  - DELETE /api/v1/oauth2/clients/{client_id}（删除客户端）
- [ ] 实现客户端认证服务（internal/oauth2/service/client_auth_service.go）
  - client_secret_basic
  - client_secret_post
  - Redirect URI 验证

**参考文档**:
- OAuth 2.1 Draft
- RFC 6749 Section 2

---

### 🔲 10. 授权码流程（Authorization Code + PKCE）
**知识点**: PKCE、code_challenge、code_verifier、S256/plain

- [ ] 设计授权码表（authorization_codes）
  - 字段：code, client_id, account_id, redirect_uri, scopes(jsonb), code_challenge, code_challenge_method, nonce, expires_at, used_at
  - 索引：code（唯一）
  - 说明：授权码短期有效（5 分钟），一次性使用
- [ ] 编写数据库迁移脚本（db/migrations/0007_authorization_codes.up.sql）
- [ ] 实现授权端点（internal/oauth2/handler/authorize_handler.go）
  - GET/POST /oauth2/authorize
  - 参数验证：client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method, nonce
  - 检查账号登录状态（从 session 读取 account_id）
  - 未登录：跳转到登录页面（保存请求参数到 session）
  - 已登录：跳转到授权同意页面
- [ ] 实现授权同意页面（前端）
  - 显示客户端信息（名称、Logo、描述）
  - 显示请求的 Scopes（翻译为易懂的权限描述）
  - 用户同意/拒绝按钮
- [ ] 实现授权码生成与存储
  - 生成唯一授权码（32 字节随机数，Base64URL 编码）
  - 关联 PKCE 参数（code_challenge, code_challenge_method）
  - 存储到 authorization_codes 表（expires_at: 5 分钟后）
  - 重定向到 redirect_uri?code=...&state=...
- [ ] 实现 Token 端点（internal/oauth2/handler/token_handler.go）
  - POST /oauth2/token
  - grant_type=authorization_code
  - 验证授权码（未过期、未使用）
  - 验证 code_verifier（PKCE，计算 SHA256 并 Base64URL 编码后与 code_challenge 比对）
  - 验证 client_id、redirect_uri 一致性
  - 签发 Access Token 和 Refresh Token（调用任务 11 的 JWT 服务）
  - 标记授权码已使用（used_at）

**参考文档**:
- RFC 7636 (PKCE)
- OAuth 2.1 Draft
- OWASP OAuth 2.0 Security Best Practices

---

### 🔲 11. JWT Access Token 签发与验证
**知识点**: JWT、Claims、iss、sub、aud、exp、nbf、iat

- [ ] 设计 Token 表（oauth2_tokens）
  - 字段：jti, account_id, client_id, token_type(access/refresh), scopes(jsonb), expires_at, revoked_at, created_at
  - 索引：jti（唯一），account_id, client_id
  - 说明：记录签发的 Token 元数据，用于撤销和审计
- [ ] 编写数据库迁移脚本（db/migrations/0008_oauth2_tokens.up.sql）
- [ ] 实现 JWT 签发服务（internal/token/service/jwt_service.go）
  - 签名算法：RS256/ES256（从 crypto_keys 表加载私钥）
  - Claims 构建：
    - 标准 Claims：iss, sub（account_id）, aud（client_id）, exp, iat, nbf, jti
    - 自定义 Claims：scope（空格分隔字符串）
    - 用户信息 Claims（可选）：email, name, roles
  - 插入 oauth2_tokens 记录
- [ ] 实现 JWT 验证服务
  - 签名验证（从 JWKS 获取公钥）
  - 过期时间验证（exp）
  - Issuer/Audience 验证
  - 黑名单检查（查询 oauth2_tokens.revoked_at）
- [ ] 实现 Token 内省端点
  - POST /oauth2/introspect
  - RFC 7662 标准
  - 返回 Token 元数据（active, scope, exp, sub, client_id 等）
  - 支持客户端认证

**参考文档**:
- RFC 7519 (JWT)
- RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens)
- golang-jwt/jwt 库

---

### 🔲 12. Refresh Token 与令牌轮换
**知识点**: Refresh Token、Token Rotation、Token Family

- [ ] 实现 Refresh Token 签发
  - 长期有效（7-30 天）
  - 存储在数据库（可撤销）
  - 关联 Access Token（Token Family）
- [ ] 实现 Refresh Token 端点
  - POST /oauth2/token
  - grant_type=refresh_token
  - 验证 Refresh Token 有效性
  - 签发新的 Access Token 和 Refresh Token（轮换）
  - 撤销旧的 Refresh Token
- [ ] 实现 Refresh Token 撤销
  - 检测重复使用（防盗用）
  - 撤销整个 Token Family

**参考文档**:
- RFC 6749 Section 6
- OAuth 2.0 Threat Model

---

### 🔲 13. Client Credentials Grant
**知识点**: Service-to-Service 认证、机器身份

- [ ] 实现 Client Credentials 端点
  - POST /oauth2/token
  - grant_type=client_credentials
  - 客户端认证（client_secret_basic/post）
  - 签发 Access Token（无 user context）
  - Scope 限制

**参考文档**:
- RFC 6749 Section 4.4

---

### 🔲 14. OIDC 核心功能
**知识点**: ID Token、UserInfo、Discovery、OIDC Scopes

- [ ] 实现 OpenID Configuration 端点
  - GET /.well-known/openid-configuration
  - 返回 OIDC 元数据（issuer, endpoints, supported algorithms, scopes, claims 等）
- [ ] 实现 ID Token 签发
  - 授权码流程中返回 id_token（在 Token 端点响应中）
  - Claims：
    - 标准 Claims：iss, sub（account_id）, aud, exp, iat, nonce, auth_time
    - 用户信息 Claims（根据 scope）：name, email, picture 等
  - 签名算法：RS256（与 Access Token 共用密钥）
- [ ] 实现 UserInfo 端点
  - GET /oauth2/userinfo
  - 验证 Access Token（从 Authorization Header）
  - 从 accounts 表和 account_credentials 表加载用户信息
  - 返回用户信息（根据 Token 的 Scopes 过滤）
- [ ] 实现 OIDC Scopes 映射
  - openid: 必须（标记为 OIDC 请求）
  - profile: name, family_name, given_name, picture, locale, timezone
  - email: email（从 account_credentials 查询 email 凭证的 identifier）, email_verified（verified 字段）
  - phone: phone_number（从 account_credentials 查询 phone 凭证）, phone_number_verified
  - address: address（从 accounts.metadata 读取）

**参考文档**:
- OpenID Connect Core 1.0
- OIDC Discovery Specification

---

### 🔲 15. OIDC 会话管理与登出
**知识点**: RP-Initiated Logout、Front-Channel Logout、Back-Channel Logout

- [ ] 设计会话表（oidc_sessions）
  - 字段：session_id, account_id, client_id, id_token_hint, created_at, expires_at
  - 索引：session_id（唯一），account_id
  - 说明：记录 OIDC 会话，用于登出管理
- [ ] 编写数据库迁移脚本（db/migrations/0009_oidc_sessions.up.sql）
- [ ] 实现 RP-Initiated Logout
  - GET /oauth2/logout
  - 参数：id_token_hint, post_logout_redirect_uri, state
  - 验证 id_token_hint（可选）
  - 清除 SSO 会话（Redis session）
  - 删除 oidc_sessions 记录
  - 撤销相关 Token（更新 oauth2_tokens.revoked_at）
  - 重定向到 post_logout_redirect_uri?state=...
- [ ] 实现 Front-Channel Logout
  - 客户端注册 frontchannel_logout_uri（存储在 oauth2_clients 表）
  - 登出时生成包含 iframe 的 HTML 页面
  - 每个 iframe 加载客户端的 logout_uri（触发客户端清除本地 session）
- [ ] 实现 Back-Channel Logout（可选）
  - 客户端注册 backchannel_logout_uri
  - 登出时 POST 请求到客户端 logout_uri
  - 发送 logout_token (JWT)，包含 sid（session ID）和 sub（account_id）
  - 异步处理（队列或 Goroutine）

**参考文档**:
- OIDC Session Management
- OIDC Front-Channel Logout
- OIDC Back-Channel Logout

---

## 阶段四：安全与防护 (第 8 周)

### 🔲 16. 速率限制与防护
**知识点**: Rate Limiting、滑动窗口、令牌桶算法

- [ ] 实现细粒度速率限制（internal/security/ratelimit/rate_limiter.go）
  - 登录端点：5 次/分钟/IP
  - 注册端点：3 次/小时/IP
  - Token 端点：20 次/分钟/client_id
  - 基于 Redis 的分布式限流
- [ ] 实现 IP 黑白名单
  - 管理后台配置
  - 中间件拦截
- [ ] 实现防暴力破解
  - 登录失败次数统计（Redis）
  - 账号临时锁定（15 分钟）
  - 验证码强制显示

**参考文档**:
- go-redis/redis_rate 库
- OWASP Rate Limiting

---

### 🔲 17. CSRF 与 CORS 防护
**知识点**: CSRF Token、Same-Site Cookie、CORS Preflight

- [ ] 实现 CSRF 中间件（middleware/csrf_middleware.go）
  - 生成 CSRF Token
  - 验证 CSRF Token
  - 存储在 Session 或 Cookie
- [ ] 实现 CORS 中间件（middleware/cors_middleware.go）
  - 允许的 Origin 配置
  - Preflight 请求处理
  - Credentials 支持
- [ ] 实现 Clickjacking 防护
  - X-Frame-Options: DENY/SAMEORIGIN
  - Content-Security-Policy: frame-ancestors

**参考文档**:
- OWASP CSRF Prevention Cheat Sheet
- MDN CORS

---

### 🔲 18. 输入校验与安全加固
**知识点**: XSS、SQL Injection、参数化查询

- [ ] 实现输入校验中间件
  - 参数类型验证
  - 长度限制
  - 正则表达式验证（邮箱、手机号等）
- [ ] 实现 XSS 防护
  - HTML 转义
  - Content-Security-Policy Header
- [ ] SQL 注入防护（已有参数化查询）
  - 代码审计
  - 使用 ORM 或 sqlx
- [ ] 实现请求防重放
  - Nonce 验证（一次性令牌）
  - 时间戳验证

**参考文档**:
- OWASP Top 10
- Go validator/v10 库

---

## 阶段五：权限与策略引擎 (第 9 周)

### 🔲 19. RBAC 权限模型
**知识点**: RBAC、ABAC、权限继承、资源权限

- [ ] 设计权限表（permissions）
  - 字段：id, resource, action, description
  - 示例：(accounts, read), (accounts, write), (oauth2_clients, manage)
  - 唯一索引：(resource, action)
- [ ] 编写数据库迁移脚本（db/migrations/0010_permissions.up.sql）
- [ ] 实现权限检查服务（internal/authz/service/permission_service.go）
  - 账号权限查询（基于角色，JOIN account_roles -> roles -> permissions）
  - 权限判断（account.can(resource, action)）
  - 缓存权限结果（Redis，TTL 5 分钟）
- [ ] 实现权限中间件（middleware/permission_middleware.go）
  - 装饰器模式：RequirePermission("accounts", "read")
  - 403 Forbidden 返回
  - 审计日志记录（权限拒绝事件）

**参考文档**:
- NIST RBAC Model
- Casbin 库（可选）

---

### 🔲 20. 基于策略的访问控制（可选 OPA 集成）
**知识点**: Policy as Code、Rego、属性驱动授权

- [ ] 集成 OPA（Open Policy Agent）
  - 安装 OPA sidecar 或嵌入式模式（使用 github.com/open-policy-agent/opa/rego）
- [ ] 定义策略文件（policy/authz.rego）
  - 示例：允许同部门账号访问资源
  - 基于时间、地理位置的访问控制
  - 基于账号属性（roles、groups）的授权
- [ ] 实现策略评估服务（internal/authz/service/policy_service.go）
  - 调用 OPA API 评估策略（rego.New().PrepareForEval()）
  - 上下文注入（account, resource, action, env）
  - 返回 allow/deny 决策
- [ ] 集成到授权流程
  - OAuth2 授权前策略检查（是否允许该账号访问该客户端）
  - API 访问前策略检查（替代或补充 RBAC）

**参考文档**:
- Open Policy Agent 官方文档
- Rego 语法

---

## 阶段六：管理后台与 API (第 10 周)

### 🔲 21. 账号管理 API
**知识点**: RESTful API、分页、过滤、排序

- [ ] 实现账号列表 API
  - GET /api/v1/admin/accounts
  - 分页：page, page_size
  - 过滤：email（从 account_credentials 关联查询）, status, created_after
  - 排序：sort=created_at:desc
  - 返回：accounts 信息 + 主要 email/phone 凭证
- [ ] 实现账号详情 API
  - GET /api/v1/admin/accounts/{account_id}
  - 返回：account 信息 + 所有凭证 + 角色 + 群组
- [ ] 实现账号创建 API
  - POST /api/v1/admin/accounts
  - 创建 account + 初始凭证（email/phone + password）
  - 支持批量导入（CSV/Excel）
- [ ] 实现账号更新 API
  - PUT /api/v1/admin/accounts/{account_id}（完整更新）
  - PATCH /api/v1/admin/accounts/{account_id}（部分更新）
  - 更新 display_name, avatar_url, locale, timezone 等
- [ ] 实现账号禁用/启用
  - POST /api/v1/admin/accounts/{account_id}/disable（设置 status='suspended'）
  - POST /api/v1/admin/accounts/{account_id}/enable（设置 status='active'）
  - 禁用时撤销所有有效 Token
- [ ] 实现账号角色分配
  - POST /api/v1/admin/accounts/{account_id}/roles（添加角色，插入 account_roles）
  - DELETE /api/v1/admin/accounts/{account_id}/roles/{role_id}（移除角色）
  - GET /api/v1/admin/accounts/{account_id}/roles（列出角色）

---

### 🔲 22. 客户端管理 API（已在任务 9 实现）
- [ ] API 文档完善
- [ ] 前端页面开发（可选）

---

### 🔲 23. 审计日志查询 API
**知识点**: 日志聚合、时序数据查询

- [ ] 实现审计日志查询 API
  - GET /api/v1/admin/audit/logs
  - 过滤：account_id, action, created_after, created_before
  - 分页与排序
  - 优化查询性能（添加索引：account_id, action, created_at）
- [ ] 实现审计日志详情 API
  - GET /api/v1/admin/audit/logs/{log_id}
  - 显示完整的日志信息（metadata、IP、User-Agent 等）
- [ ] 实现审计日志导出（CSV/JSON）
  - GET /api/v1/admin/audit/logs/export?format=csv
  - 流式导出大量数据

---

### 🔲 24. 管理后台前端（可选）
**知识点**: React/Vue、Admin UI、API 集成

- [ ] 搭建前端项目（React + Ant Design / Vue + Element Plus）
- [ ] 实现登录页面（使用 SSO 本身进行认证）
- [ ] 实现账号管理页面
  - 列表、创建、编辑、禁用
  - 凭证管理（查看邮箱、手机号、MFA 状态）
- [ ] 实现客户端管理页面
  - OAuth2 客户端注册与配置
- [ ] 实现审计日志页面
  - 查询、过滤、导出
- [ ] 实现系统配置页面
  - 身份提供商配置（Google、GitHub 等）
  - 密钥管理与轮换

**参考文档**:
- Ant Design / Element Plus
- React Query / Vue Apollo

---

## 阶段七：可观测性与运维 (第 11 周)

### 🔲 25. 结构化日志与追踪
**知识点**: Structured Logging、Trace ID、Correlation ID

- [ ] 统一日志格式（JSON）
  - 已有 Zap Logger，需规范使用
  - 字段：timestamp, level, trace_id, account_id, action, message, error, duration
  - 所有日志调用统一使用 logger.With(zap.String("account_id", id))
- [ ] 实现 Trace ID 中间件
  - 生成唯一 Trace ID（UUID v4）
  - 注入到 gin.Context（c.Set("trace_id", traceID)）
  - 响应 Header 返回（X-Trace-Id）
  - 日志中包含 trace_id
- [ ] 集成 OpenTelemetry（可选）
  - 安装 go.opentelemetry.io/otel
  - Span 追踪（HTTP 请求、数据库查询、Redis 操作）
  - 导出到 Jaeger/Zipkin

**参考文档**:
- Zap Logger 最佳实践
- OpenTelemetry Go SDK

---

### 🔲 26. 监控指标与告警
**知识点**: Prometheus、Grafana、Metrics、PromQL

- [ ] 集成 Prometheus 客户端
  - 安装 prometheus/client_golang
- [ ] 实现指标收集
  - HTTP 请求数（按路径、状态码）
  - 请求延迟（Histogram）
  - 数据库连接数
  - Redis 命令执行次数
  - 登录成功/失败次数
  - Token 签发次数
- [ ] 暴露 Metrics 端点
  - GET /metrics
- [ ] 编写 Prometheus 配置（prometheus.yml）
- [ ] 导入 Grafana Dashboard
  - 系统概览
  - 认证流量监控
  - 错误率监控

**参考文档**:
- Prometheus 官方文档
- Grafana Dashboard 库

---

### 🔲 27. 健康检查与就绪探针
**知识点**: Health Check、Liveness、Readiness、Kubernetes

- [ ] 实现健康检查端点
  - GET /health
  - 返回状态：ok/degraded/down
  - 检查项：数据库连接、Redis 连接
- [ ] 实现就绪探针端点
  - GET /readiness
  - 检查服务是否准备好接收流量
- [ ] 实现存活探针端点
  - GET /liveness
  - 检查服务是否存活（简单心跳）

**参考文档**:
- Kubernetes Health Checks

---

## 阶段八：高级功能 (第 12-13 周)

### 🔲 28. 设备管理与可信设备
**知识点**: Device Fingerprinting、User-Agent、Device Token

- [ ] 设计设备表（account_devices）
  - 字段：id, account_id, device_id, device_name, device_type, user_agent, fingerprint, trusted, last_used_at, created_at
  - 索引：account_id, device_id（唯一）
  - 说明：记录账号登录过的设备
- [ ] 编写数据库迁移脚本（db/migrations/0011_account_devices.up.sql）
- [ ] 实现设备注册与识别
  - 提取 User-Agent（解析浏览器、操作系统、设备类型）
  - 生成设备指纹（IP + UA + 浏览器特征的 hash）
  - 新设备登录时插入 account_devices 记录
  - 新设备登录通知（邮件/短信）
- [ ] 实现设备管理 API
  - GET /api/v1/user/devices（列出当前账号的所有设备）
  - DELETE /api/v1/user/devices/{device_id}（移除设备，撤销相关 Token）
  - POST /api/v1/user/devices/{device_id}/trust（标记为可信设备，降低 MFA 频率）

**参考文档**:
- FingerprintJS
- Device Detection Libraries

---

### 🔲 29. 风险评分与自适应认证
**知识点**: Risk-Based Authentication、Anomaly Detection、机器学习

- [ ] 实现风险评分引擎（internal/risk/service/risk_service.go）
  - 因素：IP 地理位置、登录时间、设备新旧、失败次数
  - 计算风险分数（0-100）
- [ ] 定义风险策略
  - 低风险（0-30）：正常登录
  - 中风险（31-70）：要求 MFA
  - 高风险（71-100）：阻止登录 + 通知用户
- [ ] 实现自适应认证流程
  - 登录时实时计算风险
  - 动态要求 MFA 或额外验证
- [ ] 实现异常登录通知
  - 邮件/短信通知用户
  - 显示登录地点、设备、时间

**参考文档**:
- Adaptive Authentication Best Practices
- Anomaly Detection Algorithms

---

### 🔲 30. Webhook 与事件系统
**知识点**: Event-Driven Architecture、Webhook、Kafka/NATS

- [ ] 设计 Webhook 表（webhooks）
  - 字段：id, client_id, url, events(jsonb), secret, enabled, created_at
- [ ] 编写数据库迁移脚本（db/migrations/0012_webhooks.up.sql）
- [ ] 实现事件发布服务（internal/event/service/publisher.go）
  - 事件类型：user.login, user.logout, user.registered, token.issued, token.revoked
  - 事件负载（JSON）
- [ ] 实现 Webhook 推送服务（internal/webhook/service/webhook_service.go）
  - HTTP POST 到客户端 URL
  - HMAC 签名验证
  - 重试机制（指数退避）
- [ ] 实现 Webhook 管理 API
  - POST /api/v1/oauth2/clients/{client_id}/webhooks
  - GET /api/v1/oauth2/clients/{client_id}/webhooks
  - DELETE /api/v1/oauth2/clients/{client_id}/webhooks/{webhook_id}

**参考文档**:
- Webhook Best Practices
- Apache Kafka / NATS Streaming

---

### 🔲 31. SCIM Provisioning（企业功能）
**知识点**: SCIM 2.0、User Provisioning、HR 系统集成

- [ ] 实现 SCIM 2.0 Users API
  - GET /scim/v2/Users（列出账号）
  - POST /scim/v2/Users（创建账号）
  - GET /scim/v2/Users/{account_id}（获取账号）
  - PUT /scim/v2/Users/{account_id}（更新账号）
  - PATCH /scim/v2/Users/{account_id}（部分更新）
  - DELETE /scim/v2/Users/{account_id}（删除/停用账号）
  - 映射：SCIM User Schema -> accounts + account_credentials
- [ ] 实现 SCIM Groups API
  - GET /scim/v2/Groups
  - POST /scim/v2/Groups
  - GET /scim/v2/Groups/{group_id}
  - PUT /scim/v2/Groups/{group_id}
  - DELETE /scim/v2/Groups/{group_id}
  - 映射：SCIM Group Schema -> groups + account_groups
- [ ] 实现 SCIM 过滤与分页
  - Filter 语法：userName eq "john@example.com"（解析并转换为 SQL）
  - 分页参数：startIndex, count

**参考文档**:
- RFC 7643 (SCIM Core Schema)
- RFC 7644 (SCIM Protocol)

---

### 🔲 32. LDAP/AD 集成（企业功能）
**知识点**: LDAP、Active Directory、绑定认证、属性映射

- [ ] 实现 LDAP 连接服务（internal/ldap/service/ldap_service.go）
  - LDAP Bind 认证
  - 用户搜索（by DN, by filter）
  - 属性读取（mail, cn, memberOf）
- [ ] 实现 LDAP 登录
  - 用户输入域账号（user@domain.com 或 DOMAIN\user）
  - LDAP Bind 验证密码
  - 同步用户信息到本地数据库
- [ ] 实现 LDAP 用户同步定时任务
  - 定期同步用户与群组
  - 增量同步（基于 modifyTimestamp）

**参考文档**:
- go-ldap/ldap 库
- Microsoft Active Directory 协议

---

## 阶段九：测试与文档 (第 14 周)

### 🔲 33. 单元测试
**知识点**: Go Testing、Testify、Mock、Table-Driven Tests

- [ ] 编写核心服务单元测试
  - User Service 测试
  - JWT Service 测试
  - OAuth2 Service 测试
  - Permission Service 测试
- [ ] 编写仓储层测试（使用 Test Database）
- [ ] Mock 外部依赖（Redis、SMTP、第三方 API）
- [ ] 达到 70%+ 代码覆盖率

**参考文档**:
- Go Testing Package
- Testify 库
- golang/mock

---

### 🔲 34. 集成测试
**知识点**: E2E Testing、Testcontainers、HTTP Test

- [ ] 使用 Testcontainers 启动测试环境
  - PostgreSQL 容器
  - Redis 容器
- [ ] 编写完整流程集成测试
  - 用户注册 -> 登录 -> 获取 Token -> 访问受保护资源
  - OAuth2 授权码流程完整测试
  - Refresh Token 轮换测试
- [ ] 编写安全测试
  - PKCE 缺失测试
  - Redirect URI 劫持测试
  - CSRF 攻击测试

**参考文档**:
- Testcontainers for Go
- httptest Package

---

### 🔲 35. API 文档
**知识点**: OpenAPI 3.0、Swagger、Redoc

- [ ] 使用 Swagger 注解生成 OpenAPI 文档
  - 安装 swaggo/swag
  - 在 Handler 中添加注解
- [ ] 生成 OpenAPI 3.0 规范文件（openapi.yaml）
- [ ] 部署 Swagger UI
  - GET /swagger/index.html
- [ ] 编写 API 使用指南（doc/api-guide.md）
  - 认证流程说明
  - 示例代码（curl、Python、JavaScript）

**参考文档**:
- swaggo/swag
- OpenAPI 3.0 Specification

---

### 🔲 36. 开发者文档
**知识点**: Markdown、架构设计、部署指南

- [ ] 编写系统架构文档（doc/architecture.md）
  - 整体架构图（用 Mermaid）
  - 模块划分
  - 数据流图
- [ ] 编写部署指南（doc/deployment.md）
  - Docker Compose 部署
  - Kubernetes 部署（Helm Chart）
  - 环境变量配置
- [ ] 编写运维手册（doc/operations.md）
  - 密钥轮换操作
  - 数据库备份与恢复
  - 日志查询与故障排查
- [ ] 编写贡献指南（CONTRIBUTING.md）

---

## 阶段十：部署与优化 (第 15 周)

### 🔲 37. Docker 化
**知识点**: Dockerfile、Multi-Stage Build、容器优化

- [ ] 编写 Dockerfile
  - Multi-stage build（编译 + 运行）
  - 使用 Alpine/Distroless 镜像
- [ ] 优化 Docker 镜像大小
  - 删除调试符号
  - 使用 .dockerignore
- [ ] 编写 docker-compose.yml（已有，需完善）
  - SSO 服务
  - PostgreSQL
  - Redis
  - Prometheus
  - Grafana

---

### 🔲 38. Kubernetes 部署
**知识点**: Kubernetes、Helm、ConfigMap、Secret、Ingress

- [ ] 编写 Kubernetes Manifests
  - Deployment
  - Service
  - ConfigMap（配置文件）
  - Secret（密钥）
  - Ingress（域名与 TLS）
  - HPA（水平自动扩展）
- [ ] 编写 Helm Chart（可选）
  - templates/
  - values.yaml
  - Chart.yaml
- [ ] 配置健康检查
  - livenessProbe
  - readinessProbe
- [ ] 配置存储
  - PersistentVolumeClaim（PostgreSQL 数据）

**参考文档**:
- Kubernetes 官方文档
- Helm 官方文档

---

### 🔲 39. 性能优化
**知识点**: Profiling、缓存策略、数据库优化

- [ ] 使用 pprof 分析性能瓶颈
  - CPU Profiling
  - Memory Profiling
- [ ] 优化数据库查询
  - 添加索引
  - 查询优化（EXPLAIN ANALYZE）
  - 使用连接池
- [ ] 优化 Redis 使用
  - Pipeline 批量操作
  - 缓存热点数据（用户信息、客户端配置）
- [ ] 实现缓存预热
  - 启动时加载常用数据到 Redis
- [ ] 实现响应压缩
  - Gzip 中间件

**参考文档**:
- Go Profiling Best Practices
- PostgreSQL Performance Tuning

---

### 🔲 40. 安全加固与审计
**知识点**: Security Hardening、Penetration Testing、OWASP

- [ ] 安全配置检查
  - HTTPS 强制（生产环境）
  - TLS 1.2+ 版本
  - 强加密套件
- [ ] 密钥管理审计
  - 私钥权限检查（600）
  - 密钥加密存储（可选 KMS）
- [ ] 代码安全审计
  - gosec 静态分析
  - 依赖漏洞扫描（snyk/trivy）
- [ ] 渗透测试（可选）
  - 使用 OWASP ZAP / Burp Suite
  - 测试 XSS、SQL 注入、CSRF、认证绕过

**参考文档**:
- OWASP ASVS (Application Security Verification Standard)
- CIS Benchmarks

---

## 附录：持续迭代

### 未来功能扩展
- [ ] 生物识别认证（WebAuthn / FIDO2）
- [ ] 无密码登录（Magic Link）
- [ ] 多租户支持（SaaS 模式）
- [ ] 国际化（i18n）支持
- [ ] 前端 SDK（JavaScript、React、Vue）
- [ ] 移动端 SDK（iOS、Android）
- [ ] 支持 SAML 2.0 协议
- [ ] 支持 WS-Federation 协议
- [ ] AI 驱动的异常检测

---

## 每日工作建议

### 工作节奏
- **每天聚焦 1-2 个任务**，完成后再进入下一个
- **每周五回顾**：代码审查、测试覆盖、文档更新
- **每两周演示**：展示已完成功能，收集反馈

### 学习路径
1. **第 1 周**：熟悉 OAuth 2.0/OIDC 协议，阅读 RFC 文档
2. **第 2-3 周**：深入 JWT、密钥管理、PKCE
3. **第 4-5 周**：实战 OAuth 2.0 流程实现
4. **第 6-7 周**：学习 OIDC、会话管理、登出
5. **第 8 周**：安全最佳实践、OWASP Top 10
6. **第 9 周**：权限模型、RBAC/ABAC
7. **第 10-11 周**：运维工具、监控、日志
8. **第 12-13 周**：高级功能、企业集成
9. **第 14 周**：测试与质量保证
10. **第 15 周**：部署与上线

---

## 资源与参考

### 必读规范
- [RFC 6749 - OAuth 2.0](https://tools.ietf.org/html/rfc6749)
- [OAuth 2.1 Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-07)
- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [RFC 7519 - JWT](https://tools.ietf.org/html/rfc7519)
- [RFC 7517 - JWK](https://tools.ietf.org/html/rfc7517)

### 推荐书籍
- *OAuth 2 in Action* by Justin Richer
- *Solving Identity Management in Modern Applications* by Yvonne Wilson & Abhishek Hingnikar

### 开源项目参考
- [ORY Hydra](https://github.com/ory/hydra) - Go OAuth 2.0 / OIDC Server
- [Keycloak](https://www.keycloak.org/) - Java SSO 解决方案
- [Authelia](https://github.com/authelia/authelia) - Go 认证服务器
- [Casdoor](https://github.com/casdoor/casdoor) - Go SSO 平台

### 社区与工具
- [jwt.io](https://jwt.io/) - JWT Debugger
- [OAuth.tools](https://oauth.tools/) - OAuth 测试工具
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

---

**祝开发顺利！记住：安全第一，质量优先，持续迭代。**
