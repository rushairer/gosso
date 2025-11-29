# SSO 开发计划

## 产品特点
### 服务场景
    多应用（Web、移动、API）统一认证与授权，支持企业用户目录与第三方身份联邦。
### 支持协议
    OIDC/OAuth 2.1（用于现代 Web/API、移动端，Authorization Code + PKCE）
### 令牌
    令牌：JWT（RS256/ES256，支持短期 Access Token 与长期 Refresh Token），可选 PASETO
### 安全强化
    MFA/风险引擎、密钥轮换、会话与令牌撤销

## 核心模块
### 身份提供与认证（IdP/AuthN）
    支持邮箱、手机号
    外部身份联邦（Social Login）
### 授权服务器（OAuth2/OIDC AS）
    流程：授权码 + PKCE、Client Credentials、Device Code、Refresh Token
    OIDC 端点：/authorize、/token、/userinfo、/.well-known/openid-configuration、/jwks
    范围与权限：scopes、resource indicators、基于策略的细粒度权限（ABAC/RBAC）
### 令牌服务与密钥管理
    JWT 签发/验证，Claim 模板与扩展
    JWKS 发布，密钥轮换与吊销（软/硬轮换）
    Token 黑名单/撤销、令牌内省（/introspect）、会话绑定
### 会话管理与登出
    浏览器会话 Cookie（HttpOnly、SameSite、Secure）、会话状态存储（Redis）
    OIDC 会话管理（front-channel/back-channel logout）
    全局登出（终止所有应用会话与刷新令牌）
### 用户目录与账号生命周期
    用户、群组、角色、权限、属性（Profile）
    外部目录集成：LDAP/AD、HR 系统；SCIM Provisioning/Deprovisioning
    自助服务：注册、找回、个人信息与安全设置
### 客户端与应用注册（Relying Party/SP 管理）
    客户端登记（client_id、密钥、重定向 URI、PKCE 策略）
    信任关系与元数据（SAML SP metadata、OIDC 客户端元数据）
    每应用/租户策略配置（MFA、Scopes、同意、会话时长）
### 同意与隐私
    同意页面与记录（scope/attribute consent）
    隐私控制（数据最小化、Retention Policy、合规审计）
### 安全与防护层
    速率限制、IP 黑白名单、WAF/CDN、CSRF/CORS、防重放
    密钥与机密管理（KMS、HSM、Vault）
    输入校验、会话固定攻击防护、点击劫持、防越权
### 集成与扩展
    Webhook/事件（登录成功/失败、账户变更、令牌签发）
    可编程策略引擎（如 OPA，支持规则与上下文属性）
    SDK/适配器（前后端语言的登录与令牌验证）
### 可观测性与平台能力
    日志（结构化）、度量（Prometheus）、追踪（OpenTelemetry）
    异常告警、健康检查与就绪探针
    灰度与回滚、蓝绿/滚动发布
### 存储与基础设施
    数据库：PostgreSQL/MySQL（用户、客户端、策略、审计）
    缓存：Redis（会话、验证码、限流、短期状态）
    队列/事件总线：Kafka/NATS（审计、webhook 异步处理）
    对象存储（头像/证书等），配置中心