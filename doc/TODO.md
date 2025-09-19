# SSO单点登录系统 - 详细实现计划

## 项目概述

基于当前代码分析，制定SSO单点登录系统的完整实现计划。项目采用Go + Gin + GORM + React.js技术栈，支持多种登录方式和OAuth2认证。

## 🔥 第一阶段：完善数据模型和数据库结构（预计2-3天）

### 1.1 修复现有模型

**文件：** `internal/domain/account/phone.go` 和 `email.go`

需要添加的字段：
```go
IsVerified  bool       `gorm:"column:is_verified;default:0" json:"is_verified"`
VerifiedAt  *time.Time `gorm:"column:verified_at;type:timestamp" json:"verified_at"`
```

### 1.2 创建新的数据模型

**需要创建的文件：**
- `internal/domain/account/profile.go` - 用户扩展信息
- `internal/domain/account/social.go` - 三方社区账号
- `internal/domain/oauth2/client.go` - OAuth2客户端
- `internal/domain/verification/code.go` - 验证码表

### 1.3 具体模型设计

#### 用户扩展信息表
```go
// internal/domain/account/profile.go
type Profile struct {
    AccountID uuid.UUID `gorm:"primaryKey;column:account_id;type:uuid"`
    Avatar    string    `gorm:"column:avatar;type:varchar(255)"`
    Gender    int8      `gorm:"column:gender;default:0"` // 0:未知 1:男 2:女
    Age       int       `gorm:"column:age"`
    Address   string    `gorm:"column:address;type:varchar(500)"`
    CreatedAt time.Time `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP"`
    UpdatedAt time.Time `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP"`
}
```

#### 三方社区账号表
```go
// internal/domain/account/social.go
type Social struct {
    ID         string     `gorm:"primaryKey;column:id;type:varchar(128)"` // 平台类型+社区账号ID
    AccountID  *uuid.UUID `gorm:"column:account_id;type:uuid"`
    Platform   string     `gorm:"column:platform;type:varchar(32)"` // wechat, qq, github等
    SocialID   string     `gorm:"column:social_id;type:varchar(64)"`
    SocialName string     `gorm:"column:social_name;type:varchar(128)"`
    CreatedAt  time.Time  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP"`
    UpdatedAt  time.Time  `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP"`
}
```

#### OAuth2客户端表
```go
// internal/domain/oauth2/client.go
type Client struct {
    ID           string    `gorm:"primaryKey;column:id;type:varchar(64)"`
    Name         string    `gorm:"column:name;type:varchar(128)"`
    Secret       string    `gorm:"column:secret;type:varchar(128)"`
    RedirectURIs string    `gorm:"column:redirect_uris;type:text"` // JSON数组
    Scopes       string    `gorm:"column:scopes;type:varchar(255)"`
    GrantTypes   string    `gorm:"column:grant_types;type:varchar(255)"`
    CreatedAt    time.Time `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP"`
    UpdatedAt    time.Time `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP"`
}
```

#### 验证码表
```go
// internal/domain/verification/code.go
type VerificationCode struct {
    ID        string    `gorm:"primaryKey;column:id;type:varchar(64)"`
    Type      string    `gorm:"column:type;type:varchar(16)"` // phone, email
    Target    string    `gorm:"column:target;type:varchar(255)"` // 手机号或邮箱
    Code      string    `gorm:"column:code;type:varchar(16)"`
    Purpose   string    `gorm:"column:purpose;type:varchar(32)"` // login, register, reset_password
    ExpiresAt time.Time `gorm:"column:expires_at;type:timestamp"`
    UsedAt    *time.Time `gorm:"column:used_at;type:timestamp"`
    CreatedAt time.Time `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP"`
}
```

## 🔥 第二阶段：完善Repository层（预计2天）

### 2.1 需要创建的Repository文件
- `internal/repository/account/profile.go`
- `internal/repository/account/social.go`
- `internal/repository/oauth2/client.go`
- `internal/repository/verification/code.go`

### 2.2 完善现有Repository

**扩展 `internal/repository/account/phone.go` 和 `email.go`：**
- 添加验证状态更新方法
- 添加按验证状态查询方法
- 添加验证时间更新方法

**需要实现的方法示例：**
```go
func (r *PhoneRepository) UpdateVerificationStatus(phone string, verified bool) error
func (r *PhoneRepository) FindVerifiedByAccountID(accountID uuid.UUID) ([]*Phone, error)
func (r *EmailRepository) UpdateVerificationStatus(email string, verified bool) error
func (r *EmailRepository) FindVerifiedByAccountID(accountID uuid.UUID) ([]*Email, error)
```

## 🔥 第三阶段：完善Service层业务逻辑（预计3-4天）

### 3.1 账户服务扩展

**文件：** `internal/service/account.go`

需要实现的方法：
```go
func (s *AccountService) RegisterByPhone(phone, code string) (*Account, error)
func (s *AccountService) RegisterByEmail(email, code string) (*Account, error)
func (s *AccountService) LoginByPhone(phone, code string) (*Account, error)
func (s *AccountService) LoginByEmail(email, code string) (*Account, error)
func (s *AccountService) BindPhone(accountID uuid.UUID, phone, code string) error
func (s *AccountService) BindEmail(accountID uuid.UUID, email, code string) error
func (s *AccountService) BindSocial(accountID uuid.UUID, platform, socialID string) error
func (s *AccountService) GetProfile(accountID uuid.UUID) (*Profile, error)
func (s *AccountService) UpdateProfile(accountID uuid.UUID, profile *Profile) error
```

### 3.2 新增服务

**需要创建的服务文件：**
- `internal/service/verification.go` - 验证码服务
- `internal/service/oauth2.go` - OAuth2服务
- `internal/service/social.go` - 三方登录服务

### 3.3 验证码服务核心方法
```go
// internal/service/verification.go
type VerificationService struct{}

func (s *VerificationService) SendPhoneCode(phone, purpose string) error
func (s *VerificationService) SendEmailCode(email, purpose string) error
func (s *VerificationService) VerifyCode(target, code, purpose string) (bool, error)
func (s *VerificationService) GenerateCode() string
func (s *VerificationService) IsCodeExpired(code *VerificationCode) bool
```

### 3.4 OAuth2服务核心方法
```go
// internal/service/oauth2.go
type OAuth2Service struct{}

func (s *OAuth2Service) CreateClient(name, redirectURI string) (*Client, error)
func (s *OAuth2Service) ValidateClient(clientID, clientSecret string) (*Client, error)
func (s *OAuth2Service) GenerateAuthorizationCode(clientID string, accountID uuid.UUID) (string, error)
func (s *OAuth2Service) ExchangeToken(code, clientID, clientSecret string) (*TokenResponse, error)
func (s *OAuth2Service) ValidateToken(token string) (*TokenInfo, error)
```

### 3.5 三方登录服务核心方法
```go
// internal/service/social.go
type SocialService struct{}

func (s *SocialService) GetAuthURL(platform, state string) (string, error)
func (s *SocialService) HandleCallback(platform, code, state string) (*SocialUserInfo, error)
func (s *SocialService) LoginOrRegister(platform string, socialInfo *SocialUserInfo) (*Account, error)
func (s *SocialService) BindToAccount(accountID uuid.UUID, platform string, socialInfo *SocialUserInfo) error
```

## 🔥 第四阶段：完善Controller层API接口（预计2-3天）

### 4.1 账户相关API

**文件：** `controller/account.go`

需要实现的接口：
- `POST /api/auth/send-phone-code` - 发送手机验证码
- `POST /api/auth/send-email-code` - 发送邮箱验证码
- `POST /api/auth/login-phone` - 手机验证码登录
- `POST /api/auth/login-email` - 邮箱验证码登录
- `POST /api/auth/bind-phone` - 绑定手机号
- `POST /api/auth/bind-email` - 绑定邮箱
- `GET /api/user/profile` - 获取用户信息
- `PUT /api/user/profile` - 更新用户信息
- `POST /api/auth/logout` - 退出登录

### 4.2 OAuth2相关API

**需要创建：** `controller/oauth2.go`
- `GET /oauth2/authorize` - 授权页面
- `POST /oauth2/authorize` - 处理授权
- `POST /oauth2/token` - 获取访问令牌
- `GET /oauth2/userinfo` - 获取用户信息
- `POST /oauth2/revoke` - 撤销令牌

### 4.3 三方登录API

**需要创建：** `controller/social.go`
- `GET /auth/social/{platform}` - 跳转到三方登录
- `GET /auth/social/{platform}/callback` - 三方登录回调
- `POST /api/user/bind-social` - 绑定三方账号
- `DELETE /api/user/unbind-social/{platform}` - 解绑三方账号

### 4.4 API响应格式标准化
```go
type APIResponse struct {
    Code    int         `json:"code"`
    Message string      `json:"message"`
    Data    interface{} `json:"data,omitempty"`
}

type TokenResponse struct {
    AccessToken  string `json:"access_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"`
    RefreshToken string `json:"refresh_token,omitempty"`
}
```

## 🔥 第五阶段：集成外部服务（预计2-3天）

### 5.1 Redis缓存集成

**需要添加的依赖：**
```go
// go.mod
github.com/go-redis/redis/v8
github.com/allegro/bigcache/v3
```

**创建文件：**
- `internal/cache/redis.go` - Redis客户端封装
- `internal/cache/bigcache.go` - 本地缓存封装

**用途：**
- 存储验证码（5分钟过期）
- 存储会话信息
- 缓存用户信息
- OAuth2授权码和令牌

### 5.2 消息发送服务

**短信发送服务：**
- 阿里云短信服务
- 腾讯云短信服务
- 创建 `internal/sms/` 目录

**邮件发送服务：**
- SMTP邮件发送
- 创建 `internal/email/` 目录

**完善任务：**
- 完善 `internal/task/account/send_phone_code.go`
- 完善 `internal/task/account/send_email_code.go`

### 5.3 三方登录SDK集成

**需要集成的平台：**
- 微信登录
- QQ登录
- GitHub OAuth2
- Google OAuth2
- Apple Sign In

**创建目录结构：**
```
internal/social/
├── wechat/
├── qq/
├── github/
├── google/
└── apple/
```

## 🔥 第六阶段：中间件和安全（预计1-2天）

### 6.1 认证中间件

**文件：** `middleware/auth.go`

功能：
- JWT令牌验证
- OAuth2令牌验证
- 用户权限检查
- 会话管理

### 6.2 安全中间件

**需要实现的中间件：**
- CORS处理 - `middleware/cors.go`
- 请求限流 - `middleware/ratelimit.go`
- 参数验证 - `middleware/validator.go`
- 请求日志 - `middleware/logger.go`
- 错误处理 - `middleware/error.go`

### 6.3 安全配置

**配置文件更新：**
```yaml
# config/development.yaml
security:
  jwt_secret: "your-jwt-secret"
  jwt_expires_in: 24h
  rate_limit:
    requests_per_minute: 60
  cors:
    allowed_origins: ["http://localhost:3000"]
    allowed_methods: ["GET", "POST", "PUT", "DELETE"]
```

## 🔥 第七阶段：前端开发（预计5-7天）

### 7.1 React.js项目搭建

**创建目录结构：**
```
web/
├── public/
├── src/
│   ├── components/
│   ├── pages/
│   ├── services/
│   ├── utils/
│   └── styles/
├── package.json
└── README.md
```

**技术栈：**
- React 18
- React Router
- Axios
- Ant Design / Material-UI
- Redux Toolkit (状态管理)

### 7.2 核心页面开发

**需要开发的页面：**
- 登录页面 (`src/pages/Login.jsx`)
- 注册页面 (`src/pages/Register.jsx`)
- 用户中心 (`src/pages/Profile.jsx`)
- OAuth2授权页面 (`src/pages/Authorize.jsx`)
- 账号绑定页面 (`src/pages/Binding.jsx`)

### 7.3 组件开发

**通用组件：**
- 验证码输入组件
- 手机号输入组件
- 邮箱输入组件
- 三方登录按钮组件

### 7.4 API服务封装

**创建 `src/services/api.js`：**
```javascript
// API服务封装
export const authAPI = {
  sendPhoneCode: (phone) => axios.post('/api/auth/send-phone-code', { phone }),
  sendEmailCode: (email) => axios.post('/api/auth/send-email-code', { email }),
  loginByPhone: (phone, code) => axios.post('/api/auth/login-phone', { phone, code }),
  loginByEmail: (email, code) => axios.post('/api/auth/login-email', { email, code }),
}
```

## 🔥 第八阶段：管理后台（预计3-4天）

### 8.1 管理API

**需要创建：** `controller/admin.go`

**管理接口：**
- `GET /admin/users` - 用户列表
- `GET /admin/users/{id}` - 用户详情
- `PUT /admin/users/{id}/status` - 更新用户状态
- `GET /admin/clients` - OAuth2客户端列表
- `POST /admin/clients` - 创建客户端
- `PUT /admin/clients/{id}` - 更新客户端
- `DELETE /admin/clients/{id}` - 删除客户端
- `GET /admin/stats` - 系统统计

### 8.2 管理前端

**创建管理后台目录：**
```
admin/
├── src/
│   ├── pages/
│   │   ├── Users/
│   │   ├── Clients/
│   │   └── Dashboard/
│   └── components/
└── package.json
```

**核心功能：**
- 用户列表和管理
- OAuth2客户端管理
- 系统监控面板
- 登录日志查看

## 🔥 第九阶段：测试和文档（预计2-3天）

### 9.1 单元测试

**需要完善的测试：**
- Service层业务逻辑测试
- Repository层数据访问测试
- Controller层API测试
- 中间件测试

### 9.2 集成测试

**测试场景：**
- 完整的注册登录流程
- OAuth2授权流程
- 三方登录流程
- 账号绑定流程

### 9.3 API文档

**使用Swagger生成API文档：**
- 添加swagger注释
- 生成API文档
- 部署文档站点

### 9.4 部署文档

**创建部署相关文档：**
- `doc/DEPLOYMENT.md` - 部署指南
- `doc/API.md` - API使用说明
- `docker-compose.yml` - Docker部署配置

## 实施建议

### 优先级排序
1. **严格按照阶段顺序执行**，每个阶段完成后进行测试
2. **数据模型优先**，确保数据结构设计合理
3. **核心功能优先**，先实现基本的注册登录功能
4. **安全性重视**，及时添加安全防护措施

### 开发规范
1. **代码规范**：使用gofmt、golint等工具
2. **提交规范**：使用conventional commits格式
3. **分支管理**：feature分支开发，main分支发布
4. **代码审查**：每个功能完成后进行代码审查

### 测试策略
1. **测试驱动开发**：每个功能开发完成后立即编写测试
2. **覆盖率要求**：单元测试覆盖率不低于80%
3. **自动化测试**：集成CI/CD流水线
4. **性能测试**：关键接口进行压力测试

### 文档维护
1. **及时更新**：代码变更时同步更新文档
2. **API文档**：使用Swagger自动生成
3. **用户手册**：编写详细的使用说明
4. **开发文档**：记录架构设计和技术决策

## 预计时间安排

| 阶段 | 内容 | 预计时间 | 累计时间 |
|------|------|----------|----------|
| 第一阶段 | 数据模型完善 | 2-3天 | 3天 |
| 第二阶段 | Repository层 | 2天 | 5天 |
| 第三阶段 | Service层 | 3-4天 | 9天 |
| 第四阶段 | Controller层 | 2-3天 | 12天 |
| 第五阶段 | 外部服务集成 | 2-3天 | 15天 |
| 第六阶段 | 中间件和安全 | 1-2天 | 17天 |
| 第七阶段 | 前端开发 | 5-7天 | 24天 |
| 第八阶段 | 管理后台 | 3-4天 | 28天 |
| 第九阶段 | 测试和文档 | 2-3天 | 31天 |

**总计：约30-35个工作日**

## 风险评估

### 技术风险
1. **三方登录集成复杂度**：各平台API差异较大
2. **OAuth2实现复杂度**：需要严格遵循RFC规范
3. **安全性要求高**：需要防范各种攻击

### 时间风险
1. **前端开发时间可能超预期**
2. **三方服务集成调试时间较长**
3. **测试阶段可能发现较多问题**

### 解决方案
1. **分阶段验收**：每个阶段完成后进行验收
2. **并行开发**：前后端可以并行开发
3. **预留缓冲时间**：每个阶段预留20%的缓冲时间

---

*最后更新时间：2025年9月20日*