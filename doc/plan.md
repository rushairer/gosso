# 开发计划

开发一个 SSO 单点登录系统，支持如下功能：

1. 系统自身的帐号系统：注册、登录、修改密码、忘记密码
   a. 登录时选择手机+验证码登录，还是邮箱+验证码登录，如果登录时发现没有对应的帐号，自动注册一个帐号
   b. 用户帐号信息一个表，主键 user_id 类型 uuid，用户信息字段： 昵称、类型：手机注册、邮箱注册、三方社区注册、状态、创建时间、更新时间
   c. 如果是手机注册，存在手机号码+用户 user_id 的记录表，主键是手机号码，是否验证字段，验证时间字段，另外创建时间和更新时间字段
   d. 如果是邮箱注册，存在邮箱+用户 user_id 的记录表，主键是邮箱，是否验证字段，验证时间字段，另外创建时间和更新时间字段
   e. 用户扩展信息表，主键 user_id，扩展信息字段：头像、性别、年龄、地址等
2. 三方社区帐号登录创建帐号系统
   a. 支持三方社区帐号登录，如微信、QQ、微博、苹果、谷歌、GitHub 等
   b. 登录时，判断是否是新用户，如果是新用户，自动创建一个帐号，并且绑定三方社区帐号
   c. 登录时，判断是否是旧用户，如果是旧用户，直接登录
   d. 三方登录帐号表，类似系统自身帐号系统里面的手机注册、邮箱注册，主键是三方社区类型+三方社区帐号，字段：用户 user_id、三方社区类型、三方社区帐号、创建时间、更新时间
3. 手机注册、邮箱注册、三方社区注册任意一个帐号成功后，可以支持绑定其他三方社区帐号、手机注册、邮箱注册，如果冲突则提示帐号已经存在无法绑定
4. 对己方平台的 OAuth2 认证，注册客户端，客户端信息表，主键是客户端 ID，字段：客户端 ID、客户端名称、客户端类型、客户端密钥、回调 URL、创建时间、更新时间
5. 管理后台，用户管理、客户端管理、三方社区管理
6. RESTful API 接口
7. React.js 前段和后端分离
8. 数据库: MySQL, Redis
9. 缓存: Redis, bigcache
10. GORM 框架
11. 后续扩展，开发对其他开发者提供的三方社区的登录支持，其他开发者注册开发者帐号后，可以自己维护自己的 OAuth2 认证客户端列表


详细实现计划
🔥 第一阶段：完善数据模型和数据库结构（预计2-3天）
1.1 修复现有模型
文件： internal/domain/account/phone.go 和 email.go

// 需要添加的字段
IsVerified  bool       `gorm:"column:is_verified;default:0" json:"is_verified"`
VerifiedAt  *time.Time `gorm:"column:verified_at;type:timestamp" json:"verified_at"`
1.2 创建新的数据模型
需要创建的文件：

internal/domain/account/profile.go - 用户扩展信息
internal/domain/account/social.go - 三方社区账号
internal/domain/oauth2/client.go - OAuth2客户端
internal/domain/verification/code.go - 验证码表
1.3 具体模型设计
用户扩展信息表：

type Profile struct {
    AccountID uuid.UUID `gorm:"primaryKey;column:account_id;type:uuid"`
    Avatar    string    `gorm:"column:avatar;type:varchar(255)"`
    Gender    int8      `gorm:"column:gender;default:0"` // 0:未知 1:男 2:女
    Age       int       `gorm:"column:age"`
    Address   string    `gorm:"column:address;type:varchar(500)"`
    CreatedAt time.Time `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP"`
    UpdatedAt time.Time `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP"`
}
三方社区账号表：

type Social struct {
    ID         string     `gorm:"primaryKey;column:id;type:varchar(128)"` // 平台类型+社区账号ID
    AccountID  *uuid.UUID `gorm:"column:account_id;type:uuid"`
    Platform   string     `gorm:"column:platform;type:varchar(32)"` // wechat, qq, github等
    SocialID   string     `gorm:"column:social_id;type:varchar(64)"`
    SocialName string     `gorm:"column:social_name;type:varchar(128)"`
    CreatedAt  time.Time  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP"`
    UpdatedAt  time.Time  `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP"`
}
OAuth2客户端表：

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
验证码表：

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
🔥 第二阶段：完善Repository层（预计2天）
2.1 需要创建的Repository文件
internal/repository/account/profile.go
internal/repository/account/social.go
internal/repository/oauth2/client.go
internal/repository/verification/code.go
2.2 完善现有Repository
扩展 internal/repository/account/phone.go 和 email.go：

添加验证状态更新方法
添加按验证状态查询方法
添加验证时间更新方法
🔥 第三阶段：完善Service层业务逻辑（预计3-4天）
3.1 账户服务扩展
文件： internal/service/account.go
需要实现的方法：

RegisterByPhone(phone, code string) (*Account, error)
RegisterByEmail(email, code string) (*Account, error)
LoginByPhone(phone, code string) (*Account, error)
LoginByEmail(email, code string) (*Account, error)
BindPhone(accountID uuid.UUID, phone, code string) error
BindEmail(accountID uuid.UUID, email, code string) error
BindSocial(accountID uuid.UUID, platform, socialID string) error
3.2 新增服务
需要创建的服务文件：

internal/service/verification.go - 验证码服务
internal/service/oauth2.go - OAuth2服务
internal/service/social.go - 三方登录服务
3.3 验证码服务核心方法
type VerificationService struct{}

func (s *VerificationService) SendPhoneCode(phone, purpose string) error
func (s *VerificationService) SendEmailCode(email, purpose string) error
func (s *VerificationService) VerifyCode(target, code, purpose string) (bool, error)
🔥 第四阶段：完善Controller层API接口（预计2-3天）
4.1 账户相关API
文件： controller/account.go
需要实现的接口：

POST /api/auth/send-phone-code - 发送手机验证码
POST /api/auth/send-email-code - 发送邮箱验证码
POST /api/auth/login-phone - 手机验证码登录
POST /api/auth/login-email - 邮箱验证码登录
POST /api/auth/bind-phone - 绑定手机号
POST /api/auth/bind-email - 绑定邮箱
GET /api/user/profile - 获取用户信息
PUT /api/user/profile - 更新用户信息
4.2 OAuth2相关API
需要创建： controller/oauth2.go

GET /oauth2/authorize - 授权页面
POST /oauth2/authorize - 处理授权
POST /oauth2/token - 获取访问令牌
GET /oauth2/userinfo - 获取用户信息
4.3 三方登录API
需要创建： controller/social.go

GET /auth/social/{platform} - 跳转到三方登录
GET /auth/social/{platform}/callback - 三方登录回调
🔥 第五阶段：集成外部服务（预计2-3天）
5.1 Redis缓存集成
添加Redis依赖到go.mod
创建 internal/cache/redis.go
用于存储验证码、会话信息等
5.2 消息发送服务
短信发送服务集成（阿里云、腾讯云等）
邮件发送服务集成（SMTP）
完善 internal/task/account/ 下的发送任务
5.3 三方登录SDK集成
微信登录SDK
GitHub OAuth2
QQ登录SDK
🔥 第六阶段：中间件和安全（预计1-2天）
6.1 认证中间件
文件： middleware/auth.go

JWT令牌验证
OAuth2令牌验证
用户权限检查
6.2 安全中间件
CORS处理
请求限流
参数验证
🔥 第七阶段：前端开发（预计5-7天）
7.1 React.js项目搭建
创建 web/ 目录
初始化React项目
配置路由、状态管理
7.2 核心页面开发
登录页面
注册页面
用户中心
OAuth2授权页面
🔥 第八阶段：管理后台（预计3-4天）
8.1 管理API
需要创建： controller/admin.go

用户管理接口
客户端管理接口
系统统计接口
8.2 管理前端
用户列表和管理
OAuth2客户端管理
系统监控面板
实施建议
优先级排序：建议严格按照阶段顺序执行，每个阶段完成后进行测试
测试驱动：每个功能开发完成后立即编写单元测试
文档同步：及时更新API文档和使用说明
代码审查：每个阶段完成后进行代码审查