# 任务 3：Redis 缓存与会话存储 - 快速开始

## 📋 任务概述

实现 Redis 缓存层和会话管理功能，为 SSO 系统提供高性能的缓存支持和会话存储能力。

## ✅ 已完成的功能

### 1. Redis 客户端封装 (`internal/cache/redis_client.go`)

提供统一的 Redis 操作接口，封装常用的 Redis 命令。

**核心功能**：
- 连接池管理（可配置连接数、超时时间）
- 基础键值操作（Set/Get/Del/Exists/Expire）
- 计数器操作（Incr/Decr）
- 哈希操作（HSet/HGet/HGetAll/HDel）
- 集合操作（SAdd/SMembers/SIsMember/SRem）
- 分布式锁支持（SetNX）
- TTL 查询
- 错误日志记录

**初始化示例**：
```go
redisClient, err := cache.NewRedisClient(
    "redis://:password@localhost:6379/0",
    100,                  // 最大连接数
    10*time.Second,       // 连接池超时
    logger,
)
defer redisClient.Close()
```

### 2. 会话管理服务 (`internal/session/service/session_service.go`)

提供完整的会话生命周期管理。

**功能特性**：
- 会话创建与存储
- 会话查询与验证
- 会话更新与刷新
- 会话删除（登出）
- 自动过期管理（默认 24 小时）
- 最后活跃时间追踪
- MFA 验证状态管理

**Redis 键设计**：
```
Key: session:{uuid}
Value: JSON 格式的 Session 对象
TTL: 24 小时（可配置）
```

**Session 数据结构**：
```go
type Session struct {
    ID           uuid.UUID         // 会话 ID
    AccountID    uuid.UUID         // 账号 ID
    Username     string            // 用户名
    IP           string            // 客户端 IP
    UserAgent    string            // 浏览器标识
    CreatedAt    time.Time         // 创建时间
    LastActiveAt time.Time         // 最后活跃时间
    MFAVerified  bool              // MFA 验证状态
    Metadata     map[string]string // 扩展元数据
}
```

**使用示例**：
```go
// 创建会话
session := &domain.Session{
    AccountID: accountID,
    Username:  "johndoe",
    IP:        "192.168.1.100",
    UserAgent: "Mozilla/5.0...",
}
err := sessionService.CreateSession(ctx, session)

// 验证会话
validSession, err := sessionService.ValidateSession(ctx, sessionID)

// 刷新会话（更新活跃时间）
err = sessionService.RefreshSession(ctx, sessionID)

// 删除会话（登出）
err = sessionService.DeleteSession(ctx, sessionID)
```

### 3. 验证码服务 (`internal/captcha/service/captcha_service.go`)

提供多种类型的验证码生成与验证功能。

**支持的验证码类型**：
- `math`：数学算式验证码（如 "23 + 45 = ?"）
- `digit`：6 位数字验证码（如 "123456"）
- `image`：图片验证码（预留）
- `audio`：音频验证码（预留）

**安全特性**：
- 自动过期（默认 5 分钟）
- 防重放攻击（验证后立即失效）
- 答案大小写不敏感

**Redis 键设计**：
```
Key: captcha:{uuid}
Value: JSON 格式的 Captcha 对象
TTL: 5 分钟（可配置）
```

**使用示例**：
```go
// 生成数学验证码
captcha, question, err := captchaService.GenerateMathCaptcha(ctx)
// question: "23 + 45 = ?"
// captcha.Answer: "68"

// 生成数字验证码
captcha, code, err := captchaService.GenerateDigitCaptcha(ctx)
// code: "123456"

// 验证验证码
err = captchaService.VerifyCaptcha(ctx, captchaID, userAnswer)
```

### 4. Token 黑名单服务 (`internal/token/service/blacklist_service.go`)

管理被撤销的 JWT Token，防止已撤销的 Token 继续使用。

**应用场景**：
- 用户主动登出
- 管理员强制下线
- 密码修改后撤销所有 Token
- 账号被封禁

**智能 TTL 管理**：
- 黑名单记录的 TTL = Token 的剩余有效期
- Token 过期后自动从黑名单移除，节省内存

**Redis 键设计**：
```
Key: blacklist:token:{jti}
Value: JSON 格式的 TokenBlacklist 对象
TTL: Token 的剩余有效期
```

**使用示例**：
```go
// 撤销 Token
err := blacklistService.RevokeToken(ctx, jti, "user_logout", tokenExpiresAt)

// 检查 Token 是否已撤销
isRevoked, err := blacklistService.IsTokenRevoked(ctx, jti)

// 获取撤销信息
info, err := blacklistService.GetRevokeInfo(ctx, jti)
```

## 🗂️ Redis 键设计规范总览

| 用途 | Key 模式 | Value 类型 | TTL | 说明 |
|------|----------|-----------|-----|------|
| 会话存储 | `session:{id}` | JSON | 24h | 用户登录会话 |
| 验证码 | `captcha:{id}` | JSON | 5min | 登录/注册验证码 |
| Token 黑名单 | `blacklist:token:{jti}` | JSON | 动态 | 已撤销的 Token |
| 登录失败计数 | `login:fail:{ip}` | String | 15min | 防暴力破解（预留） |
| 权限缓存 | `perms:{account_id}` | Set | 5min | 用户权限列表（预留） |
| OAuth2 State | `oauth2:state:{state}` | Hash | 10min | OAuth2 授权状态（预留） |
| TOTP 防重放 | `totp:used:{account_id}:{code}` | String | 90s | MFA 验证码防重放（预留） |
| 速率限制 | `ratelimit:{ip}:{endpoint}` | String | 1min | API 限流（预留） |

## 📊 项目结构

```
internal/
├── cache/
│   ├── redis_client.go          # Redis 客户端封装
│   └── redis_client_test.go     # 单元测试
├── session/
│   ├── domain/
│   │   └── session.go           # Session 实体
│   └── service/
│       ├── session_service.go   # 会话管理服务
│       └── session_service_test.go
├── captcha/
│   ├── domain/
│   │   └── captcha.go           # Captcha 实体
│   └── service/
│       ├── captcha_service.go   # 验证码服务
│       └── captcha_service_test.go
└── token/
    ├── domain/
    │   └── blacklist.go         # TokenBlacklist 实体
    └── service/
        ├── blacklist_service.go # 黑名单服务
        └── blacklist_service_test.go

examples/
└── redis_usage_example.go       # 完整使用示例
```

## 🔧 配置说明

### Redis 配置 (`config/development.yaml`)

```yaml
redis:
    dsn: redis://localhost:6379/0  # Redis 连接串
    max_active_conns: 6000          # 最大连接数
    pool_timeout_seconds: 60        # 连接池超时（秒）
```

### DSN 格式说明

```
redis://[username:password@]host:port/database
```

**示例**：
- 无密码：`redis://localhost:6379/0`
- 有密码：`redis://:mypassword@localhost:6379/0`
- 带用户名：`redis://user:password@localhost:6379/0`

## 🧪 运行测试

### 启动 Redis（使用 Docker）

```bash
# 启动开发环境（包含 Redis）
docker-compose -f docker-compose.development.yml up -d redis

# 或使用测试环境
docker-compose -f docker-compose.test.yml up -d redis
```

### 运行单元测试

```bash
# 运行所有 Redis 相关测试
go test ./internal/cache/... -v
go test ./internal/session/... -v
go test ./internal/captcha/... -v
go test ./internal/token/... -v

# 运行单个测试
go test -run TestSessionService_CreateAndGetSession ./internal/session/service -v
```

### 运行示例程序

```bash
# 编译示例
go build -o bin/redis_example ./examples/redis_usage_example.go

# 运行示例
./bin/redis_example
```

## 📈 性能特点

### 1. 连接池优化
- 预分配连接，减少连接开销
- 连接复用，提高并发性能
- 自动重试机制（最多 3 次）

### 2. 智能 TTL 管理
- 会话自动过期，无需手动清理
- 验证码自动失效，防止滥用
- Token 黑名单自动清理，节省内存

### 3. 内存优化
- JSON 序列化存储，紧凑高效
- TTL 到期自动删除，避免内存泄漏
- 条件索引避免冗余数据

## 🔒 安全考虑

### 1. 验证码安全
- 短过期时间（5 分钟）
- 一次性使用（防重放）
- 验证后立即删除

### 2. 会话安全
- 存储 IP 和 UserAgent，便于异常检测
- 支持 MFA 验证状态
- 可追踪最后活跃时间

### 3. Token 黑名单
- 立即撤销，实时生效
- 记录撤销原因，便于审计
- 自动清理过期记录

## 🚀 后续扩展

1. **速率限制**：基于 IP 和端点的 API 限流
2. **权限缓存**：缓存用户权限，减少数据库查询
3. **分布式锁**：使用 SetNX 实现分布式互斥锁
4. **Session 集群**：支持多实例 Session 共享
5. **缓存预热**：系统启动时加载热点数据

## 📚 参考资料

- [Redis 官方文档](https://redis.io/docs/)
- [go-redis 库文档](https://redis.uptrace.dev/)
- [JWT 最佳实践](https://tools.ietf.org/html/rfc8725)
- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

## ✅ 任务完成检查清单

- [x] Redis 客户端封装
- [x] 会话存储服务
- [x] 验证码缓存服务
- [x] Token 黑名单服务
- [x] 单元测试（4 个测试文件）
- [x] 使用示例
- [x] 文档编写
- [x] 编译通过

**状态**：✅ 任务 3 已完成
