# 示例程序

本目录包含 gosso 项目的使用示例，展示各个模块的功能和最佳实践。

## 📁 目录结构

```
examples/
├── README.md              # 本文件
├── account/               # 账号模块示例
│   └── main.go
├── redis/                 # Redis 缓存与会话示例
│   └── main.go
└── metadata/              # Metadata 类型使用示例
    └── main.go
```

## 🚀 运行示例

### 方式 1：直接运行（推荐）

```bash
# 运行账号模块示例
go run ./examples/account

# 运行 Redis 示例
go run ./examples/redis

# 运行 Metadata 示例
go run ./examples/metadata
```

### 方式 2：编译后运行

```bash
# 编译所有示例
go build -o bin/account_example ./examples/account
go build -o bin/redis_example ./examples/redis
go build -o bin/metadata_example ./examples/metadata

# 运行编译好的程序
./bin/account_example
./bin/redis_example
./bin/metadata_example
```

### 方式 3：使用 Makefile（如果项目提供）

```bash
make examples
```

## 📚 示例说明

### 1. 账号模块示例 (`account/`)

展示账号管理的完整流程：

- ✅ 连接数据库
- ✅ 注册新账号（用户名、邮箱、密码）
- ✅ 查找账号（根据 ID、用户名、凭证）
- ✅ 修改密码
- ✅ 绑定第三方身份（Google、GitHub 等）
- ✅ 分配角色
- ✅ 软删除账号

**前置条件**：
- PostgreSQL 数据库运行中
- 数据库已执行迁移脚本（`db/migrations/`）

**配置**：
修改 `main.go` 中的数据库连接参数：
```go
dbConfig := &db.Config{
    Host:     "localhost",
    Port:     5432,
    User:     "postgres",
    Password: "password",
    Database: "gosso",
    SSLMode:  "disable",
}
```

### 2. Redis 缓存与会话示例 (`redis/`)

展示 Redis 相关功能的使用：

- ✅ 基础 Redis 操作（Set/Get/Del/Incr）
- ✅ 哈希操作（HSet/HGet/HGetAll）
- ✅ 集合操作（SAdd/SMembers/SIsMember）
- ✅ 会话管理（创建、验证、刷新、删除）
- ✅ 验证码服务（生成、验证、防重放）
- ✅ Token 黑名单（撤销、检查、自动过期）

**前置条件**：
- Redis 服务运行中（默认端口 6379）

**启动 Redis**：
```bash
# 使用 Docker
docker run -d -p 6379:6379 redis:latest

# 或使用 docker-compose
docker-compose -f docker-compose.development.yml up -d redis
```

**配置**：
修改 `main.go` 中的 Redis 连接串：
```go
redisClient, err := cache.NewRedisClient(
    "redis://localhost:6379/0",  // DSN
    100,                          // 最大连接数
    10*time.Second,               // 连接池超时
    logger,
)
```

### 3. Metadata 类型使用示例 (`metadata/`)

展示如何安全地使用 `map[string]any` 类型的 Metadata 字段：

- ✅ 创建账号时设置 Metadata
- ✅ 使用 MetadataHelper 安全访问各种类型
- ✅ 独立函数访问模式
- ✅ 实际业务场景（权限检查）

**前置条件**：
- 无（独立运行）

**输出示例**：
```
========== Metadata 使用示例 ==========

=== 示例 1: 创建账号时设置 Metadata ===
账号创建成功: 张三
部门: engineering
级别: 3
标签: [senior backend go]

=== 示例 2: 使用 MetadataHelper 安全访问 ===
部门: engineering
级别: 3
入职日期: 2020-01-01
...
```

## 🔧 常见问题

### 1. 数据库连接失败

**问题**：`连接数据库失败: connection refused`

**解决**：
- 确保 PostgreSQL 已启动：`docker-compose up -d postgres`
- 检查数据库连接参数（host/port/user/password）
- 确保数据库已创建：`createdb gosso_dev`

### 2. Redis 连接失败

**问题**：`Failed to initialize Redis client: dial tcp :6379: connect: connection refused`

**解决**：
- 确保 Redis 已启动：`docker-compose up -d redis`
- 检查 Redis 端口是否被占用：`lsof -i :6379`
- 测试连接：`redis-cli ping`

### 3. 编译错误

**问题**：`package xxx is not in GOROOT`

**解决**：
```bash
# 更新依赖
go mod tidy
go mod download

# 清理缓存
go clean -modcache
```

### 4. 导入路径错误

**问题**：`cannot find package "github.com/rushairer/gosso/..."`

**解决**：
- 确保在项目根目录运行
- 检查 `go.mod` 中的 module 名称
- 运行 `go mod tidy`

## 📖 相关文档

- [任务 2 快速开始](../doc/task-02-quickstart.md) - 账号模块详细说明
- [任务 3 快速开始](../doc/task-03-quickstart.md) - Redis 缓存详细说明
- [Metadata 类型决策](../doc/metadata-type-decision.md) - Metadata 字段设计说明

## 🎯 最佳实践

1. **环境隔离**：开发环境使用 Docker Compose 管理依赖服务
2. **配置管理**：使用环境变量或配置文件管理连接参数
3. **错误处理**：示例代码展示了完整的错误处理模式
4. **资源清理**：记得在程序结束时关闭数据库连接和 Redis 连接
5. **日志记录**：使用结构化日志（zap）记录操作

## 🚦 快速开始指南

### 完整流程（首次运行）

```bash
# 1. 启动依赖服务
docker-compose -f docker-compose.development.yml up -d

# 2. 运行数据库迁移
go run ./cmd/migrate up

# 3. 运行示例
go run ./examples/account
go run ./examples/redis
go run ./examples/metadata
```

### 仅测试示例（不依赖外部服务）

```bash
# Metadata 示例无需外部依赖
go run ./examples/metadata
```

## 💡 贡献新示例

如果要添加新的示例，请遵循以下结构：

```bash
# 1. 创建新目录
mkdir examples/your_feature

# 2. 创建 main.go
cat > examples/your_feature/main.go << 'EOF'
package main

import "fmt"

func main() {
    fmt.Println("Your Feature Example")
    // 示例代码
}
EOF

# 3. 测试编译
go build ./examples/your_feature

# 4. 更新本 README
```

## 📞 问题反馈

如果运行示例时遇到问题，请：

1. 检查上述"常见问题"章节
2. 查看相关文档
3. 提交 Issue 并附带：
   - 错误信息
   - Go 版本 (`go version`)
   - 操作系统
   - 运行的完整命令

---

**提示**：所有示例代码都是可运行的完整程序，可以直接复制到自己的项目中使用。
