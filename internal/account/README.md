# Account Module - 账号基础模块

## 📋 概述

账号基础模块是 SSO 系统的核心模块，负责账号的创建、管理、认证凭证管理、第三方身份绑定和角色分配。

## 🏗️ 架构设计

本模块采用**标准的三层架构**（Domain-Driven Design）：

```
┌─────────────────────────────────────────────────┐
│ Service 层 (service/)                           │
│ - 业务逻辑编排                                   │
│ - 事务管理                                       │
│ - 业务验证                                       │
└──────────────┬──────────────────────────────────┘
               │ 调用
               ▼
┌─────────────────────────────────────────────────┐
│ Repository 层 (repository/)                     │
│ - 数据访问接口                                   │
│ - SQL 操作封装                                   │
│ - 不负责事务管理                                 │
└──────────────┬──────────────────────────────────┘
               │ 持久化
               ▼
┌─────────────────────────────────────────────────┐
│ Domain 层 (domain/)                             │
│ - 领域模型定义                                   │
│ - 业务规则                                       │
└─────────────────────────────────────────────────┘
```

## 📂 目录结构

```
internal/account/
├── domain/                    # 领域模型层
│   ├── account.go            # 账号实体
│   ├── credential.go         # 认证凭证实体
│   ├── federated_identity.go # 第三方身份实体
│   └── role.go               # 角色实体
│
├── repository/                # 数据访问层
│   ├── account_repository.go           # 账号仓储
│   ├── credential_repository.go        # 凭证仓储
│   ├── federated_identity_repository.go # 第三方身份仓储
│   └── role_repository.go              # 角色仓储
│
├── service/                   # 业务逻辑层
│   ├── account_service.go    # 账号服务
│   └── account_service_test.go # 单元测试
│
├── wire.go                    # 依赖注入（手动）
└── README.md                  # 模块文档
```

## 🎯 核心功能

### 1. 账号注册

支持多种注册方式：
- ✅ 邮箱 + 密码
- ✅ 手机号 + 密码
- ✅ 用户名 + 邮箱 + 密码
- ✅ 第三方账号（OAuth）

```go
req := &service.RegisterAccountRequest{
    Username:    "johndoe",
    DisplayName: "John Doe",
    Email:       "john@example.com",
    Password:    "SecurePassword123!",
    Locale:      "en",
    Timezone:    "America/New_York",
}

account, err := accountService.RegisterAccount(ctx, req)
```

### 2. 账号查询

- 根据 ID 查询
- 根据用户名查询
- 根据邮箱/手机号查询（通过凭证查询）

```go
account, err := accountService.FindAccountByID(ctx, accountID)
account, err := accountService.FindAccountByUsername(ctx, "johndoe")
```

### 3. 密码管理

- 修改密码（需验证旧密码）
- 密码重置（通过邮件/短信验证码）
- 密码强度验证

```go
err := accountService.ChangePassword(ctx, accountID, oldPassword, newPassword)
```

### 4. 第三方身份绑定

支持绑定多个第三方账号：
- Google
- GitHub
- 微信
- 企业 LDAP/AD

```go
err := accountService.BindFederatedIdentity(
    ctx,
    accountID,
    domain.ProviderGoogle,
    "google-user-12345",
    profile,
)
```

### 5. 角色分配

- 为账号分配角色
- 移除账号的角色
- 查询账号的所有角色

```go
err := accountService.AssignRole(ctx, accountID, roleID)
err := accountService.RemoveRole(ctx, accountID, roleID)
```

### 6. 软删除

采用**软删除**策略，保留数据用于审计和合规：
- 账号软删除
- 级联软删除所有关联数据（凭证、第三方身份、角色关联）
- 数据可恢复

```go
err := accountService.SoftDeleteAccount(ctx, accountID)
```

## 🔐 安全特性

### 1. 密码安全
- 使用 `bcrypt` 哈希（cost=10）
- 不存储明文密码
- 支持密码强度验证

### 2. 凭证验证
- 邮箱/手机号验证状态跟踪
- 验证时间记录
- 最后使用时间记录

### 3. 软删除
- 所有敏感数据软删除而非物理删除
- 保留完整的审计追踪
- 支持数据恢复

### 4. 事务保证
- 所有修改操作都在事务中执行
- 确保 ACID 特性
- 隔离级别：Read Committed

## 📊 数据库设计

### 核心表

| 表名 | 说明 | 软删除 |
|------|------|--------|
| `accounts` | 账号主表 | ✅ |
| `account_credentials` | 认证凭证表 | ✅ |
| `federated_identities` | 第三方身份表 | ✅ |
| `roles` | 角色表 | ✅ |
| `account_roles` | 账号-角色关联 | ✅ |

### 索引策略

- **唯一索引**：username、email、phone（配合软删除条件）
- **查询索引**：account_id、status、created_at
- **部分索引**：`WHERE deleted_at IS NULL` 避免索引膨胀

## 🧪 测试

### 运行单元测试

```bash
cd internal/account/service
go test -v
```

### 测试覆盖率

```bash
go test -cover
go test -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### 集成测试

使用 Docker + Testcontainers 进行真实数据库测试：

```bash
docker-compose -f docker-compose.test.yml up -d
go test -tags=integration ./...
```

## 🚀 快速开始

### 1. 初始化数据库

```bash
# 运行迁移
make migrate-up

# 或手动执行
psql -U postgres -d gosso -f db/migrations/0002_accounts.up.sql
```

### 2. 使用示例

查看完整示例：`examples/account_example.go`

```go
package main

import (
    "github.com/rushairer/gosso/internal/account"
    "github.com/rushairer/gosso/internal/db"
)

func main() {
    // 1. 连接数据库
    database, _ := db.Connect(dbConfig)
    
    // 2. 初始化账号服务
    accountService := account.InitializeAccountModule(database.DB)
    
    // 3. 注册账号
    req := &service.RegisterAccountRequest{
        Email:    "user@example.com",
        Password: "SecurePass123!",
    }
    account, _ := accountService.RegisterAccount(ctx, req)
}
```

## 📈 性能优化

### 1. 数据库优化
- 使用部分索引减少索引大小
- 软删除数据定期归档
- 连接池配置（MaxOpenConns=25, MaxIdleConns=5）

### 2. 查询优化
- 避免 N+1 查询
- 使用 JOIN 减少查询次数
- 合理使用 LIMIT 和 OFFSET

### 3. 缓存策略
- 账号信息缓存（Redis）
- 角色权限缓存
- 缓存失效策略

## 🔄 事务处理最佳实践

### Service 层管理事务

```go
func (s *accountServiceImpl) RegisterAccount(ctx context.Context, req *RegisterAccountRequest) (*domain.Account, error) {
    // 1. 开始事务（Service 层负责）
    tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
        Isolation: sql.LevelReadCommitted,
    })
    if err != nil {
        return nil, fmt.Errorf("开始事务失败: %w", err)
    }
    defer tx.Rollback()
    
    // 2. 调用 Repository 方法（传入事务对象）
    if err := s.accountRepo.CreateAccount(ctx, tx, account); err != nil {
        return nil, err
    }
    
    // 3. 提交事务
    if err := tx.Commit(); err != nil {
        return nil, fmt.Errorf("提交事务失败: %w", err)
    }
    
    return account, nil
}
```

### Repository 层接收事务

```go
func (r *accountRepositoryImpl) CreateAccount(ctx context.Context, tx *sql.Tx, account *domain.Account) error {
    query := `INSERT INTO accounts (...) VALUES (...)`
    _, err := tx.ExecContext(ctx, query, ...)
    if err != nil {
        return fmt.Errorf("insert account: %w", err)
    }
    return nil
}
```

## 📚 相关文档

- [数据库设计文档](../../doc/database-design.md)
- [API 文档](../../doc/api-docs.md)
- [开发指南](../../doc/development-guide.md)
- [事务处理指南](../../doc/transaction-guide.md)

## 🤝 贡献指南

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 📝 许可证

本项目采用 MIT 许可证。

## 📧 联系方式

如有问题或建议，请提交 Issue 或联系维护团队。
