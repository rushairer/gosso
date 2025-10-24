# Repository 数据访问层

## 📖 概述
数据访问层，提供数据持久化的抽象接口。隔离业务逻辑与数据存储实现，支持不同数据源的切换。

## 🏗️ 结构
```
repository/
├── account.go   # 账户仓储接口定义
└── account/     # 账户仓储具体实现
```

## 🚀 使用方法
```go
// 创建仓储实例
accountRepo := account.NewAccountRepository(db)

// 数据操作
user, err := accountRepo.FindByEmail(ctx, "user@example.com")
err = accountRepo.Create(ctx, &domain.Account{...})
```

## 🎯 设计模式
- **Repository Pattern**: 封装数据访问逻辑
- **接口分离**: 定义清晰的数据操作契约
- **实现分离**: 接口定义与具体实现分离
- **查询构建**: 支持复杂查询条件组合

## ⚙️ 数据库支持
- 支持 MySQL、PostgreSQL、SQLite
- 使用 GORM 作为 ORM 框架
- 支持事务操作和连接池管理

## 📝 注意事项
- 仓储方法应该是数据操作的原子单位
- 使用领域对象作为参数和返回值
- 错误处理应该转换为业务友好的错误
- 避免在仓储层处理业务逻辑

---
*更新时间: 2025/9/24 | 维护者: 开发团队*