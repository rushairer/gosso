# Domain 领域模型层

## 📖 概述
领域模型层，定义核心业务实体、值对象和业务规则。是整个应用的业务核心，不依赖任何外部框架。

## 🏗️ 结构
```
domain/
└── account/   # 账户领域模型
    ├── entity.go     # 实体定义
    ├── value.go      # 值对象
    └── repository.go # 仓储接口
```

## 🚀 使用方法
```go
// 创建领域实体
account := &domain.Account{
    Email:    "user@example.com",
    Password: "hashed_password",
}

// 业务规则验证
if err := account.Validate(); err != nil {
    return err
}
```

## 🎯 DDD 原则
- **实体 (Entity)**: 有唯一标识的业务对象
- **值对象 (Value Object)**: 无标识的不可变对象
- **聚合根 (Aggregate Root)**: 管理聚合内的一致性
- **领域服务**: 不属于特定实体的业务逻辑

## 📋 设计规范
- 实体包含业务标识和状态
- 值对象是不可变的
- 业务规则封装在领域对象内
- 仓储接口定义在领域层

## 📝 注意事项
- 领域层不依赖基础设施层
- 业务规则应该在领域对象中实现
- 使用充血模型，避免贫血模型
- 保持领域模型的纯净性

---
*更新时间: 2025/9/24 | 维护者: 开发团队*