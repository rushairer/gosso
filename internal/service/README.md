# Service 业务逻辑层

## 📖 概述
业务逻辑层，负责实现核心业务规则和流程编排。协调 Repository 层和 Domain 层，提供完整的业务功能。

## 🏗️ 结构
```
service/
├── account/   # 账户相关业务
├── auth/      # 认证授权业务
├── captcha/   # 验证码业务
└── email/     # 邮件服务业务
```

## 🚀 使用方法
```go
// 创建服务实例
accountService := account.NewAccountService(db)

// 调用业务方法
err := accountService.EmailRegister(ctx, "user@example.com")
```

## 🎯 设计原则
- **单一职责**: 每个服务专注特定业务领域
- **依赖注入**: 通过构造函数注入依赖
- **接口驱动**: 定义清晰的服务接口
- **事务管理**: 在服务层处理业务事务

## 📝 注意事项
- 服务方法应该是业务操作的原子单位
- 避免服务间的循环依赖
- 使用 context.Context 进行超时和取消控制
- 错误处理应该包含业务语义

---
*更新时间: 2025/9/24 | 维护者: 开发团队*