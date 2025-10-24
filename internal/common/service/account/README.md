# Account 账户服务

## 📖 概述
账户服务模块，负责用户账户的注册、管理和相关业务逻辑。支持邮箱和手机号两种注册方式。

## 🚀 使用方法
```go
// 创建账户服务
accountService := account.NewAccountService(db)

// 邮箱注册
err := accountService.EmailRegister(ctx, "user@example.com")

// 手机号注册  
err := accountService.PhoneRegister(ctx, "13800138000")
```

## 🔧 功能特性
- **邮箱注册**: 支持邮箱地址注册账户
- **手机注册**: 支持手机号码注册账户
- **去重处理**: 自动处理重复注册逻辑
- **上下文支持**: 支持请求超时和取消

## 🏗️ 依赖关系
```
AccountService
├── EmailRepository  # 邮箱数据仓储
└── PhoneRepository  # 手机数据仓储
```

## 🧪 测试
```bash
# 运行测试
cd internal/service/account
go test -v
```

## 📝 注意事项
- 使用 `FindOrCreate` 模式避免重复注册
- 所有方法都需要传入 `context.Context`
- 错误处理遵循 Go 标准模式
- 依赖注入通过构造函数实现

---
*更新时间: 2025/9/24 | 维护者: 开发团队*