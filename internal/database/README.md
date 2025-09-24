# Database 数据库层

## 📖 概述
数据库连接和配置管理模块，提供统一的数据库访问接口。支持多种数据库驱动，使用工厂模式实现驱动切换。

## 🏗️ 结构
```
database/
├── gorm.go      # GORM 数据库连接配置
├── migrate.go   # 数据库迁移
└── factory/     # 数据库工厂模式实现
    ├── factory.go           # 工厂接口定义
    ├── mysql_factory.go     # MySQL 实现
    ├── postgres_factory.go  # PostgreSQL 实现
    ├── sqlite_factory.go    # SQLite 实现
    └── default_factory.go   # 默认实现
```

## 🚀 使用方法
```go
// 创建数据库连接
db := database.NewGormDB("mysql", dsn, logLevel)

// 执行迁移
err := database.Migrate(db)
```

## ⚙️ 支持的数据库
- **MySQL**: 使用 `-tags mysql` 编译
- **PostgreSQL**: 使用 `-tags postgres` 编译  
- **SQLite**: 使用 `-tags sqlite` 编译

## 🔧 编译标签
```bash
# MySQL
go build -tags mysql

# PostgreSQL  
go build -tags postgres

# SQLite
go build -tags sqlite
```

## 📝 注意事项
- 必须使用编译标签选择数据库驱动
- 工厂模式支持运行时驱动切换
- 连接池和日志级别可配置
- 支持数据库迁移和版本管理

---
*更新时间: 2025/9/24 | 维护者: 开发团队*