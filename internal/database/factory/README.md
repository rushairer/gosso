# Database Factory 测试说明

## 概述

这个目录包含了数据库工厂模式的实现和相应的单元测试。工厂模式用于根据不同的编译标签创建相应的数据库 Dialector。

## 文件结构

```
factory/
├── factory.go           # DatabaseFactory 接口定义
├── default_factory.go   # 默认实现（无驱动时触发错误）
├── mysql_factory.go     # MySQL 实现
├── postgres_factory.go  # PostgreSQL 实现
├── sqlite_factory.go    # SQLite 实现
├── factory_test.go      # 单元测试
└── README.md           # 本文件
```

## 运行测试

### 基本测试

运行所有测试（大部分会被跳过，因为需要特定的编译标签）：

```bash
go test -v
```

### 带编译标签的测试

根据你想测试的数据库类型，使用相应的编译标签：

#### MySQL 测试
```bash
go test -v -tags mysql
```

#### PostgreSQL 测试
```bash
go test -v -tags postgres
```

#### SQLite 测试
```bash
go test -v -tags sqlite
```

### 测试覆盖率

查看测试覆盖率：

```bash
go test -v -cover
```

带编译标签的覆盖率测试：

```bash
go test -v -cover -tags mysql
```

## 测试说明

### 跳过的测试

大部分测试使用 `SkipConvey` 跳过，原因：

1. **编译标签依赖**: 不同的数据库实现需要特定的编译标签
2. **数据库连接依赖**: 某些测试需要真实的数据库连接
3. **环境依赖**: 避免在没有相应数据库环境时测试失败

### 测试内容

- **接口定义验证**: 确保 DatabaseFactory 接口正确定义
- **工厂创建测试**: 验证 NewDatabaseFactory() 的行为
- **方法签名测试**: 确保方法参数类型正确
- **编译标签说明**: 提供如何使用不同编译标签的指导

## 实际使用

在实际项目中，你需要：

1. 选择一个数据库驱动进行编译
2. 确保有相应的数据库连接配置
3. 在集成测试中验证实际的数据库连接

## 注意事项

- `default_factory.go` 会在没有任何数据库驱动编译标签时触发 `log.Fatal`
- 实际的数据库连接测试应该在集成测试中进行
- 单元测试主要验证接口和方法签名的正确性