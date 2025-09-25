# Database Factory 测试说明

## 概述

这个目录包含了数据库工厂模式的实现和相应的单元测试。工厂模式用于根据不同的编译标签创建相应的数据库 Dialector。

## 文件结构

```
factory/
├── factory.go                # DatabaseFactory 接口定义
├── default_factory.go        # 默认实现（无驱动时触发错误）
├── mysql_factory.go          # MySQL 实现
├── postgres_factory.go       # PostgreSQL 实现
├── sqlite_factory.go         # SQLite 实现
├── factory_test.go           # 通用接口测试
├── factory_mysql_test.go     # MySQL 特定测试 (需要 -tags mysql)
├── factory_postgres_test.go  # PostgreSQL 特定测试 (需要 -tags postgres)
├── factory_sqlite_test.go    # SQLite 特定测试 (需要 -tags sqlite)
└── README.md                # 本文件
```

## 测试架构设计

### 问题解决

之前的测试设计存在问题：所有数据库的测试用例都放在同一个文件中，当集成测试脚本使用编译标签（如 `-tags mysql`）时，PostgreSQL 和 SQLite 的测试会因为缺少对应驱动而失败。

### 解决方案

现在采用**按编译标签分离测试文件**的策略：

#### 通用测试 (`factory_test.go`)
- 不依赖特定数据库驱动
- 测试工厂接口的基本功能
- 验证接口实现的正确性

#### 数据库特定测试
每个数据库的测试使用 `//go:build` 指令进行编译标签隔离：

```go
//go:build mysql
// 只有使用 -tags mysql 编译时才包含此文件

//go:build postgres  
// 只有使用 -tags postgres 编译时才包含此文件

//go:build sqlite
// 只有使用 -tags sqlite 编译时才包含此文件
```

## 运行测试

### 通用测试

运行不依赖特定数据库的测试：

```bash
go test ./internal/database/factory -v
```

### 数据库特定测试

根据你想测试的数据库类型，使用相应的编译标签：

#### MySQL 测试
```bash
go test -tags mysql ./internal/database/factory -v
```

#### PostgreSQL 测试
```bash
go test -tags postgres ./internal/database/factory -v
```

#### SQLite 测试
```bash
go test -tags sqlite ./internal/database/factory -v
```

### 测试覆盖率

查看测试覆盖率：

```bash
# 通用测试覆盖率
go test -cover ./internal/database/factory

# 特定数据库测试覆盖率
go test -cover -tags mysql ./internal/database/factory
go test -cover -tags postgres ./internal/database/factory
go test -cover -tags sqlite ./internal/database/factory
```

## 测试内容

### 通用测试 (`factory_test.go`)
- ✅ **工厂创建测试**: 验证 `NewDatabaseFactory()` 返回非空工厂
- ✅ **接口实现验证**: 确保工厂实现 `DatabaseFactory` 接口
- ✅ **编译标签说明**: 提供测试文件分离的说明

### MySQL 测试 (`factory_mysql_test.go`)
- ✅ **MySQL Dialector 创建**: 测试 MySQL 连接字符串解析
- ✅ **连接池支持**: 测试使用 `*sql.DB` 创建 Dialector
- ✅ **驱动验证**: 确保返回的 Dialector 名称为 "mysql"

### PostgreSQL 测试 (`factory_postgres_test.go`)
- ✅ **PostgreSQL Dialector 创建**: 测试 PostgreSQL 连接字符串解析
- ✅ **连接池支持**: 测试使用 `*sql.DB` 创建 Dialector
- ✅ **驱动验证**: 确保返回的 Dialector 名称为 "postgres"

### SQLite 测试 (`factory_sqlite_test.go`)
- ✅ **SQLite Dialector 创建**: 测试 SQLite 连接字符串解析（包括 `:memory:`）
- ✅ **连接池支持**: 测试使用 `*sql.DB` 创建 Dialector
- ✅ **驱动验证**: 确保返回的 Dialector 名称为 "sqlite"

## 集成测试兼容性

这种测试架构完美配合集成测试脚本：

```bash
# 集成测试脚本中的数据库切换
for db_type in mysql postgres sqlite; do
    # 只编译和测试当前数据库类型
    go test -tags $db_type ./internal/database/factory -v
done
```

### 优势

1. **编译标签隔离**: 避免了不同数据库驱动的冲突
2. **测试精确性**: 每次只测试一种数据库类型
3. **失败隔离**: 一个数据库的测试失败不影响其他数据库
4. **维护简单**: 每个数据库的测试逻辑独立维护

## 实际使用

在实际项目中，你需要：

1. **选择数据库**: 根据项目需求选择一个或多个数据库驱动
2. **编译标签**: 使用相应的编译标签构建项目
3. **集成测试**: 在集成测试中验证实际的数据库连接
4. **环境配置**: 确保有相应的数据库连接配置

## 注意事项

- **默认行为**: `default_factory.go` 会在没有任何数据库驱动编译标签时触发 `log.Fatal`
- **测试范围**: 单元测试主要验证接口和方法签名，实际连接测试在集成测试中进行
- **编译要求**: 每个数据库特定的测试文件只有在对应编译标签存在时才会被编译
- **向后兼容**: 通用测试确保基本功能在任何编译配置下都能正常工作

## 最佳实践

1. **开发阶段**: 使用通用测试进行快速验证
2. **集成测试**: 使用特定数据库标签进行完整测试
3. **CI/CD**: 在持续集成中分别测试每种数据库类型
4. **文档维护**: 保持测试文档与实际测试代码同步