# 测试指南

## 📋 概述

GoSSO 项目拥有现代化的测试基础设施，支持多层次测试策略，确保代码质量和系统稳定性。

## 🏗️ 测试架构

### 测试分层策略

```
测试层次:
├── 单元测试 (Unit Tests)
│   ├── 纯逻辑测试 (utility, middleware, config)
│   ├── Mock 测试 (gomonkey - repository layer)
│   ├── 接口测试 (domain models)
│   └── 服务测试 (captcha service)
│
└── 集成测试 (Integration Tests)
    ├── 数据库测试 (service layer with real DB)
    ├── 外部服务测试 (email, task pipeline)
    ├── 工厂模式测试 (database factory)
    └── 端到端测试 (controller layer)
```

### 测试分类原则

- **单元测试**: 无外部依赖，使用 mock，执行快速
- **集成测试**: 需要外部服务（数据库、邮件等），执行较慢但更真实

## 🚀 快速开始

### 开发时快速反馈

```bash
# 运行单元测试 (推荐日常开发使用)
make test

# 查看详细输出
make test-unit
```

### 完整验证

```bash
# 运行所有测试 (提交前推荐)
make test-all

# 只运行集成测试
make test-integration
```

## 📊 测试覆盖率

### 当前覆盖率状况

- **单元测试总覆盖率**: 96.6%
  - 验证码服务: 93.3%
  - 账户仓库 (gomonkey mock): 100%
  - 上下文管理: 高覆盖率
  - 工具函数: 高覆盖率

- **集成测试覆盖率**: 69.6%-72.2%
  - MySQL: 72.2%
  - PostgreSQL: 69.6%
  - SQLite: 72.2%

### 覆盖率报告

测试完成后会生成 HTML 覆盖率报告：

- `coverage-unit.html` - 单元测试覆盖率
- `coverage-integration-mysql.html` - MySQL 集成测试
- `coverage-integration-postgres.html` - PostgreSQL 集成测试
- `coverage-integration-sqlite.html` - SQLite 集成测试

## 🗄️ 多数据库测试

### 支持的数据库

项目支持三种数据库，每种都有完整的测试覆盖：

1. **MySQL** (使用 MariaDB 兼容实现)
2. **PostgreSQL** (使用 Alpine 镜像)
3. **SQLite** (内存模式，最快)

### 数据库测试隔离

每个数据库测试完全隔离，避免环境变量污染：

```bash
# 清理所有 DSN 环境变量
unset MYSQL_DSN POSTGRES_DSN SQLITE_DSN

# 只设置当前测试数据库的 DSN
export MYSQL_DSN="gosso:gosso123@tcp(localhost:3307)/gosso_test?charset=utf8mb4&parseTime=True&loc=Local"
```

### 编译标签测试

```bash
# 测试特定数据库 (需要对应的编译标签)
go test -v -race -tags mysql ./internal/database/factory
go test -v -race -tags postgres ./internal/database/factory  
go test -v -race -tags sqlite ./internal/database/factory
```

## 🐳 Docker 测试环境

### 容器化优势

- **环境一致性**: 本地和 CI 环境完全一致
- **快速启动**: 使用 Alpine 镜像，启动速度快
- **自动清理**: 测试完成后自动清理，无残留数据
- **服务隔离**: 每个服务独立容器，互不影响

### 测试服务配置

```yaml
services:
  mysql-test:
    image: mariadb:10.11-jammy  # MySQL 兼容，更轻量
    ports: ["3307:3306"]        # 避免与开发环境冲突
    tmpfs: ["/var/lib/mysql"]   # 内存存储，测试后自动清理
    
  postgres-test:
    image: postgres:15-alpine   # Alpine 版本，镜像更小
    ports: ["5433:5432"]        # 避免与开发环境冲突
    tmpfs: ["/var/lib/postgresql/data"]
    
  mailpit-test:
    image: axllent/mailpit:latest  # 现代化邮件测试工具
    ports: ["1025:1025", "8025:8025"]
```

### 手动管理测试环境

```bash
# 启动测试服务
docker-compose -f docker-compose.test.yml up -d

# 查看服务状态
docker-compose -f docker-compose.test.yml ps

# 查看日志
docker-compose -f docker-compose.test.yml logs -f

# 清理环境
docker-compose -f docker-compose.test.yml down -v
```

## 🔧 测试脚本详解

### scripts/test-unit.sh

**用途**: 运行单元测试，无外部依赖

**特点**:
- 执行速度快 (通常 < 5秒)
- 不需要 Docker 环境
- 适合日常开发反馈
- 包含 gomonkey mock 测试

**包含的测试包**:
```bash
UNIT_TEST_PACKAGES=(
    "./internal/service/captcha"     # 验证码服务
    "./internal/context"             # 上下文处理
    "./utility"                      # 工具函数
    "./middleware"                   # 中间件
    "./config"                       # 配置处理
    "./internal/domain/account"      # 领域模型
    "./cmd"                          # 命令行工具
    "./router"                       # 路由配置
    "./internal/repository/account"  # 账户仓库 (gomonkey mock)
)
```

### scripts/test-integration.sh

**用途**: 运行集成测试，需要外部服务

**特点**:
- 需要 Docker 环境
- 测试三种数据库
- 生成独立覆盖率报告
- 完整的服务依赖测试

**包含的测试包**:
```bash
INTEGRATION_TEST_PACKAGES=(
    "./internal/service/account"     # 账户服务 (需要数据库)
    "./internal/service/email"       # 邮件服务 (需要 SMTP)
    "./internal/task/account"        # 异步任务 (需要数据库和邮件)
    "./internal/database/factory"    # 数据库工厂 (需要数据库)
    "./test/controller"              # 控制器测试 (需要完整环境)
)
```

### scripts/test-clean.sh

**用途**: 清理测试环境和临时文件

**清理内容**:
- Docker 容器和网络
- 覆盖率报告文件
- 临时测试数据

## 🎯 测试最佳实践

### 编写测试的原则

1. **单一职责**: 每个测试只验证一个功能点
2. **独立性**: 测试之间不应有依赖关系
3. **可重复**: 测试结果应该是确定的
4. **快速反馈**: 单元测试应该快速执行
5. **真实性**: 集成测试应该尽可能接近生产环境

### 测试命名规范

```go
// 单元测试
func TestServiceMethod_SuccessCase(t *testing.T) { }
func TestServiceMethod_ErrorCase(t *testing.T) { }

// 使用 Convey 框架
Convey("账户服务测试", t, func() {
    Convey("注册邮箱账户", func() {
        Convey("成功注册", func() {
            // 测试逻辑
        })
    })
})
```

### Mock 测试策略

项目使用 [gomonkey](https://github.com/agiledragon/gomonkey) 进行 mock 测试：

```go
// Mock GORM 方法
patches := gomonkey.ApplyMethod(reflect.TypeOf(&gorm.DB{}), "Create", 
    func(_ *gorm.DB, value interface{}) *gorm.DB {
        // Mock 实现
        return &gorm.DB{}
    })
defer patches.Reset()
```

**重要**: gomonkey 测试归类为单元测试，因为它们不依赖真实的外部服务。

## 🔄 CI/CD 集成

### GitHub Actions 工作流

项目使用 GitHub Actions 进行自动化测试，配置文件：`.github/workflows/test.yml`

**测试矩阵**:
```yaml
strategy:
  matrix:
    go-version: [1.25.x]
    database: [mysql, postgres, sqlite]
```

**关键特性**:
- **环境隔离**: 每个数据库测试完全独立
- **DSN 管理**: 避免环境变量污染
- **Alpine 镜像**: 提升 CI 性能
- **并行执行**: 不同数据库并行测试

### 本地 CI 模拟

```bash
# 模拟 CI 环境运行测试
export CGO_ENABLED=1
export SMTP_HOST="localhost"
export SMTP_PORT="1025"

# 清理环境变量
unset MYSQL_DSN POSTGRES_DSN SQLITE_DSN

# 运行特定数据库测试
export POSTGRES_DSN="host=localhost user=gosso password=gosso123 dbname=gosso_test port=5433 sslmode=disable"
go test -v -race -coverprofile=coverage.out -tags postgres ./...
```

## 🐛 故障排除

### 常见问题

#### 1. 数据库连接失败

**症状**: `sql: unknown driver "mysql"`

**原因**: 缺少编译标签或环境变量设置错误

**解决**:
```bash
# 确保使用正确的编译标签
go test -tags mysql ./...

# 检查环境变量
echo $MYSQL_DSN
```

#### 2. Docker 服务启动失败

**症状**: 测试超时或连接被拒绝

**解决**:
```bash
# 检查服务状态
docker-compose -f docker-compose.test.yml ps

# 查看服务日志
docker-compose -f docker-compose.test.yml logs mysql-test

# 重启服务
docker-compose -f docker-compose.test.yml restart
```

#### 3. 端口冲突

**症状**: `bind: address already in use`

**解决**:
```bash
# 检查端口占用
lsof -i :3307
lsof -i :5433

# 停止冲突的服务
docker-compose -f docker-compose.test.yml down
```

#### 4. 权限问题

**症状**: Docker 权限被拒绝

**解决**:
```bash
# 添加用户到 docker 组 (Linux)
sudo usermod -aG docker $USER

# 重新登录或使用 newgrp
newgrp docker
```

### 调试技巧

#### 1. 详细日志输出

```bash
# 运行测试时显示详细输出
go test -v ./...

# 显示测试覆盖率详情
go test -v -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

#### 2. 单独测试特定包

```bash
# 只测试账户服务
go test -v ./internal/service/account

# 只测试数据库工厂
go test -v -tags postgres ./internal/database/factory
```

#### 3. 跳过集成测试

```bash
# 使用 -short 标志跳过耗时的集成测试
go test -short ./...
```

## 📈 性能优化

### 测试执行时间优化

1. **并行测试**: 使用 `t.Parallel()` 并行执行独立测试
2. **测试缓存**: Go 会自动缓存未变更包的测试结果
3. **选择性测试**: 根据代码变更只运行相关测试
4. **内存数据库**: SQLite 使用 `:memory:` 模式

### CI/CD 性能优化

1. **Alpine 镜像**: 减少镜像下载时间
2. **Docker 缓存**: 利用 Docker 层缓存
3. **Go 模块缓存**: 缓存依赖下载
4. **并行矩阵**: 不同数据库并行测试

## 🔮 未来规划

### 测试增强计划

- [ ] **性能测试**: 添加基准测试和性能回归检测
- [ ] **E2E 测试**: 完整的端到端测试场景
- [ ] **混沌测试**: 故障注入和恢复测试
- [ ] **负载测试**: 高并发场景测试
- [ ] **安全测试**: 自动化安全漏洞扫描

### 工具集成

- [ ] **测试报告**: 集成测试报告生成工具
- [ ] **覆盖率趋势**: 跟踪覆盖率变化趋势
- [ ] **测试选择**: 智能测试选择，只运行相关测试
- [ ] **并行优化**: 进一步优化测试并行度

---

## 📚 参考资料

- [Go Testing Package](https://golang.org/pkg/testing/)
- [Convey Testing Framework](https://github.com/smartystreets/goconvey)
- [GoMonkey Mocking](https://github.com/agiledragon/gomonkey)
- [Docker Compose Testing](https://docs.docker.com/compose/)
- [GitHub Actions Go](https://docs.github.com/en/actions/guides/building-and-testing-go)

---

*最后更新: 2025-09-24*
*维护者: GoSSO 开发团队*