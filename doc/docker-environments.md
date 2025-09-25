# Docker 环境管理

本项目实现了统一的配置管理方案，支持多环境部署。所有环境配置都从 `config/` 目录读取，确保配置的一致性和可维护性。

## 环境配置文件

```
config/
├── development.yaml    # 开发环境配置
├── production.yaml     # 生产环境配置
├── test.yaml          # 测试环境配置
└── config.go          # Go 配置结构定义
```

## Docker Compose 文件

```
├── docker-compose.development.yml  # 开发环境 Docker 配置
├── docker-compose.production.yml   # 生产环境 Docker 配置
├── docker-compose.test.yml         # 测试环境 Docker 配置
└── docker-compose.yml              # 默认配置（已弃用，建议使用具体环境配置）
```

## 快速开始

### 开发环境

```bash
# 启动开发环境
make docker-dev-up

# 查看日志
make docker-dev-logs

# 停止开发环境
make docker-dev-down
```

开发环境特点：
- 应用端口：8081
- MySQL 端口：3307
- PostgreSQL 端口：5433
- Redis 端口：6380
- Mailpit SMTP：1026
- Mailpit Web UI：http://localhost:8026
- 启用调试模式和热重载

### 生产环境

```bash
# 启动生产环境
make docker-prod-up

# 查看日志
make docker-prod-logs

# 停止生产环境
make docker-prod-down
```

生产环境特点：
- 应用端口：8080
- MySQL 端口：3306
- PostgreSQL 端口：5432
- Redis 端口：6379
- 包含 Nginx 反向代理
- 资源限制和性能优化
- 生产级安全配置

### 测试环境

```bash
# 运行所有测试（自动管理测试环境）
make test-all

# 仅运行集成测试
make test-integration

# 清理测试环境
make test-clean
```

测试环境特点：
- MySQL 端口：3308
- PostgreSQL 端口：5434
- Redis 端口：6381
- Mailpit SMTP：1027
- Mailpit Web UI：http://localhost:8027
- 自动清理和隔离

## 配置解析机制

项目使用 `scripts/parse-config.go` 统一解析各环境配置：

```bash
# 解析开发环境配置
go run scripts/parse-config.go development

# 解析生产环境配置
go run scripts/parse-config.go production

# 解析测试环境配置
go run scripts/parse-config.go test
```

解析器会：
1. 读取对应的 YAML 配置文件
2. 解析数据库连接字符串
3. 生成 Docker Compose 所需的环境变量
4. 设置端口映射避免冲突

## 端口分配策略

为避免多环境冲突，采用以下端口分配：

| 服务 | 开发环境 | 生产环境 | 测试环境 |
|------|----------|----------|----------|
| 应用 | 8081 | 8080 | - |
| MySQL | 3307 | 3306 | 3308 |
| PostgreSQL | 5433 | 5432 | 5434 |
| Redis | 6380 | 6379 | 6381 |
| SMTP | 1026 | 1025 | 1027 |
| Mailpit Web | 8026 | 8025 | 8027 |

## 数据库支持

每个环境都支持多种数据库：
- **MySQL 8.0**：主要关系型数据库
- **PostgreSQL 15**：高级关系型数据库
- **SQLite**：轻量级数据库（主要用于测试）

应用会根据配置文件中的 `database.default` 设置选择默认数据库。

## 邮件服务

开发和测试环境使用 [Mailpit](https://github.com/axllent/mailpit) 作为邮件测试工具：
- 捕获所有发送的邮件
- 提供 Web 界面查看邮件
- 支持 SMTP 协议测试

生产环境需要配置真实的 SMTP 服务器。

## 网络隔离

每个环境使用独立的 Docker 网络：
- 开发环境：`gosso-dev-network` (172.21.0.0/16)
- 生产环境：`gosso-prod-network` (172.22.0.0/16)
- 测试环境：`gosso-test-network` (172.20.0.0/16)

## 数据持久化

每个环境使用独立的数据卷：
- 开发环境：`mysql_dev_data`, `postgres_dev_data`, `redis_dev_data`
- 生产环境：`mysql_prod_data`, `postgres_prod_data`, `redis_prod_data`
- 测试环境：`mysql_test_data`, `postgres_test_data`, `redis_test_data`

## 健康检查

所有服务都配置了健康检查：
- 数据库服务：连接性检查
- 应用服务：HTTP 端点检查
- Redis：ping 命令检查

## 故障排除

### 端口冲突
如果遇到端口冲突，检查：
1. 其他服务是否占用相同端口
2. 配置文件中的端口设置
3. Docker 容器是否已在运行

### 配置解析失败
确保：
1. Go 环境已正确安装
2. 配置文件语法正确
3. 所有必需字段都已填写

### 服务启动失败
检查：
1. Docker 和 Docker Compose 版本
2. 系统资源是否充足
3. 网络连接是否正常

## 最佳实践

1. **环境隔离**：始终使用对应环境的配置文件
2. **配置管理**：不要在 Docker Compose 文件中硬编码配置
3. **端口管理**：遵循端口分配策略避免冲突
4. **数据备份**：生产环境定期备份数据卷
5. **监控日志**：使用 `make docker-*-logs` 监控服务状态