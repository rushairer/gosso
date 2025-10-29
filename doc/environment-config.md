# 环境配置管理系统

## 概述

本项目实现了统一的环境配置管理系统，以 `config/config.go` 为核心，通过 `config/environments.yaml` 定义各环境的基础设施配置，确保 `script/parse-config.go` 和 Docker Compose 文件之间的配置一致性。

## 文件结构

```
config/
├── config.go              # 核心业务配置结构定义
├── development.yaml       # 开发环境应用配置
├── test.yaml             # 测试环境应用配置
└── production.yaml       # 生产环境应用配置

deploy/                    # 部署配置目录（新增）
├── config.go             # 部署配置结构定义
└── environments.yaml     # 环境配置定义

script/
├── parse-config.go       # 配置解析脚本（重构）
└── generate-env.sh       # 环境变量生成脚本（新增）

docker-compose.development.yml
docker-compose.test.yml
docker-compose.yml
```

## 配置层次

### 1. 业务配置 (config/*.yaml)
- 定义应用内部的业务配置
- 数据库连接、Redis 配置、SMTP 设置等
- 由 `config/config.go` 中的结构体定义
- 专注于应用逻辑相关的配置

### 2. 部署配置 (deploy/environments.yaml)
- 定义各环境的基础设施配置
- 端口映射、网络配置、容器配置等
- 由 `deploy/config.go` 中的结构体定义
- 专注于部署和基础设施相关的配置

## 使用方法

### 生成环境变量

```bash
# 生成单个环境配置
make env-dev      # 开发环境
make env-test     # 测试环境  
make env-prod     # 生产环境

# 生成所有环境配置
make env-all
```

### 使用生成的环境变量

```bash
# 方法1: 直接加载到当前 shell
source .env.development

# 方法2: 在 Docker Compose 中使用
docker-compose --env-file .env.development -f docker-compose.development.yml up -d

# 方法3: 在 Makefile 中使用（已集成）
make docker-dev-up
```

## 端口映射配置

### 端口命名规则

- **容器内端口**: `SERVICE_PORT` (如 `APP_PORT`, `POSTGRES_PORT`)
- **宿主机端口**: `SERVICE_EXTERNAL_PORT` (如 `APP_EXTERNAL_PORT`, `POSTGRES_EXTERNAL_PORT`)

### 默认端口定义

| 服务 | 默认端口 | 说明 |
|------|----------|------|
| APP | 8080 | 应用服务端口 |
| POSTGRES | 5432 | PostgreSQL 数据库端口 |
| REDIS | 6379 | Redis 缓存端口 |
| SMTP | 1025 | SMTP 邮件服务端口 |
| MAILPIT_WEB | 8025 | Mailpit Web UI 端口 |
| NGINX_HTTP | 80 | Nginx HTTP 端口 |
| NGINX_HTTPS | 443 | Nginx HTTPS 端口 |

### 环境端口分配

#### Production 环境
外部端口 = 默认端口 (偏移 +0)

| 服务 | 容器内端口 | 宿主机端口 | 环境变量 |
|------|------------|------------|----------|
| APP | 8080 | 8080 | `APP_PORT=8080`, `APP_EXTERNAL_PORT=8080` |
| POSTGRES | 5432 | 5432 | `POSTGRES_PORT=5432`, `POSTGRES_EXTERNAL_PORT=5432` |
| REDIS | 6379 | 6379 | `REDIS_PORT=6379`, `REDIS_EXTERNAL_PORT=6379` |
| NGINX | 80/443 | 80/443 | `NGINX_HTTP_PORT=80`, `NGINX_HTTPS_PORT=443` |

#### Development 环境
外部端口 = 默认端口 + 1 (偏移 +1)

| 服务 | 容器内端口 | 宿主机端口 | 环境变量 |
|------|------------|------------|----------|
| APP | 8080 | 8081 | `APP_PORT=8080`, `APP_EXTERNAL_PORT=8081` |
| POSTGRES | 5432 | 5433 | `POSTGRES_PORT=5432`, `POSTGRES_EXTERNAL_PORT=5433` |
| REDIS | 6379 | 6380 | `REDIS_PORT=6379`, `REDIS_EXTERNAL_PORT=6380` |
| SMTP | 1025 | 1026 | `SMTP_PORT=1025`, `SMTP_EXTERNAL_PORT=1026` |
| MAILPIT_WEB | 8025 | 8026 | `MAILPIT_WEB_PORT=8025`, `MAILPIT_WEB_EXTERNAL_PORT=8026` |

#### Test 环境
外部端口 = 默认端口 + 2 (偏移 +2)

| 服务 | 容器内端口 | 宿主机端口 | 环境变量 |
|------|------------|------------|----------|
| APP | 8080 | 8082 | `APP_PORT=8080`, `APP_EXTERNAL_PORT=8082` |
| POSTGRES | 5432 | 5434 | `POSTGRES_PORT=5432`, `POSTGRES_EXTERNAL_PORT=5434` |
| REDIS | 6379 | 6381 | `REDIS_PORT=6379`, `REDIS_EXTERNAL_PORT=6381` |
| SMTP | 1025 | 1027 | `SMTP_PORT=1025`, `SMTP_EXTERNAL_PORT=1027` |
| MAILPIT_WEB | 8025 | 8027 | `MAILPIT_WEB_PORT=8025`, `MAILPIT_WEB_EXTERNAL_PORT=8027` |

### Docker Compose 端口映射示例

```yaml
services:
  gosso:
    ports:
      - "${APP_EXTERNAL_PORT:-8081}:${APP_PORT:-8080}"
    healthcheck:
      test: ["CMD", "wget", "--spider", "http://localhost:${APP_PORT:-8080}/health"]
  
  postgres:
    ports:
      - "${POSTGRES_EXTERNAL_PORT:-5433}:${POSTGRES_PORT:-5432}"
  
  redis:
    ports:
      - "${REDIS_EXTERNAL_PORT:-6380}:${REDIS_PORT:-6379}"
```

### 环境变量使用

#### 在应用代码中
```go
// 使用容器内端口
port := os.Getenv("APP_PORT")        // 8080
dbPort := os.Getenv("POSTGRES_PORT") // 5432
```

#### 在 Docker Compose 中
```yaml
# 使用外部端口进行端口映射
ports:
  - "${APP_EXTERNAL_PORT}:${APP_PORT}"
  
# 使用内部端口进行健康检查
healthcheck:
  test: ["CMD", "curl", "http://localhost:${APP_PORT}/health"]
```

### 端口配置优势

1. **命名统一**: 所有服务都遵循相同的命名规则
2. **端口规律**: 不同环境的端口分配有明确的规律
3. **避免冲突**: 不同环境使用不同的外部端口
4. **易于理解**: 内部端口使用标准端口，外部端口有规律偏移
5. **配置简化**: 减少硬编码，提高可维护性

## 配置优先级

1. **环境配置** (`config/environments.yaml`) - 基础设施配置
2. **应用配置** (`config/*.yaml`) - 应用业务配置
3. **环境变量** - 运行时覆盖

## 添加新环境

1. 在 `deploy/environments.yaml` 中添加新环境定义
2. 创建对应的应用配置文件 `config/新环境.yaml`
3. 运行 `make env-新环境` 生成环境变量
4. 创建对应的 `docker-compose.新环境.yml` 文件

## 修改配置

### 修改基础设施配置（端口、网络等）
编辑 `deploy/environments.yaml`

### 修改应用配置（数据库连接、业务设置等）
编辑对应的 `config/*.yaml` 文件

### 重新生成环境变量
```bash
make env-all  # 或指定环境 make env-dev
```

## 配置验证

生成的环境变量会显示详细的配置信息：

```
✅ DEVELOPMENT 环境配置解析完成:
  🌐 应用: 8081 -> 8080 (debug)
  🐘 PostgreSQL: postgres:5433 -> 5432 (DB: gosso_dev)
  🔴 Redis: redis:6380 -> 6379 (DB: 0)
  📧 SMTP: mailpit:1026 -> 1025
  🌐 Mailpit Web: 8026 -> 8025
```

## 故障排除

### 配置不生效
1. 检查 `deploy/environments.yaml` 语法
2. 重新生成环境变量：`make env-all`
3. 确认使用了正确的 `.env.*` 文件

### 端口冲突
1. 检查 `deploy/environments.yaml` 中的端口配置
2. 确保不同环境使用不同的外部端口
3. 重新生成并应用配置

### Docker Compose 启动失败
1. 确认已生成对应的 `.env.*` 文件
2. 检查 Docker Compose 文件中的环境变量引用
3. 验证网络和卷配置

## 最佳实践

1. **职责分离**: 业务配置 (`config/`) 与部署配置 (`deploy/`) 分离
2. **统一配置源**: 所有部署配置都通过 `deploy/environments.yaml` 管理
3. **版本控制**: 将 `deploy/environments.yaml` 纳入版本控制
4. **环境隔离**: 不同环境使用不同的端口和网络
5. **配置验证**: 每次修改后重新生成并验证环境变量
6. **文档更新**: 配置变更时及时更新相关文档