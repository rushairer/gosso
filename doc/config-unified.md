# 统一配置管理方案

## 概述

项目现在采用统一配置管理方案，解决了之前 `config/test.yaml` 和 `docker-compose.test.yml` 配置重复维护的问题。

## 设计原则

### 单一配置源
- **配置定义**: `config/test.yaml` 作为唯一的配置定义文件
- **动态解析**: Docker Compose 通过环境变量从配置文件动态读取
- **自动化**: 集成测试脚本自动解析配置并传递给 Docker Compose

### 配置流程

```
config/test.yaml (配置定义)
       ↓
scripts/parse-test-config.go (解析脚本)
       ↓
环境变量 (MYSQL_PORT, POSTGRES_PORT, etc.)
       ↓
docker-compose.test.yml (动态配置)
       ↓
Docker 容器 (运行时配置)
```

## 文件说明

### 1. 配置文件 (`config/test.yaml`)
```yaml
database:
    drivers:
        mysql:
            dsn: gosso:gosso123@tcp(127.0.0.1:3308)/gosso_test?charset=utf8mb4&parseTime=True&loc=Local
        postgres:
            dsn: host=127.0.0.1 user=gosso password=gosso123 dbname=gosso_test port=5434 sslmode=disable
smtp:
    host: localhost
    port: 1027
```

### 2. 配置解析脚本 (`scripts/parse-test-config.go`)
- 解析 `config/test.yaml` 中的数据库和 SMTP 配置
- 提取端口、用户名、密码、数据库名等信息
- 输出环境变量供 Docker Compose 使用

### 3. Docker Compose 配置 (`docker-compose.test.yml`)
```yaml
services:
  mysql-test:
    environment:
      MYSQL_DATABASE: ${MYSQL_DATABASE:-gosso_test}
      MYSQL_USER: ${MYSQL_USER:-gosso}
      MYSQL_PASSWORD: ${MYSQL_PASSWORD:-gosso123}
    ports:
      - "${MYSQL_EXTERNAL_PORT:-3308}:3306"
```

### 4. 集成测试脚本 (`scripts/test-integration.sh`)
```bash
# 解析测试配置
eval "$(go run scripts/parse-test-config.go)"

# 启动测试服务 (使用解析的环境变量)
docker-compose -f docker-compose.test.yml up -d
```

## 使用方法

### 修改配置
只需要修改 `config/test.yaml` 文件：

```yaml
# 修改 MySQL 端口
database:
    drivers:
        mysql:
            dsn: gosso:gosso123@tcp(127.0.0.1:3309)/gosso_test?...

# 修改 SMTP 端口  
smtp:
    port: 1028
```

### 运行测试
```bash
# 运行集成测试 (自动解析配置)
./scripts/test-integration.sh

# 手动启动测试环境
eval "$(go run scripts/parse-test-config.go)"
docker-compose -f docker-compose.test.yml up -d
```

### 查看解析结果
```bash
go run scripts/parse-test-config.go
```

## 优势

### 1. **配置统一**
- 单一配置源，避免重复维护
- 修改配置只需要更新一个文件

### 2. **自动化**
- 脚本自动解析配置并传递给 Docker Compose
- 无需手动同步多个配置文件

### 3. **灵活性**
- 支持多种解析方式 (Go/Python/yq)
- 环境变量提供默认值兜底

### 4. **可维护性**
- 配置变更影响范围清晰
- 减少配置不一致导致的问题

## 端口规范

项目采用统一的端口规范：
- **Production**: 默认端口 (MySQL: 3306, PostgreSQL: 5432, SMTP: 1025, Web: 8025)
- **Development**: 默认端口 + 1 (MySQL: 3307, PostgreSQL: 5433, SMTP: 1026, Web: 8026)  
- **Test**: 默认端口 + 2 (MySQL: 3308, PostgreSQL: 5434, SMTP: 1027, Web: 8027)

## 故障排除

### 配置解析失败
```bash
# 检查配置文件语法
go run scripts/parse-test-config.go

# 检查 YAML 格式
cat config/test.yaml | head -20
```

### Docker 启动失败
```bash
# 检查环境变量
eval "$(go run scripts/parse-test-config.go)"
echo "MySQL: $MYSQL_EXTERNAL_PORT, PostgreSQL: $POSTGRES_EXTERNAL_PORT"

# 检查端口冲突
lsof -i :3308
lsof -i :5434