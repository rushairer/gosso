# GoSSO 端口规范文档

## 概述

为了避免不同环境之间的端口冲突，GoSSO 项目采用统一的端口分配规范。

## 端口分配规则

- **Production 环境**: 使用服务的默认端口
- **Development 环境**: 默认端口 + 1
- **Test 环境**: 默认端口 + 2

## 端口分配表

| 服务类型 | 服务名称 | Production | Development | Test | 说明 |
|---------|----------|------------|-------------|------|------|
| **Web 服务** | GoSSO API Server | 8080 | 8081 | 8082 | HTTP API 服务端口 |
| **数据库** | MySQL/MariaDB | 3306 | 3307 | 3308 | 关系型数据库 |
| **数据库** | PostgreSQL | 5432 | 5433 | 5434 | 关系型数据库 |
| **缓存** | Redis | 6379 | 6380 | 6381 | 内存缓存数据库 |
| **邮件** | Mailpit SMTP | 1025 | 1026 | 1027 | SMTP 邮件发送端口 |
| **邮件** | Mailpit Web UI | 8025 | 8026 | 8027 | 邮件测试 Web 界面 |

## 配置文件对应

### Production 环境 (`config/production.yaml`)
```yaml
web_server:
  port: 8080

database:
  mysql:
    port: 3306
  postgres:
    port: 5432

redis:
  port: 6379

smtp:
  port: 1025  # 生产环境使用真实 SMTP 服务
```

### Development 环境 (`config/development.yaml`)
```yaml
web_server:
  port: 8081

database:
  mysql:
    port: 3307
  postgres:
    port: 5433

redis:
  port: 6380

smtp:
  port: 1026  # 开发环境使用 Mailpit
```

### Test 环境 (`config/test.yaml`)
```yaml
web_server:
  port: 8082

database:
  mysql:
    port: 3308
  postgres:
    port: 5434

redis:
  port: 6381

smtp:
  port: 1027  # 测试环境使用 Mailpit
```

## Docker Compose 配置

### 开发环境 (`docker-compose.yml`)
```yaml
services:
  mysql-dev:
    ports:
      - "3307:3306"
  
  postgres-dev:
    ports:
      - "5433:5432"
  
  redis-dev:
    ports:
      - "6380:6379"
  
  mailpit-dev:
    ports:
      - "1026:1025"  # SMTP
      - "8026:8025"  # Web UI
```

### 测试环境 (`docker-compose.test.yml`)
```yaml
services:
  mysql-test:
    ports:
      - "3308:3306"
  
  postgres-test:
    ports:
      - "5434:5432"
  
  redis-test:
    ports:
      - "6381:6379"
  
  mailpit-test:
    ports:
      - "1027:1025"  # SMTP
      - "8027:8025"  # Web UI
```

## 端口冲突检查

### 检查端口占用
```bash
# 检查所有相关端口
lsof -i :8080,8081,8082,3306,3307,3308,5432,5433,5434,6379,6380,6381,1025,1026,1027,8025,8026,8027

# 检查特定端口
lsof -i :8081  # 开发环境 Web 服务
lsof -i :3307  # 开发环境 MySQL
```

### 端口释放
```bash
# 停止相关 Docker 服务
docker-compose down
docker-compose -f docker-compose.test.yml down

# 强制释放端口（如果需要）
sudo lsof -ti:端口号 | xargs kill -9
```

## 环境切换

### 启动开发环境
```bash
# 启动开发环境服务
docker-compose up -d

# 启动应用
./bin/gosso --config_path ./config --env development
```

### 运行测试环境
```bash
# 启动测试环境服务
docker-compose -f docker-compose.test.yml up -d

# 运行集成测试
./scripts/test-integration.sh
```

## 防火墙和安全

### 生产环境
- 只开放必要的端口 (8080)
- 数据库端口不对外暴露
- 使用内网通信

### 开发/测试环境
- 可以开放所有端口用于调试
- 注意不要在公网环境使用开发配置

## 监控和日志

### 端口监控
```bash
# 监控端口状态
netstat -tlnp | grep -E ':(8080|8081|8082|3306|3307|3308|5432|5433|5434|6379|6380|6381|1025|1026|1027|8025|8026|8027)'
```

### 服务健康检查
```bash
# Web 服务健康检查
curl http://localhost:8081/health  # 开发环境
curl http://localhost:8082/health  # 测试环境

# 数据库连接检查
mysql -h localhost -P 3307 -u gosso -p  # 开发环境 MySQL
psql -h localhost -p 5433 -U gosso -d gosso_dev  # 开发环境 PostgreSQL
```

## 故障排除

### 常见问题

1. **端口被占用**
   ```bash
   # 查找占用进程
   lsof -i :端口号
   
   # 停止进程
   kill -9 进程ID
   ```

2. **Docker 端口映射失败**
   ```bash
   # 检查 Docker 网络
   docker network ls
   
   # 重启 Docker 服务
   docker-compose down && docker-compose up -d
   ```

3. **配置文件端口不匹配**
   - 检查配置文件中的端口设置
   - 确保 Docker Compose 端口映射正确
   - 验证应用启动参数

## 扩展规划

如需添加新服务，请遵循以下规则：

1. **选择默认端口**: 选择服务的标准默认端口
2. **应用规则**: Production 使用默认端口，Development +1，Test +2
3. **更新文档**: 在此文档中添加新服务的端口分配
4. **更新配置**: 同步更新所有环境的配置文件
5. **测试验证**: 确保新端口不与现有服务冲突

## 总结

这个端口规范确保了：
- ✅ 不同环境之间无端口冲突
- ✅ 配置文件与 Docker Compose 保持一致
- ✅ 便于开发、测试和部署
- ✅ 易于维护和扩展

遵循此规范可以避免端口冲突问题，提高开发效率。