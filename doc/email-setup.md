# GoSSO 邮件发送功能使用指南

## 概述

GoSSO 项目已经集成了完整的邮件发送功能，支持发送测试邮件和验证码邮件。默认配置为使用本地 Mailpit 进行邮件测试。

## 功能特性

- ✅ 支持 SMTP 邮件发送
- ✅ 美观的 HTML 邮件模板
- ✅ 验证码邮件发送

- ✅ Mailpit 本地测试支持
- ✅ 可配置的 SMTP 设置

## 配置说明

### SMTP 配置

邮件发送配置位于 `config/development.yaml` 文件中：

```yaml
smtp:
    host: localhost        # SMTP 服务器地址
    port: 1025            # SMTP 端口
    username: ""          # SMTP 用户名（Mailpit 不需要）
    password: ""          # SMTP 密码（Mailpit 不需要）
    from: "noreply@gosso.local"  # 发件人邮箱
```

### Mailpit 设置

Mailpit 是一个现代化的邮件测试工具，默认配置：
- SMTP 端口: 1025
- Web 界面: http://localhost:8025

## 使用方法

### 1. 启动 Mailpit

```bash
# 使用 Docker 启动 Mailpit（推荐）
docker run -d --name mailpit -p 1025:1025 -p 8025:8025 axllent/mailpit:latest

# 或者使用 docker-compose
docker-compose -f docker-compose.test.yml up -d mailpit-test
```

### 2. 构建项目

```bash
# 构建项目
go build -o bin/gosso ./cmd
```

### 3. 发送验证码邮件

```bash
# 发送默认验证码邮件
./bin/gosso email code test@example.com --config_path ./config --env development

# 发送指定验证码邮件
./bin/gosso email code test@example.com \
  --code 123456 \
  --config_path ./config --env development
```

### 5. 查看邮件

访问 Mailpit Web 界面查看发送的邮件：
```
http://localhost:8025
```

## 命令行参数

### 全局参数

- `--config_path` / `-p`: 配置文件路径（默认: ./config）
- `--env` / `-e`: 环境（development/test/production，默认: development）

### 测试邮件参数

- `--subject` / `-s`: 邮件主题
- `--content` / `-c`: 邮件内容

### 验证码邮件参数

- `--code` / `-k`: 验证码（默认: 123456）

## 邮件模板

### 测试邮件模板

测试邮件包含以下信息：
- 邮件主题和内容
- SMTP 服务器配置信息
- 发送时间
- GoSSO 品牌标识

### 验证码邮件模板

验证码邮件包含：
- 醒目的验证码显示
- 有效期提醒（5分钟）
- 安全提示
- 专业的视觉设计

## 集成到应用中

### 在任务中使用

邮件发送已经集成到任务系统中，可以通过 `SendEmailCodeTask` 发送验证码：

```go
// 创建邮件发送任务
task := account.NewSendEmailCodeTask("user@example.com")

// 添加到任务管道
taskPipeline.Add(ctx, task)
```

### 直接使用邮件服务

```go
// 创建邮件服务
emailService := service.NewEmailService(config.GlobalConfig.SMTPConfig)

// 发送验证码邮件
err := emailService.SendVerificationCode("user@example.com", "123456")


```

## 生产环境配置

在生产环境中，需要修改 `config/production.yaml` 中的 SMTP 配置：

```yaml
smtp:
    host: "smtp.gmail.com"     # 实际的 SMTP 服务器
    port: 587                  # 实际的 SMTP 端口
    username: "your-email@gmail.com"
    password: "your-app-password"
    from: "noreply@yourdomain.com"
```

## 故障排除

### 常见问题

1. **邮件发送失败**
   - 检查 Mailpit 是否正在运行
   - 确认 SMTP 配置是否正确
   - 查看应用日志获取详细错误信息

2. **Mailpit 无法访问**
   - 确认 Mailpit 容器已启动：`docker ps | grep mailpit`
   - 检查端口是否被占用：`lsof -i :8025`

3. **配置文件找不到**
   - 确认配置文件路径正确
   - 检查文件权限

### 日志查看

应用会输出详细的邮件发送日志，包括：
- SMTP 连接状态
- 邮件发送结果
- 错误信息

## 扩展功能

可以根据需要扩展以下功能：
- 邮件模板系统
- 附件支持
- 批量邮件发送
- 邮件发送统计
- 邮件队列管理

## 总结

GoSSO 的邮件发送功能已经完全配置好，可以：
1. 在开发环境中使用 Mailpit 进行测试
2. 通过命令行工具快速测试邮件发送
3. 在应用中集成邮件发送功能
4. 轻松切换到生产环境的 SMTP 服务器

现在你可以开始使用邮件功能进行开发和测试了！