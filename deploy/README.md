# Deploy 部署配置

本目录包含项目的部署和基础设施配置，与业务逻辑配置 (`config/`) 分离。

## 文件说明

### `config.go`
- 定义部署配置的 Go 结构体
- 提供配置加载和访问函数
- 独立的包，不依赖业务配置

### `environments.yaml`
- 定义各环境的基础设施配置
- 包括端口映射、网络配置、容器配置等
- 用于生成 Docker Compose 环境变量

## 配置结构

```yaml
environments:
  development:
    description: "开发环境配置"
    app:
      external_port: 8081    # 外部访问端口
      internal_port: 8080    # 容器内部端口
      debug: true
      gin_mode: debug
    postgres:
      external_port: 5433    # 外部访问端口
      internal_port: 5432    # 容器内部端口
      database: gosso_dev
      user: gosso
      password: gosso123
    # ... 其他服务配置
```

## 使用方法

### 在 Go 代码中使用

```go
import "github.com/rushairer/gosso/deploy"

// 初始化部署配置
if err := deploy.InitDeployConfig("deploy"); err != nil {
    log.Fatal(err)
}

// 获取环境配置
envConfig, exists := deploy.GetEnvironment("development")
if !exists {
    log.Fatal("Environment not found")
}

// 使用配置
fmt.Printf("App port: %d\n", envConfig.App.ExternalPort)
```

### 生成环境变量

```bash
# 使用 script/parse-config.go 生成环境变量
go run script/parse-config.go development

# 或使用 Makefile
make env-dev
```

## 设计原则

1. **职责分离**: 只包含部署和基础设施相关配置
2. **环境隔离**: 不同环境使用不同的端口和网络
3. **配置统一**: 作为 Docker Compose 和脚本的单一配置源
4. **易于维护**: 结构清晰，便于修改和扩展

## 与 config/ 的区别

| 目录 | 用途 | 内容 | 示例 |
|------|------|------|------|
| `config/` | 业务配置 | 数据库连接、业务逻辑设置 | 数据库 DSN、Redis 连接、SMTP 设置 |
| `deploy/` | 部署配置 | 基础设施、端口映射 | 外部端口、网络配置、容器设置 |

这种分离确保了业务逻辑与部署环境的解耦，提高了代码的可维护性和可移植性。