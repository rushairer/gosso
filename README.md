# gosso

gosso 是一个基于 gouno 生成的 Go Web 项目。

> gouno 是 Go 语言的 Web 应用脚手架，旨在提供一个快速、可靠的起点来构建生产级别的 Web 服务。它集成了 Gin 框架、Cobra CLI 工具和 Viper 配置管理，并遵循清晰的架构设计，帮助开发者专注于业务逻辑的实现。

## 🚀 特性

- **Gin 框架**: 高性能的 HTTP Web 框架
- **Cobra CLI**: 强大的命令行接口工具，方便构建命令行应用
- **Viper 配置管理**: 灵活的配置解决方案，支持多种格式和热加载
- **分层架构**: 采用 DDD 领域驱动设计，易于理解和扩展
- **多数据库支持**: 支持 MySQL、PostgreSQL、SQLite
- **优雅关机**: 支持平滑关机，确保请求得到妥善处理
- **代码生成器**: 提供快速生成业务代码的工具

## 📦 安装与运行

### 前提条件

- Go 1.23.3+ 环境

### 克隆项目

```bash
git clone <repository-url>
cd gosso
```

### 构建项目

```bash
make build
```

### 运行 Web 服务

```bash
./bin/gouno web --config ./config/config.yaml --address 0.0.0.0 --port 8080
```

默认情况下，Web 服务将在 `http://0.0.0.0:8080` 启动。

### 开发模式

```bash
make dev
```

## 🏗️ 项目结构

```
├── cmd/            # 主应用程序入口
│   └── gouno/      # CLI命令实现
├── config/         # 配置文件
├── controller/     # 控制器层
├── doc/            # 项目文档
├── internal/       # 内部应用代码 (核心业务逻辑)
│   ├── context/    # 上下文管理
│   ├── database/   # 数据库连接和工厂模式
│   ├── domain/     # 领域模型层 (DDD)
│   ├── repository/ # 数据访问层
│   ├── service/    # 业务逻辑层
│   └── task/       # 任务处理
├── middleware/     # 中间件
├── router/         # 路由定义
├── test/           # 测试文件
├── utility/        # 工具函数
└── Makefile        # 构建脚本
```

## 🎯 架构设计

本项目采用 **分层架构 + DDD (领域驱动设计)** 模式：

- **Controller**: HTTP 请求处理和参数验证
- **Service**: 业务逻辑实现和流程编排  
- **Repository**: 数据访问抽象和持久化
- **Domain**: 领域模型和业务规则
- **Database**: 数据库连接和工厂模式

## 🗄️ 数据库支持

支持多种数据库，使用编译标签选择：

```bash
# MySQL
go build -tags mysql

# PostgreSQL  
go build -tags postgres

# SQLite
go build -tags sqlite
```

## 🛠️ 代码生成器

```bash
./bin/gouno gen -h
```

支持生成以下代码：
- `controller` - 生成控制器
- `domain` - 生成领域模型
- `repository` - 生成仓储
- `service` - 生成服务
- `suit` - 生成完整套件 (domain, repository, service)

## ⚙️ 配置

配置文件位于 `./config/config.yaml`：

```yaml
web_server:
    address: 0.0.0.0
    port: 8080
    debug: false
```

### 命令行参数

- `--config` 或 `-c`: 指定配置文件路径，默认为 `./config/config.yaml`
- `--address` 或 `-a`: 指定监听地址，默认为 `0.0.0.0`
- `--port` 或 `-p`: 指定监听端口，默认为 `8080`
- `--debug` 或 `-d`: 开启调试模式，默认为 `false`

## 📚 文档导航

- **[架构文档](internal/README.md)** - 内部模块架构说明
- **[数据库层](internal/database/README.md)** - 数据库连接和工厂模式
- **[业务逻辑层](internal/service/README.md)** - 服务层设计和使用
- **[数据访问层](internal/repository/README.md)** - 仓储模式实现
- **[领域模型层](internal/domain/README.md)** - DDD 领域设计
- **[账户服务](internal/service/account/README.md)** - 账户业务模块
- **[文档维护指南](doc/README_GUIDE.md)** - 如何维护项目文档

## 📝 开发日志

- **[2025年9月](doc/dev-log/2025-09.md)** - 当前开发进度
- **[开发日志模板](doc/dev-log/TEMPLATE.md)** - 日志记录规范

## 🧪 测试

```bash
# 运行所有测试
go test ./...

# 运行特定模块测试
go test ./internal/service/account -v

# 运行数据库工厂测试 (需要编译标签)
go test ./internal/database/factory -v -tags mysql
```

## 🔧 Makefile 命令

- `make build`: 构建项目
- `make run`: 运行开发服务器
- `make dev`: 运行开发模式

## 🌐 API 示例

项目提供了一个简单的健康检查接口：

```bash
curl http://localhost:8080/test/alive
# 返回: pong
```

## 🤝 贡献

欢迎通过以下方式为 gosso 贡献代码：

1. Fork 本仓库
2. 创建您的特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交您的更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

## 📄 许可证

本项目采用 MIT 许可证。详情请参阅 [LICENSE](LICENSE) 文件。