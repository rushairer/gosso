# gosso

[![Development Status](https://img.shields.io/badge/status-in%20development-yellow.svg)](https://github.com/rushairer/gosso)
[![Tests](https://github.com/rushairer/gosso/workflows/Tests/badge.svg)](https://github.com/rushairer/gosso/actions/workflows/test.yml)
[![Code Quality](https://github.com/rushairer/gosso/workflows/Code%20Quality/badge.svg)](https://github.com/rushairer/gosso/actions/workflows/quality.yml)
[![Go Version](https://img.shields.io/badge/go-1.23.3+-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![codecov](https://codecov.io/gh/rushairer/gosso/branch/main/graph/badge.svg)](https://codecov.io/gh/rushairer/gosso)
[![Go Report Card](https://goreportcard.com/badge/github.com/rushairer/gosso)](https://goreportcard.com/report/github.com/rushairer/gosso)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/rushairer/gosso/pulls)
[![Contributors Welcome](https://img.shields.io/badge/contributors-welcome-orange.svg)](https://github.com/rushairer/gosso/issues)

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

### 🐳 Docker 部署

#### 使用 Docker Compose (推荐)

```bash
# 启动所有服务 (包括数据库)
docker-compose up -d

# 仅启动应用和必要服务
docker-compose up -d gosso mysql redis

# 查看日志
docker-compose logs -f gosso

# 停止服务
docker-compose down
```

#### 使用 Docker

```bash
# 构建镜像
docker build -t gosso:latest .

# 运行容器
docker run -d \
  --name gosso \
  -p 8080:8080 \
  -v $(pwd)/config:/app/config:ro \
  gosso:latest
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

### 本地测试

```bash
# 运行所有测试
go test ./...

# 运行特定模块测试
go test ./internal/service/account -v

# 运行数据库工厂测试 (需要编译标签)
go test ./internal/database/factory -v -tags mysql

# 运行测试并生成覆盖率报告
go test -v -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

### CI/CD 自动化测试

项目使用 GitHub Actions 进行自动化测试：

- **🔄 持续集成**: 每次 push 和 PR 都会触发测试
- **🗄️ 多数据库测试**: 自动测试 MySQL、PostgreSQL、SQLite
- **🔧 多版本测试**: 测试 Go 1.21.x、1.22.x、1.23.x
- **📊 代码覆盖率**: 自动上传到 Codecov
- **🔍 代码质量**: golangci-lint 静态分析
- **🛡️ 安全扫描**: gosec 安全检查

查看测试状态：[GitHub Actions](https://github.com/rushairer/gosso/actions)

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

> 🚀 **项目正在积极开发中，欢迎更多开发者参与！**

我们欢迎各种形式的贡献，无论你是：
- 🐛 **发现 Bug** - 提交 Issue 帮助我们改进
- 💡 **提出想法** - 分享你的功能建议和改进意见  
- 📝 **完善文档** - 帮助改进文档和示例
- 🔧 **贡献代码** - 实现新功能或修复问题
- 🧪 **编写测试** - 提高代码质量和覆盖率

### 参与方式

1. **Fork 本仓库** 到你的 GitHub 账户
2. **创建特性分支** (`git checkout -b feature/AmazingFeature`)
3. **提交你的更改** (`git commit -m 'Add some AmazingFeature'`)
4. **推送到分支** (`git push origin feature/AmazingFeature`)
5. **提交 Pull Request** 并描述你的改动

### 开发指南

- 📖 查看 [文档维护指南](doc/README_GUIDE.md) 了解项目规范
- 📝 查看 [Git 提交规范](doc/GIT_COMMIT_GUIDE.md) 了解提交信息格式
- 🧪 运行 `go test ./...` 确保测试通过
- 📝 为新功能添加相应的测试和文档
- 🎯 遵循项目的代码风格和架构设计

#### Git 提交规范

本项目采用 [Conventional Commits](https://www.conventionalcommits.org/) 规范：

```bash
# 新功能
git commit -m "feat(auth): 添加 JWT 认证功能"

# Bug 修复
git commit -m "fix(user): 修复用户密码加密问题"

# 文档更新
git commit -m "docs(api): 更新接口文档"

# 代码重构
git commit -m "refactor(database): 重构数据库连接逻辑"
```

**使用 commitizen 工具**：
```bash
# 安装工具
npm install

# 交互式提交
npm run commit
```

### 需要帮助的领域

- [ ] **认证授权模块** - JWT、OAuth2 等认证方式
- [ ] **缓存机制** - Redis 集成和缓存策略
- [ ] **API 文档** - Swagger/OpenAPI 文档生成
- [ ] **性能优化** - 数据库查询和接口性能优化
- [ ] **部署工具** - Docker、K8s 部署配置
- [ ] **监控日志** - 日志收集和监控告警

有问题？欢迎在 [Issues](https://github.com/rushairer/gosso/issues) 中讨论！

## 📄 许可证

本项目采用 MIT 许可证。详情请参阅 [LICENSE](LICENSE) 文件。

### 开源协议说明

MIT 许可证是一个宽松的开源许可证，允许：
- ✅ **商业使用** - 可以在商业项目中使用
- ✅ **修改** - 可以修改源代码
- ✅ **分发** - 可以分发原始或修改后的代码
- ✅ **私人使用** - 可以私人使用
- ✅ **专利使用** - 提供明确的专利授权

**唯一要求**：在所有副本中包含原始许可证和版权声明。

### 行为准则

我们致力于为每个人提供友好、安全和欢迎的环境。请阅读我们的 [行为准则](CODE_OF_CONDUCT.md) 了解社区参与的期望。

## 🙏 致谢

感谢所有为 gosso 项目做出贡献的开发者！

- 基于 [gouno](https://github.com/rushairer/gouno) 项目生成
- 使用了优秀的开源库和工具
- 受到 Go 社区最佳实践的启发

**特别感谢**：
- 所有提交 Issue 和 PR 的贡献者
- 提供建议和反馈的社区成员
- Go 语言和相关开源项目的维护者