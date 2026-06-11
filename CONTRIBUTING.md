# Contributing to gosso

Thank you for your interest in contributing to gosso. This guide will help you get started.

## Prerequisites

- **Go 1.26.0+**
- **PostgreSQL 15+**
- **Redis 7+**
- **Docker & Docker Compose** (optional, for containerized development)

## Getting Started

1. Fork and clone the repository:

   ```bash
   git clone https://github.com/<your-username>/gosso.git
   cd gosso
   ```

2. Copy environment configuration:

   ```bash
   cp .env.development.example .env
   ```

3. Edit `.env` with your local database and Redis credentials.

4. Start dependencies with Docker (recommended):

   ```bash
   make docker-dev-up
   ```

   Or bring your own PostgreSQL and Redis instances.

5. Build and run:

   ```bash
   make build
   make run
   ```

## Development Workflow

### Branching

Create a feature branch from `main`:

```bash
git checkout -b feature/my-feature
```

### Hot Reload

For development with automatic reloading:

```bash
make dev
```

This requires [air](https://github.com/air-verse/air); the Makefile will install it automatically if missing.

### Running Tests

Unit tests:

```bash
make test
```

Integration tests (requires Docker services from `make docker-test-up`):

```bash
make docker-test-up
make test-integration
make docker-test-down
```

### Linting

```bash
make lint
```

To auto-fix fixable issues:

```bash
make lint-fix
```

The project uses [golangci-lint v2](https://golangci-lint.run/) with these linters enabled: `errcheck`, `govet`, `ineffassign`, `staticcheck`, `unused`, `gocritic`, `misspell`, `unconvert`, `bodyclose`, `nilerr`, `wrapcheck`, `errorlint`, `dupl`, `exhaustive`. Formatters include `gofmt` and `goimports` (with `github.com/rushairer/gosso` as the local prefix).

### Full Checklist Before Submitting

1. `go mod tidy` — no stray dependencies
2. `make lint` — all lint checks pass
3. `make test` — all unit tests pass
4. `make build` — binary builds successfully
5. Review your changes against the [Architecture Invariants](doc/ARCHITECTURE_INVARIANTS.md)

## Code Style

### Go Conventions

- `gofmt` + `goimports` formatting (enforced by linter)
- Short, lowercase package names
- Error strings: lowercase, no trailing punctuation
- Wrap errors with `%w` using `fmt.Errorf` to preserve error chains; use `errors.Is`/`errors.As` for checking
- Pass `context.Context` as the first parameter
- Avoid `panic` and global mutable state
- Public APIs have Go doc comments
- Use `defer` for cleanup; prevent goroutine leaks

### Test Conventions

- Table-driven tests are preferred for new tests
- Do not refactor existing non-table-driven tests without a clear reason
- Use `testify/assert` for assertions (already in use throughout the project)
- Use `go-sqlmock` for database tests and `miniredis` for Redis tests (existing patterns)
- Test files live alongside the code they test (e.g., `service/foo_service_test.go`)

### Architecture

- The project follows a 3-layer architecture: **domain -> repository -> service**
- Each internal module (account, admin, audit, auth, cache, db, notification, oauth2, oidc, session, token, utility) owns its layers
- The project is built on the [gouno](https://github.com/rushairer/gouno) scaffold -- `cmd/` entry point, `GoUnoConfig` structure, and `gouno` dependency are architectural foundations
- **Must read**: [Architecture Invariants](doc/ARCHITECTURE_INVARIANTS.md) — non-negotiable rules for error handling, repository patterns, controller conventions, and more
- Design decisions are documented as [Architecture Decision Records](doc/ADR/)

## CI Pipeline

All pull requests run through GitHub Actions (`.github/workflows/ci.yml`):

1. **Lint** -- `golangci-lint` v2.12.2
2. **Architecture Invariants** -- automated checks from [doc/ARCHITECTURE_INVARIANTS.md](doc/ARCHITECTURE_INVARIANTS.md)
3. **Unit Tests** -- `go test -race -coverprofile=coverage.out ./...` with a **50% coverage threshold** and per-module coverage report
4. **Vulnerability Check** -- `govulncheck ./...`
5. **Integration Tests** -- run against PostgreSQL 15 and Redis 7 service containers
6. **Build** -- binary compilation with stripped symbols
7. **Docker** -- image build on pushes to `main`/`develop`

## Security

gosso is an identity provider -- security-sensitive changes require extra care.

### Reporting Vulnerabilities

If you discover a security vulnerability, please **do not** open a public issue. Instead, email the maintainers or use GitHub's private vulnerability reporting feature. We will respond within 7 days.

### Security Guidelines for Contributors

- Never commit secrets, tokens, passwords, or private keys
- Example credentials in code or docs must be clearly marked as fake
- Cookie defaults: `HttpOnly`, `Secure`, `SameSite`
- Validate `redirect_uri` with exact string matching against a known allow-list
- Validate `state` and `nonce` parameters in OAuth2/OIDC flows
- JWT verification must check signature, `iss`, `aud`, `exp`, and `alg` (reject `none`)
- Use `bcrypt` or `argon2id` for password hashing -- never plain text or SHA
- Do not log sensitive data (tokens, session IDs, passwords)

## Submitting a Pull Request

1. Ensure all checks from the checklist above pass
2. Write a clear PR description explaining what changed and why
3. Reference any related issues
4. Keep PRs focused -- one logical change per PR
5. Be responsive to review feedback

## License

By contributing to gosso, you agree that your contributions will be licensed under the [MIT License](LICENSE).

---

# 贡献指南

感谢你对 gosso 项目的关注。以下指南将帮助你快速上手开发。

## 环境要求

- **Go 1.26.0+**
- **PostgreSQL 15+**
- **Redis 7+**
- **Docker & Docker Compose**（可选，用于容器化开发）

## 快速开始

1. Fork 并克隆仓库：

   ```bash
   git clone https://github.com/<your-username>/gosso.git
   cd gosso
   ```

2. 复制环境配置：

   ```bash
   cp .env.development.example .env
   ```

3. 编辑 `.env`，填写本地数据库和 Redis 连接信息。

4. 使用 Docker 启动依赖服务（推荐）：

   ```bash
   make docker-dev-up
   ```

5. 构建并运行：

   ```bash
   make build
   make run
   ```

## 开发流程

### 分支管理

从 `main` 创建功能分支：

```bash
git checkout -b feature/my-feature
```

### 热重载开发

```bash
make dev
```

需要 [air](https://github.com/air-verse/air)，Makefile 会自动安装。

### 运行测试

单元测试：

```bash
make test
```

集成测试（需要 `make docker-test-up` 启动的服务）：

```bash
make docker-test-up
make test-integration
make docker-test-down
```

### 代码检查

```bash
make lint       # 运行 lint 检查
make lint-fix   # 自动修复可修复的问题
```

### 提交前检查清单

1. `go mod tidy` -- 无多余依赖
2. `make lint` -- 全部 lint 检查通过
3. `make test` -- 全部单元测试通过
4. `make build` -- 二进制文件构建成功
5. 对照[架构不变量](doc/ARCHITECTURE_INVARIANTS.md)审查变更

## 代码规范

- 使用 `gofmt` + `goimports` 格式化代码
- 错误字符串小写、无尾部标点
- 用 `%w` 包装错误以保留错误链
- 公共 API 需要 Go doc 注释
- 新测试优先使用表驱动测试
- 测试断言使用 `testify/assert`
- **必读**：[架构不变量](doc/ARCHITECTURE_INVARIANTS.md) — 错误处理、Repository 模式、Controller 规范等不可违反的规则
- 设计决策记录在 [ADR 目录](doc/ADR/) 中

## CI 流水线

所有 PR 将运行 GitHub Actions 流水线：

1. **Lint** -- `golangci-lint` v2.12.2
2. **架构不变量检查** -- 自动化检查 [doc/ARCHITECTURE_INVARIANTS.md](doc/ARCHITECTURE_INVARIANTS.md) 中的规则
3. **单元测试** -- 50% 覆盖率阈值 + 模块级覆盖率报告
4. **漏洞扫描** -- `govulncheck`
5. **集成测试** -- PostgreSQL 15 + Redis 7
6. **构建** -- 二进制编译
7. **Docker** -- 推送到 `main`/`develop` 时构建镜像

## 安全

gosso 是身份认证服务，安全相关改动需格外谨慎。

### 漏洞报告

如发现安全漏洞，请**不要**公开提交 issue。请通过邮件联系维护者或使用 GitHub 私密漏洞报告功能，我们会在 7 天内响应。

### 安全指南

- 不要提交密钥、令牌、密码等敏感信息
- 示例凭据必须标注为 fake
- `redirect_uri` 必须精确匹配
- JWT 验证必须检查签名、`iss`、`aud`、`exp`、`alg`
- 不要记录敏感数据

## 提交 Pull Request

1. 确保上述检查清单全部通过
2. PR 描述中说明改了什么、为什么改
3. 引用相关 issue
4. 每个 PR 只做一件事

## 许可证

贡献即表示你同意你的贡献将在 [MIT 许可证](LICENSE) 下发布。
