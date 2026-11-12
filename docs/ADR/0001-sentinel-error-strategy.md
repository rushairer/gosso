# ADR-001: Sentinel Error 统一来源策略

**Status**: Implemented

**Date**: 2026-06-10

## Context

gosso 项目经历了 30+ 轮代码审查，发现 sentinel errors 在多个包中重复定义。具体问题：

1. **`ErrAccountNotActive`** 同时定义在 `internal/account/service/errors.go` 和 `internal/auth/service/errors.go`，两者是不同的 `error` 值，`errors.Is()` 无法跨包匹配。
2. **`ErrAccountNotFound`** 同时定义在 `internal/account/repository/account_repository.go` 和 `internal/auth/service/errors.go`。
3. **`ErrRoleNotFound`** 同时定义在 `internal/account/repository/role_repository.go` 和 `internal/account/service/errors.go`。
4. **`ErrCredentialNotFound`** 同时定义在 `internal/auth/service/errors.go` 和 `internal/account/repository/credential_repository.go`。

这导致：
- OIDC controller 使用 `authService.ErrAccountNotActive`，admin controller 使用 `accountService.ErrAccountNotActive` — 同一概念的错误在不同模块的处理方式不一致
- `authService.ErrAccountNotFound` 用 `fmt.Errorf("%w", ErrAccountNotFound)` 包装后，上游的 `errors.Is(err, repo.ErrAccountNotFound)` 仍然能匹配，但这依赖于巧合而非设计
- 新增功能时，开发者不确定该引用哪个包的 sentinel，倾向于再定义一份新的 — 恶性循环

## Decision

采用 **"概念所有权"** 策略确定 sentinel error 的唯一定义位置：

| 概念 | 规则 | 示例 |
|------|------|------|
| 实体不存在 | Repository 层定义 | `ErrAccountNotFound` → `account/repository` |
| 业务规则违反 | Service 层定义 | `ErrAccountNotActive` → `account/service` |
| 跨模块共享概念 | 最内层拥有者定义 | `ErrCredentialNotFound` → `account/repository`（凭证归 account 模块所有） |

具体规则：
1. 每个 sentinel error 只能在**一个**包中用 `errors.New()` 定义
2. 其他包通过 `import` 引用，或用 `%w` 包装后传递
3. 禁止在不同包中用相同的错误消息字符串创建新的 sentinel
4. CI 通过 `script/check-architecture.sh` 的 E1 检查自动检测违规

### 当前需要统一的 errors

| Error | 当前定义位置 | 统一后位置 |
|-------|-------------|-----------|
| `ErrAccountNotActive` | account/service + auth/service | `account/service/errors.go` |
| `ErrAccountNotFound` | account/repository + auth/service | `account/repository/account_repository.go` |
| `ErrRoleNotFound` | account/repository + account/service | `account/repository/role_repository.go` |
| `ErrCredentialNotFound` | auth/service + account/repository | `account/repository/credential_repository.go` |

## Consequences

**正面**：
- `errors.Is()` 跨包匹配变得可靠
- 新开发者不需要猜测该引用哪个 sentinel
- CI 自动检测重复定义，防止回归

**负面**：
- 需要一次性重构现有代码中的引用关系
- Service 层引用 Repository 的 sentinel error 会增加一层 import 依赖（但这是合理的 — service 依赖 repo 已经是既有事实）

**中性**：
- `internal/service/errors.go` 中的重复 sentinel 需要删除，相关代码改为 import 正确的包
