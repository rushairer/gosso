# ADR-002: Repository Scan Helper 模式

**Status**: Implemented

**Date**: 2026-06-10

## Context

gosso 的 Repository 层中，几乎每个读取数据库行的方法都在重复相同的 20-30 行 `Scan()` + `json.Unmarshal()` 代码块。例如：

- `AccountRepository.FindByID`、`FindByUsername`、`FindAll` — 三个方法中有几乎完全相同的 account 扫描代码
- `RoleRepository.FindByID`、`FindByName`、`FindAll`、`FindRolesByAccountID` — 四个方法中重复相同的 role 扫描代码（含 permissions JSON + metadata JSON 的反序列化）
- `CredentialRepository.FindByAccountAndType` 和 `FindByAccountAndTypeForUpdate` — 除了 `FOR UPDATE` 子句和 tx/db 选择外，代码逐字相同
- `FederatedIdentityRepository` — 同样模式

这种重复导致：
1. 修复一个 scan bug（如添加新列）需要修改所有查询方法 — 容易遗漏
2. Code review 中反复发现同一个 scan 模式的不同实例的问题
3. 新增查询方法时，开发者倾向于复制粘贴现有方法 — 重复代码持续增长

## Decision

为每个实体提取 **私有 scan helper 函数**：

```go
// internal/account/repository/account_repository_impl.go

// scanAccount scans a single Account from a row scanner.
// Used by FindByID, FindByUsername, and other single-row queries.
func scanAccount(scanner interface{ Scan(dest ...any) error }) (*domain.Account, error) {
    var account domain.Account
    var metadataJSON []byte
    err := scanner.Scan(
        &account.ID, &account.Username, &account.DisplayName,
        &account.Status, &account.CreatedAt, &account.UpdatedAt,
        &metadataJSON,
    )
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            return nil, ErrAccountNotFound
        }
        return nil, fmt.Errorf("scan account: %w", err)
    }
    if err := json.Unmarshal(metadataJSON, &account.Metadata); err != nil {
        return nil, fmt.Errorf("unmarshal account metadata: %w", err)
    }
    return &account, nil
}

// scanAccounts scans multiple Accounts from sql.Rows.
func scanAccounts(rows *sql.Rows) ([]*domain.Account, error) {
    defer rows.Close()
    var accounts []*domain.Account
    for rows.Next() {
        account, err := scanAccount(rows)
        if err != nil {
            return nil, err
        }
        accounts = append(accounts, account)
    }
    return accounts, rows.Err()
}
```

**规则**：
1. 每个可查询的实体必须有 `scanXxx` 和 `scanXxxs`（复数）helper
2. Helper 是包级私有函数（小写开头），不暴露到接口
3. `scanXxx` 使用 `interface{ Scan(dest ...any) error }` 参数，兼容 `*sql.Row` 和 `*sql.Rows`
4. 错误转换（如 `sql.ErrNoRows` → sentinel error）在 helper 内部完成
5. 新增查询方法**必须**调用 scan helper，禁止内联 scan 代码

## Consequences

**正面**：
- 修复 scan 逻辑（如添加新列）只需修改一处
- 新增查询方法只需 5-10 行（构造 SQL + 调用 helper）
- Code review 中不再需要逐行检查 scan 代码是否与其它方法一致
- CI 的 `dupl` linter 可以自动检测违规

**负面**：
- 需要一次性重构所有现有 repository 方法
- `CredentialRepository` 的 `FindByAccountAndType` 和 `FindByAccountAndTypeForUpdate` 共享同一个 scan helper，但它们的 `tx.QueryContext` vs `r.db.QueryContext` 调用点不同 — 需要提取 SQL 构造为独立函数

**中性**：
- scan helper 增加了一层间接调用，但对性能无实质影响（瓶颈在数据库 I/O）
- 需要确保 `*sql.Rows` 和 `*sql.Row` 的 `Scan` 方法签名一致（Go 标准库已保证）
