# Mock 测试错误修复总结

## 问题描述

在运行 `TestRegisterAccount_DuplicateEmail` 测试时遇到错误：

```
all expectations were already fulfilled, call to database transaction Begin was not expected
```

**错误信息分析**：测试期望在检测到重复邮箱后直接返回错误，不应该执行 `BeginTx`，但实际上却执行了事务开始。

## 根本原因

### 问题 1：Mock 返回的列数不匹配

**错误的 Mock 设置**（只返回 4 列）：
```go
rows := sqlmock.NewRows([]string{"id", "account_id", "credential_type", "identifier"}).
    AddRow("existing-id", "existing-account-id", domain.CredentialTypeEmail, "test@example.com")
```

**实际查询需要 12 列**（`FindByTypeAndIdentifier` 的 Scan）：
```go
err := r.db.QueryRowContext(ctx, query, credType, identifier).Scan(
    &cred.ID,              // 1
    &cred.AccountID,       // 2
    &cred.Type,            // 3
    &cred.Identifier,      // 4
    &cred.Value,           // 5 ❌ Mock 缺少
    &cred.Verified,        // 6 ❌ Mock 缺少
    &cred.PrimaryCredential, // 7 ❌ Mock 缺少
    &metadataJSON,         // 8 ❌ Mock 缺少
    &cred.CreatedAt,       // 9 ❌ Mock 缺少
    &cred.VerifiedAt,      // 10 ❌ Mock 缺少
    &cred.LastUsedAt,      // 11 ❌ Mock 缺少
    &cred.DeletedAt,       // 12 ❌ Mock 缺少
)
```

**后果**：
- `Scan` 失败，返回错误（如 `sql: expected 12 destination arguments, got 4`）
- `checkCredentialExists` 的逻辑：`if err == nil && cred != nil` → 因为 `err != nil`，返回 `nil`
- `RegisterAccount` 认为邮箱不存在，继续执行 `BeginTx`
- Mock 没有设置 `ExpectBegin`，导致错误

### 问题 2：SQL 执行顺序理解错误

**正确的执行顺序**：
1. `checkCredentialExists` → 查询邮箱（**在事务外**）
2. `BeginTx` → 开始事务
3. `CreateAccount` → 插入账号
4. `CreateCredentials` → 插入凭证
5. `Commit` → 提交事务

**之前错误的 Mock 顺序**：
```go
mock.ExpectBegin()                     // ❌ 先开始事务
mock.ExpectQuery("SELECT (.+)")...     // ❌ 再查询
```

**正确的 Mock 顺序**：
```go
mock.ExpectQuery("SELECT (.+)")...     // ✅ 先查询（事务外）
mock.ExpectBegin()                     // ✅ 再开始事务
```

## 修复方案

### 1. 完整的 Mock 数据

```go
// 设置 mock：邮箱已存在（在事务外查询）
// 注意：需要返回所有列，与 FindByTypeAndIdentifier 的 Scan 匹配
rows := sqlmock.NewRows([]string{
    "id", "account_id", "credential_type", "identifier", 
    "credential_value", "verified", "primary_credential", "metadata",
    "created_at", "verified_at", "last_used_at", "deleted_at",
}).AddRow(
    "existing-id", "existing-account-id", domain.CredentialTypeEmail, "test@example.com",
    "", true, true, []byte("{}"),
    time.Now(), nil, nil, nil,
)

mock.ExpectQuery("SELECT (.+) FROM account_credentials").
    WithArgs(domain.CredentialTypeEmail, "test@example.com").
    WillReturnRows(rows)
```

### 2. 正确的 Mock 顺序（成功注册）

```go
// 1. 期望查询邮箱是否已存在（在事务外执行）
mock.ExpectQuery("SELECT (.+) FROM account_credentials").
    WithArgs(domain.CredentialTypeEmail, "test@example.com").
    WillReturnError(sql.ErrNoRows)

// 2. 开始事务
mock.ExpectBegin()

// 3. 期望插入账号
mock.ExpectExec("INSERT INTO accounts").
    WillReturnResult(sqlmock.NewResult(1, 1))

// 4. 期望批量插入凭证
mock.ExpectExec("INSERT INTO account_credentials").
    WillReturnResult(sqlmock.NewResult(1, 1))

mock.ExpectExec("INSERT INTO account_credentials").
    WillReturnResult(sqlmock.NewResult(1, 1))

// 5. 提交事务
mock.ExpectCommit()
```

### 3. 重复邮箱测试（不需要 ExpectBegin）

```go
// 检测到重复邮箱后，不会开始事务，所以不需要 ExpectBegin
rows := sqlmock.NewRows([]string{
    "id", "account_id", "credential_type", "identifier", 
    "credential_value", "verified", "primary_credential", "metadata",
    "created_at", "verified_at", "last_used_at", "deleted_at",
}).AddRow(
    "existing-id", "existing-account-id", domain.CredentialTypeEmail, "test@example.com",
    "", true, true, []byte("{}"),
    time.Now(), nil, nil, nil,
)

mock.ExpectQuery("SELECT (.+) FROM account_credentials").
    WithArgs(domain.CredentialTypeEmail, "test@example.com").
    WillReturnRows(rows)

// ❌ 不需要 mock.ExpectBegin()
```

## 测试结果

所有测试通过：

```bash
=== RUN   TestRegisterAccount
--- PASS: TestRegisterAccount (0.05s)
=== RUN   TestRegisterAccount_DuplicateEmail
--- PASS: TestRegisterAccount_DuplicateEmail (0.00s)
=== RUN   TestChangePassword
--- PASS: TestChangePassword (0.00s)
=== RUN   TestSoftDeleteAccount
--- PASS: TestSoftDeleteAccount (0.00s)
PASS
```

## 经验教训

### 1. Mock 数据必须完整

**原则**：Mock 返回的列数和类型**必须与** `Scan` 的参数完全匹配。

**建议**：
- 查看 Repository 的 `Scan` 代码，确定需要哪些列
- 使用 `sqlmock.NewRows(columns).AddRow(values...)` 时，确保列数匹配
- 对于可为空的字段（如 `*time.Time`），使用 `nil`

### 2. 理解 SQL 执行顺序

**原则**：Mock 期望的顺序**必须与**实际 SQL 执行顺序一致。

**调试技巧**：
- 在 Repository 层添加日志，打印 SQL 执行时机
- 使用 `sqlmock` 的错误信息（会显示期望的 SQL 和实际执行的 SQL）
- 画出 Service 层的调用流程图

### 3. 事务边界要清晰

**原则**：明确哪些操作在事务内，哪些在事务外。

**最佳实践**：
- 验证逻辑（如检查重复）在**事务外**执行（避免长时间持有锁）
- 数据修改在**事务内**执行（保证原子性）
- 在测试注释中标注事务边界

### 4. 指针类型的断言

**问题**：
```go
assert.Equal(t, "testuser", account.Username)  // ❌ 类型不匹配
```

**原因**：`account.Username` 是 `*string` 类型。

**修复**：
```go
assert.NotNil(t, account.Username)            // ✅ 先检查非空
assert.Equal(t, "testuser", *account.Username) // ✅ 解引用后比较
```

## 相关文件

- 测试文件：`internal/account/service/account_service_test.go`
- Service 实现：`internal/account/service/account_service.go`
- Repository 实现：`internal/account/repository/credential_repository.go`

## 总结

这次 bug 修复展示了单元测试中 **Mock 数据的重要性**：

1. **完整性**：Mock 数据必须与实际查询返回的列匹配
2. **顺序性**：Mock 期望的顺序必须与代码执行顺序一致
3. **准确性**：类型、空值、事务边界都要准确模拟

通过这次修复，所有 `account_service` 的测试都能正常运行，为后续开发打下了良好的基础。
