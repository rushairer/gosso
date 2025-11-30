# Metadata 字段类型选择决策

## 📋 问题背景

项目中多处使用 Metadata/Profile 等扩展字段存储 JSON 数据，需要决定使用何种 Go 类型：
- `map[string]interface{}` / `map[string]any`
- `json.RawMessage`
- `map[string]string`

## 🎯 最终决策

基于场景区分使用，**已采用以下方案**：

### 1. 业务实体的扩展字段 → `map[string]any`

**适用场景**：
- `Account.Metadata`
- `Credential.Metadata`
- `Role.Metadata`
- `Group.Metadata`
- `FederatedIdentity.Profile`

**选择理由**：
- 业务逻辑需要**频繁读写和修改**
- 代码可读性和可维护性更高
- 类型灵活，支持嵌套结构
- `any` 是 Go 1.18+ 推荐的 `interface{}` 别名

**使用示例**：
```go
// 创建账号时设置元数据
account := &domain.Account{
    Metadata: map[string]any{
        "department": "engineering",
        "level":      3,
        "tags":       []string{"senior", "backend"},
    },
}

// 业务逻辑中访问和修改
if dept, ok := account.Metadata["department"].(string); ok {
    fmt.Println("部门:", dept)
}

account.Metadata["last_login"] = time.Now().Unix()
```

### 2. 审计日志字段 → `json.RawMessage`

**适用场景**：
- `AuditRecord.Resource`
- `AuditRecord.Old/New/Meta`
- `AuditEntry.Payload`

**选择理由**：
- 审计日志是**只写不改**的（写入后不修改）
- 存储的是**快照数据**，需要保留原始 JSON 格式
- 高性能：延迟解析，仅在需要时才反序列化
- 符合审计日志的"不可变"原则

**使用示例**：
```go
// 写入审计日志
resourceData := map[string]any{
    "account_id": "123",
    "action":     "login",
}
resourceJSON, _ := json.Marshal(resourceData)

audit := &domain.AuditRecord{
    Resource: json.RawMessage(resourceJSON),
}

// 读取时才反序列化（如果需要）
var resource map[string]any
json.Unmarshal(audit.Resource, &resource)
```

### 3. 会话元数据 → `map[string]string`

**适用场景**：
- `Session.Metadata`

**选择理由**：
- 会话元数据通常是简单的键值对（如设备类型、浏览器版本）
- 不需要复杂的嵌套结构
- 性能最优，无需类型断言

**使用示例**：
```go
session := &domain.Session{
    Metadata: map[string]string{
        "device":  "desktop",
        "os":      "macOS",
        "browser": "Chrome",
    },
}
```

## 📊 三种方案详细对比

| 维度 | `map[string]any` | `json.RawMessage` | `map[string]string` |
|------|------------------|-------------------|---------------------|
| **类型安全** | ⚠️ 运行时类型断言 | ⚠️ 需要反序列化 | ✅ 编译时检查 |
| **易用性** | ✅ 直接操作 map | ❌ 需要序列化/反序列化 | ✅ 最简单 |
| **性能** | ⚠️ 中等（需序列化存储） | ✅ 高（延迟解析） | ✅ 最高 |
| **灵活性** | ✅ 支持任意类型 | ✅ 支持任意 JSON | ❌ 仅支持字符串 |
| **代码可读性** | ✅ 直观 | ⚠️ 冗长 | ✅ 清晰 |
| **数据库存储** | 需要 `json.Marshal` | 直接存储 | 直接存储（或序列化） |
| **适用场景** | 频繁读写的业务字段 | 只写不改的日志字段 | 简单键值对 |

## 🔧 数据库存储处理

### `map[string]any` 的序列化示例

```go
// 写入数据库（Repository 层）
func (r *accountRepositoryImpl) CreateAccount(ctx context.Context, tx *sql.Tx, account *domain.Account) error {
    // 序列化 Metadata
    metadataJSON, err := json.Marshal(account.Metadata)
    if err != nil {
        return fmt.Errorf("marshal metadata: %w", err)
    }
    
    _, err = tx.ExecContext(ctx, query,
        account.ID,
        // ... 其他字段
        metadataJSON, // 存储为 JSONB
    )
    return err
}

// 从数据库读取
func (r *accountRepositoryImpl) FindByID(ctx context.Context, accountID string) (*domain.Account, error) {
    account := &domain.Account{}
    var metadataJSON []byte
    
    err := r.db.QueryRowContext(ctx, query, accountID).Scan(
        &account.ID,
        // ... 其他字段
        &metadataJSON, // 读取 JSONB 数据
    )
    
    // 反序列化 Metadata
    if err := json.Unmarshal(metadataJSON, &account.Metadata); err != nil {
        return nil, fmt.Errorf("unmarshal metadata: %w", err)
    }
    
    return account, nil
}
```

### `json.RawMessage` 的存储示例

```go
// 写入数据库（无需序列化）
func (r *auditRepositoryImpl) CreateAuditRecord(ctx context.Context, record *domain.AuditRecord) error {
    _, err := r.db.ExecContext(ctx, query,
        record.ID,
        record.Resource, // 直接存储，已经是 []byte
    )
    return err
}

// 从数据库读取（无需反序列化）
func (r *auditRepositoryImpl) FindByID(ctx context.Context, id uuid.UUID) (*domain.AuditRecord, error) {
    record := &domain.AuditRecord{}
    
    err := r.db.QueryRowContext(ctx, query, id).Scan(
        &record.ID,
        &record.Resource, // 直接读取为 []byte
    )
    
    return record, err
}
```

## 🎓 类型断言最佳实践

使用 `map[string]any` 时的安全访问模式：

```go
// ✅ 推荐：使用类型断言 + ok 检查
if value, ok := metadata["key"].(string); ok {
    // 使用 value
}

// ✅ 推荐：使用辅助函数
func getStringValue(m map[string]any, key string, defaultValue string) string {
    if v, ok := m[key].(string); ok {
        return v
    }
    return defaultValue
}

func getIntValue(m map[string]any, key string, defaultValue int) int {
    switch v := m[key].(type) {
    case int:
        return v
    case float64:
        return int(v) // JSON 数字默认解析为 float64
    default:
        return defaultValue
    }
}

// ❌ 不推荐：直接断言（可能 panic）
value := metadata["key"].(string)
```

## 📝 迁移记录

### 已完成的修改

- ✅ `internal/account/domain/account.go` - `Metadata` 改为 `map[string]any`
- ✅ `internal/account/domain/credential.go` - `Metadata` 改为 `map[string]any`
- ✅ `internal/account/domain/role.go` - `Role.Metadata` 和 `Group.Metadata` 改为 `map[string]any`
- ✅ `internal/account/domain/federated_identity.go` - `Profile` 改为 `map[string]any`
- ✅ `internal/account/service/account_service.go` - `RegisterAccountRequest.Metadata` 改为 `map[string]any`

### 保持不变的字段

- ⏸️ `internal/audit/domain/audit.go` - 保持 `json.RawMessage`（审计日志）
- ⏸️ `internal/session/domain/session.go` - 保持 `map[string]string`（简单键值对）

## ✅ 验证结果

```bash
# 编译通过
go build -o bin/gosso ./cmd/main.go
# 输出: 成功，无错误
```

## 🚀 后续建议

1. **创建辅助函数包**：封装常用的 Metadata 访问模式
   ```go
   // internal/utility/metadata.go
   package utility
   
   func GetString(m map[string]any, key, defaultValue string) string { ... }
   func GetInt(m map[string]any, key string, defaultValue int) int { ... }
   func GetBool(m map[string]any, key string, defaultValue bool) bool { ... }
   ```

2. **单元测试**：测试 Metadata 的序列化/反序列化
3. **文档说明**：在 API 文档中说明 Metadata 的数据类型约定

## 📚 参考资料

- [Go 1.18 any 类型](https://go.dev/blog/go1.18)
- [encoding/json 文档](https://pkg.go.dev/encoding/json)
- [JSONB in PostgreSQL](https://www.postgresql.org/docs/current/datatype-json.html)
