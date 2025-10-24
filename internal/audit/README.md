# Audit 审计系统

本模块提供了完整的审计日志解决方案，支持同步和异步审计记录，确保系统操作的可追溯性和合规性。

## 📋 目录结构

```
internal/audit/
├── README.md              # 本文档
├── domain/
│   └── audit.go          # 审计领域模型（AuditEvent, AuditPending）
├── auditor/
│   ├── auditor.go        # 审计接口定义
│   └── gorm_auditor.go   # GORM 实现
└── middleware/
    └── audit_middleware.go # 智能审计中间件
```

## 🎯 核心概念

### 两阶段审计设计

本系统采用**两阶段审计**设计，在一致性、性能和可靠性之间取得最佳平衡：

1. **AuditPending** - 事务内轻量占位记录
   - 在业务事务内快速写入，保证审计标记与业务变更同生同退
   - 包含最小必要信息，避免阻塞主事务
   - 存储在 `audit_pending` 表

2. **AuditEvent** - 最终持久化审计记录
   - 结构化的完整审计信息，用于查询、合规和溯源
   - 由后台 worker 异步处理或同步写入
   - 存储在 `audit_event` 表

## 🚀 快速开始

### 1. 初始化审计器

```go
import (
    "gosso/internal/audit/auditor"
    "gosso/internal/audit/middleware"
)

// 创建 GORM 审计器
auditor := auditor.NewGormAuditor(db)

// 创建审计中间件
auditMiddleware := middleware.NewAuditMiddleware(db, auditor)
```

### 2. 在服务中使用

```go
type UserService struct {
    db    *gorm.DB
    audit *middleware.AuditMiddleware
}

func NewUserService(db *gorm.DB, auditor auditor.Auditor) *UserService {
    return &UserService{
        db:    db,
        audit: middleware.NewAuditMiddleware(db, auditor),
    }
}
```

## 📖 使用方式

### 方式一：智能审计中间件（推荐）

使用审计中间件可以大幅简化代码，自动处理审计逻辑：

```go
// 同步审计 - 关键操作
func (s *UserService) UpdateProfile(ctx context.Context, userID uuid.UUID, data ProfileData, actor string) error {
    return middleware.WithAudit[domain.Profile](ctx, s.audit, "profile.update", actor).
        WithMeta("method", "update").
        Do(func(tx *gorm.DB) (*domain.Profile, error) {
            // 纯净的业务逻辑
            var profile domain.Profile
            if err := tx.First(&profile, "user_id = ?", userID).Error; err != nil {
                return nil, err
            }
            
            profile.Name = data.Name
            profile.Email = data.Email
            
            return &profile, tx.Save(&profile).Error
        })
}

// 异步审计 - 高频操作
func (s *UserService) RecordLogin(ctx context.Context, userID uuid.UUID, success bool, ip string, actor string) error {
    return middleware.WithAudit[map[string]interface{}](ctx, s.audit, "user.login", actor).
        Async().                    // 异步处理，避免阻塞
        WithMeta("ip", ip).
        WithMeta("success", success).
        Do(func(tx *gorm.DB) (*map[string]interface{}, error) {
            // 登录相关业务逻辑
            result := map[string]interface{}{
                "user_id":   userID.String(),
                "success":   success,
                "timestamp": time.Now(),
            }
            return &result, nil
        })
}
```

### 方式二：直接使用审计器

对于需要精确控制的场景：

```go
// 同步审计
func (s *UserService) DeleteUser(ctx context.Context, userID uuid.UUID, actor string) error {
    return s.db.Transaction(func(tx *gorm.DB) error {
        // 执行业务逻辑
        var user domain.User
        if err := tx.First(&user, "id = ?", userID).Error; err != nil {
            return err
        }
        
        if err := tx.Delete(&user).Error; err != nil {
            return err
        }
        
        // 构造审计事件
        resourceJSON, _ := json.Marshal(map[string]interface{}{
            "type": "user",
            "id":   userID.String(),
        })
        
        event := &domain.AuditEvent{
            TxID:      uuid.New(),
            AccountID: &userID,
            Actor:     actor,
            Action:    "user.delete",
            Resource:  resourceJSON,
            Old:       nil, // 可以记录删除前的用户信息
            CreatedAt: time.Now(),
        }
        
        // 同步写入审计
        return s.auditor.LogTx(ctx, tx, event)
    })
}

// 异步审计
func (s *UserService) UpdateLastSeen(ctx context.Context, userID uuid.UUID, actor string) error {
    return s.db.Transaction(func(tx *gorm.DB) error {
        // 业务逻辑
        if err := tx.Model(&domain.User{}).Where("id = ?", userID).Update("last_seen_at", time.Now()).Error; err != nil {
            return err
        }
        
        // 构造待处理审计
        payloadJSON, _ := json.Marshal(map[string]interface{}{
            "user_id": userID.String(),
            "action":  "last_seen_update",
        })
        
        pending := &domain.AuditPending{
            ID:        uuid.New(),
            TxID:      uuid.New(),
            AccountID: &userID,
            Action:    "user.last_seen",
            Payload:   payloadJSON,
            Attempts:  0,
        }
        
        // 异步入队
        return s.auditor.EnqueuePending(ctx, tx, pending)
    })
}
```

## 🎛️ 配置选项

### 审计中间件选项

```go
// 链式配置
middleware.WithAudit[T](ctx, auditMiddleware, action, actor).
    Async().                           // 异步处理
    WithMeta("key", "value").         // 添加元数据
    WithMeta("sensitive", true).      // 标记敏感操作
    Do(businessFunc)
```

### 智能特性

审计中间件提供以下智能特性：

1. **自动资源提取**：从返回对象自动提取 ID、AccountID、资源类型
2. **敏感字段过滤**：自动跳过 Password、Secret、Token 等敏感字段
3. **类型安全**：通过泛型确保编译时类型检查
4. **错误处理**：自动处理序列化错误和事务回滚

## 📊 数据模型

### AuditEvent（最终审计记录）

```go
type AuditEvent struct {
    ID        int64           `json:"id" gorm:"primaryKey;autoIncrement"`
    TxID      uuid.UUID       `json:"tx_id" gorm:"type:uuid;index:idx_audit_txid"`
    AccountID *uuid.UUID      `json:"account_id,omitempty" gorm:"type:uuid;index:idx_audit_account"`
    Actor     string          `json:"actor" gorm:"type:text"`
    Action    string          `json:"action" gorm:"type:varchar(128);index:idx_audit_action"`
    Resource  json.RawMessage `json:"resource" gorm:"type:jsonb"`
    Old       json.RawMessage `json:"old,omitempty" gorm:"type:jsonb"`
    New       json.RawMessage `json:"new,omitempty" gorm:"type:jsonb"`
    Meta      json.RawMessage `json:"meta,omitempty" gorm:"type:jsonb"`
    CreatedAt time.Time       `json:"created_at" gorm:"autoCreateTime"`
}
```

### AuditPending（待处理记录）

```go
type AuditPending struct {
    ID        uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey"`
    TxID      uuid.UUID       `json:"tx_id" gorm:"type:uuid;index;not null"`
    AccountID *uuid.UUID      `json:"account_id,omitempty" gorm:"type:uuid;index"`
    Action    string          `json:"action" gorm:"type:varchar(128);not null;index"`
    Payload   json.RawMessage `json:"payload" gorm:"type:jsonb"`
    Attempts  int             `json:"attempts" gorm:"default:0"`
    LastError *string         `json:"last_error,omitempty" gorm:"type:text"`
    CreatedAt time.Time       `json:"created_at" gorm:"autoCreateTime"`
    UpdatedAt time.Time       `json:"updated_at" gorm:"autoUpdateTime"`
}
```

## 🔄 异步处理

### Worker 实现示例

```go
// 后台 Worker 处理 pending 审计
func ProcessPendingAudits(db *gorm.DB, auditor auditor.Auditor) {
    for {
        var pendings []domain.AuditPending
        
        // 查询待处理记录（使用 FOR UPDATE SKIP LOCKED 避免竞争）
        err := db.Raw(`
            SELECT * FROM audit_pending 
            WHERE attempts < 3 
            ORDER BY created_at 
            LIMIT 100 
            FOR UPDATE SKIP LOCKED
        `).Scan(&pendings).Error
        
        if err != nil || len(pendings) == 0 {
            time.Sleep(5 * time.Second)
            continue
        }
        
        for _, pending := range pendings {
            if err := processPending(db, auditor, &pending); err != nil {
                // 更新重试次数和错误信息
                updatePendingError(db, &pending, err)
            } else {
                // 删除已处理的记录
                db.Delete(&pending)
            }
        }
    }
}

func processPending(db *gorm.DB, auditor auditor.Auditor, pending *domain.AuditPending) error {
    // 将 pending 转换为 AuditEvent
    var event domain.AuditEvent
    if err := json.Unmarshal(pending.Payload, &event); err != nil {
        return err
    }
    
    // 写入最终审计表
    return auditor.Log(context.Background(), &event)
}
```

## 📋 最佳实践

### 1. 选择审计方式

| 场景 | 推荐方式 | 原因 |
|------|----------|------|
| 关键业务操作 | 同步审计 | 立即可查，强一致性 |
| 高频操作 | 异步审计 | 避免性能影响 |
| 敏感操作 | 同步审计 | 合规要求 |
| 日志记录 | 异步审计 | 性能优先 |

### 2. 审计动作命名

```go
// 推荐的命名规范
"user.create"           // 用户创建
"user.update"           // 用户更新  
"user.delete"           // 用户删除
"credential.bind"       // 凭证绑定
"credential.verify"     // 凭证验证
"session.login"         // 登录
"session.logout"        // 登出
"permission.grant"      // 权限授予
"permission.revoke"     // 权限撤销
```

### 3. 元数据使用

```go
// 有用的元数据字段
WithMeta("ip", clientIP).                    // 客户端IP
WithMeta("user_agent", userAgent).          // 用户代理
WithMeta("method", "api").                  // 操作方式
WithMeta("sensitive", true).                // 敏感操作标记
WithMeta("compliance", "gdpr").             // 合规标记
WithMeta("batch_id", batchID).              // 批量操作ID
```

### 4. 错误处理

```go
// 审计失败不应影响业务逻辑
func (s *Service) UpdateUser(ctx context.Context, userID uuid.UUID, data UserData, actor string) error {
    err := middleware.WithAudit[domain.User](ctx, s.audit, "user.update", actor).
        Do(func(tx *gorm.DB) (*domain.User, error) {
            // 业务逻辑
            return updateUserInDB(tx, userID, data)
        })
    
    if err != nil {
        // 记录审计失败，但不阻塞业务
        log.Errorf("audit failed for user.update: %v", err)
        
        // 可以考虑降级处理，如写入本地日志
        fallbackAudit(userID, "user.update", actor, data)
    }
    
    return nil // 业务成功
}
```

## 🔍 查询和分析

### 常用查询示例

```sql
-- 查询用户的所有操作记录
SELECT * FROM audit_event 
WHERE account_id = $1 
ORDER BY created_at DESC;

-- 查询特定时间段的敏感操作
SELECT * FROM audit_event 
WHERE action IN ('user.delete', 'permission.grant') 
  AND created_at BETWEEN $1 AND $2;

-- 查询失败的异步审计
SELECT * FROM audit_pending 
WHERE attempts >= 3 
  AND last_error IS NOT NULL;

-- 统计各类操作的频率
SELECT action, COUNT(*) as count 
FROM audit_event 
WHERE created_at >= NOW() - INTERVAL '24 hours'
GROUP BY action 
ORDER BY count DESC;
```

## ⚠️ 注意事项

### 1. 性能考虑

- **Payload 大小**：AuditPending.Payload 建议限制在 64KB 以内
- **批量操作**：大批量操作考虑使用批量审计或采样审计
- **索引优化**：根据查询模式优化数据库索引
- **分区策略**：大表考虑按时间分区

### 2. 安全和隐私

- **敏感数据**：Old/New 字段可能包含敏感信息，需要访问控制
- **数据脱敏**：生产环境考虑对敏感字段进行脱敏
- **保留策略**：制定审计数据的保留和归档策略
- **加密存储**：敏感审计数据考虑加密存储

### 3. 监控和告警

- **队列积压**：监控 audit_pending 表的记录数量
- **处理延迟**：监控异步处理的延迟时间
- **失败率**：监控审计失败的比例和原因
- **存储增长**：监控审计表的存储增长趋势

## 🔧 故障排查

### 常见问题

1. **审计记录丢失**
   - 检查事务是否正确提交
   - 确认 EnqueuePending 在事务内调用
   - 检查 Worker 是否正常运行

2. **性能问题**
   - 检查 Payload 大小是否过大
   - 优化数据库索引
   - 考虑使用异步审计

3. **Worker 处理缓慢**
   - 检查数据库连接池配置
   - 优化批量处理逻辑
   - 增加 Worker 实例数量

## 📚 相关文档

- [数据库迁移文档](../../db/migrations/README.md)
- [认证服务集成示例](../authn/service/)
- [API 设计规范](../../doc/)

---

**版本**: v1.0.0  
**更新时间**: 2025-10-24  
**维护者**: 开发团队