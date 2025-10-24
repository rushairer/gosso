package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// audit 模块域模型说明：
// - AuditPending: 事务内写入的轻量"待处理"审计占位，保证审计 marker 与业务变更同生/同退，
//   由后台 worker 异步消费并转为 AuditEvent 或上报到外部系统。
// - AuditEvent: 最终的持久化审计记录，结构化存储用于合规与溯源。
// 注意：AuditEvent 的 old/new/resource/meta 可能包含敏感数据，访问需严格授权与审计。

// AuditEvent 表示一条最终持久化的审计记录，存储在 audit_event 表中。
// 目的：保证关键操作的可追溯性（谁、何时、为什么对哪个资源做了什么）。
// 实现说明：
//   - 为了与 AuditPending 保持一致性，事件体字段使用 json.RawMessage（jsonb 存储），
//     在业务/查询层按需反序列化为结构体或 map。
//   - 若你偏好把主键改为 uuid，请同时修改迁移 SQL。
type AuditEvent struct {
	ID        int64           `json:"id" gorm:"primaryKey;autoIncrement"`                            // 自增主键
	TxID      uuid.UUID       `json:"tx_id" gorm:"type:uuid;index:idx_audit_txid"`                   // 关联的事务或请求 id，由上层生成并传入（可选）
	AccountID *uuid.UUID      `json:"account_id,omitempty" gorm:"type:uuid;index:idx_audit_account"` // 受影响的账号 id（若有）
	Actor     string          `json:"actor" gorm:"type:text"`                                        // 发起者标识（如 user:123 / system / client:abc）
	Action    string          `json:"action" gorm:"type:varchar(128);index:idx_audit_action"`        // 动作标识（例如 credential.bind）
	Resource  json.RawMessage `json:"resource" gorm:"type:jsonb"`                                    // 受影响资源的摘要（json，例 {"type":"credential","id":"..."}）
	Old       json.RawMessage `json:"old,omitempty" gorm:"type:jsonb"`                               // 变更前的简要旧值（可选，可能包含敏感信息）
	New       json.RawMessage `json:"new,omitempty" gorm:"type:jsonb"`                               // 变更后的新值（可选，可能包含敏感信息）
	Meta      json.RawMessage `json:"meta,omitempty" gorm:"type:jsonb"`                              // 额外元信息（ip,user_agent,client_id,request_id 等）
	CreatedAt time.Time       `json:"created_at" gorm:"autoCreateTime"`                              // 记录时间
}

func (AuditEvent) TableName() string {
	return "audit_event"
}

// AuditPending 表示在业务事务内写入的轻量审计占位，存入 audit_pending 表。
// 该记录应在同一事务内写入，保证业务数据与审计标记一致性；后台 worker 会消费并转为 AuditEvent。
type AuditPending struct {
	ID        uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey"`
	TxID      uuid.UUID       `json:"tx_id" gorm:"type:uuid;index;not null"` // 关联事务/请求 id，非空
	AccountID *uuid.UUID      `json:"account_id,omitempty" gorm:"type:uuid;index"`
	Action    string          `json:"action" gorm:"type:varchar(128);not null;index"`
	Payload   json.RawMessage `json:"payload" gorm:"type:jsonb"` // 轻量事件负载（建议限制大小）
	Attempts  int             `json:"attempts" gorm:"default:0"`
	LastError *string         `json:"last_error,omitempty" gorm:"type:text"`
	CreatedAt time.Time       `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time       `json:"updated_at" gorm:"autoUpdateTime"`
}

func (AuditPending) TableName() string {
	return "audit_pending"
}

// 注意事项：
// - EnqueuePending（或类似方法）必须在业务事务内调用（tx 非 nil），以保证一致性。
// - AuditPending.Payload 建议保持精简（例如只包含资源摘要与变更引用），避免在事务内写入过大 JSON。
// - Worker 在消费 pending 时应保证幂等（可用 tx_id+action 去重或在写入 audit_event 时加唯一约束）。
// - AuditEvent 的 json 字段使用 json.RawMessage，以便在业务层决定是否以及如何反序列化与脱敏。