package auditor

import (
	"context"
	"gosso/internal/audit/domain"

	"gorm.io/gorm"
)

// Auditor 抽象了审计记录接口，支持在事务内/外写入审计。
// 实现者需保证：
// - EnqueuePending 必须在业务事务内调用（tx 非 nil），以保证业务变更与 pending 标记同生同退。
// - Log/LogTx 可同步写入 audit_event（适用于低频/关键操作），但高频事件建议入队 pending 后异步处理。
// - 所有方法均接收完整的 domain 对象，调用方负责构造，方法负责持久化。
type Auditor interface {
	// Log 在非事务上下文写入审计事件（直接写入 audit_event 表）。
	// 适用于必须立即持久化并可马上查询的关键事件。
	Log(ctx context.Context, event *domain.AuditEvent) error

	// LogTx 在给定事务对象内写入审计事件（事务内写入，随事务提交/回滚）。
	// 适用于需要强一致性的业务变更审计（例如 credential.bind/account.merge）。
	LogTx(ctx context.Context, tx *gorm.DB, event *domain.AuditEvent) error

	// EnqueuePending 在事务内写入 pending 标记，由后台 worker 异步消费并转为 AuditEvent 或上报外部系统。
	// 约定：
	// - 必须在业务事务内调用；tx 不可为 nil。
	// - pending.TxID 应为上层生成的 correlation id（用于幂等性与去重）。
	// - pending.Payload 建议保持精简，以免在事务内写入过大数据。
	EnqueuePending(ctx context.Context, tx *gorm.DB, pending *domain.AuditPending) error
}
