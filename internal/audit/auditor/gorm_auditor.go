package auditor

import (
	"context"
	"errors"
	"gosso/internal/audit/domain"

	"gorm.io/gorm"
)

// GormAuditor 为 GORM 实现的 Auditor
type GormAuditor struct {
	db *gorm.DB
}

func NewGormAuditor(db *gorm.DB) *GormAuditor {
	return &GormAuditor{db: db}
}

func (a *GormAuditor) Log(ctx context.Context, event *domain.AuditEvent) error {
	if event == nil {
		return errors.New("audit event required")
	}
	return a.db.WithContext(ctx).Create(event).Error
}

func (a *GormAuditor) LogTx(ctx context.Context, tx *gorm.DB, event *domain.AuditEvent) error {
	if event == nil {
		return errors.New("audit event required")
	}
	if tx == nil {
		return errors.New("transaction required")
	}
	return tx.WithContext(ctx).Create(event).Error
}

// EnqueuePending 在事务 tx 内写入一条 AuditPending 记录。
// 调用方负责构造完整的 pending 对象，本方法只负责持久化。
func (a *GormAuditor) EnqueuePending(ctx context.Context, tx *gorm.DB, pending *domain.AuditPending) error {
	if tx == nil {
		return errors.New("transaction required")
	}
	if pending == nil {
		return errors.New("audit pending required")
	}

	return tx.WithContext(ctx).Create(pending).Error
}
