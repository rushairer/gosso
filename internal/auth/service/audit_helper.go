package service

import (
	"context"

	"go.uber.org/zap"

	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	auditService "github.com/rushairer/gosso/internal/audit/service"
)

// auditLog is a shared helper that submits an audit record and logs a warning on failure.
func auditLog(ctx context.Context, auditor *auditService.Auditor, logger *zap.Logger, record *auditDomain.AuditRecord) {
	if auditor != nil {
		if err := auditor.Log(ctx, record); err != nil {
			logger.Warn("Failed to submit audit record", zap.Error(err))
		}
	}
}
