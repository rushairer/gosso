package repository

import (
	"context"
	"time"

	"github.com/rushairer/gosso/internal/audit/domain"
)

// AuditQueryFilter defines the filters for querying audit records.
type AuditQueryFilter struct {
	AccountID string
	EventType string
	StartTime *time.Time
	EndTime   *time.Time
	Page      int
	PageSize  int
}

// AuditQueryRepository defines read operations for audit records.
type AuditQueryRepository interface {
	Query(ctx context.Context, filter AuditQueryFilter) ([]*domain.AuditRecord, int, error)
}
