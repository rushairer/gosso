package repository

import (
	"context"
	"database/sql"

	"github.com/rushairer/gosso/internal/audit/domain"
)

type AuditRepository struct {
	db *sql.DB
}

func NewAuditRepository(
	db *sql.DB,
) *AuditRepository {
	return &AuditRepository{
		db: db,
	}
}

func (r *AuditRepository) Log(
	ctx context.Context,
	record *domain.AuditRecord,
) (err error) {
	return
}

func (r *AuditRepository) LogTx(
	ctx context.Context,
	record *domain.AuditRecord,
) (err error) {
	return
}
