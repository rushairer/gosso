package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rushairer/gosso/internal/audit/domain"
)

const auditMaxPageSize = 100

// clampAuditPagination normalizes page and pageSize to valid ranges.
// Returns (page, pageSize, offset).
func clampAuditPagination(page, pageSize int) (int, int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > auditMaxPageSize {
		pageSize = 20
	}
	offset := (page - 1) * pageSize
	return page, pageSize, offset
}

type auditQueryRepositoryImpl struct {
	db *sql.DB
}

// NewAuditQueryRepository creates a new audit query repository instance.
func NewAuditQueryRepository(db *sql.DB) AuditQueryRepository {
	return &auditQueryRepositoryImpl{db: db}
}

// Query searches audit records with optional filters and pagination.
func (r *auditQueryRepositoryImpl) Query(ctx context.Context, filter AuditQueryFilter) ([]*domain.AuditRecord, int, error) {
	_, pageSize, offset := clampAuditPagination(filter.Page, filter.PageSize)

	where := "1=1"
	var args []any
	paramIdx := 1

	if filter.AccountID != "" {
		where += fmt.Sprintf(" AND account_id = $%d", paramIdx)
		args = append(args, filter.AccountID)
		paramIdx++
	}
	if filter.EventType != "" {
		where += fmt.Sprintf(" AND action = $%d", paramIdx)
		args = append(args, filter.EventType)
		paramIdx++
	}
	if filter.StartTime != nil {
		where += fmt.Sprintf(" AND created_at >= $%d", paramIdx)
		args = append(args, *filter.StartTime)
		paramIdx++
	}
	if filter.EndTime != nil {
		where += fmt.Sprintf(" AND created_at <= $%d", paramIdx)
		args = append(args, *filter.EndTime)
		paramIdx++
	}

	// Count total matching records.
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM audit_record WHERE %s", where)
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit records: %w", err)
	}
	if total == 0 {
		return []*domain.AuditRecord{}, 0, nil
	}

	// Select page of records.
	selectQuery := fmt.Sprintf(
		`SELECT id, tx_id, account_id, action, actor, resource, "old", "new", meta, created_at
		FROM audit_record
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, where, paramIdx, paramIdx+1)
	args = append(args, pageSize, offset)

	rows, err := r.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query audit records: %w", err)
	}
	defer func() { _ = rows.Close() }()

	records, err := scanAuditRecords(rows)
	if err != nil {
		return nil, 0, err
	}
	return records, total, nil
}

// scanAuditRecords iterates all rows and returns a slice of AuditRecord.
func scanAuditRecords(rows *sql.Rows) ([]*domain.AuditRecord, error) {
	var records []*domain.AuditRecord
	for rows.Next() {
		record, err := scanAuditRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("scan audit record: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit records: %w", err)
	}
	return records, nil
}

// scanAuditRecord scans a single audit_record row into an AuditRecord.
func scanAuditRecord(s interface{ Scan(dest ...any) error }) (*domain.AuditRecord, error) {
	var record domain.AuditRecord
	var oldJSON, newJSON, metaJSON []byte
	var accountID sql.NullString

	if err := s.Scan(
		&record.ID,
		&record.CorrelationID,
		&accountID,
		&record.Action,
		&record.Actor,
		&record.Resource,
		&oldJSON,
		&newJSON,
		&metaJSON,
		&record.CreatedAt,
	); err != nil {
		return nil, err
	}

	if accountID.Valid {
		record.AccountID = &accountID.String
	}
	if len(oldJSON) > 0 {
		record.Old = json.RawMessage(oldJSON)
	}
	if len(newJSON) > 0 {
		record.New = json.RawMessage(newJSON)
	}
	if len(metaJSON) > 0 {
		record.Meta = json.RawMessage(metaJSON)
	}

	return &record, nil
}

// Ensure unused imports are consumed.
var _ = time.Time{}
