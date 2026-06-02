package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/rushairer/batchflow"

	"github.com/rushairer/gosso/internal/audit"
	"github.com/rushairer/gosso/internal/audit/domain"
)

type Auditor struct {
	db           *sql.DB
	batchflow    *batchflow.BatchFlow
	recordSchema *batchflow.SQLSchema
	cancel       context.CancelFunc
}

func NewAuditor(_ context.Context, db *sql.DB) *Auditor {
	auditorCtx, cancel := context.WithCancel(context.Background())
	auditor := Auditor{db: db, cancel: cancel}
	auditor.batchflow = batchflow.NewPostgreSQLBatchFlow(auditorCtx, db, batchflow.PipelineConfig{
		BufferSize:    100,                    // 缓冲区大小
		FlushSize:     50,                     // 批量刷新大小
		FlushInterval: 5 * time.Second,        // 刷新间隔
		Timeout:       300 * time.Millisecond, // 超时时间
		Retry: batchflow.RetryConfig{
			Enabled:     true,                  // 是否重试
			MaxAttempts: 3,                     // 总尝试次数（含首轮），建议 2~3
			BackoffBase: 10 * time.Millisecond, // 退避基值（指数退避起点）
			MaxBackoff:  20 * time.Millisecond, // 最大退避时长（上限）
		},

		ConcurrencyLimit: 100, // 批量并发限制
	})
	auditor.recordSchema = batchflow.NewSQLSchema(
		"audit_record",                                                                                       // 表名
		batchflow.ConflictIgnoreOperationConfig,                                                              // 冲突策略
		"id", "tx_id", "account_id", "action", "actor", "resource", "old", "new", "meta", "dd", "created_at", // 列名
	)

	return &auditor
}

func (a *Auditor) ErrorChan() <-chan error {
	return a.batchflow.ErrorChan(1024)
}

// Close stops the batchflow pipeline, allowing in-flight batches to complete.
// Call this during application shutdown after the HTTP server has stopped.
func (a *Auditor) Close() {
	if a.cancel != nil {
		a.cancel()
	}
}

func (a *Auditor) Do(
	ctx context.Context,
	businessFunc func(innerCtx context.Context, db *sql.DB) (*domain.AuditRecord, error),
) error {

	auditRecord, err := businessFunc(ctx, a.db)
	if err != nil {
		return err
	}

	if auditRecord != nil {
		request := batchflow.NewRequest(a.recordSchema).
			Set("id", auditRecord.ID).
			Set("tx_id", auditRecord.TxID).
			SetString("action", auditRecord.Action).
			SetString("actor", auditRecord.Actor).
			Set("resource", auditRecord.Resource).
			Set("old", auditRecord.Old).
			Set("new", auditRecord.New).
			Set("meta", auditRecord.Meta).
			SetString("dd", auditRecord.CreatedAt.Format("20060102")).
			SetTime("created_at", auditRecord.CreatedAt)

		if auditRecord.AccountID != nil {
			request.SetString("account_id", auditRecord.AccountID.String())
		}

		if err := a.batchflow.Submit(ctx, request); err != nil {
			return err
		}
	}
	return nil
}

// Log submits an audit record for async batch write. Safe for nil receiver (no-op).
// It enriches the record's Meta with the request ID from context when available.
func (a *Auditor) Log(ctx context.Context, record *domain.AuditRecord) error {
	if a == nil {
		return nil
	}

	// Inject request_id into meta
	if requestID := audit.RequestIDFromContext(ctx); requestID != "" {
		var meta map[string]any
		if record.Meta != nil {
			_ = json.Unmarshal(record.Meta, &meta)
		}
		if meta == nil {
			meta = make(map[string]any)
		}
		meta["request_id"] = requestID
		record.Meta, _ = json.Marshal(meta)
	}

	request := batchflow.NewRequest(a.recordSchema).
		Set("id", record.ID).
		Set("tx_id", record.TxID).
		SetString("action", record.Action).
		SetString("actor", record.Actor).
		Set("resource", record.Resource).
		Set("old", record.Old).
		Set("new", record.New).
		Set("meta", record.Meta).
		SetString("dd", record.CreatedAt.Format("20060102")).
		SetTime("created_at", record.CreatedAt)

	if record.AccountID != nil {
		request.SetString("account_id", record.AccountID.String())
	}

	return a.batchflow.Submit(ctx, request)
}
