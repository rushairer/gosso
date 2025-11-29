package service

import (
	"context"
	"database/sql"
	"time"

	"github.com/rushairer/batchflow"
	"github.com/rushairer/gosso/internal/audit/domain"
)

type Auditor struct {
	db           *sql.DB
	batchflow    *batchflow.BatchFlow
	recordSchema *batchflow.SQLSchema
}

func NewAuditor(ctx context.Context, db *sql.DB) *Auditor {
	auditor := Auditor{db: db}
	auditor.batchflow = batchflow.NewPostgreSQLBatchFlow(ctx, db, batchflow.PipelineConfig{
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
		"audit_records",                                                                                      // 表名
		batchflow.ConflictIgnoreOperationConfig,                                                              // 冲突策略
		"id", "tx_id", "account_id", "action", "actor", "resource", "old", "new", "meta", "dd", "created_at", // 列名
	)

	return &auditor
}

func (a *Auditor) ErrorChan() <-chan error {
	return a.batchflow.ErrorChan(1024)
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
			request.SetString("did", auditRecord.AccountID.String())
		}

		if err := a.batchflow.Submit(ctx, request); err != nil {
			return err
		}
	}
	return nil
}
