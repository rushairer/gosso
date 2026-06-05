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
		BufferSize:    100,                    // Buffer size
		FlushSize:     50,                     // Batch flush size
		FlushInterval: 5 * time.Second,        // Flush interval
		Timeout:       300 * time.Millisecond, // Timeout
		Retry: batchflow.RetryConfig{
			Enabled:     true,                  // Enable retry
			MaxAttempts: 3,                     // Total attempts (including first attempt), suggest 2-3
			BackoffBase: 10 * time.Millisecond, // Backoff base (exponential backoff start)
			MaxBackoff:  20 * time.Millisecond, // Max backoff duration (upper limit)
		},

		ConcurrencyLimit: 100, // Batch concurrency limit
	})
	auditor.recordSchema = batchflow.NewSQLSchema(
		"audit_record",                                                                                       // Table name
		batchflow.ConflictIgnoreOperationConfig,                                                              // Conflict policy
		"id", "tx_id", "account_id", "action", "actor", "resource", "old", "new", "meta", "dd", "created_at", // Column names
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

// Wait cancels the batchflow context and waits for the drain grace period to
// elapse, ensuring all in-flight audit batches are flushed. Call this during
// graceful shutdown instead of Close() when you need to guarantee writes complete.
func (a *Auditor) Wait() {
	if a.cancel != nil {
		a.cancel()
	}
	// batchflow uses a hardcoded 2s drain grace period on context cancel.
	// Sleep slightly longer to ensure all in-flight batches are flushed.
	time.Sleep(2500 * time.Millisecond)
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
