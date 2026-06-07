package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/rushairer/batchflow"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/audit"
	"github.com/rushairer/gosso/internal/audit/domain"
	"github.com/rushairer/gosso/internal/utility"
)

const (
	auditBufferSize    = 100
	auditFlushSize     = 50
	auditFlushInterval = 5 * time.Second
	auditTimeout       = 300 * time.Millisecond
	auditMaxAttempts   = 3
	auditBackoffBase   = 10 * time.Millisecond
	auditMaxBackoff    = 20 * time.Millisecond
	auditConcurrency   = 100
	auditErrorChanSize = 1024

	// auditDrainGracePeriod is how long Wait() sleeps after cancelling the context.
	// batchflow uses a hardcoded 2s drain grace period; we add 500ms margin.
	auditDrainGracePeriod = 2500 * time.Millisecond
)

type Auditor struct {
	db              *sql.DB
	batchflow       *batchflow.BatchFlow
	recordSchema    *batchflow.SQLSchema
	cancel          context.CancelFunc
	logger          *zap.Logger
	drainGracePeriod time.Duration
}

func NewAuditor(_ context.Context, db *sql.DB, logger *zap.Logger) *Auditor {
	logger = utility.EnsureLogger(logger)
	auditorCtx, cancel := context.WithCancel(context.Background())
	auditor := Auditor{db: db, cancel: cancel, logger: logger, drainGracePeriod: auditDrainGracePeriod}
	auditor.batchflow = batchflow.NewPostgreSQLBatchFlow(auditorCtx, db, batchflow.PipelineConfig{
		BufferSize:    auditBufferSize,
		FlushSize:     auditFlushSize,
		FlushInterval: auditFlushInterval,
		Timeout:       auditTimeout,
		Retry: batchflow.RetryConfig{
			Enabled:     true,
			MaxAttempts: auditMaxAttempts,
			BackoffBase: auditBackoffBase,
			MaxBackoff:  auditMaxBackoff,
		},
		ConcurrencyLimit: auditConcurrency,
	})
	auditor.recordSchema = batchflow.NewSQLSchema(
		"audit_record",                                                                                       // Table name
		batchflow.ConflictIgnoreOperationConfig,                                                              // Conflict policy
		"id", "tx_id", "account_id", "action", "actor", "resource", "old", "new", "meta", "dd", "created_at", // Column names
	)

	return &auditor
}

func (a *Auditor) ErrorChan() <-chan error {
	return a.batchflow.ErrorChan(auditErrorChanSize)
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
//
// The drain grace period must exceed batchflow's internal drain timeout (hardcoded
// at 2s). It is configurable via SetDrainGracePeriod for testing or custom deployments.
func (a *Auditor) Wait() {
	if a.cancel != nil {
		a.cancel()
	}
	time.Sleep(a.drainGracePeriod)
}

// SetDrainGracePeriod overrides the default drain grace period. Must be called
// before Wait(). Useful for testing with shorter timeouts.
func (a *Auditor) SetDrainGracePeriod(d time.Duration) {
	a.drainGracePeriod = d
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
			request.SetString("account_id", *auditRecord.AccountID)
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
			if err := json.Unmarshal(record.Meta, &meta); err != nil {
				a.logger.Warn("Failed to unmarshal audit meta, replacing with request_id only",
					zap.Error(err), zap.String("request_id", requestID))
				meta = map[string]any{"request_id": requestID, "parse_error": err.Error()}
				marshaled, _ := json.Marshal(meta)
				record.Meta = marshaled
				return a.submit(ctx, record)
			}
		}
		if meta == nil {
			meta = make(map[string]any)
		}
		meta["request_id"] = requestID
		marshaled, err := json.Marshal(meta)
		if err != nil {
			a.logger.Warn("Failed to marshal enriched audit meta, preserving original",
				zap.Error(err), zap.String("request_id", requestID))
			return a.submit(ctx, record)
		}
		record.Meta = marshaled
	}

	return a.submit(ctx, record)
}

// submit builds a batchflow request from an audit record and submits it.
func (a *Auditor) submit(ctx context.Context, record *domain.AuditRecord) error {
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
		request.SetString("account_id", *record.AccountID)
	}

	return a.batchflow.Submit(ctx, request)
}

// LogSync writes an audit record directly to the database, bypassing the batch pipeline.
// Use for critical security events (login failures, account deletion, role changes) where
// loss on crash is unacceptable. Safe for nil receiver (no-op).
func (a *Auditor) LogSync(ctx context.Context, record *domain.AuditRecord) error {
	if a == nil {
		return nil
	}

	// Inject request_id into meta (same logic as Log)
	if requestID := audit.RequestIDFromContext(ctx); requestID != "" {
		var meta map[string]any
		if record.Meta != nil {
			if err := json.Unmarshal(record.Meta, &meta); err != nil {
				meta = map[string]any{"request_id": requestID, "parse_error": err.Error()}
			}
		}
		if meta == nil {
			meta = make(map[string]any)
		}
		meta["request_id"] = requestID
		if marshaled, err := json.Marshal(meta); err == nil {
			record.Meta = marshaled
		}
	}

	query := `INSERT INTO audit_record (id, tx_id, account_id, action, actor, resource, "old", "new", meta, dd, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	var accountID interface{}
	if record.AccountID != nil {
		accountID = *record.AccountID
	}

	_, err := a.db.ExecContext(ctx, query,
		record.ID,
		record.TxID,
		accountID,
		record.Action,
		record.Actor,
		record.Resource,
		record.Old,
		record.New,
		record.Meta,
		record.CreatedAt.Format("20060102"),
		record.CreatedAt,
	)
	return err
}
