package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"sync"
	"time"

	"github.com/rushairer/batchflow"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/config"
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
)

// Auditor batches and asynchronously writes audit-log records to the database.
type Auditor struct {
	db           *sql.DB
	batchflow    *batchflow.BatchFlow
	recordSchema *batchflow.SQLSchema
	cancel       context.CancelFunc
	logger       *zap.Logger
	closeOnce    sync.Once
}

// NewAuditor creates an Auditor backed by the given database. Call [Auditor.Wait]
// before process exit to flush pending records.
// If pipelineCfg is non-nil, its BufferSize/FlushSize/FlushInterval values override
// the built-in defaults (zero-valued fields keep the default).
func NewAuditor(ctx context.Context, db *sql.DB, pipelineCfg *config.TaskPipelineConfig, logger *zap.Logger) *Auditor {
	logger = utility.EnsureLogger(logger)
	auditorCtx, cancel := context.WithCancel(ctx)
	auditor := Auditor{db: db, cancel: cancel, logger: logger}

	bufferSize := uint32(auditBufferSize)
	flushSize := uint32(auditFlushSize)
	flushInterval := auditFlushInterval
	timeout := auditTimeout
	maxAttempts := auditMaxAttempts
	backoffBase := auditBackoffBase
	maxBackoff := auditMaxBackoff
	concurrency := auditConcurrency
	if pipelineCfg != nil {
		if pipelineCfg.BufferSize > 0 {
			bufferSize = pipelineCfg.BufferSize
		}
		if pipelineCfg.FlushSize > 0 {
			flushSize = pipelineCfg.FlushSize
		}
		if pipelineCfg.FlushInterval > 0 {
			flushInterval = pipelineCfg.FlushInterval
		}
		if pipelineCfg.Timeout > 0 {
			timeout = pipelineCfg.Timeout
		}
		if pipelineCfg.MaxAttempts > 0 {
			maxAttempts = pipelineCfg.MaxAttempts
		}
		if pipelineCfg.BackoffBase > 0 {
			backoffBase = pipelineCfg.BackoffBase
		}
		if pipelineCfg.MaxBackoff > 0 {
			maxBackoff = pipelineCfg.MaxBackoff
		}
		if pipelineCfg.Concurrency > 0 {
			concurrency = pipelineCfg.Concurrency
		}
	}

	auditor.batchflow = batchflow.NewPostgreSQLBatchFlow(auditorCtx, db, batchflow.PipelineConfig{
		BufferSize:    bufferSize,
		FlushSize:     flushSize,
		FlushInterval: flushInterval,
		Timeout:       timeout,
		Retry: batchflow.RetryConfig{
			Enabled:     true,
			MaxAttempts: maxAttempts,
			BackoffBase: backoffBase,
			MaxBackoff:  maxBackoff,
		},
		ConcurrencyLimit: concurrency,
	})
	auditor.recordSchema = batchflow.NewSQLSchema(
		"audit_record",                                                                                               // Table name
		batchflow.ConflictIgnoreOperationConfig,                                                                      // Conflict policy
		"id", "tx_id", "account_id", "action", "actor", "resource", "\"old\"", "\"new\"", "meta", "dd", "created_at", // Column names
	)

	return &auditor
}

func (a *Auditor) ErrorChan() <-chan error {
	return a.batchflow.ErrorChan(auditErrorChanSize)
}

// Close stops the batchflow pipeline, allowing in-flight batches to complete.
// Safe to call multiple times (idempotent via sync.Once).
// Call this during application shutdown after the HTTP server has stopped.
func (a *Auditor) Close() {
	a.closeOnce.Do(func() {
		if a.batchflow != nil {
			if err := a.batchflow.Close(); err != nil {
				a.logger.Error("Failed to close audit batch pipeline", zap.Error(err))
			}
		}
		if a.cancel != nil {
			a.cancel()
		}
	})
}

// Wait waits for all in-flight audit batches to be flushed to the database.
// Call this during graceful shutdown. It is equivalent to Close() — it flushes
// pending batches, cancels the auditor context, and is safe to call multiple times.
func (a *Auditor) Wait() {
	a.Close()
}

// buildBatchRequest constructs a batchflow.Request from an audit record.
func (a *Auditor) buildBatchRequest(record *domain.AuditRecord) *batchflow.Request {
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

	return request
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
		if err := a.batchflow.Submit(ctx, a.buildBatchRequest(auditRecord)); err != nil {
			return err
		}
	}
	return nil
}

// enrichMeta injects request_id into the record's Meta JSON. It handles
// unmarshal/marshal failures consistently with logging and fallback behavior.
func (a *Auditor) enrichMeta(record *domain.AuditRecord, requestID string) {
	var meta map[string]any
	if record.Meta != nil {
		if err := json.Unmarshal(record.Meta, &meta); err != nil {
			a.logger.Warn("Failed to unmarshal audit meta, replacing with request_id only",
				zap.Error(err), zap.String("request_id", requestID))
			meta = map[string]any{"request_id": requestID, "parse_error": err.Error()}
			marshaled, _ := json.Marshal(meta)
			record.Meta = marshaled
			return
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
		return
	}
	record.Meta = marshaled
}

// Log submits an audit record for async batch write. Safe for nil receiver (no-op).
// It enriches the record's Meta with the request ID from context when available.
func (a *Auditor) Log(ctx context.Context, record *domain.AuditRecord) error {
	if a == nil {
		return nil
	}

	if requestID := audit.RequestIDFromContext(ctx); requestID != "" {
		a.enrichMeta(record, requestID)
	}

	return a.submit(ctx, record)
}

// submit builds a batchflow request from an audit record and submits it.
func (a *Auditor) submit(ctx context.Context, record *domain.AuditRecord) error {
	return a.batchflow.Submit(ctx, a.buildBatchRequest(record))
}

// LogSync writes an audit record directly to the database, bypassing the batch pipeline.
// Use for critical security events (login failures, account deletion, role changes) where
// loss on crash is unacceptable. Safe for nil receiver (no-op).
func (a *Auditor) LogSync(ctx context.Context, record *domain.AuditRecord) error {
	if a == nil {
		return nil
	}

	if requestID := audit.RequestIDFromContext(ctx); requestID != "" {
		a.enrichMeta(record, requestID)
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

// AuditLog is a convenience helper that submits an audit record asynchronously
// and logs a warning on failure. Safe when auditor is nil.
//
// Use AuditLog for non-critical events where occasional loss is acceptable
// (e.g. account registration, federated identity binding). For security-critical
// events (login failures, account deletion, role changes, password changes) where
// loss on crash is unacceptable, use AuditLogSync instead.
func AuditLog(ctx context.Context, auditor *Auditor, logger *zap.Logger, record *domain.AuditRecord) {
	if auditor != nil {
		if err := auditor.Log(ctx, record); err != nil {
			logger.Warn("Failed to submit audit record", zap.Error(err))
		}
	}
}

// AuditLogSync writes an audit record synchronously for critical security events
// where loss on crash is unacceptable (login failures, account deletion, role changes).
// Returns nil when auditor is nil (safe no-op). Callers should handle the error
// (typically by logging) to avoid silent loss of security-critical records.
func AuditLogSync(ctx context.Context, auditor *Auditor, logger *zap.Logger, record *domain.AuditRecord) error {
	if auditor != nil {
		if err := auditor.LogSync(ctx, record); err != nil {
			logger.Error("Failed to write audit record synchronously", zap.Error(err))
			return err
		}
	}
	return nil
}
