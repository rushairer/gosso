package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/audit"
	"github.com/rushairer/gosso/internal/audit/domain"
)

// ──────────────────────────────────────────────
// NewAuditor
// ──────────────────────────────────────────────

func TestNewAuditor_NilLogger(t *testing.T) {
	// NewAuditor accepts nil DB and nil logger (for testing).
	// It should not panic and should return a valid auditor.
	auditor := NewAuditor(context.Background(), nil, nil, nil)
	require.NotNil(t, auditor)
	assert.NotNil(t, auditor.logger)
	assert.NotNil(t, auditor.cancel)
	assert.Equal(t, auditDrainGracePeriod, auditor.drainGracePeriod)
	auditor.Close()
}

func TestNewAuditor_WithLogger(t *testing.T) {
	logger := zap.NewNop()
	auditor := NewAuditor(context.Background(), nil, nil, logger)
	require.NotNil(t, auditor)
	assert.Equal(t, logger, auditor.logger)
	auditor.Close()
}

// ──────────────────────────────────────────────
// Close
// ──────────────────────────────────────────────
func TestAuditor_Close(t *testing.T) {
	auditor := NewAuditor(context.Background(), nil, nil, nil)
	// Close should not panic
	assert.NotPanics(t, func() { auditor.Close() })
}

// ──────────────────────────────────────────────
// Wait and SetDrainGracePeriod
// ──────────────────────────────────────────────
func TestAuditor_Wait_ShortDrain(t *testing.T) {
	auditor := NewAuditor(context.Background(), nil, nil, nil)
	auditor.SetDrainGracePeriod(1 * time.Millisecond)

	start := time.Now()
	auditor.Wait()
	elapsed := time.Since(start)

	// Should return quickly (well under 1 second)
	assert.Less(t, elapsed, 1*time.Second)
}

func TestAuditor_SetDrainGracePeriod(t *testing.T) {
	auditor := NewAuditor(context.Background(), nil, nil, nil)
	defer auditor.Close()

	auditor.SetDrainGracePeriod(100 * time.Millisecond)
	assert.Equal(t, 100*time.Millisecond, auditor.drainGracePeriod)
}

// ──────────────────────────────────────────────
// ErrorChan
// ──────────────────────────────────────────────
func TestAuditor_ErrorChan(t *testing.T) {
	auditor := NewAuditor(context.Background(), nil, nil, nil)
	defer auditor.Close()

	ch := auditor.ErrorChan()
	assert.NotNil(t, ch)
}

// ──────────────────────────────────────────────
// Log and LogSync with nil receiver
// ──────────────────────────────────────────────
func TestAuditor_Log_NilReceiver(t *testing.T) {
	var auditor *Auditor
	record := &domain.AuditRecord{
		ID:        uuid.New().String(),
		TxID:      uuid.New().String(),
		Action:    "test.action",
		Actor:     "test",
		Resource:  json.RawMessage(`{}`),
		CreatedAt: time.Now(),
	}
	err := auditor.Log(context.Background(), record)
	assert.NoError(t, err)
}

func TestAuditor_LogSync_NilReceiver(t *testing.T) {
	var auditor *Auditor
	record := &domain.AuditRecord{
		ID:        uuid.New().String(),
		TxID:      uuid.New().String(),
		Action:    "test.action",
		Actor:     "test",
		Resource:  json.RawMessage(`{}`),
		CreatedAt: time.Now(),
	}
	err := auditor.LogSync(context.Background(), record)
	assert.NoError(t, err)
}

// ──────────────────────────────────────────────
// AuditLog and AuditLogSync convenience helpers with nil auditor
// ──────────────────────────────────────────────
func TestAuditLog_NilAuditor(t *testing.T) {
	record := &domain.AuditRecord{
		ID:        uuid.New().String(),
		TxID:      uuid.New().String(),
		Action:    "test.action",
		Actor:     "test",
		Resource:  json.RawMessage(`{}`),
		CreatedAt: time.Now(),
	}
	// Should not panic when auditor is nil
	assert.NotPanics(t, func() {
		AuditLog(context.Background(), nil, zap.NewNop(), record)
	})
}

func TestAuditLogSync_NilAuditor(t *testing.T) {
	record := &domain.AuditRecord{
		ID:        uuid.New().String(),
		TxID:      uuid.New().String(),
		Action:    "test.action",
		Actor:     "test",
		Resource:  json.RawMessage(`{}`),
		CreatedAt: time.Now(),
	}
	assert.NotPanics(t, func() {
		AuditLogSync(context.Background(), nil, zap.NewNop(), record)
	})
}

// ──────────────────────────────────────────────
// AuditLog with real auditor (nil DB, tests error path)
// ──────────────────────────────────────────────
func TestAuditLog_WithAuditor_SubmitError(t *testing.T) {
	auditor := NewAuditor(context.Background(), nil, nil, nil)
	auditor.Close() // Close immediately so Submit will fail

	record := &domain.AuditRecord{
		ID:        uuid.New().String(),
		TxID:      uuid.New().String(),
		Action:    "test.action",
		Actor:     "test",
		Resource:  json.RawMessage(`{}`),
		CreatedAt: time.Now(),
	}

	// Should log warning, not panic
	assert.NotPanics(t, func() {
		AuditLog(context.Background(), auditor, zap.NewNop(), record)
	})
}

// ──────────────────────────────────────────────
// Log with request ID enrichment
// ──────────────────────────────────────────────
func TestAuditor_Log_WithRequestID(t *testing.T) {
	auditor := NewAuditor(context.Background(), nil, nil, nil)
	defer auditor.Close()

	ctx := audit.SetMetadata(context.Background(), "127.0.0.1", "test-agent", "req-123")

	record := &domain.AuditRecord{
		ID:        uuid.New().String(),
		TxID:      uuid.New().String(),
		Action:    "test.action",
		Actor:     "test",
		Resource:  json.RawMessage(`{}`),
		Meta:      json.RawMessage(`{"existing": "value"}`),
		CreatedAt: time.Now(),
	}

	// Submit will fail (nil DB), but the request_id injection logic runs
	_ = auditor.Log(ctx, record)

	// Verify that request_id was injected into Meta
	var meta map[string]any
	err := json.Unmarshal(record.Meta, &meta)
	require.NoError(t, err)
	assert.Equal(t, "req-123", meta["request_id"])
	assert.Equal(t, "value", meta["existing"])
}

func TestAuditor_LogSync_WithRequestID(t *testing.T) {
	db, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	auditor := NewAuditor(context.Background(), db, nil, nil)
	defer auditor.Close()

	ctx := audit.SetMetadata(context.Background(), "127.0.0.1", "test-agent", "req-456")

	sqlMock.ExpectExec("INSERT INTO audit_record").
		WillReturnResult(sqlmock.NewResult(0, 1))

	record := &domain.AuditRecord{
		ID:        uuid.New().String(),
		TxID:      uuid.New().String(),
		Action:    "test.action",
		Actor:     "test",
		Resource:  json.RawMessage(`{}`),
		Meta:      json.RawMessage(`{}`),
		CreatedAt: time.Now(),
	}

	err = auditor.LogSync(ctx, record)
	require.NoError(t, err)
	require.NoError(t, sqlMock.ExpectationsWereMet())

	var meta map[string]any
	err = json.Unmarshal(record.Meta, &meta)
	require.NoError(t, err)
	assert.Equal(t, "req-456", meta["request_id"])
}

// ──────────────────────────────────────────────
// Log with malformed meta (triggers fallback)
// ──────────────────────────────────────────────
func TestAuditor_Log_MalformedMeta(t *testing.T) {
	auditor := NewAuditor(context.Background(), nil, nil, nil)
	defer auditor.Close()

	ctx := audit.SetMetadata(context.Background(), "127.0.0.1", "test-agent", "req-789")

	record := &domain.AuditRecord{
		ID:        uuid.New().String(),
		TxID:      uuid.New().String(),
		Action:    "test.action",
		Actor:     "test",
		Resource:  json.RawMessage(`{}`),
		Meta:      json.RawMessage(`not valid json`),
		CreatedAt: time.Now(),
	}

	_ = auditor.Log(ctx, record)

	// Should have replaced meta with request_id + parse_error
	var meta map[string]any
	err := json.Unmarshal(record.Meta, &meta)
	require.NoError(t, err)
	assert.Equal(t, "req-789", meta["request_id"])
	assert.NotEmpty(t, meta["parse_error"])
}

func TestAuditor_LogSync_MalformedMeta(t *testing.T) {
	db, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	auditor := NewAuditor(context.Background(), db, nil, nil)
	defer auditor.Close()

	ctx := audit.SetMetadata(context.Background(), "127.0.0.1", "test-agent", "req-999")

	sqlMock.ExpectExec("INSERT INTO audit_record").
		WillReturnResult(sqlmock.NewResult(0, 1))

	record := &domain.AuditRecord{
		ID:        uuid.New().String(),
		TxID:      uuid.New().String(),
		Action:    "test.action",
		Actor:     "test",
		Resource:  json.RawMessage(`{}`),
		Meta:      json.RawMessage(`bad json`),
		CreatedAt: time.Now(),
	}

	err = auditor.LogSync(ctx, record)
	require.NoError(t, err)
	require.NoError(t, sqlMock.ExpectationsWereMet())

	var meta map[string]any
	err = json.Unmarshal(record.Meta, &meta)
	require.NoError(t, err)
	assert.Equal(t, "req-999", meta["request_id"])
	assert.NotEmpty(t, meta["parse_error"])
}

// ──────────────────────────────────────────────
// Log without request ID (no enrichment)
// ──────────────────────────────────────────────
func TestAuditor_Log_WithoutRequestID(t *testing.T) {
	auditor := NewAuditor(context.Background(), nil, nil, nil)
	defer auditor.Close()

	originalMeta := json.RawMessage(`{"foo": "bar"}`)
	record := &domain.AuditRecord{
		ID:        uuid.New().String(),
		TxID:      uuid.New().String(),
		Action:    "test.action",
		Actor:     "test",
		Resource:  json.RawMessage(`{}`),
		Meta:      originalMeta,
		CreatedAt: time.Now(),
	}

	_ = auditor.Log(context.Background(), record)

	// Meta should be unchanged (no request_id context)
	var meta map[string]any
	err := json.Unmarshal(record.Meta, &meta)
	require.NoError(t, err)
	assert.Equal(t, "bar", meta["foo"])
	assert.Nil(t, meta["request_id"])
}

// ──────────────────────────────────────────────
// Do
// ──────────────────────────────────────────────

func TestDo_BusinessFuncError(t *testing.T) {
	auditor := NewAuditor(context.Background(), nil, nil, nil)
	defer auditor.Close()

	expectedErr := errors.New("business failure")
	err := auditor.Do(context.Background(), func(_ context.Context, _ *sql.DB) (*domain.AuditRecord, error) {
		return nil, expectedErr
	})
	assert.ErrorIs(t, err, expectedErr)
}

func TestDo_NilRecord(t *testing.T) {
	auditor := NewAuditor(context.Background(), nil, nil, nil)
	defer auditor.Close()

	err := auditor.Do(context.Background(), func(_ context.Context, _ *sql.DB) (*domain.AuditRecord, error) {
		return nil, nil
	})
	assert.NoError(t, err)
}

func TestDo_WithRecord(t *testing.T) {
	auditor := NewAuditor(context.Background(), nil, nil, nil)
	defer auditor.Close()

	record := &domain.AuditRecord{
		ID:        uuid.New().String(),
		TxID:      uuid.New().String(),
		Action:    "test.action",
		Actor:     "test",
		Resource:  json.RawMessage(`{}`),
		CreatedAt: time.Now(),
	}

	err := auditor.Do(context.Background(), func(_ context.Context, _ *sql.DB) (*domain.AuditRecord, error) {
		return record, nil
	})
	assert.NoError(t, err)
}

func TestDo_WithRecordAndAccountID(t *testing.T) {
	auditor := NewAuditor(context.Background(), nil, nil, nil)
	defer auditor.Close()

	accountID := "acc-123"
	record := &domain.AuditRecord{
		ID:        uuid.New().String(),
		TxID:      uuid.New().String(),
		AccountID: &accountID,
		Action:    "test.action",
		Actor:     "test",
		Resource:  json.RawMessage(`{}`),
		CreatedAt: time.Now(),
	}

	err := auditor.Do(context.Background(), func(_ context.Context, _ *sql.DB) (*domain.AuditRecord, error) {
		return record, nil
	})
	assert.NoError(t, err)
}

func TestDo_SubmitAfterClose(t *testing.T) {
	auditor := NewAuditor(context.Background(), nil, nil, nil)
	auditor.Close()

	record := &domain.AuditRecord{
		ID:        uuid.New().String(),
		TxID:      uuid.New().String(),
		Action:    "test.action",
		Actor:     "test",
		Resource:  json.RawMessage(`{}`),
		CreatedAt: time.Now(),
	}

	err := auditor.Do(context.Background(), func(_ context.Context, _ *sql.DB) (*domain.AuditRecord, error) {
		return record, nil
	})
	// batchflow.Submit after context cancellation recovers panics internally and returns nil.
	assert.NoError(t, err)
}

// ──────────────────────────────────────────────
// AuditLogSync with real auditor
// ──────────────────────────────────────────────

func TestAuditLogSync_WithAuditor_Success(t *testing.T) {
	db, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	auditor := NewAuditor(context.Background(), db, nil, nil)
	defer auditor.Close()

	sqlMock.ExpectExec("INSERT INTO audit_record").
		WillReturnResult(sqlmock.NewResult(0, 1))

	record := &domain.AuditRecord{
		ID:        uuid.New().String(),
		TxID:      uuid.New().String(),
		Action:    "test.action",
		Actor:     "test",
		Resource:  json.RawMessage(`{}`),
		CreatedAt: time.Now(),
	}

	assert.NotPanics(t, func() {
		AuditLogSync(context.Background(), auditor, zap.NewNop(), record)
	})
	require.NoError(t, sqlMock.ExpectationsWereMet())
}

func TestAuditLogSync_WithAuditor_DBError(t *testing.T) {
	db, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	auditor := NewAuditor(context.Background(), db, nil, nil)
	defer auditor.Close()

	sqlMock.ExpectExec("INSERT INTO audit_record").
		WillReturnError(errors.New("connection refused"))

	record := &domain.AuditRecord{
		ID:        uuid.New().String(),
		TxID:      uuid.New().String(),
		Action:    "test.action",
		Actor:     "test",
		Resource:  json.RawMessage(`{}`),
		CreatedAt: time.Now(),
	}

	assert.NotPanics(t, func() {
		AuditLogSync(context.Background(), auditor, zap.NewNop(), record)
	})
	require.NoError(t, sqlMock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// Log with AccountID (covers submit AccountID branch)
// ──────────────────────────────────────────────

func TestAuditor_Log_WithAccountID(t *testing.T) {
	auditor := NewAuditor(context.Background(), nil, nil, nil)
	defer auditor.Close()

	accountID := "acc-456"
	record := &domain.AuditRecord{
		ID:        uuid.New().String(),
		TxID:      uuid.New().String(),
		AccountID: &accountID,
		Action:    "test.action",
		Actor:     "test",
		Resource:  json.RawMessage(`{}`),
		CreatedAt: time.Now(),
	}

	err := auditor.Log(context.Background(), record)
	assert.NoError(t, err)
}
