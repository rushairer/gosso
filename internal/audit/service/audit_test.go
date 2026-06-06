//go:build integration

package service_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/bytedance/sonic"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rushairer/gosso/internal/audit/domain"
	"github.com/rushairer/gosso/internal/audit/service"
	"github.com/rushairer/gosso/tests"
)

func TestAudit(t *testing.T) {
	db, err := tests.NewTestDB()
	if err != nil {
		t.Skipf("skipping: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	auditor := service.NewAuditor(ctx, db, nil)

	testAccountID := uuid.New().String()

	err = auditor.Do(ctx, func(innerCtx context.Context, db *sql.DB) (*domain.AuditRecord, error) {
		id, err := uuid.NewV7()
		if err != nil {
			return nil, err
		}

		data := map[string]interface{}{
			"key":  "value",
			"mhid": "123",
			"foo":  "bar",
		}
		dataJson, err := sonic.Marshal(data)
		if err != nil {
			return nil, err
		}
		resource := json.RawMessage(dataJson)
		return &domain.AuditRecord{
			ID:        id.String(),
			TxID:      id.String(),
			AccountID: &testAccountID,
			Action:    "test.action",
			Actor:     "test",
			Resource:  resource,
			Old:       json.RawMessage("{}"),
			New:       json.RawMessage(`{"mhid":"123"}`),
			Meta:      json.RawMessage(`{"foo":"bar"}`),
			CreatedAt: time.Now(),
		}, nil
	})
	require.NoError(t, err)

	// Wait for the auditor to flush
	time.Sleep(2 * time.Second)

	// Verify the audit record was persisted
	var count int
	err = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_record WHERE account_id = $1 AND action = 'test.action'`,
		testAccountID,
	).Scan(&count)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 1, "audit record should have been persisted")

	// Cleanup
	_, _ = db.ExecContext(ctx, `DELETE FROM audit_record WHERE account_id = $1`, testAccountID)

	go func() {
		errorChan := auditor.ErrorChan()
		for err := range errorChan {
			_ = err
		}
	}()

	os.Setenv("GOUNO_TEST", "true")
}
