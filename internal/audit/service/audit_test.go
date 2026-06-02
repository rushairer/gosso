//go:build integration

package service_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"testing"
	"time"

	"github.com/bytedance/sonic"
	"github.com/google/uuid"

	"github.com/rushairer/gosso/internal/audit/domain"
	"github.com/rushairer/gosso/internal/audit/service"
	"github.com/rushairer/gosso/tests"
)

func TestAudit(t *testing.T) {

	db := tests.NewTestDB()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	auditor := service.NewAuditor(ctx, db)

	_ = auditor.Do(ctx, func(innerCtx context.Context, db *sql.DB) (*domain.AuditRecord, error) {

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
			ID:        id,
			TxID:      id,
			AccountID: &id,
			Action:    "redis.set",
			Actor:     "test",
			Resource:  resource,
			Old:       json.RawMessage("{}"),
			New:       json.RawMessage(`{"mhid":"123"}`),
			Meta:      json.RawMessage(`{"foo":"bar"}`),
			CreatedAt: time.Now(),
		}, nil
	})

	go func() {
		errorChan := auditor.ErrorChan()
		for err := range errorChan {
			log.Printf("Batch processing error: %v", err)
		}
	}()

	<-ctx.Done()

}
