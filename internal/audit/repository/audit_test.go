package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rushairer/gosso/internal/audit/domain"
	"github.com/rushairer/gosso/internal/audit/repository"
	"github.com/rushairer/gosso/test"
)

func TestLog(t *testing.T) {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	db := test.NewTestDB()

	repository := repository.NewAuditRepository(db)

	id, err := uuid.NewV7()
	if err != nil {
		t.Error(err)
	}
	err = repository.Log(ctx, &domain.AuditRecord{
		ID:     id,
		Action: "test",
	})
	if err != nil {
		t.Error(err)
	}
}
