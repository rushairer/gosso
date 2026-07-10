package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditQueryRepository_QueryWithFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	start := time.Now().Add(-time.Hour)
	end := time.Now()
	filter := AuditQueryFilter{
		AccountID: "account-001",
		EventType: "account.updated",
		StartTime: &start,
		EndTime:   &end,
		Page:      0,
		PageSize:  500,
	}
	mock.ExpectQuery("SELECT COUNT.*FROM audit_record").
		WithArgs(filter.AccountID, filter.EventType, start, end).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	createdAt := time.Now()
	mock.ExpectQuery("(?s)SELECT id, tx_id.*FROM audit_record").
		WithArgs(filter.AccountID, filter.EventType, start, end, 20, 0).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tx_id", "account_id", "action", "actor", "resource", "old", "new", "meta", "created_at",
		}).AddRow(
			"audit-001", "correlation-001", "account-001", "account.updated", "admin-001",
			[]byte(`{"type":"account","id":"account-001"}`), []byte(`{"status":"pending"}`),
			[]byte(`{"status":"active"}`), []byte(`{"request_id":"request-001"}`), createdAt,
		))

	records, total, err := NewAuditQueryRepository(db).Query(context.Background(), filter)

	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, records, 1)
	assert.Equal(t, "audit-001", records[0].ID)
	require.NotNil(t, records[0].AccountID)
	assert.Equal(t, "account-001", *records[0].AccountID)
	assert.JSONEq(t, `{"status":"active"}`, string(records[0].New))
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAuditQueryRepository_QueryEmpty(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery("SELECT COUNT.*FROM audit_record").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	records, total, err := NewAuditQueryRepository(db).Query(context.Background(), AuditQueryFilter{Page: 1, PageSize: 20})

	require.NoError(t, err)
	assert.Zero(t, total)
	assert.Empty(t, records)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAuditQueryRepository_CountFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	queryErr := errors.New("database unavailable")
	mock.ExpectQuery("SELECT COUNT.*FROM audit_record").WillReturnError(queryErr)

	records, total, err := NewAuditQueryRepository(db).Query(context.Background(), AuditQueryFilter{})

	assert.ErrorIs(t, err, queryErr)
	assert.Nil(t, records)
	assert.Zero(t, total)
	assert.NoError(t, mock.ExpectationsWereMet())
}
