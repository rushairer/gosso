package db

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDB(t *testing.T) {
	sqlDB, _, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	db := NewDB(sqlDB)
	assert.NotNil(t, db)
	assert.Equal(t, sqlDB, db.DB)
}

// ──────────────────────────────────────────────
// WithTransaction
// ──────────────────────────────────────────────

func TestWithTransaction_CommitSuccess(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	mock.ExpectCommit()

	db := NewDB(sqlDB)
	err = db.WithTransaction(context.Background(), func(_ *sql.Tx) error {
		return nil
	})

	require.NoError(t, err)
}

func TestWithTransaction_CallbackError_RollsBack(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	mock.ExpectRollback()

	db := NewDB(sqlDB)
	bizErr := fmt.Errorf("business logic error")
	err = db.WithTransaction(context.Background(), func(_ *sql.Tx) error {
		return bizErr
	})

	assert.Error(t, err)
	assert.Equal(t, bizErr, err)
}

func TestWithTransaction_CommitError(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	mock.ExpectCommit().WillReturnError(fmt.Errorf("commit failed"))

	db := NewDB(sqlDB)
	err = db.WithTransaction(context.Background(), func(_ *sql.Tx) error {
		return nil
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "commit transaction")
}

func TestWithTransaction_PanicRecovery(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	mock.ExpectRollback()

	db := NewDB(sqlDB)

	assert.Panics(t, func() {
		_ = db.WithTransaction(context.Background(), func(_ *sql.Tx) error {
			panic("test panic")
		})
	})
}

// ──────────────────────────────────────────────
// WithTransactionIsolation
// ──────────────────────────────────────────────

func TestWithTransactionIsolation_Success(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	mock.ExpectCommit()

	db := NewDB(sqlDB)
	err = db.WithTransactionIsolation(context.Background(), 0, func(_ *sql.Tx) error {
		return nil
	})

	require.NoError(t, err)
}

func TestWithTransactionIsolation_CallbackError(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	mock.ExpectRollback()

	db := NewDB(sqlDB)
	bizErr := fmt.Errorf("isolation error")
	err = db.WithTransactionIsolation(context.Background(), 0, func(_ *sql.Tx) error {
		return bizErr
	})

	assert.Error(t, err)
	assert.Equal(t, bizErr, err)
}

func TestWithTransactionIsolation_PanicRecovery(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	mock.ExpectRollback()

	db := NewDB(sqlDB)

	assert.Panics(t, func() {
		_ = db.WithTransactionIsolation(context.Background(), 0, func(_ *sql.Tx) error {
			panic("isolation panic")
		})
	})
}
