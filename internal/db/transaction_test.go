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

// ──────────────────────────────────────────────
// RunInTransaction
// ──────────────────────────────────────────────

func TestRunInTransaction_CommitSuccess(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	mock.ExpectCommit()

	err = RunInTransaction(context.Background(), sqlDB, func(_ *sql.Tx) error {
		return nil
	})

	require.NoError(t, err)
}

func TestRunInTransaction_CallbackError_RollsBack(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	mock.ExpectRollback()

	bizErr := fmt.Errorf("business logic error")
	err = RunInTransaction(context.Background(), sqlDB, func(_ *sql.Tx) error {
		return bizErr
	})

	assert.Error(t, err)
	assert.Equal(t, bizErr, err)
}

func TestRunInTransaction_CommitError(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	mock.ExpectCommit().WillReturnError(fmt.Errorf("commit failed"))

	err = RunInTransaction(context.Background(), sqlDB, func(_ *sql.Tx) error {
		return nil
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "commit transaction")
}

func TestRunInTransaction_PanicRecovery(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	mock.ExpectRollback()

	assert.Panics(t, func() {
		_ = RunInTransaction(context.Background(), sqlDB, func(_ *sql.Tx) error {
			panic("test panic")
		})
	})
}

// ──────────────────────────────────────────────
// RunInTransactionIsolation
// ──────────────────────────────────────────────

func TestRunInTransactionIsolation_Success(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	mock.ExpectCommit()

	err = RunInTransactionIsolation(context.Background(), sqlDB, sql.LevelReadCommitted, func(_ *sql.Tx) error {
		return nil
	})

	require.NoError(t, err)
}

func TestRunInTransactionIsolation_CallbackError(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	mock.ExpectRollback()

	bizErr := fmt.Errorf("isolation error")
	err = RunInTransactionIsolation(context.Background(), sqlDB, sql.LevelReadCommitted, func(_ *sql.Tx) error {
		return bizErr
	})

	assert.Error(t, err)
	assert.Equal(t, bizErr, err)
}

func TestRunInTransactionIsolation_PanicRecovery(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectBegin()
	mock.ExpectRollback()

	assert.Panics(t, func() {
		_ = RunInTransactionIsolation(context.Background(), sqlDB, sql.LevelReadCommitted, func(_ *sql.Tx) error {
			panic("isolation panic")
		})
	})
}
