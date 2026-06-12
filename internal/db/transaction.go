package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"

	"go.uber.org/zap"
)

// logger is an optional structured logger for the db package.
// If nil, fallback to the standard log package.
var logger *zap.Logger

// SetLogger configures a structured logger for the db package.
// Call this during application startup before any transaction runs.
func SetLogger(l *zap.Logger) {
	logger = l
}

// RunInTransaction executes fn within a database transaction with LevelReadCommitted isolation.
// If fn returns an error or panics, the transaction is rolled back; otherwise it is committed.
func RunInTransaction(ctx context.Context, db *sql.DB, fn func(tx *sql.Tx) error) (err error) {
	return RunInTransactionIsolation(ctx, db, sql.LevelReadCommitted, fn)
}

// RunInTransactionIsolation is like RunInTransaction but allows specifying the isolation level.
func RunInTransactionIsolation(ctx context.Context, db *sql.DB, isolation sql.IsolationLevel, fn func(tx *sql.Tx) error) (err error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: isolation})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	panicked := true
	defer func() {
		if p := recover(); p != nil {
			if rerr := tx.Rollback(); rerr != nil {
				logRollbackError("rollback failed during panic recovery", rerr)
			}
			panic(p)
		} else if panicked || err != nil {
			if rerr := tx.Rollback(); rerr != nil {
				logRollbackError("rollback failed", rerr)
				if err != nil {
					err = errors.Join(err, fmt.Errorf("transaction rollback failed: %w", rerr))
				} else {
					err = fmt.Errorf("transaction rollback failed: %w", rerr)
				}
			}
		}
	}()

	err = fn(tx)
	panicked = false

	if err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// logRollbackError logs a rollback failure using the structured logger if available,
// falling back to the standard log package otherwise.
func logRollbackError(msg string, rerr error) {
	if logger != nil {
		logger.Warn(msg, zap.Error(rerr))
	} else {
		log.Printf("%s: %v", msg, rerr)
	}
}
