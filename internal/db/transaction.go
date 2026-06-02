package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
)

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
				log.Printf("rollback failed during panic recovery: %v", rerr)
			}
			panic(p)
		} else if panicked || err != nil {
			if rerr := tx.Rollback(); rerr != nil {
				log.Printf("rollback failed: %v", rerr)
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

// WithTransaction is a transaction helper method that automatically handles commit and rollback.
// Suitable for simple scenarios; explicit transaction management is recommended for complex business logic.
func (db *DB) WithTransaction(ctx context.Context, fn func(tx *sql.Tx) error) (err error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	panicked := true
	defer func() {
		if p := recover(); p != nil {
			if rerr := tx.Rollback(); rerr != nil {
				log.Printf("rollback failed during panic recovery: %v", rerr)
			}
			panic(p)
		} else if panicked || err != nil {
			if rerr := tx.Rollback(); rerr != nil {
				log.Printf("rollback failed: %v", rerr)
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

// WithTransactionIsolation is a transaction helper method with a specified isolation level
func (db *DB) WithTransactionIsolation(ctx context.Context, isolation sql.IsolationLevel, fn func(tx *sql.Tx) error) (err error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{
		Isolation: isolation,
	})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	panicked := true
	defer func() {
		if p := recover(); p != nil {
			if rerr := tx.Rollback(); rerr != nil {
				log.Printf("rollback failed during panic recovery: %v", rerr)
			}
			panic(p)
		} else if panicked || err != nil {
			if rerr := tx.Rollback(); rerr != nil {
				log.Printf("rollback failed: %v", rerr)
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
