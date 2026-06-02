package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
)

// DB is a database wrapper that provides transaction helper methods
type DB struct {
	*sql.DB
}

// NewDB creates a database wrapper
func NewDB(db *sql.DB) *DB {
	return &DB{DB: db}
}

// WithTransaction is a transaction helper method that automatically handles commit and rollback.
// Suitable for simple scenarios; explicit transaction management is recommended for complex business logic.
func (db *DB) WithTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			if rerr := tx.Rollback(); rerr != nil {
				log.Printf("rollback failed during panic recovery: %v", rerr)
			}
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		if rerr := tx.Rollback(); rerr != nil {
			log.Printf("rollback failed: %v (original error: %v)", rerr, err)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// WithTransactionIsolation is a transaction helper method with a specified isolation level
func (db *DB) WithTransactionIsolation(ctx context.Context, isolation sql.IsolationLevel, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{
		Isolation: isolation,
	})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			if rerr := tx.Rollback(); rerr != nil {
				log.Printf("rollback failed during panic recovery: %v", rerr)
			}
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		if rerr := tx.Rollback(); rerr != nil {
			log.Printf("rollback failed: %v (original error: %v)", rerr, err)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// Sentinel errors for transaction failures
var (
	ErrBeginTransaction = errors.New("begin transaction failed")
	ErrCommitTransaction = errors.New("commit transaction failed")
)
