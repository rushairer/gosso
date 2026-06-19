package db

import (
	"context"
	"database/sql"
)

// Queryable abstracts *sql.DB and *sql.Tx for query and exec operations,
// eliminating duplication between standalone and transactional repository methods.
type Queryable interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}
