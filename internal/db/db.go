package db

import (
	"database/sql"
)

// DB is a database wrapper that provides transaction helper methods
type DB struct {
	*sql.DB
}

// NewDB creates a database wrapper
func NewDB(db *sql.DB) *DB {
	return &DB{DB: db}
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.DB.Close()
}
