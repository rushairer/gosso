package db

// Scannable is satisfied by both *sql.Row and *sql.Rows.
type Scannable interface {
	Scan(dest ...any) error
}
