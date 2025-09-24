//go:build sqlite
// +build sqlite

package factory

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func NewDatabaseFactory() DatabaseFactory {
	return &SQLiteFactory{}
}

type SQLiteFactory struct{}

func (f SQLiteFactory) CreateDialector(driverName string, dataSourceName string) gorm.Dialector {
	sqlDB, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		log.Fatalf("open database failed, err: %v", err)
	}
	return sqlite.New(sqlite.Config{Conn: sqlDB})
}

func (f SQLiteFactory) CreateDialectorWithPoll(sqlDB gorm.ConnPool) gorm.Dialector {
	return sqlite.New(sqlite.Config{Conn: sqlDB})
}
