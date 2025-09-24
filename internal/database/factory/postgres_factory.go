//go:build postgres
// +build postgres

package factory

import (
	"database/sql"
	"log"

	_ "github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func NewDatabaseFactory() DatabaseFactory {
	return &PostgresFactory{}
}

type PostgresFactory struct{}

func (f PostgresFactory) CreateDialector(driverName string, dataSourceName string) gorm.Dialector {
	sqlDB, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		log.Fatalf("open database failed, err: %v", err)
	}
	return postgres.New(postgres.Config{Conn: sqlDB})
}

func (f PostgresFactory) CreateDialectorWithPoll(sqlDB gorm.ConnPool) gorm.Dialector {
	return postgres.New(postgres.Config{Conn: sqlDB})
}
