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
	// PostgreSQL 使用 pgx 驱动，但 GORM 的 postgres 驱动可以直接使用 DSN
	if driverName == "pgx" || driverName == "postgres" {
		return postgres.Open(dataSourceName)
	}

	// 兼容旧的 sql.Open 方式
	sqlDB, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		log.Fatalf("open database failed, err: %v", err)
	}
	return postgres.New(postgres.Config{Conn: sqlDB})
}

func (f PostgresFactory) CreateDialectorWithPoll(sqlDB gorm.ConnPool) gorm.Dialector {
	return postgres.New(postgres.Config{Conn: sqlDB})
}
