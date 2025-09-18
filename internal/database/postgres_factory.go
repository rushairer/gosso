//go:build postgres
// +build postgres

package database

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func NewDatabaseFactory() DatabaseFactory {
	return &PostgresFactory{}
}

type PostgresFactory struct{}

func (f PostgresFactory) CreateDialector(sqlDB gorm.ConnPool) gorm.Dialector {
	return postgres.New(postgres.Config{Conn: sqlDB})
}
