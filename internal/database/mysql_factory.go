//go:build mysql
// +build mysql

package database

import (
	"database/sql"
	"log"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func NewDatabaseFactory() DatabaseFactory {
	return &MySQLFactory{}
}

type MySQLFactory struct{}

func (f MySQLFactory) CreateDialector(driverName string, dataSourceName string) gorm.Dialector {
	sqlDB, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		log.Fatalf("open database failed, err: %v", err)
	}
	return mysql.New(mysql.Config{Conn: sqlDB})
}

func (f MySQLFactory) CreateDialectorWithPoll(sqlDB gorm.ConnPool) gorm.Dialector {
	return mysql.New(mysql.Config{Conn: sqlDB})
}
