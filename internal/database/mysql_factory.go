//go:build mysql
// +build mysql

package database

import (
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func NewDatabaseFactory() DatabaseFactory {
	return &MySQLFactory{}
}

type MySQLFactory struct{}

func (f MySQLFactory) CreateDialector(sqlDB gorm.ConnPool) gorm.Dialector {
	return mysql.New(mysql.Config{Conn: sqlDB})
}
