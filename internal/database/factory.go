package database

import "gorm.io/gorm"

type DatabaseFactory interface {
	CreateDialector(sqlDB gorm.ConnPool) gorm.Dialector
}
