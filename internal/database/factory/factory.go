package factory

import "gorm.io/gorm"

type DatabaseFactory interface {
	CreateDialector(driverName string, dataSourceName string) gorm.Dialector
	CreateDialectorWithPoll(sqlDB gorm.ConnPool) gorm.Dialector
}
