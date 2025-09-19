package database

import (
	"gosso/config"
	"log"
	"os"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

func NewGormDB(config config.DatabaseConfigDriver) *gorm.DB {
	var dialector gorm.Dialector
	factory := NewDatabaseFactory()
	dialector = factory.CreateDialector(config.Driver, config.DSN)

	dbLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second,                      // 慢速 SQL 阈值
			LogLevel:                  logger.LogLevel(config.LogLevel), // 日志级别
			IgnoreRecordNotFoundError: true,                             // 忽略记录器的 ErrRecordNotFound 错误
		},
	)

	gormDB, err := gorm.Open(
		dialector,
		&gorm.Config{
			Logger: dbLogger,
			NamingStrategy: schema.NamingStrategy{
				SingularTable: true,
			},
		})
	if err != nil {
		log.Fatalf("open database failed, err: %v", err)
	}

	return gormDB
}
