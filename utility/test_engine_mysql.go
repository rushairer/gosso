//go:build mysql

package utility

import (
	"gosso/internal/database"
	"log"
	"os"

	"gorm.io/gorm"
)

// NewTestDB 创建 MySQL 测试数据库连接
func NewTestDB() *gorm.DB {
	initTestConfig()

	var driver, dsn string
	var logLevel int = 1 // 默认日志级别

	// 优先使用环境变量配置的 MySQL DSN
	if mysqlDSN := os.Getenv("MYSQL_DSN"); mysqlDSN != "" {
		driver = "mysql"
		dsn = mysqlDSN
	} else {
		// 使用测试环境的 MySQL 配置
		driver = "mysql"
		dsn = "gosso:gosso123@tcp(localhost:3308)/gosso_test?charset=utf8mb4&parseTime=True&loc=Local"
	}

	gormDB := database.NewGormDB(driver, dsn, logLevel)

	var err error
	err = database.CleanMigrate(gormDB)
	if err != nil {
		log.Fatalf("clean migrate failed, err: %v", err)
	}

	err = database.AutoMigrate(gormDB)
	if err != nil {
		log.Fatalf("auto migrate failed, err: %v", err)
	}

	return gormDB
}
