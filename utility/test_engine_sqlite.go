//go:build sqlite

package utility

import (
	"gosso/internal/database"
	"log"
	"os"

	"gorm.io/gorm"
)

// NewTestDB 创建 SQLite 测试数据库连接
func NewTestDB() *gorm.DB {
	initTestConfig()

	var driver, dsn string
	var logLevel int = 1 // 默认日志级别

	// 优先使用环境变量配置的 SQLite DSN
	if sqliteDSN := os.Getenv("SQLITE_DSN"); sqliteDSN != "" {
		driver = "sqlite3"
		dsn = sqliteDSN
	} else {
		// 使用内存 SQLite 数据库
		driver = "sqlite3"
		dsn = ":memory:"
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
