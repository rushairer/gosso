//go:build postgres

package utility

import (
	"gosso/internal/database"
	"log"
	"os"

	"gorm.io/gorm"
)

// NewTestDB 创建 PostgreSQL 测试数据库连接
func NewTestDB() *gorm.DB {
	initTestConfig()

	var driver, dsn string
	var logLevel int = 1 // 默认日志级别

	// 优先使用环境变量配置的 PostgreSQL DSN
	if postgresDSN := os.Getenv("POSTGRES_DSN"); postgresDSN != "" {
		driver = "pgx"
		dsn = postgresDSN
	} else {
		// 使用测试环境的 PostgreSQL 配置
		driver = "pgx"
		dsn = "host=localhost user=gosso password=gosso123 dbname=gosso_test port=5434 sslmode=disable TimeZone=Asia/Shanghai"
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
