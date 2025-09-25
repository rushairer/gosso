//go:build sqlite

package utility

import (
	"gosso/config"
	"gosso/internal/database"
	"gosso/internal/database/factory"
	"log"
	"os"

	"gorm.io/gorm"
)

// GetTestSQLiteConfig 获取 SQLite 测试配置
func GetTestSQLiteConfig() (driver, dsn string, logLevel int) {
	initTestConfig()

	// 优先使用环境变量配置的 SQLite DSN
	if sqliteDSN := os.Getenv("SQLITE_DSN"); sqliteDSN != "" {
		return "sqlite3", sqliteDSN, 1
	}

	// 从配置文件获取 SQLite 配置
	sqliteConfig := config.GlobalConfig.DatabaseConfig.GetDriver("sqlite")
	if sqliteConfig != nil {
		return sqliteConfig.Driver, sqliteConfig.DSN, sqliteConfig.LogLevel
	}

	// 默认配置（兜底）
	return "sqlite3", ":memory:", 1
}

// GetTestSQLiteDialector 获取 SQLite 测试 Dialector
func GetTestSQLiteDialector() gorm.Dialector {
	driver, dsn, _ := GetTestSQLiteConfig()
	dbFactory := factory.NewDatabaseFactory()
	return dbFactory.CreateDialector(driver, dsn)
}

// NewTestDB 创建 SQLite 测试数据库连接
func NewTestDB() *gorm.DB {
	driver, dsn, logLevel := GetTestSQLiteConfig()

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
