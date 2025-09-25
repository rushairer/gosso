//go:build postgres

package utility

import (
	"gosso/config"
	"gosso/internal/database"
	"gosso/internal/database/factory"
	"log"
	"os"

	"gorm.io/gorm"
)

// GetTestPostgreSQLConfig 获取 PostgreSQL 测试配置
func GetTestPostgreSQLConfig() (driver, dsn string, logLevel int) {
	initTestConfig()

	// 优先使用环境变量配置的 PostgreSQL DSN
	if postgresDSN := os.Getenv("POSTGRES_DSN"); postgresDSN != "" {
		return "pgx", postgresDSN, 1
	}

	// 从配置文件获取 PostgreSQL 配置
	postgresConfig := config.GlobalConfig.DatabaseConfig.GetDriver("postgres")
	if postgresConfig != nil {
		return postgresConfig.Driver, postgresConfig.DSN, postgresConfig.LogLevel
	}

	// 默认配置（兜底）
	return "pgx", "host=127.0.0.1 user=gosso password=gosso123 dbname=gosso_test port=5434 sslmode=disable TimeZone=Asia/Shanghai", 1
}

// GetTestPostgreSQLDialector 获取 PostgreSQL 测试 Dialector
func GetTestPostgreSQLDialector() gorm.Dialector {
	driver, dsn, _ := GetTestPostgreSQLConfig()
	dbFactory := factory.NewDatabaseFactory()
	return dbFactory.CreateDialector(driver, dsn)
}

// NewTestDB 创建 PostgreSQL 测试数据库连接
func NewTestDB() *gorm.DB {
	driver, dsn, logLevel := GetTestPostgreSQLConfig()

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
