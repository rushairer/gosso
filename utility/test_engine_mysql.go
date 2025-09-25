//go:build mysql

package utility

import (
	"gosso/config"
	"gosso/internal/database"
	"gosso/internal/database/factory"
	"log"
	"os"

	"gorm.io/gorm"
)

// GetTestMySQLConfig 获取 MySQL 测试配置
func GetTestMySQLConfig() (driver, dsn string, logLevel int) {
	initTestConfig()

	// 优先使用环境变量配置的 MySQL DSN
	if mysqlDSN := os.Getenv("MYSQL_DSN"); mysqlDSN != "" {
		return "mysql", mysqlDSN, 1
	}

	// 从配置文件获取 MySQL 配置
	mysqlConfig := config.GlobalConfig.DatabaseConfig.GetDriver("mysql")
	if mysqlConfig != nil {
		return mysqlConfig.Driver, mysqlConfig.DSN, mysqlConfig.LogLevel
	}

	// 默认配置（兜底）
	return "mysql", "gosso:gosso123@tcp(127.0.0.1:3308)/gosso_test?charset=utf8mb4&parseTime=True&loc=Local", 1
}

// GetTestMySQLDialector 获取 MySQL 测试 Dialector
func GetTestMySQLDialector() gorm.Dialector {
	driver, dsn, _ := GetTestMySQLConfig()
	dbFactory := factory.NewDatabaseFactory()
	return dbFactory.CreateDialector(driver, dsn)
}

// NewTestDB 创建 MySQL 测试数据库连接
func NewTestDB() *gorm.DB {
	driver, dsn, logLevel := GetTestMySQLConfig()

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
