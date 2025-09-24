package testutil

import (
	"gosso/internal/database/factory"
	"os"

	"gorm.io/gorm"
)

// GetTestDatabase 根据构建标签和环境变量返回测试数据库连接
func GetTestDatabase() (*gorm.DB, error) {
	dbFactory := factory.NewDatabaseFactory()

	// 根据环境变量选择数据库类型和连接字符串
	if mysqlDSN := os.Getenv("MYSQL_DSN"); mysqlDSN != "" {
		dialector := dbFactory.CreateDialector("mysql", mysqlDSN)
		return gorm.Open(dialector, &gorm.Config{})
	}

	if postgresDSN := os.Getenv("POSTGRES_DSN"); postgresDSN != "" {
		dialector := dbFactory.CreateDialector("postgres", postgresDSN)
		return gorm.Open(dialector, &gorm.Config{})
	}

	// 默认使用内存数据库（SQLite）
	dialector := dbFactory.CreateDialector("sqlite3", ":memory:")
	return gorm.Open(dialector, &gorm.Config{})
}

// GetTestDatabaseType 返回当前测试使用的数据库类型
func GetTestDatabaseType() string {
	if os.Getenv("MYSQL_DSN") != "" {
		return "mysql"
	}
	if os.Getenv("POSTGRES_DSN") != "" {
		return "postgres"
	}
	return "sqlite"
}
