package utility

import (
	"database/sql"
	"gosso/config"
	"gosso/internal/domain"
	"gosso/router"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// getProjectRoot attempts to find the project root by looking for go.mod file.
func getProjectRoot() string {
	_, b, _, _ := runtime.Caller(0)
	// This will be the directory of the current file (test_engine.go)
	currentDir := filepath.Dir(b)

	// Traverse up the directory tree to find go.mod
	for {
		goModPath := filepath.Join(currentDir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return currentDir
		}
		parentDir := filepath.Dir(currentDir)
		if parentDir == currentDir { // Reached file system root
			log.Fatalf("go.mod not found in any parent directory")
		}
		currentDir = parentDir
	}
}

func NewTestDB() *gorm.DB {
	projectRoot := getProjectRoot()
	configPath := filepath.Join(projectRoot, "config")
	err := config.InitConfig(configPath, "test", nil)
	if err != nil {
		log.Fatalf("init config failed, err: %v", err)
	}

	// init db
	sqlDB, err := sql.Open(config.GlobalConfig.DatabaseConfig.Driver, config.GlobalConfig.DatabaseConfig.DSN)
	if err != nil {
		log.Fatalf("open database failed, err: %v", err)
	}

	dbLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second,                                                  // 慢速 SQL 阈值
			LogLevel:                  logger.LogLevel(config.GlobalConfig.DatabaseConfig.LogLevel), // 日志级别
			IgnoreRecordNotFoundError: true,                                                         // 忽略记录器的 ErrRecordNotFound 错误
		},
	)

	gormDB, err := gorm.Open(
		mysql.New(mysql.Config{
			Conn: sqlDB,
		}),
		&gorm.Config{
			Logger: dbLogger,
		})
	if err != nil {
		log.Fatalf("open database failed, err: %v", err)
	}

	err = domain.CleanMigrate(gormDB)
	if err != nil {
		log.Fatalf("clean migrate failed, err: %v", err)
	}

	err = domain.AutoMigrate(gormDB)
	if err != nil {
		log.Fatalf("auto migrate failed, err: %v", err)
	}

	return gormDB
}

func NewTestEngine() *gin.Engine {
	gormDB := NewTestDB()

	engine := gin.New()
	router.RegisterWebRouter(engine, gormDB)

	return engine
}
