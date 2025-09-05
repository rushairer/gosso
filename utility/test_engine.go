package utility

import (
	"context"
	"database/sql"
	"errors"
	"gosso/config"
	"gosso/internal/domain"
	"gosso/router"
	"gosso/task"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	gopipeline "github.com/rushairer/go-pipeline"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
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
	err := config.InitConfig(configPath, "test")
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
			NamingStrategy: schema.NamingStrategy{
				SingularTable: true,
			},
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

func NewTestEngine(ctx context.Context, withTask bool) *gin.Engine {
	engine := gin.New()

	gormDB := NewTestDB()

	var taskPipeline *gopipeline.Pipeline[task.Task]
	if withTask {
		taskPipeline = task.NewTaskPipeline(
			config.GlobalConfig.TaskPipelineConfig.BufferSize,
			config.GlobalConfig.TaskPipelineConfig.FlushSize,
			config.GlobalConfig.TaskPipelineConfig.FlushInterval,
		)
		go func() {
			if err := taskPipeline.AsyncPerform(ctx); err != nil {
				if errors.Is(err, gopipeline.ErrContextIsClosed) {
					log.Printf("async perform task pipeline context is closed, exit: %v", err)
					return
				}
				log.Fatalf("async perform task pipeline failed, err: %v", err)
			}
		}()
	}

	router.RegisterWebRouter(engine, gormDB, taskPipeline)

	return engine
}
