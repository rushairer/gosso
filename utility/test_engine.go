package utility

import (
	"context"
	"errors"
	"gosso/config"
	"gosso/internal/database"
	"gosso/router"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/rushairer/gouno/task"

	"github.com/gin-gonic/gin"
	gopipeline "github.com/rushairer/go-pipeline"
	"gorm.io/gorm"
)

// projectRoot attempts to find the project root by looking for go.mod file.
func projectRoot() string {
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

var testOnce sync.Once

func initTestConfig() {
	testOnce.Do(func() {
		projectRoot := projectRoot()
		configPath := filepath.Join(projectRoot, "config")
		err := config.InitConfig(configPath, "test")
		if err != nil {
			log.Fatalf("init config failed, err: %v", err)
		}
	})
}

func NewTestDB() *gorm.DB {
	initTestConfig()

	// 根据环境变量选择数据库类型，优先使用 CI 环境配置
	var driver, dsn string
	var logLevel int = 1 // 默认日志级别

	if mysqlDSN := os.Getenv("MYSQL_DSN"); mysqlDSN != "" {
		driver = "mysql"
		dsn = mysqlDSN
	} else if postgresDSN := os.Getenv("POSTGRES_DSN"); postgresDSN != "" {
		driver = "pgx"
		dsn = postgresDSN
	} else {
		// 回退到配置文件中的默认驱动
		defaultDriver := config.GlobalConfig.DatabaseConfig.GetDefaultDriver()
		if defaultDriver == nil {
			// 如果配置文件也没有，使用内存 SQLite
			driver = "sqlite3"
			dsn = ":memory:"
		} else {
			driver = defaultDriver.Driver
			dsn = defaultDriver.DSN
			logLevel = defaultDriver.LogLevel
		}
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

func NewTestTaskPipeline(ctx context.Context) *gopipeline.Pipeline[task.Task] {
	initTestConfig()

	taskPipeline := task.NewTaskPipeline(
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

	return taskPipeline
}

func NewTestEngine(ctx context.Context, withTask bool) *gin.Engine {
	engine := gin.New()

	gormDB := NewTestDB()

	var taskPipeline *gopipeline.Pipeline[task.Task]
	if withTask {
		taskPipeline = NewTestTaskPipeline(ctx)
	}

	router.RegisterWebRouter(config.GlobalConfig, engine, gormDB, taskPipeline)

	return engine
}
