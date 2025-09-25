package utility

import (
	"context"
	"errors"
	"gosso/config"
	"gosso/router"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/rushairer/gouno/task"

	"github.com/gin-gonic/gin"
	gopipeline "github.com/rushairer/go-pipeline"
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

// NewTestDB 函数现在由编译标签特定的文件提供：
// - test_engine_mysql.go (需要 -tags mysql)
// - test_engine_postgres.go (需要 -tags postgres)
// - test_engine_sqlite.go (需要 -tags sqlite)

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
