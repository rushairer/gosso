package tests

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/rushairer/gosso/config"
)

func NewTestDB() (*sql.DB, error) {
	configManager, err := NewTestConfigManager()
	if err != nil {
		return nil, fmt.Errorf("load test config: %w", err)
	}

	dsn := configManager.Config().DatabaseConfig.GetDefaultDriver().DSN

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if err = db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return db, nil
}

func NewTestConfigManager() (*config.ConfigManager, error) {
	projectRoot := projectRoot()
	configPath := filepath.Join(projectRoot, "config")
	configManager, err := config.NewConfigManager(nil, configPath, "test")
	if err != nil {
		return nil, err
	}
	return configManager, nil
}

func projectRoot() string {
	_, b, _, _ := runtime.Caller(0)
	currentDir := filepath.Dir(b)

	for {
		goModPath := filepath.Join(currentDir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return currentDir
		}
		parentDir := filepath.Dir(currentDir)
		if parentDir == currentDir {
			log.Fatalf("go.mod not found in any parent directory")
		}
		currentDir = parentDir
	}
}
